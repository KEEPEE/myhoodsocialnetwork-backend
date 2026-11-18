//! REST API uzla — B3 placeholder (MYHSN-5) rozšírený o B4 (MYHSN-6).
//!
//! Autentizácia: `POST /channels` zostáva admin operácia bez prihlásenia
//! (apka/I3 to tak používajú — **nesmieme meniť**). B4 koncovky používajú
//! **session token** (D-26): pri registrácii/prihlásení ho vydáme, v
//! úložni je len jeho BLAKE3 hash. Kde sa posiela:
//! - `POST /devices` — telom `{account_session, …}` (zadania B4) alebo
//!   hlavičkou `Authorization: Bearer <token>`,
//! - `GET /devices`, `DELETE /devices/{id}` — hlavičkou `Authorization`.
//!
//! Koniec pointy:
//! - `GET /channels` — zoznam kanálov. **Soľ slepého hashu sa nevracia** —
//!   drží ju len domáci uzol (D-25), lebo bez nej ktokoľvek zistí, či dva
//!   záznamy majú rovnaký obsah.
//! - `POST /channels` — vytvor kanál `{name, kind}`.
//! - `GET /node/info` — ID uzla, proto verzia a **epochy kanálov**
//!   (klient podľa nich pozná, či je za epochou — D-25).
//! - `POST /register` — účet + prvý device kľúč + session token (B4).
//! - `POST /login` — meno + heslo (Argon2id) → session token (B4).
//! - `POST /devices` — atest nového kľúča existujúcemu účtu (B4).
//! - `GET /devices` — zoznam zariadení (B4).
//! - `DELETE /devices/{id}` — revokácia kľúča (B4); F10a: revokované
//!   zariadenie uzol best-effort vyhodí aj z prebiehajúcich hovorov.
//! - `GET /members` — lookup pubkey → username pre atestované aktívne
//!   kľúče všetkých účtov (B5.1, MYHSN-19; bez auth — username je na
//!   uzle verejný).
//! - `GET /records/{hash}` — **surový log**: čo uzol o zázname drží, vrátane
//!   dekódovaného obsahu (B6, MYHSN-8; dôkaz, že erase vymenil bajty a
//!   ponechal dôvod).
//! - `GET /channels/{id}/records` — **čítací pohľad**: čo čitateľ vidí po
//!   vyhodnotení tombstone/hide/erase (B6, D-30).
//!
//! Heslá a tokeny sa **nikdy nelogujú**; odpovede obsahujú len id/hex
//! kľúče a časy.
//!
//! ⚠ Obe B6 koncovky čítajú **bez autentizácie** (ako `GET /members`) a
//! vracajú aj dekódovaný obsah — na pilotnom LAN uzle je to zámer (testy a
//! diagnostika), na verejnom uzle by obsah patril za session token.

use crate::auth;
use crate::store::{self, DeviceRow, Store, StoreError};
use axum::extract::{Extension, Json, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::delete;
use axum::routing::get;
use axum::Router;
use myhsn_core::channel::{Channel, ChannelKind};
use myhsn_core::identity::{AccountId, DevicePublicKey, NodeId};
use myhsn_core::record::{from_hex, to_hex, Envelope, EraseReason, RecordHash, RecordKind};
use myhsn_core::seq::ChannelId;
use myhsn_core::storage::{RangeQuery, RecordStore};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

/// Relácia prihlásenia trvá ~30 dní (B4: expirácia session tokena).
pub const SESSION_TTL_SECS: u64 = 30 * 24 * 3600;

/// Minimálna dĺžka hesla pri registrácii — uzol je jediná brána pred
/// útokom na Argon2, krátké heslo by zbytočne oslabovalo D-26 model.
pub const MIN_PASSWORD_LEN: usize = 8;
/// Maximálna dĺžka hesla (Argon2 je lineárny, ale chceme strop v tele).
pub const MAX_PASSWORD_LEN: usize = 1024;

/// Zdieľaná úloža. `Store` je `Send` (rusqlite `Connection` nie je `Sync`),
/// preto `Mutex`. Zápisy do SQLite sú krátke; WS sync (B5) drží zámok len
/// počas operácií úložne, neverí sa mu cez `.await`.
pub type SharedStore = Arc<Mutex<Store>>;

/// Router s API koncami (stav sa pridáva cez `with_state`).
///
/// **F14a:** defaultná politika `open` + bez WS broadcastera — testy a
/// `build_router` sa správajú ako skôr. Produkčný uzol volá
/// [`api_router_full`].
pub fn api_router(state: SharedStore) -> Router {
    api_router_full(state, std::sync::Arc::new(crate::roles::AuthConfig::default()), None)
}

/// [`api_router`] + `[auth]` konfigurácia a rukoväť na WS push (F14a).
pub fn api_router_full(
    state: SharedStore,
    auth: std::sync::Arc<crate::roles::AuthConfig>,
    ws: Option<crate::ws::WsBroadcaster>,
) -> Router {
    Router::new()
        .route("/channels", get(list_channels).post(create_channel))
        .route("/node/info", get(node_info))
        .route("/register", axum::routing::post(register))
        .route("/login", axum::routing::post(login))
        .route(
            "/devices",
            get(list_devices).post(attest_device),
        )
        .route("/devices/{id}", delete(revoke_device))
        .route("/members", get(list_members))
        .route("/me", get(get_me).patch(patch_me))
        .route("/records/{hash}", get(get_record))
        .route("/channels/{id}/records", get(list_channel_records))
        // --- F14a (MYHSN-56): správa rolí, nastavenia, pozvánky ---------
        .route("/admin/users", get(admin_users))
        .route("/admin/users/{id}", delete(admin_user_delete))
        .route("/admin/roles", axum::routing::post(admin_roles))
        .route(
            "/admin/settings",
            get(admin_settings_get)
                .put(admin_settings_put)
                .delete(admin_settings_delete),
        )
        .route("/invites", get(invites_list).post(invites_create))
        .route("/invites/{id}", delete(invites_delete))
        // --- F14c (MYHSN-58): skupinové kanály (owner/admin/member) ------
        .route(
            "/channels/{id}/members",
            get(channel_members).post(channel_member_add),
        )
        .route(
            "/channels/{id}/members/{acct}",
            delete(channel_member_remove).put(channel_member_set_role),
        )
        .route("/channels/{id}/transfer", axum::routing::post(channel_transfer))
        .route("/channels/{id}/mute", axum::routing::post(channel_mute))
        .route("/channels/{id}/mute/{acct}", delete(channel_unmute))
        .with_state(state)
        .layer(axum::Extension(auth))
        .layer(axum::Extension(ws))
}

/// Zámok, ktorý nepanikári ani po panike iného handleru (uzol musí žiť).
pub(crate) fn lock(store: &SharedStore) -> std::sync::MutexGuard<'_, Store> {
    store.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Chyba API → HTTP stav + textová správa (žiadne tajné v odpovedi).
///
/// **F14a:** voliteľný strojovo čitateľný `code` — klient sa rozhoduje
/// podľa neho, nie podľa slovenského textu. Kód má len nové koncovky;
/// staré chyby ostávajú plain-text (spätná kompatibilita odpovedí).
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
    code: Option<&'static str>,
}

impl ApiError {
    pub(crate) fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            code: None,
        }
    }
    /// **F14a:** chyba s strojovým kódom → JSON odpoveď
    /// `{"error": ..., "code": ...}`.
    pub(crate) fn coded(
        status: StatusCode,
        message: impl Into<String>,
        code: &'static str,
    ) -> Self {
        Self {
            status,
            message: message.into(),
            code: Some(code),
        }
    }
    pub(crate) fn bad_request(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, msg)
    }
    pub(crate) fn unauthorized(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, msg)
    }
    fn conflict(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, msg)
    }
    pub(crate) fn not_found(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, msg)
    }
    /// 413 — jeden upload je väčší ako `max_upload_bytes` (B7, D-33).
    pub(crate) fn payload_too_large(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, msg)
    }
    /// 507 Insufficient Storage — kvota na účet je vyčerpaná (B7, D-33).
    /// Voľba kódu: 507 je registrovaná IANA kód pre „server sa nezmestí“
    /// (WebDAV kvóta); 429 je skôr rate-limit a 452 nie je štandard.
    pub(crate) fn insufficient_storage(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::INSUFFICIENT_STORAGE, msg)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // F14a: chyba s kódom → JSON; ostatné ostávajú plain-text (starý
        // klient kontroloval len HTTP status, text bol len pomôcka)
        match self.code {
            Some(code) => (
                self.status,
                Json(json!({ "error": self.message, "code": code })),
            )
                .into_response(),
            None => (self.status, self.message).into_response(),
        }
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        // chybu logujeme celú, klient dostane stručnú verziu
        tracing::warn!(error = %e, "chyba úložne pri REST požiadavke");
        match e {
            StoreError::NoSuchChannel(_) => Self::new(StatusCode::NOT_FOUND, "kanál neexistuje"),
            StoreError::ChannelNameTaken(n) => {
                Self::new(StatusCode::CONFLICT, format!("názov kanála „{n}“ je obsadený"))
            }
            StoreError::PositionConflict { .. } => {
                Self::new(StatusCode::CONFLICT, "pozícia v logu je obsadená")
            }
            StoreError::SchemaTooNew { .. } => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "schéma je novšia než binárka",
            ),
            // B4 — žiadne z týchto hlásení neobsahuje heslo ani token
            StoreError::UsernameTaken(u) => {
                Self::new(StatusCode::CONFLICT, format!("username „{u}“ je obsadený"))
            }
            StoreError::NoSuchAccount => Self::unauthorized("účet neexistuje"),
            StoreError::BadDeviceKeyLen(n) => Self::bad_request(format!(
                "verejný kľúč musí mať 32 bajtov (64 hex znakov), dostali sme {n}"
            )),
            StoreError::DeviceKeyTaken => {
                Self::conflict("tento device kľúč je už atestovaný")
            }
            StoreError::NoSuchDevice(id) => {
                Self::not_found(format!("zariadenie {id} tohto účtu neexistuje"))
            }
            StoreError::ClientHashTaken => {
                Self::conflict("záznam už bol prevzatý")
            }
            other => Self::new(StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        }
    }
}

/// Kanál vo verejnej forme — bez soli (D-25). B8 (doc 24 §2) pridáva
/// **len nové polia**: `cover` (vždy prítomné, prípadne `null`) a
/// `meta_version`; existujúce kľúče nemenia tvar ani typ.
/// JSON kanála. **F14c** pridáva `owner`, `group` a `channel_role` —
/// aditívne polia, stará apka neznáme kľúče ignoruje. `owner` je hex id
/// ownera group kanála alebo `null` (legacy kanál), `channel_role` je
/// efektívna rola **volajúceho** (`owner|admin|member` alebo `null`).
fn channel_json(
    c: &Channel,
    cover: Option<&store::CoverRef>,
    meta_version: i64,
    owner: Option<&[u8; 32]>,
    channel_role: Option<&str>,
) -> Value {
    json!({
        "id": myhsn_core::record::to_hex(&c.id),
        "name": c.name,
        "kind": c.kind.as_str(),
        "node_epoch": c.node_epoch,
        "cover": cover.map(|cv| json!({
            "url": format!("/media/{}", cv.media_id),
            "hash": to_hex(&cv.hash),
            "mime": cv.mime,
            "set_by": cv.set_by,
            "set_at": cv.set_at,
        })),
        "meta_version": meta_version,
        // --- F14c (MYHSN-58): aditívne, starí klienti ich preskočia ---
        "owner": owner.map(|o| to_hex(o)),
        "group": owner.is_some(),
        "channel_role": channel_role,
    })
}

/// Dotaz `GET /channels` (F14c): `?include_groups=1` zaradí do zoznamu aj
/// **skupinové** kanály. Bez neho sú pred klientom skryté (rozhodnutie §4)
/// — admin panel a apka s F14c podporou ho posielajú.
#[derive(Debug, Deserialize, Default)]
pub struct ListChannelsQuery {
    #[serde(default)]
    pub include_groups: Option<String>,
}

impl ListChannelsQuery {
    /// `1`, `true` alebo `yes` (case-insensitive) = group kanály zapnúť.
    fn wants_groups(&self) -> bool {
        matches!(
            self.include_groups.as_deref().map(str::to_ascii_lowercase).as_deref(),
            Some("1") | Some("true") | Some("yes")
        )
    }
}

/// `GET /channels` — zoznam kanálov uzla (B8: každá položka má navyše
/// `cover` a `meta_version`; soľ sa stále nevracia). **F14c:** skupinové
/// kanály sú štandardne VON (voľba `?include_groups=1`), Bearer je
/// voliteľný — s ním odpoveď doplní `channel_role` volajúceho.
pub async fn list_channels(
    State(store): State<SharedStore>,
    Query(q): Query<ListChannelsQuery>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let include_groups = q.wants_groups();
    let (channels, covers, owners, roles) = {
        let store = lock(&store);
        let channels = store.list_channels()?;
        let covers = store.channel_cover_rows()?;
        let owners: std::collections::HashMap<ChannelId, Option<Option<[u8; 32]>>> =
            store.channel_owners()?.into_iter().collect();
        // Bearer je dobrovoľný: neplatný token nie je chyba, len anonym
        let caller = bearer_token(&headers).and_then(|t| session_account(&store, Some(&t)).ok());
        let mut roles: std::collections::HashMap<ChannelId, &'static str> =
            Default::default();
        if let Some(who) = caller {
            for c in &channels {
                if let Ok(Some(auth)) = store.channel_authority(&c.id, &who) {
                    if let Some(code) = auth.role {
                        roles.insert(c.id, channel_role_name(code));
                    }
                }
            }
        }
        (channels, covers, owners, roles)
    };
    let cover_map: std::collections::HashMap<ChannelId, &store::ChannelCoverRow> =
        covers.iter().map(|c| (c.id, c)).collect();
    let items: Vec<Value> = channels
        .iter()
        // group kanál = `owner IS NOT NULL`; bez `include_groups` ho
        // klient neuvidí vôbec (rozhodnutie F14c §4)
        .filter(|c| include_groups || !matches!(owners.get(&c.id), Some(Some(Some(_)))))
        .map(|c| {
            let row = cover_map.get(&c.id);
            let owner = owners.get(&c.id).copied().flatten().flatten();
            channel_json(
                c,
                row.and_then(|r| r.cover.as_ref()),
                row.map(|r| r.meta_version).unwrap_or(0),
                owner.as_ref(),
                roles.get(&c.id).copied(),
            )
        })
        .collect();
    Ok(Json(json!({ "channels": items })))
}

/// Telo `POST /channels` — `{name, kind?, group?, owner?}`.
#[derive(Debug, Deserialize)]
pub struct CreateChannelRequest {
    pub name: String,
    #[serde(default)]
    pub kind: Option<String>,
    /// **F14c:** `true` = skupinový kanál s ownerom (vyžaduje Bearer).
    /// Neprítomné = legacy kanál — **Bearer sa ani neparsuje**, lebo apka
    /// posiela `Authorization` globálne a jej validácia by rozbila
    /// tvorbu kanálov (rozhodnutie §10).
    #[serde(default)]
    pub group: Option<bool>,
    /// **F14c:** meno alebo hex id budúceho ownera. Rešpektuje ho len
    /// **server admin**; inak 403 `insufficient_perms`.
    #[serde(default)]
    pub owner: Option<String>,
}

/// `POST /channels` — vytvor kanál. Legacy: verejná operácia bez auth
/// (apka/I3 to tak používa — **nesmieme meniť**). **F14c group:**
/// `{"group": true}` + Bearer, owner = volajúci (iného ownera nastaví len
/// server admin); group kanál smie vytvoriť hociktorý aktívny účet.
pub async fn create_channel(
    State(store): State<SharedStore>,
    Extension(ws): Extension<Option<crate::ws::WsBroadcaster>>,
    headers: HeaderMap,
    Json(req): Json<CreateChannelRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let kind = match req.kind.as_deref().unwrap_or("wall") {
        k => ChannelKind::from_str(k).ok_or_else(|| {
            ApiError::bad_request("kind je len wall | chat | mixed")
        })?,
    };
    if req.group.unwrap_or(false) {
        let mut store = lock(&store);
        let who = actor_channel(&store, &headers)?;
        if who.status != 0 {
            return Err(ApiError::coded(
                StatusCode::CONFLICT,
                "ucet nie je aktivny — caka na schvalenie",
                "account_inactive",
            ));
        }
        let mut owner = who.account;
        if let Some(raw) = req.owner.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            let target = store
                .resolve_account(raw)?
                .ok_or_else(|| {
                    ApiError::coded(StatusCode::NOT_FOUND, "ucet neexistuje", "account_not_found")
                })?;
            if target.id != who.account {
                if who.role != 2 {
                    return Err(ApiError::coded(
                        StatusCode::FORBIDDEN,
                        "ineho ownera nastavi len server admin",
                        "insufficient_perms",
                    ));
                }
                let (_role, _perms, status) = store
                    .account_role(&target.id)?
                    .ok_or_else(|| {
                        ApiError::coded(
                            StatusCode::NOT_FOUND,
                            "ucet neexistuje",
                            "account_not_found",
                        )
                    })?;
                if status != 0 {
                    return Err(ApiError::coded(
                        StatusCode::CONFLICT,
                        "ucet nie je aktivny",
                        "account_inactive",
                    ));
                }
                owner = target.id;
            }
        }
        let owner_name = store
            .account_by_id(&owner)?
            .map(|a| a.username)
            .unwrap_or_default();
        let (created, env) = store
            .create_group_channel(&req.name, kind, &owner, &owner_name, (who.account, who.device))
            .map_err(channel_error)?;
        drop(store);
        if let Some(ws) = ws {
            ws.broadcast_group_record(&env.encode());
            ws.broadcast_channel_role_update(created.id, owner, &owner_name, "owner", false);
        }
        tracing::info!(
            channel = %created.name,
            kind = created.kind.as_str(),
            group = true,
            id = %myhsn_core::record::to_hex(&created.id),
            "skupinový kanál vytvorený"
        );
        // `channel_role` je efektívna rola **volajúceho**: server admin,
        // ktorý nastavil cudzieho ownera, v kanáli členom nie je
        let role = if owner == who.account { Some("owner") } else { None };
        return Ok((
            StatusCode::CREATED,
            Json(channel_json(&created, None, 0, Some(&owner), role)),
        ));
    }
    let created = {
        let mut store = lock(&store);
        store.create_channel(&req.name, kind)?
    };
    tracing::info!(
        channel = %created.name,
        kind = created.kind.as_str(),
        id = %myhsn_core::record::to_hex(&created.id),
        "kanál vytvorený"
    );
    Ok((StatusCode::CREATED, Json(channel_json(&created, None, 0, None, None))))
}

/// `GET /node/info` — ID uzla, proto verzia a epochy kanálov (D-25).
pub async fn node_info(State(store): State<SharedStore>) -> Result<Json<Value>, ApiError> {
    let mut store = lock(&store);
    let node_id: NodeId = store.node_id()?;
    let channels = store.list_channels()?;
    // **F14a:** systémový kanál (audit rolí) nepatrí do zoznamu kanálov —
    // bežný klient ho nemá vidieť; prítomnosť nahlásime samostatným
    // poľom `system_channel` a `has_admin` (apka sa podľa nich vypyta
    // na admina pri prvom spustení).
    let system = store.system_channel_id()?;
    let has_admin = store.has_admin()?;
    // **F14c:** `GET /node/info` nemá caps, takže skupinové kanály tu
    // nechávame len pre tých, čo o nich vedia — teda nikoho. Schopnosti
    // uzla deklaruje aditívne pole `features` (rozhodnutie §5: `NODE_CAPS`
    // ostáva `["sync"]`, aby dekóder `lk` bota nič nezhodilo).
    let owners: std::collections::HashMap<ChannelId, Option<Option<[u8; 32]>>> =
        store.channel_owners()?.into_iter().collect();

    let mut items: Vec<Value> = Vec::with_capacity(channels.len());
    let mut max_epoch: u64 = 0;
    for c in &channels {
        if Some(c.id) == system {
            continue;
        }
        if matches!(owners.get(&c.id), Some(Some(Some(_)))) {
            continue;
        }
        let next_seq = store.peek_next_seq(&c.id, c.node_epoch)?;
        max_epoch = max_epoch.max(c.node_epoch);
        items.push(json!({
            "id": myhsn_core::record::to_hex(&c.id),
            "name": c.name,
            "kind": c.kind.as_str(),
            "node_epoch": c.node_epoch,
            "next_seq": next_seq,
        }));
    }

    Ok(Json(json!({
        "node_id": myhsn_core::record::to_hex(&node_id),
        "proto_version": myhsn_core::PROTO_VERSION,
        "node_epoch": max_epoch,
        "channels": items,
        "software_version": env!("CARGO_PKG_VERSION"),
        // F14a — voliteľné polia, stará apka ich ignoruje
        "has_admin": has_admin,
        "system_channel": system.map(|id| myhsn_core::record::to_hex(&id)),
        // F14c — aditívna deklarácia schopností (NAJPRVEDAjšia cesta, ako
        // ich nahlásiť bez zmeny `NODE_CAPS`: JSON pole ignoruje každý
        // starý klient, WS caps by niekto mohol parseovať inak)
        "features": ["roles", "channels"],
    })))
}

// ===========================================================================
// B4 (MYHSN-6): účty, device keys, login — D-26
// ===========================================================================

/// Currentný čas (unix sekundy) pre created/attested/expires polia.
pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Vyber session token z hlavičky `Authorization: Bearer <hex>`.
pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    let rest = value.strip_prefix("Bearer ")?.trim();
    if rest.is_empty() {
        None
    } else {
        Some(rest.to_string())
    }
}

/// Rozparso a over token (hex 64 znakov) → účet. Prázdny/neplatný token
/// je vždy 401 — rozdiel „neznamy token“ vs. „expirovany“ navonok
/// netajíme (klient aj tak musí urobiť login).
pub(crate) fn session_account(
    store: &Store,
    token_hex: Option<&str>,
) -> Result<AccountId, ApiError> {
    let token_hex = token_hex.ok_or_else(|| ApiError::unauthorized("chyba session token"))?;
    let raw = from_hex(token_hex)
        .filter(|b| b.len() == auth::SESSION_TOKEN_LEN)
        .ok_or_else(|| ApiError::unauthorized("session token ma byt 64 hex znakov"))?;
    let mut buf = [0u8; auth::SESSION_TOKEN_LEN];
    buf.copy_from_slice(&raw);
    let token_hash = auth::hash_session_token(&buf);
    store
        .session_account(&token_hash, now_secs())
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::unauthorized("session token je neplatny alebo expirovany"))
}

/// Device kľúč vo verejnej forme (id pre revokáciu, kľúč hex, časy).
fn device_json(d: &DeviceRow) -> Value {
    json!({
        "id": d.id,
        "public_key": to_hex(&d.key.public_key.0),
        "label": d.key.label,
        "attested_at": d.key.attested_at,
        "revoked_at": d.key.revoked_at,
    })
}

/// Validácia mena a hesla ešte pred Argonom (lacná brána pred drahou).
fn validate_credentials(username: &str, password: &str) -> Result<(), ApiError> {
    let name = username.trim();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(ApiError::bad_request("username je povinný (max 64 znakov)"));
    }
    if name.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(ApiError::bad_request("username nesmie obsahovať medzery ani riadiace znaky"));
    }
    if password.len() < MIN_PASSWORD_LEN || password.len() > MAX_PASSWORD_LEN {
        return Err(ApiError::bad_request(format!(
            "heslo musí mať {MIN_PASSWORD_LEN}..{MAX_PASSWORD_LEN} bajtov"
        )));
    }
    Ok(())
}

/// Parse hex device kľúča zo žiadosti (32 B = 64 hex znakov).
fn parse_device_pub(hex: &str) -> Result<DevicePublicKey, ApiError> {
    let raw = from_hex(hex).ok_or_else(|| ApiError::bad_request("device_pub musí byť hex"))?;
    if raw.len() != 32 {
        return Err(ApiError::bad_request(
            "device_pub musí mať 32 bajtov (64 hex znakov)",
        ));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&raw);
    Ok(DevicePublicKey(pk))
}

/// Telo `POST /register` (B4). `device_label` je voliteľné. B8 (doc 24 §4)
/// pridáva voliteľné `display_name` — bez neho sa správa presne ako skôr.
/// **F14a** pridáva voliteľné `invite` (hex token pozvánky) — staré telá
/// bez neho prejdú identicky.
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    /// verejný ed25519 kľúč prvého zariadenia (hex, 64 znakov)
    pub device_pub: String,
    #[serde(default)]
    pub device_label: Option<String>,
    /// Voliteľné meno zobrazenia (B8). Prázdne/absentné → NULL.
    #[serde(default)]
    pub display_name: Option<String>,
    /// **F14a:** token jednorazovej pozvánky (hex, 64 znakov).
    #[serde(default)]
    pub invite: Option<String>,
}

/// Validácia `display_name` (B8, doc 24 §4): orezať medzery, 1–40 znakov
/// (`chars().count()`), bez riadiacich znakov; prázdny reťazec znamená
/// NULL. Porušenie → 400 so slovenskou chybou.
pub(crate) fn validate_display_name(raw: &str) -> Result<Option<String>, ApiError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let count = trimmed.chars().count();
    if count > 40 {
        return Err(ApiError::bad_request(
            "Meno musí mať najviac 40 znakov.",
        ));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(ApiError::bad_request(
            "Meno nesmie obsahovať riadiace znaky.",
        ));
    }
    Ok(Some(trimmed.to_string()))
}

/// `POST /register` — vytvorí účet (Argon2id hash) + prvý device kľúč a
/// vráti session token. Kritérium B4: duplicitný username → 409.
///
/// **F14a (MYHSN-56):** registrácia rešpektuje politiku
/// (`open`/`invite_only`/`admin_approved`, efektívna = meta override →
/// TOML → open) a pravidlo prvého admina. Chyby s kódmi:
/// `invite_required` (403), `invite_invalid` (400), `account_pending`
/// (403 — účet vznikol, ale čaká na schválenie).
pub async fn register(
    State(store): State<SharedStore>,
    Extension(auth): Extension<std::sync::Arc<crate::roles::AuthConfig>>,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    use crate::roles::RegistrationPolicy;
    validate_credentials(&req.username, &req.password)?;
    let device_pub = parse_device_pub(&req.device_pub)?;
    // B8: display_name validovať ešte pred drahým Argonom. Vrcholový
    // `Option` je „pole prítomné“, vnútorný je „neprázdna hodnota“ —
    // flatten ich spojí: Some(meno) / None (absentné aj prázdne).
    let display_name = req
        .display_name
        .as_deref()
        .map(validate_display_name)
        .transpose()?
        .flatten();

    // **F14a:** pozvánka — formát overíme pred Argonom (lacné), spotreba
    // je až v transakcii. Neplatný/expirovaný/použitý token = 400.
    let invite_token = req.invite.as_deref().map(|hex| {
        from_hex(hex)
            .filter(|b| b.len() == 32)
            .map(|b| {
                let mut t = [0u8; 32];
                t.copy_from_slice(&b);
                t
            })
            .ok_or_else(|| {
                ApiError::coded(
                    StatusCode::BAD_REQUEST,
                    "pozvánka musí byť hex 64 znakov",
                    "invite_invalid",
                )
            })
    }).transpose()?;

    // Argon2id je drahý zámerne (D-26); beží v async handleri — pri
    // jednom uzle pre malú komunitu stačí, pri davoch pridáme pool (B7)
    let pass_hash = auth::hash_password(&req.password)
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let now = now_secs();
    let mut store = lock(&store);

    // efektívna politika: meta override (runtime) → TOML → open (O11)
    let policy = match store.policy_override()? {
        Some(raw) => raw
            .parse::<RegistrationPolicy>()
            .unwrap_or(auth.registration_policy),
        None => auth.registration_policy,
    };
    let admin_candidate = auth.may_bootstrap(&req.username);
    // **O13/Z5:** na uzle bez admina nesmie `invite_only` zablokovať
    // bootstrap — prvý kandidat (menovo zhodný s `bootstrap_admin`, alebo
    // hocikto pri `None`) smie registráciu dokončiť aj bez pozvánky.
    let require_invite = policy == RegistrationPolicy::InviteOnly
        && !(admin_candidate && !store.has_admin()?);

    let outcome = match store.register_account(
        &req.username,
        &pass_hash,
        now,
        admin_candidate,
        require_invite,
        policy == RegistrationPolicy::AdminApproved,
        invite_token.as_ref(),
    ) {
        Ok(o) => o,
        Err(crate::store::RegError::UsernameTaken(n)) => {
            return Err(ApiError::conflict(format!("username {n:?} je uzivany")))
        }
        Err(crate::store::RegError::InviteRequired) => {
            return Err(ApiError::coded(
                StatusCode::FORBIDDEN,
                "server vyzaduje pozvanku (invite_only)",
                "invite_required",
            ))
        }
        Err(crate::store::RegError::InviteInvalid) => {
            return Err(ApiError::coded(
                StatusCode::BAD_REQUEST,
                "pozvanka je neplatna, expirovana alebo pouzita",
                "invite_invalid",
            ))
        }
        Err(crate::store::RegError::Store(e)) => return Err(ApiError::from(e)),
    };
    let account = outcome.account;

    // B8: voliteľné meno uložiť hneď za vytvorením účtu
    if let Some(name) = display_name.as_deref() {
        store.set_display_name(&account.id, Some(name))?;
    }
    let label = req.device_label.unwrap_or_else(|| "zariadenie".to_string());
    let device = store.attest_device_key(&account.id, &device_pub, &label, now)?;

    // **F14a:** čakajúci účet nedostane session token — nemôže ani čítať,
    // kým ho neschváli admin (grant). Meno+id vrátime, aby apka vedela
    // zobrazit „čaká na schválenie“.
    if outcome.pending {
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "ucet cakna na schvalenie adminom",
            "account_pending",
        ));
    }

    // session token: 32 B náhody navonok, v DB len hash (nikdy nie token)
    let token = auth::new_session_token();
    store.put_session(&auth::hash_session_token(&token), &account.id, now, SESSION_TTL_SECS)?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "account_id": to_hex(&account.id),
            "username": account.username,
            "session_token": to_hex(&token),
            "device": device_json(&device),
            // B8: potvrdenie uloženého mena (NULL ak nenastavené)
            "display_name": display_name,
            // F14a — voliteľné polia (stará apka nevie čítať, ignoruje)
            "role": role_code_name(outcome.role),
            "perms": outcome.perms,
            "pending": false,
        })),
    ))
}

/// Telo `POST /login`.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// `POST /login` — meno + heslo → session token. Kritérium B4: zlé
/// heslo → 401 (a neexistujúci účet taktiež 401, s rovnakou prácou
/// v Argone — viac v `auth::verify_password_unknown_user`).
pub async fn login(
    State(store): State<SharedStore>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<Value>, ApiError> {
    let account = {
        let store = lock(&store);
        store
            .account_by_username(req.username.trim())
            .map_err(ApiError::from)?
    };
    let Some(account) = account else {
        auth::verify_password_unknown_user(&req.password);
        return Err(ApiError::unauthorized("nespravne meno alebo heslo"));
    };
    if !auth::verify_password(&req.password, &account.password_argon2id_hash) {
        return Err(ApiError::unauthorized("nespravne meno alebo heslo"));
    }

    // **F14a:** heslo sedí, ale účet čaká na schválenie → 403 s kódom
    // (nie 401: dôveryhodnosť preukázaná, chýba len povolenie).
    let (role, perms, status) = {
        let store = lock(&store);
        store
            .account_role(&account.id)
            .map_err(ApiError::from)?
            .unwrap_or((0, 0, 0))
    };
    if status == 1 {
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "ucet cakna na schvalenie adminom",
            "account_pending",
        ));
    }

    let now = now_secs();
    let token = auth::new_session_token();
    {
        let mut store = lock(&store);
        store.put_session(&auth::hash_session_token(&token), &account.id, now, SESSION_TTL_SECS)?;
    }
    Ok(Json(json!({
        "account_id": to_hex(&account.id),
        "username": account.username,
        "session_token": to_hex(&token),
        // F14a — voliteľné polia
        "role": role_code_name(role),
        "perms": perms,
    })))
}

/// Telo `POST /devices` — atest nového kľúča (D-26: robí ho už overený
/// účet cez session token existujúceho zariadenia).
#[derive(Debug, Deserialize)]
pub struct AttestDeviceRequest {
    pub device_pub: String,
    #[serde(default)]
    pub label: Option<String>,
    /// session token v tele (alternatíva k hlavičke `Authorization`)
    #[serde(default)]
    pub account_session: Option<String>,
}

/// `POST /devices` — atest nového device kľúča. Vyžaduje platný session
/// token = dôveru existujúceho zariadenia (kritérium B4).
pub async fn attest_device(
    State(store): State<SharedStore>,
    headers: HeaderMap,
    Json(req): Json<AttestDeviceRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let device_pub = parse_device_pub(&req.device_pub)?;
    // token: telový `account_session` má prednosť pred hlavičkou
    let bearer = bearer_token(&headers);
    let token = req.account_session.as_deref().or(bearer.as_deref());

    let now = now_secs();
    let mut store = lock(&store);
    let account_id = session_account(&store, token)?;
    let label = req.label.unwrap_or_else(|| "zariadenie".to_string());
    let device = store.attest_device_key(&account_id, &device_pub, &label, now)?;
    Ok((StatusCode::CREATED, Json(json!({ "device": device_json(&device) }))))
}

/// `GET /devices` — zoznam zariadení prihláseného účtu (session token v
/// hlavičke). Revokované kľúče sú prítomné s `revoked_at` (história).
pub async fn list_devices(
    State(store): State<SharedStore>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let store = lock(&store);
    let account_id = session_account(&store, bearer_token(&headers).as_deref())?;
    let devices = store.list_devices(&account_id)?;
    Ok(Json(json!({
        "account_id": to_hex(&account_id),
        "devices": devices.iter().map(device_json).collect::<Vec<_>>(),
    })))
}

/// `DELETE /devices/{id}` — revokácia (B4 kritérium: podpis revokovaným
/// kľúčom sa potom odmietne). Idempotentné; cudzie id → 404.
///
/// F10a: po revokácii uzol zariadenie **best-effort** vyhodí zo všetkých
/// LiveKit miestností (`RemoveParticipant`, na pozadí — odpoveď nečaká na
/// LiveKit a jeho zlyhanie sa len zaloguje). Návrat do hovoru zablokuje
/// webhook kontrola členstva (`calls::api`). `calls` je `None` v unit
/// testoch, ktoré volajú handler priamo bez routera.
pub async fn revoke_device(
    State(store): State<SharedStore>,
    calls: Option<Extension<crate::calls::CallsState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    let revoked_key = {
        let mut store = lock(&store);
        let account_id = session_account(&store, bearer_token(&headers).as_deref())?;
        let key = store
            .list_devices(&account_id)?
            .into_iter()
            .find(|d| d.id == id)
            .map(|d| d.key.public_key.0);
        store.revoke_device(&account_id, id, now_secs())?;
        key
    };
    if let (Some(Extension(calls)), Some(pk)) = (calls, revoked_key) {
        calls.kick_device_detached(pk);
    }
    Ok(Json(json!({ "revoked": id })))
}

// ===========================================================================
// B5.1 (MYHSN-19): lookup pubkey → username
// ===========================================================================

/// `GET /members` — mapa aktívnych device kľúčov na mená účtov (B5.1).
/// Bez auth: username je na uzle verejný údaj a kľúč je verejný kľúč —
/// odpoveď neobsahuje nič citlivé (žiadne heslá, e-maily, tokeny).
/// Vracajú sa len **atestované a nezrušené** kľúče; účet s viacerými
/// zariadeniami je tam raz za každé aktívne zariadenie.
pub async fn list_members(State(store): State<SharedStore>) -> Result<Json<Value>, ApiError> {
    let members = lock(&store).members()?;
    let items: Vec<Value> = members
        .iter()
        .map(|m| {
            json!({
                "public_key_hex": to_hex(&m.public_key),
                "username": m.username,
                // B8 (doc 24 §4): len pridané polia — display_name (null|
                // string) a avatar (null | {url, hash}); existujúce kľúče
                // ostávajú nedotknuté
                "display_name": m.display_name,
                "avatar": m.avatar.as_ref().map(|(id, hash)| json!({
                    "url": format!("/media/{id}"),
                    "hash": to_hex(hash),
                })),
            })
        })
        .collect();
    Ok(Json(json!({ "members": items })))
}

// ===========================================================================
// B8 (MYHSN-22): GET/PATCH /me — display_name a avatar vlastného účtu
// ===========================================================================

/// Avatar vo verejnej forme `{url, hash, mime}` (B8).
fn avatar_json(avatar: &Option<(String, [u8; 32], Option<String>)>) -> Option<Value> {
    avatar.as_ref().map(|(id, hash, mime)| {
        json!({
            "url": format!("/media/{id}"),
            "hash": to_hex(hash),
            "mime": mime,
        })
    })
}

/// `GET /me` — účet z session tokena: id, username, display_name, avatar.
pub async fn get_me(
    State(store): State<SharedStore>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let account = {
        let store = lock(&store);
        session_account(&store, bearer_token(&headers).as_deref())?
    };
    let row = {
        let store = lock(&store);
        let row = store
            .account_by_id(&account)
            .map_err(ApiError::from)?
            .ok_or_else(|| ApiError::unauthorized("účet neexistuje"))?;
        // **F14a:** apka volá `/me` po logine — rolu vrátime sem, aby
        // admin UI nepotreboval extra request (starý klient pole ignoruje)
        let (role, perms, status) =
            store.account_role(&account).map_err(ApiError::from)?.unwrap_or((0, 0, 0));
        (row, role, perms, status)
    };
    Ok(Json(json!({
        "account_id": to_hex(&row.0.id),
        "username": row.0.username,
        "display_name": row.0.display_name,
        "avatar": avatar_json(&row.0.avatar),
        "role": role_code_name(row.1),
        "perms": row.2,
        "pending": row.3 == 1,
    })))
}

/// Telo `PATCH /me` (B8): `{ "display_name": "Janka K." | null }`.
#[derive(Debug, Deserialize)]
pub struct PatchMeRequest {
    /// `null`/absentné zmaže meno, reťazec ho nastaví (po validácii).
    #[serde(default)]
    pub display_name: Option<String>,
}

/// `PATCH /me` — zmena `display_name`. Vráti to isté čo `GET /me`.
/// 400 pri zlej validácii, 401 bez relácie.
pub async fn patch_me(
    State(store): State<SharedStore>,
    headers: HeaderMap,
    Json(req): Json<PatchMeRequest>,
) -> Result<Json<Value>, ApiError> {
    let account = {
        let store = lock(&store);
        session_account(&store, bearer_token(&headers).as_deref())?
    };
    // B8: display_name — null zmaže, reťazec validovať a nastaviť
    let name = match req.display_name.as_deref() {
        None => None,
        Some(raw) => validate_display_name(raw)?,
    };
    {
        let mut store = lock(&store);
        store.set_display_name(&account, name.as_deref())?;
    }
    let row = {
        let store = lock(&store);
        store
            .account_by_id(&account)
            .map_err(ApiError::from)?
            .ok_or_else(|| ApiError::unauthorized("účet neexistuje"))?
    };
    Ok(Json(json!({
        "account_id": to_hex(&row.id),
        "username": row.username,
        "display_name": row.display_name,
        "avatar": avatar_json(&row.avatar),
    })))
}

// --- B6: čítanie záznamov (MYHSN-8, rozhodnutie D-30) ---------------------

/// Horná medza `limit` pre `GET /channels/{id}/records` — diagnostické
/// čítie nesmie stiahnuť celý log naraz.
const RECORDS_DEFAULT_LIMIT: u32 = 200;
const RECORDS_MAX_LIMIT: u32 = 1000;

/// Rozparsovanie 32-bajtového id z hex reťazca (hash záznamu, id kanála
/// aj device kľúč majú rovnaký tvar). `None` = nie hex alebo zlá dĺžka.
pub(crate) fn parse_id32_hex(s: &str) -> Option<[u8; 32]> {
    let bytes = from_hex(s)?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

fn parse_id32(s: &str) -> Result<[u8; 32], ApiError> {
    parse_id32_hex(s).ok_or_else(|| ApiError::bad_request("id musí byť hex 32 bajtov (64 znakov)"))
}

/// Čitateľný názov druhu záznamu (JSON pomôcka; identifikátory v kóde aj v
/// drôte ostávajú anglicky).
fn kind_name(kind: RecordKind) -> &'static str {
    match kind {
        RecordKind::Post => "post",
        RecordKind::Reaction => "reaction",
        RecordKind::ChatMsg => "chat_msg",
        RecordKind::Tombstone => "tombstone",
        RecordKind::Hide => "hide",
        RecordKind::Erase => "erase",
        // F14a: audit rolí (systémový kanál)
        RecordKind::GrantRole => "grant_role",
        RecordKind::RevokeRole => "revoke_role",
        // F14c: audity skupinových kanálov (žijú v kanáli, ktorého sa týkajú)
        RecordKind::CreateChannel => "create_channel",
        RecordKind::GrantChannelRole => "grant_channel_role",
        RecordKind::RevokeChannelRole => "revoke_channel_role",
        RecordKind::TransferChannelOwner => "transfer_channel_owner",
    }
}

/// Názov kanálovej role pre JSON auditu (F14c); 255 = „už nie je člen“.
fn channel_role_name(code: u8) -> &'static str {
    if code == u8::MAX {
        return "none";
    }
    myhsn_core::roles::ChannelRole::from_code(code)
        .map(|r| r.name())
        .unwrap_or("unknown")
}

/// Názov role pre JSON auditu (F14a); neznámy kód ostane `unknown`.
fn role_code_name(code: u8) -> &'static str {
    myhsn_core::roles::Role::from_code(code)
        .map(|r| r.name())
        .unwrap_or("unknown")
}

/// Názov + kód dôvodu erase (D-30 má stabilné kódy 1 – 4).
fn erase_reason_name(reason: EraseReason) -> (&'static str, u16) {
    match reason {
        EraseReason::AuthorRequest => ("author_request", 1),
        EraseReason::Retention => ("retention", 2),
        EraseReason::Moderation => ("moderation", 3),
        EraseReason::LegalOrder => ("legal_order", 4),
        EraseReason::Other(c) => ("other", c),
    }
}

/// Čitateľný pohľad na obálku pre REST. Obsah vracáme **dekódovaný** —
/// tieto koncovky sú diagnostika, nie distribučný kanál uzla: bez toho by
/// sa nedal dokázať erase („obsah je preč, dôvod ostal“, D-30).
fn record_json(env: &Envelope) -> Value {
    use myhsn_core::record::Payload;
    let content = match env.payload() {
        Ok(Payload::Post { text, media_ref }) => json!({ "text": text, "media_ref": media_ref }),
        Ok(Payload::ChatMsg { text, media }) => json!({
            "text": text,
            "media_id": media.as_ref().map(|m| m.media_id.clone()),
        }),
        Ok(Payload::Reaction { target, emoji }) => {
            json!({ "target_hex": to_hex(&target), "emoji": emoji })
        }
        Ok(Payload::Tombstone { target }) => json!({ "target_hex": to_hex(&target) }),
        Ok(Payload::Hide { target, reason }) => {
            json!({ "target_hex": to_hex(&target), "reason": reason })
        }
        Ok(Payload::Erase { target, reason, target_kind }) => {
            let (name, code) = erase_reason_name(reason);
            json!({
                "target_hex": to_hex(&target),
                "reason": name,
                "reason_code": code,
                "erased_kind": kind_name(target_kind),
            })
        }
        Ok(Payload::GrantRole { target, target_name, role, perms, by, by_device }) => {
            json!({
                "target_hex": to_hex(target.as_slice()),
                "target_name": target_name,
                "role": role_code_name(role),
                "role_code": role,
                "perms": perms,
                "by_hex": to_hex(by.as_slice()),
                "by_device_hex": to_hex(by_device.as_slice()),
            })
        }
        Ok(Payload::RevokeRole { target, target_name, by, by_device }) => {
            json!({
                "target_hex": to_hex(target.as_slice()),
                "target_name": target_name,
                "role": "user",
                "by_hex": to_hex(by.as_slice()),
                "by_device_hex": to_hex(by_device.as_slice()),
            })
        }
        // --- F14c (MYHSN-58): audity skupinových kanálov -----------------
        // `GET /channels/{id}/records` ich vracia VŽDY (aj klientom bez
        // capov) — kontrakt says frontend musí filtrovať (rozhodnutie §4).
        Ok(Payload::CreateChannel { channel, name, kind, owner, owner_name, by, by_device }) => {
            json!({
                "channel_hex": to_hex(channel.as_slice()),
                "name": name,
                "kind": ChannelKind::from_code(kind).map(|k| k.as_str()).unwrap_or("unknown"),
                "kind_code": kind,
                "owner_hex": to_hex(owner.as_slice()),
                "owner_name": owner_name,
                "by_hex": to_hex(by.as_slice()),
                "by_device_hex": to_hex(by_device.as_slice()),
            })
        }
        Ok(Payload::GrantChannelRole { channel, target, target_name, channel_role, by, by_device }) => {
            json!({
                "channel_hex": to_hex(channel.as_slice()),
                "target_hex": to_hex(target.as_slice()),
                "target_name": target_name,
                "channel_role": channel_role_name(channel_role),
                "channel_role_code": channel_role,
                "by_hex": to_hex(by.as_slice()),
                "by_device_hex": to_hex(by_device.as_slice()),
            })
        }
        Ok(Payload::RevokeChannelRole { channel, target, target_name, by, by_device }) => {
            json!({
                "channel_hex": to_hex(channel.as_slice()),
                "target_hex": to_hex(target.as_slice()),
                "target_name": target_name,
                "channel_role": "none",
                "by_hex": to_hex(by.as_slice()),
                "by_device_hex": to_hex(by_device.as_slice()),
            })
        }
        Ok(Payload::TransferChannelOwner { channel, from, from_name, to, to_name, prev_role, by, by_device }) => {
            json!({
                "channel_hex": to_hex(channel.as_slice()),
                "from_hex": to_hex(from.as_slice()),
                "from_name": from_name,
                "to_hex": to_hex(to.as_slice()),
                "to_name": to_name,
                "previous_role": channel_role_name(prev_role),
                "previous_role_code": prev_role,
                "by_hex": to_hex(by.as_slice()),
                "by_device_hex": to_hex(by_device.as_slice()),
            })
        }
        // nepoznané telo — ukážeme aspoň dĺžku bajtov (uzol takéto dáta
        // neprijíma, takže to nastane len pri ručne vpísanom zázname)
        Err(_) => json!({ "body_len": env.body_bytes.len() }),
    };
    json!({
        "hash_hex": to_hex(env.hash().as_slice()),
        "channel_hex": to_hex(&env.stamp.channel),
        "node_epoch": env.stamp.node_epoch,
        "node_seq": env.stamp.node_seq,
        "kind": kind_name(env.kind),
        "author_hex": env.author.hex(),
        "body_hash_hex": to_hex(env.body_hash.as_slice()),
        // po erase je slepý hash NIL — práve táto nula v odpovedi je dôkaz,
        // že bez obsahu už nič neindexuje (D-30)
        "blind_hash_hex": to_hex(env.blind_hash.as_slice()),
        "content": content,
    })
}

/// `GET /records/{hash}` — **surový log** pod kanonickým identifikátorom
/// (B6). Vráti to, čo uzol o zázname skutočne drží: druh, autora, pozíciu
/// a dekódovaný obsah. Po erase tu preto vidíme prázdny obsah + dôvod.
///
/// Pozor na význam hashu: identifikátor je BLAKE3 bajtov, takže **po erase
/// má záznam nový hash** a ten starý už v logu nie je (404). Ak chcete
/// vidieť, čo čitateľ naozaj dostane, použite `GET /channels/{id}/records`.
pub async fn get_record(
    State(store): State<SharedStore>,
    Path(hex_hash): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let hash = RecordHash(parse_id32(&hex_hash)?);
    let raw = lock(&store)
        .get(&hash)?
        .ok_or_else(|| ApiError::not_found("záznam neexistuje"))?;
    let env = Envelope::decode(&raw).map_err(|e| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("poškodená obálka v logu: {e:?}"),
        )
    })?;
    Ok(Json(record_json(&env)))
}

/// Dotaz na čítací pohľad: `?from_epoch=&from_seq=&limit=&reader=<hex kľúča>`.
#[derive(Debug, Deserialize)]
pub struct RecordsQuery {
    #[serde(default)]
    from_epoch: Option<u64>,
    #[serde(default)]
    from_seq: Option<u64>,
    #[serde(default)]
    limit: Option<u32>,
    /// Hex device kľúča čitateľa — podľa neho sa vyhodnotí `hide` (D-30).
    /// Bez neho sa hide nevylučuje, lebo REST relácia nemá autentizáciu a
    /// skryté je len pre autora hide záznamu.
    #[serde(default)]
    reader: Option<String>,
}

/// `GET /channels/{id}/records` — **čítací pohľad** na kanál (B6, D-30):
/// surový log po vyhodnotení mazacích kindov. Tombstonovaný cieľ sa tu už
/// neobjaví, erase cieľ sa objaví s práznym obsahom a dôvodom a hide
/// vyfiltruje len záznamy, ktoré skryl `reader`.
pub async fn list_channel_records(
    State(store): State<SharedStore>,
    Path(hex_id): Path<String>,
    Query(q): Query<RecordsQuery>,
) -> Result<Json<Value>, ApiError> {
    let channel: ChannelId = parse_id32(&hex_id)?;
    let reader = q
        .reader
        .as_deref()
        .map(|r| {
            parse_id32(r).map_err(|_| ApiError::bad_request("reader nie je hex 32B kľúč"))
        })
        .transpose()?;
    let limit = q.limit.unwrap_or(RECORDS_DEFAULT_LIMIT).min(RECORDS_MAX_LIMIT);
    let query = RangeQuery {
        channel,
        // watermark je najvyššia aplikovaná pozícia (D-29), ale tu je
        // parameter „od“ — default je od seq 1, teda „pošli celý kanál“
        from_epoch: q.from_epoch.unwrap_or(0),
        from_seq: q.from_seq.unwrap_or(1),
        limit,
    };
    let rows = lock(&store).visible_range(&query, reader.as_ref())?;
    let items: Vec<Value> = rows
        .iter()
        .map(|(pos, raw)| match Envelope::decode(raw) {
            Ok(env) => json!({
                "epoch": pos.node_epoch,
                "seq": pos.node_seq,
                "record": record_json(&env),
            }),
            Err(_) => json!({
                "epoch": pos.node_epoch,
                "seq": pos.node_seq,
                "error": "poškodená obálka",
            }),
        })
        .collect();
    Ok(Json(json!({
        "channel_hex": to_hex(&channel),
        "from_epoch": query.from_epoch,
        "from_seq": query.from_seq,
        "limit": limit,
        "reader_hex": reader.as_ref().map(|r| to_hex(&r[..])),
        "count": items.len(),
        "records": items,
    })))
}

// ===========================================================================
// F14a (MYHSN-56): správa rolí, nastavenia politiky, pozvánky
// ===========================================================================
//
// Pravidlá (rozhodnutia O15/O16/O17, wiki doc 32):
// - **iba admin** udeľuje/oberá role (žiadna delegácia na moderátora —
//   predišlo by tranzitívnemu eskalovaniu);
// - posledný admin sa nedá odomocniť → 409 `last_admin`;
// - `perms` bitmask platí len pre moderatora, neznáme bity → 400;
// - pozvánky smie tvoriť admin alebo moderator s bitom `INVITE_USERS`,
//   moderator vidí/mazá len vlastné a len nepoužité (O14).

/// Prihlásený aktér REST požiadavky: účet + rola + device kľúč pre audit
/// (`by`/`by_device` v tele GrantRole/RevokeRole).
struct Actor {
    account: AccountId,
    role: u8,
    perms: u32,
    status: u8,
    device: [u8; 32],
}

fn actor(store: &Store, headers: &HeaderMap) -> Result<Actor, ApiError> {
    let account = session_account(store, bearer_token(headers).as_deref())?;
    let (role, perms, status) = store
        .account_role(&account)?
        .ok_or_else(|| ApiError::unauthorized("účet neexistuje"))?;
    let device = store.first_active_device(&account)?.unwrap_or([0u8; 32]);
    Ok(Actor { account, role, perms, status, device })
}

fn require_admin(a: &Actor) -> Result<(), ApiError> {
    if a.status == 1 {
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "ucet cakna na schvalenie",
            "account_pending",
        ));
    }
    if a.role == 2 {
        Ok(())
    } else {
        Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "operacia vyzaduje admina",
            "admin_required",
        ))
    }
}

/// Admin, alebo moderátor s konkrétnym bitom (`INVITE_USERS`…).
fn require_perm(a: &Actor, bit: u32, what: &str) -> Result<(), ApiError> {
    if a.status == 1 {
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "ucet cakna na schvalenie",
            "account_pending",
        ));
    }
    let allowed = a.role == 2 || (a.role == 1 && (a.perms & bit) != 0);
    if allowed {
        Ok(())
    } else {
        Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            format!("operacia vyzaduje opravnenie {what}"),
            "insufficient_perms",
        ))
    }
}

fn admin_user_json(u: &crate::store::AdminUserRow) -> Value {
    json!({
        "account_id": to_hex(&u.id),
        "username": u.username,
        "role": role_code_name(u.role),
        "role_code": u.role,
        "perms": u.perms,
        "pending": u.status == 1,
        "created": u.created,
    })
}

/// `GET /admin/users` — kompletný zoznam účtov aj s rolami (admin).
pub async fn admin_users(
    State(store): State<SharedStore>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let store = lock(&store);
    let who = actor(&store, &headers)?;
    require_admin(&who)?;
    let users = store.list_users_admin()?;
    Ok(Json(json!({ "users": users.iter().map(admin_user_json).collect::<Vec<_>>() })))
}

/// `DELETE /admin/users/{id}` — **reject** čakajúceho účtu (Z2): vymaže
/// ho a uvoľní meno. Aktívny účet sa týmto mazať nedá (história logu
/// viaže na author kľúče — archivácia je úloha budúcich verzií).
pub async fn admin_user_delete(
    State(store): State<SharedStore>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let target = parse_id32(&id)?;
    let mut store = lock(&store);
    let who = actor(&store, &headers)?;
    require_admin(&who)?;
    let (_role, _perms, status) = store
        .account_role(&target)?
        .ok_or_else(|| ApiError::not_found("ucet neexistuje"))?;
    if status != 1 {
        return Err(ApiError::coded(
            StatusCode::BAD_REQUEST,
            "mazat sa daju len cakajuce ucty (schvalenie je grant role)",
            "not_pending",
        ));
    }
    store.delete_account(&target)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Telo `POST /admin/roles`: `{account, role, perms?}` alebo
/// `{account, revoke: true}`. `account` je meno **alebo** hex id (Z3).
#[derive(Debug, Deserialize)]
pub struct RoleChangeRequest {
    pub account: String,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub perms: Option<u64>,
    #[serde(default)]
    pub revoke: Option<bool>,
}

/// `POST /admin/roles` — grant/revoke role; zápis do účtu aj audit do
/// systémového kanála v jednej transakcii, potom WS push (`RoleUpdate`
/// + auditný `Record`) reláciám s capom `"roles"`.
pub async fn admin_roles(
    State(store): State<SharedStore>,
    Extension(ws): Extension<Option<crate::ws::WsBroadcaster>>,
    headers: HeaderMap,
    Json(req): Json<RoleChangeRequest>,
) -> Result<Json<Value>, ApiError> {
    use myhsn_core::roles::Role;
    let revoke = req.revoke.unwrap_or(false);
    // cieľová rola: revoke → user; inak povinné meno role
    let new_role = if revoke {
        Role::User
    } else {
        let name = req
            .role
            .as_deref()
            .ok_or_else(|| ApiError::bad_request("chýba role (user|moderator|admin)"))?;
        Role::from_name(name.trim().to_ascii_lowercase().as_str())
            .ok_or_else(|| ApiError::bad_request("role musi byt user|moderator|admin"))?
    };
    // perms: povolené len pre moderatora; neznáme bity odmietneme (O17)
    let perms = req.perms.unwrap_or(0);
    if perms > u64::from(u32::MAX) {
        return Err(ApiError::bad_request("perms musi byt 32-bit bitmaska"));
    }
    let perms = perms as u32;
    if perms != 0 && new_role != Role::Moderator {
        return Err(ApiError::coded(
            StatusCode::BAD_REQUEST,
            "perms sa davaju len moderatorovi",
            "perms_not_moderator",
        ));
    }
    if !myhsn_core::roles::perms_valid(perms) {
        return Err(ApiError::coded(
            StatusCode::BAD_REQUEST,
            "perms obsahuje nezname bity",
            "perms_unknown_bits",
        ));
    }

    let mut store = lock(&store);
    let who = actor(&store, &headers)?;
    require_admin(&who)?;
    let target = store
        .resolve_account(req.account.trim())?
        .ok_or_else(|| ApiError::not_found("ucet neexistuje"))?;

    let env = match store.apply_role_change(
        &target.id,
        new_role.code(),
        perms,
        revoke,
        Some((who.account, who.device)),
    ) {
        Ok(env) => env,
        Err(crate::store::RoleError::NoSuchAccount) => {
            return Err(ApiError::not_found("ucet neexistuje"))
        }
        Err(crate::store::RoleError::LastAdmin) => {
            return Err(ApiError::coded(
                StatusCode::CONFLICT,
                "posledny admin sa neda odomocnit",
                "last_admin",
            ))
        }
        Err(crate::store::RoleError::Store(e)) => return Err(ApiError::from(e)),
    };

    // push PO commite (O8): audit záznam + RoleUpdate len cap-"roles"
    if let Some(ws) = ws {
        ws.broadcast_system_record(&env.encode());
        ws.broadcast_role_update(target.id, &target.username, new_role.name(), perms as u64);
    }

    Ok(Json(json!({
        "account_id": to_hex(&target.id),
        "username": target.username,
        "role": new_role.name(),
        "perms": if new_role == Role::Moderator { perms } else { 0 },
        "pending": false,
        "audit_hash": to_hex(env.hash().as_slice()),
    })))
}

/// `GET /admin/settings` — efektívna politika + odkiaľ prichádza (O11).
pub async fn admin_settings_get(
    State(store): State<SharedStore>,
    Extension(cfg): Extension<Arc<crate::roles::AuthConfig>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let store = lock(&store);
    let who = actor(&store, &headers)?;
    require_admin(&who)?;
    let raw_override = store.policy_override()?;
    let (policy, source) = match raw_override.as_deref() {
        Some(raw) if raw.parse::<crate::roles::RegistrationPolicy>().is_ok() => {
            (raw.parse().unwrap(), "meta")
        }
        _ => (cfg.registration_policy, "config"),
    };
    Ok(Json(json!({
        "registration_policy": policy.to_string(),
        "source": source,
        "config_value": cfg.registration_policy.to_string(),
        "bootstrap_admin": cfg.bootstrap_admin,
    })))
}

/// Telo `PUT /admin/settings`.
#[derive(Debug, Deserialize)]
pub struct SettingsRequest {
    pub registration_policy: String,
}

/// `PUT /admin/settings` — runtime override politiky (meta). Reštart
/// uzla nie je potrebný; TOML ostáva deklarovaný stav.
pub async fn admin_settings_put(
    State(store): State<SharedStore>,
    headers: HeaderMap,
    Json(req): Json<SettingsRequest>,
) -> Result<Json<Value>, ApiError> {
    let policy = req.registration_policy.parse::<crate::roles::RegistrationPolicy>().map_err(
        |e| ApiError::coded(StatusCode::BAD_REQUEST, e, "invalid_policy"),
    )?;
    let mut store = lock(&store);
    let who = actor(&store, &headers)?;
    require_admin(&who)?;
    store.set_policy_override(Some(policy.as_str()))?;
    Ok(Json(json!({ "registration_policy": policy.to_string(), "source": "meta" })))
}

/// `DELETE /admin/settings` — zruší override, vracia sa k TOML.
pub async fn admin_settings_delete(
    State(store): State<SharedStore>,
    Extension(cfg): Extension<Arc<crate::roles::AuthConfig>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let mut store = lock(&store);
    let who = actor(&store, &headers)?;
    require_admin(&who)?;
    store.set_policy_override(None)?;
    Ok(Json(json!({
        "registration_policy": cfg.registration_policy.to_string(),
        "source": "config",
    })))
}

/// Telo `POST /invites` — voliteľné `label` a `expires_in` (sekundy).
#[derive(Debug, Deserialize)]
pub struct InviteCreateRequest {
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
}

fn invite_json(i: &crate::store::InviteRow) -> Value {
    json!({
        "id": i.id,
        "label": i.label,
        "created_by": to_hex(&i.created_by),
        "created_at": i.created_at,
        "expires_at": i.expires_at,
        "used": i.used_by.is_some(),
        "used_by": i.used_by.map(|b| to_hex(&b)),
        "used_at": i.used_at,
    })
}

/// `POST /invites` — nová jednorazová pozvánka; token sa vráti len raz.
pub async fn invites_create(
    State(store): State<SharedStore>,
    headers: HeaderMap,
    Json(req): Json<InviteCreateRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let mut store = lock(&store);
    let who = actor(&store, &headers)?;
    require_perm(&who, myhsn_core::roles::INVITE_USERS, "invite_users")?;
    let now = now_secs();
    let expires_at = req.expires_in.map(|s| now.saturating_add(s));
    let (id, token) = store.create_invite(req.label, who.account, now, expires_at)?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": id,
            "token": to_hex(&token),
            "expires_at": expires_at,
        })),
    ))
}

/// `GET /invites` — admin vidí všetky, moderator s bitom len vlastné.
pub async fn invites_list(
    State(store): State<SharedStore>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let store = lock(&store);
    let who = actor(&store, &headers)?;
    require_perm(&who, myhsn_core::roles::INVITE_USERS, "invite_users")?;
    let filter = if who.role == 2 { None } else { Some(who.account) };
    let invites = store.list_invites(filter.as_ref())?;
    Ok(Json(json!({ "invites": invites.iter().map(invite_json).collect::<Vec<_>>() })))
}

/// `DELETE /invites/{id}` — zruší nepoužitú pozvánku (admin všetky,
/// moderator len vlastné; použitá sa zrušiť nedá, O14).
pub async fn invites_delete(
    State(store): State<SharedStore>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let mut store = lock(&store);
    let who = actor(&store, &headers)?;
    require_perm(&who, myhsn_core::roles::INVITE_USERS, "invite_users")?;
    let deleted = store.delete_invite(id, &who.account, who.role == 2)?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::coded(
            StatusCode::NOT_FOUND,
            "pozvanka neexistuje alebo uz bola pouzita",
            "invite_not_deletable",
        ))
    }
}

// ===========================================================================
// F14c (MYHSN-58): skupinové kanály — členstvo, per-kanálové role,
// stíšenie a prenechanie ownera. Rozhodnutia + kontrakt: wiki doc 1011 §5,
// strojové kódy sú záväzné pre klienta (rozhodnutie §10).
// ===========================================================================

/// Mapovanie chýb operácií so skupinami na REST kontrakt. Klient sa
/// rozhoduje podľa **strojového kódu**, slovenská veta je pomôcka človeku.
fn channel_error(e: crate::store::ChannelError) -> ApiError {
    use crate::store::ChannelError as E;
    match e {
        E::Store(err) => ApiError::from(err),
        E::NoSuchChannel => {
            ApiError::coded(StatusCode::NOT_FOUND, "kanal neexistuje", "channel_not_found")
        }
        E::NotGroupChannel => ApiError::coded(
            StatusCode::CONFLICT,
            "kanal nie je skupinovy — nema ownera ani zoznam clenov",
            "not_group_channel",
        ),
        E::NoSuchAccount => {
            ApiError::coded(StatusCode::NOT_FOUND, "ucet neexistuje", "account_not_found")
        }
        E::AccountInactive => {
            ApiError::coded(StatusCode::CONFLICT, "ucet nie je aktivny", "account_inactive")
        }
        E::AlreadyMember => {
            ApiError::coded(StatusCode::CONFLICT, "ucet uz je clen kanala", "already_member")
        }
        E::NotMember => {
            ApiError::coded(StatusCode::NOT_FOUND, "ucet nie je clen kanala", "not_member")
        }
        E::OwnerCannotBeRemoved => ApiError::coded(
            StatusCode::CONFLICT,
            "ownera nemoze odobrat — group kanál musi mat ownera, pouzi transfer",
            "owner_must_transfer",
        ),
        E::AlreadyOwner => {
            ApiError::coded(StatusCode::CONFLICT, "ucet uz je owner kanala", "already_owner")
        }
        // `owner_not_mutable` nie je v pôvodnom zozname kódov — pridávame ho
        // tu a dokumentujeme (rozhodnutie §7: ownera stíšiť nemožno)
        E::OwnerNotMutable => ApiError::coded(
            StatusCode::CONFLICT,
            "ownera nemoze stisit — stisi sa len clen (member/admin)",
            "owner_not_mutable",
        ),
        E::NotMuted => ApiError::coded(StatusCode::NOT_FOUND, "ucet nie je stiseny", "not_muted"),
        E::InvalidRole => ApiError::coded(
            StatusCode::BAD_REQUEST,
            "role musi byt member alebo admin",
            "invalid_role",
        ),
    }
}

/// `actor` pre F14c koncovky: 401 má strojový kód `auth_required`
/// (rozhodnutie §10), nie plain-text ako staré koncovky z B4.
fn actor_channel(store: &Store, headers: &HeaderMap) -> Result<Actor, ApiError> {
    actor(store, headers).map_err(|e| {
        if e.status == StatusCode::UNAUTHORIZED {
            ApiError::coded(StatusCode::UNAUTHORIZED, e.message, "auth_required")
        } else {
            e
        }
    })
}

/// **F14c:** spravuje členstvo, role, stíšenie aj obálku kanála? Owner a
/// channel admin (len v group kanáli), server admin, alebo moderator s
/// `MANAGE_CHANNELS` — server-level práva platia v **každom** kanáli
/// (rozhodnutie §6).
fn can_manage_channel(a: &Actor, auth: &store::ChannelAuthority) -> bool {
    a.role == 2
        || (a.role == 1 && (a.perms & myhsn_core::roles::MANAGE_CHANNELS) != 0)
        || matches!(auth.role, Some(1) | Some(2))
}

/// **F14c:** iniciuje prenechanie ownera? Rozhodnutie §8: súčasný owner,
/// server admin, alebo moderator s `MANAGE_CHANNELS`. Channel admin SEM
/// nesmie — inak by si ownera vymenoval sám.
fn can_transfer_channel(a: &Actor, auth: &store::ChannelAuthority) -> bool {
    a.role == 2
        || (a.role == 1 && (a.perms & myhsn_core::roles::MANAGE_CHANNELS) != 0)
        || auth.owner == Some(a.account)
}

/// Načítaj group kanál a právomoc volajúceho; zjednotí kódy
/// `channel_not_found` (404) a `not_group_channel` (409) pre všetky
/// F14c koncovky, aby sa nedali rozísť.
fn load_group_channel(
    store: &Store,
    channel: &ChannelId,
    who: &Actor,
) -> Result<store::ChannelAuthority, ApiError> {
    let auth = store
        .channel_authority(channel, &who.account)?
        .ok_or_else(|| {
            ApiError::coded(StatusCode::NOT_FOUND, "kanal neexistuje", "channel_not_found")
        })?;
    if !auth.group {
        return Err(ApiError::coded(
            StatusCode::CONFLICT,
            "kanal nie je skupinovy — nema ownera ani zoznam clenov",
            "not_group_channel",
        ));
    }
    Ok(auth)
}

/// Riadok `GET /channels/{id}/members`. `muted` je pohodlná boolean
/// pomôcka (klient by si ju počítal z `muted_until`), preto ju posielame
/// už vyčíslenú — a `muted_until` ostáva v odpovedi ako zdroj pravdy.
fn member_json(m: &store::ChannelMemberRow, now: u64) -> Value {
    json!({
        "account": to_hex(&m.account),
        "username": m.username,
        "role": channel_role_name(m.role),
        "role_code": m.role,
        "added_by": m.added_by.map(|b| to_hex(&b)),
        "joined_at": m.joined_at,
        "muted_until": m.muted_until,
        "muted": m.muted_until.map(|t| t > now).unwrap_or(false),
    })
}

/// Telo `POST /channels/{id}/members` — `{account}` (meno alebo hex id,
/// rovnako ako F14a admin koncovky, rozhodnutie Z3).
#[derive(Debug, Deserialize)]
pub struct ChannelMemberRequest {
    pub account: String,
}

/// Telo `PUT /channels/{id}/members/{acct}` — `{role: member|admin}`.
#[derive(Debug, Deserialize)]
pub struct ChannelRoleRequest {
    pub role: String,
}

/// Telo `POST /channels/{id}/transfer` — `{account, previous_role?}`.
/// `previous_role ∈ admin|member|none` (default `admin`, rozhodnutie §8).
#[derive(Debug, Deserialize)]
pub struct ChannelTransferRequest {
    pub account: String,
    #[serde(default)]
    pub previous_role: Option<String>,
}

/// Telo `POST /channels/{id}/mute` — `{account, duration_secs?}`
/// (default 3600 s, rozhodnutie §7).
#[derive(Debug, Deserialize)]
pub struct ChannelMuteRequest {
    pub account: String,
    #[serde(default)]
    pub duration_secs: Option<i64>,
}

/// Default dĺžka stíšenia (rozhodnutie F14c §7).
pub const DEFAULT_MUTE_SECS: i64 = 3600;
/// Strop dĺžky stíšenia: 30 dní. Bez stropu by jeden zlý klient „stíšil
/// navždy“ a materializovaný stav bez auditu sa nedá dohľadať.
pub const MAX_MUTE_SECS: i64 = 30 * 24 * 3600;

/// `GET /channels/{id}/members` — **verejný** zoznam členov group kanála
/// (spoločenská sieť: kto v skupine je, je verejné). S Bearer odpoveď
/// pridá `my_role`; neplatný Bearer je anonym, nie chyba (rozhodnutie §10).
pub async fn channel_members(
    State(store): State<SharedStore>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let channel = parse_id32(&id)?;
    let store = lock(&store);
    let owner = store
        .channel_owner(&channel)?
        .ok_or_else(|| {
            ApiError::coded(StatusCode::NOT_FOUND, "kanal neexistuje", "channel_not_found")
        })?
        .ok_or_else(|| {
            ApiError::coded(
                StatusCode::CONFLICT,
                "kanal nie je skupinovy — nema ownera ani zoznam clenov",
                "not_group_channel",
            )
        })?;
    let members = store.channel_members(&channel)?;
    let owner_name = store
        .account_by_id(&owner)?
        .map(|a| a.username)
        .unwrap_or_default();
    let caller = bearer_token(&headers).and_then(|t| session_account(&store, Some(&t)).ok());
    let my_role = match caller {
        Some(acc) => store
            .channel_authority(&channel, &acc)?
            .and_then(|a| a.role)
            .map(channel_role_name),
        None => None,
    };
    let now = now_secs();
    Ok(Json(json!({
        "channel": to_hex(&channel),
        "group": true,
        "owner": {
            "account": to_hex(&owner),
            "username": owner_name,
            "role": "owner",
            "muted": false,
        },
        "members": members.iter().map(|m| member_json(m, now)).collect::<Vec<_>>(),
        "my_role": my_role,
    })))
}

/// `POST /channels/{id}/members` — pridaj **membera** (channel admin+,
/// server admin alebo `MANAGE_CHANNELS` moderator). 409 `already_member`,
/// 404 `account_not_found`, 409 `account_inactive`.
pub async fn channel_member_add(
    State(store): State<SharedStore>,
    Extension(ws): Extension<Option<crate::ws::WsBroadcaster>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<ChannelMemberRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let channel = parse_id32(&id)?;
    let mut store = lock(&store);
    let who = actor_channel(&store, &headers)?;
    let auth = load_group_channel(&store, &channel, &who)?;
    if !can_manage_channel(&who, &auth) {
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "operacia vyzaduje channel admina alebo ownera",
            "not_channel_admin",
        ));
    }
    let target = store
        .resolve_account(req.account.trim())?
        .ok_or_else(|| {
            ApiError::coded(StatusCode::NOT_FOUND, "ucet neexistuje", "account_not_found")
        })?;
    let env = store
        .channel_add_member(&channel, &target.id, (who.account, who.device))
        .map_err(channel_error)?;
    drop(store);
    if let Some(ws) = ws {
        ws.broadcast_group_record(&env.encode());
        ws.broadcast_channel_role_update(channel, target.id, &target.username, "member", false);
    }
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "channel": to_hex(&channel),
            "account": to_hex(&target.id),
            "username": target.username,
            "role": "member",
            "audit_hash": to_hex(env.hash().as_slice()),
        })),
    ))
}

/// `DELETE /channels/{id}/members/{acct}` — odober člena. **Self-leave**
/// smie hociktorý člen (owner nie — 409 `owner_must_transfer`); cudzieho
/// člena odoberie len správca kanála s **prísne vyššou hodnosťou**
/// (rozhodnutie §6).
pub async fn channel_member_remove(
    State(store): State<SharedStore>,
    Extension(ws): Extension<Option<crate::ws::WsBroadcaster>>,
    headers: HeaderMap,
    Path((id, acct)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let channel = parse_id32(&id)?;
    let mut store = lock(&store);
    let who = actor_channel(&store, &headers)?;
    let auth = load_group_channel(&store, &channel, &who)?;
    let target = store
        .resolve_account(acct.trim())?
        .ok_or_else(|| {
            ApiError::coded(StatusCode::NOT_FOUND, "ucet neexistuje", "account_not_found")
        })?;
    let self_leave = target.id == who.account;
    if !self_leave {
        if !can_manage_channel(&who, &auth) {
            return Err(ApiError::coded(
                StatusCode::FORBIDDEN,
                "operacia vyzaduje channel admina alebo ownera",
                "not_channel_admin",
            ));
        }
        let target_auth = store
            .channel_authority(&channel, &target.id)?
            .ok_or_else(|| {
                ApiError::coded(StatusCode::NOT_FOUND, "kanal neexistuje", "channel_not_found")
            })?;
        if auth.rank() <= target_auth.rank() {
            return Err(ApiError::coded(
                StatusCode::FORBIDDEN,
                "clena s rovnakou alebo vyssou hodnostou nemoze odobrat rovnaky clanok",
                "insufficient_perms",
            ));
        }
    }
    let env = store
        .channel_revoke_member(&channel, &target.id, (who.account, who.device))
        .map_err(channel_error)?;
    drop(store);
    if let Some(ws) = ws {
        ws.broadcast_group_record(&env.encode());
        ws.broadcast_channel_role_update(channel, target.id, &target.username, "none", false);
    }
    Ok(Json(json!({
        "channel": to_hex(&channel),
        "account": to_hex(&target.id),
        "role": "none",
        "left": self_leave,
        "audit_hash": to_hex(env.hash().as_slice()),
    })))
}

/// `PUT /channels/{id}/members/{acct}` — `member` ↔ `admin`. Rola `owner`
/// je 400 `use_transfer` (ownera mení len transfer, rozhodnutie §8);
/// neznáme meno role je 400 `invalid_role`.
pub async fn channel_member_set_role(
    State(store): State<SharedStore>,
    Extension(ws): Extension<Option<crate::ws::WsBroadcaster>>,
    headers: HeaderMap,
    Path((id, acct)): Path<(String, String)>,
    Json(req): Json<ChannelRoleRequest>,
) -> Result<Json<Value>, ApiError> {
    use myhsn_core::roles::ChannelRole;
    let channel = parse_id32(&id)?;
    let role = ChannelRole::from_name(req.role.trim()).ok_or_else(|| {
        ApiError::coded(
            StatusCode::BAD_REQUEST,
            "role musi byt member alebo admin",
            "invalid_role",
        )
    })?;
    if role == ChannelRole::Owner {
        return Err(ApiError::coded(
            StatusCode::BAD_REQUEST,
            "ownera meni len POST /channels/{id}/transfer",
            "use_transfer",
        ));
    }
    let mut store = lock(&store);
    let who = actor_channel(&store, &headers)?;
    let auth = load_group_channel(&store, &channel, &who)?;
    if !can_manage_channel(&who, &auth) {
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "operacia vyzaduje channel admina alebo ownera",
            "not_channel_admin",
        ));
    }
    let target = store
        .resolve_account(acct.trim())?
        .ok_or_else(|| {
            ApiError::coded(StatusCode::NOT_FOUND, "ucet neexistuje", "account_not_found")
        })?;
    let target_auth = store
        .channel_authority(&channel, &target.id)?
        .ok_or_else(|| {
            ApiError::coded(StatusCode::NOT_FOUND, "kanal neexistuje", "channel_not_found")
        })?;
    if auth.rank() <= target_auth.rank() {
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "rolu moze menit len ten s prísne vyššou hodnosťou",
            "insufficient_perms",
        ));
    }
    let env = store
        .channel_set_role(&channel, &target.id, role.code(), (who.account, who.device))
        .map_err(channel_error)?;
    drop(store);
    if let Some(ws) = ws {
        ws.broadcast_group_record(&env.encode());
        ws.broadcast_channel_role_update(
            channel,
            target.id,
            &target.username,
            role.name(),
            target_auth.muted(now_secs()),
        );
    }
    Ok(Json(json!({
        "channel": to_hex(&channel),
        "account": to_hex(&target.id),
        "username": target.username,
        "role": role.name(),
        "audit_hash": to_hex(env.hash().as_slice()),
    })))
}

/// `POST /channels/{id}/transfer` — prenechaj ownera (rozhodnutie §8).
/// Iniciuje owner, server admin alebo `MANAGE_CHANNELS` moderator; cieľ je
/// aktívny účet (ak nie je člen, transfer ho pridá). 409 `already_owner`.
pub async fn channel_transfer(
    State(store): State<SharedStore>,
    Extension(ws): Extension<Option<crate::ws::WsBroadcaster>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<ChannelTransferRequest>,
) -> Result<Json<Value>, ApiError> {
    let channel = parse_id32(&id)?;
    // `previous_role`: default `admin` (rozhodnutie §8), `none` = odchod
    let prev_role = match req.previous_role.as_deref().map(str::trim).unwrap_or("admin") {
        "admin" => 1u8,
        "member" => 0u8,
        "none" => u8::MAX,
        _ => {
            return Err(ApiError::coded(
                StatusCode::BAD_REQUEST,
                "previous_role musi byt admin | member | none",
                "invalid_role",
            ))
        }
    };
    let mut store = lock(&store);
    let who = actor_channel(&store, &headers)?;
    let auth = load_group_channel(&store, &channel, &who)?;
    if !can_transfer_channel(&who, &auth) {
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "ownera moze prenechat len owner, server admin alebo moderator s manage_channels",
            "not_channel_owner",
        ));
    }
    let previous_owner = auth.owner.unwrap_or([0u8; 32]);
    let previous_name = store
        .account_by_id(&previous_owner)?
        .map(|a| a.username)
        .unwrap_or_default();
    let target = store
        .resolve_account(req.account.trim())?
        .ok_or_else(|| {
            ApiError::coded(StatusCode::NOT_FOUND, "ucet neexistuje", "account_not_found")
        })?;
    let env = store
        .channel_transfer_owner(&channel, &target.id, prev_role, (who.account, who.device))
        .map_err(channel_error)?;
    drop(store);
    if let Some(ws) = ws {
        ws.broadcast_group_record(&env.encode());
        ws.broadcast_channel_role_update(channel, target.id, &target.username, "owner", false);
        ws.broadcast_channel_role_update(
            channel,
            previous_owner,
            &previous_name,
            channel_role_name(prev_role),
            false,
        );
    }
    Ok(Json(json!({
        "channel": to_hex(&channel),
        "owner": to_hex(&target.id),
        "owner_username": target.username,
        "previous_owner": to_hex(&previous_owner),
        "previous_role": channel_role_name(prev_role),
        "audit_hash": to_hex(env.hash().as_slice()),
    })))
}

/// `POST /channels/{id}/mute` — stíš člena (rozhodnutie §7). Channel admin+
/// alebo server-level správca, cieľ musí mať **prísne nižšiu hodnosť**;
/// owner sa stíšiť nedá (409 `owner_not_mutable`).
pub async fn channel_mute(
    State(store): State<SharedStore>,
    Extension(ws): Extension<Option<crate::ws::WsBroadcaster>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<ChannelMuteRequest>,
) -> Result<Json<Value>, ApiError> {
    let channel = parse_id32(&id)?;
    let duration = req.duration_secs.unwrap_or(DEFAULT_MUTE_SECS);
    if duration <= 0 || duration > MAX_MUTE_SECS {
        return Err(ApiError::bad_request(format!(
            "duration_secs musi byt 1..={MAX_MUTE_SECS}"
        )));
    }
    let mut store = lock(&store);
    let who = actor_channel(&store, &headers)?;
    let auth = load_group_channel(&store, &channel, &who)?;
    if !can_manage_channel(&who, &auth) {
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "stisit moze len channel admin alebo owner",
            "not_channel_admin",
        ));
    }
    let target = store
        .resolve_account(req.account.trim())?
        .ok_or_else(|| {
            ApiError::coded(StatusCode::NOT_FOUND, "ucet neexistuje", "account_not_found")
        })?;
    let target_auth = store
        .channel_authority(&channel, &target.id)?
        .ok_or_else(|| {
            ApiError::coded(StatusCode::NOT_FOUND, "kanal neexistuje", "channel_not_found")
        })?;
    // owner sa stíšiť nedá **nikdy** (rozhodnutie §7) — tento kód je
    // presnejší než pravidlo hodností, preto ide pred ním
    if target_auth.role == Some(2) {
        return Err(ApiError::coded(
            StatusCode::CONFLICT,
            "ownera nemoze stisit — stisi sa len clen (member/admin)",
            "owner_not_mutable",
        ));
    }
    if auth.rank() <= target_auth.rank() {
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "stisit moze len ten s prísne vyššou hodnosťou",
            "insufficient_perms",
        ));
    }
    let now = now_secs();
    let until = now.saturating_add(duration as u64);
    store.channel_set_mute(&channel, &target.id, until).map_err(channel_error)?;
    drop(store);
    if let Some(ws) = ws {
        ws.broadcast_channel_role_update(
            channel,
            target.id,
            &target.username,
            channel_role_name(target_auth.role.unwrap_or(0)),
            true,
        );
    }
    Ok(Json(json!({
        "channel": to_hex(&channel),
        "account": to_hex(&target.id),
        "username": target.username,
        "muted_until": until,
        "duration_secs": duration,
    })))
}

/// `DELETE /channels/{id}/mute/{acct}` — zruš stíšenie; 404 `not_muted`,
/// ak účet stíšený nie je.
pub async fn channel_unmute(
    State(store): State<SharedStore>,
    Extension(ws): Extension<Option<crate::ws::WsBroadcaster>>,
    headers: HeaderMap,
    Path((id, acct)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let channel = parse_id32(&id)?;
    let mut store = lock(&store);
    let who = actor_channel(&store, &headers)?;
    let auth = load_group_channel(&store, &channel, &who)?;
    if !can_manage_channel(&who, &auth) {
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "zrusit stíšenie moze len channel admin alebo owner",
            "not_channel_admin",
        ));
    }
    let target = store
        .resolve_account(acct.trim())?
        .ok_or_else(|| {
            ApiError::coded(StatusCode::NOT_FOUND, "ucet neexistuje", "account_not_found")
        })?;
    store.channel_clear_mute(&channel, &target.id).map_err(channel_error)?;
    drop(store);
    if let Some(ws) = ws {
        ws.broadcast_channel_role_update(channel, target.id, &target.username, "member", false);
    }
    Ok(Json(json!({
        "channel": to_hex(&channel),
        "account": to_hex(&target.id),
        "username": target.username,
        "muted_until": null,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use myhsn_core::record::to_hex;

    fn shared() -> SharedStore {
        Arc::new(Mutex::new(Store::open_in_memory().unwrap()))
    }

    /// `POST /channels` v **legacy** tvare: bez WS pusha, bez Bearer —
    /// presne ako volal koncovku klient pred F14c. Vráti `(status, JSON)`
    /// aby testy mohli kontrolovať aj chybový kód.
    async fn create_ch(
        state: &SharedStore,
        name: &str,
        kind: Option<&str>,
    ) -> (StatusCode, Value) {
        match create_channel(
            State(state.clone()),
            no_ws(),
            HeaderMap::new(),
            Json(CreateChannelRequest {
                name: name.into(),
                kind: kind.map(String::from),
                group: None,
                owner: None,
            }),
        )
        .await
        {
            Ok((status, Json(json))) => (status, json),
            Err(e) => (e.status, json!({ "error": e.message, "code": e.code })),
        }
    }

    /// `GET /channels` s voliteľným `?include_groups=` a Bearer tokenom.
    async fn list_ch(state: &SharedStore, include_groups: Option<&str>, token: Option<&str>) -> Value {
        let q = Query(ListChannelsQuery { include_groups: include_groups.map(String::from) });
        let headers = token.map(bearer_headers).unwrap_or_default();
        let Json(json) = list_channels(State(state.clone()), q, headers).await.unwrap();
        json
    }

    /// `GET /channels` na prázdnom uzle je prázdny zoznam, nie chyba.
    #[tokio::test]
    async fn list_channels_empty_is_ok() {
        let state = shared();
        let body = list_ch(&state, None, None).await;
        assert_eq!(body["channels"].as_array().unwrap().len(), 0);
    }

    /// `POST /channels` vytvorí kanál a `GET /channels` ho ukáže; soľ sa
    /// neuniká (D-25).
    #[tokio::test]
    async fn create_then_list_channel() {
        let state = shared();
        let (status, created) = create_ch(&state, "nastienka", Some("wall")).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(created["name"], "nastienka");
        assert_eq!(created["kind"], "wall");
        assert_eq!(created["node_epoch"], 0);
        assert_eq!(created["id"].as_str().unwrap().len(), 64, "id je hex 32B");

        let list = list_ch(&state, None, None).await;
        let arr = list["channels"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["name"], "nastienka");
        assert!(
            list.to_string().to_lowercase().find("salt").is_none(),
            "soľ slepého hashu sa nesmie objaviť v API (D-25)"
        );
    }

    /// Chat kanál sa vytvorí s druhom `chat`; neznámy druh je 400.
    #[tokio::test]
    async fn create_chat_channel_and_reject_bad_kind() {
        let state = shared();
        let (status, _) = create_ch(&state, "partia", Some("chat")).await;
        assert_eq!(status, StatusCode::CREATED);

        let (err_status, _) = create_ch(&state, "zly", Some("lol")).await;
        assert_eq!(err_status, StatusCode::BAD_REQUEST);
    }

    /// Duplicitný názov → 409 CONFLICT.
    #[tokio::test]
    async fn duplicate_channel_name_conflicts() {
        let state = shared();
        let (first, _) = create_ch(&state, "dvojka", None).await;
        assert_eq!(first, StatusCode::CREATED, "prvý pokus prebehne");
        let (second, _) = create_ch(&state, "dvojka", None).await;
        assert_eq!(second, StatusCode::CONFLICT);
    }

    /// `GET /node/info` má ID uzla, proto verziu a epochy kanálov.
    #[tokio::test]
    async fn node_info_reports_id_proto_and_epochs() {
        let state = shared();
        let (status, _) = create_ch(&state, "nastienka", None).await;
        assert_eq!(status, StatusCode::CREATED);

        let Json(info) = node_info(State(state.clone())).await.unwrap();
        assert_eq!(info["node_id"].as_str().unwrap().len(), 64);
        assert_eq!(info["proto_version"], myhsn_core::PROTO_VERSION as u64);
        assert_eq!(info["node_epoch"], 0);
        let chs = info["channels"].as_array().unwrap();
        assert_eq!(chs.len(), 1);
        assert_eq!(chs[0]["node_epoch"], 0);
        assert_eq!(chs[0]["next_seq"], 1, "alokátor ešte nevydal poradie");

        // ID uzla je stabilný medzi volaniami
        let Json(info2) = node_info(State(state)).await.unwrap();
        assert_eq!(info["node_id"], info2["node_id"]);
    }

    /// Router zostaviteľný (signatúra axum 0.8) — test na stav a cesty.
    #[test]
    fn api_router_builds() {
        let _app = api_router(shared());
    }

    /// Hex pomocník je konzistentný s core.
    #[test]
    fn hex_helper_matches_core() {
        assert_eq!(to_hex(&[0x0a, 0xff]), "0aff");
    }

    // --- B4 (MYHSN-6): register / login / devices ------------------------

    fn device_pub_hex(seed: &[u8; 32]) -> String {
        to_hex(&myhsn_core::identity::public_from_seed(seed))
    }

    /// Požiadaj o register a vráť (status, JSON) — handler voláme priamo,
    /// HTTP vrstvu kryjú integrné WS testy.
    async fn do_register(state: &SharedStore, body: serde_json::Value) -> (StatusCode, Value) {
        match register(
            State(state.clone()),
            Extension(std::sync::Arc::new(crate::roles::AuthConfig::default())),
            Json(serde_json::from_value(body).unwrap()),
        )
        .await
        {
            Ok((status, Json(json))) => (status, json),
            Err(e) => (e.status, json!({ "error": e.message })),
        }
    }

    async fn do_login(state: &SharedStore, body: serde_json::Value) -> (StatusCode, Value) {
        match login(State(state.clone()), Json(serde_json::from_value(body).unwrap())).await {
            Ok(Json(json)) => (StatusCode::OK, json),
            Err(e) => (e.status, json!({ "error": e.message })),
        }
    }

    /// **Kritérium B4:** `POST /register` vytvorí účet + prvý device kľúč
    /// a vráti session token; duplicitný username → **409**.
    #[tokio::test]
    async fn register_creates_account_and_token_duplicate_is_409() {
        let state = shared();
        let (status, body) = do_register(
            &state,
            json!({
                "username": "juraj",
                "password": "hodne-dlhe-heslo",
                "device_pub": device_pub_hex(&[0xa1; 32]),
                "device_label": "mobil",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["account_id"].as_str().unwrap().len(), 64);
        assert_eq!(body["session_token"].as_str().unwrap().len(), 64);
        assert_eq!(body["device"]["label"], "mobil");
        assert!(body["device"]["revoked_at"].is_null());

        // duplicitný username → 409 (kľúč iného účtu môže byť ten istý
        // len pre iné meno; tu je meno duplikát)
        let (status2, _) = do_register(
            &state,
            json!({
                "username": "juraj",
                "password": "ine-heslo-tak-dlhe",
                "device_pub": device_pub_hex(&[0xa2; 32]),
            }),
        )
        .await;
        assert_eq!(status2, StatusCode::CONFLICT, "duplicitný username musí byť 409");
    }

    /// Krátke heslo a zlý formát kľúča → 400 (ešte pred Argonom).
    #[tokio::test]
    async fn register_validates_inputs() {
        let state = shared();
        let (status, _) = do_register(
            &state,
            json!({"username": "x", "password": "krtké", "device_pub": device_pub_hex(&[1; 32])}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "heslo pod minimum → 400");

        let (status, _) = do_register(
            &state,
            json!({"username": "x", "password": "hodne-dlhe-heslo", "device_pub": "deadbe"}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "špatná dĺžka kľúča → 400");
    }

    /// **Kritérium B4:** zlé heslo → **401**; správne heslo vráti token
    /// a neexistujúci účet má rovnaké 401 (žiadna indícia o existencii).
    #[tokio::test]
    async fn login_wrong_password_is_401() {
        let state = shared();
        let (status, body) = do_register(
            &state,
            json!({
                "username": "peto",
                "password": "spravne-heslo123",
                "device_pub": device_pub_hex(&[0xb1; 32]),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let account_id = body["account_id"].clone();

        let (status, ok) = do_login(
            &state,
            json!({"username": "peto", "password": "spravne-heslo123"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ok["account_id"], account_id);
        assert_eq!(ok["session_token"].as_str().unwrap().len(), 64);

        let (status, _) = do_login(&state, json!({"username": "peto", "password": "zle-heslo-123"}))
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "zlé heslo → 401");

        let (status2, unknown) =
            do_login(&state, json!({"username": "nikto", "password": "akekolvek-heslo"})).await;
        assert_eq!(status2, StatusCode::UNAUTHORIZED);
        // rovnaké znenie chyby — existenciu účtu netajíme stavom ani textom
        assert_eq!(unknown["error"], "nespravne meno alebo heslo");
    }

    /// **Kľúčový B4 flow:** dve zariadenia toho istého účtu — druhé
    /// atestuje kľúč cez session token; `GET /devices` ukáže oba;
    /// `DELETE` revokuje a kľúč prestane byť aktívny. Bez tokena → 401.
    #[tokio::test]
    async fn two_devices_attest_list_and_revoke() {
        let state = shared();
        let (status, body) = do_register(
            &state,
            json!({
                "username": "zuzka",
                "password": "heslo-heslo-heslo",
                "device_pub": device_pub_hex(&[0xc1; 32]),
                "device_label": "mobil",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let token = body["session_token"].as_str().unwrap().to_string();
        let first_id = body["device"]["id"].as_i64().unwrap();

        // atest druhého zariadenia cez account_session v tele
        let req: AttestDeviceRequest = serde_json::from_value(json!({
            "device_pub": device_pub_hex(&[0xc2; 32]),
            "label": "notebook",
            "account_session": token,
        }))
        .unwrap();
        let (status, body) =
            attest_device(State(state.clone()), HeaderMap::new(), Json(req)).await.unwrap();
        assert_eq!(status, StatusCode::CREATED);
        let second_id = body["device"]["id"].as_i64().unwrap();
        assert_ne!(first_id, second_id);

        // GET /devices s Bearer hlavičkou — oba kľúče, oba aktívne
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        let Json(listed) = list_devices(State(state.clone()), headers.clone()).await.unwrap();
        assert_eq!(listed["devices"].as_array().unwrap().len(), 2);

        // bez tokena → 401
        let err = list_devices(State(state.clone()), HeaderMap::new()).await.unwrap_err();
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);

        // revokácia druhého zariadenia
        let Json(revoked) =
            revoke_device(State(state.clone()), None, headers.clone(), Path(second_id))
                .await
                .unwrap();
        assert_eq!(revoked["revoked"], second_id);

        // úloža: kľúč 2 už nie je aktívny, kľúč 1 áno (B4 kritérium
        // „revokovaný podpis sa odmietne“ — overuje sa cez tento dotaz)
        let store = lock(&state);
        let pk2 = myhsn_core::identity::public_from_seed(&[0xc2; 32]);
        let pk1 = myhsn_core::identity::public_from_seed(&[0xc1; 32]);
        assert!(store.device_account_if_active(&pk2).unwrap().is_none());
        assert!(store.device_account_if_active(&pk1).unwrap().is_some());
        drop(store);

        // GET po revokácii: záznam ostáva v histórii s revoked_at (D-26)
        let Json(listed) = list_devices(State(state.clone()), headers).await.unwrap();
        let devices = listed["devices"].as_array().unwrap();
        assert_eq!(devices.len(), 2);
        let revoked_row = devices.iter().find(|d| d["id"] == second_id).unwrap();
        assert!(revoked_row["revoked_at"].as_i64().is_some());
    }

    /// Expirovaný/neplatný token → 401 aj pri ateste.
    #[tokio::test]
    async fn attest_with_bad_token_is_401() {
        let state = shared();
        let req: AttestDeviceRequest = serde_json::from_value(json!({
            "device_pub": device_pub_hex(&[0xd1; 32]),
            "account_session": "0000000000000000000000000000000000000000000000000000000000000000",
        }))
        .unwrap();
        let err = attest_device(State(state), HeaderMap::new(), Json(req)).await.unwrap_err();
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }

    // --- B5.1 (MYHSN-19): GET /members -----------------------------------

    /// Nájdi záznam v tele `GET /members` podľa hex kľúča.
    fn member_by_key<'a>(body: &'a Value, hex: &str) -> Option<&'a Value> {
        body["members"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["public_key_hex"] == hex)
    }

    /// Prázdny uzol: `/members` je prázdne pole, nie chyba.
    #[tokio::test]
    async fn members_empty_is_ok() {
        let state = shared();
        let Json(body) = list_members(State(state)).await.unwrap();
        assert_eq!(body["members"].as_array().unwrap().len(), 0);
    }

    /// **Kritérium MYHSN-19:** 2 účty s device keys → obaja v `/members`
    /// (bez auth); atest druhého zariadenia prida záznam (kľúč → záznam);
    /// **revokovaný kľúč z `/members` zmizne.**
    #[tokio::test]
    async fn members_lists_active_keys_and_drops_revoked() {
        let state = shared();
        let (status, anna) = do_register(
            &state,
            json!({
                "username": "anna",
                "password": "hodne-dlhe-heslo",
                "device_pub": device_pub_hex(&[0xe1; 32]),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, _boris) = do_register(
            &state,
            json!({
                "username": "boris",
                "password": "druhe-heslo-dlhe",
                "device_pub": device_pub_hex(&[0xe2; 32]),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        // oba účty, presné kľúče → mená
        let Json(list) = list_members(State(state.clone())).await.unwrap();
        assert_eq!(list["members"].as_array().unwrap().len(), 2);
        assert_eq!(
            member_by_key(&list, &device_pub_hex(&[0xe1; 32]))
                .expect("annin kľúč musí byť v /members")["username"],
            "anna"
        );
        assert_eq!(
            member_by_key(&list, &device_pub_hex(&[0xe2; 32]))
                .expect("borisov kľúč musí byť v /members")["username"],
            "boris"
        );

        // atest druhého zariadenia → účet je v zozname raz za každý aktívny kľúč
        let token = anna["session_token"].as_str().unwrap().to_string();
        let req: AttestDeviceRequest = serde_json::from_value(json!({
            "device_pub": device_pub_hex(&[0xe3; 32]),
            "account_session": token,
        }))
        .unwrap();
        let (status, _) = attest_device(State(state.clone()), HeaderMap::new(), Json(req))
            .await
            .unwrap();
        assert_eq!(status, StatusCode::CREATED);
        let Json(list) = list_members(State(state.clone())).await.unwrap();
        let annas: Vec<&Value> = list["members"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|m| m["username"] == "anna")
            .collect();
        assert_eq!(annas.len(), 2, "dva aktívne kľúče = dva záznamy");

        // revokácia prvého kľúča → zmizne, ostatní ostanú
        let first_id = anna["device"]["id"].as_i64().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        let Json(revoked) = revoke_device(State(state.clone()), None, headers, Path(first_id))
            .await
            .unwrap();
        assert_eq!(revoked["revoked"], first_id);
        let Json(list) = list_members(State(state.clone())).await.unwrap();
        assert_eq!(list["members"].as_array().unwrap().len(), 2, "revokovaný kľúč musí zmiznúť");
        assert!(member_by_key(&list, &device_pub_hex(&[0xe1; 32])).is_none());
        assert_eq!(
            member_by_key(&list, &device_pub_hex(&[0xe3; 32]))
                .expect("druhý annin kľúč musí ostať")["username"],
            "anna"
        );
        assert_eq!(
            member_by_key(&list, &device_pub_hex(&[0xe2; 32]))
                .expect("borisov kľúč musí ostať")["username"],
            "boris"
        );
    }

    // --- B6 (MYHSN-8): čítacie koncovky, rozhodnutie D-30 -----------------

    use myhsn_core::identity::{public_from_seed, DevicePublicKey};
    use myhsn_core::record::{Envelope, NodeStamp, Payload, RecordHash};
    use myhsn_core::seq::SeqPos;
    use myhsn_core::storage::RecordStore;

    /// Autor príspevkov v týchto testoch.
    const B6_SEED: [u8; 32] = [0xb6; 32];

    /// Vloží príspevok priamo do úložne (WS vrstvu kryjú `tests/ws_sync.rs`).
    fn b6_post(store: &SharedStore, channel: [u8; 32], seq: u64, text: &str) -> RecordHash {
        let env = Envelope::build(
            &B6_SEED,
            &Payload::Post { text: text.into(), media_ref: None },
            NodeStamp::new(channel, 0, seq, public_from_seed(&B6_SEED)),
            b"so1",
            None,
        );
        let hash = env.hash();
        store
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .append(&SeqPos::new(channel, 0, seq), &hash, &env.encode())
            .unwrap();
        hash
    }

    /// `GET /records/{hash}` vráti dekódovaný obsah a **404** pre hash,
    /// ktorý už neexistuje — po erase je to očakávaná odpoveď, lebo
    /// identifikátor je hash bajtov (D-25).
    #[tokio::test]
    async fn get_record_shows_content_and_404_after_erase() {
        let state = shared();
        let created = create_ch(&state, "nastienka", Some("wall")).await.1;
        let ch = created["id"].as_str().unwrap().to_string();
        let channel = <[u8; 32]>::try_from(from_hex(&ch).unwrap().as_slice()).unwrap();
        let hash = b6_post(&state, channel, 1, "citlivy obsah");

        let Json(body) = get_record(State(state.clone()), Path(hash.hex())).await.unwrap();
        assert_eq!(body["kind"], "post");
        assert_eq!(body["content"]["text"], "citlivy obsah");
        assert_eq!(body["node_seq"], 1);
        assert_eq!(body["author_hex"], DevicePublicKey::from_seed(&B6_SEED).hex());

        // neznámy hash → 404, nie 500
        assert_eq!(
            get_record(State(state.clone()), Path("ee".repeat(32)))
                .await
                .unwrap_err()
                .status,
            StatusCode::NOT_FOUND
        );
        // zlý tvar → 400
        assert_eq!(
            get_record(State(state.clone()), Path("nie-hex".into()))
                .await
                .unwrap_err()
                .status,
            StatusCode::BAD_REQUEST
        );

        // erase: obsah je preč, dôvod ostáva, starý hash neplatí
        let erase = Envelope::build(
            &B6_SEED,
            &Payload::Erase {
                target: hash.0,
                reason: EraseReason::AuthorRequest,
                target_kind: RecordKind::Post,
            },
            NodeStamp::new(channel, 0, 2, public_from_seed(&B6_SEED)),
            b"so1",
            None,
        );
        {
            let mut s = state.lock().unwrap_or_else(|p| p.into_inner());
            let acc = s
                .create_account("b6", "$argon2id$v=19$m=1,t=1,p=1$c2Fs$c2Fs", 1)
                .unwrap();
            s.attest_device_key(&acc.id, &DevicePublicKey::from_seed(&B6_SEED), "d", 1)
                .unwrap();
            s.insert_record_erasing(
                &SeqPos::new(channel, 0, 2),
                &erase.hash(),
                &erase.encode(),
                None,
                Some((&hash, EraseReason::AuthorRequest)),
            )
            .unwrap();
        }

        assert_eq!(
            get_record(State(state.clone()), Path(hash.hex()))
                .await
                .unwrap_err()
                .status,
            StatusCode::NOT_FOUND,
            "po erase starý identifikátor neplatí"
        );

        // čítací pohľad ukáže nahradený rad s dôvodom — to je dôkaz B6
        let Json(view) = list_channel_records(
            State(state.clone()),
            Path(ch.clone()),
            Query(RecordsQuery { from_epoch: None, from_seq: None, limit: None, reader: None }),
        )
        .await
        .unwrap();
        assert_eq!(view["count"], 1, "vymenený rad + akcia → len vymenený rad");
        let rec = &view["records"][0]["record"];
        assert_eq!(rec["kind"], "erase");
        assert_eq!(rec["content"]["reason"], "author_request");
        assert_eq!(rec["content"]["reason_code"], 1);
        assert_eq!(rec["node_seq"], 1, "pozícia ostáva");
        assert_eq!(rec["blind_hash_hex"], "00".repeat(32), "slepý hash sa ruší (D-30)");
        assert!(
            view.to_string().find("citlivy obsah").is_none(),
            "obsah sa v pohľade nesmie objaviť"
        );
    }

    /// `GET /channels/{id}/records` vyhodnocuje mazanie: tombstone platí pre
    /// každého, hide len pre `reader` device kľúč.
    #[tokio::test]
    async fn channel_records_applies_tombstone_and_per_reader_hide() {
        let state = shared();
        let channel = [0x33; 32];
        {
            let mut s = state.lock().unwrap_or_else(|p| p.into_inner());
            s.create_channel("nastienka", ChannelKind::Wall).unwrap();
        }
        let post = b6_post(&state, channel, 1, "viditelny");
        b6_post(&state, channel, 2, "druhy");

        let query = |reader: Option<String>| RecordsQuery {
            from_epoch: None,
            from_seq: None,
            limit: None,
            reader,
        };
        let read = |reader: Option<String>| {
            let state = state.clone();
            async move {
                list_channel_records(
                    State(state),
                    Path(to_hex(&channel)),
                    Query(query(reader)),
                )
                .await
                .unwrap()
                .0
            }
        };

        // bez mazania: obidva príspevky
        assert_eq!(read(None).await["count"], 2);

        // tombstone prvého → zmizne pre každého
        let ts = Envelope::build(
            &B6_SEED,
            &Payload::Tombstone { target: post.0 },
            NodeStamp::new(channel, 0, 3, public_from_seed(&B6_SEED)),
            b"so1",
            None,
        );
        state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .append(&SeqPos::new(channel, 0, 3), &ts.hash(), &ts.encode())
            .unwrap();
        let kinds: Vec<_> = read(None)
            .await
            .get("records")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["record"]["kind"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(kinds, vec!["post", "tombstone"], "tombstone platí pre každého");

        // hide druhého príspevku od iného kľúča
        let hider_seed = [0x44u8; 32];
        let hider = public_from_seed(&hider_seed);
        let second = state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .channel_hashes(&channel)
            .unwrap()
            .into_iter()
            .find(|(p, _)| p.node_seq == 2)
            .unwrap()
            .1;
        let hide = Envelope::build(
            &hider_seed,
            &Payload::Hide { target: second.0, reason: "nechcem".into() },
            NodeStamp::new(channel, 0, 4, public_from_seed(&B6_SEED)),
            b"so1",
            None,
        );
        state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .append(&SeqPos::new(channel, 0, 4), &hide.hash(), &hide.encode())
            .unwrap();

        // bez čitateľa: hide sa neaplikuje (uzol nevie, kto číta)
        assert_eq!(read(None).await["count"], 3, "post + tombstone + hide");

        // autor hide: druhý príspevok je preč
        let kinds: Vec<_> = read(Some(to_hex(&hider)))
            .await
            .get("records")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["record"]["kind"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(kinds, vec!["tombstone", "hide"], "hide skryl príspevok len jeho");

        // zlý id kanála → 400
        assert_eq!(
            list_channel_records(
                State(state.clone()),
                Path("zzz".into()),
                Query(query(None))
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::BAD_REQUEST
        );
    }

    // --- B8 (MYHSN-22): zlaté JSON, display_name, /me ----------------------

    /// Hlavička s Bearer tokenom pre /me a /me/avatar.
    fn bearer(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        h
    }

    /// **Zlaté JSON (doc 24 §5.5):** `GET /channels` si ponecháva existujúce
    /// kľúče `{id, name, kind, node_epoch}` s rovnakými typmi a **len
    /// pridáva** `cover` (null|objekt) a `meta_version` (číslo). Starý klient
    /// sa nesmie ničim pokaziť.
    #[tokio::test]
    async fn channels_json_is_backward_compatible() {
        let state = shared();
        let _ = create_ch(&state, "nastienka", Some("wall")).await;
        let body = list_ch(&state, None, None).await;
        let item = &body["channels"][0];
        // existujúce kľúče: typy musia sedieť
        assert!(item["id"].is_string(), "id ostáva reťazec");
        assert_eq!(item["id"].as_str().unwrap().len(), 64);
        assert_eq!(item["name"], "nastienka");
        assert_eq!(item["kind"], "wall");
        assert!(item["node_epoch"].is_number(), "node_epoch ostáva číslo");
        // nové kľúče: cover null (bez obálky), meta_version 0
        assert!(item["cover"].is_null(), "bez obálky → cover null");
        assert_eq!(item["meta_version"], 0);
        // soľ stále netečie
        assert!(body.to_string().to_lowercase().find("salt").is_none());
    }

    /// **Zlaté JSON (doc 24 §5.5):** `GET /members` si ponecháva
    /// `{public_key_hex, username}` a pridáva `display_name` + `avatar`.
    #[tokio::test]
    async fn members_json_adds_display_name_and_avatar() {
        let state = shared();
        let (status, body) = do_register(
            &state,
            json!({
                "username": "jano",
                "password": "hodne-dlhe-heslo",
                "device_pub": device_pub_hex(&[0x71; 32]),
                "display_name": "Jano K.",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["display_name"], "Jano K.");
        let Json(members) = list_members(State(state)).await.unwrap();
        let m = &members["members"][0];
        // existujúce kľúče
        assert!(m["public_key_hex"].is_string());
        assert_eq!(m["username"], "jano");
        // nové kľúče
        assert_eq!(m["display_name"], "Jano K.");
        assert!(m["avatar"].is_null(), "bez avatara → null");
    }

    /// **Kritérium B8 (doc 24 §4):** `POST /register` prijme `display_name`;
    /// príliš dlhé (> 40) a riadiace znaky → 400; prázdne → NULL.
    #[tokio::test]
    async fn register_validates_display_name() {
        let state = shared();
        // platné
        let (status, body) = do_register(
            &state,
            json!({
                "username": "ok",
                "password": "hodne-dlhe-heslo",
                "device_pub": device_pub_hex(&[0x81; 32]),
                "display_name": "Pokusník",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["display_name"], "Pokusník");

        // príliš dlhé (41 znakov)
        let long = "x".repeat(41);
        let (status, _) = do_register(
            &state,
            json!({
                "username": "dlhy",
                "password": "hodne-dlhe-heslo",
                "device_pub": device_pub_hex(&[0x82; 32]),
                "display_name": long,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "41 znakov → 400");

        // riadiaci znak
        let (status, _) = do_register(
            &state,
            json!({
                "username": "riadiaci",
                "password": "hodne-dlhe-heslo",
                "device_pub": device_pub_hex(&[0x83; 32]),
                "display_name": "bad\nname",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "nový riadok → 400");

        // prázdne → NULL (400 nie je, uloží sa None)
        let (status, body) = do_register(
            &state,
            json!({
                "username": "prazdne",
                "password": "hodne-dlhe-heslo",
                "device_pub": device_pub_hex(&[0x84; 32]),
                "display_name": "   ",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(body["display_name"].is_null(), "prázdne → null");
    }

    /// **Kritérium B8 (doc 24 §4):** `GET /me` + `PATCH /me` s Bearer
    /// tokenom; bez tokena 401; zmena mena sa prejavi.
    #[tokio::test]
    async fn get_and_patch_me_roundtrip() {
        let state = shared();
        let (status, reg) = do_register(
            &state,
            json!({
                "username": "ja",
                "password": "hodne-dlhe-heslo",
                "device_pub": device_pub_hex(&[0x91; 32]),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let token = reg["session_token"].as_str().unwrap().to_string();

        // GET /me bez mena
        let Json(me) = get_me(State(state.clone()), bearer(&token)).await.unwrap();
        assert_eq!(me["username"], "ja");
        assert!(me["display_name"].is_null());
        assert!(me["avatar"].is_null());
        assert_eq!(me["account_id"], reg["account_id"]);

        // GET /me bez tokena → 401
        let err = get_me(State(state.clone()), HeaderMap::new()).await.unwrap_err();
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);

        // PATCH /me nastaví meno
        let Json(patched) = patch_me(
            State(state.clone()),
            bearer(&token),
            Json(PatchMeRequest {
                display_name: Some("Pokusník".into()),
            }),
        )
        .await
        .unwrap();
        assert_eq!(patched["display_name"], "Pokusník");

        // overenie cez /members
        let Json(members) = list_members(State(state.clone())).await.unwrap();
        assert_eq!(members["members"][0]["display_name"], "Pokusník");

        // PATCH na príliš dlhé → 400
        let err = patch_me(
            State(state.clone()),
            bearer(&token),
            Json(PatchMeRequest {
                display_name: Some("y".repeat(41)),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);

        // PATCH null zmaže
        let Json(cleared) = patch_me(
            State(state),
            bearer(&token),
            Json(PatchMeRequest {
                display_name: None,
            }),
        )
        .await
        .unwrap();
        assert!(cleared["display_name"].is_null());
    }
    // --- F14a (MYHSN-56): roly, politiky, pozvánky cez REST --------------

    fn bearer_headers(token_hex: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_str(&format!("Bearer {token_hex}")).unwrap(),
        );
        h
    }

    fn no_ws() -> Extension<Option<crate::ws::WsBroadcaster>> {
        Extension(None)
    }

    fn auth_ext(cfg: crate::roles::AuthConfig) -> Extension<Arc<crate::roles::AuthConfig>> {
        Extension(Arc::new(cfg))
    }

    /// Zaregistruje účet a vráti (status, JSON, session_token hex).
    async fn reg(
        state: &SharedStore,
        cfg: &crate::roles::AuthConfig,
        body: serde_json::Value,
    ) -> (StatusCode, Value, Option<String>) {
        let (status, resp) = do_register_ext(state, cfg, body).await;
        let token = resp.get("session_token").and_then(|t| t.as_str()).map(String::from);
        (status, resp, token)
    }

    async fn do_register_ext(
        state: &SharedStore,
        cfg: &crate::roles::AuthConfig,
        body: serde_json::Value,
    ) -> (StatusCode, Value) {
        match register(
            State(state.clone()),
            auth_ext(cfg.clone()),
            Json(serde_json::from_value(body).unwrap()),
        )
        .await
        {
            Ok((status, Json(json))) => (status, json),
            Err(e) => (
                e.status,
                json!({ "error": e.message, "code": e.code }),
            ),
        }
    }

    async fn call_roles(
        state: &SharedStore,
        token: &str,
        body: serde_json::Value,
    ) -> (StatusCode, Value) {
        match admin_roles(
            State(state.clone()),
            no_ws(),
            bearer_headers(token),
            Json(serde_json::from_value(body).unwrap()),
        )
        .await
        {
            Ok(Json(json)) => (StatusCode::OK, json),
            Err(e) => (e.status, json!({ "error": e.message, "code": e.code })),
        }
    }

    fn reg_body(username: &str, seed_byte: u8) -> serde_json::Value {
        let mut seed = [0u8; 32];
        seed[0] = seed_byte;
        json!({
            "username": username,
            "password": "heslo-12345678",
            "device_pub": device_pub_hex(&seed),
        })
    }

    /// `invite_only` bez pozvánky → 403 `invite_required`; s pozvánkou 201;
    /// použitá pozvánka → 400 `invite_invalid`. Prvý admin (bootstrap) smie
    /// aj bez pozvánky, inak by sa uzol nedal vôbec otvoriť (O13).
    #[tokio::test]
    async fn f14a_register_invite_only_policy_and_invite_flow() {
        let state = shared();
        let invite_only = crate::roles::AuthConfig {
            registration_policy: crate::roles::RegistrationPolicy::InviteOnly,
            bootstrap_admin: None,
        };

        // prvý registrujúci je bootstrap → admin aj bez pozvánky
        let (status, body, token) = reg(&state, &invite_only, reg_body("adminprvy", 1)).await;
        assert_eq!(status, StatusCode::CREATED, "bootstrap prepustí bez pozvánky: {body}");
        assert_eq!(body["role"], json!("admin"));
        let token = token.unwrap();

        // druhý bez pozvánky → 403 s kódom
        let (status, body, _) = reg(&state, &invite_only, reg_body("druhy", 2)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["code"], json!("invite_required"));

        // admin vytvorí pozvánku
        let created = invites_create(
            State(state.clone()),
            bearer_headers(&token),
            Json(serde_json::from_value(json!({ "label": "susedka" })).unwrap()),
        )
        .await
        .unwrap();
        assert_eq!(created.0, StatusCode::CREATED);
        let invite_token = created.1["token"].as_str().unwrap().to_string();

        // s pozvánkou 201; ten istý token druhýkrát → 400 invite_invalid
        let mut b = reg_body("pozvany", 3);
        b["invite"] = json!(invite_token);
        let (status, _, _) = reg(&state, &invite_only, b).await;
        assert_eq!(status, StatusCode::CREATED);
        let mut b2 = reg_body("iny", 4);
        b2["invite"] = json!(invite_token);
        let (status, body, _) = reg(&state, &invite_only, b2).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], json!("invite_invalid"));

        // zoznam ukáže spotrebu
        let list = invites_list(State(state.clone()), bearer_headers(&token)).await.unwrap();
        let invites = list.0["invites"].as_array().unwrap();
        assert_eq!(invites.len(), 1);
        assert_eq!(invites[0]["used"], json!(true));
    }

    /// Grant/revoke: admin len admin; perms len moderator; neznáme bity 400;
    /// posledný admin 409 `last_admin`.
    #[tokio::test]
    async fn f14a_admin_roles_grant_revoke_and_invariants() {
        let state = shared();
        let open = crate::roles::AuthConfig::default();
        let (_, admin_body, admin_token) = reg(&state, &open, reg_body("admin", 1)).await;
        assert_eq!(admin_body["role"], json!("admin"));
        let admin_token = admin_token.unwrap();
        let (_, _, user_token) = reg(&state, &open, reg_body("uci", 2)).await;
        let user_token = user_token.unwrap();

        // bežný user → 403 admin_required
        let (status, body) =
            call_roles(&state, &user_token, json!({ "account": "uci", "role": "moderator" })).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["code"], json!("admin_required"));

        // perms len moderator
        let (status, body) =
            call_roles(&state, &admin_token, json!({ "account": "uci", "role": "admin", "perms": 1 }))
                .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], json!("perms_not_moderator"));

        // neznáme bity
        let (status, body) = call_roles(
            &state,
            &admin_token,
            json!({ "account": "uci", "role": "moderator", "perms": (1u64 << 10) }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], json!("perms_unknown_bits"));

        // grant moderatora + audit hash v odpovedi
        let (status, body) = call_roles(
            &state,
            &admin_token,
            json!({ "account": "uci", "role": "moderator", "perms": 5 }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["role"], json!("moderator"));
        assert_eq!(body["perms"], json!(5));
        assert!(body["audit_hash"].as_str().unwrap().len() == 64);

        // posledného admina nemožno odomocniť
        let (status, body) =
            call_roles(&state, &admin_token, json!({ "account": "admin", "revoke": true })).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["code"], json!("last_admin"));

        // meno NEBOJ hex id cieľa (Z3)
        let target_id = {
            let s = lock(&state);
            to_hex(&s.account_by_username("uci").unwrap().unwrap().id)
        };
        let (status, body) =
            call_roles(&state, &admin_token, json!({ "account": target_id, "role": "user" })).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["role"], json!("user"));
    }

    /// `/me` hlási rolu; `GET /admin/users` len admin; nastavenia politiky
    /// put/get/delete s `source`.
    #[tokio::test]
    async fn f14a_me_admin_users_and_settings_roundtrip() {
        let state = shared();
        let open = crate::roles::AuthConfig::default();
        let (_, _, admin_token) = reg(&state, &open, reg_body("admin", 1)).await;
        let admin_token = admin_token.unwrap();
        let (_, _, user_token) = reg(&state, &open, reg_body("uci", 2)).await;
        let user_token = user_token.unwrap();

        let me = get_me(State(state.clone()), bearer_headers(&user_token)).await.unwrap();
        assert_eq!(me.0["role"], json!("user"));
        let me = get_me(State(state.clone()), bearer_headers(&admin_token)).await.unwrap();
        assert_eq!(me.0["role"], json!("admin"));

        let users = admin_users(State(state.clone()), bearer_headers(&admin_token)).await.unwrap();
        assert_eq!(users.0["users"].as_array().unwrap().len(), 2);
        let err = admin_users(State(state.clone()), bearer_headers(&user_token)).await.unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);

        // settings: default config → meta override → späť na config
        let s = admin_settings_get(
            State(state.clone()),
            auth_ext(crate::roles::AuthConfig::default()),
            bearer_headers(&admin_token),
        )
        .await
        .unwrap();
        assert_eq!(s.0["registration_policy"], json!("open"));
        assert_eq!(s.0["source"], json!("config"));

        let s = admin_settings_put(
            State(state.clone()),
            bearer_headers(&admin_token),
            Json(serde_json::from_value(json!({ "registration_policy": "invite_only" })).unwrap()),
        )
        .await
        .unwrap();
        assert_eq!(s.0["source"], json!("meta"));

        let s = admin_settings_get(
            State(state.clone()),
            auth_ext(crate::roles::AuthConfig::default()),
            bearer_headers(&admin_token),
        )
        .await
        .unwrap();
        assert_eq!(s.0["registration_policy"], json!("invite_only"));
        assert_eq!(s.0["source"], json!("meta"));

        let s = admin_settings_delete(
            State(state.clone()),
            auth_ext(crate::roles::AuthConfig {
                registration_policy: crate::roles::RegistrationPolicy::AdminApproved,
                bootstrap_admin: None,
            }),
            bearer_headers(&admin_token),
        )
        .await
        .unwrap();
        assert_eq!(s.0["registration_policy"], json!("admin_approved"));
        assert_eq!(s.0["source"], json!("config"));

        // neplatná politika → 400 invalid_policy
        let err = admin_settings_put(
            State(state.clone()),
            bearer_headers(&admin_token),
            Json(serde_json::from_value(json!({ "registration_policy": "anarchia" })).unwrap()),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.code, Some("invalid_policy"));
    }

    /// Pozvánky: user bez bita 403; moderator s bitom `INVITE_USERS` tvorí
    /// a vidí len vlastné; bez bita `INVITE_USERS` (len MODERATE_CHANNELS)
    /// 403.
    #[tokio::test]
    async fn f14a_invites_require_bit_and_moderator_sees_own_only() {
        let state = shared();
        let open = crate::roles::AuthConfig::default();
        let (_, _, admin_token) = reg(&state, &open, reg_body("admin", 1)).await;
        let admin_token = admin_token.unwrap();
        let (_, mod_body, mod_token) = reg(&state, &open, reg_body("modka", 2)).await;
        let _ = mod_body;
        let mod_token = mod_token.unwrap();
        let (_, _, user_token) = reg(&state, &open, reg_body("uci", 3)).await;
        let user_token = user_token.unwrap();

        // user → 403 insufficient_perms
        let err = invites_create(
            State(state.clone()),
            bearer_headers(&user_token),
            Json(serde_json::from_value(json!({})).unwrap()),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert_eq!(err.code, Some("insufficient_perms"));

        // moderator bez bita INVITE_USERS (len MODERATE_CHANNELS=1)
        call_roles(
            &state,
            &admin_token,
            json!({ "account": "modka", "role": "moderator", "perms": 1 }),
        )
        .await;
        let err = invites_create(
            State(state.clone()),
            bearer_headers(&mod_token),
            Json(serde_json::from_value(json!({})).unwrap()),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);

        // moderator s bitom INVITE_USERS (4) → vytvorí a vidí len vlastné
        call_roles(
            &state,
            &admin_token,
            json!({ "account": "modka", "role": "moderator", "perms": 4 }),
        )
        .await;
        let created = invites_create(
            State(state.clone()),
            bearer_headers(&mod_token),
            Json(serde_json::from_value(json!({ "label": "od moderatora" })).unwrap()),
        )
        .await
        .unwrap();
        assert_eq!(created.0, StatusCode::CREATED);
        let admin_created = invites_create(
            State(state.clone()),
            bearer_headers(&admin_token),
            Json(serde_json::from_value(json!({ "label": "od admina" })).unwrap()),
        )
        .await
        .unwrap();
        let admin_invite_id = admin_created.1["id"].as_i64().unwrap();

        let list = invites_list(State(state.clone()), bearer_headers(&mod_token)).await.unwrap();
        let invites = list.0["invites"].as_array().unwrap();
        assert_eq!(invites.len(), 1, "moderator vidí len vlastnú pozvánku");

        // moderator nemazí cudziu (adminovu) pozvánku
        let err =
            invites_delete(State(state.clone()), bearer_headers(&mod_token), Path(admin_invite_id))
                .await
                .unwrap_err();
        assert_eq!(err.status, StatusCode::NOT_FOUND);
        // admin ju zmaže
        let ok =
            invites_delete(State(state.clone()), bearer_headers(&admin_token), Path(admin_invite_id))
                .await;
        assert!(matches!(ok, Ok(StatusCode::NO_CONTENT)));
    }

    /// `admin_approved`: registrácia bez pozvánky → 403 `account_pending`,
    /// login taktiež 403; grant adminom účet aktivuje a login prejde.
    #[tokio::test]
    async fn f14a_admin_approved_pending_flow() {
        let state = shared();
        let approved = crate::roles::AuthConfig {
            registration_policy: crate::roles::RegistrationPolicy::AdminApproved,
            bootstrap_admin: None,
        };
        // bootstrap admin aj tu (prvý, bez pozvánky)
        let (_, _, admin_token) = reg(&state, &approved, reg_body("admin", 1)).await;
        let admin_token = admin_token.unwrap();

        let (status, body, token) = reg(&state, &approved, reg_body("cakajuci", 2)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["code"], json!("account_pending"));
        assert!(token.is_none(), "pending nedostane session token");

        // login pending účtu → 403 account_pending
        let err = login(
            State(state.clone()),
            Json(serde_json::from_value(json!({ "username": "cakajuci", "password": "heslo-12345678" })).unwrap()),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert_eq!(err.code, Some("account_pending"));

        // grant = schválenie → login prejde
        call_roles(&state, &admin_token, json!({ "account": "cakajuci", "role": "user" })).await;
        let (status, _) = do_login(
            &state,
            json!({ "username": "cakajuci", "password": "heslo-12345678" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // reject: DELETE /admin/users/{id} vymaže pending účet
        let pending_id = {
            let s = lock(&state);
            to_hex(&s.account_by_username("cakajuci2").unwrap().map(|a| a.id).unwrap_or_default())
        };
        let _ = pending_id;
        let (status, _, _) = reg(&state, &approved, reg_body("cakajuci2", 3)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let new_id = {
            let s = lock(&state);
            to_hex(&s.account_by_username("cakajuci2").unwrap().unwrap().id)
        };
        let ok = admin_user_delete(
            State(state.clone()),
            bearer_headers(&admin_token),
            Path(new_id),
        )
        .await;
        assert!(matches!(ok, Ok(StatusCode::NO_CONTENT)));
        assert!(lock(&state).account_by_username("cakajuci2").unwrap().is_none());
    }

    // --- F14c (MYHSN-58): skupinové kanály cez REST ----------------------

    /// `POST /channels` s `{"group": true}` a Bearer tokenom.
    async fn create_group(
        state: &SharedStore,
        token: &str,
        name: &str,
        owner: Option<&str>,
    ) -> (StatusCode, Value) {
        match create_channel(
            State(state.clone()),
            no_ws(),
            bearer_headers(token),
            Json(CreateChannelRequest {
                name: name.into(),
                kind: Some("mixed".into()),
                group: Some(true),
                owner: owner.map(String::from),
            }),
        )
        .await
        {
            Ok((status, Json(json))) => (status, json),
            Err(e) => (e.status, json!({ "error": e.message, "code": e.code })),
        }
    }

    /// `id` z odpovede `POST /channels`.
    fn channel_id_of(body: &Value) -> String {
        body["id"].as_str().expect("id kanála").to_string()
    }

    /// Kód strojovej chyby z odpovede, ktorú vrátila mapa `ApiError`.
    fn err_code(body: &Value) -> Option<&str> {
        body["code"].as_str()
    }

    async fn add_member(
        state: &SharedStore,
        token: &str,
        ch: &str,
        account: &str,
    ) -> (StatusCode, Value) {
        match channel_member_add(
            State(state.clone()),
            no_ws(),
            bearer_headers(token),
            Path(ch.into()),
            Json(ChannelMemberRequest { account: account.into() }),
        )
        .await
        {
            Ok((status, Json(json))) => (status, json),
            Err(e) => (e.status, json!({ "error": e.message, "code": e.code })),
        }
    }

    async fn set_channel_role(
        state: &SharedStore,
        token: &str,
        ch: &str,
        acct: &str,
        role: &str,
    ) -> (StatusCode, Value) {
        match channel_member_set_role(
            State(state.clone()),
            no_ws(),
            bearer_headers(token),
            Path((ch.into(), acct.into())),
            Json(ChannelRoleRequest { role: role.into() }),
        )
        .await
        {
            Ok(Json(json)) => (StatusCode::OK, json),
            Err(e) => (e.status, json!({ "error": e.message, "code": e.code })),
        }
    }

    async fn remove_member(
        state: &SharedStore,
        token: &str,
        ch: &str,
        acct: &str,
    ) -> (StatusCode, Value) {
        match channel_member_remove(
            State(state.clone()),
            no_ws(),
            bearer_headers(token),
            Path((ch.into(), acct.into())),
        )
        .await
        {
            Ok(Json(json)) => (StatusCode::OK, json),
            Err(e) => (e.status, json!({ "error": e.message, "code": e.code })),
        }
    }

    async fn transfer_channel(
        state: &SharedStore,
        token: &str,
        ch: &str,
        acct: &str,
        previous_role: Option<&str>,
    ) -> (StatusCode, Value) {
        match channel_transfer(
            State(state.clone()),
            no_ws(),
            bearer_headers(token),
            Path(ch.into()),
            Json(ChannelTransferRequest {
                account: acct.into(),
                previous_role: previous_role.map(String::from),
            }),
        )
        .await
        {
            Ok(Json(json)) => (StatusCode::OK, json),
            Err(e) => (e.status, json!({ "error": e.message, "code": e.code })),
        }
    }

    async fn mute_channel(
        state: &SharedStore,
        token: &str,
        ch: &str,
        acct: &str,
        duration_secs: Option<i64>,
    ) -> (StatusCode, Value) {
        match channel_mute(
            State(state.clone()),
            no_ws(),
            bearer_headers(token),
            Path(ch.into()),
            Json(ChannelMuteRequest { account: acct.into(), duration_secs }),
        )
        .await
        {
            Ok(Json(json)) => (StatusCode::OK, json),
            Err(e) => (e.status, json!({ "error": e.message, "code": e.code })),
        }
    }

    async fn unmute_channel(
        state: &SharedStore,
        token: &str,
        ch: &str,
        acct: &str,
    ) -> (StatusCode, Value) {
        match channel_unmute(
            State(state.clone()),
            no_ws(),
            bearer_headers(token),
            Path((ch.into(), acct.into())),
        )
        .await
        {
            Ok(Json(json)) => (StatusCode::OK, json),
            Err(e) => (e.status, json!({ "error": e.message, "code": e.code })),
        }
    }

    async fn group_members(
        state: &SharedStore,
        ch: &str,
        token: Option<&str>,
    ) -> (StatusCode, Value) {
        let headers = token.map(bearer_headers).unwrap_or_default();
        match channel_members(State(state.clone()), headers, Path(ch.into())).await {
            Ok(Json(json)) => (StatusCode::OK, json),
            Err(e) => (e.status, json!({ "error": e.message, "code": e.code })),
        }
    }

    /// Položka kanála v odpovedi `GET /channels`.
    fn channel_item(list: &Value, id: &str) -> Value {
        list["channels"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == json!(id))
            .cloned()
            .unwrap_or(Value::Null)
    }

    /// **Group kanál cez REST:** Bearer povinný (401 `auth_required`),
    /// owner = volajúci, viditeľnosť len s `?include_groups=1`, `features`
    /// v `GET /node/info`, členstvo + strojové kódy chýb.
    #[tokio::test]
    async fn f14c_group_channel_creation_membership_and_visibility() {
        let state = shared();
        let open = crate::roles::AuthConfig::default();
        // prvý registrujúci je bootstrap server admin — necháme ho bokom,
        // aby test nerozhodovala serverová rola
        let (_, _, root) = reg(&state, &open, reg_body("roota", 1)).await;
        let (_, _, owner_t) = reg(&state, &open, reg_body("gardas", 2)).await;
        let (_, _, member_t) = reg(&state, &open, reg_body("clen", 3)).await;
        let (root_t, owner_t, member_t) = (root.unwrap(), owner_t.unwrap(), member_t.unwrap());

        let (status, body) = create_group(&state, &owner_t, "partia", None).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["group"], json!(true), "group kanál je označený");
        assert_eq!(body["channel_role"], json!("owner"), "volajúci je owner");
        assert_eq!(
            body["owner"].as_str().unwrap_or_default().len(),
            64,
            "owner je hex id volajúceho: {body}"
        );
        let ch = channel_id_of(&body);

        // bez Bearera sa group kanál nevytvorí — 401 `auth_required`
        let err = create_channel(
            State(state.clone()),
            no_ws(),
            HeaderMap::new(),
            Json(CreateChannelRequest {
                name: "bez-authu".into(),
                kind: None,
                group: Some(true),
                owner: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(err.code, Some("auth_required"));

        // viditeľnosť: bez voľby je group kanál pred klientom skrytý
        let plain = list_ch(&state, None, None).await;
        assert_eq!(channel_item(&plain, &ch), Value::Null, "group kanál je skrytý");
        let with = list_ch(&state, Some("1"), None).await;
        assert_ne!(channel_item(&with, &ch), Value::Null, "?include_groups=1 ho ukáže");
        assert_eq!(channel_item(&with, &ch)["channel_role"], Value::Null, "anonym nemá rolu");
        // s Bearerom doplní rolu volajúceho
        let mine = list_ch(&state, Some("1"), Some(&owner_t)).await;
        assert_eq!(channel_item(&mine, &ch)["channel_role"], json!("owner"));
        let other = list_ch(&state, Some("1"), Some(&member_t)).await;
        assert_eq!(channel_item(&other, &ch)["channel_role"], Value::Null);

        // `GET /node/info`: group kanál v zozname nie je, schopnosti áno
        let Json(info) = node_info(State(state.clone())).await.unwrap();
        assert!(!info["channels"].to_string().contains(&ch), "node/info group kanál netvrdí");
        assert_eq!(info["features"], json!(["roles", "channels"]));

        // členstvo
        let (status, added) = add_member(&state, &owner_t, &ch, "clen").await;
        assert_eq!(status, StatusCode::CREATED, "{added}");
        assert_eq!(added["role"], json!("member"));
        let (dup, dup_body) = add_member(&state, &owner_t, &ch, "clen").await;
        assert_eq!(dup, StatusCode::CONFLICT);
        assert_eq!(err_code(&dup_body), Some("already_member"));
        let (nf, nf_body) = add_member(&state, &owner_t, &ch, "duch").await;
        assert_eq!(nf, StatusCode::NOT_FOUND);
        assert_eq!(err_code(&nf_body), Some("account_not_found"));

        // zoznam členov je verejný; owner je v samostatnom bloku
        let (status, list) = group_members(&state, &ch, None).await;
        assert_eq!(status, StatusCode::OK);
        let members = list["members"].as_array().unwrap();
        assert_eq!(members.len(), 1, "owner nie je riadok členov: {list}");
        assert_eq!(members[0]["role"], json!("member"));
        assert_eq!(members[0]["username"], json!("clen"));
        assert_eq!(list["owner"]["role"], json!("owner"));
        assert!(list["my_role"].is_null(), "anonym nemá rolu");
        let (_, mine_list) = group_members(&state, &ch, Some(&member_t)).await;
        assert_eq!(mine_list["my_role"], json!("member"));

        // server admin vidí group kanál a má v ňom nadradené právo
        let admin_view = list_ch(&state, Some("1"), Some(&root_t)).await;
        assert_ne!(channel_item(&admin_view, &ch), Value::Null);
    }

    /// **Matica právomocí (rozhodnutie §6):** member nesmie nič, channel
    /// admin smie členov ale nie transfer, owner smie všetko okrem
    /// vlastného odobrania, server admin zasahuje do cudzej skupiny.
    #[tokio::test]
    async fn f14c_channel_role_permission_matrix() {
        let state = shared();
        let open = crate::roles::AuthConfig::default();
        let (_, _, root) = reg(&state, &open, reg_body("roota", 1)).await;
        let (_, _, owner_t) = reg(&state, &open, reg_body("gardas", 2)).await;
        let (_, _, admin_t) = reg(&state, &open, reg_body("kika", 3)).await;
        let (_, _, member_t) = reg(&state, &open, reg_body("clen", 4)).await;
        let (_, _, alien_t) = reg(&state, &open, reg_body("cudzie", 5)).await;
        let (root_t, owner_t, admin_t, member_t, alien_t) =
            (root.unwrap(), owner_t.unwrap(), admin_t.unwrap(), member_t.unwrap(), alien_t.unwrap());

        let (status, body) = create_group(&state, &owner_t, "partia", None).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let ch = channel_id_of(&body);
        for who in ["kika", "clen", "cudzie"] {
            let (s, b) = add_member(&state, &owner_t, &ch, who).await;
            assert_eq!(s, StatusCode::CREATED, "{who}: {b}");
        }
        let (s, b) = set_channel_role(&state, &owner_t, &ch, "kika", "admin").await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["role"], json!("admin"));

        // member: pridávanie, zmena role, stíšenie aj transfer = 403
        let (s, b) = add_member(&state, &member_t, &ch, "kika").await;
        assert_eq!(s, StatusCode::FORBIDDEN, "member nesmie pridávať: {b}");
        assert_eq!(err_code(&b), Some("not_channel_admin"));
        let (s, b) = set_channel_role(&state, &member_t, &ch, "clen", "admin").await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(err_code(&b), Some("not_channel_admin"));
        let (s, b) = mute_channel(&state, &member_t, &ch, "clen", None).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(err_code(&b), Some("not_channel_admin"));
        let (s, b) = transfer_channel(&state, &member_t, &ch, "kika", None).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "member nesmie prenechávať ownera: {b}");
        assert_eq!(err_code(&b), Some("not_channel_owner"));
        // cudziec (nie člen) taktiež
        let (s, b) = add_member(&state, &alien_t, &ch, "kika").await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(err_code(&b), Some("not_channel_admin"));

        // channel admin: pridáva a znižuje členov, ale nedosiahne na ownera
        // ani na rovnakého admina (rozhodnutie §6: prísne vyššia hodnosť)
        let (s, b) = add_member(&state, &admin_t, &ch, "kika").await;
        assert_eq!(s, StatusCode::CONFLICT, "admin už je v kanáli: {b}");
        let (s, b) = set_channel_role(&state, &admin_t, &ch, "clen", "member").await;
        assert_eq!(s, StatusCode::OK, "admin zníži membera: {b}");
        let (s, b) = set_channel_role(&state, &admin_t, &ch, "kika", "member").await;
        assert_eq!(s, StatusCode::FORBIDDEN, "admin nedosiahne na seba: {b}");
        assert_eq!(err_code(&b), Some("insufficient_perms"));
        let (s, b) = set_channel_role(&state, &admin_t, &ch, "gardas", "admin").await;
        assert_eq!(s, StatusCode::FORBIDDEN, "admin nedosiahne na ownera: {b}");
        assert_eq!(err_code(&b), Some("insufficient_perms"));
        let (s, b) = transfer_channel(&state, &admin_t, &ch, "clen", None).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "channel admin nemeňuje ownera: {b}");
        assert_eq!(err_code(&b), Some("not_channel_owner"));

        // owner: nemôže sám seba odobrať ani znížiť, môže odobrať admina
        let (s, b) = set_channel_role(&state, &owner_t, &ch, "gardas", "member").await;
        assert_eq!(s, StatusCode::FORBIDDEN, "ownera nemozo znížiť: {b}");
        assert_eq!(err_code(&b), Some("insufficient_perms"));
        let (s, b) = remove_member(&state, &owner_t, &ch, "gardas").await;
        assert_eq!(s, StatusCode::CONFLICT, "owner musí transferovať: {b}");
        assert_eq!(err_code(&b), Some("owner_must_transfer"));
        // member smie odísť sám
        let (s, b) = remove_member(&state, &member_t, &ch, "clen").await;
        assert_eq!(s, StatusCode::OK, "member odíde sám: {b}");
        assert_eq!(b["left"], json!(true));
        let (s, b) = remove_member(&state, &member_t, &ch, "clen").await;
        assert_eq!(s, StatusCode::NOT_FOUND, "už nie je člen: {b}");
        assert_eq!(err_code(&b), Some("not_member"));
        // owner odobere admina
        let (s, b) = remove_member(&state, &owner_t, &ch, "kika").await;
        assert_eq!(s, StatusCode::OK, "owner odobere admina: {b}");

        // server admin vládne aj cudzej skupine, no ownera stíšiť nedokáže
        let (s, b) = add_member(&state, &root_t, &ch, "cudzie").await;
        assert_eq!(s, StatusCode::CONFLICT, "už je člen: {b}");
        let (s, b) = mute_channel(&state, &root_t, &ch, "cudzie", None).await;
        assert_eq!(s, StatusCode::OK, "server admin stíši člena cudzej skupiny: {b}");
        let (s, b) = mute_channel(&state, &root_t, &ch, "gardas", None).await;
        assert_eq!(s, StatusCode::CONFLICT, "owner sa stíšiť nedá: {b}");
        assert_eq!(err_code(&b), Some("owner_not_mutable"));
    }

    /// **Transfer ownera:** `previous_role` (default admin), 409
    /// `already_owner`, 400 `use_transfer` pri `PUT` s rolou `owner`.
    #[tokio::test]
    async fn f14c_transfer_owner_over_rest() {
        let state = shared();
        let open = crate::roles::AuthConfig::default();
        let (_, _, _root) = reg(&state, &open, reg_body("roota", 1)).await;
        let (_, _, owner_t) = reg(&state, &open, reg_body("gardas", 2)).await;
        let (_, _, member_t) = reg(&state, &open, reg_body("clen", 3)).await;
        let (owner_t, member_t) = (owner_t.unwrap(), member_t.unwrap());

        let (_, body) = create_group(&state, &owner_t, "dedictvo", None).await;
        let ch = channel_id_of(&body);
        add_member(&state, &owner_t, &ch, "clen").await;

        let (s, b) = transfer_channel(&state, &owner_t, &ch, "clen", None).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["previous_role"], json!("admin"), "default previous_role");
        assert_eq!(b["owner_username"], json!("clen"));
        let (_, list) = group_members(&state, &ch, None).await;
        assert_eq!(list["owner"]["username"], json!("clen"));
        assert_eq!(list["members"][0]["username"], json!("gardas"));
        assert_eq!(list["members"][0]["role"], json!("admin"));
        // nový owner je owner, predošlý je channel admin
        let (_, mine) = group_members(&state, &ch, Some(&member_t)).await;
        assert_eq!(mine["my_role"], json!("owner"));
        let (_, old) = group_members(&state, &ch, Some(&owner_t)).await;
        assert_eq!(old["my_role"], json!("admin"));

        // transfer samému sebe
        let (s, b) = transfer_channel(&state, &member_t, &ch, "clen", None).await;
        assert_eq!(s, StatusCode::CONFLICT);
        assert_eq!(err_code(&b), Some("already_owner"));
        // neznámy účet
        let (s, b) = transfer_channel(&state, &member_t, &ch, "duch", None).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert_eq!(err_code(&b), Some("account_not_found"));
        // predošlý owner už ownera prenechať nemôže
        let (s, b) = transfer_channel(&state, &owner_t, &ch, "gardas", None).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(err_code(&b), Some("not_channel_owner"));

        // previous_role = none → predošlý owner odíde z kanála
        let (s, b) = transfer_channel(&state, &member_t, &ch, "gardas", Some("none")).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["previous_role"], json!("none"));
        let (_, list) = group_members(&state, &ch, None).await;
        assert!(list["members"].as_array().unwrap().is_empty(), "{list}");
        // neznáma previous_role
        let (s, b) = transfer_channel(&state, &owner_t, &ch, "clen", Some("carsky")).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(err_code(&b), Some("invalid_role"));

        // `PUT` s rolou `owner` je 400 `use_transfer`
        let (s, b) = set_channel_role(&state, &owner_t, &ch, "clen", "owner").await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(err_code(&b), Some("use_transfer"));
        // neznáma rola
        let (s, b) = set_channel_role(&state, &owner_t, &ch, "clen", "kral").await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(err_code(&b), Some("invalid_role"));
    }

    /// **Stíšenie:** default 3600 s, `muted` v zozname, 404 `not_muted`
    /// pri druhom zrušení, 409 `owner_not_mutable`.
    #[tokio::test]
    async fn f14c_mute_over_rest() {
        let state = shared();
        let open = crate::roles::AuthConfig::default();
        let (_, _, _root) = reg(&state, &open, reg_body("roota", 1)).await;
        let (_, _, owner_t) = reg(&state, &open, reg_body("gardas", 2)).await;
        let (_, _, member_t) = reg(&state, &open, reg_body("clen", 3)).await;
        let (owner_t, member_t) = (owner_t.unwrap(), member_t.unwrap());

        let (_, body) = create_group(&state, &owner_t, "ticho", None).await;
        let ch = channel_id_of(&body);
        add_member(&state, &owner_t, &ch, "clen").await;

        let (s, b) = mute_channel(&state, &owner_t, &ch, "clen", None).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["duration_secs"], json!(3600), "default dĺžka");
        assert!(b["muted_until"].as_i64().unwrap() > 1_700_000_000, "budúcnosť: {b}");
        let (_, list) = group_members(&state, &ch, None).await;
        assert_eq!(list["members"][0]["muted"], json!(true));
        assert!(list["members"][0]["muted_until"].is_i64());

        let (s, b) = unmute_channel(&state, &owner_t, &ch, "clen").await;
        assert_eq!(s, StatusCode::OK, "{b}");
        let (_, list) = group_members(&state, &ch, None).await;
        assert_eq!(list["members"][0]["muted"], json!(false));
        let (s, b) = unmute_channel(&state, &owner_t, &ch, "clen").await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert_eq!(err_code(&b), Some("not_muted"));

        // owner sa stíšiť nedá
        let (s, b) = mute_channel(&state, &owner_t, &ch, "gardas", None).await;
        assert_eq!(s, StatusCode::CONFLICT);
        assert_eq!(err_code(&b), Some("owner_not_mutable"));
        // neplatná dĺžka
        let (s, _) = mute_channel(&state, &owner_t, &ch, "clen", Some(0)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let (s, _) = mute_channel(
            &state,
            &owner_t,
            &ch,
            "clen",
            Some(crate::api::MAX_MUTE_SECS + 1),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        // vlastné stíšenie vidí člen v `my_role` len ako rolu — `muted`
        // dostane v zozname a v `HelloAck`
        let (_, mine) = group_members(&state, &ch, Some(&member_t)).await;
        assert_eq!(mine["my_role"], json!("member"));
    }

    /// **Legacy kanál:** žiadne membership API — všade 409
    /// `not_group_channel`, ale vo zoznamoch je ako doteraz (regresia).
    #[tokio::test]
    async fn f14c_legacy_channel_has_no_membership_api() {
        let state = shared();
        let open = crate::roles::AuthConfig::default();
        let (_, _, _root) = reg(&state, &open, reg_body("roota", 1)).await;
        let (_, _, owner_t) = reg(&state, &open, reg_body("gardas", 2)).await;
        let owner_t = owner_t.unwrap();

        let (s, b) = create_ch(&state, "verejny", Some("wall")).await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        assert_eq!(b["group"], json!(false), "legacy kanál nie je group");
        assert!(b["owner"].is_null(), "legacy kanál nemá ownera");
        let ch = channel_id_of(&b);

        // legacy kanál je vo zozname aj bez `include_groups` (B8 regresia)
        let plain = list_ch(&state, None, None).await;
        assert_ne!(channel_item(&plain, &ch), Value::Null, "legacy kanál je viditeľný");

        for (status, body) in [
            group_members(&state, &ch, Some(&owner_t)).await,
            add_member(&state, &owner_t, &ch, "gardas").await,
            set_channel_role(&state, &owner_t, &ch, "gardas", "admin").await,
            remove_member(&state, &owner_t, &ch, "gardas").await,
            transfer_channel(&state, &owner_t, &ch, "gardas", None).await,
            mute_channel(&state, &owner_t, &ch, "gardas", None).await,
            unmute_channel(&state, &owner_t, &ch, "gardas").await,
        ] {
            assert_eq!(status, StatusCode::CONFLICT, "legacy kanál: {body}");
            assert_eq!(err_code(&body), Some("not_group_channel"));
        }

        // neexistujúci kanál = 404 `channel_not_found`
        let ghost = "00".repeat(32);
        let (s, b) = group_members(&state, &ghost, None).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert_eq!(err_code(&b), Some("channel_not_found"));
        let (s, b) = add_member(&state, &owner_t, &ghost, "gardas").await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert_eq!(err_code(&b), Some("channel_not_found"));
        // zlé id = 400
        let (s, _) = group_members(&state, "zz", None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
    }

    /// **Audity sú čitateľné:** `GET /channels/{id}/records` ukáže druhy
    /// kind 8 – 11 pod ich názvami — frontend ich musí filtrovať sám
    /// (rozhodnutie §4: vraciame ich aj klientom bez capov).
    #[tokio::test]
    async fn f14c_channel_audits_are_readable_via_records() {
        let state = shared();
        let open = crate::roles::AuthConfig::default();
        let (_, _, _root) = reg(&state, &open, reg_body("roota", 1)).await;
        let (_, _, owner_t) = reg(&state, &open, reg_body("gardas", 2)).await;
        let (_, _, member_t) = reg(&state, &open, reg_body("clen", 3)).await;
        let (owner_t, _member_t) = (owner_t.unwrap(), member_t.unwrap());

        let (_, body) = create_group(&state, &owner_t, "zaznamy", None).await;
        let ch = channel_id_of(&body);
        add_member(&state, &owner_t, &ch, "clen").await;
        set_channel_role(&state, &owner_t, &ch, "clen", "admin").await;
        transfer_channel(&state, &owner_t, &ch, "clen", None).await;

        let Json(view) = list_channel_records(
            State(state.clone()),
            Path(ch.clone()),
            Query(RecordsQuery {
                from_epoch: None,
                from_seq: None,
                limit: Some(50),
                reader: None,
            }),
        )
        .await
        .unwrap();
        let kinds: Vec<String> = view["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["record"]["kind"].as_str().unwrap_or_default().to_string())
            .collect();
        for expected in ["create_channel", "grant_channel_role", "transfer_channel_owner"] {
            assert!(kinds.iter().any(|k| k == expected), "chýba audit {expected}: {kinds:?}");
        }
        // audit má meno cieľa aj kanál — frontend to nepotrebuje dekódovať
        let grant = view["records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["record"]["kind"] == json!("grant_channel_role"))
            .unwrap();
        assert_eq!(grant["record"]["content"]["target_name"], json!("clen"));
        assert_eq!(grant["record"]["content"]["channel_hex"], json!(ch));
        // transfer nesie meno predošlého aj nového ownera
        let transfer = view["records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["record"]["kind"] == json!("transfer_channel_owner"))
            .unwrap();
        assert_eq!(transfer["record"]["content"]["from_name"], json!("gardas"));
        assert_eq!(transfer["record"]["content"]["to_name"], json!("clen"));
        assert_eq!(transfer["record"]["content"]["previous_role"], json!("admin"));
    }

    /// **Admin nastaví ownera pri vytvorení:** `owner` v tele rešpektuje len
    /// server admin, bežný účet dostane 403 `insufficient_perms`.
    #[tokio::test]
    async fn f14c_create_group_with_other_owner_requires_server_admin() {
        let state = shared();
        let open = crate::roles::AuthConfig::default();
        let (_, _, root) = reg(&state, &open, reg_body("roota", 1)).await;
        let (_, _, owner_t) = reg(&state, &open, reg_body("gardas", 2)).await;
        let (root_t, owner_t) = (root.unwrap(), owner_t.unwrap());

        // bežný účet nemôže nastaviť cudzieho ownera
        let (s, b) = create_group(&state, &owner_t, "cizia", Some("roota")).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{b}");
        assert_eq!(err_code(&b), Some("insufficient_perms"));
        // server admin áno — a v kanáli potom nie je člen
        let (s, b) = create_group(&state, &root_t, "adminova", Some("gardas")).await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let ch = channel_id_of(&b);
        assert_eq!(b["channel_role"], Value::Null, "server admin nie je owner");
        let (_, list) = group_members(&state, &ch, Some(&owner_t)).await;
        assert_eq!(list["owner"]["username"], json!("gardas"));
        assert_eq!(list["my_role"], json!("owner"));
        // neznámy owner = 404
        let (s, b) = create_group(&state, &root_t, "duch", Some("nikto")).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert_eq!(err_code(&b), Some("account_not_found"));
    }
}
