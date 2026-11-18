//! WebSocket sync (B5, MYHSN-7, rozhodnutia **D-24** a **D-29**).
//!
//! Vlastná tenká vrstva nad WSS (D-24): každá WS binárna správa je frame
//! z [`myhsn_core::wire`] — 8B hlavička `ver | type | channel | len` +
//! minicbor payload. Verzia je v hlavičke každého frame (D-22), handshake
//! je `Hello`/`HelloAck`/`Reject` a **caps v HelloAck sú autorita
//! protokolu** (D-29).
//!
//! Protokol relácie:
//! 1. klient pošle `Hello {proto_min, proto_max, caps, watermarky per
//!    kanál}`; uzol odpovie `HelloAck {verzia, caps, epochy kanálov}`
//!    alebo `Reject {kód, dôvod}` pri nekompatibilnej verzii (D-22).
//! 2. uzol hneď po `HelloAck` dobehne chýbajúce záznamy: pre každý
//!    watermark volá `RecordStore::range` od `(epoch, seq+1)` nahor
//!    (watermark = najvyššia aplikovaná pozícia, D-29).
//! 3. klient posiela `Record` (kanonické bajty obálky s `stamp_sig =
//!    None`, epocha/seq 0 — poradie predsa nemôže poznať klient). Uzol:
//!    overí obálku a podpis autora, **overí, že autorov kľúč je aktívny
//!    device key** (B4 — revokovaný kľúč sa odmietne), alokuje
//!    `node_seq`, dosadí pečiatku + slepý hash so soľou kanála, podpíše
//!    pečiatku operačným kľúčom a vloží. Odpoveď je `Ack {hash, channel,
//!    epoch, seq}` s **finálnym** hashom uloženej obálky.
//! 4. idempotencia (kritérium B5c): duplicitná správa (rovnaké prijaté
//!    bajty → rovnaký `client_hash`) dostane `Ack` s pôvodnou pozíciou a
//!    **nič sa nepridá**. Poradie pred opečiatkovaním nie je finálny
//!    hash záznamu, preto uzol deduplikuje po `client_hash` (stĺpec
//!    `records.client_hash`, UNIQUE).
//! 5. nová opečiatkovaná obálka sa pushuje všetkým pripojeným klientom
//!    (vrátane odosielateľa — aplikácia je idempotentná podľa hashu,
//!    D-29, takže duplikát nevadí).
//!
//! Bloby (obrázky) idú mimo WS cez HTTP (D-24) — to je až B6+, tu nie sú.
//! Session token z B4 sa cez WS zatiaľ neposiela: autoritu má podpis
//! v obálke overený voči device keys (D-26), nie transportná relácia.
//!
//! Logovanie relácie (B5.1, MYHSN-19): **pripojenie / Hello / Reject /
//! disconnect** idú na INFO, peer IP a počet dobehnutých záznamov na
//! DEBUG. V logoch nie je ani obsah správ, ani tokeny — len anonymné id
//! relácie a protokolové metadáta (verzie, caps, kódy), čo držíme aj
//! kvôli GDPR (IP je osobný údaj, preto len DEBUG).

use crate::api::SharedStore;
use crate::cors::{check_ws_origin, default_allowed_origins, OriginVerdict};
use crate::store::{ChannelAuthority, Store};
use axum::extract::connect_info::ConnectInfo;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequestParts, State};
use axum::http::header::{self, HeaderMap};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use myhsn_core::channel::Channel;
use myhsn_core::identity;
use myhsn_core::record::{Envelope, NodeStamp, RecordHash, RecordKind};
// B6: catch-up číta `Store::visible_range` (inherentná metóda, nie trait),
// preto tu `RecordStore` už nie je — surový `range` ostáva pre jadro a testy.
use myhsn_core::storage::RangeQuery;
use myhsn_core::wire::{
    self, Ack, ChannelEpoch, ChannelRoleEntry, FrameError, Header, HelloAck, MsgType, Reject,
    REJECT_HANDSHAKE, REJECT_PROTOCOL, REJECT_RECORD, REJECT_VERSION, WIRE_VERSION,
};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use tokio::sync::mpsc;
use tokio::time::Duration;

/// Bez handshake nesmie relácia čakať donekonečna (klient za proxy).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Koľko záznamov dobehne jeden watermark na jednu reláciu (stránovanie
/// dokonalé až s `Sync` správou; B5 stačí horná medza, D-33 kvóty prídu v B7).
const CATCH_UP_LIMIT: u32 = 500;

/// Capabilities uzla — autorita protokolu (D-29). `sync` = zvláda
/// Hello/watermark/Record/Ack/push.
pub const NODE_CAPS: [&str; 1] = ["sync"];

/// **F14a:** klient, ktorý v `Hello.caps` oznámil `"roles"`, smie dostať
/// 4. prvok `HelloAck` `[role, perms]`, `RoleUpdate` (MsgType 9) a
/// audity rolí v systémovom kanáli. Stará Dart apka cap neposiela —
/// neznámy MsgType by jej reláciu zahodil a reconnect by sa točil
/// (overené na `wire.dart`/`ws_client.dart`), preto prísny gate.
pub const CAP_ROLES: &str = "roles";

/// **F14c (MYHSN-58):** klient, ktorý v `Hello.caps` oznámil `"channels"`,
/// odteraz vidí **skupinové kanály**: ich epochy v `HelloAck`, ich záznamy
/// v catch-up aj v pushi, `ChannelRoleUpdate` (MsgType 10) a 5. prvok
/// `HelloAck` so svojimi kanálovými rolami. Starí klienti (F14b apka, `lk`
/// bot) cap neposielajú — pre nich skupinové kanály **neexistujú**, inak by
/// na neznámy MsgType 10 padli do reconnect loopu (rozhodnutie F14c §4).
pub const CAP_CHANNELS: &str = "channels";

/// **F14c:** komu sa push ide. Vyčísľuje sa z capov relácie — nie z obsahu
/// správy, aby sa nedalo zabudnúť na bránu pri novom type správy.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PushGate {
    /// Všetci pripojení — záznamy verejných/legacy kanálov (B5, D-29).
    Everyone,
    /// Len relácie s capom `"roles"` (F14a: audit rolí, `RoleUpdate`).
    Roles,
    /// Len relácie s capom `"channels"` (F14c: audity a `ChannelRoleUpdate`
    /// skupinových kanálov).
    Channels,
}

/// Sender push správ jednej relácie (broadcast z iných úloh).
type ClientTx = mpsc::UnboundedSender<Message>;

/// Registrovaná relácia: sender + príznaky, či klient zvláda rolové a
/// kanálové správy (F14a cap `"roles"`, F14c cap `"channels"`).
#[derive(Clone)]
struct ClientEntry {
    tx: ClientTx,
    wants_roles: bool,
    wants_channels: bool,
}

/// Zdieľaný stav WS vrstvy. `Clone` = zdieľané zámky, nie kopie dát.
#[derive(Clone)]
pub struct WsState {
    store: SharedStore,
    /// `client_id → relácia` — registrovaní klienti pre push.
    clients: Arc<Mutex<HashMap<u64, ClientEntry>>>,
    next_id: Arc<AtomicU64>,
    /// Webové originy akceptované pri handshate (F12d, CSWSH) — tá istá
    /// konfigurácia ako `CorsLayer`, lebo oba kontrolujú tú istú dôkazu.
    origins: Vec<String>,
}

/// **F14a:** rukoväť pre REST API, ktorou môže pushnúť zmenu role do
/// živých WS relácií (`RoleUpdate` + auditný `Record`). Drží ten istý
/// map klientov ako `WsState`, preto prežíva aj obnovenie relácií.
#[derive(Clone)]
pub struct WsBroadcaster {
    clients: Arc<Mutex<HashMap<u64, ClientEntry>>>,
}

impl WsBroadcaster {
    /// Push frame všetkým reláciám, ktoré prešli bránou `gate`.
    fn send_filtered(&self, msg: Message, gate: PushGate) {
        let senders: Vec<ClientTx> = self
            .clients
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .filter(|e| match gate {
                PushGate::Everyone => true,
                PushGate::Roles => e.wants_roles,
                PushGate::Channels => e.wants_channels,
            })
            .map(|e| e.tx.clone())
            .collect();
        for sender in senders {
            let _ = sender.send(msg.clone());
        }
    }

    /// Push `RoleUpdate` (MsgType 9) reláciám s capom `"roles"`.
    pub fn broadcast_role_update(
        &self,
        account: [u8; 32],
        username: &str,
        role: &str,
        perms: u64,
    ) {
        let payload = wire::encode_role_update(&wire::RoleUpdate {
            account,
            username: username.to_string(),
            role: role.to_string(),
            perms,
        });
        self.send_filtered(frame(MsgType::RoleUpdate, &payload), PushGate::Roles);
    }

    /// **F14c:** Push `ChannelRoleUpdate` (MsgType 10) reláciám s capom
    /// `"channels"`. Tvar je **stavový** (čím účet v kanáli JE), nie akčný —
    /// `channel_role ∈ owner|admin|member|none`, kde `none` už nie je člen
    /// (rozhodnutie F14c §5).
    pub fn broadcast_channel_role_update(
        &self,
        channel: [u8; 32],
        account: [u8; 32],
        username: &str,
        channel_role: &str,
        muted: bool,
    ) {
        let payload = wire::encode_channel_role_update(&wire::ChannelRoleUpdate {
            channel,
            account,
            username: username.to_string(),
            channel_role: channel_role.to_string(),
            muted,
        });
        self.send_filtered(frame(MsgType::ChannelRoleUpdate, &payload), PushGate::Channels);
    }

    /// Push auditnej obálky zo systémového kanála — len reláciám s capom
    /// `"roles"` (O5: starí klienti systémový kanál ani nevidia v epochách).
    pub fn broadcast_system_record(&self, raw: &[u8]) {
        self.send_filtered(frame(MsgType::Record, raw), PushGate::Roles);
    }

    /// **F14c:** Push auditnej obálky **skupinového** kanála — len reláciám
    /// s capom `"channels"` (rovnaká logika ako systémový kanál, len iný
    /// cap; bez capu klient group kanál nevidí, takže by záznamu nerozumel).
    pub fn broadcast_group_record(&self, raw: &[u8]) {
        self.send_filtered(frame(MsgType::Record, raw), PushGate::Channels);
    }
}

impl WsState {
    pub fn new(store: SharedStore) -> Self {
        Self {
            store,
            clients: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicU64::new(1)),
            origins: default_allowed_origins(),
        }
    }

    /// Nastav originy z `[http] allowed_origins` (stavebník, rovnaký
    /// vzor ako `CallsState::with_moderators`): bez volania zostávajú
    /// defaulty, teda testy a `build_router` sa nesprávajú inak ako pred
    /// F12d okrem toho, že cudzí `Origin` už neprejde.
    pub fn with_origins(mut self, origins: Vec<String>) -> Self {
        self.origins = origins;
        self
    }

    /// Zámok, ktorý nepanikári ani po panike inej úlohy (uzol musí žiť).
    fn lock_store(&self) -> MutexGuard<'_, Store> {
        self.store.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Anonymné id relácie pre logy (MYHSN-19): nie je to token ani PII,
    /// len párni riadky „pripojenie“ a „disconnect“ dohromady.
    fn next_conn_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn register(&self, id: u64, tx: ClientTx, wants_roles: bool, wants_channels: bool) {
        self.clients
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(id, ClientEntry { tx, wants_roles, wants_channels });
    }

    fn unregister(&self, id: u64) {
        self.clients
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&id);
    }

    /// Rukoväť pre REST API (F14a): push zmien role do živých relácií.
    pub fn broadcaster(&self) -> WsBroadcaster {
        WsBroadcaster { clients: Arc::clone(&self.clients) }
    }

    /// Push všetkým pripojeným klientom, ktorí prešli bránou (kritérium
    /// B5a): záznamy **systémového** kanála idú len reláciám s capom
    /// `"roles"` (F14a, O5), záznamy **skupinových** kanálov len reláciám
    /// s capom `"channels"` (F14c, rozhodnutie §4).
    fn broadcast(&self, msg: Message, gate: PushGate) {
        let senders: Vec<ClientTx> = {
            let clients = self.clients.lock().unwrap_or_else(|p| p.into_inner());
            clients
                .values()
                .filter(|e| match gate {
                    PushGate::Everyone => true,
                    PushGate::Roles => e.wants_roles,
                    PushGate::Channels => e.wants_channels,
                })
                .map(|e| e.tx.clone())
                .collect()
        };
        for sender in senders {
            let _ = sender.send(msg.clone());
        }
    }
}

/// Router s WS koncovkou (merge do hlavného routera, stav cez `with_state`).
pub fn ws_router(state: WsState) -> Router {
    Router::new().route("/ws", get(ws_handler)).with_state(state)
}

/// Voliteľná peer IP pre WS logovanie (MYHSN-19). `ConnectInfo` v
/// extenziách je len keď server beží s
/// `into_make_service_with_connect_info` (tak to robí `main.rs`);
/// integrné testy používajú plain `serve` a tam IP jednoducho nie je —
/// relácia sa loguje len s anonymným id.
struct MaybePeer(Option<IpAddr>);

impl<S> FromRequestParts<S> for MaybePeer
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|info| info.0.ip()),
        ))
    }
}

/// Handshake WS + **kontrola `Origin`** (F12d, MYHSN-47: CSWSH).
///
/// Poradie je zámer: `Origin` sa rozhoduje **pred** `on_upgrade`, teda skôr,
/// než sa prečíta čo i len jeden frame a skôr, než vôbec začne relácia
/// (autentifikácia na WS nie je — autoritu má podpis v obálke, D-26).
/// Handshake teda stále nepozná identitu, ale už vie, **ktorá stránka** ho
/// otvorila, a cudziu stránku s nepovoleným originom nepustí dnu.
///
/// Pravidlá sú v [`crate::cors::check_ws_origin`]: bez `Origin` = natívny
/// klient → povoliť; v zozname alebo vlastný host → povoliť; inak 403.
async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<WsState>,
    headers: HeaderMap,
    MaybePeer(peer_ip): MaybePeer,
) -> Response {
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    match check_ws_origin(&state.origins, origin, host) {
        OriginVerdict::Denied => {
            let conn = state.next_conn_id();
            tracing::warn!(
                conn,
                origin = origin.unwrap_or("-"),
                host = host.unwrap_or("-"),
                "ws reject: Origin nie je povoleny (CSWSH)"
            );
            return (
                StatusCode::FORBIDDEN,
                "WebSocket: Origin tohto puvodu tu nie je povoleny\n",
            )
                .into_response();
        }
        // Natívny klient (`dart:io`, `lk` bot) Origin neposiela a apka
        // nasadená priamo na uzle posiela origin vlastného hosta — oba
        // musia žiť, a INFO riadok je dôkaz, že im F12d neprekáža.
        OriginVerdict::Missing | OriginVerdict::SelfOrigin => {
            tracing::info!(
                origin = origin.unwrap_or("-"),
                host = host.unwrap_or("-"),
                "ws handshake: Origin akceptovany (nativny klient alebo uzol sam)"
            );
        }
        // Webový klient z povoleného originu: INFO by zdvojnásobovalo
        // riadky na každé pripojenie, stačí DEBUG.
        OriginVerdict::Allowed => {
            tracing::debug!(
                origin = origin.unwrap_or("-"),
                "ws handshake: Origin povoleny"
            );
        }
    }
    ws.on_upgrade(move |socket| handle_socket(socket, state, peer_ip))
}

// --- framing pomocníci ---------------------------------------------------

/// Zostav frame s aktuálnou verziou drôtu a pošli ako binárnu WS správu.
fn frame(msg_type: MsgType, payload: &[u8]) -> Message {
    let header = Header {
        version: WIRE_VERSION,
        msg_type: msg_type as u8,
        // multiplex kanál relácie (u16) zatiaľ nepoužívame — ChannelId je
        // v payloade obálky; vyhradené pre budúce paralelne toky
        channel: 0,
        len: payload.len() as u32,
    };
    // axum 0.8 berie Binary ako `Bytes`; Vec<u8> → Bytes je lacný move
    Message::Binary(wire::encode_frame(&header, payload).into())
}

fn reject_frame(code: u16, reason: &str) -> Message {
    frame(
        MsgType::Reject,
        &wire::encode_reject(&Reject {
            code,
            reason: reason.to_string(),
        }),
    )
}

fn ack_frame(ack: &Ack) -> Message {
    frame(MsgType::Ack, &wire::encode_ack(ack))
}

fn describe_frame_error(e: &FrameError) -> (u16, String) {
    match e {
        FrameError::VersionMismatch { got } => {
            (REJECT_VERSION, format!("neplatna verzia drata {got}, uzol {WIRE_VERSION}"))
        }
        FrameError::UnknownType { got } => (REJECT_PROTOCOL, format!("neznamy typ spravy {got}")),
        other => (REJECT_PROTOCOL, format!("poskodeny frame: {other:?}")),
    }
}

/// Jednotné logovanie odoslaného `Reject` (MYHSN-19): kód + krátky dôvod.
/// Dôvody sú protokolové texty bez obsahu správ a bez tajných.
fn log_reject(conn: u64, code: u16, reason: &str) {
    tracing::info!(conn, code, reason, "ws reject");
}

/// `HelloAck` payload + catch-up záznamy pod jedným zámkom úložne:
/// medzi dotazom a registráciou relácie nesmie vzniknúť okno, v ktorom
/// by push utiekol a catch-up ho nezachytil (duplikát naopak nevadí).
fn build_hello_ack(store: &mut Store, hello: &wire::Hello) -> (Vec<u8>, Vec<Vec<u8>>) {
    let wants_roles = hello.caps.iter().any(|c| c == CAP_ROLES);
    let wants_channels = hello.caps.iter().any(|c| c == CAP_CHANNELS);
    let system = store.system_channel_id().ok().flatten();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // **F14a:** 4. prvok `HelloAck` len pre klientov s capom `"roles"` a
    // s rozlúšteným session tokenom (5. prvok `Hello`). Token tu je
    // jediné miesto, kde ho WS vôbec vidí — nikam sa nepíše do logu.
    let session_account = match (wants_roles, hello.session.as_deref()) {
        (true, Some(token_hex)) => {
            let token = myhsn_core::record::from_hex(token_hex).filter(|t| t.len() == 32);
            token.and_then(|t| {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(&t);
                store
                    .session_account(&crate::auth::hash_session_token(&buf), now)
                    .ok()
                    .flatten()
            })
        }
        _ => None,
    };
    let role_info = session_account.as_ref().and_then(|account| {
        let (role, perms, _status) = store.account_role(account).ok()??;
        let name = myhsn_core::roles::Role::from_code(role)
            .map(|r| r.name().to_string())
            .unwrap_or_else(|| "user".to_string());
        Some((name, perms as u64))
    });

    // **F14c (MYHSN-58):** 5. prvok `[[channel, role_str, muted]...]` len
    // klientovi s **oboma** capmi (`roles` + `channels`) a platnou session
    // — teda nikdy bez 4. prvku, žiadne pozičné `null`. F14b klient by
    // 5. prvok zahodil, preto je brána povinná (rozhodnutie §5).
    let channel_roles = match (wants_roles && wants_channels, session_account.as_ref()) {
        (true, Some(account)) => Some(
            store
                .channel_roles_for_account(account, now)
                .unwrap_or_default()
                .into_iter()
                .map(|(channel, code, muted)| ChannelRoleEntry {
                    channel,
                    role: myhsn_core::roles::ChannelRole::from_code(code)
                        .map(|r| r.name().to_string())
                        .unwrap_or_else(|| "member".to_string()),
                    muted,
                })
                .collect(),
        ),
        _ => None,
    };

    let channels = store.list_channels().unwrap_or_default();
    // `owner` každého kanála: `Some(Some(_))` = group. Bez capu `"channels"`
    // sú group kanály pred klientom skryté úplne — epochy aj dobehnutie
    // (rozhodnutie F14c §4).
    let owners: HashMap<myhsn_core::seq::ChannelId, Option<Option<[u8; 32]>>> =
        store.channel_owners().unwrap_or_default().into_iter().collect();
    let is_group = |id: &myhsn_core::seq::ChannelId| matches!(owners.get(id), Some(Some(Some(_))));

    let ack = HelloAck {
        version: myhsn_core::PROTO_VERSION,
        caps: NODE_CAPS.iter().map(|c| c.to_string()).collect(),
        // systémový kanál ukážeme len reláciám s capom `"roles"` — starý
        // klient by v ňom videl audity, ktorým nerozumie (O5); group kanály
        // len reláciám s capom `"channels"` (F14c)
        epochs: channels
            .iter()
            .filter(|c| wants_roles || Some(c.id) != system)
            .filter(|c| wants_channels || !is_group(&c.id))
            .map(|c| ChannelEpoch {
                channel: c.id,
                node_epoch: c.node_epoch,
            })
            .collect(),
        role: role_info,
        channel_roles,
    };

    // dobehnutie: od watermarku **vrátane ďalšej pozície** (watermark je
    // najvyššia aplikovaná, D-29) — range rieši aj novšie epochy
    let mut catch_up: Vec<Vec<u8>> = Vec::new();
    for w in &hello.watermarks {
        // **F14c:** group kanál, o ktorý klient bez capu `"channels"`
        // nezaujíma (ani ho nevidí v epochách), mu nedoháňame — inak by
        // dostal záznamy, ktorým nerozumie
        if !wants_channels && is_group(&w.channel) {
            continue;
        }
        let query = RangeQuery {
            channel: w.channel,
            from_epoch: w.node_epoch,
            from_seq: w.node_seq.saturating_add(1),
            limit: CATCH_UP_LIMIT,
        };
        // B6 (MYHSN-8, D-30): čítací pohľad, nie surový log — tombstone
        // záznamy sú už vyhodnotené a cieľ z tohto dobehnutia zmizol.
        // `reader: None`, lebo WS relácia nemá autentizáciu (B5): hide sa
        // týka len jeho autora, ktorému záznam vrátime a filter aplikuje
        // sám vo svojej cache.
        if let Ok(rows) = store.visible_range(&query, None) {
            catch_up.extend(rows.into_iter().map(|(_pos, raw)| raw));
        }
    }
    (wire::encode_hello_ack(&ack), catch_up)
}

// --- spracovanie Record (append) ------------------------------------------

/// Spracuj prijatú obálku a vráte odpoveď (`Ack` alebo `Reject`).
///
/// Postupuje presne po krokoch zadania B5: overenie podpisu autora voči
/// **aktívnemu** device key (B4), `alloc_seq`, idempotentný append podľa
/// hashu, `Ack {hash, stamp}` a push. Chyby vraciame ako `Reject` s
/// kódom `REJECT_RECORD` — relácia môže pokračovať ďalej (odmietnutý
/// záznam neznamená odmietnutú reláciu).
fn process_record(state: &WsState, raw: &[u8]) -> Message {
    let mut store = state.lock_store();

    // 1) obálka musí byť dekódovateľná a platná (verzia, body_hash,
    //    podpis autora — `validate`, D-25)
    let mut env = match Envelope::decode(raw) {
        Ok(env) => env,
        Err(e) => return reject_frame(REJECT_RECORD, &format!("obalka: {e:?}")),
    };
    if let Err(e) = env.validate() {
        return reject_frame(REJECT_RECORD, &format!("validacia obalky: {e:?}"));
    }

    // 2) kanál existuje (jeho soľ doplníme do slepého hashu)
    let channel: Channel = match store.get_channel(&env.stamp.channel) {
        Ok(Some(c)) => c,
        Ok(None) => return reject_frame(REJECT_RECORD, "kanal neexistuje"),
        Err(e) => return reject_frame(REJECT_RECORD, &format!("chyba ulozne: {e}")),
    };

    // 2b) **F14a (MYHSN-56):** systémový kanál je write-protected — audit
    //     rolí píše VÝHRADNE uzol (author = operačný kľúč, `by/by_device`
    //     v tele). Externý klient doň nemôže napísať, ani keby mal platne
    //    podpísanú obálku; audit mimoň nechať prejsť by falzifikoval históriu.
    let system = store.system_channel_id().ok().flatten();
    if Some(env.stamp.channel) == system {
        return reject_frame(
            REJECT_RECORD,
            "systemovy kanal je write-protected (audit pise uzol)",
        );
    }
    if matches!(
        env.kind,
        RecordKind::GrantRole
            | RecordKind::RevokeRole
            | RecordKind::CreateChannel
            | RecordKind::GrantChannelRole
            | RecordKind::RevokeChannelRole
            | RecordKind::TransferChannelOwner
    ) {
        // **F14c (MYHSN-58):** audity kind 6 – 11 píše výhradne uzol, a to v
        // **každom** kanáli (rozhodnutie §3) — nie len v systémovom. Externý
        // append by falzifikoval históriu členstva tej ktorej skupiny, a
        // jedno pravidlo pre všetky audity je ľahšie overiteľné než dve.
        return reject_frame(
            REJECT_RECORD,
            "audit rol alebo skupiny (kind 6..=11) moze appendovat len uzol",
        );
    }

    // 3) B4 brána: autor MUSÍ byť aktívny device key — neznámy alebo
    //    revokovaný kľúč sa odmietne (kritérium B4: podpis revokovaným
    //    kľúčom sa odmietne pri append)
    let author_account: [u8; 32] = match store.device_account_if_active(&env.author.0) {
        Ok(Some(account)) => account,
        Ok(None) => {
            return reject_frame(
                REJECT_RECORD,
                "autorov kľúč nie je aktívny (neznamy alebo revokovany)",
            )
        }
        Err(e) => return reject_frame(REJECT_RECORD, &format!("chyba ulozne: {e}")),
    };

    // 3b) **F14c (MYHSN-58):** právomoc autora v tomto kanáli. V group
    //     kanáli prispievajú (Post/ChatMsg/Reaction) len členovia — alebo
    //     server admin, ktorému práva platia v každom kanáli (rozhodnutie
    //     §6) — a stíšený člen nepíše nič (rozhodnutie §7). Tombstone, Hide
    //     a Erase vlastného príspevku ostávajú aj bývalému členovi; kto smie
    //     siahnuť do cudzieho, rozhoduje `deletion::evaluate` (rozhodnutie
    //     §12).
    let authority = match store.channel_authority(&env.stamp.channel, &author_account) {
        Ok(Some(a)) => a,
        // kanál sme práve overili, že existuje; `None` by bol pretek s
        // mazaním — necháme to na bežnú cestu (záznam len pripojíme)
        Ok(None) => ChannelAuthority::default(),
        Err(e) => return reject_frame(REJECT_RECORD, &format!("chyba ulozne: {e}")),
    };
    if authority.group
        && matches!(
            env.kind,
            RecordKind::Post | RecordKind::ChatMsg | RecordKind::Reaction
        )
    {
        if !authority.is_member() && authority.server_role != 2 {
            return reject_frame(
                REJECT_RECORD,
                "do skupinoveho kanala pisu len clenovia (member/admin/owner)",
            );
        }
        if authority.muted(crate::api::now_secs()) {
            return reject_frame(REJECT_RECORD, "ucet je v tomto kanali stisteny (muted)");
        }
    }

    // 4) idempotentná aplikácia podľa hashu **prijatých** bajtov (D-29):
    //    rovnaká správa už bola prevzatá → Ack s pôvodnou pozíciou
    let client_hash = RecordHash::from_raw(raw).0;
    if let Some((pos, final_hash)) = store.record_by_client_hash(&client_hash).ok().flatten() {
        return ack_frame(&Ack {
            hash: final_hash.0,
            channel: pos.channel,
            node_epoch: pos.node_epoch,
            node_seq: pos.node_seq,
        });
    }

    // 4b) **B6 (MYHSN-8, D-30):** mazacie druhy (tombstone / hide / erase)
    //     musia mať cieľ v logu, v tom istom kanáli a — pre tombstone a
    //     erase — rovnakého autora, ako je podpisovateľ. Overujeme tu,
    //     PRED alokáciou poradia, aby odmietnutý záznam nenechal dieru v
    //     poradí kanála. Poradie oproti kroku 4 nie je náhoda: duplikát
    //     erase by inak narazil na „cieľ je už vymazaný“ a dostal `Reject`
    //     namiesto idempotentného `Ack` (D-29).
    let effect = match crate::deletion::evaluate(&store, &env) {
        Ok(effect) => effect,
        Err(e) => return reject_frame(REJECT_RECORD, &e.message()),
    };

    // 5) poradí prideľuje domáci uzol (D-25) a opečiatkuje
    let pos = match store.alloc_seq(&env.stamp.channel) {
        Ok(pos) => pos,
        Err(e) => return reject_frame(REJECT_RECORD, &format!("alokacia poradia: {e}")),
    };
    let seed = match store.node_sign_seed() {
        Ok(seed) => seed,
        Err(e) => return reject_frame(REJECT_RECORD, &format!("kľúč uzla: {e}")),
    };
    env.stamp = NodeStamp::new(
        pos.channel,
        pos.node_epoch,
        pos.node_seq,
        identity::public_from_seed(&seed),
    );
    // slepý hash patrí sóli kanála — klient ho nepozná a nesmie si ho
    // vynútiť vlastnou hodnotou (D-25)
    env.blind_hash = channel.blind(&env.body_hash);
    env.stamp_sig = Some(identity::sign(&seed, &env.stamp_signing_bytes()));

    let stamped = env.encode();
    let final_hash = env.hash();
    // B6 (MYHSN-8, D-30): erase záznam sa nevkladá „samotný“ — úložňa v tej
    // istej transakcii fyzicky nahradí bajty cieľa, takže log nikdy neobsahuje
    // dôvod so zachovaným obsahom.
    let erase = match &effect {
        crate::deletion::Effect::Erase { target, reason } => Some((target, *reason)),
        _ => None,
    };
    if let Err(e) =
        store.insert_record_erasing(&pos, &final_hash, &stamped, Some(&client_hash), erase)
    {
        // pretek dvoch rovnakých správ: tá druhá vyhrala `client_hash` —
        // odpovedajme jej Ack, nie chybou
        if matches!(e, crate::store::StoreError::ClientHashTaken) {
            if let Some((pos2, hash2)) = store.record_by_client_hash(&client_hash).ok().flatten() {
                return ack_frame(&Ack {
                    hash: hash2.0,
                    channel: pos2.channel,
                    node_epoch: pos2.node_epoch,
                    node_seq: pos2.node_seq,
                });
            }
        }
        return reject_frame(REJECT_RECORD, &format!("vlozenie do logu: {e}"));
    }
    drop(store);

    // 6) push opečiatkovanej obálky všetkým pripojeným (kritérium B5a) —
    //    externé záznamy nikdy nie sú zo systémového kanála (krok 2b) a
    //    záznamy group kanála idú len reláciám s capom `"channels"`
    //    (rozhodnutie F14c §4: bez capu klient skupinu nevidí)
    let gate = if authority.group { PushGate::Channels } else { PushGate::Everyone };
    state.broadcast(frame(MsgType::Record, &stamped), gate);

    ack_frame(&Ack {
        hash: final_hash.0,
        channel: pos.channel,
        node_epoch: pos.node_epoch,
        node_seq: pos.node_seq,
    })
}

// --- slučka relácie --------------------------------------------------------

/// Obálka celej relácie (MYHSN-19): loguje **pripojenie** a **disconnect**
/// na každej ceste — krátky disconnect sa dá diagnostikovať z logov.
/// Logy neobsahujú obsah správ ani tokeny: anonymné id relácie, na INFO
/// len protokolové metadáta, peer IP (osobný údaj) len na DEBUG.
async fn handle_socket(mut ws: WebSocket, state: WsState, peer_ip: Option<IpAddr>) {
    let conn = state.next_conn_id();
    tracing::info!(conn, "ws pripojenie");
    if let Some(ip) = peer_ip {
        tracing::debug!(conn, peer = %ip, "ws peer");
    }
    let reason = run_session(&mut ws, &state, conn).await;
    tracing::info!(conn, reason, "ws disconnect");
    // axum 0.8 nemá `close()` — korektné zavretie je Close frame
    let _ = ws.send(Message::Close(None)).await;
}

/// Handshake + slučka relácie. Vracia **dôvod** ukončenia pre log
/// disconnectu; každé `return` tu znamená koniec relácie.
async fn run_session(ws: &mut WebSocket, state: &WsState, conn: u64) -> &'static str {
    // --- handshake: prvá správa MUSÍ byť Hello (D-24) -------------------
    let first = match tokio::time::timeout(HANDSHAKE_TIMEOUT, ws.recv()).await {
        Ok(Some(Ok(Message::Binary(bytes)))) => bytes,
        Ok(Some(Ok(_))) => {
            log_reject(conn, REJECT_HANDSHAKE, "prva sprava nie je binarny Hello");
            let _ = ws
                .send(reject_frame(REJECT_HANDSHAKE, "prva sprava musi byt binarny Hello"))
                .await;
            return "reject: prva sprava nie je binarny Hello";
        }
        // ticho/chyba: končíme bez Rejectu — log stačí disconnect s dôvodom
        Ok(Some(Err(_))) => return "chyba socketu pri cakani na Hello",
        Ok(None) => return "socket zatvoreny pred Hello",
        Err(_) => return "timeout pri cakani na Hello",
    };

    let (hdr, payload) = match wire::decode_frame(&first) {
        Ok(v) => v,
        Err(e) => {
            let (code, reason) = describe_frame_error(&e);
            log_reject(conn, code, &reason);
            let _ = ws.send(reject_frame(code, &reason)).await;
            return "poskodeny frame Hello";
        }
    };
    if hdr.msg_type != MsgType::Hello as u8 {
        log_reject(conn, REJECT_HANDSHAKE, "prva sprava nie je Hello");
        let _ = ws
            .send(reject_frame(REJECT_HANDSHAKE, "prva sprava nie je Hello"))
            .await;
        return "reject: prva sprava nie je Hello";
    }
    let hello = match wire::decode_hello(payload) {
        Ok(h) => h,
        Err(_) => {
            log_reject(conn, REJECT_HANDSHAKE, "neplatny payload Hello");
            let _ = ws
                .send(reject_frame(REJECT_HANDSHAKE, "neplatny payload Hello"))
                .await;
            return "reject: neplatny payload Hello";
        }
    };
    // verzie/caps/počet watermarkov sú protokolové metadáta — nie obsah
    // správ a nie tajné (MYHSN-19)
    tracing::info!(
        conn,
        proto_min = hello.proto_min,
        proto_max = hello.proto_max,
        caps = ?hello.caps,
        watermarks = hello.watermarks.len(),
        "ws hello"
    );

    // D-22: obojsmerná kompatibilita — uzol rozumie jedine `PROTO_VERSION`;
    // nevyhovujúci rozsah klienta = Reject s kódom (kritérium B5d)
    let proto = myhsn_core::PROTO_VERSION as u16;
    if hello.proto_min > proto || hello.proto_max < proto {
        log_reject(
            conn,
            REJECT_VERSION,
            &format!("uzol hovori proto {proto}, klient pozaduje {}..{}", hello.proto_min, hello.proto_max),
        );
        let _ = ws
            .send(reject_frame(
                REJECT_VERSION,
                &format!(
                    "uzol hovori proto {proto}, klient pozaduje {}..{}",
                    hello.proto_min, hello.proto_max
                ),
            ))
            .await;
        return "reject: nekompatibilna verzia protokolu";
    }

    // --- registrácia, potom HelloAck + catch-up ---------------------------
    //
    // Poradie je zámerne: registrovať **pred** catch-up dotazom. Append,
    // ktorý prebehne medzi registráciou a dotazom, príde ako push aj v
    // catch-up (duplikát rieši idempotentná aplikácia, D-29); opačné
    // poradie by nechalo okno, v ktorom by záznam utiekol obojstranne.
    let (tx, mut rx) = mpsc::unbounded_channel();
    // **F14a:** relácia s capom `"roles"` dostáva rolové správy; bez neho
    // je relácia bitovo identická starému protokolu (žiadny 4. prvok Ack,
    // žiadny MsgType 9, žiadne audity v epochách ani v pushi).
    let wants_roles = hello.caps.iter().any(|c| c == CAP_ROLES);
    let wants_channels = hello.caps.iter().any(|c| c == CAP_CHANNELS);
    state.register(conn, tx, wants_roles, wants_channels);

    let (ack_payload, catch_up) = {
        let mut store = state.lock_store();
        build_hello_ack(&mut store, &hello)
    };

    // HelloAck ide cez rovnaký framing ako všetko ostatné (D-24:
    // verzia je v hlavičke každého frame)
    let caught_up = catch_up.len();
    if ws.send(frame(MsgType::HelloAck, &ack_payload)).await.is_err() {
        state.unregister(conn);
        return "send HelloAck zlyhal";
    }
    for raw in catch_up {
        if ws.send(frame(MsgType::Record, &raw)).await.is_err() {
            state.unregister(conn);
            return "send catch-up zlyhal";
        }
    }
    tracing::debug!(conn, catch_up = caught_up, "ws helloack");

    // --- slučka: Record → Ack/push, Ping → Pong, Hello → re-handshake ----
    let end = 'session: loop {
        tokio::select! {
            maybe = ws.recv() => {
                let msg = match maybe {
                    Some(Ok(m)) => m,
                    _ => break 'session "klient zatvoril socket",
                };
                let bytes = match msg {
                    Message::Binary(b) => b,
                    Message::Close(_) => break 'session "klient poslal Close frame",
                    // Text ignorujeme (protokol je binárny); protocol-level
                    // Ping/Pong rieši axum sám
                    Message::Text(_) | Message::Ping(_) | Message::Pong(_) => continue,
                };
                let (hdr, payload) = match wire::decode_frame(&bytes) {
                    Ok(v) => v,
                    Err(e) => {
                        let (code, reason) = describe_frame_error(&e);
                        log_reject(conn, code, &reason);
                        let _ = ws.send(reject_frame(code, &reason)).await;
                        break 'session "poskodeny frame v relacii";
                    }
                };
                match MsgType::from_u8(hdr.msg_type) {
                    Some(MsgType::Record) => {
                        let reply = process_record(state, payload);
                        if ws.send(reply).await.is_err() {
                            break 'session "send Ack zlyhal";
                        }
                    }
                    Some(MsgType::Hello) => {
                        // re-handshake (reconnect bez nového socketu):
                        // posli HelloAck + catch-up znova. Hello sa
                        // dekoduje PRED zámkom — MutexGuard nesmie žiť
                        // cez `.await` (future musí byť Send)
                        let re_hello = match wire::decode_hello(payload) {
                            Ok(h) => h,
                            Err(_) => {
                                log_reject(conn, REJECT_HANDSHAKE, "neplatny Hello (re-handshake)");
                                let _ = ws
                                    .send(reject_frame(REJECT_HANDSHAKE, "neplatny Hello"))
                                    .await;
                                break 'session "reject: neplatny Hello pri re-handshake";
                            }
                        };
                        tracing::debug!(
                            conn,
                            proto_min = re_hello.proto_min,
                            proto_max = re_hello.proto_max,
                            "ws re-handshake"
                        );
                        let (ack, catch_up) = {
                            let mut store = state.lock_store();
                            build_hello_ack(&mut store, &re_hello)
                        };
                        if ws.send(frame(MsgType::HelloAck, &ack)).await.is_err() {
                            break 'session "send HelloAck zlyhal (re-handshake)";
                        }
                        for raw in catch_up {
                            if ws.send(frame(MsgType::Record, &raw)).await.is_err() {
                                break 'session "send catch-up zlyhal (re-handshake)";
                            }
                        }
                    }
                    Some(MsgType::Ping) => {
                        if ws.send(frame(MsgType::Pong, &[])).await.is_err() {
                            break 'session "send Pong zlyhal";
                        }
                    }
                    Some(MsgType::Pong) => {}
                    // správy, ktoré klient od uzla očakáva, nie posiela
                    _ => {
                        log_reject(conn, REJECT_PROTOCOL, "klient neposiela tento typ spravy");
                        let _ = ws
                            .send(reject_frame(
                                REJECT_PROTOCOL,
                                "klient neposiela tento typ spravy",
                            ))
                            .await;
                        break 'session "reject: neziaduci typ spravy od klienta";
                    }
                }
            }
            // push z broadcastu (iné relácie appendli nový záznam)
            Some(push) = rx.recv() => {
                if ws.send(push).await.is_err() {
                    break 'session "send push zlyhal";
                }
            }
        }
    };

    state.unregister(conn);
    end
}
