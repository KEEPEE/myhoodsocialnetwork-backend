//! REST koncovky hovorov (F10a).
//!
//! - `POST /calls/token` — session token v `Authorization: Bearer` (ako
//!   `GET /devices`); telo `{channel, device_pub?}` → `{url, token, room}`.
//!   Pred mintom uzol **zaistí miestnosť** (`auto_create: false`, spike
//!   nález č. 11: miestnosť vytvorená „do zásoby“ po `empty_timeout` zmizne).
//! - `GET /calls/health` — verejné `{mode, livekit, version}`.
//! - `POST /calls/webhook` — LiveKit webhook (JWT v `Authorization`, viď
//!   [`super::webhook`]). Na `participant_joined` overí členstvo; nečlena
//!   **vyhodí** cez `RemoveParticipant` a odpovie `{"ok": false}`.
//!   LiveKit odpoveď webhooku nevyhodnocuje (fire-and-forget) — samotné
//!   `ok: false` by participanta neodmietlo, odmietnutie robí kick.
//! - `POST /calls/room/ensure` — vytvor miestnosť kanála, ak neexistuje
//!   (idempotentné; session token).
//! - `POST /calls/kick` — moderátor vyhodí účastníka z hovoru
//!   (session token + meno v `[calls] moderators`, inak 403).

use super::token::CallGrant;
use super::webhook::{self, EVENT_PARTICIPANT_JOINED};
use super::{
    device_identity, device_may_join, parse_device_identity, room_name, CallsError, CallsState,
};
use crate::api::{bearer_token, lock, parse_id32_hex, session_account, ApiError};
use crate::store::Store;
use axum::extract::{Json, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use myhsn_core::identity::AccountId;
use myhsn_core::record::from_hex;
use serde::Deserialize;
use serde_json::{json, Value};

/// Router `calls` koncoviek. `build_router` ho merge-ne vedľa ostatných.
pub fn calls_router(state: CallsState) -> Router {
    Router::new()
        .route("/calls/token", post(issue_token))
        .route("/calls/health", get(health))
        .route("/calls/webhook", post(livekit_webhook))
        .route("/calls/room/ensure", post(ensure_room))
        .route("/calls/kick", post(kick))
        .with_state(state)
}

impl From<CallsError> for ApiError {
    fn from(e: CallsError) -> Self {
        match e {
            CallsError::Disabled => ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "hovory sú na tomto uzle vypnuté",
            ),
            CallsError::LiveKit(m) => {
                tracing::warn!(error = %m, "LiveKit Server API zlyhalo");
                ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "LiveKit je nedostupný")
            }
            CallsError::Webhook(m) => {
                tracing::warn!(error = %m, "odmietnutý webhook");
                ApiError::unauthorized("neplatný podpis webhooku")
            }
            other => {
                tracing::warn!(error = %other, "chyba hovorov");
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "interná chyba hovorov")
            }
        }
    }
}

/// Telo `POST /calls/token`.
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    /// hex id kanála (64 znakov)
    pub channel: String,
    /// hex verejný kľúč zariadenia, ktoré sa pripája. Session je per účet
    /// (B4), identita v hovore per zariadenie — bez neho uzol vyberie
    /// jediné aktívne zariadenie účtu, inak 400.
    #[serde(default)]
    pub device_pub: Option<String>,
}

/// Telo `POST /calls/room/ensure`.
#[derive(Debug, Deserialize)]
pub struct EnsureRoomRequest {
    pub channel: String,
}

/// Telo `POST /calls/kick`.
#[derive(Debug, Deserialize)]
pub struct KickRequest {
    /// Miestnosť hovoru — presne to, čo vrátil `POST /calls/token` v poli
    /// `room` (hex id kanála, 64 znakov). Kick sa nikdy nevzťahuje na
    /// miestnosť, ktorú uzol nepozná.
    pub room: String,
    /// Identita participantu v tvare `D<base32>` — to, čo klient vidí v
    /// zozname účastníkov. Správny tvar overujeme, aby moderátor nemohol
    /// vyhodiť cudzieho participantu (napr. egress bota inej aplikácie)
    /// na zdieľanom LiveKit serveri.
    pub identity: String,
}

fn parse_channel(hex: &str) -> Result<[u8; 32], ApiError> {
    parse_id32_hex(hex)
        .ok_or_else(|| ApiError::bad_request("channel musí byť hex 32 bajtov (64 znakov)"))
}

fn forbidden(msg: &str) -> ApiError {
    ApiError::new(StatusCode::FORBIDDEN, msg)
}

/// Telo odpovede `POST /calls/token`. Samostatná funkcia len preto, aby
/// kontrakt poľa `can_moderate` chytil test — skutočná odpoveď vzniká až po
/// `ensure_room`, ktoré bez živého LiveKit servera nenasimulujeme.
fn token_response(url: String, jwt: String, room: String, can_moderate: bool) -> Value {
    json!({
        "url": url,
        "token": jwt,
        "room": room,
        "can_moderate": can_moderate,
    })
}

/// Device kľúč požiadavky: zadaný (musí patriť účtu a byť aktívny), alebo
/// jediné aktívne zariadenie účtu.
fn resolve_device(
    store: &Store,
    account: &AccountId,
    device_pub: Option<&str>,
) -> Result<[u8; 32], ApiError> {
    match device_pub {
        Some(hex) => {
            let pk: [u8; 32] = from_hex(hex.trim())
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| {
                    ApiError::bad_request("device_pub musí mať 32 bajtov (64 hex znakov)")
                })?;
            match store.device_account_if_active(&pk)? {
                Some(owner) if owner == *account => Ok(pk),
                _ => Err(forbidden(
                    "zariadenie nepatrí tomuto účtu alebo je revokované",
                )),
            }
        }
        None => {
            let active: Vec<[u8; 32]> = store
                .list_devices(account)?
                .into_iter()
                .filter(|d| d.key.revoked_at.is_none())
                .map(|d| d.key.public_key.0)
                .collect();
            match active.as_slice() {
                [only] => Ok(*only),
                [] => Err(forbidden("účet nemá aktívne zariadenie")),
                _ => Err(ApiError::bad_request(
                    "účet má viac zariadení — pošli device_pub",
                )),
            }
        }
    }
}

/// `POST /calls/token` — JWT pre vstup do hovoru kanála (TTL 60 s).
pub async fn issue_token(
    State(calls): State<CallsState>,
    headers: HeaderMap,
    Json(req): Json<TokenRequest>,
) -> Result<Json<Value>, ApiError> {
    let tokens = calls.tokens()?.clone();
    let channel = parse_channel(&req.channel)?;
    // zámok úložne len na synchrónnu časť — nikdy cez .await
    let (identity, name) = {
        let store = lock(calls.store());
        let account = session_account(&store, bearer_token(&headers).as_deref())?;
        if store.get_channel(&channel)?.is_none() {
            return Err(ApiError::not_found("kanál neexistuje"));
        }
        let device = resolve_device(&store, &account, req.device_pub.as_deref())?;
        match device_may_join(&store, &device, &channel)? {
            Some(owner) if owner == account => {}
            _ => return Err(forbidden("zariadenie nie je členom kanála")),
        }
        let name = store
            .account_by_id(&account)?
            .map(|a| a.username)
            .ok_or_else(|| ApiError::unauthorized("účet neexistuje"))?;
        (device_identity(&device), name)
    };
    let room = room_name(&channel);
    tokens.ensure_room(&room).await?;
    let jwt = tokens.mint(&CallGrant {
        identity: &identity,
        name: &name,
        room: &room,
    })?;
    let host = headers.get(header::HOST).and_then(|h| h.to_str().ok());
    let url = calls.client_url(host)?;
    // token sa nikdy neloguje
    tracing::info!(%identity, %room, "vydaný token hovoru");
    // `can_moderate` patrí SEM, nie do `GET /calls/health`: health je verejná
    // koncovka bez authentifikácie a tvrdiť v nej, že niekto moderuje, by
    // prezrádzalo zoznam moderátorov komukoľvek. Tu je identita už overená
    // reláciou a klient (F10d) podľa nej ukáže/tají tlačidlo „Vyhodiť“.
    let can_moderate = calls.can_moderate(&name);
    Ok(Json(token_response(url, jwt, room, can_moderate)))
}

/// `GET /calls/health` — verejný stav hovorov.
pub async fn health(State(calls): State<CallsState>) -> Json<Value> {
    Json(json!({
        "mode": calls.mode().as_str(),
        "livekit": calls.status().as_str(),
        "version": calls.version(),
    }))
}

/// `POST /calls/room/ensure` — idempotentné vytvorenie miestnosti kanála.
pub async fn ensure_room(
    State(calls): State<CallsState>,
    headers: HeaderMap,
    Json(req): Json<EnsureRoomRequest>,
) -> Result<Json<Value>, ApiError> {
    let tokens = calls.tokens()?.clone();
    let channel = parse_channel(&req.channel)?;
    {
        let store = lock(calls.store());
        session_account(&store, bearer_token(&headers).as_deref())?;
        if store.get_channel(&channel)?.is_none() {
            return Err(ApiError::not_found("kanál neexistuje"));
        }
    }
    let room = room_name(&channel);
    let created = tokens.ensure_room(&room).await?;
    Ok(Json(json!({ "room": room, "created": created })))
}

/// `POST /calls/kick` — moderátor vyhodí účastníka z hovoru kanála (F10d).
///
/// **Oprávnenie:** uzol v MVP nemá model rolí — `Channel` v `crates/core`
/// nemá majiteľa a [`crate::calls::device_may_join`] považuje za člena
/// akékoľvek atestované aktívne zariadenie kanála (deletion.rs: „koncept
/// admina/operátora uzla v MVP nie je“). Kick preto nerieši „majiteľ
/// kanála“, ale **rozhodnutie operátora uzla**: množinu moderátorov
/// vyhlasuje konfigurácia `[calls] moderators`. Prázdny zoznam = nikto
/// nevyhadzuje (403 pre každého), čo je bezpečný predvolený stav.
///
/// Kick ide cez [`TokenService::kick`] (`RemoveParticipant`), ktoré uzol
/// už používa na nečlenov z webhooku — LiveKit participantovi pošle
/// `RoomDisconnected`, takže obe strany uvidia odchod do ~1 s.
pub async fn kick(
    State(calls): State<CallsState>,
    headers: HeaderMap,
    Json(req): Json<KickRequest>,
) -> Result<Json<Value>, ApiError> {
    let tokens = calls.tokens()?.clone();
    let channel = parse_channel(&req.room)
        .map_err(|_| ApiError::bad_request("room musí byť hex id kanála (64 znakov)"))?;
    let identity = req.identity.trim().to_string();
    if parse_device_identity(&identity).is_none() {
        return Err(ApiError::bad_request(
            "identity musí byť identita zariadenia (D + base32)",
        ));
    }
    let username = {
        let store = lock(calls.store());
        let account = session_account(&store, bearer_token(&headers).as_deref())?;
        if store.get_channel(&channel)?.is_none() {
            return Err(ApiError::not_found("kanál neexistuje"));
        }
        store
            .account_by_id(&account)?
            .map(|a| a.username)
            .ok_or_else(|| ApiError::unauthorized("účet neexistuje"))?
    };
    if !calls.can_moderate(&username) {
        return Err(forbidden("calls: nad hovorom nevládneš"));
    }
    let room = room_name(&channel);
    tokens.kick(&identity, &room).await?;
    // koho kickujeme logujeme (identity nie je tajomstvo), koho a prečo áno
    tracing::info!(%room, %identity, %username, "moderátor vyhodil účastníka");
    Ok(Json(json!({
        "room": room,
        "identity": identity,
        "kicked": true,
    })))
}

/// Rozhodnutie webhooku pre `participant_joined` (čistá funkcia — testy).
/// Chyba úložne = **fail-closed** (nečlen): radšej vyhodiť, než pustiť
/// revokované zariadenie.
pub fn webhook_allows(store: &Store, room: &str, identity: &str) -> bool {
    let (Some(pk), Some(channel)) = (parse_device_identity(identity), parse_id32_hex(room)) else {
        return false;
    };
    match device_may_join(store, &pk, &channel) {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(e) => {
            tracing::error!(error = %e, %identity, %room, "webhook: kontrola členstva zlyhala — fail-closed");
            false
        }
    }
}

/// `POST /calls/webhook` — telo ako `String`: hash sa počíta z presných
/// bajtov, ktoré LiveKit podpísal.
pub async fn livekit_webhook(
    State(calls): State<CallsState>,
    headers: HeaderMap,
    body: String,
) -> Result<Json<Value>, ApiError> {
    let tokens = calls.tokens()?.clone();
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());
    let ev = webhook::verify(&body, auth, tokens.verifier())?;
    if ev.event != EVENT_PARTICIPANT_JOINED {
        tracing::debug!(event = %ev.event, id = %ev.id, "webhook bez akcie");
        return Ok(Json(json!({ "ok": true })));
    }
    let (Some(room), Some(identity)) = (ev.room, ev.identity) else {
        tracing::warn!(id = %ev.id, "participant_joined bez room/identity");
        return Ok(Json(json!({ "ok": true })));
    };
    let allowed = {
        let store = lock(calls.store());
        webhook_allows(&store, &room, &identity)
    };
    if allowed {
        tracing::debug!(%identity, %room, "webhook: člen v hovore");
        return Ok(Json(json!({ "ok": true })));
    }
    tracing::warn!(%identity, %room, mode = calls.mode().as_str(), "webhook: NEčlen v hovore — vyhadzujem");
    // kick mimo požiadavky: LiveKit čaká na odpoveď webhooku obmedzene
    // a odpoveď aj tak nevyhodnocuje
    tokio::spawn(async move {
        if let Err(e) = tokens.kick(&identity, &room).await {
            tracing::warn!(%identity, %room, error = %e, "vyhodenie nečlena zlyhalo");
        }
    });
    Ok(Json(json!({ "ok": false })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::SharedStore;
    use crate::calls::{CallsMode, LiveKitStatus, StatusCell, TokenService};
    use axum::body::Body;
    use axum::http::Request;
    use myhsn_core::channel::ChannelKind;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    const KEY: &str = "myhsn-test-key";
    const SECRET: &str = "myhsn-test-secret-0123456789abcdef-xyz";

    struct Fixture {
        store: SharedStore,
        channel: [u8; 32],
        token: String,
        device: [u8; 32],
    }

    /// Účet „anna“ s jedným zariadením + kanál.
    fn fixture() -> Fixture {
        let mut store = Store::open_in_memory().unwrap();
        let ch = store
            .create_channel("nastienka", ChannelKind::Wall)
            .unwrap();
        let acc = store
            .create_account("anna", "phc-netreba", crate::api::now_secs())
            .unwrap();
        let device = [0x11u8; 32];
        store
            .attest_device_key(
                &acc.id,
                &myhsn_core::identity::DevicePublicKey(device),
                "telefon",
                crate::api::now_secs(),
            )
            .unwrap();
        let tok = crate::auth::new_session_token();
        store
            .put_session(
                &crate::auth::hash_session_token(&tok),
                &acc.id,
                crate::api::now_secs(),
                3600,
            )
            .unwrap();
        Fixture {
            store: Arc::new(Mutex::new(store)),
            channel: ch.id,
            token: myhsn_core::record::to_hex(&tok),
            device,
        }
    }

    fn managed_state(store: SharedStore) -> CallsState {
        // Server API na mŕtvom porte — testy, ktoré ho nevolajú
        CallsState::with_tokens(
            store,
            CallsMode::Managed,
            TokenService::new("http://127.0.0.1:9", KEY, SECRET),
            Some("uzol.local".into()),
            Arc::new(StatusCell::new(LiveKitStatus::Running)),
            Some("1.13.11".into()),
        )
    }

    async fn call(router: Router, req: Request<Body>) -> (StatusCode, String) {
        let resp = router.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    fn post_json(uri: &str, token: Option<&str>, body: Value) -> Request<Body> {
        let mut b = Request::post(uri).header("content-type", "application/json");
        if let Some(t) = token {
            b = b.header("authorization", format!("Bearer {t}"));
        }
        b.body(Body::from(body.to_string())).unwrap()
    }

    #[tokio::test]
    async fn health_reports_mode_status_version() {
        let f = fixture();
        let (st, body) = call(
            calls_router(CallsState::off(f.store.clone())),
            Request::get("/calls/health").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            v,
            json!({"mode": "off", "livekit": "absent", "version": null})
        );

        let (_, body) = call(
            calls_router(managed_state(f.store)),
            Request::get("/calls/health").body(Body::empty()).unwrap(),
        )
        .await;
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            v,
            json!({"mode": "managed", "livekit": "running", "version": "1.13.11"})
        );
    }

    #[tokio::test]
    async fn token_when_off_is_503() {
        let f = fixture();
        let ch = room_name(&f.channel);
        let (st, _) = call(
            calls_router(CallsState::off(f.store)),
            post_json("/calls/token", Some(&f.token), json!({ "channel": ch })),
        )
        .await;
        assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn token_auth_and_membership_gate() {
        let f = fixture();
        let router = calls_router(managed_state(f.store.clone()));
        let ch = room_name(&f.channel);
        // bez session → 401
        let (st, _) = call(
            router.clone(),
            post_json("/calls/token", None, json!({ "channel": ch })),
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        // zlý hex → 400
        let (st, _) = call(
            router.clone(),
            post_json("/calls/token", Some(&f.token), json!({ "channel": "xyz" })),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        // neexistujúci kanál → 404
        let (st, _) = call(
            router.clone(),
            post_json(
                "/calls/token",
                Some(&f.token),
                json!({ "channel": "cd".repeat(32) }),
            ),
        )
        .await;
        assert_eq!(st, StatusCode::NOT_FOUND);
        // cudzie zariadenie → 403
        let (st, _) = call(
            router.clone(),
            post_json(
                "/calls/token",
                Some(&f.token),
                json!({ "channel": ch, "device_pub": "22".repeat(32) }),
            ),
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN);
        // člen prejde bránou → zlyhá až ensure_room na mŕtvom LiveKite (503)
        let (st, _) = call(
            router,
            post_json(
                "/calls/token",
                Some(&f.token),
                json!({ "channel": ch, "device_pub": myhsn_core::record::to_hex(&f.device) }),
            ),
        )
        .await;
        assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Kick (F10d): rebríček oprávnenia. Uzol nemá role, preto bránou
    /// prechádza **len** meno z `[calls] moderators` — a to aj tak narazí
    /// na mŕtvy LiveKit (503), čo dokazuje, že brána nepustila skôr, než
    /// sa vôbec volalo Server API.
    #[tokio::test]
    async fn kick_ladder_session_room_identity_moderator() {
        let f = fixture();
        let room = room_name(&f.channel);
        let target = device_identity(&[0x77u8; 32]);
        let body = |room: &str, identity: &str| json!({ "room": room, "identity": identity });

        // vypnuté hovory → 503 skôr, než sa pozeráme na identitu
        let (st, _) = call(
            calls_router(CallsState::off(f.store.clone())),
            post_json("/calls/kick", Some(&f.token), body(&room, &target)),
        )
        .await;
        assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);

        // bez relácie → 401
        let router = calls_router(managed_state(f.store.clone()));
        let (st, _) = call(
            router.clone(),
            post_json("/calls/kick", None, body(&room, &target)),
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);

        // nezmyselná miestnosť → 400 (kick nikdy nesmie siahnuť do
        // miestnosti, ktorú uzol nepozná)
        let (st, _) = call(
            router.clone(),
            post_json("/calls/kick", Some(&f.token), body("nope", &target)),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);

        // cudzí tvar identity → 400
        let (st, _) = call(
            router.clone(),
            post_json(
                "/calls/kick",
                Some(&f.token),
                body(&room, "egress_worker_2"),
            ),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);

        // well-formed ale neexistujúci kanál → 404
        let (st, _) = call(
            router.clone(),
            post_json(
                "/calls/kick",
                Some(&f.token),
                body(&"cd".repeat(32), &target),
            ),
        )
        .await;
        assert_eq!(st, StatusCode::NOT_FOUND);

        // relácia bez moderátorského mena → 403 (prázdny zoznam = nikto)
        let (st, _) = call(
            router.clone(),
            post_json("/calls/kick", Some(&f.token), body(&room, &target)),
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN);

        // moderátor → bránou prejde, padne až na Server API (503)
        let moderated =
            calls_router(managed_state(f.store.clone()).with_moderators(vec!["anna".into()]));
        let (st, _) = call(
            moderated,
            post_json("/calls/kick", Some(&f.token), body(&room, &target)),
        )
        .await;
        assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Prázdne položky a medziny v konfigurácii neznamenajú právo pre
    /// prázdne meno; veľkosť písmen na menách sa nepozoruje (operátor píše
    /// zoznam do TOML ručne a `username` je v uzle unikátny už pri registrácii).
    #[test]
    fn moderator_list_ignores_case_and_blanks() {
        let f = fixture();
        let s = managed_state(f.store.clone()).with_moderators(vec![
            "  Anna ".into(),
            String::new(),
            "   ".into(),
        ]);
        assert!(s.can_moderate("anna"));
        assert!(s.can_moderate("ANNA"));
        assert!(s.can_moderate(" anna "), "trim na vstupe");
        assert!(!s.can_moderate(""), "prázdne meno nesmie zdediať medzeru");
        assert!(!s.can_moderate("anna2"));
        assert!(
            !managed_state(f.store).can_moderate("anna"),
            "bez zoznamu nikto nemoderuje"
        );
    }

    /// Kontrakt odpovede `POST /calls/token`: pridané `can_moderate`
    /// (klient podľa neho ukáže tlačidlo „Vyhodiť“). Testuje sa samostatná
    /// funkcia, lebo skutočná odpoveď potrebuje živý LiveKit (`ensure_room`).
    #[test]
    fn token_response_carries_can_moderate() {
        let v = token_response("ws://x:7880".into(), "jwt".into(), "room".into(), true);
        assert_eq!(
            v,
            json!({"url": "ws://x:7880", "token": "jwt", "room": "room", "can_moderate": true})
        );
        let v = token_response("ws://x:7880".into(), "jwt".into(), "room".into(), false);
        assert_eq!(v["can_moderate"], json!(false), "false musí byť prítomné");
    }

    #[test]
    fn resolve_device_picks_single_active_or_requires_choice() {
        let f = fixture();
        let mut store = f.store.lock().unwrap();
        let acc = store.device_account_if_active(&f.device).unwrap().unwrap();
        assert_eq!(resolve_device(&store, &acc, None).unwrap(), f.device);
        store
            .attest_device_key(
                &acc,
                &myhsn_core::identity::DevicePublicKey([0x33; 32]),
                "laptop",
                crate::api::now_secs(),
            )
            .unwrap();
        assert!(
            resolve_device(&store, &acc, None).is_err(),
            "dve zariadenia → treba vybrať"
        );
        let hex = myhsn_core::record::to_hex(&[0x33; 32]);
        assert_eq!(
            resolve_device(&store, &acc, Some(&hex)).unwrap(),
            [0x33; 32]
        );
    }

    #[test]
    fn webhook_gate_member_nonmember_revoked() {
        let f = fixture();
        let mut store = f.store.lock().unwrap();
        let room = room_name(&f.channel);
        let ident = device_identity(&f.device);
        assert!(webhook_allows(&store, &room, &ident));
        assert!(
            !webhook_allows(&store, &room, &device_identity(&[0x44; 32])),
            "neznámy kľúč"
        );
        assert!(
            !webhook_allows(&store, &"cd".repeat(32), &ident),
            "neexistujúci kanál"
        );
        assert!(
            !webhook_allows(&store, &room, "egress_bot"),
            "cudzí tvar identity"
        );
        // revokácia → webhook už nepustí (spike G4d+)
        let acc = store.device_account_if_active(&f.device).unwrap().unwrap();
        let id = store.list_devices(&acc).unwrap()[0].id;
        store
            .revoke_device(&acc, id, crate::api::now_secs())
            .unwrap();
        assert!(!webhook_allows(&store, &room, &ident));
    }

    /// Webhook s podpisom z TokenService (rovnaký mechanizmus ako LiveKit):
    /// člen → ok:true, nečlen → ok:false, zlý podpis → 401.
    #[tokio::test]
    async fn webhook_endpoint_signature_and_decision() {
        use base64::Engine as _;
        use sha2::Digest as _;
        let f = fixture();
        let router = calls_router(managed_state(f.store.clone()));
        let room = room_name(&f.channel);
        let sign = |body: &str| {
            let sha = base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(body));
            livekit_api::access_token::AccessToken::with_api_key(KEY, SECRET)
                .with_sha256(&sha)
                .to_jwt()
                .unwrap()
        };
        let ev = |ident: &str| {
            json!({"event": "participant_joined", "id": "EV_1", "room": {"name": room},
                   "participant": {"identity": ident}})
            .to_string()
        };
        let req = |body: String, auth: String| {
            Request::post("/calls/webhook")
                .header("content-type", "application/webhook+json")
                .header("authorization", auth)
                .body(Body::from(body))
                .unwrap()
        };

        let member = ev(&device_identity(&f.device));
        let (st, b) = call(router.clone(), req(member.clone(), sign(&member))).await;
        assert_eq!((st, b.as_str()), (StatusCode::OK, r#"{"ok":true}"#));

        let stranger = ev(&device_identity(&[0x55; 32]));
        let (st, b) = call(router.clone(), req(stranger.clone(), sign(&stranger))).await;
        assert_eq!((st, b.as_str()), (StatusCode::OK, r#"{"ok":false}"#));

        let (st, _) = call(router.clone(), req(stranger.clone(), sign(&member))).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "hash tela nesedí");

        let other =
            json!({"event": "room_finished", "id": "EV_2", "room": {"name": room}}).to_string();
        let (st, b) = call(router, req(other.clone(), sign(&other))).await;
        assert_eq!((st, b.as_str()), (StatusCode::OK, r#"{"ok":true}"#));
    }

    #[test]
    fn client_url_uses_public_host_or_request_host() {
        let f = fixture();
        let s = managed_state(f.store.clone());
        assert_eq!(
            s.client_url(Some("iny:8123")).unwrap(),
            "ws://uzol.local:7880"
        );
        let s2 = CallsState::with_tokens(
            f.store.clone(),
            CallsMode::Managed,
            TokenService::new("http://127.0.0.1:9", KEY, SECRET),
            None,
            Arc::new(StatusCell::new(LiveKitStatus::Running)),
            None,
        );
        assert_eq!(
            s2.client_url(Some("192.0.2.20:8123")).unwrap(),
            "ws://192.0.2.20:7880"
        );
        assert_eq!(s2.client_url(None).unwrap(), "ws://127.0.0.1:7880");
        let ext = CallsState::with_tokens(
            f.store,
            CallsMode::External,
            TokenService::new("https://lk.example.sk", KEY, SECRET),
            Some("wss://lk.example.sk".into()),
            Arc::new(StatusCell::new(LiveKitStatus::Running)),
            None,
        );
        assert_eq!(ext.client_url(Some("x")).unwrap(), "wss://lk.example.sk");
    }
}
