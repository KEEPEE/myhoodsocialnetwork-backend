//! Knižnica uzla MyHoodSocialNetwork (D-31: uzol beží len ako serverový
//! program — VPS / mini-PC / Raspberry Pi / naša VM).
//!
//! B1 scaffold: REST healthz + info, konfigurácia z TOML, logging tracing.
//! B2 (MYHSN-4): SQLite úloža záznamov — rusqlite implementácia traitov z
//! jadra, WAL, migrácie v kóde ([`store`]).
//! B3 (MYHSN-5): kanály, alokátor `node_seq` per kanál, epochy pri obnove z
//! zálohy a REST placeholder `GET/POST /channels`, `GET /node/info` ([`api`]).
//! B4 (MYHSN-6): účty a device keys — Argon2id login, atesty, revokácia,
//! session tokeny ([`auth`], `store`, REST `/register`, `/login`, `/devices`).
//! B5 (MYHSN-7): WebSocket sync — Hello/HelloAck/Reject s verziami a caps,
//! watermark catch-up, idempotentný append s pečiatkou uzla a push
//! pripojeným klientom ([`ws`], framing [`myhsn_core::wire`], D-24).
//! B6 (MYHSN-8): mazanie — aplikačná vrstva troch druhov z **D-30**
//! ([`deletion`]): tombstone a erase smie len autor cieľa, hide ktokoľvek
//! pre seba; erase **fyzicky** nahradí obsah cieľa v tej istej transakcii
//! ([`store::Store::insert_record_erasing`]) a čítací pohľad
//! ([`store::Store::visible_range`]) vyhodnotí mazacie záznamy, takže
//! tombstonovaný príspevok čitateľ už nikdy neuzrie.
//! F10a: skupinové hovory cez LiveKit SFU ([`calls`]) — mint tokenov,
//! webhook kontrola členstva, LiveKit ako spravovaný potomok uzla.
//!
//! Lib-cieľ existuje preto, aby integrné testy (`tests/`) vedeli spustiť
//! skutočný router na ephemeral porti; binárka [`main`] je tenký obal
//! (konfigurácia + logging + bind).

pub mod api;
pub mod auth;
pub mod calls;
pub mod cors;
pub mod deletion;
pub mod media;
pub mod media_clean;
pub mod roles;
pub mod store;
pub mod ws;

use axum::routing::get;
use axum::Router;

/// Liveness probe pre I1 (deploy na pilotnom uzle, port 8123): 200 „ok“.
pub async fn healthz() -> &'static str {
    "ok"
}

/// Krátky info text o uzle.
pub async fn index() -> String {
    format!(
        "MyHoodSocialNetwork node v{}\nproto: {}\nB2–B8 — dostupné: GET /healthz, GET /, \
         GET /channels, POST /channels, GET /node/info, POST /register, POST /login, \
         GET/POST /devices, DELETE /devices/{{id}}, GET /members, GET/PATCH /me, \
         GET /ws (WebSocket sync), \
         POST /media, GET /media/{{id}} (pominuteľné bloby, D-33), \
         PUT/DELETE /channels/{{id}}/cover a PUT/DELETE /me/avatar (trvalé bloby, B8), \
         GET /records/{{hash}} (surový log) a GET /channels/{{id}}/records (čítací pohľad \
         s vyhodnoteným mazaním, B6 / D-30), \
         POST /calls/token, GET /calls/health, POST /calls/webhook, \
         POST /calls/room/ensure (hovory cez LiveKit, F10a).\n",
        env!("CARGO_PKG_VERSION"),
        myhsn_core::PROTO_VERSION,
    )
}

/// Úplný router uzla — healthz + REST ([`api::api_router`]) + WS
/// ([`ws::ws_router`]) + média ([`media::media_router`]). Integrné testy
/// spúšťajú presne tento router. Hovory sú tu vypnuté (`mode = off`) a
/// CORS/`Origin` používajú defaultné originy ([`cors::default_allowed_origins`]);
/// uzol s `[calls]` a `[http]` volá [`build_router_with_calls`].
pub fn build_router(shared: api::SharedStore, media_rt: media::MediaRuntime) -> Router {
    let calls = calls::CallsState::off(shared.clone());
    build_router_with_calls(
        shared,
        media_rt,
        calls,
        &cors::HttpConfig::default(),
        std::sync::Arc::new(roles::AuthConfig::default()),
    )
}

/// [`build_router`] + koncovky hovorov ([`calls::calls_router`]) + HTTP
/// vrstva z `[http]` ([`cors`]). Stav hovorov ide aj ako `Extension`, aby
/// `DELETE /devices/{id}` vedel revokované zariadenie vyhodiť z
/// prebiehajúcich hovorov.
///
/// **Po poradí `.layer()` záleží:** `CorsLayer` je posledná, teda
/// najvrchnejšia. Na `OPTIONS` odpovie sama (k preflightu patrí odpovedať
/// skôr, než niečo overujeme alebo routujeme) a na každú ďalšiu odpoveď —
/// vrátane 401 a 404 — prilepí `Access-Control-Allow-Origin`. Keby bola
/// pod `Extension` alebo pod routami, 401/404 by CORS hlavičku nedostali a
/// prehliadač by nahlásil CORS chybu namiesto skutočného dôvodu.
pub fn build_router_with_calls(
    shared: api::SharedStore,
    media_rt: media::MediaRuntime,
    calls_state: calls::CallsState,
    http: &cors::HttpConfig,
    auth: std::sync::Arc<roles::AuthConfig>,
) -> Router {
    let ws_state = ws::WsState::new(shared.clone()).with_origins(http.origins());
    let media_state = media::MediaState::new(shared.clone(), media_rt);
    Router::new()
        .route("/healthz", get(healthz))
        .route("/", get(index))
        // F14a: API dostane [auth] politiku a rukoväť na WS push zmien role
        .merge(api::api_router_full(shared, auth, Some(ws_state.broadcaster())))
        .merge(ws::ws_router(ws_state))
        .merge(media::media_router(media_state))
        .merge(calls::calls_router(calls_state.clone()))
        .layer(axum::Extension(calls_state))
        // POSLEDNÁ `.layer()` = najvrchnejšia (F12d, MYHSN-47) — viď higher
        // dokumentácia. WS kontrola `Origin` je samostatná, lebo WS nepodlieha
        // CORS špecifikácii ([`cors`]).
        .layer(http.cors_layer())
}
