//! Integrné testy F12d (MYHSN-47): **CORS** a kontrola **`Origin` pri WS
//! handshate**. Volajú ten istý router, aký spúšťa `main.rs`
//! ([`node::build_router`]), HTTP čas cez `tower::ServiceExt::oneshot`
//! (presný prístup k hlavičkám, bez soketu), WS čas na **skutočnom
//! serveri** s `tokio-tungstenite` (handshake nemožno simulovať).
//!
//! Kritériá zo zadania, každé má svoj test:
//! - (a) preflight `OPTIONS` s `Access-Control-Request-Method` +
//!   `-Headers: authorization,content-type` z povoleného originu →
//!   `Access-Control-Allow-Origin` **presne** ten origin (+ metódy, hlavičky),
//! - (b) preflight z cudzieho originu → ACAO **chýba**,
//! - (c) bežný `GET` z povoleného originu → ACAO; z cudzieho → chýba,
//! - (d) 404 a 401 nesú ACAO (dôkaz, že `CorsLayer` je najvrchnejšia
//!   vrstva a prehliadač teda vidí skutočný dôvod chyby, nie CORS),
//! - (e) WS: povolený `Origin` → 101, **bez** `Origin` → 101 (natívny
//!   klient), `Origin` vlastného hosta → 101, cudzí `Origin` → **403**,
//! - (f) `[http] allowed_origins` sa **skutočne** číta: vlastný zoznam
//!   nahradí defaulty (inak by test (a) prešiel aj s vypnutou konfiguráciou).

use axum::body::Body;
use axum::http::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, ORIGIN,
};
use axum::http::Request;
use axum::http::{HeaderName, HeaderValue, Method, StatusCode};
use node::api::SharedStore;
use node::cors::HttpConfig;
use node::store::Store;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Error as WsError;
use tower::ServiceExt; // oneshot

/// Webový origin z defaultov (`cors::default_allowed_origins`).
const ALLOWED: &str = "http://192.0.2.10:8080";
/// Origin, ktorý v zozname nie je nikdy.
const EVIL: &str = "http://evil.example";

fn store() -> SharedStore {
    Arc::new(Mutex::new(Store::open_in_memory().unwrap()))
}

/// Router s defaultnou HTTP vrstvou — presne to, čo dostane uzol bez
/// sekcie `[http]` v `node.toml`.
fn router() -> axum::Router {
    node::build_router(
        store(),
        node::media::MediaRuntime::with_dir(std::env::temp_dir().join("myhsn-cors-test-media")),
    )
}

/// (a) Preflight z povoleného originu: uzol musí odpovedať sám (žiadna
/// routa sa nevolá) a musí menovať presne ten origin, metódy aj hlavičky,
/// ktoré klient pyta. `authorization` a `content-type` nie sú
/// CORS-safelisted, takže bez tohto by sa apka k uzlu nedostala.
#[tokio::test]
async fn preflight_from_allowed_origin_is_answered_with_exact_origin() {
    let req = Request::builder()
        .method(Method::OPTIONS)
        .uri("/node/info")
        .header(ORIGIN, ALLOWED)
        .header("access-control-request-method", "POST")
        .header(
            "access-control-request-headers",
            "authorization,content-type",
        )
        .body(Body::empty())
        .unwrap();
    let resp = router().oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK, "preflight odpovedá vrstva");
    assert_eq!(
        resp.headers()
            .get(ACCESS_CONTROL_ALLOW_ORIGIN)
            .map(|v| v.to_str().unwrap()),
        Some(ALLOWED),
        "ACAO musí byť presne origin klienta, nie *"
    );
    let methods = resp
        .headers()
        .get(ACCESS_CONTROL_ALLOW_METHODS)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    for m in ["GET", "POST", "PUT", "PATCH", "DELETE"] {
        assert!(methods.contains(m), "chýba metóda {m} v {methods}");
    }
    let headers = resp
        .headers()
        .get(ACCESS_CONTROL_ALLOW_HEADERS)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_lowercase();
    assert!(
        headers.contains("authorization"),
        "chýba authorization v {headers}"
    );
    assert!(
        headers.contains("content-type"),
        "chýba content-type v {headers}"
    );
    // tower-http posiela Vary automaticky; bez neho by cache vrátila zlý ACAO
    let vary = resp
        .headers()
        .get_all(HeaderName::from_static("vary"))
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join(",")
        .to_lowercase();
    assert!(vary.contains("origin"), "chýba Vary: Origin ({vary})");
}

/// (b) Preflight z cudzieho originu: ACAO nesmie byť vôbec — inak by
/// prehliadač pustil hociktorú stránku.
#[tokio::test]
async fn preflight_from_foreign_origin_has_no_acao() {
    let req = Request::builder()
        .method(Method::OPTIONS)
        .uri("/node/info")
        .header(ORIGIN, EVIL)
        .header("access-control-request-method", "GET")
        .header(
            "access-control-request-headers",
            "authorization,content-type",
        )
        .body(Body::empty())
        .unwrap();
    let resp = router().oneshot(req).await.unwrap();
    assert!(
        resp.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).is_none(),
        "cudzí origin nesmie dostať ACAO"
    );
}

/// (c) Bežný (nepreflight) GET: ACAO len pre povolený origin.
#[tokio::test]
async fn simple_get_carries_acao_only_for_allowed_origin() {
    for (origin, expect) in [(ALLOWED, true), (EVIL, false)] {
        let req = Request::builder()
            .uri("/node/info")
            .header(ORIGIN, origin)
            .header("authorization", "Bearer nejaky-token")
            .body(Body::empty())
            .unwrap();
        let resp = router().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{origin} → 200");
        assert_eq!(
            resp.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).is_some(),
            expect,
            "ACAO pre {origin} očakávaná={expect}"
        );
    }
}

/// (d) Chybové odpovede nesú ACAO. Bez toho by prehliadač pri 401/404
/// nahlásil CORS chybu a vývojár by lial slzy nad vrstvou, ktorá je v
/// poriadku — preto je `CorsLayer` posledná `.layer()` v reťazi.
#[tokio::test]
async fn error_responses_still_carry_acao() {
    // 404: neexistujúca cesta
    let req = Request::builder()
        .uri("/neexistuje")
        .header(ORIGIN, ALLOWED)
        .body(Body::empty())
        .unwrap();
    let resp = router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        resp.headers()
            .get(ACCESS_CONTROL_ALLOW_ORIGIN)
            .map(|v| v.to_str().unwrap()),
        Some(ALLOWED),
        "404 musí niesť ACAO"
    );

    // 401: `GET /me` bez session tokena
    let req = Request::builder()
        .uri("/me")
        .header(ORIGIN, ALLOWED)
        .body(Body::empty())
        .unwrap();
    let resp = router().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        resp.headers()
            .get(ACCESS_CONTROL_ALLOW_ORIGIN)
            .map(|v| v.to_str().unwrap()),
        Some(ALLOWED),
        "401 musí niesť ACAO"
    );
}

/// (f) `[http] allowed_origins` nie je dekorácia: vlastný zoznam nahradí
/// defaulty, takže defaultný pilotný origin zrazu **dostane zamietnuté**.
#[tokio::test]
async fn configured_origins_replace_defaults() {
    let http = HttpConfig {
        allowed_origins: vec!["http://only.example".to_string()],
    };
    let app = node::build_router_with_calls(
        store(),
        node::media::MediaRuntime::with_dir(std::env::temp_dir().join("myhsn-cors-test-media-2")),
        node::calls::CallsState::off(store()),
        &http,
        std::sync::Arc::new(node::roles::AuthConfig::default()),
    );
    let req = Request::builder()
        .uri("/node/info")
        .header(ORIGIN, ALLOWED)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).is_none(),
        "po explicitnom zozname už defaultný origin nesmie prejsť"
    );

    let req = Request::builder()
        .uri("/node/info")
        .header(ORIGIN, "http://only.example")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.headers()
            .get(ACCESS_CONTROL_ALLOW_ORIGIN)
            .map(|v| v.to_str().unwrap()),
        Some("http://only.example")
    );
}

// --- WebSocket: kontrola `Origin` pred upgrade ----------------------------

/// Skutočný server (handshake sa nedá volať cez `oneshot` — treba soket).
async fn spawn_server() -> SocketAddr {
    let app = router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// Požiadavka na `/ws` s voliteľným `Origin` (inak presne to, čo posiela
/// natívny `dart:io` klient — bez `Origin`, overené sondou v F12d).
fn ws_request(
    addr: SocketAddr,
    origin: Option<&str>,
) -> tokio_tungstenite::tungstenite::http::Request<()> {
    let mut req = format!("ws://{addr}/ws").into_client_request().unwrap();
    if let Some(o) = origin {
        req.headers_mut()
            .insert(ORIGIN, HeaderValue::from_str(o).unwrap());
    }
    req
}

/// Vrát status handshakeu: 101 pri úspechu, inak status odpovede uzla.
async fn ws_handshake_status(addr: SocketAddr, origin: Option<&str>) -> StatusCode {
    match connect_async(ws_request(addr, origin)).await {
        Ok((_ws, resp)) => resp.status(),
        Err(WsError::Http(resp)) => resp.status(),
        Err(e) => panic!("caklany HTTP handshake, prislo: {e:?}"),
    }
}

/// (e) Webový klient z povoleného originu: WS prechádza (101). WS
/// nepodlieha CORS, ale `Origin` musí byť v zozname.
#[tokio::test]
async fn ws_handshake_from_allowed_origin_is_101() {
    let addr = spawn_server().await;
    assert_eq!(
        ws_handshake_status(addr, Some(ALLOWED)).await,
        StatusCode::SWITCHING_PROTOCOLS
    );
}

/// (e) Natívny klient `Origin` **neposiela** (`dart:io`, `lk` bot) — musí
/// zostať funkčný, inak by F12d rozbil mobilnú apku.
#[tokio::test]
async fn ws_handshake_without_origin_is_101() {
    let addr = spawn_server().await;
    assert_eq!(
        ws_handshake_status(addr, None).await,
        StatusCode::SWITCHING_PROTOCOLS,
        "natívny klient bez Origin musí prejsť"
    );
}

/// (e) `Origin` vlastného hosta (apka nasadená priamo na uzle, alebo
/// klient, ktorý ju posiela explicitne s adresou uzla) → povoliť.
#[tokio::test]
async fn ws_handshake_from_self_origin_is_101() {
    let addr = spawn_server().await;
    let self_origin = format!("http://{addr}");
    assert_eq!(
        ws_handshake_status(addr, Some(&self_origin)).await,
        StatusCode::SWITCHING_PROTOCOLS,
        "vlastný host ({self_origin}) je povolený"
    );
}

/// (e) CSWSH: cudzí `Origin` → handshake sa nekoná, uzol odpovie 403.
#[tokio::test]
async fn ws_handshake_from_foreign_origin_is_403() {
    let addr = spawn_server().await;
    assert_eq!(
        ws_handshake_status(addr, Some(EVIL)).await,
        StatusCode::FORBIDDEN,
        "cudzí Origin musí byť zamietnutý ešte pred upgrade"
    );
}
