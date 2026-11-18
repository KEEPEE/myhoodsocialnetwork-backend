//! HTTP vrstva uzla (F12d, MYHSN-47): **CORS** pre webové originy a
//! kontrola **`Origin` pri WebSocket handshate** (CSWSH).
//!
//! Prečo to existuje: webová apka (F12f) beží na
//! `http://192.0.2.10:8080/myhoodSN/app/` a volá uzol
//! `http://192.0.2.20:8123` — teda **cross-origin**. Bez
//! `Access-Control-Allow-Origin` prehliadač zahodí každú odpoveď
//! (F12a, `/tmp/mh/f12a/cors.md`: `ERR_FAILED` na `GET /node/info`).
//!
//! Dve nezávislé veci, ktoré sa nesmú zamieňať:
//!
//! 1. **REST/HTTP** — riadi CORS špecifikácia. Vyššia vrstva (`CorsLayer`)
//!    odpovedá na preflight a vracia `Access-Control-Allow-*`. Preflight je
//!    nevyhnutný, lebo klient posiela `authorization: Bearer …` a
//!    `content-type: application/json|application/octet-stream`, čo nie sú
//!    CORS-safelisted hlavičky.
//! 2. **WebSocket** — CORS špecifikácii **nepodlieha** (žiadny preflight,
//!    uzol môže odpovedať bez `Access-Control-Allow-*`; F12a overené
//!    sondou). Hrozí však **CSWSH** (cross-site WebSocket hijacking):
//!    identita je až v `Hello` frame, nie v hlavičke, preto iná stránka
//!    mohla otvoriť WS na náš uzol a posielať `Record`-y. Riešenie je
//!    vlastná kontrola `Origin` hlavičky v [`crate::ws::ws_handler`] —
//!    nie CORS vrstva.
//!
//! ## Pravidlá, ktoré tento modul definuje
//!
//! * `CorsLayer` je v [`crate::build_router_with_calls`] **posledná**
//!   `.layer()`, teda najvrchnejšia: na `OPTIONS` odpovie sama a neverí sa
//!   do handlerov (žiadna auth), a na zvyšné odpovede (vrátane 401/404)
//!   prilepí `Access-Control-Allow-Origin`.
//! * `allow_credentials(false)` — autentifikácia je Bearer token v tele
//!   hlavičky, nie cookie. Ak by sme niekedy presli na cookie reláciu,
//!   treba prepínať aj toto a nikdy dať `*`.
//! * `Vary: Origin` (+ `Access-Control-Request-Method|-Headers`) posiela
//!   tower-http automaticky (default `Vary`), takže zdieľaná cache
//!   nesmie vrátiť zlý header.
//! * WS handshake: `Origin` chýba → **povoliť** (natívni klienti —
//!   `dart:io WebSocket` Origin **neposiela**, overené sondou
//!   `/tmp/mh/f12d/origin_probe.dart` 2026-11-17: handshake obsahuje len
//!   `user-agent`, `connection`, `cache-control`, `accept-encoding`,
//!   `sec-websocket-*`, `host`, `upgrade`). `Origin` prítomný → povoliť
//!   len ak je v `allowed_origins` **alebo** je to origin vlastného hosta
//!   (`http://`/`https://` + `Host` hlavička — istože apka nasadená priamo
//!   na uzle nesmie byť vlastným Originom odmietnutá). Inak **403**.

use serde::Deserialize;

/// Defaultné povolené webové originy, ak `[http]` v `node.toml` chýba.
///
/// Prvé dva sú pilotné webové originy (F12f: apka na `.1:8080` a jej
/// doménový alias), zvyšné tri sú **dočasné dev-only** originy merané v F12d
/// (priamy cross-origin test bez proxy z vývojového kontajnera):
///
/// | origin | čo je |
/// |---|---|
/// | `http://192.0.2.10:8080` | web apka (F12f), hlavný pilot |
/// | `http://web.example.com:8080` | ten istý web cez doménový alias |
/// | `http://127.0.0.1:8088` | lokálny vývoj / F12a spike |
/// | `http://198.51.100.2:8089` | **dev-only**: vývojový kontajner, F12f proxy |
/// | `http://198.51.100.2:8091` | **dev-only**: vývojový kontajner, F12d priamy test |
///
/// Dev-only originy sa majú odstrániť s TLS/doménou (F12e) — uzol na
/// verejnej adrese nemá dôvod púšťať originy z docker siete.
pub fn default_allowed_origins() -> Vec<String> {
    [
        "http://192.0.2.10:8080",
        "http://web.example.com:8080",
        "http://127.0.0.1:8088",
        "http://198.51.100.2:8089",
        "http://198.51.100.2:8091",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

/// Sekcia `[http]` v `node.toml` (D-29: konfigurácia mimo kódu).
///
/// Celá sekcia je **voliteľná** — jej vynechanie znamená
/// [`default_allowed_origins`] (spätná kompatibilita: starý `node.toml`
/// bez `[http]` sa spustí rovnako). `allowed_origins` je zoznam **presných**
/// reťazcov originu (scheme + host + port, bez koncového `/`); porovnávajú
/// sa presne, lebo to vyžaduje CORS špecifikácia.
#[derive(Debug, Clone, Deserialize)]
pub struct HttpConfig {
    /// Webové originy, ktorým uzol odpovie `Access-Control-Allow-Origin`
    /// a ktoré akceptuje ako `Origin` pri WebSocket handshate.
    #[serde(default = "default_allowed_origins")]
    pub allowed_origins: Vec<String>,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            allowed_origins: default_allowed_origins(),
        }
    }
}

impl HttpConfig {
    /// Očistené originy (trim, prázdne položky preč) — jediné miesto,
    /// kde sa konfigurácia mení na to, čo používajú obe kontroly.
    pub fn origins(&self) -> Vec<String> {
        self.allowed_origins
            .iter()
            .map(|o| o.trim().trim_end_matches('/').to_string())
            .filter(|o| !o.is_empty())
            .collect()
    }

    /// `CorsLayer` pre tento config. Metódy zahŕňajú aj `PATCH`, hoci ho
    /// zadanie F12d nevymenovalo — apka ho reálne posiela (`PATCH /me`,
    /// F12a §3), a `OPTIONS` kvôli preflightu na `OPTIONS` požiadavku.
    pub fn cors_layer(&self) -> tower_http::cors::CorsLayer {
        use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
        use axum::http::HeaderValue;
        use axum::http::Method;
        use std::time::Duration;
        use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};

        let origins: Vec<HeaderValue> = self
            .origins()
            .into_iter()
            .filter_map(|o| HeaderValue::from_str(&o).ok())
            .collect();

        CorsLayer::new()
            // `list` = presná zhoda; nepovolenému originu header **nepridáme**
            // (nie `*`), čo je presne to, čo web očakáva.
            .allow_origin(AllowOrigin::list(origins))
            .allow_methods(AllowMethods::list([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
                Method::OPTIONS,
            ]))
            .allow_headers(AllowHeaders::list([AUTHORIZATION, CONTENT_TYPE]))
            .allow_credentials(false)
            // Preflight si prehliadač pamätá hodinu — bez toho by každá
            // akcia v apke znamenala ďalší OPTIONS na uzol.
            .max_age(Duration::from_secs(3600))
    }
}

/// Rozhodnutie o `Origin` pri **WebSocket** handshate (CSWSH).
///
/// Nie je to CORS: WS nepotrebuje `Access-Control-Allow-*`, len rozhodnutie
/// „prijmú tento handshake, alebo nie“.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginVerdict {
    /// Klient `Origin` neposlal → **povoliť** (natívni klienti:
    /// `dart:io`, `lk` bot, curl). Bez tohto by sme rozbití natívny klient.
    Missing,
    /// `Origin` je v zozname povolených webových originov → povoliť.
    Allowed,
    /// `Origin` je origin **vlastného hosta** (`Host` hlavička) → povoliť.
    /// Kryje apku nasadenú priamo na uzle a natívneho klienta, ktorý
    /// `Origin` posiela explicitne s adresou uzla.
    SelfOrigin,
    /// `Origin` prítomný a nepatrný → **zamietnuť** (403 handshake).
    Denied,
}

/// Rozhodni o WS handshate na základe `Origin` a `Host`.
///
/// `origin`/`host` sú hodnoty hlavičiek tak, ako prišli (`None` = hlavička
/// chýba). `allowed` je zoznam z [`HttpConfig::origins`].
///
/// Vlastný origin počítame z `Host` hlavičky s `http://` **aj** `https://`:
/// uzol sám nepozná, či je pred ním TLS terminátor, a `Host` obsahuje
/// aj port, takže origin je jednoznačný.
pub fn check_ws_origin(
    allowed: &[String],
    origin: Option<&str>,
    host: Option<&str>,
) -> OriginVerdict {
    let Some(origin) = origin.map(str::trim).filter(|o| !o.is_empty()) else {
        return OriginVerdict::Missing;
    };
    if allowed.iter().any(|a| a == origin) {
        return OriginVerdict::Allowed;
    }
    if let Some(host) = host.map(str::trim).filter(|h| !h.is_empty()) {
        if origin == format!("http://{host}") || origin == format!("https://{host}") {
            return OriginVerdict::SelfOrigin;
        }
    }
    OriginVerdict::Denied
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Celý `node.toml` — rovnaké viazanie sekcie ako `main::NodeConfig`,
    /// aby test dokazoval, že `[http]` je **sekcia** (nie kľúče na vrchole).
    #[derive(Deserialize)]
    struct Doc {
        #[serde(default)]
        http: HttpConfig,
    }

    fn parse(toml: &str) -> HttpConfig {
        toml::from_str::<Doc>(toml).expect("platny TOML").http
    }

    /// Spätná kompatibilita: sekcia `[http]` je voliteľná a bez nej sú
    /// defaulty — starý `node.toml` (len `listen`/`data_dir`/`[media]`/
    /// `[calls]`) sa MUSÍ naďalej naštartovať. Neznáme kľúče serde
    /// ignoruje, takže sekcia ustojí aj budúce rozšírenie.
    #[test]
    fn http_section_is_optional_with_defaults() {
        let bare = parse("listen = \"0.0.0.0:8123\"\ndata_dir = \"./data\"\n");
        assert_eq!(bare.allowed_origins, default_allowed_origins());
        // prázdna sekcia = tiež defaulty (nie prázdny zoznam)
        assert_eq!(parse("[http]\n").allowed_origins, default_allowed_origins());
        // ani `[calls]` pred tým nepokazí čítanie
        let with_calls =
            parse("[calls]\nmode = \"off\"\n[http]\nallowed_origins = [\"https://a.example\"]\n");
        assert_eq!(
            with_calls.allowed_origins,
            vec!["https://a.example".to_string()]
        );
    }

    /// Explicitný zoznam **nahradí** defaulty (operátor uzla rozhoduje),
    /// nie ho rozšíri.
    #[test]
    fn explicit_list_replaces_defaults() {
        let cfg = parse("[http]\nallowed_origins = [\"https://hood.example\"]\n");
        assert_eq!(cfg.origins(), vec!["https://hood.example".to_string()]);
    }

    /// Defaulty sú použiteľné presne: absolute http(s) originy bez koncového
    /// lomítka a bez duplicít — inak by `AllowOrigin::list` porovnával
    /// reťazce, ktoré web nikdy nepošle.
    #[test]
    fn defaults_are_exact_origins() {
        let d = default_allowed_origins();
        assert_eq!(d.len(), 5, "2 pilotove webove + 3 docasne dev-only");
        for o in &d {
            assert!(o.starts_with("http://") || o.starts_with("https://"), "{o}");
            assert!(!o.ends_with('/'), "{o} nesmie mat koncovy lomítko");
            assert!(!o.contains("://*"), "{o} nesmie byt wildcard");
        }
        let mut sorted = d.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), d.len(), "bez duplicít");
    }

    /// `origins()` znáša operátorovské nedbanlivosti (medzery, koncové
    /// lomítko, prázdne položky) — inak by `node.toml` ticho vypol web.
    #[test]
    fn origins_normalizes_whitespace_and_trailing_slash() {
        let cfg = HttpConfig {
            allowed_origins: vec![
                "  http://a.example:8080/ ".into(),
                "".into(),
                "http://b.example".into(),
            ],
        };
        assert_eq!(
            cfg.origins(),
            vec![
                "http://a.example:8080".to_string(),
                "http://b.example".to_string()
            ]
        );
    }

    /// Matica WS kontroly — každá vetva osobitne, lebo natívny klient
    /// (chýbajúci `Origin`) musí zostať funkčný a cudzí origin zomrieť.
    #[test]
    fn ws_origin_matrix() {
        let allowed = default_allowed_origins();
        let host = "192.0.2.20:8123";

        // natívny klient bez Originu (dart:io, lk bot) → povoliť
        assert_eq!(
            check_ws_origin(&allowed, None, Some(host)),
            OriginVerdict::Missing
        );
        assert_eq!(
            check_ws_origin(&allowed, Some(""), Some(host)),
            OriginVerdict::Missing
        );

        // povolený webový origin → povoliť
        assert_eq!(
            check_ws_origin(&allowed, Some("http://192.0.2.10:8080"), Some(host)),
            OriginVerdict::Allowed
        );

        // vlastný host (apka na uzle, alebo klient s explicitným Originom
        // adresy uzla) → povoliť, http aj https
        assert_eq!(
            check_ws_origin(&allowed, Some("http://192.0.2.20:8123"), Some(host)),
            OriginVerdict::SelfOrigin
        );
        assert_eq!(
            check_ws_origin(&allowed, Some("https://192.0.2.20:8123"), Some(host)),
            OriginVerdict::SelfOrigin
        );

        // cudzí origin → zamietnuť (CSWSH)
        assert_eq!(
            check_ws_origin(&allowed, Some("http://evil.example"), Some(host)),
            OriginVerdict::Denied
        );
        // vlastný host, ale iný Host (proxy) → cudzí origin, nie self
        assert_eq!(
            check_ws_origin(
                &allowed,
                Some("http://192.0.2.20:8123"),
                Some("127.0.0.1:8123")
            ),
            OriginVerdict::Denied
        );
        // self-origin bez Host hlavičky → nedá sa dokázať → zamietnuť
        assert_eq!(
            check_ws_origin(&allowed, Some("http://192.0.2.20:8123"), None),
            OriginVerdict::Denied
        );
        // port je súčasť originu: 8123 ≠ 8124
        assert_eq!(
            check_ws_origin(&allowed, Some("http://192.0.2.20:8124"), Some(host)),
            OriginVerdict::Denied
        );
    }

    /// Zoznam bez povolených originov neznamená „povoliť všetko“ —
    /// operátor, ktorý napíše `allowed_origins = []`, vypne web.
    #[test]
    fn empty_list_denies_every_explicit_origin() {
        let none: Vec<String> = Vec::new();
        assert_eq!(
            check_ws_origin(&none, Some("http://a.example"), Some("h")),
            OriginVerdict::Denied
        );
        assert_eq!(
            check_ws_origin(&none, None, Some("h")),
            OriginVerdict::Missing
        );
    }

    /// `CorsLayer` sa dá zostaviť z defaultov (panika by bola pri štarte
    /// uzla) a `AllowOrigin::list` neobsahuje `*`.
    #[test]
    fn cors_layer_builds_from_defaults() {
        let _layer = HttpConfig::default().cors_layer();
    }
}
