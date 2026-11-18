//! Binárka uzla — tenký spúšťač nad knižnicou [`node`].
//!
//! Konfigurácia z TOML, logging tracing, otvorenie úložne a bind. Router
//! stavia [`node::build_router`] (zdieľaný s integrnými testmi).

use axum::Router;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Konfigurácia uzla zo TOML súboru (D-29: konfigurácia mimo kódu).
#[derive(Debug, Deserialize)]
struct NodeConfig {
    /// Adresa, na ktorej uzol počúva (default 0.0.0.0:8123 — pilot na vývojovom hostovi).
    #[serde(default = "default_listen")]
    listen: String,
    /// Adresár s dátami (SQLite + media; B2).
    #[serde(default = "default_data_dir")]
    data_dir: String,
    /// Sekcia `[media]` (B7/MYHSN-9, D-33): kvóty a TTL pominuteľných blobov.
    /// **Voliteľná** — jej absencia znamená defaulty (spätná kompatibilita).
    #[serde(default)]
    media: node::media::MediaConfig,
    /// Sekcia `[calls]` (F10a): hovory cez LiveKit SFU — `mode = off |
    /// managed | external`. **Voliteľná** — absencia = `off`.
    #[serde(default)]
    calls: node::calls::CallsConfig,
    /// Sekcia `[http]` (F12d, MYHSN-47): webové originy pre CORS a
    /// pripustené `Origin` pri WebSocket handshate. **Voliteľná** —
    /// absencia znamená defaulty [`node::cors::default_allowed_origins`]
    /// (spätná kompatibilita: starý `node.toml` bez `[http]` naštartuje
    /// a web funguje bez zásahu operátora).
    #[serde(default)]
    http: node::cors::HttpConfig,
    /// Sekcia `[auth]` (F14a, MYHSN-56): politika registrácie a bootstrap
    /// prvého admina. **Voliteľná** — absencia znamená `open` a žiadny
    /// bootstrap, teda správanie presne ako pred F14a.
    #[serde(default)]
    auth: node::roles::AuthConfig,
}

fn default_listen() -> String {
    "0.0.0.0:8123".to_string()
}

fn default_data_dir() -> String {
    "./data".to_string()
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            data_dir: default_data_dir(),
            media: node::media::MediaConfig::default(),
            calls: node::calls::CallsConfig::default(),
            http: node::cors::HttpConfig::default(),
            auth: node::roles::AuthConfig::default(),
        }
    }
}

impl NodeConfig {
    /// Cesta k databázovému súboru uzla.
    fn db_path(&self) -> PathBuf {
        PathBuf::from(&self.data_dir).join("myhsn.db")
    }
}

/// Načítaj konfiguráciu: cesta z env `MYHSN_NODE_CONFIG`, inak
/// `config/node.toml` relatívne k CWD. Neexistujúci/neplatný súbor
/// nepadá — použijú sa výchozie hodnoty a napíšeme to do logu.
fn load_config() -> NodeConfig {
    let path = std::env::var("MYHSN_NODE_CONFIG").unwrap_or_else(|_| "config/node.toml".into());
    match std::fs::read_to_string(&path) {
        Ok(text) => match toml::from_str::<NodeConfig>(&text) {
            Ok(cfg) => {
                tracing::info!(path = %path, listen = %cfg.listen, data_dir = %cfg.data_dir, "konfigurácia načítaná z TOML");
                cfg
            }
            Err(e) => {
                tracing::warn!(path = %path, error = %e, "neplatný TOML — používam výchozie hodnoty");
                NodeConfig::default()
            }
        },
        Err(_) => {
            tracing::info!(path = %path, "súbor konfigurácie nenájdený — používam výchozie hodnoty");
            NodeConfig::default()
        }
    }
}

#[tokio::main]
async fn main() {
    // Logging: tracing + env filter (RUST_LOG, default info).
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    let cfg = load_config();

    // Úloža (B2): otvor SQLite, aplikuj migrácie, priprav zdieľaný stav.
    let db_path = cfg.db_path();
    let store = match node::store::Store::open(&db_path) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(path = %db_path.display(), error = %e, "úloža sa nedá otvoriť");
            std::process::exit(1);
        }
    };
    tracing::info!(
        path = %db_path.display(),
        schema = store.schema_version().unwrap_or(0),
        journal = %store.journal_mode().unwrap_or_default(),
        "úloža otvorená"
    );
    // ID uzla = verejný kľúč operačnej pečiatky (D-27); vyžiadam ho hneď
    // pri štarte, aby sa generoval raz a bol stabilný.
    let shared: node::api::SharedStore = Arc::new(Mutex::new(store));
    {
        let mut s = shared.lock().unwrap_or_else(|p| p.into_inner());
        match s.node_id() {
            Ok(id) => tracing::info!(node_id = %myhsn_core::record::to_hex(&id), "ID uzla"),
            Err(e) => tracing::warn!(error = %e, "ID uzla sa nedá zistiť"),
        }
    }

    // F14a (MYHSN-56): systémový kanál auditu rolí + bootstrap prvého
    // admina. Kanál vytvoríme raz (idempotentné, id držíme v meta — O5);
    // bootstrap povýši účet z `[auth] bootstrap_admin`, ak uzol ešte
    // admina nemá (O2 — rieši aj migráciu DB, kde účet existuje skôr).
    {
        let mut s = shared.lock().unwrap_or_else(|p| p.into_inner());
        match s.ensure_system_channel() {
            Ok(id) => {
                tracing::info!(
                    channel = %myhsn_core::record::to_hex(&id),
                    "systémový kanál rolí pripravený (F14a)"
                )
            }
            Err(e) => tracing::warn!(error = %e, "systémový kanál sa nedá pripraviť"),
        }
        if let Some(name) = cfg.auth.bootstrap_admin.as_deref() {
            match s.bootstrap_admin_at_startup(name) {
                Ok(true) => tracing::info!(
                    account = %name,
                    "bootstrap_admin povýšený na admina ([auth] bootstrap_admin, F14a)"
                ),
                Ok(false) => {
                    let exists = s
                        .account_by_username(name.trim())
                        .map(|a| a.is_some())
                        .unwrap_or(false);
                    if exists {
                        tracing::info!(
                            account = %name,
                            "bootstrap_admin preskočený — uzol už má admina"
                        )
                    } else {
                        tracing::info!(
                            account = %name,
                            "bootstrap_admin účet ešte neexistuje — povýši sa pri registrácii"
                        )
                    }
                }
                Err(e) => tracing::warn!(error = %e, "bootstrap_admin zlyhal"),
            }
        }
        // O11: runtime override tieni TOML — povieme to operátorovi,
        // aby nečudoval prečo `[auth]` nemá efekt
        if let Ok(Some(p)) = s.policy_override() {
            if p != cfg.auth.registration_policy.as_str() {
                tracing::warn!(
                    override_policy = %p,
                    config_policy = %cfg.auth.registration_policy,
                    "registrácia sa riadi override z /admin/settings, nie TOML [auth]"
                );
            }
        }
        tracing::info!(
            registration_policy = %cfg.auth.registration_policy,
            bootstrap_admin = %cfg.auth.bootstrap_admin.as_deref().unwrap_or("-"),
            "F14a: rolový systém aktívny"
        );
    }

    // Médium (B7/MYHSN-9, D-33): vyrieš adresár blobov a limity z [media].
    let media_rt = node::media::MediaRuntime::from_config(&cfg.media, &cfg.data_dir);
    tracing::info!(
        dir = %media_rt.dir.display(),
        max_upload = media_rt.max_upload_bytes,
        max_per_account = media_rt.max_bytes_per_account,
        ttl = media_rt.ephemeral_ttl_secs,
        cover_max = media_rt.cover_max_bytes,
        avatar_max = media_rt.avatar_max_bytes,
        "media povolené (POST/GET /media, PUT/DELETE cover+avatar)"
    );

    // Sweep pri štarte (B8, doc 24 krok 7): zotavenie z pádu medzi zápisom
    // súboru a commitom — zmazať .tmp súbory, súbory bez riadka a trvalé
    // riadky bez ukazovateľa.
    let sweep = node::media::sweep_orphans(&shared, &media_rt);
    if sweep.tmp_files + sweep.orphan_files + sweep.orphan_rows > 0 {
        tracing::info!(
            tmp = sweep.tmp_files,
            orphan_files = sweep.orphan_files,
            orphan_rows = sweep.orphan_rows,
            "media sweep vyčistil siroty"
        );
    }

    // Hovory (F10a): managed spustí supervízora LiveKitu (stiahnutie,
    // potomok, health, backoff); external len sondu; off nič.
    let (calls_state, calls_handle) =
        node::calls::CallsState::start(&cfg.calls, &cfg.data_dir, &cfg.listen, shared.clone());

    // Router stavia lib (zhodný s integrnými testami): healthz, REST, WS,
    // media + calls.
    let app: Router = node::build_router_with_calls(
        shared,
        media_rt,
        calls_state,
        &cfg.http,
        Arc::new(cfg.auth),
    );
    // F12d (MYHSN-47): mriežka HTTP vrstvy patrí do štartovacieho logu —
    // je to dôkaz, aké originy uzol akceptuje (REST CORS aj WS `Origin`),
    // bez toho aby sme museli čítať konfiguráciu od operátora z logu.
    tracing::info!(
        allowed_origins = %cfg.http.origins().join(","),
        "HTTP vrstva: CORS + WS Origin kontrola ([http] allowed_origins)"
    );

    let listener = match tokio::net::TcpListener::bind(&cfg.listen).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(listen = %cfg.listen, error = %e, "bind zlyhal");
            std::process::exit(1);
        }
    };

    tracing::info!(listen = %cfg.listen, data_dir = %cfg.data_dir, "uzol spustený (B2–B5)");
    // ConnectInfo<SocketAddr> slúži WS logovaniu (MYHSN-19): peer IP sa
    // loguje na DEBUG. Integrné testy volajú build_router s plain serve —
    // tam ConnectInfo chýba a handler s tým počíta (Option).
    let serve = app.into_make_service_with_connect_info::<SocketAddr>();
    // Shutdown (F10a): pri SIGINT/SIGTERM najprv zastav LiveKit potomka
    // (SIGTERM / Job Object), až potom koniec procesu. Nie graceful
    // shutdown axum — dlhé WS relácie by ho blokovali; správanie REST/WS
    // pri ukončení ostáva ako predtým (proces skončí).
    let exit_code = tokio::select! {
        res = axum::serve(listener, serve) => match res {
            Ok(()) => 0,
            Err(e) => {
                tracing::error!(error = %e, "server zlyhal");
                1
            }
        },
        _ = shutdown_signal() => {
            tracing::info!("signál ukončenia — zastavujem uzol");
            0
        }
    };
    if let Some(handle) = calls_handle {
        handle.stop().await;
    }
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
}

/// Ctrl-C všade, na unixe aj SIGTERM (systemd, docker stop).
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::warn!(error = %e, "Ctrl-C handler sa nedá nainštalovať");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "SIGTERM handler sa nedá nainštalovať");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
}
