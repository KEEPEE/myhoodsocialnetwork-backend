//! F10a: skupinové audio volania + zdieľanie obrazovky cez **LiveKit SFU**.
//!
//! Uzol médiá **nesmeruje** — robí to LiveKit (server 1.13.11). Uzol je
//! jediná autorita nad tým, kto smie do miestnosti (spike G4: LiveKit nemá
//! trvalú revokačnú listinu), preto:
//!
//! - **mintuje** krátke tokeny (TTL 60 s, per kanál) len zariadeniam, ktoré
//!   prejdú bránou členstva ([`device_may_join`]) — [`token::TokenService`],
//! - pri revokácii zariadenia ho **vyhodí** cez Server API `RemoveParticipant`
//!   (best-effort, [`CallsState::kick_device_detached`]),
//! - vo webhooku `participant_joined` **znovu overí** členstvo a nečlena
//!   vyhodí ([`api`]; spike G4d+: `revoke_token_ts` re-entry nezabráni).
//!
//! Režimy (`[calls] mode`, default `off`):
//! - `off` — hovory nedostupné (`POST /calls/token` → 503),
//! - `managed` — LiveKit je **spravovaný potomok uzla**
//!   ([`manager::LiveKitManager`]): stiahnutie binárky s pinom SHA-256,
//!   vygenerovaný `livekit.yaml`, health-check, reštart s backoffom,
//! - `external` — operátor prevádzkuje LiveKit sám (`livekit_url` +
//!   `api_key` + `api_secret`); webhook musí nastaviť on.
//!
//! Tajomstvá (`api_secret`, mintnuté JWT) sa **nikdy nelogujú** — `Debug`
//! konfigurácie ich zakrýva.

pub mod api;
pub mod manager;
mod process;
pub mod token;
pub mod webhook;

use crate::api::SharedStore;
use crate::store::{Store, StoreError};
use myhsn_core::identity::AccountId;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

pub use api::calls_router;
pub use manager::{LiveKitManager, ManagerHandle};
pub use token::TokenService;

/// Pinnutá verzia LiveKit servera (spike F10.0 overil 1.13.11).
pub const LIVEKIT_VERSION: &str = "1.13.11";
/// HTTP/WS signal port LiveKitu v režime `managed`.
pub const LIVEKIT_HTTP_PORT: u16 = 7880;
/// ICE/TCP fallback port (spike: `livekit-server ports` → 7881).
pub const LIVEKIT_RTC_TCP_PORT: u16 = 7881;
/// Jediný ICE/UDP port namiesto rozsahu 50000–60000 (spike nález č. 2).
pub const LIVEKIT_RTC_UDP_PORT: u16 = 7882;
/// `room.empty_timeout` v sekundách (spike nález č. 11: 30 s je pasca).
pub const ROOM_EMPTY_TIMEOUT_SECS: u32 = 300;
/// TTL tokena — token slúži len na vstup, ACL drží uzol (spike G4).
pub const TOKEN_TTL_SECS: u64 = 60;
/// LiveKit od 1.x odmieta kratšie tajomstvá kľúča.
pub const MIN_SECRET_LEN: usize = 32;
/// Prefix identity participanta: `d_<device_pubkey_b32>`.
pub const IDENTITY_PREFIX: &str = "d_";

// ===========================================================================
// Konfigurácia `[calls]`
// ===========================================================================

/// Režim hovorov (`[calls] mode`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CallsMode {
    /// Hovory vypnuté (default — starý `node.toml` bez `[calls]`).
    #[default]
    Off,
    /// LiveKit ako spravovaný potomok uzla.
    Managed,
    /// LiveKit prevádzkovaný mimo uzla.
    External,
}

impl CallsMode {
    pub fn as_str(self) -> &'static str {
        match self {
            CallsMode::Off => "off",
            CallsMode::Managed => "managed",
            CallsMode::External => "external",
        }
    }
}

/// TOML sekcia `[calls]` — **voliteľná**; absencia = `mode = "off"`.
#[derive(Clone, Default, Deserialize)]
pub struct CallsConfig {
    #[serde(default)]
    pub mode: CallsMode,
    /// API kľúč LiveKitu. `managed` bez kľúča → uzol si ho vygeneruje a
    /// uloží do `<data_dir>/addons/livekit/keys.toml`.
    #[serde(default)]
    pub api_key: Option<String>,
    /// API tajomstvo (min. 32 znakov). Nikdy sa neloguje.
    #[serde(default)]
    pub api_secret: Option<String>,
    /// `external`: URL LiveKitu pre klientov (`wss://lk.example.sk`);
    /// Server API ide na rovnaký host cez `http(s)://`.
    #[serde(default)]
    pub livekit_url: Option<String>,
    /// `managed`: host v URL, ktorú dostane klient (`ws://<host>:7880`).
    /// Vynechaj → host z hlavičky `Host` požiadavky.
    #[serde(default)]
    pub public_host: Option<String>,
    /// `managed`: `rtc.node_ip` (spike nález č. 3) — IP, ktorú LiveKit
    /// ohlási v ICE kandidátoch (NAT/Docker). Vynechaj → autodetekcia.
    #[serde(default)]
    pub node_ip: Option<String>,
    /// `managed`: verzia LiveKit servera; musí byť v pin tabuľke
    /// ([`manager::RELEASES`]). Default [`LIVEKIT_VERSION`].
    #[serde(default)]
    pub version: Option<String>,
    /// Mená účtov, ktoré **smú** vyhodiť participantov z hovoru
    /// (`POST /calls/kick`, F10d MYHSN-39).
    ///
    /// Prečo config a nie tabuľka: uzol **nemá model rolí** —
    /// `deletion.rs` to povie narovinu („koncept admina/operátora uzla v
    /// MVP nie je“) a `Channel` v `crates/core` nemá pole owner (a
    /// `crates/core` sa F10d nesmie dotknúť). Jediný oprávnený zdroj
    /// rozhodnutia je preto **operátor uzla**, ktorý zoznam napíše do
    /// `node.toml`. Je to zámerne per uzol: moderátor na jednom uzle nie je
    /// moderátor na druhom — a práve to po F5 (viac uzlov) chceme.
    ///
    /// Prázdny zoznam = nikto nemoderuje (`POST /calls/kick` nepustí dnu
    /// nikoho). Porovnáva sa nezávisle od veľkosti písmen a po orezaní
    /// medzier — operátor píše do TOML ručne a `username` je v uzle unikátne
    /// už pri vytváraní účtu, preto normalizácia stačí táto.
    #[serde(default)]
    pub moderators: Vec<String>,
}

/// `Debug` bez tajomstva — `NodeConfig` sa môže dostať do logu.
impl std::fmt::Debug for CallsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallsConfig")
            .field("mode", &self.mode)
            .field("api_key", &self.api_key)
            .field("api_secret", &self.api_secret.as_ref().map(|_| "<skryté>"))
            .field("livekit_url", &self.livekit_url)
            .field("public_host", &self.public_host)
            .field("node_ip", &self.node_ip)
            .field("version", &self.version)
            .field("moderators", &self.moderators)
            .finish()
    }
}

fn non_empty(v: &Option<String>) -> Option<&str> {
    v.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

impl CallsConfig {
    /// Verzia LiveKitu pre `managed`.
    pub fn version(&self) -> &str {
        non_empty(&self.version).unwrap_or(LIVEKIT_VERSION)
    }

    /// Statická kontrola konfigurácie (bez I/O). Chyba = hovory sa
    /// nespustia, uzol beží ďalej (rozhoduje [`CallsState::start`]).
    pub fn validate(&self) -> Result<(), CallsError> {
        match self.mode {
            CallsMode::Off => Ok(()),
            CallsMode::Managed => {
                if manager::release(self.version()).is_none() {
                    return Err(CallsError::Config(format!(
                        "LiveKit {} nie je v pin tabuľke SHA-256 (podporované: {})",
                        self.version(),
                        manager::RELEASES
                            .iter()
                            .map(|r| r.version)
                            .collect::<Vec<_>>()
                            .join(", ")
                    )));
                }
                match (non_empty(&self.api_key), non_empty(&self.api_secret)) {
                    (None, None) => Ok(()), // vygenerujú sa
                    (Some(_), Some(secret)) => check_secret(secret),
                    _ => Err(CallsError::Config(
                        "api_key a api_secret treba zadať spolu (alebo oba vynechať)".into(),
                    )),
                }
            }
            CallsMode::External => {
                let url = non_empty(&self.livekit_url).ok_or_else(|| {
                    CallsError::Config("mode = external vyžaduje livekit_url".into())
                })?;
                server_api_url(url)?;
                if non_empty(&self.api_key).is_none() {
                    return Err(CallsError::Config(
                        "mode = external vyžaduje api_key".into(),
                    ));
                }
                let secret = non_empty(&self.api_secret).ok_or_else(|| {
                    CallsError::Config("mode = external vyžaduje api_secret".into())
                })?;
                check_secret(secret)
            }
        }
    }
}

fn check_secret(secret: &str) -> Result<(), CallsError> {
    if secret.chars().count() < MIN_SECRET_LEN {
        return Err(CallsError::Config(format!(
            "api_secret musí mať aspoň {MIN_SECRET_LEN} znakov (LiveKit kratšie odmietne)"
        )));
    }
    Ok(())
}

/// Klientska URL (`ws(s)://`) → URL Server API (`http(s)://`).
pub fn server_api_url(client_url: &str) -> Result<String, CallsError> {
    let url = client_url.trim().trim_end_matches('/');
    let mapped = if let Some(rest) = url.strip_prefix("wss://") {
        format!("https://{rest}")
    } else if let Some(rest) = url.strip_prefix("ws://") {
        format!("http://{rest}")
    } else if url.starts_with("https://") || url.starts_with("http://") {
        url.to_string()
    } else {
        return Err(CallsError::Config(format!(
            "livekit_url musí začínať ws://, wss://, http:// alebo https:// (je „{url}“)"
        )));
    };
    Ok(mapped)
}

/// Opačný smer pre klienta: `http(s)://` → `ws(s)://`.
fn client_ws_url(url: &str) -> String {
    let url = url.trim().trim_end_matches('/');
    if let Some(rest) = url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        url.to_string()
    }
}

/// Kľúče LiveKitu — tajomstvo sa nikdy nevypisuje.
#[derive(Clone)]
pub struct ApiKeys {
    pub key: String,
    pub secret: String,
}

impl std::fmt::Debug for ApiKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeys")
            .field("key", &self.key)
            .field("secret", &"<skryté>")
            .finish()
    }
}

/// Súbor s vygenerovanými kľúčmi pre `managed` bez kľúčov v configu.
#[derive(Deserialize, serde::Serialize)]
struct KeysFile {
    api_key: String,
    api_secret: String,
}

/// Kľúče pre `managed`: z configu, inak načítané/vygenerované v
/// `<addons>/keys.toml` (práva 0600 na unixe). Stabilné medzi reštartmi,
/// aby klienti s ešte platným tokenom neprišli o spojenie.
pub fn resolve_managed_keys(cfg: &CallsConfig, addons_dir: &Path) -> Result<ApiKeys, CallsError> {
    if let (Some(key), Some(secret)) = (non_empty(&cfg.api_key), non_empty(&cfg.api_secret)) {
        return Ok(ApiKeys {
            key: key.to_string(),
            secret: secret.to_string(),
        });
    }
    let path = addons_dir.join("keys.toml");
    if let Ok(text) = std::fs::read_to_string(&path) {
        let parsed: KeysFile = toml::from_str(&text)
            .map_err(|e| CallsError::Config(format!("{} je poškodený: {e}", path.display())))?;
        check_secret(&parsed.api_secret)?;
        return Ok(ApiKeys {
            key: parsed.api_key,
            secret: parsed.api_secret,
        });
    }
    std::fs::create_dir_all(addons_dir).map_err(|e| CallsError::io(addons_dir, e))?;
    let keys = ApiKeys {
        key: format!(
            "myhsn{}",
            &myhsn_core::record::to_hex(&crate::auth::random_32())[..12]
        ),
        secret: myhsn_core::record::to_hex(&crate::auth::random_32()),
    };
    let text = toml::to_string(&KeysFile {
        api_key: keys.key.clone(),
        api_secret: keys.secret.clone(),
    })
    .map_err(|e| CallsError::Config(e.to_string()))?;
    process::write_private(&path, text.as_bytes()).map_err(|e| CallsError::io(&path, e))?;
    tracing::info!(path = %path.display(), api_key = %keys.key, "vygenerované LiveKit API kľúče");
    Ok(keys)
}

/// `<data_dir>/addons/livekit`.
pub fn addons_dir(data_dir: &str) -> PathBuf {
    PathBuf::from(data_dir).join("addons").join("livekit")
}

// ===========================================================================
// Chyby
// ===========================================================================

/// Chyby modulu hovorov. Texty neobsahujú tajomstvá ani tokeny.
#[derive(Debug)]
pub enum CallsError {
    /// Hovory sú v konfigurácii vypnuté.
    Disabled,
    /// Neplatná konfigurácia `[calls]`.
    Config(String),
    /// Súborový systém (cesta + chyba).
    Io(String),
    /// Stiahnutie binárky zlyhalo.
    Download(String),
    /// SHA-256 stiahnutého archívu nesedí s pinom.
    Checksum { expected: String, actual: String },
    /// Platforma nemá LiveKit release (napr. macOS — spike nález č. 1).
    UnsupportedPlatform(String),
    /// Mint tokena / overenie JWT.
    Token(String),
    /// Server API LiveKitu (twirp) alebo nedostupný server.
    LiveKit(String),
    /// Webhook: chýbajúci/neplatný podpis alebo telo.
    Webhook(String),
}

impl CallsError {
    pub(crate) fn io(path: &Path, e: std::io::Error) -> Self {
        CallsError::Io(format!("{}: {e}", path.display()))
    }
}

impl std::fmt::Display for CallsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallsError::Disabled => write!(f, "calls: hovory sú na tomto uzle vypnuté"),
            CallsError::Config(m) => write!(f, "calls: konfigurácia: {m}"),
            CallsError::Io(m) => write!(f, "calls: I/O: {m}"),
            CallsError::Download(m) => write!(f, "calls: stiahnutie LiveKit: {m}"),
            CallsError::Checksum { expected, actual } => write!(
                f,
                "calls: SHA-256 archívu nesedí (čakané {expected}, je {actual})"
            ),
            CallsError::UnsupportedPlatform(p) => {
                write!(f, "calls: LiveKit nemá binárku pre platformu {p}")
            }
            CallsError::Token(m) => write!(f, "calls: token: {m}"),
            CallsError::LiveKit(m) => write!(f, "calls: LiveKit: {m}"),
            CallsError::Webhook(m) => write!(f, "calls: webhook: {m}"),
        }
    }
}

impl std::error::Error for CallsError {}

// ===========================================================================
// Identita participanta: d_<device_pubkey_b32>
// ===========================================================================

const B32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// RFC 4648 base32, malé písmená, bez paddingu (32 B → 52 znakov).
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32_ALPHABET[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32_ALPHABET[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Inverzia [`base32_encode`]; prijíma len **kanonický** tvar (malé
/// písmená, bez paddingu, nulové zvyškové bity) — jedna identita = jeden
/// reťazec, inak by sa dal obísť porovnávací kľúč.
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        let v = B32_ALPHABET.iter().position(|&a| a == c)? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
        buf &= (1 << bits) - 1;
    }
    if bits >= 5 || buf != 0 {
        return None;
    }
    Some(out)
}

/// Identita participanta pre device kľúč.
pub fn device_identity(pubkey: &[u8; 32]) -> String {
    format!("{IDENTITY_PREFIX}{}", base32_encode(pubkey))
}

/// `d_<b32>` → device pubkey. Čokoľvek iné (agent, egress, cudzí tvar) je
/// `None` = nečlen.
pub fn parse_device_identity(identity: &str) -> Option<[u8; 32]> {
    let raw = base32_decode(identity.strip_prefix(IDENTITY_PREFIX)?)?;
    raw.try_into().ok()
}

/// Miestnosť = hex id kanála.
pub fn room_name(channel: &[u8; 32]) -> String {
    myhsn_core::record::to_hex(channel)
}

/// **Brána členstva** — jediné miesto, kde sa rozhoduje, či zariadenie
/// smie do hovoru kanála (mint tokena aj webhook ju volajú rovnako).
///
/// Uzol zatiaľ nemá ACL per kanál: rovnako ako WS append (`ws.rs`) je
/// členom kanála každé **atestované a nezrušené** zariadenie a kanál musí
/// existovať. Keď pribudne členstvo per kanál, mení sa len táto funkcia.
pub fn device_may_join(
    store: &Store,
    device_pub: &[u8; 32],
    channel: &[u8; 32],
) -> Result<Option<AccountId>, StoreError> {
    if store.get_channel(channel)?.is_none() {
        return Ok(None);
    }
    store.device_account_if_active(device_pub)
}

// ===========================================================================
// Stav LiveKitu + zdieľaný stav handlerov
// ===========================================================================

/// Stav LiveKitu pre `GET /calls/health`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LiveKitStatus {
    /// Binárka nie je k dispozícii (režim `off`, alebo ešte nestiahnutá).
    Absent = 0,
    /// Binárka je, ale proces nebeží / health-check zlyháva.
    Stopped = 1,
    /// Health-check `GET /` vracia 200.
    Running = 2,
}

impl LiveKitStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            LiveKitStatus::Absent => "absent",
            LiveKitStatus::Stopped => "stopped",
            LiveKitStatus::Running => "running",
        }
    }
}

/// Atomický stav zdieľaný supervízorom a handlermi.
#[derive(Debug)]
pub struct StatusCell(AtomicU8);

impl StatusCell {
    pub fn new(s: LiveKitStatus) -> Self {
        Self(AtomicU8::new(s as u8))
    }
    pub fn get(&self) -> LiveKitStatus {
        match self.0.load(Ordering::Relaxed) {
            2 => LiveKitStatus::Running,
            1 => LiveKitStatus::Stopped,
            _ => LiveKitStatus::Absent,
        }
    }
    pub fn set(&self, s: LiveKitStatus) {
        self.0.store(s as u8, Ordering::Relaxed);
    }
}

/// Kam klient pripojí WebRTC signal.
#[derive(Debug, Clone)]
enum ClientUrl {
    /// `ws://<public_host | Host hlavička>:7880`.
    Managed { public_host: Option<String> },
    /// Pevná URL z configu.
    External(String),
}

struct CallsInner {
    store: SharedStore,
    mode: CallsMode,
    tokens: Option<Arc<TokenService>>,
    client_url: Option<ClientUrl>,
    status: Arc<StatusCell>,
    version: Option<String>,
    /// Mená oprávnené moderovať (F10d) — viď [`CallsConfig::moderators`].
    moderators: Vec<String>,
}

/// Zdieľaný stav `calls` handlerov (lacný `Clone`).
#[derive(Clone)]
pub struct CallsState {
    inner: Arc<CallsInner>,
}

/// Vyriešený node port + IP pre webhook URL v `livekit.yaml`.
fn webhook_url(listen: &str) -> String {
    let addr: Option<std::net::SocketAddr> = listen.parse().ok();
    let (host, port) = match addr {
        Some(a) if a.ip().is_unspecified() || a.ip().is_loopback() => {
            ("127.0.0.1".to_string(), a.port())
        }
        Some(std::net::SocketAddr::V4(a)) => (a.ip().to_string(), a.port()),
        Some(std::net::SocketAddr::V6(a)) => (format!("[{}]", a.ip()), a.port()),
        None => (
            "127.0.0.1".to_string(),
            listen
                .rsplit(':')
                .next()
                .and_then(|p| p.parse().ok())
                .unwrap_or(8123),
        ),
    };
    format!("http://{host}:{port}/calls/webhook")
}

impl CallsState {
    /// Režim `off` — testy a uzol bez `[calls]`.
    pub fn off(store: SharedStore) -> Self {
        Self {
            inner: Arc::new(CallsInner {
                store,
                mode: CallsMode::Off,
                tokens: None,
                client_url: None,
                status: Arc::new(StatusCell::new(LiveKitStatus::Absent)),
                version: None,
                moderators: Vec::new(),
            }),
        }
    }

    /// Stav s danou službou tokenov (testy a `external` bez supervízora).
    pub fn with_tokens(
        store: SharedStore,
        mode: CallsMode,
        tokens: TokenService,
        client_url: Option<String>,
        status: Arc<StatusCell>,
        version: Option<String>,
    ) -> Self {
        let client_url = match (mode, client_url) {
            (CallsMode::External, Some(u)) => Some(ClientUrl::External(client_ws_url(&u))),
            (_, host) => Some(ClientUrl::Managed { public_host: host }),
        };
        Self {
            inner: Arc::new(CallsInner {
                store,
                mode,
                tokens: Some(Arc::new(tokens)),
                client_url,
                status,
                version,
                moderators: Vec::new(),
            }),
        }
    }

    /// Nastaví zoznam moderátorov (F10d, MYHSN-39).
    ///
    /// Stavebná metóda, nie parameter: `with_tokens` volajú testy v šiestich
    /// miestach a pridávať ďalší pozíčný parameter by bol šum. Práva sú
    /// vedľajšia starosť a prázdny zoznam je bezpečný default — kick bez
    /// nich nedokáže nikto.
    #[must_use]
    pub fn with_moderators(mut self, moderators: Vec<String>) -> Self {
        let clean: Vec<String> = moderators
            .iter()
            .map(|m| m.trim().to_string())
            .filter(|m| !m.is_empty())
            .collect();
        let old = Arc::clone(&self.inner);
        self.inner = Arc::new(CallsInner {
            store: Arc::clone(&old.store),
            mode: old.mode,
            tokens: old.tokens.clone(),
            client_url: old.client_url.clone(),
            status: Arc::clone(&old.status),
            version: old.version.clone(),
            moderators: clean,
        });
        self
    }

    /// `true` keď username smie moderovať hovory na **tomto** uzle.
    ///
    /// Porovnáva s `username` účtu nezávisle od veľkosti písmen a po orezaní
    /// medzier. Prázdny zoznam moderátorov
    /// znamená, že apka tlačidlo „Vyhodiť“ neukáže a uzol aj tak vráti 403
    /// — obrana je na oboch koncoch, lebo UI klame (klient môže byť starý).
    #[must_use]
    pub fn can_moderate(&self, username: &str) -> bool {
        self.inner
            .moderators
            .iter()
            .any(|m| m.eq_ignore_ascii_case(username.trim()))
    }

    /// Spustenie podľa konfigurácie (volá `main`). Chybná konfigurácia
    /// hovory **vypne** a zaloguje chybu — uzol bez hovorov je stále uzol.
    /// `managed` spustí supervízora; jeho handle treba pri shutdown
    /// zastaviť ([`ManagerHandle::stop`]).
    pub fn start(
        cfg: &CallsConfig,
        data_dir: &str,
        listen: &str,
        store: SharedStore,
    ) -> (Self, Option<ManagerHandle>) {
        if let Err(e) = cfg.validate() {
            tracing::error!(error = %e, "hovory vypnuté pre chybnú konfiguráciu [calls]");
            return (Self::off(store), None);
        }
        match cfg.mode {
            CallsMode::Off => {
                tracing::info!("hovory vypnuté ([calls] mode = off)");
                (Self::off(store), None)
            }
            CallsMode::External => {
                // validate() zaručil prítomnosť a tvar
                let url = non_empty(&cfg.livekit_url).unwrap_or_default().to_string();
                let api = server_api_url(&url).unwrap_or_default();
                let tokens = TokenService::new(
                    &api,
                    non_empty(&cfg.api_key).unwrap_or_default(),
                    non_empty(&cfg.api_secret).unwrap_or_default(),
                );
                let status = Arc::new(StatusCell::new(LiveKitStatus::Stopped));
                let handle = ManagerHandle::probe_only(api.clone(), status.clone());
                tracing::info!(livekit_url = %url, "hovory: externý LiveKit (webhook musí nastaviť operátor)");
                (
                    Self::with_tokens(store, CallsMode::External, tokens, Some(url), status, None)
                        .with_moderators(cfg.moderators.clone()),
                    Some(handle),
                )
            }
            CallsMode::Managed => {
                let addons = addons_dir(data_dir);
                let keys = match resolve_managed_keys(cfg, &addons) {
                    Ok(k) => k,
                    Err(e) => {
                        tracing::error!(error = %e, "hovory vypnuté: LiveKit kľúče");
                        return (Self::off(store), None);
                    }
                };
                let api = format!("http://127.0.0.1:{LIVEKIT_HTTP_PORT}");
                let tokens = TokenService::new(&api, &keys.key, &keys.secret);
                let status = Arc::new(StatusCell::new(LiveKitStatus::Absent));
                let mgr = LiveKitManager::new(manager::ManagedSettings {
                    version: cfg.version().to_string(),
                    addons_dir: addons,
                    keys,
                    webhook_url: webhook_url(listen),
                    node_ip: non_empty(&cfg.node_ip).map(str::to_string),
                });
                let handle = mgr.start(status.clone());
                (
                    Self::with_tokens(
                        store,
                        CallsMode::Managed,
                        tokens,
                        non_empty(&cfg.public_host).map(str::to_string),
                        status,
                        Some(cfg.version().to_string()),
                    )
                    .with_moderators(cfg.moderators.clone()),
                    Some(handle),
                )
            }
        }
    }

    pub fn mode(&self) -> CallsMode {
        self.inner.mode
    }
    pub fn status(&self) -> LiveKitStatus {
        self.inner.status.get()
    }
    pub fn version(&self) -> Option<&str> {
        self.inner.version.as_deref()
    }
    pub fn store(&self) -> &SharedStore {
        &self.inner.store
    }
    /// Služba tokenov; `Err(Disabled)` v režime `off`.
    pub fn tokens(&self) -> Result<&Arc<TokenService>, CallsError> {
        self.inner.tokens.as_ref().ok_or(CallsError::Disabled)
    }

    /// URL pre klienta. `request_host` = hlavička `Host` (bez portu sa
    /// použije tak, ako je; port sa vždy nahradí LiveKit portom).
    pub fn client_url(&self, request_host: Option<&str>) -> Result<String, CallsError> {
        match self.inner.client_url.as_ref().ok_or(CallsError::Disabled)? {
            ClientUrl::External(u) => Ok(u.clone()),
            ClientUrl::Managed { public_host } => {
                let host = public_host
                    .as_deref()
                    .or(request_host.map(strip_port))
                    .filter(|h| !h.is_empty())
                    .unwrap_or("127.0.0.1");
                Ok(format!("ws://{host}:{LIVEKIT_HTTP_PORT}"))
            }
        }
    }

    /// Best-effort vyhodenie zariadenia zo **všetkých** miestností (pri
    /// revokácii kľúča). Neblokuje volajúceho; zlyhanie sa len zaloguje —
    /// webhook kontrola členstva je druhá poistka.
    pub fn kick_device_detached(&self, device_pub: [u8; 32]) {
        let Ok(tokens) = self.tokens().cloned() else {
            return; // hovory vypnuté — nie je koho vyhodiť
        };
        let identity = device_identity(&device_pub);
        tokio::spawn(async move {
            match tokens.kick_everywhere(&identity).await {
                Ok(n) => {
                    tracing::info!(%identity, rooms = n, "revokované zariadenie vyhodené z hovorov")
                }
                Err(e) => {
                    tracing::warn!(%identity, error = %e, "vyhodenie revokovaného zariadenia z hovorov zlyhalo")
                }
            }
        });
    }
}

/// `host:port` / `[v6]:port` → host (hranaté zátvorky ostávajú).
fn strip_port(host: &str) -> &str {
    if let Some(end) = host.find(']') {
        return &host[..=end];
    }
    match host.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !h.contains(':') => h,
        _ => host,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> CallsConfig {
        #[derive(Deserialize)]
        struct Wrap {
            #[serde(default)]
            calls: CallsConfig,
        }
        toml::from_str::<Wrap>(text).unwrap().calls
    }

    #[test]
    fn missing_section_is_off() {
        let c = parse("listen = \"0.0.0.0:8123\"\n");
        assert_eq!(c.mode, CallsMode::Off);
        assert!(c.validate().is_ok());
    }

    #[test]
    fn managed_without_keys_is_valid_and_defaults_version() {
        let c = parse("[calls]\nmode = \"managed\"\n");
        assert_eq!(c.mode, CallsMode::Managed);
        assert_eq!(c.version(), LIVEKIT_VERSION);
        c.validate().unwrap();
    }

    /// F10d: moderátori sú voliteľné pole — bez neho uzol nikoho nepustí
    /// ku kicku. Konfigurácia sa mení na zoznam bez iných zmien.
    #[test]
    fn moderators_default_empty_and_parse_from_toml() {
        let c = parse("[calls]\nmode = \"managed\"\n");
        assert!(c.moderators.is_empty(), "bez konfigurácie nikto");
        let c = parse("[calls]\nmode = \"managed\"\nmoderators = [\"anna\", \"bo\"]\n");
        assert_eq!(c.moderators, vec!["anna".to_string(), "bo".to_string()]);
        // Debug zoznam ukáže — mená nie sú tajomstvo a bez nich sa
        // nedá diagnostikovať „prečo mi to vrátilo 403“
        assert!(format!("{c:?}").contains("anna"));
    }

    #[test]
    fn managed_rejects_short_secret_half_keys_and_unknown_version() {
        let short =
            parse("[calls]\nmode = \"managed\"\napi_key = \"k\"\napi_secret = \"kratke\"\n");
        assert!(matches!(short.validate(), Err(CallsError::Config(_))));
        let half = parse("[calls]\nmode = \"managed\"\napi_key = \"k\"\n");
        assert!(matches!(half.validate(), Err(CallsError::Config(_))));
        let ver = parse("[calls]\nmode = \"managed\"\nversion = \"0.0.1\"\n");
        assert!(matches!(ver.validate(), Err(CallsError::Config(_))));
    }

    #[test]
    fn external_requires_url_and_keys() {
        let ok = parse(
            "[calls]\nmode = \"external\"\nlivekit_url = \"wss://lk.example.sk\"\n\
             api_key = \"APIabc\"\napi_secret = \"0123456789abcdef0123456789abcdef\"\n",
        );
        ok.validate().unwrap();
        assert_eq!(ok.livekit_url.as_deref(), Some("wss://lk.example.sk"));
        let no_url = parse("[calls]\nmode = \"external\"\napi_key = \"a\"\napi_secret = \"0123456789abcdef0123456789abcdef\"\n");
        assert!(no_url.validate().is_err());
        let bad_scheme = parse(
            "[calls]\nmode = \"external\"\nlivekit_url = \"lk.example.sk\"\n\
             api_key = \"a\"\napi_secret = \"0123456789abcdef0123456789abcdef\"\n",
        );
        assert!(bad_scheme.validate().is_err());
    }

    #[test]
    fn unknown_mode_is_parse_error() {
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct Wrap {
            calls: CallsConfig,
        }
        assert!(toml::from_str::<Wrap>("[calls]\nmode = \"auto\"\n").is_err());
    }

    #[test]
    fn debug_hides_secret() {
        let c = parse(
            "[calls]\nmode = \"external\"\napi_secret = \"supertajne-supertajne-supertajne\"\n",
        );
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("supertajne"), "{dbg}");
    }

    #[test]
    fn url_scheme_mapping() {
        assert_eq!(server_api_url("wss://a.sk/").unwrap(), "https://a.sk");
        assert_eq!(
            server_api_url("ws://1.2.3.4:7880").unwrap(),
            "http://1.2.3.4:7880"
        );
        assert_eq!(server_api_url("https://a.sk").unwrap(), "https://a.sk");
        assert_eq!(client_ws_url("https://a.sk"), "wss://a.sk");
    }

    #[test]
    fn base32_roundtrip_and_canonical() {
        // RFC 4648 test vectors (malé písmená, bez paddingu)
        assert_eq!(base32_encode(b"foobar"), "mzxw6ytboi");
        assert_eq!(base32_encode(b"f"), "my");
        assert_eq!(base32_decode("mzxw6ytboi").unwrap(), b"foobar");
        let pk = [0xa5u8; 32];
        let id = device_identity(&pk);
        assert_eq!(id.len(), 2 + 52);
        assert_eq!(parse_device_identity(&id), Some(pk));
        // veľké písmená, padding, nenulové zvyškové bity, cudzí prefix
        assert_eq!(parse_device_identity(&id.to_uppercase()), None);
        assert_eq!(base32_decode("mz"), None); // 'z' nechá nenulové bity
        assert_eq!(parse_device_identity("u_abc"), None);
        assert_eq!(parse_device_identity("d_my"), None); // zlá dĺžka
    }

    #[test]
    fn webhook_url_from_listen() {
        assert_eq!(
            webhook_url("0.0.0.0:8123"),
            "http://127.0.0.1:8123/calls/webhook"
        );
        assert_eq!(
            webhook_url("127.0.0.1:9000"),
            "http://127.0.0.1:9000/calls/webhook"
        );
        assert_eq!(
            webhook_url("198.51.100.5:8123"),
            "http://198.51.100.5:8123/calls/webhook"
        );
        assert_eq!(
            webhook_url("[::]:8123"),
            "http://127.0.0.1:8123/calls/webhook"
        );
    }

    #[test]
    fn strip_port_variants() {
        assert_eq!(strip_port("uzol.local:8123"), "uzol.local");
        assert_eq!(strip_port("uzol.local"), "uzol.local");
        assert_eq!(strip_port("[fe80::1]:8123"), "[fe80::1]");
        assert_eq!(strip_port("fe80::1"), "fe80::1");
    }

    #[test]
    fn managed_keys_are_generated_once_and_reused() {
        let dir = std::env::temp_dir().join(format!(
            "myhsn-calls-keys-{}",
            myhsn_core::record::to_hex(&crate::auth::random_32())
        ));
        let cfg = CallsConfig {
            mode: CallsMode::Managed,
            ..Default::default()
        };
        let a = resolve_managed_keys(&cfg, &dir).unwrap();
        let b = resolve_managed_keys(&cfg, &dir).unwrap();
        assert_eq!(a.key, b.key);
        assert_eq!(a.secret, b.secret);
        assert!(a.secret.len() >= MIN_SECRET_LEN);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("keys.toml"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
