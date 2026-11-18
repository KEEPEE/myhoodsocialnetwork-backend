//! `LiveKitManager` — LiveKit server ako **spravovaný potomok uzla**
//! (režim `managed`).
//!
//! Životný cyklus (supervízor [`LiveKitManager::start`]):
//! 1. **inštalácia** do `<data_dir>/addons/livekit/<ver>/`: stiahnutie
//!    release archívu z GitHubu, overenie **SHA-256 voči pinu** v
//!    [`RELEASES`] (nie voči `checksums.txt` z toho istého zdroja),
//!    rozbalenie len binárky, značka `.sha256`; pri ďalšom štarte sa
//!    nesťahuje,
//! 2. **konfigurácia** `<addons>/livekit.yaml` (0600 — obsahuje tajomstvo)
//!    vygenerovaná pri každom štarte z `[calls]`,
//! 3. **spawn** s väzbou na uzol ([`super::process`]), stdout/stderr (JSON
//!    logy) → `tracing` target `livekit`,
//! 4. **health-check** `GET http://127.0.0.1:7880/` každých 5 s,
//! 5. pád / dlhodobo zlyhávajúci health → **reštart s exponenciálnym
//!    backoffom** 1 → 60 s (reset po ≥ 60 s zdravého behu),
//! 6. **graceful stop** pri shutdown uzla ([`ManagerHandle::stop`]).

use super::process::{self, ChildGuard};
use super::{
    ApiKeys, CallsError, LiveKitStatus, StatusCell, LIVEKIT_HTTP_PORT, LIVEKIT_RTC_TCP_PORT,
    LIVEKIT_RTC_UDP_PORT, ROOM_EMPTY_TIMEOUT_SECS,
};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Interval health-checku.
pub const HEALTH_INTERVAL: Duration = Duration::from_secs(5);
/// Timeout jedného health požiadavku.
const HEALTH_TIMEOUT: Duration = Duration::from_secs(2);
/// Po koľkých zlyhaniach za sebou (po tom, čo už bol zdravý) reštart.
const HEALTH_FAILS_BEFORE_RESTART: u32 = 3;
/// Koľko čakať na prvý úspešný health po spawne.
const STARTUP_GRACE: Duration = Duration::from_secs(60);
/// Exponenciálny backoff reštartu.
pub const BACKOFF_MIN: Duration = Duration::from_secs(1);
pub const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// Zdravý beh aspoň takto dlho → backoff sa vynuluje.
const BACKOFF_RESET_AFTER: Duration = Duration::from_secs(60);
/// Strop veľkosti archívu (release má ~20 MB) — ochrana disku.
const MAX_ARCHIVE_BYTES: u64 = 200 * 1024 * 1024;
/// Timeout celého sťahovania (spike: Windows 57 MB za 41 s).
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(600);

/// Meno binárky v archíve.
#[cfg(windows)]
pub const BINARY_NAME: &str = "livekit-server.exe";
#[cfg(not(windows))]
pub const BINARY_NAME: &str = "livekit-server";

/// Pin jedného release assetu.
#[derive(Debug, Clone, Copy)]
pub struct Asset {
    /// `linux_amd64`, `linux_arm64`, `linux_armv7`, `windows_amd64`, …
    pub platform: &'static str,
    /// SHA-256 archívu (hex).
    pub sha256: &'static str,
}

/// Pinnutý LiveKit release.
#[derive(Debug, Clone, Copy)]
pub struct Release {
    pub version: &'static str,
    pub assets: &'static [Asset],
}

/// **Pin tabuľka** verzia → SHA-256 per platforma. Hodnoty sú vypočítané
/// zo stiahnutých archívov (`sha256sum`, 2026-11-15) a zhodujú sa s
/// `checksums.txt` aj s `digest` v GitHub API pre tag `v1.13.11`.
/// Nová verzia = nový riadok (a nové overenie), nie zmena existujúceho.
pub const RELEASES: &[Release] = &[Release {
    version: "1.13.11",
    assets: &[
        Asset {
            platform: "linux_amd64",
            sha256: "1e9ee90ca301e1842b2887fc77cb122759756a9c8aeb4334ee91de3325ec43fb",
        },
        Asset {
            platform: "linux_arm64",
            sha256: "2af6ce091d6b3c79d1677f8ff1bbb91a8007f40b2325c059b52d38383c0830b6",
        },
        Asset {
            platform: "linux_armv7",
            sha256: "5f663a6498c3d81ef2dce55a3a1e7815aacfe78207e469abc0bd9c5b5ca5070b",
        },
        Asset {
            platform: "windows_amd64",
            sha256: "5d071ea43339f0140d24a66f0b2ff8a7bf6c4d0dceb19b30abca835670213667",
        },
        Asset {
            platform: "windows_arm64",
            sha256: "47ebfaa1ef6de546bf17a6699d4d9be59693bd5c3ffbec14d0749bd396ea3875",
        },
    ],
}];

/// Release pre verziu, ak je pinnutý.
pub fn release(version: &str) -> Option<&'static Release> {
    RELEASES.iter().find(|r| r.version == version)
}

/// Platforma tohto buildu v názvosloví LiveKit release assetov.
pub fn current_platform() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("linux_amd64"),
        ("linux", "aarch64") => Some("linux_arm64"),
        ("linux", "arm") => Some("linux_armv7"),
        ("windows", "x86_64") => Some("windows_amd64"),
        ("windows", "aarch64") => Some("windows_arm64"),
        _ => None, // macOS: LiveKit binárku nevydáva (spike nález č. 1)
    }
}

/// `livekit_<ver>_<platform>.tar.gz|zip`
pub fn archive_name(version: &str, platform: &str) -> String {
    let ext = if platform.starts_with("windows") {
        "zip"
    } else {
        "tar.gz"
    };
    format!("livekit_{version}_{platform}.{ext}")
}

/// URL release assetu na GitHube.
pub fn download_url(version: &str, platform: &str) -> String {
    format!(
        "https://github.com/livekit/livekit/releases/download/v{version}/{}",
        archive_name(version, platform)
    )
}

/// Vstupy managera (vyriešené z `[calls]` + `data_dir` + `listen`).
#[derive(Debug, Clone)]
pub struct ManagedSettings {
    pub version: String,
    /// `<data_dir>/addons/livekit`
    pub addons_dir: PathBuf,
    pub keys: ApiKeys,
    /// `http://127.0.0.1:<node_port>/calls/webhook`
    pub webhook_url: String,
    /// voliteľné `rtc.node_ip`
    pub node_ip: Option<String>,
}

/// Správca LiveKit potomka.
pub struct LiveKitManager {
    settings: ManagedSettings,
    http: reqwest::Client,
}

/// Prečo skončilo sledovanie potomka.
enum ChildOutcome {
    Exited(std::io::Result<std::process::ExitStatus>),
    Unhealthy,
    StopRequested,
}

/// YAML reťazec v úvodzovkách (JSON reťazec je platný YAML flow scalar).
fn yq(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

impl LiveKitManager {
    pub fn new(settings: ManagedSettings) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(concat!("myhsn-node/", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_default();
        Self { settings, http }
    }

    /// `<addons>/<ver>/`
    pub fn version_dir(&self) -> PathBuf {
        self.settings.addons_dir.join(&self.settings.version)
    }

    /// `<addons>/<ver>/livekit-server[.exe]`
    pub fn binary_path(&self) -> PathBuf {
        self.version_dir().join(BINARY_NAME)
    }

    /// `<addons>/livekit.yaml`
    pub fn config_path(&self) -> PathBuf {
        self.settings.addons_dir.join("livekit.yaml")
    }

    fn expected_asset(&self) -> Result<(&'static str, &'static str), CallsError> {
        let platform = current_platform().ok_or_else(|| {
            CallsError::UnsupportedPlatform(format!(
                "{}/{}",
                std::env::consts::OS,
                std::env::consts::ARCH
            ))
        })?;
        let rel = release(&self.settings.version).ok_or_else(|| {
            CallsError::Config(format!("LiveKit {} nie je pinnutý", self.settings.version))
        })?;
        let asset = rel
            .assets
            .iter()
            .find(|a| a.platform == platform)
            .ok_or_else(|| CallsError::UnsupportedPlatform(platform.to_string()))?;
        Ok((platform, asset.sha256))
    }

    /// Zaruč nainštalovanú binárku (overenú voči pinu). Idempotentné.
    pub async fn ensure_installed(&self) -> Result<PathBuf, CallsError> {
        let (platform, sha) = self.expected_asset()?;
        let dir = self.version_dir();
        let bin = self.binary_path();
        let marker = dir.join(".sha256");
        if bin.is_file()
            && std::fs::read_to_string(&marker)
                .map(|m| m.trim() == sha)
                .unwrap_or(false)
        {
            return Ok(bin);
        }
        std::fs::create_dir_all(&dir).map_err(|e| CallsError::io(&dir, e))?;
        let archive = dir.join(format!(
            "{}.part",
            archive_name(&self.settings.version, platform)
        ));
        let url = download_url(&self.settings.version, platform);
        tracing::info!(target: "livekit", %url, "sťahujem LiveKit server");
        let t0 = Instant::now();
        let actual = self.download(&url, &archive).await;
        let actual = match actual {
            Ok(h) => h,
            Err(e) => {
                let _ = std::fs::remove_file(&archive);
                return Err(e);
            }
        };
        tracing::info!(target: "livekit", secs = t0.elapsed().as_secs(), "LiveKit stiahnutý");
        let archive2 = archive.clone();
        let dir2 = dir.clone();
        let expected = sha.to_string();
        let res = tokio::task::spawn_blocking(move || {
            install_from_archive(&archive2, &expected, &actual, &dir2)
        })
        .await
        .map_err(|e| CallsError::Io(format!("inštalácia: {e}")))?;
        let _ = std::fs::remove_file(&archive);
        res?;
        tracing::info!(target: "livekit", path = %bin.display(), "LiveKit nainštalovaný a overený (SHA-256)");
        Ok(bin)
    }

    /// Stiahni `url` do `dest` a vráť hex SHA-256 stiahnutých bajtov.
    async fn download(&self, url: &str, dest: &Path) -> Result<String, CallsError> {
        use tokio::io::AsyncWriteExt;
        let fut = async {
            let mut resp = self
                .http
                .get(url)
                .send()
                .await
                .and_then(|r| r.error_for_status())
                .map_err(|e| CallsError::Download(e.to_string()))?;
            if resp.content_length().unwrap_or(0) > MAX_ARCHIVE_BYTES {
                return Err(CallsError::Download("archív je väčší než strop".into()));
            }
            let mut file = tokio::fs::File::create(dest)
                .await
                .map_err(|e| CallsError::io(dest, e))?;
            let mut hasher = Sha256::new();
            let mut total: u64 = 0;
            while let Some(chunk) = resp
                .chunk()
                .await
                .map_err(|e| CallsError::Download(e.to_string()))?
            {
                total += chunk.len() as u64;
                if total > MAX_ARCHIVE_BYTES {
                    return Err(CallsError::Download("archív je väčší než strop".into()));
                }
                hasher.update(&chunk);
                file.write_all(&chunk)
                    .await
                    .map_err(|e| CallsError::io(dest, e))?;
            }
            file.sync_all().await.map_err(|e| CallsError::io(dest, e))?;
            Ok(hex(&hasher.finalize()))
        };
        tokio::time::timeout(DOWNLOAD_TIMEOUT, fut)
            .await
            .map_err(|_| CallsError::Download("timeout".into()))?
    }

    /// Obsah `livekit.yaml` (spike overené hodnoty).
    pub fn render_config(&self) -> String {
        let s = &self.settings;
        let mut y = String::new();
        y.push_str("# Vygeneroval myhsn-node pri štarte — NEUPRAVOVAŤ, prepíše sa.\n");
        y.push_str("# Zdroj: sekcia [calls] v node.toml. Obsahuje API tajomstvo (0600).\n");
        y.push_str(&format!("port: {LIVEKIT_HTTP_PORT}\n"));
        y.push_str("bind_addresses:\n  - \"0.0.0.0\"\n");
        y.push_str("rtc:\n");
        y.push_str(&format!("  tcp_port: {LIVEKIT_RTC_TCP_PORT}\n"));
        y.push_str(&format!("  udp_port: {LIVEKIT_RTC_UDP_PORT}\n"));
        y.push_str("  use_external_ip: false\n");
        if let Some(ip) = &s.node_ip {
            y.push_str(&format!("  node_ip: {}\n", yq(ip)));
        }
        y.push_str("keys:\n");
        y.push_str(&format!("  {}: {}\n", yq(&s.keys.key), yq(&s.keys.secret)));
        y.push_str("room:\n");
        y.push_str("  auto_create: false\n");
        y.push_str(&format!("  empty_timeout: {ROOM_EMPTY_TIMEOUT_SECS}\n"));
        y.push_str("webhook:\n");
        y.push_str(&format!("  api_key: {}\n", yq(&s.keys.key)));
        y.push_str(&format!("  urls:\n    - {}\n", yq(&s.webhook_url)));
        y.push_str("logging:\n  json: true\n  level: info\n");
        y
    }

    fn write_config(&self) -> Result<PathBuf, CallsError> {
        let path = self.config_path();
        std::fs::create_dir_all(&self.settings.addons_dir)
            .map_err(|e| CallsError::io(&self.settings.addons_dir, e))?;
        process::write_private(&path, self.render_config().as_bytes())
            .map_err(|e| CallsError::io(&path, e))?;
        Ok(path)
    }

    fn spawn_child(&self, bin: &Path, config: &Path) -> Result<(Child, ChildGuard), CallsError> {
        let mut cmd = Command::new(bin);
        cmd.arg("--config")
            .arg(config)
            .arg("--bind")
            .arg("0.0.0.0")
            .current_dir(&self.settings.addons_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        process::configure(&mut cmd);
        let mut child = cmd.spawn().map_err(|e| CallsError::io(bin, e))?;
        let guard = process::attach(&child).map_err(|e| CallsError::io(bin, e))?;
        if let Some(out) = child.stdout.take() {
            tokio::spawn(pipe_logs(out));
        }
        if let Some(err) = child.stderr.take() {
            tokio::spawn(pipe_logs(err));
        }
        tracing::info!(target: "livekit", pid = child.id().unwrap_or(0), "LiveKit spustený");
        Ok((child, guard))
    }

    /// Spusti supervízora na pozadí.
    pub fn start(self, status: Arc<StatusCell>) -> ManagerHandle {
        let (stop_tx, stop_rx) = watch::channel(false);
        let task = tokio::spawn(self.supervise(status, stop_rx));
        ManagerHandle { stop_tx, task }
    }

    async fn supervise(self, status: Arc<StatusCell>, mut stop: watch::Receiver<bool>) {
        let mut backoff = BACKOFF_MIN;
        let health_url = format!("http://127.0.0.1:{LIVEKIT_HTTP_PORT}/");
        loop {
            if *stop.borrow() {
                break;
            }
            let bin = match self.ensure_installed().await {
                Ok(b) => b,
                Err(e) => {
                    status.set(LiveKitStatus::Absent);
                    tracing::warn!(target: "livekit", error = %e, retry_secs = backoff.as_secs(), "LiveKit nie je k dispozícii");
                    if sleep_or_stop(&mut stop, backoff).await {
                        break;
                    }
                    backoff = next_backoff(backoff);
                    continue;
                }
            };
            status.set(LiveKitStatus::Stopped);
            let spawned = self
                .write_config()
                .and_then(|cfg| self.spawn_child(&bin, &cfg));
            let (mut child, guard) = match spawned {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(target: "livekit", error = %e, retry_secs = backoff.as_secs(), "spustenie LiveKitu zlyhalo");
                    if sleep_or_stop(&mut stop, backoff).await {
                        break;
                    }
                    backoff = next_backoff(backoff);
                    continue;
                }
            };
            let (outcome, healthy_for) =
                watch_child(&self.http, &health_url, &mut child, &status, &mut stop).await;
            status.set(LiveKitStatus::Stopped);
            match outcome {
                ChildOutcome::StopRequested => {
                    process::terminate(&mut child, guard).await;
                    break;
                }
                ChildOutcome::Exited(res) => {
                    // guard (Windows job) sa zahodí na konci iterácie
                    match res {
                        Ok(st) => {
                            tracing::warn!(target: "livekit", status = %st, "LiveKit skončil")
                        }
                        Err(e) => {
                            tracing::warn!(target: "livekit", error = %e, "LiveKit: čakanie na proces zlyhalo")
                        }
                    }
                }
                ChildOutcome::Unhealthy => {
                    tracing::warn!(target: "livekit", "LiveKit neodpovedá na health-check — reštartujem");
                    process::terminate(&mut child, guard).await;
                }
            }
            if healthy_for >= BACKOFF_RESET_AFTER {
                backoff = BACKOFF_MIN;
            }
            tracing::info!(target: "livekit", retry_secs = backoff.as_secs(), "reštart LiveKitu po backoffe");
            if sleep_or_stop(&mut stop, backoff).await {
                break;
            }
            backoff = next_backoff(backoff);
        }
        status.set(if self.binary_path().is_file() {
            LiveKitStatus::Stopped
        } else {
            LiveKitStatus::Absent
        });
        tracing::info!(target: "livekit", "supervízor LiveKitu zastavený");
    }
}

/// Sleduj potomka: pád, health, stop. Vracia aj dĺžku zdravého behu.
async fn watch_child(
    http: &reqwest::Client,
    health_url: &str,
    child: &mut Child,
    status: &StatusCell,
    stop: &mut watch::Receiver<bool>,
) -> (ChildOutcome, Duration) {
    let started = Instant::now();
    let mut healthy_since: Option<Instant> = None;
    let mut fails = 0u32;
    let mut tick = tokio::time::interval(HEALTH_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let healthy_for = |since: Option<Instant>| since.map(|s| s.elapsed()).unwrap_or_default();
    loop {
        tokio::select! {
            res = child.wait() => return (ChildOutcome::Exited(res), healthy_for(healthy_since)),
            changed = stop.changed() => {
                // Err = handle zahodený → tiež stop
                if changed.is_err() || *stop.borrow() {
                    return (ChildOutcome::StopRequested, healthy_for(healthy_since));
                }
            }
            _ = tick.tick() => {
                if probe(http, health_url).await {
                    if healthy_since.is_none() {
                        tracing::info!(target: "livekit", secs = started.elapsed().as_secs(), "LiveKit zdravý");
                        healthy_since = Some(Instant::now());
                    }
                    status.set(LiveKitStatus::Running);
                    fails = 0;
                } else {
                    status.set(LiveKitStatus::Stopped);
                    fails += 1;
                    let give_up = match healthy_since {
                        Some(_) => fails >= HEALTH_FAILS_BEFORE_RESTART,
                        None => started.elapsed() >= STARTUP_GRACE,
                    };
                    if give_up {
                        return (ChildOutcome::Unhealthy, healthy_for(healthy_since));
                    }
                    // zlyhanie resetuje „zdravý od“, nech backoff nevynuluje flapping
                    if fails >= HEALTH_FAILS_BEFORE_RESTART {
                        healthy_since = None;
                    }
                }
            }
        }
    }
}

/// `GET <url>` → 200?
async fn probe(http: &reqwest::Client, url: &str) -> bool {
    matches!(
        http.get(url).timeout(HEALTH_TIMEOUT).send().await,
        Ok(r) if r.status().is_success()
    )
}

/// Čakaj `d` alebo do stop signálu. `true` = stop.
async fn sleep_or_stop(stop: &mut watch::Receiver<bool>, d: Duration) -> bool {
    if *stop.borrow() {
        return true;
    }
    tokio::select! {
        _ = tokio::time::sleep(d) => false,
        changed = stop.changed() => changed.is_err() || *stop.borrow(),
    }
}

/// 1 → 2 → 4 → … → 60 s.
pub fn next_backoff(cur: Duration) -> Duration {
    (cur * 2).min(BACKOFF_MAX)
}

fn hex(bytes: &[u8]) -> String {
    myhsn_core::record::to_hex(bytes)
}

/// Over SHA-256 archívu a rozbaľ z neho binárku do `dir` (atomicky:
/// `.part` + rename), potom zapíš značku `.sha256`. `actual_sha` je hash
/// vypočítaný počas sťahovania.
pub fn install_from_archive(
    archive: &Path,
    expected_sha: &str,
    actual_sha: &str,
    dir: &Path,
) -> Result<PathBuf, CallsError> {
    if !actual_sha.eq_ignore_ascii_case(expected_sha) {
        return Err(CallsError::Checksum {
            expected: expected_sha.to_string(),
            actual: actual_sha.to_string(),
        });
    }
    let bin = dir.join(BINARY_NAME);
    let part = dir.join(format!("{BINARY_NAME}.part"));
    extract_binary(archive, &part)?;
    process::make_executable(&part).map_err(|e| CallsError::io(&part, e))?;
    std::fs::rename(&part, &bin).map_err(|e| CallsError::io(&bin, e))?;
    let marker = dir.join(".sha256");
    std::fs::write(&marker, expected_sha).map_err(|e| CallsError::io(&marker, e))?;
    Ok(bin)
}

/// Rozbaľ jediný súbor [`BINARY_NAME`] (Linux: `.tar.gz`).
#[cfg(unix)]
fn extract_binary(archive: &Path, dest: &Path) -> Result<(), CallsError> {
    let f = std::fs::File::open(archive).map_err(|e| CallsError::io(archive, e))?;
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(f));
    let entries = tar
        .entries()
        .map_err(|e| CallsError::Download(format!("archív: {e}")))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| CallsError::Download(format!("archív: {e}")))?;
        let is_bin = entry
            .path()
            .ok()
            .and_then(|p| p.file_name().map(|n| n == BINARY_NAME))
            .unwrap_or(false);
        if is_bin && entry.header().entry_type().is_file() {
            let mut out = std::fs::File::create(dest).map_err(|e| CallsError::io(dest, e))?;
            std::io::copy(&mut entry, &mut out).map_err(|e| CallsError::io(dest, e))?;
            out.sync_all().map_err(|e| CallsError::io(dest, e))?;
            return Ok(());
        }
    }
    Err(CallsError::Download(format!(
        "archív neobsahuje {BINARY_NAME}"
    )))
}

/// Rozbaľ jediný súbor [`BINARY_NAME`] (Windows: `.zip`).
#[cfg(windows)]
fn extract_binary(archive: &Path, dest: &Path) -> Result<(), CallsError> {
    let f = std::fs::File::open(archive).map_err(|e| CallsError::io(archive, e))?;
    let mut zip =
        zip::ZipArchive::new(f).map_err(|e| CallsError::Download(format!("archív: {e}")))?;
    let mut entry = zip
        .by_name(BINARY_NAME)
        .map_err(|_| CallsError::Download(format!("archív neobsahuje {BINARY_NAME}")))?;
    let mut out = std::fs::File::create(dest).map_err(|e| CallsError::io(dest, e))?;
    std::io::copy(&mut entry, &mut out).map_err(|e| CallsError::io(dest, e))?;
    out.sync_all().map_err(|e| CallsError::io(dest, e))?;
    Ok(())
}

/// Úroveň + správa + zvyšok polí z jedného riadku LiveKit logu.
#[derive(Debug, PartialEq, Eq)]
pub struct LogLine {
    pub level: tracing::Level,
    pub logger: String,
    pub msg: String,
    /// ostatné JSON polia (bez level/ts/msg/logger/caller)
    pub fields: String,
}

/// LiveKit (zap) JSON log → [`LogLine`]; ne-JSON riadok je `info` s textom.
pub fn parse_log_line(line: &str) -> LogLine {
    let Ok(serde_json::Value::Object(mut map)) = serde_json::from_str(line) else {
        return LogLine {
            level: tracing::Level::INFO,
            logger: String::new(),
            msg: line.to_string(),
            fields: String::new(),
        };
    };
    let take = |map: &mut serde_json::Map<String, serde_json::Value>, k: &str| match map.remove(k) {
        Some(serde_json::Value::String(s)) => s,
        Some(other) => other.to_string(),
        None => String::new(),
    };
    let level = match take(&mut map, "level").as_str() {
        "debug" => tracing::Level::DEBUG,
        "warn" | "warning" => tracing::Level::WARN,
        "error" | "dpanic" | "panic" | "fatal" => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };
    let msg = take(&mut map, "msg");
    let logger = take(&mut map, "logger");
    map.remove("ts");
    map.remove("caller");
    let fields = if map.is_empty() {
        String::new()
    } else {
        serde_json::Value::Object(map).to_string()
    };
    LogLine {
        level,
        logger,
        msg,
        fields,
    }
}

/// Potrubie stdout/stderr potomka → `tracing` target `livekit`.
async fn pipe_logs<R: AsyncRead + Unpin>(reader: R) {
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if line.trim().is_empty() {
            continue;
        }
        let l = parse_log_line(&line);
        match l.level {
            tracing::Level::ERROR => {
                tracing::error!(target: "livekit", logger = %l.logger, fields = %l.fields, "{}", l.msg)
            }
            tracing::Level::WARN => {
                tracing::warn!(target: "livekit", logger = %l.logger, fields = %l.fields, "{}", l.msg)
            }
            tracing::Level::DEBUG | tracing::Level::TRACE => {
                tracing::debug!(target: "livekit", logger = %l.logger, fields = %l.fields, "{}", l.msg)
            }
            tracing::Level::INFO => {
                tracing::info!(target: "livekit", logger = %l.logger, fields = %l.fields, "{}", l.msg)
            }
        }
    }
}

/// Handle supervízora (`managed`) alebo sondy (`external`).
pub struct ManagerHandle {
    stop_tx: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl ManagerHandle {
    /// `external`: len health sonda `GET <api_url>/` každých 5 s.
    pub fn probe_only(api_url: String, status: Arc<StatusCell>) -> Self {
        let (stop_tx, mut stop) = watch::channel(false);
        let task = tokio::spawn(async move {
            let http = reqwest::Client::new();
            let url = format!("{}/", api_url.trim_end_matches('/'));
            loop {
                let ok = probe(&http, &url).await;
                let new = if ok {
                    LiveKitStatus::Running
                } else {
                    LiveKitStatus::Stopped
                };
                if status.get() != new {
                    tracing::info!(target: "livekit", %url, status = new.as_str(), "stav externého LiveKitu");
                }
                status.set(new);
                if sleep_or_stop(&mut stop, HEALTH_INTERVAL).await {
                    break;
                }
            }
        });
        Self { stop_tx, task }
    }

    /// Graceful stop (SIGTERM potomkovi, čakanie max. ~15 s).
    pub async fn stop(self) {
        let _ = self.stop_tx.send(true);
        if tokio::time::timeout(Duration::from_secs(15), self.task)
            .await
            .is_err()
        {
            tracing::warn!(target: "livekit", "supervízor sa nezastavil do 15 s");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "myhsn-calls-{tag}-{}",
            hex(&crate::auth::random_32())
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn settings(dir: &Path) -> ManagedSettings {
        ManagedSettings {
            version: "1.13.11".into(),
            addons_dir: dir.to_path_buf(),
            keys: ApiKeys {
                key: "myhsnkey".into(),
                secret: "0123456789abcdef0123456789abcdef".into(),
            },
            webhook_url: "http://127.0.0.1:8123/calls/webhook".into(),
            node_ip: Some("192.0.2.20".into()),
        }
    }

    #[test]
    fn pin_table_covers_target_platforms() {
        let rel = release(super::super::LIVEKIT_VERSION).expect("default verzia je pinnutá");
        for p in ["linux_amd64", "linux_arm64", "windows_amd64"] {
            let a = rel.assets.iter().find(|a| a.platform == p).expect(p);
            assert_eq!(a.sha256.len(), 64);
            assert!(a.sha256.bytes().all(|c| c.is_ascii_hexdigit()));
        }
        assert_eq!(
            download_url("1.13.11", "linux_amd64"),
            "https://github.com/livekit/livekit/releases/download/v1.13.11/livekit_1.13.11_linux_amd64.tar.gz"
        );
        assert_eq!(
            archive_name("1.13.11", "windows_amd64"),
            "livekit_1.13.11_windows_amd64.zip"
        );
    }

    #[test]
    fn backoff_doubles_to_cap() {
        let mut b = BACKOFF_MIN;
        let mut seen = vec![b.as_secs()];
        for _ in 0..8 {
            b = next_backoff(b);
            seen.push(b.as_secs());
        }
        assert_eq!(seen, vec![1, 2, 4, 8, 16, 32, 60, 60, 60]);
    }

    #[test]
    fn config_has_spike_values() {
        let dir = tmpdir("yaml");
        let y = LiveKitManager::new(settings(&dir)).render_config();
        for needle in [
            "port: 7880\n",
            "  - \"0.0.0.0\"\n",
            "  tcp_port: 7881\n",
            "  udp_port: 7882\n",
            "  node_ip: \"192.0.2.20\"\n",
            "  \"myhsnkey\": \"0123456789abcdef0123456789abcdef\"\n",
            "  auto_create: false\n",
            "  empty_timeout: 300\n",
            "  api_key: \"myhsnkey\"\n",
            "    - \"http://127.0.0.1:8123/calls/webhook\"\n",
            "  json: true\n",
        ] {
            assert!(y.contains(needle), "chýba {needle:?} v:\n{y}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn log_line_parsing() {
        let l = parse_log_line(
            r#"{"level":"warn","ts":1763200000.1,"logger":"livekit","caller":"x.go:1","msg":"could not connect","room":"ab"}"#,
        );
        assert_eq!(l.level, tracing::Level::WARN);
        assert_eq!(l.msg, "could not connect");
        assert_eq!(l.logger, "livekit");
        assert_eq!(l.fields, r#"{"room":"ab"}"#);
        let raw = parse_log_line("starting LiveKit server");
        assert_eq!(raw.level, tracing::Level::INFO);
        assert_eq!(raw.msg, "starting LiveKit server");
        assert_eq!(
            parse_log_line(r#"{"level":"fatal","msg":"x"}"#).level,
            tracing::Level::ERROR
        );
    }

    /// Archív s falošnou binárkou: správny SHA → nainštalované; zlý → chyba
    /// a nič sa nerozbalí.
    #[cfg(unix)]
    #[test]
    fn install_verifies_sha_and_extracts_only_binary() {
        let dir = tmpdir("install");
        let archive = dir.join("lk.tar.gz");
        {
            let f = std::fs::File::create(&archive).unwrap();
            let gz = flate2::write::GzEncoder::new(f, flate2::Compression::fast());
            let mut b = tar::Builder::new(gz);
            for (name, body) in [
                ("LICENSE", &b"license"[..]),
                (BINARY_NAME, &b"#!/bin/sh\necho lk\n"[..]),
            ] {
                let mut h = tar::Header::new_gnu();
                h.set_size(body.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_data(&mut h, name, body).unwrap();
            }
            b.into_inner().unwrap().finish().unwrap();
        }
        let sha = hex(&Sha256::digest(std::fs::read(&archive).unwrap()));

        let bad = install_from_archive(&archive, &"0".repeat(64), &sha, &dir);
        assert!(matches!(bad, Err(CallsError::Checksum { .. })));
        assert!(!dir.join(BINARY_NAME).exists());

        let bin = install_from_archive(&archive, &sha, &sha, &dir).unwrap();
        assert_eq!(std::fs::read(&bin).unwrap(), b"#!/bin/sh\necho lk\n");
        assert!(!dir.join("LICENSE").exists(), "rozbaľuje sa len binárka");
        assert_eq!(std::fs::read_to_string(dir.join(".sha256")).unwrap(), sha);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&bin).unwrap().permissions().mode() & 0o111,
            0o111
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Už nainštalovaná binárka so správnou značkou sa nesťahuje znova.
    #[tokio::test]
    async fn ensure_installed_skips_download_when_marker_matches() {
        let Some(platform) = current_platform() else {
            return; // nepodporovaná platforma testu (macOS)
        };
        let dir = tmpdir("marker");
        let mgr = LiveKitManager::new(settings(&dir));
        let sha = release("1.13.11")
            .unwrap()
            .assets
            .iter()
            .find(|a| a.platform == platform)
            .unwrap()
            .sha256;
        std::fs::create_dir_all(mgr.version_dir()).unwrap();
        std::fs::write(mgr.binary_path(), b"x").unwrap();
        std::fs::write(mgr.version_dir().join(".sha256"), sha).unwrap();
        assert_eq!(mgr.ensure_installed().await.unwrap(), mgr.binary_path());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Integrný** (vyžaduje sieť + skutočnú binárku): stiahne LiveKit
    /// 1.13.11, spustí ho ako potomka, počká na health a zastaví ho.
    /// `cargo test -p node -- --ignored livekit_manager_real`
    #[tokio::test]
    #[ignore = "vyžaduje sieť a skutočnú LiveKit binárku (porty 7880–7882)"]
    async fn livekit_manager_real_binary_starts_and_stops() {
        let dir = tmpdir("real");
        let status = Arc::new(StatusCell::new(LiveKitStatus::Absent));
        let mut s = settings(&dir);
        s.node_ip = None;
        let handle = LiveKitManager::new(s).start(status.clone());
        let t0 = Instant::now();
        while status.get() != LiveKitStatus::Running {
            assert!(
                t0.elapsed() < Duration::from_secs(300),
                "LiveKit sa nespustil"
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        handle.stop().await;
        assert_eq!(status.get(), LiveKitStatus::Stopped);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
