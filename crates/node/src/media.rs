//! Médium — upload a stiahnutie **pominuteľných** blobov (B7/MYHSN-9).
//!
//! Rozhodnutia, ktoré tu žijú:
//! - **D-33** (kvóty a retention v TOML konfigurácii operátora; obrázky v
//!   chate sú pominuteľné — nie sú súčasťou append-only logu, lebo inak by
//!   sa nedali zmysť; TTL). Bloby teda žijú MIMO logu: súbory na disku,
//!   metadáta (veľkosť, hash, expirácia) v SQLite tabuľke `media`.
//! - **D-24** (bloby sa posielajú mimo WS session — HTTP). Upload aj
//!   stiahnutie sú obyčajné HTTP koncovky, nie WS frame.
//! - **D-25** (obálka — referencia na blob v tele správy). Samotná referencia
//!   (`media_id`) je v tele správy autora; uzol ju pri appende len uchováva,
//!   blob si klient stiahne z `GET /media/{id}`.
//!
//! Koncovky:
//! - `POST /media` — telí = **raw bajty** (`application/octet-stream`),
//!   autenticované `Authorization: Bearer <session token>`. Overí veľkosť
//!   jedného uploadu a kvótu na účet, uloží súbor + záznam, vráti
//!   `{id, url, expires_at, hash}`. Kódy: `413` nad `max_upload_bytes`,
//!   `507 Insufficient Storage` nad kvótou účtu (zdokumentovaná voľba —
//!   507 je registrovaná IANA kód pre kvótu úložiska, 429 je rate-limit),
//!   `401` bez session.
//! - `GET /media/{id}` — **bez auth** (id je 32 náhodných bajtov =
//!   neuhádnuiteľné), stream súboru, `404` po exspirácii alebo neznáme id.
//!
//! **Lazy cleanup (D-33):** pri KAŽDOM uploade aj stiahnutí premazáme
//! expirované záznamy a ich súbory — v tejto fáze bez cronu/dedicovaného
//! vlákna. Expirácia je teda viazaná na prevádzku (ako Retention erase,
//! `EraseReason::Retention`), čo je zámer.
//!
//! Súbory ani metadáta neobsahujú tajné; logujeme len dĺžky a kódy.

use crate::api::{self, ApiError, SharedStore};
use crate::auth;
use crate::media_clean;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use myhsn_core::record::{from_hex, to_hex};
use serde::Deserialize;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;

// --- defaulty sekcie [media] (D-33: nastavuje operátor, tu sú výchozie) ----

/// Výchozí strop jedného uploadu: 8 MiB (dostatčné pre fotku z telefónu).
pub const DEFAULT_MAX_UPLOAD_BYTES: u64 = 8 * 1024 * 1024;
/// Výchozí kvota neexpirovaných blobov na jeden účet: 200 MiB.
pub const DEFAULT_MAX_BYTES_PER_ACCOUNT: u64 = 200 * 1024 * 1024;
/// Výchozí TTL pominuteľného blobu: 86 400 s = 1 deň (produktové pravidlo
/// ownera: obrázky v chatoch vydržia pár dní, potom preč).
pub const DEFAULT_EPHEMERAL_TTL_SECS: u64 = 86_400;
/// Výchozí strop obálky kanála (B8/MYHSN-22, doc 24 §5.2): 2 MiB.
pub const DEFAULT_COVER_MAX_BYTES: u64 = 2 * 1024 * 1024;
/// Výchozí strop profilovej fotky (B8/MYHSN-22, doc 24 §5.2): 512 KiB.
pub const DEFAULT_AVATAR_MAX_BYTES: u64 = 512 * 1024;

fn default_max_upload() -> u64 {
    DEFAULT_MAX_UPLOAD_BYTES
}
fn default_max_per_account() -> u64 {
    DEFAULT_MAX_BYTES_PER_ACCOUNT
}
fn default_ttl() -> u64 {
    DEFAULT_EPHEMERAL_TTL_SECS
}
fn default_cover_max() -> u64 {
    DEFAULT_COVER_MAX_BYTES
}
fn default_avatar_max() -> u64 {
    DEFAULT_AVATAR_MAX_BYTES
}

/// TOML sekcia `[media]` — **voliteľná**; jej absencia znamená defaulty
/// (spätná kompatibilita: starý `node.toml` bez sekcie sa naďalej spustí).
#[derive(Debug, Clone, Deserialize)]
pub struct MediaConfig {
    /// Max veľkosť jedného uploadu v bajtoch.
    #[serde(default = "default_max_upload")]
    pub max_upload_bytes: u64,
    /// Max súčet neexpirovaných blobov na účet v bajtoch.
    #[serde(default = "default_max_per_account")]
    pub max_bytes_per_account: u64,
    /// TTL blobu v sekundách od uploadu.
    #[serde(default = "default_ttl")]
    pub ephemeral_ttl_secs: u64,
    /// Adresár blobov. `None` => `<data_dir>/media` (vyrieši [`Self::resolve_dir`]).
    #[serde(default)]
    pub dir: Option<String>,
    /// Max veľkosť obálky kanála v bajtoch (B8, `PUT /channels/{id}/cover`).
    #[serde(default = "default_cover_max")]
    pub cover_max_bytes: u64,
    /// Max veľkosť profilovej fotky v bajtoch (B8, `PUT /me/avatar`).
    #[serde(default = "default_avatar_max")]
    pub avatar_max_bytes: u64,
}

impl Default for MediaConfig {
    fn default() -> Self {
        Self {
            max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES,
            max_bytes_per_account: DEFAULT_MAX_BYTES_PER_ACCOUNT,
            ephemeral_ttl_secs: DEFAULT_EPHEMERAL_TTL_SECS,
            dir: None,
            cover_max_bytes: DEFAULT_COVER_MAX_BYTES,
            avatar_max_bytes: DEFAULT_AVATAR_MAX_BYTES,
        }
    }
}

impl MediaConfig {
    /// Vyrieši adresár blobov: vlastný `dir` (ak nastavený), inak
    /// `<data_dir>/media`. Relatívne cesty necháva na CWD procesa (ako
    /// `data_dir` sám).
    pub fn resolve_dir(&self, data_dir: &str) -> PathBuf {
        match self.dir.as_deref() {
            Some(d) if !d.trim().is_empty() => PathBuf::from(d),
            _ => PathBuf::from(data_dir).join("media"),
        }
    }
}

/// Runtime konfigurácia media — vyriešená adresa + limity. `Arc`-nute v
/// [`MediaState`], aby ju zdieľali všetky relácie bez kopírovania.
#[derive(Debug, Clone)]
pub struct MediaRuntime {
    pub max_upload_bytes: u64,
    pub max_bytes_per_account: u64,
    pub ephemeral_ttl_secs: u64,
    pub dir: PathBuf,
    /// Strop obálky kanála (B8).
    pub cover_max_bytes: u64,
    /// Strop profilovej fotky (B8).
    pub avatar_max_bytes: u64,
}

impl MediaRuntime {
    /// Z TOML konfigurácie + dátového adresára uzla (volá `main`).
    pub fn from_config(cfg: &MediaConfig, data_dir: &str) -> Self {
        Self {
            max_upload_bytes: cfg.max_upload_bytes,
            max_bytes_per_account: cfg.max_bytes_per_account,
            ephemeral_ttl_secs: cfg.ephemeral_ttl_secs,
            dir: cfg.resolve_dir(data_dir),
            cover_max_bytes: cfg.cover_max_bytes,
            avatar_max_bytes: cfg.avatar_max_bytes,
        }
    }

    /// Defaultné limity s daným adresárom — pre testy a integrný router.
    pub fn with_dir(dir: impl Into<PathBuf>) -> Self {
        Self {
            max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES,
            max_bytes_per_account: DEFAULT_MAX_BYTES_PER_ACCOUNT,
            ephemeral_ttl_secs: DEFAULT_EPHEMERAL_TTL_SECS,
            dir: dir.into(),
            cover_max_bytes: DEFAULT_COVER_MAX_BYTES,
            avatar_max_bytes: DEFAULT_AVATAR_MAX_BYTES,
        }
    }
}

/// Zdieľaný stav media handlerov: úložňa (metadáta + kvota) + runtime.
#[derive(Clone)]
pub struct MediaState {
    pub store: SharedStore,
    pub rt: Arc<MediaRuntime>,
}

impl MediaState {
    pub fn new(store: SharedStore, rt: MediaRuntime) -> Self {
        Self {
            store,
            rt: Arc::new(rt),
        }
    }
}

/// Router s media koncami. `build_router` ho merge-ne vedľa REST a WS.
/// B8 (MYHSN-22) pridáva atomické `PUT/DELETE /channels/{id}/cover` a
/// `PUT/DELETE /me/avatar` — obálky a avatary sú trvalé bloby (trieda 2/1),
/// preto žijú v tomto module (potrebujú adresár + limity), nie v `api`.
pub fn media_router(state: MediaState) -> Router {
    Router::new()
        .route("/media", axum::routing::post(upload_media))
        .route("/media/{id}", get(get_media))
        .route(
            "/channels/{id}/cover",
            axum::routing::put(put_cover).delete(delete_cover),
        )
        .route(
            "/me/avatar",
            axum::routing::put(put_avatar).delete(delete_avatar),
        )
        .with_state(state)
}

/// Cesta k súboru blobu (`<dir>/<id>.bin`).
fn blob_path(rt: &MediaRuntime, id: &str) -> PathBuf {
    rt.dir.join(format!("{id}.bin"))
}

/// Lazy cleanup (D-33): premazá expirované záznamy a ich súbory. Volané z
/// každého uploadu aj stiahnutia. Chyby len logujeme — cleanup nesmie zlyhať
/// requestu (najhoršie, že expirovaný blob ostane o niečo dlhšie).
fn cleanup_expired(state: &MediaState, now: i64) {
    let expired = {
        let mut store = api::lock(&state.store);
        match store.take_expired_media(now) {
            Ok(ids) => ids,
            Err(e) => {
                tracing::warn!(error = %e, "media cleanup: dotaz na expiráciu zlyhal");
                return;
            }
        }
    };
    for id in expired {
        // súbor môže chýbať (už zmazaný) — ignorujeme
        let _ = std::fs::remove_file(blob_path(&state.rt, &id));
    }
}

/// `POST /media` — raw bajty + Bearer session token.
///
/// Poradie kontroly je zámerné: najprv auth (401), potom cleanup, potom
/// veľkosť (413), potom kvota (507) — drahý zápis na disk ide až naposledy.
async fn upload_media(
    State(state): State<MediaState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let now = api::now_secs() as i64;

    // 1) Autentizácia: bez platnej relácie 401 (zámok držíme len na dotaz).
    let account = {
        let store = api::lock(&state.store);
        api::session_account(&store, api::bearer_token(&headers).as_deref())?
    };

    // 2) Lazy cleanup pred kontrolou kvoty — uvoľní miesto po expirovaných.
    cleanup_expired(&state, now);

    // 3) Veľkosť jedného uploadu.
    let size = body.len() as u64;
    if size == 0 {
        return Err(ApiError::bad_request("telo uploadu je prázdne"));
    }
    if size > state.rt.max_upload_bytes {
        return Err(ApiError::payload_too_large(format!(
            "upload {size} B prekráča limit {} B",
            state.rt.max_upload_bytes
        )));
    }

    // 4) Kvota na účet: súčet neexpirovaných + tento upload nesmie preliezť strop.
    let used = {
        let store = api::lock(&state.store);
        store.active_media_bytes(&account, now).map_err(ApiError::from)?
    };
    if used.saturating_add(size as i64) > state.rt.max_bytes_per_account as i64 {
        return Err(ApiError::insufficient_storage(format!(
            "kvota účtu: {used} B už uložených, limit {} B",
            state.rt.max_bytes_per_account
        )));
    }

    // 5) Neuhádnuiteľné id (32 B) + BLAKE3 hash obsahu (integrity).
    let id = to_hex(&auth::random_32());
    let hash = *blake3::hash(&body).as_bytes();

    std::fs::create_dir_all(&state.rt.dir).map_err(|e| {
        tracing::warn!(error = %e, dir = %state.rt.dir.display(), "media adresár sa nedá vytvoriť");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "media adresár nedostupný")
    })?;
    let path = blob_path(&state.rt, &id);
    if let Err(e) = std::fs::write(&path, &body) {
        tracing::warn!(error = %e, "media zápis súboru zlyhal");
        return Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "zápis media zlyhal",
        ));
    }

    let expires_at = now.saturating_add(state.rt.ephemeral_ttl_secs as i64);
    let inserted = {
        let mut store = api::lock(&state.store);
        store.insert_media(&id, &account, size as i64, &hash, now, expires_at)
    };
    if let Err(e) = inserted {
        // DB zlyhal → súbor osirotel, zmazeme ho (inak by tiekol disk).
        let _ = std::fs::remove_file(&path);
        return Err(ApiError::from(e));
    }

    tracing::debug!(id = %id, size, "media upload prijatý");
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": id,
            "url": format!("/media/{id}"),
            "expires_at": expires_at,
            "hash": to_hex(&hash),
        })),
    )
        .into_response())
}

/// `GET /media/{id}` — bez auth (id je neuhádnuiteľné), stream súboru.
async fn get_media(
    State(state): State<MediaState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let now = api::now_secs() as i64;

    // Id musí byť hex 32 B (64 znakov) — inak 404 (neznáme, nie chyba).
    if id.len() != 64 || from_hex(&id).is_none() {
        return Err(ApiError::not_found("media nenájdené"));
    }

    cleanup_expired(&state, now);

    let row = {
        let store = api::lock(&state.store);
        store.get_media(&id).map_err(ApiError::from)?
    };
    let Some(row) = row else {
        return Err(ApiError::not_found("media nenájdené"));
    };
    // Cleanup mohol meškať (alebo práve beží iná relácia) — expirované je 404.
    if row.expires_at <= now {
        return Err(ApiError::not_found("media expirované"));
    }

    let path = blob_path(&state.rt, &id);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(_) => {
            // Konsistencia: záznam bez súboru → zmaz záznam a 404.
            let mut store = api::lock(&state.store);
            let _ = store.delete_media(&id);
            return Err(ApiError::not_found("media súbor chýba"));
        }
    };

    // B8 (doc 24 §2): Content-Type sa berie zo stĺpca `mime` (staré riadky
    // ostávajú octet-stream). Pre trvalé bloby (trieda > 0) posieme
    // `Cache-Control: immutable` + `ETag` — je to bezpečné, lebo pri výmene
    // fotky vzniká nové id, teda nová URL. Pominuteľné majú max-age do
    // expirácie.
    let content_type = row
        .mime
        .clone()
        .unwrap_or_else(|| "application/octet-stream".to_string());
    let cache_control = if row.class > 0 {
        "public, max-age=31536000, immutable".to_string()
    } else {
        let remaining = (row.expires_at - now).max(0);
        format!("public, max-age={remaining}")
    };
    let etag = if row.class > 0 {
        Some(format!("\"{}\"", to_hex(&row.hash)))
    } else {
        None
    };

    let mut resp = (StatusCode::OK, bytes).into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
    h.insert(header::CACHE_CONTROL, cache_control.parse().unwrap());
    if let Some(e) = etag {
        h.insert(header::ETAG, e.parse().unwrap());
    }
    Ok(resp)
}

// ===========================================================================
// B8 (MYHSN-22): obálky kanálov a profilové fotky — doc 24 §2
// ===========================================================================

/// Overenie typu a vyčistenie metadát (spoločné pre obálku aj avatar).
/// Požiadavky (doc 24): `Content-Type` musí byť `image/jpeg` alebo
/// `image/png` **a** magic bytes musia sedieť k typu; WebP/GIF/SVG alebo
/// nesúlad → 415. Následne sa vyčistia GPS/IPTC/XMP metadata (GDPR —
/// `GET /media` je bez auth).
fn validate_and_clean(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(&'static str, Vec<u8>), ApiError> {
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(';').next().unwrap_or("").trim().to_ascii_lowercase())
        .unwrap_or_default();
    if ct != "image/jpeg" && ct != "image/png" {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Podporované sú len JPEG a PNG (Content-Type image/jpeg|image/png).",
        ));
    }
    let sniffed = media_clean::detect_mime(body).ok_or_else(|| {
        ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Súbor nezodpovedá supported formátu (magic bytes).",
        )
    })?;
    if sniffed != ct {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type nesedí s obsahom súboru.",
        ));
    }
    let cleaned = media_clean::clean(body, sniffed).ok_or_else(|| {
        ApiError::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, "Neplatný obrázok.")
    })?;
    Ok((sniffed, cleaned))
}

/// Atómové uloženie súboru (doc 24 krok 4): `<id>.tmp` → fsync → rename na
/// `<id>.bin`. Zlyhanie kedykoľvek pred rename nenechá čiastočný blob
/// (sweep pri štarte uprace `.tmp`).
fn store_blob_atomically(rt: &MediaRuntime, id: &str, bytes: &[u8]) -> Result<(), ApiError> {
    std::fs::create_dir_all(&rt.dir).map_err(|e| {
        tracing::warn!(error = %e, dir = %rt.dir.display(), "media adresár sa nedá vytvoriť");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "media adresár nedostupný")
    })?;
    let tmp = rt.dir.join(format!("{id}.tmp"));
    let final_path = blob_path(rt, id);
    let write = (|| -> std::io::Result<()> {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?; // dáta na disku pred rename (doc 24 krok 4)
        f.sync_data().ok();
        drop(f);
        std::fs::rename(&tmp, &final_path)?;
        // sync adresára nie je prenositeľne dostupný; rename + fsync súboru
        // je v praxi dostatočné (ext4 s default mountovaním)
        Ok(())
    })();
    if let Err(e) = write {
        let _ = std::fs::remove_file(&tmp);
        tracing::warn!(error = %e, "media zápis súboru zlyhal");
        return Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "zápis media zlyhal",
        ));
    }
    Ok(())
}

/// **F14c (MYHSN-58):** kto smie meniť **obálku** kanála. V group kanáli
/// channel admin alebo owner, prípadne server admin / moderator s
/// `MANAGE_CHANNELS` (rozhodnutie §13). Legacy kanál ostáva bez zmeny —
/// stačí Bearer, ako doteraz. Neexistujúci kanál tu nič netvrdí
/// (`channel_authority` je `None`), 404 ošetrí úložňa ako doteraz.
fn cover_gate(
    store: &crate::store::Store,
    channel: &[u8; 32],
    account: &[u8; 32],
) -> Result<(), ApiError> {
    let auth = match store.channel_authority(channel, account).map_err(ApiError::from)? {
        Some(auth) => auth,
        None => return Ok(()),
    };
    if !auth.group {
        return Ok(());
    }
    let allowed = auth.server_role == 2
        || (auth.server_role == 1
            && (auth.server_perms & myhsn_core::roles::MANAGE_CHANNELS) != 0)
        || matches!(auth.role, Some(1) | Some(2));
    if allowed {
        Ok(())
    } else {
        Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "obalku skupinoveho kanala meni len channel admin, owner alebo manage_channels moderator",
            "not_channel_admin",
        ))
    }
}

/// `PUT /channels/{id}/cover` — raw bajty + `Content-Type: image/jpeg|png`
/// + Bearer. Jeden atomický request: neexistuje stav „nahraté, ešte
/// nepripojené“ (doc 24). Kódy: 400 zlé id · 401 · 404 kanál · 413 nad
/// `cover_max_bytes` · 415 typ/magic nesedí.
///
/// **F14c (MYHSN-58):** v group kanáli pribúda 403 `not_channel_admin` —
/// obálku mení channel admin alebo owner, prípadne server admin či
/// moderator s `MANAGE_CHANNELS`. Legacy kanál ostáva bez zmeny, stačí
/// Bearer a existujúci kanál.
async fn put_cover(
    State(state): State<MediaState>,
    headers: HeaderMap,
    Path(hex_id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let now = api::now_secs() as i64;
    let account = {
        let store = api::lock(&state.store);
        api::session_account(&store, api::bearer_token(&headers).as_deref())?
    };
    let channel = api::parse_id32_hex(&hex_id)
        .ok_or_else(|| ApiError::bad_request("id kanála musí byť hex 32 bajtov (64 znakov)"))?;
    // **F14c:** skôr, než zapíšeme blob na disk — bez práva nesmeme ani
    // siahnuť na súborový systém
    {
        let store = api::lock(&state.store);
        cover_gate(&store, &channel, &account)?;
    }

    let size = body.len() as u64;
    if size == 0 {
        return Err(ApiError::bad_request("telo je prázdne"));
    }
    if size > state.rt.cover_max_bytes {
        return Err(ApiError::payload_too_large(format!(
            "obálka {size} B prekráča limit {} B.",
            state.rt.cover_max_bytes
        )));
    }
    let (mime, cleaned) = validate_and_clean(&headers, &body)?;

    let id = to_hex(&auth::random_32());
    let hash = *blake3::hash(&cleaned).as_bytes();
    store_blob_atomically(&state.rt, &id, &cleaned)?;

    let update = {
        let mut store = api::lock(&state.store);
        let res = store.put_channel_cover(
            &channel,
            &account,
            &id,
            mime,
            cleaned.len() as i64,
            &hash,
            now,
        );
        // DB zlyhal → nový súbor osirel, zmazeme ho (inak by tiekol disk)
        if res.is_err() {
            let _ = std::fs::remove_file(blob_path(&state.rt, &id));
        }
        res
    }
    .map_err(ApiError::from)?;

    // Starý súbor až PO commite (doc 24 krok 6) — pri páde pred ním ho
    // uprace sweep pri štarte.
    if let Some(old) = &update.old_media_id {
        let _ = std::fs::remove_file(blob_path(&state.rt, old));
    }

    // set_by je username účtu, ktorý obálku nastavil (spoločenská kontrola)
    let set_by = {
        let store = api::lock(&state.store);
        store
            .account_by_id(&account)
            .ok()
            .flatten()
            .map(|a| a.username)
    };
    tracing::debug!(channel = %hex_id, id = %id, size = cleaned.len(), "obálka kanála nastavená");
    Ok((
        StatusCode::OK,
        Json(json!({
            "cover": {
                "url": format!("/media/{id}"),
                "hash": to_hex(&hash),
                "mime": mime,
                "set_by": set_by,
                "set_at": now,
            },
            "meta_version": update.meta_version,
        })),
    )
        .into_response())
}

/// `DELETE /channels/{id}/cover` — idempotentné 204 (aj bez obálky).
/// Fyzicky zmaze bajty hneď; v logu nič neostane (GDPR, doc 24).
async fn delete_cover(
    State(state): State<MediaState>,
    headers: HeaderMap,
    Path(hex_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let account = {
        let store = api::lock(&state.store);
        api::session_account(&store, api::bearer_token(&headers).as_deref())?
    };
    let channel = api::parse_id32_hex(&hex_id)
        .ok_or_else(|| ApiError::bad_request("id kanála musí byť hex 32 bajtov (64 znakov)"))?;
    // **F14c:** mazanie obálky je jej zmena — rovnaká brána ako PUT
    {
        let store = api::lock(&state.store);
        cover_gate(&store, &channel, &account)?;
    }
    let old = {
        let mut store = api::lock(&state.store);
        store.clear_channel_cover(&channel).map_err(ApiError::from)?
    };
    if let Some(old) = &old {
        let _ = std::fs::remove_file(blob_path(&state.rt, old));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// `PUT /me/avatar` — rovnaké pravidlá ako obálka, limit
/// `avatar_max_bytes` (512 KiB). 200 `{avatar: {url, hash, mime}}`.
async fn put_avatar(
    State(state): State<MediaState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let now = api::now_secs() as i64;
    let account = {
        let store = api::lock(&state.store);
        api::session_account(&store, api::bearer_token(&headers).as_deref())?
    };

    let size = body.len() as u64;
    if size == 0 {
        return Err(ApiError::bad_request("telo je prázdne"));
    }
    if size > state.rt.avatar_max_bytes {
        return Err(ApiError::payload_too_large(format!(
            "avatar {size} B prekráča limit {} B.",
            state.rt.avatar_max_bytes
        )));
    }
    let (mime, cleaned) = validate_and_clean(&headers, &body)?;

    let id = to_hex(&auth::random_32());
    let hash = *blake3::hash(&cleaned).as_bytes();
    store_blob_atomically(&state.rt, &id, &cleaned)?;

    let old = {
        let mut store = api::lock(&state.store);
        let res = store.put_account_avatar(
            &account,
            &id,
            mime,
            cleaned.len() as i64,
            &hash,
            now,
        );
        if res.is_err() {
            let _ = std::fs::remove_file(blob_path(&state.rt, &id));
        }
        res
    }
    .map_err(ApiError::from)?;

    if let Some(old) = &old {
        let _ = std::fs::remove_file(blob_path(&state.rt, old));
    }
    tracing::debug!(id = %id, size = cleaned.len(), "avatar nastavený");
    Ok((
        StatusCode::OK,
        Json(json!({
            "avatar": {
                "url": format!("/media/{id}"),
                "hash": to_hex(&hash),
                "mime": mime,
            },
        })),
    )
        .into_response())
}

/// `DELETE /me/avatar` — idempotentné 204, fyzické zmazanie bajtov.
async fn delete_avatar(
    State(state): State<MediaState>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let account = {
        let store = api::lock(&state.store);
        api::session_account(&store, api::bearer_token(&headers).as_deref())?
    };
    let old = {
        let mut store = api::lock(&state.store);
        store.clear_account_avatar(&account).map_err(ApiError::from)?
    };
    if let Some(old) = &old {
        let _ = std::fs::remove_file(blob_path(&state.rt, old));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Výsledok upratovania pri štarte (len na logovanie).
#[derive(Debug, Default)]
pub struct SweepReport {
    pub tmp_files: usize,
    pub orphan_files: usize,
    pub orphan_rows: usize,
}

/// **Sweep pri štarte uzla** (doc 24 krok 7): zotavenie z pádu medzi
/// zápisom súboru a commitom transakcie.
///
/// 1. `.tmp` súbory (nedokončený rename) — zmazať.
/// 2. `.bin` súbory bez riadku v `media` — siroty z pádu pred commitom.
/// 3. Trvalé riadky (trieda 1/2), na ktoré už nič neukazuje (kanál/účet
///    zmenený iným uzlom alebo ručne) — zmazať riadok aj súbor.
///
/// Pominuteľné bloby (trieda 0) sa tu neupratujú — o ne sa stará TTL
/// cleanup, lebo „ukazovateľ“ na ne drží len telo správy v logu (D-25).
pub fn sweep_orphans(shared: &SharedStore, rt: &MediaRuntime) -> SweepReport {
    let mut report = SweepReport::default();
    let entries = match std::fs::read_dir(&rt.dir) {
        Ok(e) => e,
        Err(_) => return report, // adresár ešte neexistuje — nič upratať
    };
    let mut files: Vec<(String, PathBuf)> = Vec::new(); // (id, cesta) pre *.bin
    for entry in entries.flatten() {
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if name.ends_with(".tmp") {
            if std::fs::remove_file(&path).is_ok() {
                report.tmp_files += 1;
            }
        } else if let Some(stem) = name.strip_suffix(".bin") {
            files.push((stem.to_string(), path));
        }
    }
    // súbory bez riadku
    let known: std::collections::HashSet<String> = {
        let store = api::lock(shared);
        store.all_media_ids().unwrap_or_default().into_iter().collect()
    };
    for (id, path) in &files {
        if !known.contains(id) {
            if std::fs::remove_file(path).is_ok() {
                report.orphan_files += 1;
            }
        }
    }
    // trvalé riadky bez ukazovateľa (vrátane ich súborov)
    let dead = {
        let mut store = api::lock(shared);
        store.take_unreferenced_permanent_media().unwrap_or_default()
    };
    for id in dead {
        let _ = std::fs::remove_file(blob_path(rt, &id));
        report.orphan_rows += 1;
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt; // oneshot_ready / oneshot pre volanie routera

    use std::sync::{Arc, Mutex};

    /// Dočasný adresár pre testy — unikátny, po teste zmazaný.
    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            p.push(format!(
                "myhsn-media-{}-{}-{}",
                tag,
                std::process::id(),
                auth::random_32().iter().map(|b| *b as u32).sum::<u32>()
            ));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Zostaví router + úložňu + reláciu; vráti (router, token_hex, store).
    async fn setup(_tag: &str, rt: MediaRuntime) -> (Router, String, SharedStore) {
        let store: SharedStore = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let account = {
            let mut s = store.lock().unwrap();
            s.create_account("tester", "phc", 1_000).unwrap().id
        };
        let token = {
            let mut s = store.lock().unwrap();
            let t = auth::new_session_token();
            let now = api::now_secs();
            s.put_session(&auth::hash_session_token(&t), &account, now, 30 * 24 * 3600)
                .unwrap();
            to_hex(&t)
        };
        let router = media_router(MediaState::new(store.clone(), rt));
        (router, token, store)
    }

    fn post_media(token: &str, body: &[u8]) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/media")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/octet-stream")
            .body(Body::from(body.to_vec()))
            .unwrap()
    }

    /// (a) Roundtrip: upload → download, zhodný hash aj bajty.
    #[tokio::test]
    async fn upload_download_roundtrip_matches_hash() {
        let tmp = TempDir::new("roundtrip");
        let (router, token, _store) = setup("roundtrip", MediaRuntime::with_dir(&tmp.0)).await;
        let payload = b"myhsn-obrazok-bytes-123".to_vec();

        let resp = router.clone().oneshot(post_media(&token, &payload)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let id = json["id"].as_str().unwrap().to_string();
        assert_eq!(id.len(), 64, "id je hex 32 B");
        let expected_hash = to_hex(blake3::hash(&payload).as_bytes());
        assert_eq!(json["hash"].as_str().unwrap(), expected_hash);
        assert_eq!(json["url"].as_str().unwrap(), format!("/media/{id}"));

        let get = Request::builder()
            .uri(format!("/media/{id}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(get).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let got = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&*got, &payload[..], "stiahnuté bajty sedia s uploadom");
    }

    /// (b) Nad limitom jedného uploadu → 413.
    #[tokio::test]
    async fn oversize_upload_is_413() {
        let tmp = TempDir::new("oversize");
        let rt = MediaRuntime {
            max_upload_bytes: 16,
            ..MediaRuntime::with_dir(&tmp.0)
        };
        let (router, token, _store) = setup("oversize", rt).await;
        let big = vec![7u8; 17]; // 17 > 16
        let req = post_media(&token, &big);
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// (c) Kvota na účet → druhý upload nad strop dostane 507.
    #[tokio::test]
    async fn account_quota_is_507() {
        let tmp = TempDir::new("quota");
        let rt = MediaRuntime {
            max_upload_bytes: 100,
            max_bytes_per_account: 100,
            ..MediaRuntime::with_dir(&tmp.0)
        };
        let (router, token, _store) = setup("quota", rt).await;
        let first = vec![1u8; 60];
        let req = post_media(&token, &first);
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        // 60 + 60 = 120 > 100 → kvota
        let second = vec![2u8; 60];
        let req = post_media(&token, &second);
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INSUFFICIENT_STORAGE);
    }

    /// (d) Expirácia → 404 a súbor je zmazaný (lazy cleanup pri GET).
    #[tokio::test]
    async fn expiry_returns_404_and_deletes_file() {
        let tmp = TempDir::new("expiry");
        let rt = MediaRuntime {
            ephemeral_ttl_secs: 0, // expiruje okamžite (expires_at == created)
            ..MediaRuntime::with_dir(&tmp.0)
        };
        let (router, token, _store) = setup("expiry", rt).await;
        let payload = b"pominutelny".to_vec();
        let req = post_media(&token, &payload);
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let id = json["id"].as_str().unwrap().to_string();
        let file = tmp.0.join(format!("{id}.bin"));
        assert!(file.exists(), "hneď po uploadi súbor existuje");

        // GET spustí cleanup → zmaže expirovaný záznam + súbor → 404
        let get = Request::builder().uri(format!("/media/{id}")).body(Body::empty()).unwrap();
        let resp = router.oneshot(get).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(!file.exists(), "expirovaný súbor bol zmazaný");
    }

    /// (e) Bez auth → 401.
    #[tokio::test]
    async fn upload_without_auth_is_401() {
        let tmp = TempDir::new("noauth");
        let (router, _token, _store) = setup("noauth", MediaRuntime::with_dir(&tmp.0)).await;
        let req = Request::builder()
            .method("POST")
            .uri("/media")
            .body(Body::from(b"x".to_vec()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// GET neznáme/nesprávne id → 404 (bez auth, bez paniky).
    #[tokio::test]
    async fn get_unknown_id_is_404() {
        let tmp = TempDir::new("unknown");
        let (router, _token, _store) = setup("unknown", MediaRuntime::with_dir(&tmp.0)).await;
        let get = Request::builder()
            .uri("/media/deadbeef") // krátke id → 404
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(get).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Konfigurácia bez sekcie [media] = defaulty (spätná kompatibilita).
    #[test]
    fn config_defaults_when_section_absent() {
        let cfg: MediaConfig = toml::from_str("listen = \"0.0.0.0:1\"\ndata_dir = \"./d\"")
            .unwrap_or_default();
        // toml bez [media] → MediaConfig::default() cez #[serde(default)] v NodeConfig;
        // tu testujeme priamo default sekcie:
        let with_media: MediaConfig = toml::from_str("").unwrap();
        assert_eq!(with_media.max_upload_bytes, DEFAULT_MAX_UPLOAD_BYTES);
        assert_eq!(with_media.ephemeral_ttl_secs, DEFAULT_EPHEMERAL_TTL_SECS);
        assert_eq!(with_media.resolve_dir("./d"), PathBuf::from("./d/media"));
        let _ = cfg;
    }

    /// Vlastný `dir` v TOML má prednosť pred `<data_dir>/media`.
    #[test]
    fn config_dir_override() {
        let cfg: MediaConfig =
            toml::from_str("dir = \"/var/lib/myhsn/media\"\nephemeral_ttl_secs = 60")
                .unwrap();
        assert_eq!(cfg.ephemeral_ttl_secs, 60);
        assert_eq!(cfg.max_upload_bytes, DEFAULT_MAX_UPLOAD_BYTES);
        assert_eq!(cfg.resolve_dir("./d"), PathBuf::from("/var/lib/myhsn/media"));
    }

    // --- B8 (MYHSN-22): obálky, avatary, hlavičky, sweep -------------------

    /// Minimálny platný JPEG (SOI + APP0 + SOS + data + EOI) — prechádza
    /// magic aj clean bez zmeny.
    fn tiny_jpeg() -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8];
        // APP0 JFIF (dĺžka 4 = 2 + 2 payload)
        v.extend_from_slice(&[0xFF, 0xE0, 0x00, 0x04, b'J', b'F']);
        v.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x04, 0x00, 0x08]); // SOS
        v.extend_from_slice(&[0xAA, 0xBB]);
        v.extend_from_slice(&[0xFF, 0xD9]); // EOI
        v
    }

    /// JPEG s EXIF APP1 (orientation + GPS IFD), XMP a IPTC — na dôkaz,
    /// že endpoint vyčistí GPS/XMP/IPTC a ponechá orientation.
    fn jpeg_with_gps() -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8];
        v.extend_from_slice(&[0xFF, 0xE0, 0x00, 0x04, b'J', b'F']); // APP0
        // EXIF APP1: prefix + big-endian TIFF s orientation + GPS IFD pointer
        let mut exif = b"Exif\0\0".to_vec();
        exif.extend_from_slice(b"MM"); // big-endian
        exif.extend_from_slice(&0x002Au16.to_be_bytes());
        exif.extend_from_slice(&8u32.to_be_bytes()); // IFD0 na 8
        exif.extend_from_slice(&2u16.to_be_bytes()); // 2 entry
        // orientation (0x0112 SHORT count1 = 6)
        exif.extend_from_slice(&0x0112u16.to_be_bytes());
        exif.extend_from_slice(&3u16.to_be_bytes());
        exif.extend_from_slice(&1u32.to_be_bytes());
        exif.extend_from_slice(&[0u8, 6, 0, 0]);
        // GPSInfo (0x8825 LONG count1 = offset 32)
        exif.extend_from_slice(&0x8825u16.to_be_bytes());
        exif.extend_from_slice(&4u16.to_be_bytes());
        exif.extend_from_slice(&1u32.to_be_bytes());
        exif.extend_from_slice(&32u32.to_be_bytes());
        exif.extend_from_slice(&0u32.to_be_bytes()); // next IFD
        // GPS IFD na 32: 1 entry + next 0
        exif.extend_from_slice(&1u16.to_be_bytes());
        exif.extend_from_slice(&0x0001u16.to_be_bytes());
        exif.extend_from_slice(&2u16.to_be_bytes());
        exif.extend_from_slice(&2u32.to_be_bytes());
        exif.extend_from_slice(b"N\0\0\0");
        exif.extend_from_slice(&0u32.to_be_bytes());
        let elen = (exif.len() + 2) as u16;
        v.extend_from_slice(&[0xFF, 0xE1]);
        v.extend_from_slice(&elen.to_be_bytes());
        v.extend_from_slice(&exif);
        // XMP APP1
        let xmp = b"http://ns.adobe.com/xap/1.0/\0<xmp/>";
        let xlen = (xmp.len() + 2) as u16;
        v.extend_from_slice(&[0xFF, 0xE1]);
        v.extend_from_slice(&xlen.to_be_bytes());
        v.extend_from_slice(xmp);
        // IPTC APP13
        let iptc = b"IPTC\0\x1c\x02\x00tajny popis";
        let ilen = (iptc.len() + 2) as u16;
        v.extend_from_slice(&[0xFF, 0xED]);
        v.extend_from_slice(&ilen.to_be_bytes());
        v.extend_from_slice(iptc);
        // SOS + data + EOI
        v.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x04, 0x00, 0x08]);
        v.extend_from_slice(&[0x11, 0x22]);
        v.extend_from_slice(&[0xFF, 0xD9]);
        v
    }

    fn put_req(
        method: &str,
        uri: &str,
        token: &str,
        ct: Option<&str>,
        body: &[u8],
    ) -> Request<Body> {
        let mut b = Request::builder().method(method).uri(uri);
        if !token.is_empty() {
            b = b.header("authorization", format!("Bearer {token}"));
        }
        if let Some(c) = ct {
            b = b.header("content-type", c);
        }
        b.body(Body::from(body.to_vec())).unwrap()
    }

    /// Vytvorí kanál v úložni a vráti jeho hex id.
    fn make_channel(store: &SharedStore, name: &str) -> String {
        let mut s = store.lock().unwrap();
        let ch = s
            .create_channel(name, myhsn_core::channel::ChannelKind::Wall)
            .unwrap();
        to_hex(&ch.id)
    }

    async fn json_of(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn cover_id_of(json: &serde_json::Value) -> String {
        json["cover"]["url"]
            .as_str()
            .unwrap()
            .trim_start_matches("/media/")
            .to_string()
    }

    /// **Kritérium B8 (doc 24 §5.4/5.5):** `PUT /channels/{id}/cover` uloží
    /// obálku, `GET /media/{id}` ju vráti so správnym Content-Type,
    /// Cache-Control immutable a ETagom (trvalý blob).
    #[tokio::test]
    async fn put_cover_happy_path_and_media_headers() {
        let tmp = TempDir::new("cover_ok");
        let (router, token, store) = setup("cover_ok", MediaRuntime::with_dir(&tmp.0)).await;
        let ch_hex = make_channel(&store, "nastienka");

        let resp = router
            .clone()
            .oneshot(put_req(
                "PUT",
                &format!("/channels/{ch_hex}/cover"),
                &token,
                Some("image/jpeg"),
                &tiny_jpeg(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = json_of(resp).await;
        let cover = &json["cover"];
        assert_eq!(json["meta_version"], 1);
        assert_eq!(cover["mime"], "image/jpeg");
        assert_eq!(cover["set_by"], "tester");
        assert!(cover["set_at"].is_number());
        let id = cover_id_of(&json);
        assert_eq!(id.len(), 64);
        assert!(
            blob_path(&MediaRuntime::with_dir(&tmp.0), &id).exists(),
            "súbor na disku"
        );

        // GET /media/{id} — trvalý blob: Content-Type + immutable + ETag
        let get = Request::builder()
            .uri(format!("/media/{id}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(get).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()["content-type"], "image/jpeg");
        assert!(resp.headers()["cache-control"]
            .to_str()
            .unwrap()
            .contains("immutable"));
        assert!(resp.headers().contains_key("etag"), "trvalý blob má ETag");
    }

    /// **Kritérium B8:** kódy chýb — 401 bez auth, 404 neznámy kanál,
    /// 413 nad limitom, 415 zlý typ/magic.
    #[tokio::test]
    async fn put_cover_error_codes() {
        let tmp = TempDir::new("cover_err");
        let rt = MediaRuntime {
            cover_max_bytes: 64,
            ..MediaRuntime::with_dir(&tmp.0)
        };
        let (router, token, store) = setup("cover_err", rt).await;
        let ch_hex = make_channel(&store, "nastienka");

        // 401 bez tokena
        let resp = router
            .clone()
            .oneshot(put_req(
                "PUT",
                &format!("/channels/{ch_hex}/cover"),
                "",
                Some("image/jpeg"),
                &tiny_jpeg(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // 404 neznámy kanál
        let resp = router
            .clone()
            .oneshot(put_req(
                "PUT",
                &format!("/channels/{}/cover", "ee".repeat(32)),
                &token,
                Some("image/jpeg"),
                &tiny_jpeg(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // 413 nad limitom (64 B)
        let big = [vec![0xFF, 0xD8, 0xFF, 0xD9], vec![9u8; 100]].concat();
        let resp = router
            .clone()
            .oneshot(put_req(
                "PUT",
                &format!("/channels/{ch_hex}/cover"),
                &token,
                Some("image/jpeg"),
                &big,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        // 415 Content-Type nie je jpeg/png
        let resp = router
            .clone()
            .oneshot(put_req(
                "PUT",
                &format!("/channels/{ch_hex}/cover"),
                &token,
                Some("image/webp"),
                &tiny_jpeg(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

        // 415 magic bytes nesedia s Content-Type (PNG hlavička, ale jpeg CT)
        let resp = router
            .oneshot(put_req(
                "PUT",
                &format!("/channels/{ch_hex}/cover"),
                &token,
                Some("image/jpeg"),
                media_clean::PNG_MAGIC,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    /// **Kritérium B8 (doc 24 §5.4 krit. 3):** výmena obálky zmaze starý
    /// súbor — v adresári ostane len nový.
    #[tokio::test]
    async fn put_cover_replaces_and_deletes_old_file() {
        let tmp = TempDir::new("cover_replace");
        let (router, token, store) = setup("cover_replace", MediaRuntime::with_dir(&tmp.0)).await;
        let ch_hex = make_channel(&store, "nastienka");
        let rt = MediaRuntime::with_dir(&tmp.0);

        let resp = router
            .clone()
            .oneshot(put_req(
                "PUT",
                &format!("/channels/{ch_hex}/cover"),
                &token,
                Some("image/jpeg"),
                &tiny_jpeg(),
            ))
            .await
            .unwrap();
        let first = json_of(resp).await;
        let id1 = cover_id_of(&first);

        let png = [media_clean::PNG_MAGIC.to_vec(), vec![0u8; 12]].concat();
        let resp = router
            .clone()
            .oneshot(put_req(
                "PUT",
                &format!("/channels/{ch_hex}/cover"),
                &token,
                Some("image/png"),
                &png,
            ))
            .await
            .unwrap();
        let second = json_of(resp).await;
        let id2 = cover_id_of(&second);
        assert_ne!(id1, id2);
        assert_eq!(second["meta_version"], 2);

        assert!(!blob_path(&rt, &id1).exists(), "starý súbor zmazaný");
        assert!(blob_path(&rt, &id2).exists(), "nový súbor prítomný");
    }

    /// **Kritérium B8:** `DELETE /channels/{id}/cover` zmaze súbor a je
    /// idempotentné (204 aj bez obálky).
    #[tokio::test]
    async fn delete_cover_removes_file_and_is_idempotent() {
        let tmp = TempDir::new("cover_del");
        let (router, token, store) = setup("cover_del", MediaRuntime::with_dir(&tmp.0)).await;
        let ch_hex = make_channel(&store, "nastienka");
        let rt = MediaRuntime::with_dir(&tmp.0);

        let resp = router
            .clone()
            .oneshot(put_req(
                "PUT",
                &format!("/channels/{ch_hex}/cover"),
                &token,
                Some("image/jpeg"),
                &tiny_jpeg(),
            ))
            .await
            .unwrap();
        let id = cover_id_of(&json_of(resp).await);

        let resp = router
            .clone()
            .oneshot(put_req(
                "DELETE",
                &format!("/channels/{ch_hex}/cover"),
                &token,
                None,
                b"",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert!(!blob_path(&rt, &id).exists(), "fyzicky zmazané (GDPR)");

        // idempotentné: druhý DELETE tiež 204
        let resp = router
            .oneshot(put_req(
                "DELETE",
                &format!("/channels/{ch_hex}/cover"),
                &token,
                None,
                b"",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    /// **Dôkaz GDPR (doc 24 §2 krok 3):** `PUT` s JPEG obsahujúcim GPS/XMP/
    /// IPTC uloží vyčistené bajty — GPS IFD je nulnutý, XMP a IPTC preč,
    /// orientation zachované.
    #[tokio::test]
    async fn put_cover_strips_gps_xmp_iptc() {
        let tmp = TempDir::new("cover_gps");
        let (router, token, store) = setup("cover_gps", MediaRuntime::with_dir(&tmp.0)).await;
        let ch_hex = make_channel(&store, "nastienka");

        let resp = router
            .clone()
            .oneshot(put_req(
                "PUT",
                &format!("/channels/{ch_hex}/cover"),
                &token,
                Some("image/jpeg"),
                &jpeg_with_gps(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = json_of(resp).await;
        let id = cover_id_of(&json);

        // stiahni uložený blob a over vyčistenie
        let get = Request::builder()
            .uri(format!("/media/{id}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(get).await.unwrap();
        let stored = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert!(
            !stored.windows(20).any(|w| w.starts_with(b"http://ns.adobe.com")),
            "XMP preč"
        );
        assert!(!stored.windows(4).any(|w| w == b"IPTC"), "IPTC preč");
        // GPS IFD pointer (0x8825) má nulnutú hodnotu
        let exif_at = stored
            .windows(6)
            .position(|w| w == b"Exif\0\0")
            .expect("EXIF ostal");
        let tiff = &stored[exif_at + 6..];
        let count = u16::from_be_bytes([tiff[8], tiff[9]]) as usize;
        let mut gps_zeroed = false;
        let mut orient_ok = false;
        for n in 0..count {
            let e = 10 + n * 12;
            let tag = u16::from_be_bytes([tiff[e], tiff[e + 1]]);
            if tag == 0x8825 {
                assert_eq!(&tiff[e + 8..e + 12], &[0u8; 4], "GPS IFD nulnutý");
                gps_zeroed = true;
            }
            if tag == 0x0112 {
                assert_eq!(&tiff[e + 8..e + 10], &[0u8, 6], "orientation zachované");
                orient_ok = true;
            }
        }
        assert!(gps_zeroed, "GPS tag prítomný a nulnutý");
        assert!(orient_ok, "orientation zachované");
    }

    /// **Kritérium B8:** `PUT /me/avatar` + `DELETE /me/avatar`.
    #[tokio::test]
    async fn put_and_delete_avatar() {
        let tmp = TempDir::new("avatar");
        let (router, token, _store) = setup("avatar", MediaRuntime::with_dir(&tmp.0)).await;
        let rt = MediaRuntime::with_dir(&tmp.0);

        let resp = router
            .clone()
            .oneshot(put_req(
                "PUT",
                "/me/avatar",
                &token,
                Some("image/png"),
                media_clean::PNG_MAGIC,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = json_of(resp).await;
        assert_eq!(json["avatar"]["mime"], "image/png");
        let id = json["avatar"]["url"]
            .as_str()
            .unwrap()
            .trim_start_matches("/media/")
            .to_string();

        let resp = router
            .oneshot(put_req("DELETE", "/me/avatar", &token, None, b""))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert!(!blob_path(&rt, &id).exists());
    }

    /// **Kritérium B8 (doc 24 §2):** sweep pri štarte zmaže `.tmp`, súbory
    /// bez riadka a trvalé riadky bez ukazovateľa.
    #[test]
    fn sweep_orphans_cleans_tmp_orphan_files_and_rows() {
        let tmp = TempDir::new("sweep");
        let rt = MediaRuntime::with_dir(&tmp.0);
        let store: SharedStore = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));

        // 1. .tmp súbor
        std::fs::write(rt.dir.join("deadbeef.tmp"), b"ciastocny").unwrap();
        // 2. .bin súbor bez riadku v media
        std::fs::write(rt.dir.join("aabbcc.bin"), b"sirota-subor").unwrap();
        // 3. trvalý riadok bez ukazovateľa: naviazaný avatar + sirota riadok
        {
            let mut s = store.lock().unwrap();
            let acc = s.create_account("sweep", "phc", 1).unwrap().id;
            s.put_account_avatar(&acc, "row-kept", "image/png", 5, &[0x22; 32], 1)
                .unwrap();
            // sirota riadok triedy 2 priamo (kanál/účet naň neukazuje)
            s.insert_media_row_raw("row-orphan", &acc, 5, &[0x11; 32], 1, i64::MAX, 2, Some("image/jpeg"))
                .unwrap();
        }
        std::fs::write(blob_path(&rt, "row-orphan"), b"x").unwrap();
        std::fs::write(blob_path(&rt, "row-kept"), b"x").unwrap();

        let report = sweep_orphans(&store, &rt);
        assert_eq!(report.tmp_files, 1, ".tmp zmazaný");
        assert_eq!(report.orphan_files, 1, "aabbcc.bin bez riadka zmazaný");
        assert_eq!(report.orphan_rows, 1, "row-orphan riadok zmazaný");
        assert!(!rt.dir.join("deadbeef.tmp").exists());
        assert!(!rt.dir.join("aabbcc.bin").exists());
        assert!(!blob_path(&rt, "row-orphan").exists(), "sirota súbor preč");
        assert!(blob_path(&rt, "row-kept").exists(), "naviazaný avatar ostáva");
        assert!(store
            .lock()
            .unwrap()
            .get_media("row-kept")
            .unwrap()
            .is_some());
        assert!(store
            .lock()
            .unwrap()
            .get_media("row-orphan")
            .unwrap()
            .is_none());
    }

    /// TOML: `cover_max_bytes` a `avatar_max_bytes` sa dajú nastaviť.
    #[test]
    fn config_cover_and_avatar_limits() {
        let cfg: MediaConfig =
            toml::from_str("cover_max_bytes = 100\navatar_max_bytes = 50").unwrap();
        assert_eq!(cfg.cover_max_bytes, 100);
        assert_eq!(cfg.avatar_max_bytes, 50);
        // absencia → defaulty
        let d: MediaConfig = toml::from_str("").unwrap();
        assert_eq!(d.cover_max_bytes, DEFAULT_COVER_MAX_BYTES);
        assert_eq!(d.avatar_max_bytes, DEFAULT_AVATAR_MAX_BYTES);
    }
}
