//! SQLite úloža záznamov a kanálov (rozhodnutie **D-29**).
//!
//! Tu — a len tu — žije SQL. Jadro `core` definuje iba log/KV traity
//! ([`myhsn_core::storage`]) a zostáva sans-IO; `rusqlite` s feature
//! `bundled` je závislosť tohto crate (overené `cargo tree -p core`).
//!
//! Schéma (verzia 4, migrácie v kóde cez `PRAGMA user_version`):
//! - `meta` — KV (watermarky, soľ, ID uzla, manifest) → [`MetaStore`],
//! - `records` — append-only log; `hash` je primárny kľúč, takže append je
//!   **idempotentný podľa hashu** (D-25), a `UNIQUE (channel, node_epoch,
//!   node_seq)` stráži poradie (D-25); `client_hash` (B5) je unikátny hash
//!   **prijatých** bajtov pred opečiatkovaním — vďaka nemu je aj WS append
//!   idempotentný voči opakovanej správe toho istého klienta,
//! - `channels` — kanály vrátane epochy a soli slepého hashu,
//! - `seq_counters` — alokátor `node_seq` per `(channel, node_epoch)`;
//!   nová epocha nemá riadok, takže poradie začína od 1 (D-25),
//! - `accounts` / `device_keys` — B4 (MYHSN-6, D-26): účet = množina
//!   device kľúčov atestovaných uzlom; heslo sa drží ako Argon2id PHC
//!   hash, nikdy nie v jasnom tvare,
//! - `sessions` — B4: relácie prihlásenia; **ukladá sa len BLAKE3 hash
//!   tokena** s expiráciou (~30 dní), hodnota tokena nikde.
//!
//! Prevádzkové veci: WAL mód (čítač/nezávislý zapisovateľ bez blokovania),
//! `foreign_keys=ON`, `synchronous=NORMAL` a **transakcia** okolo každého
//! zápisu, aby log nemohol zostať napoly zapísaný.

// B3/B4 stavia rozhranie úložne, ktoré až B6 (mazanie) a B7 (kvóty) naplno
// napoja na binárku — kým ich `main` nevolá, Rust by inak hlásil `dead_code`
// aj na veciach, ktoré jadro a testy aktívne používajú. Preto allow tu, nie
// zmazanie kódu.
#![allow(dead_code)]

use myhsn_core::channel::{Channel, ChannelKind};
use myhsn_core::identity::{Account, AccountId, DeviceKey, DevicePublicKey, NodeId};
use myhsn_core::record::{
    Envelope, EnvelopeError, EraseReason, NodeStamp, Payload, RecordHash, RecordKind,
};
use myhsn_core::seq::{ChannelId, SeqPos};
use myhsn_core::storage::{MetaStore, RangeQuery, RecordStore};
use rusqlite::{params, Connection, Error as SqliteError};
use std::collections::HashSet;
use std::fmt;
use std::path::Path;

/// Cieľová verzia schémy. Migrácie sa aplikujú po sebe pri štarte uzla
/// (D-21b: migrácie schémy pri štarte).
const SCHEMA_VERSION: i64 = 6;

/// Kľúč v `meta`: ID systémového kanála s auditom rolí (F14a, O5 —
/// filtrujeme podľa ID, nie podľa mena).
const META_SYSTEM_CHANNEL: &[u8] = b"system_channel_id";
/// Kľúč v `meta`: runtime override politiky registrácie (F14a, O11).
const META_POLICY: &[u8] = b"registration_policy";
/// Kľúč v `meta`: najnižšia verzia binárky, ktorá túto DB bezpečne otvorí
/// (F14c). Aditívne migrácie môžu v budúcnosti zapísať nižšiu hodnotu, než
/// je ich vlastná verzia — potom staršia binárka DB otvorí aj po migrácii
/// (rollback bez obnovy dát). V6 píše `6`: F14a binárka má v kóde
/// `SCHEMA_VERSION=5` a prísny guard `found > SCHEMA_VERSION`, takže na
/// schéme 6 naskočí len po obnove `.pre-v6` zálohy (rozhodnutie F14c,
/// wiki doc 32 §5).
const META_SCHEMA_COMPAT: &[u8] = b"schema_compat";

/// Výsledok atómovej registrácie (F14a).
#[derive(Debug)]
pub struct RegOutcome {
    pub account: Account,
    /// Kód role (`myhsn_core::roles::Role`): 2 ak účet práve získal
    /// admina (bootstrap), inak 0.
    pub role: u8,
    pub perms: u32,
    /// `true` = účet čaká na schválenie (`admin_approved`).
    pub pending: bool,
    pub invite_consumed: bool,
    /// `true` = registrácia práve vytvorila prvého admina uzla.
    pub became_admin: bool,
}

/// Chyby registrácie pod rolovým systémom (F14a).
#[derive(Debug)]
pub enum RegError {
    Store(StoreError),
    UsernameTaken(String),
    /// `invite_only` a klient neposlal platnú pozvánku.
    InviteRequired,
    /// Pozvánka odoslaná, ale neplatná / expirovaná / already-použitá.
    InviteInvalid,
}

impl From<StoreError> for RegError {
    fn from(e: StoreError) -> Self {
        RegError::Store(e)
    }
}

impl From<SqliteError> for RegError {
    fn from(e: SqliteError) -> Self {
        RegError::Store(e.into())
    }
}

/// Chyby zmeny role (F14a).
#[derive(Debug)]
pub enum RoleError {
    Store(StoreError),
    NoSuchAccount,
    /// Posledný admin sa nesmie odomocniť (demota/revokácia).
    LastAdmin,
}

impl From<StoreError> for RoleError {
    fn from(e: StoreError) -> Self {
        RoleError::Store(e)
    }
}

impl From<SqliteError> for RoleError {
    fn from(e: SqliteError) -> Self {
        RoleError::Store(e.into())
    }
}

/// **F14c (MYHSN-58):** chyby operácií so skupinovými kanálmi. Kódy
/// `ApiError` mapuje v `api.rs` (strojové kódy kontraktu).
#[derive(Debug)]
pub enum ChannelError {
    Store(StoreError),
    /// Kanál pod id neexistuje.
    NoSuchChannel,
    /// Kanál existuje, ale nie je skupinový (`owner IS NULL`) — membership
    /// operácie nad ním nedávajú zmysel.
    NotGroupChannel,
    /// Cieľový účet neexistuje.
    NoSuchAccount,
    /// Cieľový účet existuje, ale nie je aktívny (`status != 0`).
    AccountInactive,
    /// Účet už člen je (POST /members nad existujúcim; grant role je PUT).
    AlreadyMember,
    /// Účet člen nie je (DELETE/mute nad nečlenom; owner nie je člen).
    NotMember,
    /// Ownera nemožno revoke/odobrať — kanál musí mať ownera; najprv
    /// transfer (`owner_must_transfer`).
    OwnerCannotBeRemoved,
    /// Cieľ už je owner (`already_owner`).
    AlreadyOwner,
    /// Owner sa nedá stíšiť (F14c; dôvod je v dokumentácii, F14d prináša
    /// audit `SetChannelMute` a mute ownera cez server admina).
    OwnerNotMutable,
    /// Zrušenie stíšenia nad účtom, ktorý stíšený nie je (`not_muted`).
    NotMuted,
    /// Kód role nedáva zmysel (owner nie je riadok, 255 len pre `prev_role`).
    /// Bráni ho už volajúci (REST), ale stráž v úložni je lacná.
    InvalidRole,
}

impl From<StoreError> for ChannelError {
    fn from(e: StoreError) -> Self {
        ChannelError::Store(e)
    }
}

impl From<SqliteError> for ChannelError {
    fn from(e: SqliteError) -> Self {
        ChannelError::Store(e.into())
    }
}

/// Stav ownera kanála (F14c) — tri stavy, ktoré sa nesmú zamieňať:
/// * `None` … kanál **neexistuje**
/// * `Some(None)` … **legacy** kanál (`channels.owner IS NULL`) — žiadny
///   membership model, správanie presne ako pred F14c
/// * `Some(Some(owner))` … **skupinový** kanál s ownerom
pub type ChannelOwnerState = Option<Option<[u8; 32]>>;

/// Riadok `GET /channels/{id}/members` (F14c). `role` je kód
/// [`myhsn_core::roles::ChannelRole`] pre členov (0/1); owner ide samostatne
/// (`channels.owner`), nie ako riadok tejto tabuľky.
#[derive(Debug)]
pub struct ChannelMemberRow {
    pub account: [u8; 32],
    pub username: String,
    pub role: u8,
    pub added_by: Option<[u8; 32]>,
    pub joined_at: u64,
    pub muted_until: Option<u64>,
}

/// **F14c (MYHSN-58):** efektívna právomoc účtu v konkrétnom kanáli.
/// Zjednocuje **serverovú** rolu (F14a) a **kanálovú** rolu (F14c) do
/// jedného rozhodovacieho tvaru, aby WS gating, REST gating aj pravidlá
/// mazania cudzích príspevkov (`deletion.rs`) zisťovali to isté jedným
/// dotazom a nemohli sa rozísť.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChannelAuthority {
    /// `true` = group kanál (`channels.owner` NOT NULL). V legacy kanáli
    /// nie sú žiadne membership požiadavky (rozhodnutie F14c §1).
    pub group: bool,
    /// Owner group kanála (`None` = legacy kanál).
    pub owner: Option<[u8; 32]>,
    /// Kanálová role: `Some(2)` owner (dosadená z `channels.owner`),
    /// `Some(1)` admin, `Some(0)` member, `None` = nie je člen.
    pub role: Option<u8>,
    /// Stíšenie do tejto unix sekundy; `None` = nie je stíšený.
    pub muted_until: Option<u64>,
    /// Serverová rola účtu: 0 user, 1 moderator, 2 admin (F14a).
    pub server_role: u8,
    /// Bitmaska práv moderátora (F14a, `myhsn_core::roles`).
    pub server_perms: u32,
}

impl ChannelAuthority {
    /// **Hodnosť** podľa rozhodnutia F14c §6 — maximum zo serverovej a
    /// kanálovej zložky: server admin 5, moderator s `DELETE_POSTS` 4,
    /// owner 3, channel admin 2, member 1, iný 0. Prísne vyššia hodnosť je
    /// podmienka zásahu do cudzieho príspevku aj do cudzieho člena.
    pub fn rank(&self) -> u8 {
        use myhsn_core::roles::DELETE_POSTS;
        let server = if self.server_role == 2 {
            5
        } else if self.server_role == 1 && (self.server_perms & DELETE_POSTS) != 0 {
            4
        } else {
            0
        };
        let channel = match self.role {
            Some(2) => 3,
            Some(1) => 2,
            Some(0) => 1,
            _ => 0,
        };
        server.max(channel)
    }

    /// Schopnosť mazať **cudzí** príspevok v tomto kanáli (F14c §6):
    /// server admin a moderator s `DELETE_POSTS` v **každom** kanáli
    /// (teda aj v legacy — zadanie „v každom kanáli“), owner kanála alebo
    /// channel admin — posledné dve len v group kanáli.
    pub fn can_delete(&self) -> bool {
        use myhsn_core::roles::DELETE_POSTS;
        if self.server_role == 2 {
            return true;
        }
        if self.server_role == 1 && (self.server_perms & DELETE_POSTS) != 0 {
            return true;
        }
        self.group && matches!(self.role, Some(1) | Some(2))
    }

    /// Člen group kanála: member, admin alebo owner. Owner nie je riadok
    /// tabuľky `channel_members`, ale členom kanála JE.
    pub fn is_member(&self) -> bool {
        self.role.is_some()
    }

    /// Považuje sa účet za stíšeného v čase `now` (F14c §7)? Hranica je
    /// neostrá: `now == muted_until` už stíšenie ukončuje.
    pub fn muted(&self, now: u64) -> bool {
        self.muted_until.map(|until| until > now).unwrap_or(false)
    }
}

/// Riadok `GET /invites` (token sa vracia len pri vytvorení).
#[derive(Debug)]
pub struct InviteRow {
    pub id: i64,
    pub label: Option<String>,
    pub created_by: [u8; 32],
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub used_by: Option<[u8; 32]>,
    pub used_at: Option<u64>,
}

/// Riadok `GET /admin/users` (F14a).
#[derive(Debug)]
pub struct AdminUserRow {
    pub id: [u8; 32],
    pub username: String,
    pub role: u8,
    pub perms: u32,
    pub status: u8,
    pub created: u64,
}

/// SQL pre verziu 1. Držíme ho tu, mimo jadra (D-29).
const MIGRATE_V1: &str = r#"
CREATE TABLE meta (
    key   BLOB PRIMARY KEY NOT NULL,
    value BLOB NOT NULL
);

CREATE TABLE channels (
    id         BLOB PRIMARY KEY NOT NULL,
    name       TEXT NOT NULL UNIQUE,
    kind       INTEGER NOT NULL,
    salt       BLOB NOT NULL,
    node_epoch INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE seq_counters (
    channel    BLOB NOT NULL,
    node_epoch INTEGER NOT NULL,
    -- najvyššie už PRIDELené poradie v tejto epoche (0 = ešte nič);
    -- UPOZORNENIE: pri `INSERT … ON CONFLICT DO UPDATE … RETURNING` SQLite
    -- vracia hodnotu PO update, preto stĺpec nesmie byť „ďalšie“, ale
    -- „posledné pridelené“. Inak by prvá alokácia vrátila 2 namiesto 1.
    last_seq   INTEGER NOT NULL,
    PRIMARY KEY (channel, node_epoch),
    FOREIGN KEY (channel) REFERENCES channels(id)
);

CREATE TABLE records (
    hash       BLOB PRIMARY KEY NOT NULL,
    channel    BLOB NOT NULL,
    node_epoch INTEGER NOT NULL,
    node_seq   INTEGER NOT NULL,
    body_hash  BLOB NOT NULL,
    blind_hash BLOB NOT NULL,
    kind       INTEGER NOT NULL,
    author     BLOB NOT NULL,
    raw        BLOB NOT NULL,
    UNIQUE (channel, node_epoch, node_seq)
);

-- index pre slepé vyhľadávanie v rámci kanála (D-25);
-- poradie kanála obsluhuje index UNIQUE (channel, node_epoch, node_seq)
CREATE INDEX idx_records_blind ON records (channel, blind_hash);
"#;

/// SQL pre verziu 2 — B4 (účty, device keys, sessions) + B5 (`client_hash`
/// pre idempotentný WS append pred opečiatkovaním).
const MIGRATE_V2: &str = r#"
CREATE TABLE accounts (
    id         BLOB PRIMARY KEY NOT NULL,
    username   TEXT NOT NULL UNIQUE,
    -- Argon2id PHC reťazec ($argon2id$v=19$m=19456,t=2,p=1$…); heslo samo
    -- sa nikdy neuloží (D-26)
    pass_hash  TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE device_keys (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id BLOB NOT NULL REFERENCES accounts(id),
    -- ed25519 verejný kľúč zariadenia; jeden kľúč patrí práve jednému
    -- účtu (D-26: účet = množina kľúčov, kľúč sa nedá zdieľať)
    public_key BLOB NOT NULL UNIQUE,
    label      TEXT NOT NULL,
    attested_at INTEGER NOT NULL,
    revoked_at INTEGER,                     -- NULL = aktívny kľúč
    UNIQUE (account_id, public_key)
);
CREATE INDEX idx_device_keys_active ON device_keys (public_key)
    WHERE revoked_at IS NULL;

CREATE TABLE sessions (
    token_hash BLOB PRIMARY KEY NOT NULL,   -- BLAKE3(token), nikdy nie token
    account_id BLOB NOT NULL REFERENCES accounts(id),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL             -- unix sekundy; za tou dobou 401
);
CREATE INDEX idx_sessions_expiry ON sessions (expires_at);

-- B5: hash prijatých bajtov pred opečiatkovaním. UNIQUE dovoľuje viac
-- NULL (erase záznamy a priame vklady ho nemajú), duplikát tej istej
-- WS správy tak odmietne databáza, nie len naša kontrola.
ALTER TABLE records ADD COLUMN client_hash BLOB;
CREATE UNIQUE INDEX idx_records_client_hash ON records (client_hash)
    WHERE client_hash IS NOT NULL;
"#;

/// Verzia 3 (B7/MYHSN-9, D-33): tabuľka **media** pre pominuteľné bloby
/// (obrázky v chate). Súbory žijú MIMO append-only logu (D-33 — inak by sa
/// nedali zmysť), v SQLite je len metadáta potrebné na kvótu a expiráciu.
/// `id` je hex 32 náhodných bajtov (neuhádnuiteľné → GET bez auth), `hash`
/// je BLAKE3 obsahu (integrity), `expires_at` riadi TTL a lazy cleanup.
const MIGRATE_V3: &str = r#"
CREATE TABLE media (
    id         TEXT  PRIMARY KEY NOT NULL,
    account_id BLOB  NOT NULL,
    size       INTEGER NOT NULL,
    hash       BLOB  NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

-- kvota na účet sčítava neexpirované bloby; cleanup skúma expiráciu
CREATE INDEX media_account_active ON media (account_id, expires_at);
CREATE INDEX media_expires ON media (expires_at);
"#;

/// Verzia 4 (B8/MYHSN-22, návrh doc 24 §2): **len ADD COLUMN** — žiadne
/// prestavby tabuliek, staré dáta sa nedotknú.
///
/// - `accounts.display_name` — voliteľné meno zobrazenia (NULL = nenastavené,
///   klient zobrazuje username); `accounts.avatar_media` — media.id profilovej
///   fotky (trvalý blob, trieda 1).
/// - `channels.cover_*` — obálka kanála ako atribút kanála (rovnako ako
///   `name`/`kind`, nepodpísané; L1 manifest ju raz ponesie), `meta_version`
///   rastie pri každej zmene obálky, aby klient vedel, či treba prekresliť.
/// - `media.class` — 0 = pominuteľný (chat, TTL), 1 = avatar, 2 = obálka;
///   kvota a cleanup sa týkajú **len** triedy 0. `media.mime` — skutočný
///   typ pre `GET /media/{id}` (NULL = staré riadky → octet-stream).
const MIGRATE_V4: &str = r#"
ALTER TABLE accounts ADD COLUMN display_name TEXT;          -- NULL = nenastavené
ALTER TABLE accounts ADD COLUMN avatar_media TEXT;          -- media.id alebo NULL

ALTER TABLE channels ADD COLUMN cover_media  TEXT;          -- media.id alebo NULL
ALTER TABLE channels ADD COLUMN cover_set_by BLOB;          -- accounts.id
ALTER TABLE channels ADD COLUMN cover_set_at INTEGER;       -- unix s
ALTER TABLE channels ADD COLUMN meta_version INTEGER NOT NULL DEFAULT 0;

-- 0 = pominuteľný (chat, TTL), 1 = avatar, 2 = obálka
ALTER TABLE media ADD COLUMN class INTEGER NOT NULL DEFAULT 0;
ALTER TABLE media ADD COLUMN mime  TEXT;                    -- NULL = staré riadky → octet-stream
CREATE INDEX media_class ON media (class);
"#;

/// **F14a (MYHSN-56):** rolový systém, politika registrácie a pozvánky.
/// - `accounts.role` — 0 = user, 1 = moderator, 2 = admin (kódy
///   `myhsn_core::roles::Role`); default 0, teda **každý existujúci účet
///   zostáva user** (spätná kompatibilita: migrácia nikoho nepovýši).
/// - `accounts.perms` — bitmask práv moderátora
///   (`myhsn_core::roles::*`); pre admina a usera kanonicky 0.
/// - `accounts.status` — 0 = aktívny, 1 = čakajúci na schválenie
///   (`admin_approved`). Rozšíriteľné (banned neskôr) — preto číslo,
///   nie bool (rozhodnutie O4, wiki doc 32).
/// - `invites` — single-use pozvánky: token sa ukladá len ako BLAKE3
///   hash (vzor `sessions`), `used_by`/`used_at` nesú spotrebu.
const MIGRATE_V5: &str = r#"
ALTER TABLE accounts ADD COLUMN role   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE accounts ADD COLUMN perms  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE accounts ADD COLUMN status INTEGER NOT NULL DEFAULT 0;

CREATE TABLE invites (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash BLOB NOT NULL UNIQUE,
    label      TEXT,
    created_by BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    used_by    BLOB,
    used_at    INTEGER
);
CREATE INDEX invites_created_by ON invites (created_by);
"#;

/// **F14c (MYHSN-58):** aditívna migrácia na verziu 6 — skupinové kanály.
/// Žiadna deštruktívna zmena: `channels.owner` je voliteľný stĺpec (NULL =
/// legacy kanál bez membership modelu, teda KAŽDÝ existujúci kanál aj
/// systémový), `channel_members` je nová tabuľka, ktorú stará binárka
/// jednoducho nevidí. `INSERT INTO channels (id, name, kind, salt,
/// node_epoch)` v starej binárke zostáva platný (owner dostane NULL).
/// Rollback BINÁRKY F14a na schéme 6 však `migrate()` odmietne
/// (`SchemaTooNew`, guard bol v kóde vždy) — preto migrácia PRED aplikáciou
/// urobí `VACUUM INTO` súborovú zálohu a rollback = binárka + obnova
/// `.pre-v6.bak` (rozhodnutie F14c, wiki doc 32 §5).
const MIGRATE_V6: &str = r#"
ALTER TABLE channels ADD COLUMN owner BLOB;

CREATE TABLE channel_members (
    channel     BLOB NOT NULL,
    account     BLOB NOT NULL,
    -- per-kanálová role: 0 = member, 1 = admin (myhsn_core::roles::ChannelRole).
    -- Owner TU nie je — drží sa v channels.owner a práve jeden owner
    -- plynie zo štruktúry schémy (rozhodnutie F14c).
    role        INTEGER NOT NULL,
    added_by    BLOB,
    joined_at   INTEGER NOT NULL,
    -- stíšenie (F14c): unix sekunda, kedy stíšenie skončí; NULL = nie je
    -- stíšený. Materializovaný stav bez auditu (vzor cover), kind 12 je
    -- v core rezervovaný pre budúci SetChannelMute.
    muted_until INTEGER,
    PRIMARY KEY (channel, account)
) WITHOUT ROWID;
CREATE INDEX channel_members_account ON channel_members (account);
"#;

/// Chyby úložne.
#[derive(Debug)]
pub enum StoreError {
    /// Zlyhanie SQLite.
    Sql(SqliteError),
    /// I/O okolo súboru databázy (adresár sa nedá vytvoriť, disk je plný).
    Io(std::io::Error),
    /// Uložené/poslané raw bajty nie sú platná obálka — indexové stĺpce
    /// by sa nedali zostaviť a záznam by sa nedal overiť.
    NotEnvelope(EnvelopeError),
    /// `hash` nezodpovedá `BLAKE3(raw)`, alebo pečiatka v obálke nesedí s
    /// pozíciou, pod ktorou ju uzol ukladá. Index by klamal.
    IndexMismatch { reason: &'static str },
    /// Pozícia `(channel, node_epoch, node_seq)` už patrí inému hashu.
    PositionConflict {
        channel: ChannelId,
        node_epoch: u64,
        node_seq: u64,
    },
    /// Kanál s týmto ID neexistuje.
    NoSuchChannel(ChannelId),
    /// Názov kanála je v uzle obsadený.
    ChannelNameTaken(String),
    /// V dátach je nepoznaný druh kanála (posun medzi verziami).
    BadChannelKind(i64),
    /// Schéma je novšia, než tá, ktorej rozumí táto binárka (rollback
    /// binárky bez obnovy dát — D-22).
    SchemaTooNew { found: i64, supported: i64 },
    /// Username je v uzle obsadený (B4, D-26).
    UsernameTaken(String),
    /// Účet neexistuje (B4).
    NoSuchAccount,
    /// Verejný kľúč má inú dĺžku, než ed25519 vyžaduje (B4).
    BadDeviceKeyLen(usize),
    /// Device kľúč je už atestovaný (tým istým alebo iným účtom) — B4.
    DeviceKeyTaken,
    /// Device kľúč pod týmto id a účtom neexistuje (B4).
    NoSuchDevice(i64),
    /// Záznam s týmto `client_hash` už bol prevzatý (B5 — pretek dvoch
    /// rovnakých správ; volajúci má dotazať existujúcu pozíciu).
    ClientHashTaken,
    /// Erase (B6, D-30) mieri na záznam, ktorý v logu nie je — cieľ sa nedá
    /// fyzicky nahradiť, preto ani erase záznam nevkladáme.
    EraseTargetMissing(RecordHash),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Sql(e) => write!(f, "SQLite: {e}"),
            StoreError::Io(e) => write!(f, "I/O: {e}"),
            StoreError::NotEnvelope(e) => write!(f, "nie je platná obálka: {e:?}"),
            StoreError::IndexMismatch { reason } => write!(f, "index nesedí s obálkou: {reason}"),
            StoreError::PositionConflict {
                channel,
                node_epoch,
                node_seq,
            } => write!(
                f,
                "pozícia (channel {}… , epoch {node_epoch}, seq {node_seq}) je už obsadená",
                &myhsn_core::record::to_hex(&channel[..4])
            ),
            StoreError::NoSuchChannel(c) => {
                write!(f, "kanál {}… neexistuje", &myhsn_core::record::to_hex(&c[..4]))
            }
            StoreError::ChannelNameTaken(n) => write!(f, "názov kanála „{n}“ je obsadený"),
            StoreError::BadChannelKind(k) => write!(f, "nepoznaný druh kanála {k}"),
            StoreError::SchemaTooNew { found, supported } => write!(
                f,
                "schéma {found} je novšia než podporovaná {supported}"
            ),
            StoreError::UsernameTaken(u) => write!(f, "username „{u}“ je obsadený"),
            StoreError::NoSuchAccount => write!(f, "účet neexistuje"),
            StoreError::BadDeviceKeyLen(n) => {
                write!(f, "verejný kľúč má {n} bajtov, očakávam 32")
            }
            StoreError::DeviceKeyTaken => write!(f, "device kľúč je už atestovaný"),
            StoreError::NoSuchDevice(id) => write!(f, "device kľúč id {id} neexistuje"),
            StoreError::ClientHashTaken => write!(f, "záznam s týmto client_hash už existuje"),
            StoreError::EraseTargetMissing(h) => write!(
                f,
                "cieľ erase {}… neexistuje",
                myhsn_core::record::to_hex(&h.0[..8])
            ),
        }
    }
}

impl std::error::Error for StoreError {}

/// Device kľúč s databázovým id (REST `DELETE /devices/{id}` ho potrebuje;
/// core `DeviceKey` id neobsahuje, lebo to je detail úložne).
#[derive(Clone, Debug)]
pub struct DeviceRow {
    pub id: i64,
    pub key: DeviceKey,
}

/// Záznam lookupu pubkey → meno pre `GET /members` (B5.1, MYHSN-19;
/// rozšírené B8/MYHSN-22 o `display_name` a `avatar`). Obsahuje iba
/// verejné údaje: kľúč zariadenia, username, voliteľné meno a odkaz na
/// profilovú fotku — žiadne heslo, e-mail ani session token (GDPR minimum).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberRow {
    pub public_key: [u8; 32],
    pub username: String,
    /// Voliteľné meno zobrazenia (NULL = nenastavené → klient ukazuje
    /// username). B8, návrh doc 24 §4.
    pub display_name: Option<String>,
    /// Profilová fotka ako `(media_id, BLAKE3 hash)` alebo NULL. `url` si
    /// skladá API vrstva z id.
    pub avatar: Option<(String, [u8; 32])>,
}

/// Referencia na obálku kanála pre `GET /channels` (B8, doc 24 §2):
/// `{url, hash, mime, set_by, set_at}` — `set_by` je **username** účtu,
/// ktorý obálku naposledy nastavil (spoločenská kontrola v malej komunite).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverRef {
    pub media_id: String,
    pub hash: [u8; 32],
    pub mime: Option<String>,
    pub set_by: Option<String>,
    pub set_at: Option<i64>,
}

/// Obálka + `meta_version` kanála pre `GET /channels` (B8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelCoverRow {
    pub id: ChannelId,
    pub meta_version: i64,
    pub cover: Option<CoverRef>,
}

/// Účet pre `GET /me` / `PATCH /me` (B8) — verejné pole + avatar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountRow {
    pub id: [u8; 32],
    pub username: String,
    pub display_name: Option<String>,
    /// Avatar ako `(media_id, hash, mime)` alebo NULL.
    pub avatar: Option<(String, [u8; 32], Option<String>)>,
}

/// Výsledok atomického `PUT /channels/{id}/cover` (B8): id starého blobu
/// (volajúci zmaže súbor **až po commite**) a nový `meta_version`.
#[derive(Clone, Debug)]
pub struct CoverUpdate {
    pub old_media_id: Option<String>,
    pub meta_version: i64,
}

/// Záznam pominuteľného blobu (B7/MYHSN-9, D-33). Sám súbor žije na disku
/// mimo append-only logu; tu sú len metadáta pre kvótu a expiráciu. `id` je
/// hex 32 náhodných bajtov, `hash` je BLAKE3 obsahu (integrity).
/// B8/MYHSN-22: `class` rozlišuje pominuteľný (0) / avatar (1) / obálku (2)
/// — kvota a lazy cleanup sa týkajú **len** triedy 0; trvalé bloby majú
/// `expires_at = i64::MAX`. `mime` je skutočný typ pre `GET /media/{id}`
/// (NULL = staré riadky → octet-stream).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaRow {
    pub id: String,
    pub account_id: [u8; 32],
    pub size: i64,
    pub hash: [u8; 32],
    pub created_at: i64,
    pub expires_at: i64,
    pub class: i64,
    pub mime: Option<String>,
}

impl From<SqliteError> for StoreError {
    fn from(e: SqliteError) -> Self {
        StoreError::Sql(e)
    }
}

/// Je to constraint violation? (Rozlíšime idempotentný append od skutočnej
/// kolízie pozície dotazom na hash, takže nepotrebujeme extended code.)
fn is_constraint_violation(e: &SqliteError) -> bool {
    matches!(
        e,
        SqliteError::SqliteFailure(err, _)
            if err.code == rusqlite::ffi::ErrorCode::ConstraintViolation
    )
}

/// SQLite úloža: log záznamov + KV meta + kanály + alokátor poradia.
pub struct Store {
    conn: Connection,
    /// Cache operačného seedu uzla (B5): 32 B, generované pri prvom
    /// použití a perzistentné v `meta`. Verejná časť je `node_id`
    /// a podpisuje ňou uzol pečiatky (D-27 — správa root kľúča a
    /// rotácia patria admin vrstve, tu je len operačný kľúč).
    node_seed_cache: Option<[u8; 32]>,
}

impl Store {
    /// Otvor (alebo vytvor) databázu v `path`, nastav WAL a aplikuj migrácie.
    pub fn open(path: &Path) -> Result<Store, StoreError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(StoreError::Io)?;
            }
        }
        let conn = Connection::open(path)?;
        Self::from_connection(conn)
    }

    /// In-memory databáza — testy a dočasné stavy.
    pub fn open_in_memory() -> Result<Store, StoreError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    /// Otvor existujúce spojenie (testy, znovupoužitie).
    pub fn from_connection(conn: Connection) -> Result<Store, StoreError> {
        // WAL: čítanie sa neblokuje so zápisom; pre uzol s WS sync (B5)
        // je to požadovaný režim.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let store = Store {
            conn,
            node_seed_cache: None,
        };
        store.migrate()?;
        Ok(store)
    }

    /// Aplikuj chýbajúce migrácie. Verzia je v `PRAGMA user_version`,
    /// teda v rovnakom súbore ako dáta — žiadny externý súbor.
    fn migrate(&self) -> Result<(), StoreError> {
        let found: i64 = self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if found > SCHEMA_VERSION {
            // **F14c:** aditívne migrácie môžu explícite povoliť otvorenie
            // novšej schémy staršou binárkou — meta kľúč `schema_compat`
            // hovorí, ktorej najnižšej binárke schéma neprekáža. Bez neho
            // (alebo s compat > našej verzie) je to fatálne: F14a binárka
            // guard bez compat mechanizmu nemá a rollback sa robí obnovou
            // `.pre-v6` zálohy, ktorú vytvorila migrácia V6.
            let compat: Option<i64> = self
                .conn
                .query_row(
                    "SELECT value FROM meta WHERE key = ?1",
                    params![META_SCHEMA_COMPAT],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .ok()
                .and_then(|v| String::from_utf8(v).ok())
                .and_then(|s| s.trim().parse().ok());
            if compat.map(|c| c <= SCHEMA_VERSION) == Some(true) {
                tracing::warn!(
                    found,
                    supported = SCHEMA_VERSION,
                    compat = compat.unwrap_or(0),
                    "schéma je novšia, ale schema_compat ju povoľuje (aditívne zmeny)"
                );
                return Ok(());
            }
            return Err(StoreError::SchemaTooNew {
                found,
                supported: SCHEMA_VERSION,
            });
        }
        if found == SCHEMA_VERSION {
            return Ok(());
        }

        // **F14c:** súbory DB pred migráciou na 6 zálohujeme `VACUUM INTO`
        // (jeden konzistentný snapshot aj pri WAL). Bez cesty k súboru
        // (:memory:, testy) sa záloha preskočí. Zlyhanie zálohy = migrácia
        // nespadne — bez zálohy sa uzol zdvihnúť nesmie (rollback inak
        // nie je možný).
        if found < 6 && found > 0 {
            self.backup_before_v6()?;
        }

        // migrácie 0 → 1 → … → 6 v jednej transakcii (expand/contract, D-22:
        // stará binárka zvládne súbory s novšou schémou čítať, len nie
        // nové tabuľky písať)
        let tx = self.conn.unchecked_transaction()?;
        if found < 1 {
            tx.execute_batch(MIGRATE_V1)?;
        }
        if found < 2 {
            tx.execute_batch(MIGRATE_V2)?;
        }
        if found < 3 {
            tx.execute_batch(MIGRATE_V3)?;
        }
        if found < 4 {
            tx.execute_batch(MIGRATE_V4)?;
        }
        if found < 5 {
            tx.execute_batch(MIGRATE_V5)?;
        }
        if found < 6 {
            tx.execute_batch(MIGRATE_V6)?;
            // F14c: kto najmladší musí túto DB otvoriť, aby jej rozumel
            // (schema_compat mechanizmus — V6 vyžaduje binárku ≥ 6).
            Self::meta_set_in(&tx, META_SCHEMA_COMPAT, b"6")?;
        }
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tx.commit()?;
        tracing::info!(version = SCHEMA_VERSION, "schéma úložne vytvorená/migrovaná");
        Ok(())
    }

    /// Cesta k hlavnému súboru DB, alebo `None` (`:memory:`).
    fn db_file_path(&self) -> Result<Option<std::path::PathBuf>, StoreError> {
        let file: String = self
            .conn
            .query_row("PRAGMA database_list", [], |row| row.get::<_, String>(2))
            .unwrap_or_default();
        Ok(if file.is_empty() {
            None
        } else {
            Some(std::path::PathBuf::from(file))
        })
    }

    /// `VACUUM INTO '<db>.pre-v6.<ts>.bak'` — povinná pred V6 (rollback
    /// binárky F14a bez obnovy dát nie je možný, guard `SchemaTooNew` je
    /// v jeho kóde natvrdo). Existujúca záloha sa neprepisuje: pri
    /// opätovnom štarte po polovičkej migrácii stačí tá prvá.
    fn backup_before_v6(&self) -> Result<(), StoreError> {
        let path = match self.db_file_path()? {
            Some(p) => p,
            None => return Ok(()),
        };
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let dest = format!("{}.pre-v6.{}.bak", path.display(), ts);
        // VACUUM INTO cieľ musí existovať až teraz; single-quote escape
        // (cesta s apostrofom je exotická, ale správna).
        let escaped = dest.replace('\'', "''");
        self.conn
            .execute_batch(&format!("VACUUM INTO '{escaped}'"))?;
        tracing::info!(backup = %dest, "záloha pred migráciou V6 vytvorená");
        Ok(())
    }

    /// Aktuálna verzia schémy v súbore.
    pub fn schema_version(&self) -> Result<i64, StoreError> {
        Ok(self.conn.query_row("PRAGMA user_version", [], |row| row.get(0))?)
    }

    /// Režim žurnálu (test, že WAL naozaj beží — na :memory: SQLite vráti
    /// „memory“, preto sa test robí na súbore).
    pub fn journal_mode(&self) -> Result<String, StoreError> {
        Ok(self
            .conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))?)
    }

    // --- kľúč a ID uzla (B4/B5, D-27) -----------------------------------

    /// **Operačný kľúč uzla** (D-27): seed 32 B z OS RNG, perzistentný v
    /// `meta` pod kľúčom `node_key_seed`. Uzol ním podpisuje sekvenčné
    /// pečiatky záznamov.
    ///
    /// D-27 počíta s root kľúčom offline, ktorý tento operačný kľúč
    /// podpisuje (QR pinuje root). Root key management je úloha admin
    /// vrstvy (C fáza) — kým neexistuje, `node_id` je **verejná časť
    /// tohto operačného kľúča**: dočasná, ale stabilná a už dnes
    /// overiteľná (pečiatky v obálkach sedia k `signed_by_node`).
    pub fn node_sign_seed(&mut self) -> Result<[u8; 32], StoreError> {
        if let Some(seed) = self.node_seed_cache {
            return Ok(seed);
        }
        let stored = self.meta_get(b"node_key_seed")?;
        let seed = match stored {
            Some(raw) if raw.len() == 32 => {
                let mut s = [0u8; 32];
                s.copy_from_slice(&raw);
                s
            }
            _ => {
                let s = crate::auth::random_32();
                self.meta_set(b"node_key_seed", s.as_slice())?;
                tracing::info!("operačný kľúč uzla vygenerovaný (D-27, root správa neskôr)");
                s
            }
        };
        self.node_seed_cache = Some(seed);
        Ok(seed)
    }

    /// Verejná časť operačného kľúča uzla.
    pub fn node_pub(&mut self) -> Result<NodeId, StoreError> {
        let seed = self.node_sign_seed()?;
        Ok(myhsn_core::identity::public_from_seed(&seed))
    }

    /// Stabilné ID uzla = verejný kľúč, ktorým uzol pečiatkuje (D-27).
    ///
    /// B3 mal dočasné náhodné ID; od B4/B5 sa odvodzuje od operačného
    /// kľúča, aby `signed_by_node` v obálkach sedelo s kľúčom pečiatok.
    /// Pri upgrade sa hodnota raz zmení (súbory z B3 nemali členov ani
    /// dôležité dáta) — `meta` pole `node_id` držíme synchronizované
    /// pre `GET /node/info`.
    pub fn node_id(&mut self) -> Result<NodeId, StoreError> {
        let id = self.node_pub()?;
        let stale = self.meta_get(b"node_id")?;
        if stale.as_deref() != Some(id.as_slice()) {
            self.meta_set(b"node_id", id.as_slice())?;
        }
        Ok(id)
    }

    // --- kanály a poradie (B3) -----------------------------------------

    /// Vytvor kanál. ID aj soľ sa generujú deterministicky z počítadla
    /// (unikátnosť garantuje počítadlo + UNIQUE na názov); kryptografickú
    /// soľ dodá B4/B5 spolu s kľúčmi uzla.
    pub fn create_channel(&mut self, name: &str, kind: ChannelKind) -> Result<Channel, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let ch = Self::create_channel_in(&tx, name, kind, None)?;
        tx.commit()?;
        Ok(ch)
    }

    /// **F14c (MYHSN-58):** vytvor **skupinový** kanál — to isté čo
    /// `create_channel`, ale `channels.owner` je nastavený na zakladateľa
    /// a v novom kanáli hneď pribudne auditný záznam `CreateChannel`
    /// (kind 8) ako **seq 1**: história členstva patrí ku kanálu a
    /// replikuje sa s ním (rozhodnutie F14c). Všetko v jednej transakcii —
    /// kanál bez auditu ani audit bez kanála nevznikne.
    pub fn create_group_channel(
        &mut self,
        name: &str,
        kind: ChannelKind,
        owner: &[u8; 32],
        owner_name: &str,
        by: ([u8; 32], [u8; 32]),
    ) -> Result<(Channel, Envelope), ChannelError> {
        let tx = self.conn.unchecked_transaction()?;
        let ch = Self::create_channel_in(&tx, name, kind, Some(owner))?;
        let (by_acc, by_dev) = by;
        let payload = Payload::CreateChannel {
            channel: ch.id,
            name: ch.name.clone(),
            kind: kind.code(),
            owner: *owner,
            owner_name: owner_name.to_string(),
            by: by_acc,
            by_device: by_dev,
        };
        let env = Self::append_node_record_in(&tx, &ch.id, &payload)?;
        tx.commit()?;
        Ok((ch, env))
    }

    /// Spoločné telo tvorby kanála (počítadlo, id, soľ, INSERT). `owner`
    /// `Some` = skupinový kanál (F14c), `None` = legacy/verejný — presne
    /// ako pred F14c, vrátane generovania id/solice.
    fn create_channel_in(
        tx: &rusqlite::Transaction<'_>,
        name: &str,
        kind: ChannelKind,
        owner: Option<&[u8; 32]>,
    ) -> Result<Channel, StoreError> {
        let name = name.trim().to_string();
        if name.is_empty() {
            return Err(StoreError::ChannelNameTaken(name));
        }
        let counter: i64 = {
            let raw = Self::meta_get_in(tx, b"channel_counter")?;
            let next = raw.map(|v| i64::from_le_bytes(v.try_into().unwrap_or([0; 8]))).unwrap_or(0) + 1;
            Self::meta_set_in(tx, b"channel_counter", &next.to_le_bytes())?;
            next
        };
        let mut pre = b"myhsn:channel:v1:".to_vec();
        pre.extend_from_slice(name.as_bytes());
        pre.extend_from_slice(&counter.to_le_bytes());
        let id: ChannelId = *blake3::hash(&pre).as_bytes();

        let mut salt_pre = b"myhsn:salt:v1:".to_vec();
        salt_pre.extend_from_slice(&id);
        salt_pre.extend_from_slice(&counter.to_le_bytes());
        let salt: [u8; 32] = *blake3::hash(&salt_pre).as_bytes();

        if let Err(e) = tx.execute(
            "INSERT INTO channels (id, name, kind, salt, node_epoch, owner) \
             VALUES (?1, ?2, ?3, ?4, 0, ?5)",
            params![
                id.as_slice(),
                name,
                kind.code() as i64,
                salt.as_slice(),
                owner.map(|o| o.as_slice()),
            ],
        ) {
            // UNIQUE(name): názov kanála je v uzle jedinečný — kvôli UX aj
            // preto, že klient kanály pozná podľa názvu
            if is_constraint_violation(&e) {
                return Err(StoreError::ChannelNameTaken(name));
            }
            return Err(StoreError::Sql(e));
        }
        Ok(Channel {
            id,
            name,
            kind,
            salt,
            node_epoch: 0,
        })
    }

    /// Zoznam kanálov zoradený podľa názvu (pre `GET /channels`).
    pub fn list_channels(&self) -> Result<Vec<Channel>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name, kind, salt, node_epoch FROM channels ORDER BY name")?;
        let rows = stmt.query_map([], |row| {
            let id_raw: Vec<u8> = row.get(0)?;
            let kind_code: i64 = row.get(2)?;
            let salt_raw: Vec<u8> = row.get(3)?;
            Ok((id_raw, row.get::<_, String>(1)?, kind_code, salt_raw, row.get::<_, i64>(4)?))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (id_raw, name, kind_code, salt_raw, epoch) = r?;
            let kind = ChannelKind::from_code(u8::try_from(kind_code).unwrap_or(255))
                .ok_or(StoreError::BadChannelKind(kind_code))?;
            out.push(Channel {
                id: arr32(&id_raw),
                name,
                kind,
                salt: arr32(&salt_raw),
                node_epoch: epoch as u64,
            });
        }
        Ok(out)
    }

    /// Kanál podľa ID.
    pub fn get_channel(&self, id: &ChannelId) -> Result<Option<Channel>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT name, kind, salt, node_epoch FROM channels WHERE id = ?1")?;
        let mut rows = stmt.query_map(params![id.as_slice()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        match rows.next() {
            None => Ok(None),
            Some(r) => {
                let (name, kind_code, salt_raw, epoch) = r?;
                let kind = ChannelKind::from_code(u8::try_from(kind_code).unwrap_or(255))
                    .ok_or(StoreError::BadChannelKind(kind_code))?;
                Ok(Some(Channel {
                    id: *id,
                    name,
                    kind,
                    salt: arr32(&salt_raw),
                    node_epoch: epoch as u64,
                }))
            }
        }
    }

    // --- F14c (MYHSN-58): skupinové kanály, členstvo, právomoci ----------

    /// `owner` kanála. `None` = kanál neexistuje; `Some(None)` = **legacy**
    /// kanál (`owner IS NULL` — žiadny membership model, správanie presne
    /// ako pred F14c); `Some(Some(owner))` = skupinový kanál.
    pub fn channel_owner(&self, id: &ChannelId) -> Result<ChannelOwnerState, StoreError> {
        // `query_row` bez riadku = kanál neexistuje (chybu netlmočíme),
        // `NULL` v stĺpci = legacy kanál. Vnorený Option teda nie je len
        // lenivosť — práve ono odlišuje „nie je kanál“ od „kanál bez ownera“.
        Ok(self
            .conn
            .query_row(
                "SELECT owner FROM channels WHERE id = ?1",
                params![id.as_slice()],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .ok()
            .map(|owner| owner.as_deref().map(arr32)))
    }

    /// `channel_id → owner` pre **všetky** kanály (F14c). Druhý `Option` má
    /// rovnaký význam ako v [`Store::channel_owner`].
    pub fn channel_owners(&self) -> Result<Vec<(ChannelId, ChannelOwnerState)>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT id, owner FROM channels")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (id, owner) = r?;
            out.push((arr32(&id), Some(owner.as_deref().map(arr32))));
        }
        Ok(out)
    }

    /// Členovia group kanála (**bez ownera** — ten nie je riadok tabuľky,
    /// rozhodnutie F14c §1), abecedne podľa mena.
    pub fn channel_members(&self, channel: &ChannelId) -> Result<Vec<ChannelMemberRow>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT m.account, a.username, m.role, m.added_by, m.joined_at, m.muted_until \
             FROM channel_members m JOIN accounts a ON a.id = m.account \
             WHERE m.channel = ?1 ORDER BY a.username",
        )?;
        let rows = stmt.query_map(params![channel.as_slice()], |row| {
            Ok(ChannelMemberRow {
                account: arr32(&row.get::<_, Vec<u8>>(0)?),
                username: row.get(1)?,
                role: row.get::<_, i64>(2)? as u8,
                added_by: row.get::<_, Option<Vec<u8>>>(3)?.as_deref().map(arr32),
                joined_at: row.get::<_, i64>(4)? as u64,
                muted_until: row.get::<_, Option<i64>>(5)?.map(|v| v as u64),
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// **F14c:** efektívna právomoc účtu v kanáli — zdroj pre REST gating,
    /// WS gating aj pravidlá mazania cudzích príspevkov (`deletion.rs`).
    /// `None` = kanál neexistuje.
    pub fn channel_authority(
        &self,
        channel: &ChannelId,
        account: &[u8; 32],
    ) -> Result<Option<ChannelAuthority>, StoreError> {
        let owner = match self.channel_owner(channel)? {
            None => return Ok(None),
            Some(owner) => owner,
        };
        let (server_role, server_perms) = self
            .account_role(account)?
            .map(|(role, perms, _status)| (role, perms))
            .unwrap_or((0, 0));
        let member = self
            .conn
            .query_row(
                "SELECT role, muted_until FROM channel_members \
                 WHERE channel = ?1 AND account = ?2",
                params![channel.as_slice(), account.as_slice()],
                |row| Ok((row.get::<_, i64>(0)? as u8, row.get::<_, Option<i64>>(1)?)),
            )
            .ok();
        let (role, muted_until) = match member {
            Some((role, muted)) => (Some(role), muted.map(|v| v as u64)),
            None => (None, None),
        };
        // owner NIE je riadok v `channel_members` — efektívnu rolu mu
        // dosadíme z `channels.owner` (rozhodnutie F14c §1)
        let role = if owner == Some(*account) { Some(2) } else { role };
        Ok(Some(ChannelAuthority {
            group: owner.is_some(),
            owner,
            role,
            muted_until,
            server_role,
            server_perms,
        }))
    }

    /// Všetky group kanály, v ktorých má účet efektívnu rolu (owner, admin
    /// alebo member), zoradené **podľa bajtov kanála** — zdroj 5. prvku
    /// `HelloAck` (rozhodnutie F14c §5). Položka je `(channel, role_code,
    /// muted)`.
    pub fn channel_roles_for_account(
        &self,
        account: &[u8; 32],
        now: u64,
    ) -> Result<Vec<([u8; 32], u8, bool)>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT c.id, c.owner, m.role, m.muted_until FROM channels c \
             LEFT JOIN channel_members m ON m.channel = c.id AND m.account = ?1 \
             WHERE c.owner IS NOT NULL AND (c.owner = ?1 OR m.account IS NOT NULL) \
             ORDER BY c.id",
        )?;
        let rows = stmt.query_map(params![account.as_slice()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, Option<i64>>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (id, owner, role, muted) = r?;
            let id = arr32(&id);
            let is_owner = arr32(&owner) == *account;
            let code: u8 = if is_owner { 2 } else { role.unwrap_or(0) as u8 };
            // owner sa stíšiť nedá (rozhodnutie F14c §7), preto `muted` len
            // pre členov; hranica je **neostrá** — `now` už stíšenie ukončilo
            let muted = !is_owner && muted.map(|t| (t as u64) > now).unwrap_or(false);
            out.push((id, code, muted));
        }
        // `ORDER BY c.id` je poradie vytvorenia (rowid), NIE bajty kanála.
        // 5. prvok `HelloAck` ide na drôt, takže poradie musí byť
        // deterministické medzi uzlami — triedime podľa bajtov id.
        out.sort_by_key(|(id, _, _)| *id);
        Ok(out)
    }

    /// Skontroluj, že kanál existuje a je **group**; vráti jeho ownera.
    /// `NoSuchChannel` / `NotGroupChannel` podľa rozhodnutia F14c §10.
    fn require_group_in(
        tx: &rusqlite::Transaction<'_>,
        channel: &ChannelId,
    ) -> Result<[u8; 32], ChannelError> {
        match tx.query_row(
            "SELECT owner FROM channels WHERE id = ?1",
            params![channel.as_slice()],
            |row| row.get::<_, Option<Vec<u8>>>(0),
        ) {
            Err(_) => Err(ChannelError::NoSuchChannel),
            Ok(None) => Err(ChannelError::NotGroupChannel),
            Ok(Some(raw)) => Ok(arr32(&raw)),
        }
    }

    /// `(username, status)` účtu v otvorenej transakcii; `NoSuchAccount` ak
    /// neexistuje. `status` vracia aj pre neaktívne účty (F14c §15:
    /// deaktivácia ** nemaže** členstvo).
    fn account_row_in(
        tx: &rusqlite::Transaction<'_>,
        account: &[u8; 32],
    ) -> Result<(String, u8), ChannelError> {
        tx.query_row(
            "SELECT username, status FROM accounts WHERE id = ?1",
            params![account.as_slice()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u8)),
        )
        .map_err(|_| ChannelError::NoSuchAccount)
    }

    /// Meno **aktívneho** účtu (`status = 0`); inak `NoSuchAccount` /
    /// `AccountInactive` (rozhodnutie F14c §10).
    fn active_account_in(
        tx: &rusqlite::Transaction<'_>,
        account: &[u8; 32],
    ) -> Result<String, ChannelError> {
        match Self::account_row_in(tx, account)? {
            (name, 0) => Ok(name),
            (_, _) => Err(ChannelError::AccountInactive),
        }
    }

    /// **F14c:** pridaj **membera** do group kanála — audit
    /// `GrantChannelRole` (kind 9, rola `member`) a INSERT do
    /// `channel_members` v JEDNEJ transakcii (rozhodnutie F14c §1:
    /// materializovaný stav + audit spolu). Vráti opečiatkovaný audit,
    /// ktorý volajúci pushne PO commite (vzor `apply_role_change`, O8).
    pub fn channel_add_member(
        &mut self,
        channel: &ChannelId,
        target: &[u8; 32],
        by: ([u8; 32], [u8; 32]),
    ) -> Result<Envelope, ChannelError> {
        let tx = self.conn.unchecked_transaction()?;
        let owner = Self::require_group_in(&tx, channel)?;
        let username = Self::active_account_in(&tx, target)?;
        // owner už v kanáli JE (len nie ako riadok) — pridať ho je 409
        if owner == *target {
            return Err(ChannelError::AlreadyMember);
        }
        let exists: i64 = tx.query_row(
            "SELECT COUNT(1) FROM channel_members WHERE channel = ?1 AND account = ?2",
            params![channel.as_slice(), target.as_slice()],
            |r| r.get(0),
        )?;
        if exists > 0 {
            return Err(ChannelError::AlreadyMember);
        }
        tx.execute(
            "INSERT INTO channel_members (channel, account, role, added_by, joined_at) \
             VALUES (?1, ?2, 0, ?3, ?4)",
            params![
                channel.as_slice(),
                target.as_slice(),
                by.0.as_slice(),
                Self::now_secs() as i64
            ],
        )?;
        let env = Self::append_node_record_in(
            &tx,
            channel,
            &Payload::GrantChannelRole {
                channel: *channel,
                target: *target,
                target_name: username,
                channel_role: 0,
                by: by.0,
                by_device: by.1,
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// **F14c:** zmeň per-kanálovú rolu člena (`member` ↔ `admin`) — audit
    /// kind 9 s novou rolou + UPDATE v jednej transakcii. Ownera týmto
    /// meniť nemožno (REST mapuje `owner` na 400 `use_transfer`), preto
    /// `role` je len 0/1.
    pub fn channel_set_role(
        &mut self,
        channel: &ChannelId,
        target: &[u8; 32],
        role: u8,
        by: ([u8; 32], [u8; 32]),
    ) -> Result<Envelope, ChannelError> {
        if !matches!(role, 0 | 1) {
            return Err(ChannelError::InvalidRole);
        }
        let tx = self.conn.unchecked_transaction()?;
        Self::require_group_in(&tx, channel)?;
        let (username, _status) = Self::account_row_in(&tx, target)?;
        let updated = tx.execute(
            "UPDATE channel_members SET role = ?3 WHERE channel = ?1 AND account = ?2",
            params![channel.as_slice(), target.as_slice(), role as i64],
        )?;
        if updated == 0 {
            return Err(ChannelError::NotMember);
        }
        let env = Self::append_node_record_in(
            &tx,
            channel,
            &Payload::GrantChannelRole {
                channel: *channel,
                target: *target,
                target_name: username,
                channel_role: role,
                by: by.0,
                by_device: by.1,
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// **F14c:** odober členstvo (member/admin) — audit kind 10 + DELETE v
    /// jednej transakcii. Owner sa odobrať nedá (`OwnerCannotBeRemoved` →
    /// 409 `owner_must_transfer`), kanál tak má vždy ownera.
    pub fn channel_revoke_member(
        &mut self,
        channel: &ChannelId,
        target: &[u8; 32],
        by: ([u8; 32], [u8; 32]),
    ) -> Result<Envelope, ChannelError> {
        let tx = self.conn.unchecked_transaction()?;
        let owner = Self::require_group_in(&tx, channel)?;
        if owner == *target {
            return Err(ChannelError::OwnerCannotBeRemoved);
        }
        let (username, _status) = Self::account_row_in(&tx, target)?;
        let deleted = tx.execute(
            "DELETE FROM channel_members WHERE channel = ?1 AND account = ?2",
            params![channel.as_slice(), target.as_slice()],
        )?;
        if deleted == 0 {
            return Err(ChannelError::NotMember);
        }
        let env = Self::append_node_record_in(
            &tx,
            channel,
            &Payload::RevokeChannelRole {
                channel: *channel,
                target: *target,
                target_name: username,
                by: by.0,
                by_device: by.1,
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// **F14c:** prenechanie ownera (rozhodnutie §8) — **jeden** audit kind
    /// 11, `UPDATE channels.owner`, úprava radu pôvodného ownera podľa
    /// `prev_role` (255 = odchod z kanála) a odobranie radu nového ownera
    /// (owner nie je riadok) — všetko v jednej transakcii, takže kanál
    /// nemá okamih bez ownera ani dvoch ownerov.
    ///
    /// `to` musí byť aktívny účet; ak ešte nie je člen, transfer ho pridá
    /// (stane sa ownerom, teda riadok nemá). Transfer na súčasného ownera
    /// je `AlreadyOwner` (409 `already_owner`).
    pub fn channel_transfer_owner(
        &mut self,
        channel: &ChannelId,
        to: &[u8; 32],
        prev_role: u8,
        by: ([u8; 32], [u8; 32]),
    ) -> Result<Envelope, ChannelError> {
        if !(matches!(prev_role, 0 | 1) || prev_role == u8::MAX) {
            return Err(ChannelError::InvalidRole);
        }
        let tx = self.conn.unchecked_transaction()?;
        let from = Self::require_group_in(&tx, channel)?;
        if from == *to {
            return Err(ChannelError::AlreadyOwner);
        }
        let to_name = Self::active_account_in(&tx, to)?;
        let (from_name, _status) = Self::account_row_in(&tx, &from)?;
        let now = Self::now_secs() as i64;

        tx.execute(
            "UPDATE channels SET owner = ?2 WHERE id = ?1",
            params![channel.as_slice(), to.as_slice()],
        )?;
        // nový owner nesmie ostať member/admin riadok — owner plynie zo
        // `channels.owner` a práve jeden owner je štrukturálne
        tx.execute(
            "DELETE FROM channel_members WHERE channel = ?1 AND account = ?2",
            params![channel.as_slice(), to.as_slice()],
        )?;
        if prev_role == u8::MAX {
            tx.execute(
                "DELETE FROM channel_members WHERE channel = ?1 AND account = ?2",
                params![channel.as_slice(), from.as_slice()],
            )?;
        } else {
            tx.execute(
                "INSERT INTO channel_members (channel, account, role, added_by, joined_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT (channel, account) DO UPDATE SET role = excluded.role",
                params![
                    channel.as_slice(),
                    from.as_slice(),
                    prev_role as i64,
                    by.0.as_slice(),
                    now
                ],
            )?;
        }
        let env = Self::append_node_record_in(
            &tx,
            channel,
            &Payload::TransferChannelOwner {
                channel: *channel,
                from,
                from_name,
                to: *to,
                to_name,
                prev_role,
                by: by.0,
                by_device: by.1,
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// **F14c:** stíšenie člena (rozhodnutie §7) — **materializovaný** stav
    /// bez auditu (vzor cover; kind 12 je v core rezervovaný pre budúci
    /// `SetChannelMute`). `until` je unix sekunda, kedy stíšenie skončí.
    pub fn channel_set_mute(
        &mut self,
        channel: &ChannelId,
        target: &[u8; 32],
        until: u64,
    ) -> Result<(), ChannelError> {
        let tx = self.conn.unchecked_transaction()?;
        let owner = Self::require_group_in(&tx, channel)?;
        if owner == *target {
            return Err(ChannelError::OwnerNotMutable);
        }
        let updated = tx.execute(
            "UPDATE channel_members SET muted_until = ?3 WHERE channel = ?1 AND account = ?2",
            params![channel.as_slice(), target.as_slice(), until as i64],
        )?;
        if updated == 0 {
            return Err(ChannelError::NotMember);
        }
        tx.commit()?;
        Ok(())
    }

    /// **F14c:** zruš stíšenie; `NotMuted` (= 404 `not_muted`) ak účet
    /// stíšený nie je.
    pub fn channel_clear_mute(
        &mut self,
        channel: &ChannelId,
        target: &[u8; 32],
    ) -> Result<(), ChannelError> {
        let tx = self.conn.unchecked_transaction()?;
        Self::require_group_in(&tx, channel)?;
        let cleared = tx.execute(
            "UPDATE channel_members SET muted_until = NULL \
             WHERE channel = ?1 AND account = ?2 AND muted_until IS NOT NULL",
            params![channel.as_slice(), target.as_slice()],
        )?;
        if cleared == 0 {
            let member: i64 = tx.query_row(
                "SELECT COUNT(1) FROM channel_members WHERE channel = ?1 AND account = ?2",
                params![channel.as_slice(), target.as_slice()],
                |r| r.get(0),
            )?;
            return Err(if member == 0 {
                ChannelError::NotMember
            } else {
                ChannelError::NotMuted
            });
        }
        tx.commit()?;
        Ok(())
    }

    /// **Repair pomôcka (F14c):** postav obsah `channel_members` znova len
    /// z **append-only logu** (audity kind 8 – 11). Slúži na dôkaz, že
    /// materializovaný stav je skutočne derivátom logu (test
    /// `rebuild_members_from_log`), a na budúcu opravu po kalamite.
    ///
    /// `muted_until` z logu **nevystopovateľné** — stíšenie je
    /// materializovaný stav bez auditu (kind 12 rezervovaný), preto rebuild
    /// stíšenie zruší. To je zdokumentovaná vlastnosť, nie chyba.
    pub fn rebuild_channel_members_from_log(&mut self) -> Result<usize, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute_batch("DELETE FROM channel_members;")?;
        // kanály po poradí ich bajtov — deterministický rebuild
        let channels: Vec<Vec<u8>> = {
            let mut stmt = tx.prepare(
                "SELECT id FROM channels WHERE owner IS NOT NULL ORDER BY id",
            )?;
            let rows = stmt
                .query_map([], |row| row.get::<_, Vec<u8>>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };
        let mut rows_written = 0usize;
        for ch_raw in channels {
            let raws: Vec<Vec<u8>> = {
                let mut stmt = tx.prepare(
                    "SELECT raw FROM records WHERE channel = ?1 \
                     AND kind BETWEEN 8 AND 11 ORDER BY node_epoch, node_seq",
                )?;
                let rows = stmt
                    .query_map(params![ch_raw.as_slice()], |row| row.get::<_, Vec<u8>>(0))?
                    .collect::<Result<Vec<_>, _>>()?;
                rows
            };
            // vlastný stav replayu — žiadny UPDATE mimo tejto transakcie
            let mut owner: Option<[u8; 32]> = None;
            let mut members: std::collections::BTreeMap<[u8; 32], u8> = Default::default();
            for raw in raws {
                let env = match Envelope::decode(&raw) {
                    Ok(env) => env,
                    Err(_) => continue,
                };
                match env.payload() {
                    Ok(Payload::CreateChannel { owner: o, .. }) => {
                        owner = Some(o);
                    }
                    Ok(Payload::GrantChannelRole { target, channel_role, .. }) => {
                        // owner sa grantom nemení (kód 2 v audite nepatrí)
                        if Some(target) == owner || !matches!(channel_role, 0 | 1) {
                            continue;
                        }
                        members.insert(target, channel_role);
                    }
                    Ok(Payload::RevokeChannelRole { target, .. }) => {
                        members.remove(&target);
                    }
                    Ok(Payload::TransferChannelOwner { from, to, prev_role, .. }) => {
                        members.remove(&to);
                        owner = Some(to);
                        if prev_role == u8::MAX {
                            members.remove(&from);
                        } else if matches!(prev_role, 0 | 1) {
                            members.insert(from, prev_role);
                        }
                    }
                    _ => {}
                }
            }
            if let Some(o) = owner {
                tx.execute(
                    "UPDATE channels SET owner = ?2 WHERE id = ?1",
                    params![ch_raw.as_slice(), o.as_slice()],
                )?;
            }
            for (account, role) in members {
                tx.execute(
                    "INSERT INTO channel_members (channel, account, role, added_by, joined_at) \
                     VALUES (?1, ?2, ?3, NULL, 0) ON CONFLICT (channel, account) DO UPDATE \
                     SET role = excluded.role",
                    params![ch_raw.as_slice(), account.as_slice(), role as i64],
                )?;
                rows_written += 1;
            }
        }
        tx.commit()?;
        Ok(rows_written)
    }

    /// Unix sekundy (joined_at / muted_until). Držíme tu, nie v `api`,
    /// lebo úložňa potrebuje čas priamo pri INSERT-e.
    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// **Alokuj ďalšie `node_seq` v kanáli** (D-25).
    ///
    /// Jedným SQL príkazom `INSERT … ON CONFLICT DO UPDATE … RETURNING` —
    /// to je atómový inkrement, žiadne prečítaj-zmeň-zapíš okno, v ktorom
    /// by sa dva zápisy dostali na rovnaké poradie. Nová epocha ešte nemá
    /// riadok v `seq_counters`, preto začína na 1.
    pub fn alloc_seq(&mut self, channel: &ChannelId) -> Result<SeqPos, StoreError> {
        let epoch = self.channel_epoch(channel)?;
        self.alloc_seq_in_epoch(channel, epoch)
    }

    /// Alokácia v konkrétnej epoche (voliteľné; `alloc_seq` používa
    /// aktuálnu epochu kanála).
    pub fn alloc_seq_in_epoch(
        &mut self,
        channel: &ChannelId,
        node_epoch: u64,
    ) -> Result<SeqPos, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        // istota, že kanál existuje (inak by poradie viselo nad ničím)
        let exists: i64 = tx.query_row(
            "SELECT COUNT(1) FROM channels WHERE id = ?1",
            params![channel.as_slice()],
            |row| row.get(0),
        )?;
        if exists == 0 {
            return Err(StoreError::NoSuchChannel(*channel));
        }
        let seq: i64 = tx.query_row(
            "INSERT INTO seq_counters (channel, node_epoch, last_seq) VALUES (?1, ?2, 1) \
             ON CONFLICT (channel, node_epoch) DO UPDATE SET last_seq = last_seq + 1 \
             RETURNING last_seq",
            params![channel.as_slice(), node_epoch as i64],
            |row| row.get(0),
        )?;
        tx.commit()?;
        Ok(SeqPos::new(*channel, node_epoch, seq as u64))
    }

    /// Aktuálna epocha kanála.
    pub fn channel_epoch(&self, channel: &ChannelId) -> Result<u64, StoreError> {
        self.get_channel(channel)?
            .map(|c| c.node_epoch)
            .ok_or(StoreError::NoSuchChannel(*channel))
    }

    /// Ďalšie poradie, ktoré alokátor vydá (bez alokácie) — pre
    /// `GET /node/info`. Počíta sa z posledného prideleného (0 = nič).
    pub fn peek_next_seq(&self, channel: &ChannelId, node_epoch: u64) -> Result<u64, StoreError> {
        let last: Option<i64> = self.conn.query_row(
            "SELECT last_seq FROM seq_counters WHERE channel = ?1 AND node_epoch = ?2",
            params![channel.as_slice(), node_epoch as i64],
            |row| row.get(0),
        ).ok();
        Ok(last.unwrap_or(0) as u64 + 1)
    }

    /// **D-25: obnova zo zálohy → nová epocha.**
    ///
    /// Posunie `node_epoch` všetkých kanálov o 1. Záznamy sa **nemažú** —
    /// ostávajú so starou epochou, takže sa nič nestratí a kolízia
    /// `(channel, node_epoch, node_seq)` je vylúčená. Alokátory poradia sa
    /// netvoria pre nové epochy, takže `node_seq` v novej epoche začína od
    /// 1 (kritérium B3b).
    ///
    /// Vráti nové epochy jednotlivých kanálov.
    pub fn restore_new_epoch(&mut self) -> Result<Vec<(ChannelId, u64)>, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute_batch("UPDATE channels SET node_epoch = node_epoch + 1;")?;
        // statement musí zomrieť pred commitom (požičiava si od tx)
        let rows = {
            let mut stmt = tx.prepare("SELECT id, node_epoch FROM channels ORDER BY name")?;
            let rows = stmt
                .query_map([], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };
        tx.commit()?;
        Ok(rows.into_iter().map(|(id, e)| (arr32(&id), e as u64)).collect())
    }

    /// Počet záznamov v logu (diagnostika, testy).
    pub fn record_count(&self) -> Result<u64, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(1) FROM records", [], |row| row.get::<_, i64>(0))?
            as u64)
    }

    /// Pohľad na log kanála ako `(pozícia, hash)` — vstup pre
    /// [`myhsn_core::channel::reconcile`] (B3c).
    pub fn channel_hashes(&self, channel: &ChannelId) -> Result<Vec<(SeqPos, RecordHash)>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT channel, node_epoch, node_seq, hash FROM records \
             WHERE channel = ?1 ORDER BY node_epoch, node_seq",
        )?;
        let rows = stmt.query_map(params![channel.as_slice()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (ch, epoch, seq, hash_raw) = r?;
            out.push((
                SeqPos::new(arr32(&ch), epoch as u64, seq as u64),
                RecordHash(arr32(&hash_raw)),
            ));
        }
        Ok(out)
    }

    // --- účty, device keys, sessions (B4, MYHSN-6, D-26) ----------------

    /// Vytvor účet. `pass_hash` je Argon2id PHC reťazec z `crate::auth`
    /// — uzol nevidí heslo. ID sa generuje z OS RNG (náhoda je tu
    /// správnej ako počítadlo: ID účtu je verejné a nesmie odhaľovať
    /// počet registrácií).
    pub fn create_account(
        &mut self,
        username: &str,
        pass_hash: &str,
        now: u64,
    ) -> Result<Account, StoreError> {
        let username = username.trim().to_string();
        let tx = self.conn.unchecked_transaction()?;
        let id: AccountId = crate::auth::random_32();
        if let Err(e) = tx.execute(
            "INSERT INTO accounts (id, username, pass_hash, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![id.as_slice(), username, pass_hash, now as i64],
        ) {
            if is_constraint_violation(&e) {
                return Err(StoreError::UsernameTaken(username));
            }
            return Err(StoreError::Sql(e));
        }
        tx.commit()?;
        Ok(Account {
            id,
            username,
            password_argon2id_hash: pass_hash.to_string(),
            created: now,
        })
    }

    /// Účet podľa usernameu (presná zhoda, BINARY kolácia — `Juraj` a
    /// `juraj` sú rôzne účty; normalizáciu robí apka).
    pub fn account_by_username(&self, username: &str) -> Result<Option<Account>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, pass_hash, created_at FROM accounts WHERE username = ?1")?;
        let mut rows = stmt.query_map(params![username], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?))
        })?;
        match rows.next() {
            None => Ok(None),
            Some(r) => {
                let (id_raw, pass_hash, created) = r?;
                Ok(Some(Account {
                    id: arr32(&id_raw),
                    username: username.to_string(),
                    password_argon2id_hash: pass_hash,
                    created: created as u64,
                }))
            }
        }
    }

    /// Atestuj device kľúč účtu (D-26: nové zariadenie = atest nového
    /// kľúča, história platí). Kľúč je v uzle unikátny — nemôže patriť
    /// dvom účtom naraz.
    pub fn attest_device_key(
        &mut self,
        account_id: &AccountId,
        public_key: &DevicePublicKey,
        label: &str,
        now: u64,
    ) -> Result<DeviceRow, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let exists: i64 = tx.query_row(
            "SELECT COUNT(1) FROM accounts WHERE id = ?1",
            params![account_id.as_slice()],
            |row| row.get(0),
        )?;
        if exists == 0 {
            return Err(StoreError::NoSuchAccount);
        }
        let label = {
            let l = label.trim();
            if l.is_empty() {
                "zariadenie".to_string()
            } else {
                l.chars().take(64).collect()
            }
        };
        let res = tx.execute(
            "INSERT INTO device_keys (account_id, public_key, label, attested_at) \
             VALUES (?1, ?2, ?3, ?4)",
            params![account_id.as_slice(), public_key.0.as_slice(), label, now as i64],
        );
        if let Err(e) = res {
            if is_constraint_violation(&e) {
                return Err(StoreError::DeviceKeyTaken);
            }
            return Err(StoreError::Sql(e));
        }
        let row_id: i64 = tx.last_insert_rowid();
        tx.commit()?;
        Ok(DeviceRow {
            id: row_id,
            key: DeviceKey {
                account_id: *account_id,
                public_key: *public_key,
                label,
                attested_at: now,
                revoked_at: None,
            },
        })
    }

    /// Zoznam zariadení účtu (aj revokovaných — D-26: história platí,
    /// revokovaný kľúč ostáva v prehľade).
    pub fn list_devices(&self, account_id: &AccountId) -> Result<Vec<DeviceRow>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, public_key, label, attested_at, revoked_at FROM device_keys \
             WHERE account_id = ?1 ORDER BY attested_at, id",
        )?;
        let rows = stmt.query_map(params![account_id.as_slice()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<i64>>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (id, pk_raw, label, attested, revoked) = r?;
            out.push(DeviceRow {
                id,
                key: DeviceKey {
                    account_id: *account_id,
                    public_key: DevicePublicKey(arr32(&pk_raw)),
                    label,
                    attested_at: attested as u64,
                    revoked_at: revoked.map(|v| v as u64),
                },
            });
        }
        Ok(out)
    }

    /// Revokácia device kľúča (B4 kritérium: podpis revokovaným kľúčom
    /// sa odmietne). `Err(NoSuchDevice)` = kľúč nepatrí tomuto účtu.
    /// Revokácia je idempotentná: druhý pokus nič nemení a je úspešný.
    pub fn revoke_device(
        &mut self,
        account_id: &AccountId,
        device_id: i64,
        now: u64,
    ) -> Result<bool, StoreError> {
        let changed = self.conn.execute(
            "UPDATE device_keys SET revoked_at = ?3 \
             WHERE id = ?1 AND account_id = ?2 AND revoked_at IS NULL",
            params![device_id, account_id.as_slice(), now as i64],
        )?;
        if changed > 0 {
            return Ok(true);
        }
        // buď neexistuje, alebo je už revokovaný — rozlíšime dotazom
        let owned: i64 = self.conn.query_row(
            "SELECT COUNT(1) FROM device_keys WHERE id = ?1 AND account_id = ?2",
            params![device_id, account_id.as_slice()],
            |row| row.get(0),
        )?;
        if owned == 0 {
            return Err(StoreError::NoSuchDevice(device_id));
        }
        Ok(true) // už revokovaný — idempotentný úspech
    }

    /// Vráti `Some(account_id)` práve vtedy, keď je kľúč atestovaný a
    /// **aktívny** (nie revoked). To je brána pre overovanie podpisov
    /// pri append (B4 kritérium + B5 WS).
    pub fn device_account_if_active(
        &self,
        public_key: &[u8; 32],
    ) -> Result<Option<AccountId>, StoreError> {
        // **F14a (O3):** čakajúci účet (`status = 1`) nesmie písať ani cez
        // WS — relácia nemá autentizáciu, autoritou je len podpis, takže
        // kontrola patrí sem, nie len do loginu.
        Ok(self
            .conn
            .query_row(
                "SELECT dk.account_id FROM device_keys dk \
                 JOIN accounts a ON a.id = dk.account_id \
                 WHERE dk.public_key = ?1 AND dk.revoked_at IS NULL AND a.status = 0",
                params![public_key.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .ok()
            .map(|raw| arr32(&raw)))
    }

    /// **F14c:** účet **ľubovoľného** device kľúča (aj revokovaného, aj
    /// čakajúceho účtu) — potrebné na zistenie **hodnosti autora**
    /// cudzieho príspevku pri moderátorskom mazaní (`deletion.rs`). Na
    /// append sa používa prísnejší [`Store::device_account_if_active`].
    pub fn account_for_device(&self, public_key: &[u8; 32]) -> Option<AccountId> {
        self.conn
            .query_row(
                "SELECT account_id FROM device_keys WHERE public_key = ?1",
                params![public_key.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .ok()
            .map(|raw| arr32(&raw))
    }

    /// B5.1 (MYHSN-19): mapa **atestovaných a nezrušených** device kľúčov
    /// na mená účtov pre `GET /members`. Jeden SQL dotaz: záznam v
    /// `device_keys` vzniká len atestáciou (B4), takže podmienka
    /// `revoked_at IS NULL` presne vyberie aktívne kľúče; JOIN na
    /// `accounts` pridá username. Účet s viacerými aktívnymi zariadeniami
    /// je tam toľkokrát, koľkokrát — klient potrebuje mapu kľúč → meno.
    /// Poradie podľa mena a id je deterministické (testy aj apka).
    /// B8 (doc 24 §4): pridáva `display_name` a `avatar` (LEFT JOIN na
    /// `media` — existujúce kľúče odpovede sa nemenia, len pribúdajú).
    pub fn members(&self) -> Result<Vec<MemberRow>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT d.public_key, a.username, a.display_name, av.id, av.hash \
             FROM device_keys d \
             JOIN accounts a ON a.id = d.account_id \
             LEFT JOIN media av ON av.id = a.avatar_media \
             WHERE d.revoked_at IS NULL \
             ORDER BY a.username, d.id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<Vec<u8>>>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (pk_raw, username, display_name, av_id, av_hash) = r?;
            let avatar = match (av_id, av_hash) {
                (Some(id), Some(hash)) => Some((id, arr32(&hash))),
                _ => None,
            };
            out.push(MemberRow {
                public_key: arr32(&pk_raw),
                username,
                display_name,
                avatar,
            });
        }
        Ok(out)
    }

    // --- sessions (B4) ----------------------------------------------------
    //
    // Session token = 32 B náhody; v DB je **len BLAKE3 hash** a
    // expirácia. Ani pri logovaní sa token nikde nevypisuje.

    /// Vytvor reláciu: uloží hash tokena s expiráciou (`now + ttl`).
    /// Pri príležitosti vymaže prešlé relácie (žiadny cron netreba).
    pub fn put_session(
        &mut self,
        token_hash: &[u8; 32],
        account_id: &AccountId,
        now: u64,
        ttl_secs: u64,
    ) -> Result<(), StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO sessions (token_hash, account_id, created_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(token_hash) DO UPDATE SET account_id = excluded.account_id, \
             created_at = excluded.created_at, expires_at = excluded.expires_at",
            params![token_hash.as_slice(), account_id.as_slice(), now as i64, (now + ttl_secs) as i64],
        )?;
        tx.execute(
            "DELETE FROM sessions WHERE expires_at <= ?1",
            params![now as i64],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Účet priradený k hashu tokena, len ak relácia nevypršala.
    pub fn session_account(
        &self,
        token_hash: &[u8; 32],
        now: u64,
    ) -> Result<Option<AccountId>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT account_id FROM sessions \
                 WHERE token_hash = ?1 AND expires_at > ?2",
                params![token_hash.as_slice(), now as i64],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .ok()
            .map(|raw| arr32(&raw)))
    }

    // --- B5: idempotentný WS append (client_hash) -------------------------

    /// Pozícia záznamu podľa jeho **finálneho** hashu (pre Ack duplikátu).
    pub fn record_position(&self, hash: &RecordHash) -> Result<Option<SeqPos>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT channel, node_epoch, node_seq FROM records WHERE hash = ?1",
                params![hash.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .ok()
            .map(|(ch, epoch, seq)| SeqPos::new(arr32(&ch), epoch as u64, seq as u64)))
    }

    /// Nájdi záznam podľa hashu **prijatých** bajtov (pred opečiatkovaním).
    /// Vráti pozíciu + finálny hash uloženej obálky — presne to, čo patrí
    /// do `Ack` pri duplicitnej správe (kritérium B5c).
    pub fn record_by_client_hash(
        &self,
        client_hash: &[u8; 32],
    ) -> Result<Option<(SeqPos, RecordHash)>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT channel, node_epoch, node_seq, hash FROM records WHERE client_hash = ?1",
                params![client_hash.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .ok()
            .map(|(ch, epoch, seq, hash_raw)| {
                (
                    SeqPos::new(arr32(&ch), epoch as u64, seq as u64),
                    RecordHash(arr32(&hash_raw)),
                )
            }))
    }

    /// Vlož opečiatkovanú obálku s voliteľným `client_hash` (cesta B5).
    /// Kontrola obálky je rovnaká ako pri [`RecordStore::append`]; líšia
    /// sa len vkladaný stĺpec. `ClientHashTaken` pri preteku dvoch
    /// rovnakých správ — volajúci má dotazať [`Self::record_by_client_hash`].
    pub fn insert_record(
        &mut self,
        pos: &SeqPos,
        hash: &RecordHash,
        raw: &[u8],
        client_hash: Option<&[u8; 32]>,
    ) -> Result<(), StoreError> {
        self.insert_record_erasing(pos, hash, raw, client_hash, None)
    }

    /// **B6 (MYHSN-8, D-30):** to isté čo [`Self::insert_record`], ale navyše
    /// v **tej istej transakcii** aplikuje účinok erase záznamu: ak je
    /// `erase = Some((cieľ, dôvod))`, fyzicky nahradí bajty cieľa pohľadom
    /// `Envelope::erased(reason)` — obsah je preč, dôvod, autor, pozícia a
    /// meta ostávajú (D-30: „erase odstráni obsah a nechá dôvod“).
    ///
    /// Cieľ si ponechá svoju pozíciu `(channel, node_epoch, node_seq)`; mení
    /// sa len jeho obsah, a preto aj jeho `hash` (identifikátor je BLAKE3
    /// bajtov, D-25). Slepej hash sa ruší na `NIL` — bez obsahu už nič
    /// neindexuje (D-30). Pečiatku uzla znova podpíšeme operačným kľúčom,
    /// lebo pôvodná pečiatka viazala staré bajty.
    ///
    /// Atómovosť nie je kozmetika: keby vloženie erase záznamu a náhrada
    /// obsahu žili v dvoch transakciách, pád medzi nimi by zanechal dôvod
    /// so **zachovaným** obsahom — teda stav, ktorý D-30 výslovne zakazuje.
    pub fn insert_record_erasing(
        &mut self,
        pos: &SeqPos,
        hash: &RecordHash,
        raw: &[u8],
        client_hash: Option<&[u8; 32]>,
        erase: Option<(&RecordHash, EraseReason)>,
    ) -> Result<(), StoreError> {
        let env = Envelope::decode(raw).map_err(StoreError::NotEnvelope)?;
        if RecordHash::from_raw(raw) != *hash {
            return Err(StoreError::IndexMismatch {
                reason: "hash != BLAKE3(raw)",
            });
        }
        if env.hash() != *hash {
            return Err(StoreError::IndexMismatch {
                reason: "hash nesedí s kanonickými bajtmi obálky",
            });
        }
        if env.stamp.channel != pos.channel
            || env.stamp.node_epoch != pos.node_epoch
            || env.stamp.node_seq != pos.node_seq
        {
            return Err(StoreError::IndexMismatch {
                reason: "pečiatka obálky nesedí s pozíciou v logu",
            });
        }

        // Operačný kľúč uzla potrebujeme len pri erase (znova podpíšeme
        // nahradenú obálku). Zisťujeme ho **pred** transakciou, lebo
        // [`Store::node_sign_seed`] berie `&mut self` a transakcia už
        // požičiava `conn`.
        let seed = erase.map(|_| self.node_sign_seed()).transpose()?;

        let tx = self.conn.unchecked_transaction()?;
        let seen: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM records WHERE hash = ?1",
                params![hash.as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .ok();
        if seen.is_some() {
            tx.commit()?;
            return Ok(());
        }
        let inserted = tx.execute(
            "INSERT INTO records \
             (hash, channel, node_epoch, node_seq, body_hash, blind_hash, kind, author, raw, client_hash) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                hash.as_slice(),
                pos.channel.as_slice(),
                pos.node_epoch as i64,
                pos.node_seq as i64,
                env.body_hash.as_slice(),
                env.blind_hash.as_slice(),
                env.kind.code() as i64,
                env.author.0.as_slice(),
                raw,
                client_hash.map(|h| h.as_slice()),
            ],
        );
        match inserted {
            Ok(_) => {}
            Err(e) if is_constraint_violation(&e) => {
                // rozlíšime kolíziu pozície od preteku client_hashu
                let pos_taken: i64 = tx.query_row(
                    "SELECT COUNT(1) FROM records WHERE channel = ?1 AND node_epoch = ?2 AND node_seq = ?3",
                    params![pos.channel.as_slice(), pos.node_epoch as i64, pos.node_seq as i64],
                    |row| row.get(0),
                )?;
                if pos_taken > 0 {
                    return Err(StoreError::PositionConflict {
                        channel: pos.channel,
                        node_epoch: pos.node_epoch,
                        node_seq: pos.node_seq,
                    });
                }
                return Err(StoreError::ClientHashTaken);
            }
            Err(e) => return Err(StoreError::Sql(e)),
        }

        // B6: erase záznam sa nevkladá „samotný“ — v tej istej transakcii
        // musíme vymeniť aj obsah cieľa. Zlyhanie tu zroluje aj vloženie,
        // takže log nikdy neobsahuje dôvod bez vymazaného obsahu (D-30).
        if let Some((target, reason)) = erase {
            let seed = seed.expect("seed sme zistili práve pre erase");
            apply_erase_in_tx(&tx, target, reason, &seed)?;
        }
        tx.commit()?;
        Ok(())
    }

    // --- čítací pohľad s mazacími kindmi (B6/MYHSN-8, D-30) --------------

    /// **Čítací pohľad** na log kanála vyhodnotený podľa mazacích záznamov.
    /// [`RecordStore::range`] ostáva surový append-only log (zmluva jadra,
    /// D-29) — toto je **aplikačná vrstva**, ktorú čítajú WS catch-up aj REST.
    ///
    /// Semantika kindov (rozhodnutie k D-30, zdokumentované aj v README):
    ///
    /// * **Tombstone(cieľ)** → cieľ z pohľadu **zmizne**. Vrátime len
    ///   tombstone záznam: klient, ktorý už má cieľ vo cache, z neho vie,
    ///   že má zmiznúť aj jemu; nový čitateľ cieľ nikdy neuzrie. (Voľba
    ///   „vrátiť cieľ s priznaným tombstonom“ sme zamietli — apka by musela
    ///   rozlišovať dva stavy tam, kde D-30 hovorí „príspevok je preč“.)
    /// * **Hide(cieľ)** → skryté **len pre účet, ktorý hide podpísal**;
    ///   autorom záznamu je device kľúč toho účtu, takže účet nepotrebujeme
    ///   v tele. Server vie filtrovať len keď pozná čitateľa (`reader`);
    ///   inak hide záznam vráti a filter aplikuje klient — WS relácia nemá
    ///   autentizáciu (B5) a hide sa týka jedinej osoby, jeho autora.
    /// * **Erase(cieľ, dôvod)** → obsah je už **fyzicky** vymenený v zápise
    ///   cieľa ([`Store::insert_record_erasing`]), preto čítacia cesta obsah
    ///   nerieši: vráti sa vymenená obálka (kind `Erase`, dôvod, meta) a
    ///   klient z nej kreslí placeholder. V logu sú po erase **dva** erase
    ///   záznamy — vymenený rad cieľa (NIL podpis autora) a *akcia* erase
    ///   (podpísaná autorom). Akcia sa vynechá vtedy, keď je vymenený rad
    ///   v tomto scane: čitateľ by inak videl placeholder dvakrát. Akcie sa
    ///   naopak **nevynechá**, ak je watermark čitateľa nad cieľom — len z
    ///   nej vie, že má svoj cache záznam vymazať.
    ///
    /// `limit` platí pre riadky logu **pred** filtrovaním, preto vrátený
    /// počet môže byť menší. Nie je to stránovacia zmluva (stránovanie
    /// prinesie `Sync`); limit je ochrana pred veľkým result-setom.
    pub fn visible_range(
        &self,
        q: &RangeQuery,
        reader: Option<&[u8; 32]>,
    ) -> Result<Vec<(SeqPos, Vec<u8>)>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT channel, node_epoch, node_seq, hash, kind, author, raw FROM records \
             WHERE channel = ?1 AND (node_epoch > ?2 OR (node_epoch = ?2 AND node_seq >= ?3)) \
             ORDER BY node_epoch, node_seq LIMIT ?4",
        )?;
        let rows = stmt.query_map(
            params![
                q.channel.as_slice(),
                q.from_epoch as i64,
                q.from_seq as i64,
                q.limit as i64
            ],
            |row| {
                Ok(Row {
                    pos: SeqPos::new(
                        arr32(&row.get::<_, Vec<u8>>(0)?),
                        row.get::<_, i64>(1)? as u64,
                        row.get::<_, i64>(2)? as u64,
                    ),
                    hash: arr32(&row.get::<_, Vec<u8>>(3)?),
                    kind: row.get::<_, i64>(4)?,
                    author: arr32(&row.get::<_, Vec<u8>>(5)?),
                    raw: row.get::<_, Vec<u8>>(6)?,
                })
            },
        )?;
        let rows: Vec<Row> = rows.collect::<Result<Vec<_>, _>>()?;

        // 1) jazykové sady: čo v scane je a čo ktoré mazanie ruší. Ideme
        //    dva razy, lebo tombstone (seq 7) ruší cieľ (seq 3) — pri
        //    jedinom prechode by sme cieľ už boli pustili von.
        let present: HashSet<[u8; 32]> = rows.iter().map(|r| r.hash).collect();
        // Vymenené rady po erase: poznáme ich podľa **NIL podpisu autora**
        // (`Envelope::erased` ho nastavuje a uzol ho pri výmene obsahu
        // nepodpisuje znovu). Klient-sent erase záznam podpis mať MUSÍ
        // (`deletion::evaluate`), takže NIL je spoľahlivý rozlišovač:
        // NIL = „tento rad už neobsahuje obsah“, podpis = „niekto niečo
        // vymazal“. To potrebné rozlíšiť, lebo oba mienia ten istý cieľ a
        // čitateľ by inak videl placeholder dvakrát.
        let erased_here: HashSet<[u8; 32]> = rows
            .iter()
            .filter(|r| RecordKind::from_code(r.kind as u8) == Some(RecordKind::Erase))
            .filter(|r| erased_view_sig_nil(&r.raw))
            .filter_map(|r| deletion_target(&r.raw))
            .collect();
        let mut tombstoned: HashSet<[u8; 32]> = HashSet::new();
        let mut hidden: HashSet<[u8; 32]> = HashSet::new();
        for r in &rows {
            match RecordKind::from_code(r.kind as u8) {
                Some(RecordKind::Tombstone) => {
                    if let Some(t) = deletion_target(&r.raw) {
                        tombstoned.insert(t);
                    }
                }
                Some(RecordKind::Hide) if reader == Some(&r.author) => {
                    // skryté len pre autora hide — iného čitateľa sa to
                    // netýka, preto bez `reader` (alebo cudzieho) tu
                    // nevymávame nič
                    if let Some(t) = deletion_target(&r.raw) {
                        hidden.insert(t);
                    }
                }
                _ => {}
            }
        }

        // 2) filter
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            match RecordKind::from_code(r.kind as u8) {
                // mazacie záznamy samy sa vracejú vždy (okrem akcie erase,
                // ktorej vymenený rad je v scane) — klient bez nich nevie čo zmizlo
                Some(RecordKind::Tombstone) | Some(RecordKind::Hide) => {
                    out.push((r.pos, r.raw));
                }
                Some(RecordKind::Erase) => {
                    if erased_view_sig_nil(&r.raw) {
                        // vymenený rad cieľa: always patrí do pohľadu,
                        // nesie dôvod a pozíciu (D-30: obsah preč, dôvod vtedy)
                        out.push((r.pos, r.raw));
                    } else {
                        // akcia erase: potrebná len pre čitateľa, ktorého
                        // watermark je nad cieľom (inak by nemel čo vymazať).
                        // Ak je vymenený rad v tomto scane, stačí on.
                        let redundant = deletion_target(&r.raw)
                            .map(|t| erased_here.contains(&t) || present.contains(&t))
                            .unwrap_or(false);
                        if !redundant {
                            out.push((r.pos, r.raw));
                        }
                    }
                }
                _ => {
                    if tombstoned.contains(&r.hash) || hidden.contains(&r.hash) {
                        continue;
                    }
                    out.push((r.pos, r.raw));
                }
            }
        }
        Ok(out)
    }

    // --- media (B7/MYHSN-9, D-33) -------------------------------------

    /// Vloží záznam **pominuteľného** blobu (trieda 0). `id` je primárny
    /// kľúč (hex 32 B); kolízia je prakticky vylúčená (náhodné id), ale
    /// schéma ju stráži. Trvalé bloby (avatar/obálka) vkladajú
    /// `put_account_avatar` / `put_channel_cover` v jednej transakcii
    /// so zmenou ukazovateľa.
    pub fn insert_media(
        &mut self,
        id: &str,
        account_id: &[u8; 32],
        size: i64,
        hash: &[u8; 32],
        created_at: i64,
        expires_at: i64,
    ) -> Result<(), StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO media (id, account_id, size, hash, created_at, expires_at, class, mime)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, NULL)",
            params![id, account_id.as_slice(), size, hash.as_slice(), created_at, expires_at],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Načíta záznam blobu podľa id. `None` = neznáme id (alebo už zmazané).
    pub fn get_media(&self, id: &str) -> Result<Option<MediaRow>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, account_id, size, hash, created_at, expires_at, class, mime
                 FROM media WHERE id = ?1",
                params![id],
                |row| {
                    Ok(MediaRow {
                        id: row.get(0)?,
                        account_id: arr32(&row.get::<_, Vec<u8>>(1)?),
                        size: row.get(2)?,
                        hash: arr32(&row.get::<_, Vec<u8>>(3)?),
                        created_at: row.get(4)?,
                        expires_at: row.get(5)?,
                        class: row.get(6)?,
                        mime: row.get(7)?,
                    })
                },
            )
            .ok())
    }

    /// Súčet bajtov **neexpirovaných pominuteľných** blobov jedného účtu
    /// (kvóta, D-33). Započítava len `expires_at > now` — expirované sa
    /// ešte len môžu dočistiť a už nepatria do účtu. B8 (doc 24 §2):
    /// počíta **len triedu 0** — inak by si človek chatovými fotkami
    /// zablokoval zmenu avatara alebo obálky.
    pub fn active_media_bytes(&self, account_id: &[u8; 32], now: i64) -> Result<i64, StoreError> {
        let sum: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(size), 0) FROM media
             WHERE account_id = ?1 AND expires_at > ?2 AND class = 0",
            params![account_id.as_slice(), now],
            |row| row.get(0),
        )?;
        Ok(sum)
    }

    /// Vymaže **expirované pominuteľné** záznamy (`class = 0 AND
    /// expires_at <= now`) a vráti ich id, aby volajúci zmazal aj súbory
    /// na disku (lazy cleanup, D-33). Volané z KAŽDÉHO uploadu aj
    /// stiahnutia — v tejto fáze bez cronu. Trvalé bloby (trieda 1/2)
    /// filter chráni aj keby im niekto nastavil expiráciu (obranná
    /// hĺbka; inak dostávajú `expires_at = i64::MAX`).
    pub fn take_expired_media(&mut self, now: i64) -> Result<Vec<String>, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let ids: Vec<String> = {
            let mut stmt =
                tx.prepare("SELECT id FROM media WHERE class = 0 AND expires_at <= ?1")?;
            let rows = stmt.query_map(params![now], |row| row.get::<_, String>(0))?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        if !ids.is_empty() {
            tx.execute(
                "DELETE FROM media WHERE class = 0 AND expires_at <= ?1",
                params![now],
            )?;
        }
        tx.commit()?;
        Ok(ids)
    }

    /// Smaže konkrétny záznam blobu (napr. keď súbor chýba na disku).
    pub fn delete_media(&mut self, id: &str) -> Result<(), StoreError> {
        self.conn.execute("DELETE FROM media WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Vloží media riadok s ľubovoľnou triedou/mime/expiráciou **bez**
    /// nastavovania ukazovateľa (kanál/účet). Prevádzkovo to simuluje
    /// crash medzi vložením riadku a naviazaním; testy sweepu to používajú
    /// na vytvorenie siroty. `class > 0` bez ukazovateľa zmaže
    /// [`Self::take_unreferenced_permanent_media`].
    pub(crate) fn insert_media_row_raw(
        &mut self,
        id: &str,
        account_id: &[u8; 32],
        size: i64,
        hash: &[u8; 32],
        created_at: i64,
        expires_at: i64,
        class: i64,
        mime: Option<&str>,
    ) -> Result<(), StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO media (id, account_id, size, hash, created_at, expires_at, class, mime)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                id,
                account_id.as_slice(),
                size,
                hash.as_slice(),
                created_at,
                expires_at,
                class,
                mime
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    // --- B8 (MYHSN-22): display_name, avatary, obálky, sweep --------------

    /// Všetky id blobov, ktoré úložňa pozná (sweep pri štarte: súbory bez
    /// riadku v `media` sú siroty z pádu medzi zápisom a commitom).
    pub fn all_media_ids(&self) -> Result<Vec<String>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT id FROM media")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Vymaže **trvalé** riadky (trieda 1/2), na ktoré už nič neukazuje
    /// (žiadny kanál nemá `cover_media` = id, žiadny účet `avatar_media`),
    /// a vráti ich id na zmazanie súborov. Pominuteľné (trieda 0) sa
    /// neupratujú týmto spôsobom — o ne sa stará TTL cleanup, lebo na
    /// neukazovateľa sa pozerá až klient v tele správy (D-25).
    pub fn take_unreferenced_permanent_media(&mut self) -> Result<Vec<String>, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let ids: Vec<String> = {
            let mut stmt = tx.prepare(
                "SELECT id FROM media WHERE class > 0 \
                 AND id NOT IN (SELECT cover_media FROM channels WHERE cover_media IS NOT NULL) \
                 AND id NOT IN (SELECT avatar_media FROM accounts WHERE avatar_media IS NOT NULL)",
            )?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        if !ids.is_empty() {
            tx.execute(
                "DELETE FROM media WHERE class > 0 \
                 AND id NOT IN (SELECT cover_media FROM channels WHERE cover_media IS NOT NULL) \
                 AND id NOT IN (SELECT avatar_media FROM accounts WHERE avatar_media IS NOT NULL)",
                [],
            )?;
        }
        tx.commit()?;
        Ok(ids)
    }

    /// Účet podľa id s voliteľným menom a profilovou fotkou (`GET /me`).
    pub fn account_by_id(&self, id: &[u8; 32]) -> Result<Option<AccountRow>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT a.id, a.username, a.display_name, av.id, av.hash, av.mime \
                 FROM accounts a LEFT JOIN media av ON av.id = a.avatar_media \
                 WHERE a.id = ?1",
                params![id.as_slice()],
                |row| {
                    let av = match (
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<Vec<u8>>>(4)?,
                    ) {
                        (Some(aid), Some(hash)) => {
                            Some((aid, arr32(&hash), row.get::<_, Option<String>>(5)?))
                        }
                        _ => None,
                    };
                    Ok(AccountRow {
                        id: arr32(&row.get::<_, Vec<u8>>(0)?),
                        username: row.get(1)?,
                        display_name: row.get(2)?,
                        avatar: av,
                    })
                },
            )
            .ok())
    }

    /// Nastaví/vymaže `display_name` (B8, doc 24 §4). Prázdny reťazec =
    /// NULL; validáciu dĺžky a riadiacich znakov robí API vrstva.
    pub fn set_display_name(
        &mut self,
        account_id: &[u8; 32],
        display_name: Option<&str>,
    ) -> Result<(), StoreError> {
        let changed = self.conn.execute(
            "UPDATE accounts SET display_name = ?2 WHERE id = ?1",
            params![account_id.as_slice(), display_name],
        )?;
        if changed == 0 {
            return Err(StoreError::NoSuchAccount);
        }
        Ok(())
    }

    /// **Atomické nastavenie obálky kanála** (B8, doc 24 §2): v jednej
    /// transakcii vloží trvalý riadok `media` (trieda 2), ukáže kanál na
    /// nový blob, zvýši `meta_version` a zmaže starý riadok. Súbor nového
    /// blobu musí byť na disku **už pred** volaním (tmp+fsync+rename);
    /// súbor starého blobu zmaže volajúci až po úspešnom návrate.
    ///
    /// Dva súbežné PUT-y: vyhrá posledný commit, jeho transakcia vidí
    /// medzitým nastavený blob ako „starý“ a zmaže jeho riadok — sirota
    /// nevznikne.
    pub fn put_channel_cover(
        &mut self,
        channel_id: &ChannelId,
        account_id: &[u8; 32],
        media_id: &str,
        mime: &str,
        size: i64,
        hash: &[u8; 32],
        now: i64,
    ) -> Result<CoverUpdate, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let current: Option<(Option<String>, i64)> = tx
            .query_row(
                "SELECT cover_media, meta_version FROM channels WHERE id = ?1",
                params![channel_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok();
        let (old_media_id, meta) = current.ok_or(StoreError::NoSuchChannel(*channel_id))?;
        tx.execute(
            "INSERT INTO media (id, account_id, size, hash, created_at, expires_at, class, mime)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 2, ?7)",
            params![
                media_id,
                account_id.as_slice(),
                size,
                hash.as_slice(),
                now,
                i64::MAX, // trvalý blob — chráni ho aj filter class v cleanup
                mime
            ],
        )?;
        tx.execute(
            "UPDATE channels SET cover_media = ?2, cover_set_by = ?3, cover_set_at = ?4, \
             meta_version = meta_version + 1 WHERE id = ?1",
            params![
                channel_id.as_slice(),
                media_id,
                account_id.as_slice(),
                now
            ],
        )?;
        if let Some(old) = &old_media_id {
            tx.execute("DELETE FROM media WHERE id = ?1", params![old])?;
        }
        tx.commit()?;
        Ok(CoverUpdate {
            old_media_id,
            meta_version: meta + 1,
        })
    }

    /// **Odstránenie obálky** (B8): idempotentné — bez obálky je úspech
    /// bez zmeny (`Ok(None)`). V transakcii zmaže riadok média; súbor
    /// zmazáva volajúci po návrate. `Err(NoSuchChannel)` = 404.
    pub fn clear_channel_cover(
        &mut self,
        channel_id: &ChannelId,
    ) -> Result<Option<String>, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let current: Option<Option<String>> = tx
            .query_row(
                "SELECT cover_media FROM channels WHERE id = ?1",
                params![channel_id.as_slice()],
                |row| row.get(0),
            )
            .ok();
        let old = match current {
            None => return Err(StoreError::NoSuchChannel(*channel_id)),
            Some(None) => {
                tx.commit()?;
                return Ok(None); // idempotentné: obálka nebola nastavená
            }
            Some(Some(old)) => old,
        };
        tx.execute(
            "UPDATE channels SET cover_media = NULL, cover_set_by = NULL, cover_set_at = NULL, \
             meta_version = meta_version + 1 WHERE id = ?1",
            params![channel_id.as_slice()],
        )?;
        tx.execute("DELETE FROM media WHERE id = ?1", params![&old])?;
        tx.commit()?;
        Ok(Some(old))
    }

    /// Obálky všetkých kanálov pre `GET /channels` (B8): `meta_version` +
    /// referencia na blob s menom toho, kto obálku nastavil. LEFT JOIN —
    /// kanál bez obálky je prítomný s `cover = None`.
    pub fn channel_cover_rows(&self) -> Result<Vec<ChannelCoverRow>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT c.id, c.meta_version, c.cover_media, m.hash, m.mime, \
                    c.cover_set_at, u.username \
             FROM channels c \
             LEFT JOIN media m ON m.id = c.cover_media \
             LEFT JOIN accounts u ON u.id = c.cover_set_by",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<i64>>(5)?,
                row.get::<_, Option<String>>(6)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (id_raw, meta_version, cover_id, hash, mime, set_at, set_by) = r?;
            // obranná konsistencia: ukazovateľ na neexistujúci riadok →
            // navonok žiadna obálka (sweep/transaction to nepustia, ale
            // radšej nevrátime polovičkový objekt)
            let cover = match (cover_id, hash) {
                (Some(id), Some(hash)) => Some(CoverRef {
                    media_id: id,
                    hash: arr32(&hash),
                    mime,
                    set_by,
                    set_at,
                }),
                _ => None,
            };
            out.push(ChannelCoverRow {
                id: arr32(&id_raw),
                meta_version,
                cover,
            });
        }
        Ok(out)
    }

    /// **Atomické nastavenie profilovej fotky** (B8, doc 24 §2): jedna
    /// transakcia — INSERT trvalého média (trieda 1), UPDATE účtu, DELETE
    /// starého riadku. Rovnaká atómová dohoda ako `put_channel_cover`;
    /// starý súbor maza až volajúci po návrate.
    pub fn put_account_avatar(
        &mut self,
        account_id: &[u8; 32],
        media_id: &str,
        mime: &str,
        size: i64,
        hash: &[u8; 32],
        now: i64,
    ) -> Result<Option<String>, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let old: Option<Option<String>> = tx
            .query_row(
                "SELECT avatar_media FROM accounts WHERE id = ?1",
                params![account_id.as_slice()],
                |row| row.get(0),
            )
            .ok();
        let old = match old {
            None => return Err(StoreError::NoSuchAccount),
            Some(v) => v,
        };
        tx.execute(
            "INSERT INTO media (id, account_id, size, hash, created_at, expires_at, class, mime)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7)",
            params![
                media_id,
                account_id.as_slice(),
                size,
                hash.as_slice(),
                now,
                i64::MAX,
                mime
            ],
        )?;
        tx.execute(
            "UPDATE accounts SET avatar_media = ?2 WHERE id = ?1",
            params![account_id.as_slice(), media_id],
        )?;
        if let Some(old) = &old {
            tx.execute("DELETE FROM media WHERE id = ?1", params![old])?;
        }
        tx.commit()?;
        Ok(old)
    }

    /// **Odstránenie profilovej fotky** (B8): idempotentné, maza riadok
    /// média v transakcii; súbor volajúci.
    pub fn clear_account_avatar(
        &mut self,
        account_id: &[u8; 32],
    ) -> Result<Option<String>, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let old: Option<Option<String>> = tx
            .query_row(
                "SELECT avatar_media FROM accounts WHERE id = ?1",
                params![account_id.as_slice()],
                |row| row.get(0),
            )
            .ok();
        let old = match old {
            None => return Err(StoreError::NoSuchAccount),
            Some(v) => v,
        };
        if let Some(old) = &old {
            tx.execute(
                "UPDATE accounts SET avatar_media = NULL WHERE id = ?1",
                params![account_id.as_slice()],
            )?;
            tx.execute("DELETE FROM media WHERE id = ?1", params![old])?;
        }
        tx.commit()?;
        Ok(old)
    }

    // --- F14a: role, registrácia, pozvánky (MYHSN-56) -------------------
    //
    // Materializovaný stav rolí žije v stĺpcoch `accounts` (rýchla kontrola
    // oprávnení, transakčná konzistencia), **audit** každej zmeny sa
    // appenduje do logu ako obálka kind 6/7 v systémovom kanáli. Oboje v
    // JEDNEJ transakcii (rozhodnutie O8, wiki doc 32): stav a audit sa
    // nikdy nemôžu rozísť. Audit píše uzol sám (author = operačný kľúč,
    // `by`/`by_device` v tele) — device kľúč admina neopustí zariadenie
    // (D-26), rozhodnutie O9.

    /// **F14a:** prvý nerevokovaný device kľúč účtu — audit zmeny role
    /// potrebuje `by_device` (kto a z ktorého zariadenia), ale session
    /// token sám o sebe device nenesie.
    pub fn first_active_device(
        &self,
        account_id: &[u8; 32],
    ) -> Result<Option<[u8; 32]>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT public_key FROM device_keys \
                 WHERE account_id = ?1 AND revoked_at IS NULL ORDER BY attested_at LIMIT 1",
                params![account_id.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .ok()
            .map(|raw| arr32(&raw)))
    }

    /// Existuje na uzle aspoň jeden admin? (`GET /node/info` → `has_admin`)
    pub fn has_admin(&self) -> Result<bool, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT EXISTS(SELECT 1 FROM accounts WHERE role = 2)", [], |r| {
                r.get::<_, i64>(0)
            })?
            != 0)
    }

    /// `(role, perms, status)` účtu; `None` = neexistuje.
    pub fn account_role(&self, id: &[u8; 32]) -> Result<Option<(u8, u32, u8)>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT role, perms, status FROM accounts WHERE id = ?1",
                params![id.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)? as u8,
                        row.get::<_, i64>(1)? as u32,
                        row.get::<_, i64>(2)? as u8,
                    ))
                },
            )
            .ok())
    }

    /// Nájdi účet podľa mena **alebo** hex id (admin API prijíma oboje,
    /// rozhodnutie Z3). Hex má 64 znakov → id; inak meno (BINARY kolácia).
    pub fn resolve_account(&self, name_or_id: &str) -> Result<Option<Account>, StoreError> {
        if name_or_id.len() == 64 && name_or_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            if let Some(bytes) = myhsn_core::record::from_hex(name_or_id) {
                if let Some(acc) = self.account_by_id(&arr32(&bytes))? {
                    return Ok(Some(Account {
                        id: acc.id,
                        username: acc.username,
                        password_argon2id_hash: String::new(),
                        created: 0,
                    }));
                }
            }
        }
        self.account_by_username(name_or_id)
    }

    /// **Atómová registrácia** (rozhodnutia O1/O2/O12/O13): INSERT účtu,
    /// spotreba pozvánky a pravidlo prvého admina v JEDNEJ transakcii.
    ///
    /// - `admin_candidate` — smie tento účet získať admina (žiadny
    ///   `bootstrap_admin` nakonfigurovaný, alebo meno sa presne rovná).
    ///   Povýšenie nastane len ak uzol **ešte nemá admina** — kontrola je
    ///   vnútri transakcie, takže dve súbežné registrácie nemôžu vyhrať
    ///   obe (SQLite serializuje zápisy, navyše `SharedStore` je za Mutex).
    /// - `require_invite` — politika `invite_only`: bez platnej pozvánky
    ///   je registrácia `InviteRequired`.
    /// - `pending_if_no_invite` — politika `admin_approved`: bez pozvánky
    ///   vznikne čakajúci účet (`status = 1`). Prvý admin (bootstrap) je
    ///   VŽDY aktívny, inak by sa nikto nedostal dnu.
    /// - `invite_token` — ak je prítomný, MUSÍ byť platný (neplatný =
    ///   `InviteInvalid` v každej politike) a spotrebuje sa single-use.
    // politika je matica 4 voliteľných príznakov — rozšíriť na struct by
    // čítanie volania skôr skomplikovalo než zjednodušilo
    #[allow(clippy::too_many_arguments)]
    pub fn register_account(
        &mut self,
        username: &str,
        pass_hash: &str,
        now: u64,
        admin_candidate: bool,
        require_invite: bool,
        pending_if_no_invite: bool,
        invite_token: Option<&[u8; 32]>,
    ) -> Result<RegOutcome, RegError> {
        use RegError::*;
        let username = username.trim().to_string();
        let tx = self.conn.unchecked_transaction()?;
        let id: AccountId = crate::auth::random_32();

        // 1) spotreba pozvánky (single-use + expirácia), ak bola poslaná
        let mut invite_consumed = false;
        if let Some(token) = invite_token {
            let token_hash = crate::auth::hash_session_token(token);
            let used = tx.execute(
                "UPDATE invites SET used_by = ?1, used_at = ?2 \
                 WHERE token_hash = ?3 AND used_by IS NULL \
                   AND (expires_at IS NULL OR expires_at > ?2)",
                params![id.as_slice(), now as i64, token_hash.as_slice()],
            )?;
            if used != 1 {
                return Err(InviteInvalid);
            }
            invite_consumed = true;
        } else if require_invite {
            return Err(InviteRequired);
        }

        // 2) pravidlo prvého admina — vnútri transakcie (O1: viazané na id
        // nového účtu, inak by UPDATE povýšil všetky účty)
        let admin_exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM accounts WHERE role = 2)",
            [],
            |r| r.get::<_, i64>(0),
        )? != 0;
        let became_admin = admin_candidate && !admin_exists;
        let role: u8 = if became_admin { 2 } else { 0 };
        // čakajúci len ak politika vyžaduje schválenie A účet sa nestal adminom
        let status: u8 =
            if pending_if_no_invite && invite_token.is_none() && !became_admin {
                1
            } else {
                0
            };

        // 3) INSERT — pri obsadenom mene rollback (pozvánka sa nesmie minúť)
        if let Err(e) = tx.execute(
            "INSERT INTO accounts (id, username, pass_hash, created_at, role, perms, status) \
             VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)",
            params![id.as_slice(), username, pass_hash, now as i64, role as i64, status as i64],
        ) {
            if is_constraint_violation(&e) {
                return Err(UsernameTaken(username));
            }
            return Err(Store(e.into()));
        }
        tx.commit()?;
        Ok(RegOutcome {
            account: Account {
                id,
                username,
                password_argon2id_hash: pass_hash.to_string(),
                created: now,
            },
            role,
            perms: 0,
            pending: status == 1,
            invite_consumed,
            became_admin,
        })
    }

    /// **Jediná cesta ku zmene role** (rozhodnutie O8): invarianty,
    /// UPDATE účtu a append auditného záznamu v jednej transakcii.
    /// Vráti opečiatkovanú obálku auditu (pre WS broadcast PO commite).
    ///
    /// Invarianty (O16/O17): demota/revokácia **posledného admina** je
    /// `LastAdmin` — kontrola je vnútri transakcie, dve súbežné degradácie
    /// sa navzájom vidia. Grant zároveň **schvaľuje** pending účet
    /// (`status = 0`, rozhodnutie Z2). `perms` sa ukladajú kanonicky:
    /// nenulové len pre moderátora.
    pub fn apply_role_change(
        &mut self,
        target: &[u8; 32],
        new_role: u8,
        perms: u32,
        revoke: bool,
        by: Option<([u8; 32], [u8; 32])>,
    ) -> Result<Envelope, RoleError> {
        use RoleError::*;
        let tx = self.conn.unchecked_transaction()?;

        // cieľ musí existovať; poznáme meno (audit) a súčasnú rolu
        let (username, old_role): (String, i64) = tx
            .query_row(
                "SELECT username, role FROM accounts WHERE id = ?1",
                params![target.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| NoSuchAccount)?;

        // posledný admin sa nesmie odomocniť (demota/revokácia)
        if old_role == 2 && new_role != 2 {
            let others: i64 = tx.query_row(
                "SELECT COUNT(1) FROM accounts WHERE role = 2 AND id != ?1",
                params![target.as_slice()],
                |r| r.get(0),
            )?;
            if others == 0 {
                return Err(LastAdmin);
            }
        }

        // kanonická forma: perms len moderátor, grant zároveň schvaľuje
        let perms_stored: i64 = if new_role == 1 { perms as i64 } else { 0 };
        tx.execute(
            "UPDATE accounts SET role = ?1, perms = ?2, status = 0 WHERE id = ?3",
            params![new_role as i64, perms_stored, target.as_slice()],
        )?;

        // audit do systémového kanála (O5: id v meta, vytvoríme len raz)
        let channel = Self::ensure_system_channel_in(&tx)?;
        let (by_acc, by_dev) = by.unwrap_or(([0u8; 32], [0u8; 32]));
        let payload = if revoke {
            Payload::RevokeRole {
                target: *target,
                target_name: username,
                by: by_acc,
                by_device: by_dev,
            }
        } else {
            Payload::GrantRole {
                target: *target,
                target_name: username,
                role: new_role,
                perms: perms_stored as u32,
                by: by_acc,
                by_device: by_dev,
            }
        };
        let env = Self::append_node_record_in(&tx, &channel, &payload)?;
        tx.commit()?;
        Ok(env)
    }

    /// ID systémového kanála, alebo `None` (ešte neexistuje).
    pub fn system_channel_id(&self) -> Result<Option<ChannelId>, StoreError> {
        Ok(self.meta_get(META_SYSTEM_CHANNEL)?.as_deref().map(arr32))
    }

    /// Vytvor systémový kanál (idempotentné). Volá `main` pri štarte aj
    /// `apply_role_change` vnútri transakcie.
    pub fn ensure_system_channel(&mut self) -> Result<ChannelId, StoreError> {
        if let Some(id) = self.system_channel_id()? {
            if self.get_channel(&id)?.is_some() {
                return Ok(id);
            }
        }
        let tx = self.conn.unchecked_transaction()?;
        let id = Self::ensure_system_channel_in(&tx)?;
        tx.commit()?;
        Ok(id)
    }

    fn ensure_system_channel_in(tx: &rusqlite::Transaction<'_>) -> Result<ChannelId, StoreError> {
        if let Some(raw) = Self::meta_get_in(tx, META_SYSTEM_CHANNEL)? {
            let id = arr32(&raw);
            let exists: i64 = tx.query_row(
                "SELECT COUNT(1) FROM channels WHERE id = ?1",
                params![id.as_slice()],
                |r| r.get(0),
            )?;
            if exists == 1 {
                return Ok(id);
            }
        }
        // `POST /channels` je bez auth — meno „system“ si môže nárokovať
        // hocikto skôr ako my. Hľadáme voľné meno (rozhodnutie O5: filtruje
        // sa podľa ID z meta, nie podľa mena).
        let mut name = "system".to_string();
        for i in 2..=64u32 {
            let taken: i64 = tx.query_row(
                "SELECT COUNT(1) FROM channels WHERE name = ?1",
                params![name],
                |r| r.get(0),
            )?;
            if taken == 0 {
                break;
            }
            name = format!("system-{i}");
        }
        // rovnaká derivácia id ako `create_channel` (counter v meta)
        let counter: i64 = {
            let raw = Self::meta_get_in(tx, b"channel_counter")?;
            let next =
                raw.map(|v| i64::from_le_bytes(v.try_into().unwrap_or([0; 8]))).unwrap_or(0) + 1;
            Self::meta_set_in(tx, b"channel_counter", &next.to_le_bytes())?;
            next
        };
        let mut pre = b"myhsn:channel:v1:".to_vec();
        pre.extend_from_slice(name.as_bytes());
        pre.extend_from_slice(&counter.to_le_bytes());
        let id: ChannelId = *blake3::hash(&pre).as_bytes();
        let mut salt_pre = b"myhsn:salt:v1:".to_vec();
        salt_pre.extend_from_slice(&id);
        salt_pre.extend_from_slice(&counter.to_le_bytes());
        let salt: [u8; 32] = *blake3::hash(&salt_pre).as_bytes();
        tx.execute(
            "INSERT INTO channels (id, name, kind, salt, node_epoch) VALUES (?1, ?2, ?3, ?4, 0)",
            params![id.as_slice(), name, ChannelKind::Mixed.code() as i64, salt.as_slice()],
        )?;
        Self::meta_set_in(tx, META_SYSTEM_CHANNEL, id.as_slice())?;
        Ok(id)
    }

    /// Append **uzlom podpisovanej** obálky do ľubovoľného kanála v rámci
    /// otvorenej transakcie: alokácia seq, author = operačný kľúč uzla,
    /// podpis tela aj pečiatky, slepý hash so soľou kanála — postup
    /// identický s `ws.rs::process_record` (len bez kontroly device kľúča:
    /// autorom je uzol sám, O9). Pôvodný názov `append_system_record_in`
    /// sedel len na audit rolí; F14c píše ten istý postup aj audity skupín
    /// do group kanálov, preto všeobecný názov.
    fn append_node_record_in(
        tx: &rusqlite::Transaction<'_>,
        channel: &ChannelId,
        payload: &Payload,
    ) -> Result<Envelope, StoreError> {
        let body_bytes = payload.encode();
        let body_hash = RecordHash::from_raw(&body_bytes);
        // seed uzla (rovnaká logika ako `node_sign_seed`, len vnútri tx)
        let seed: [u8; 32] = match Self::meta_get_in(tx, b"node_key_seed")? {
            Some(raw) if raw.len() == 32 => {
                let mut s = [0u8; 32];
                s.copy_from_slice(&raw);
                s
            }
            _ => {
                let s = crate::auth::random_32();
                Self::meta_set_in(tx, b"node_key_seed", s.as_slice())?;
                s
            }
        };
        let node_pub = myhsn_core::identity::public_from_seed(&seed);
        let epoch: u64 = tx.query_row(
            "SELECT node_epoch FROM channels WHERE id = ?1",
            params![channel.as_slice()],
            |r| r.get::<_, i64>(0),
        )? as u64;
        let seq: i64 = tx.query_row(
            "INSERT INTO seq_counters (channel, node_epoch, last_seq) VALUES (?1, ?2, 1) \
             ON CONFLICT (channel, node_epoch) DO UPDATE SET last_seq = last_seq + 1 \
             RETURNING last_seq",
            params![channel.as_slice(), epoch as i64],
            |r| r.get(0),
        )?;
        let salt: Vec<u8> = tx.query_row(
            "SELECT salt FROM channels WHERE id = ?1",
            params![channel.as_slice()],
            |r| r.get(0),
        )?;
        let mut env = Envelope {
            fmt: myhsn_core::record::ENVELOPE_FORMAT_V1,
            algo: myhsn_core::record::AlgoTag::Blake3Ed25519,
            kind: payload.kind(),
            author: myhsn_core::identity::DevicePublicKey(node_pub),
            body_sig: myhsn_core::identity::sign(&seed, &body_bytes),
            body_bytes,
            stamp: NodeStamp::new(*channel, epoch, seq as u64, node_pub),
            stamp_sig: None,
            body_hash,
            blind_hash: RecordHash([0u8; 32]),
        };
        env.blind_hash = RecordHash::blind(&salt, env.body_hash.as_bytes());
        // doménová separácia podpisov (O10): telo sa podpisuje BEZ prefixu
        // (prvý bajt je CBOR array 0x80..=0x9f), pečiatka s STAMP_DOMAIN
        // (začína 'm' = 0x6d) — zámena je vylúčená, test v core
        env.stamp_sig = Some(myhsn_core::identity::sign(&seed, &env.stamp_signing_bytes()));
        let raw = env.encode();
        let hash = env.hash();
        tx.execute(
            "INSERT INTO records (hash, channel, node_epoch, node_seq, body_hash, blind_hash, \
             kind, author, raw) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                hash.as_bytes().as_slice(),
                channel.as_slice(),
                epoch as i64,
                seq,
                env.body_hash.as_bytes().as_slice(),
                env.blind_hash.as_slice(),
                env.kind.code() as i64,
                node_pub.as_slice(),
                raw,
            ],
        )?;
        Ok(env)
    }

    // --- pozvánky (MYHSN-56, O12/O13/O14) --------------------------------

    /// Vytvor single-use pozvánku. Vráti `(id, token)` — token sa vráti
    /// naplno LEN raz, v DB je výhradne BLAKE3 hash (vzor `sessions`).
    pub fn create_invite(
        &mut self,
        label: Option<String>,
        created_by: [u8; 32],
        now: u64,
        expires_at: Option<u64>,
    ) -> Result<(i64, [u8; 32]), StoreError> {
        let token = crate::auth::random_32();
        let token_hash = crate::auth::hash_session_token(&token);
        self.conn.execute(
            "INSERT INTO invites (token_hash, label, created_by, created_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                token_hash.as_slice(),
                label,
                created_by.as_slice(),
                now as i64,
                expires_at.map(|e| e as i64)
            ],
        )?;
        Ok((self.conn.last_insert_rowid(), token))
    }

    /// Zoznam pozvánok; `created_by = Some` filtruje len vlastné (moderátor).
    pub fn list_invites(
        &self,
        created_by: Option<&[u8; 32]>,
    ) -> Result<Vec<InviteRow>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, label, created_by, created_at, expires_at, used_by, used_at \
             FROM invites WHERE (?1 IS NULL OR created_by = ?1) ORDER BY id",
        )?;
        let rows = stmt.query_map(params![created_by.map(|b| b.as_slice())], |row| {
            let cb: Vec<u8> = row.get(2)?;
            Ok(InviteRow {
                id: row.get(0)?,
                label: row.get(1)?,
                created_by: arr32(&cb),
                created_at: row.get::<_, i64>(3)? as u64,
                expires_at: row.get::<_, Option<i64>>(4)?.map(|v| v as u64),
                used_by: row.get::<_, Option<Vec<u8>>>(5)?.as_deref().map(arr32),
                used_at: row.get::<_, Option<i64>>(6)?.map(|v| v as u64),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(StoreError::from)
    }

    /// Zmazí **nepoužitú** pozvánku. Admin môže všetky, moderator len
    /// vlastné (O14). Vráti `false` ak neexistuje alebo už bola použitá.
    pub fn delete_invite(
        &mut self,
        id: i64,
        by: &[u8; 32],
        is_admin: bool,
    ) -> Result<bool, StoreError> {
        let n = self.conn.execute(
            "DELETE FROM invites \
             WHERE id = ?1 AND used_by IS NULL AND (?2 OR created_by = ?3)",
            params![id, is_admin, by.as_slice()],
        )?;
        Ok(n == 1)
    }

    // --- administrátorský pohľad + reject (MYHSN-56) ---------------------

    pub fn list_users_admin(&self) -> Result<Vec<AdminUserRow>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, username, role, perms, status, created_at FROM accounts ORDER BY username",
        )?;
        let rows = stmt.query_map([], |row| {
            let id: Vec<u8> = row.get(0)?;
            Ok(AdminUserRow {
                id: arr32(&id),
                username: row.get(1)?,
                role: row.get::<_, i64>(2)? as u8,
                perms: row.get::<_, i64>(3)? as u32,
                status: row.get::<_, i64>(4)? as u8,
                created: row.get::<_, i64>(5)? as u64,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(StoreError::from)
    }

    /// **Reject pending účtu** (rozhodnutie Z2): vymaže účet aj jeho
    /// zariadenia a relácie a uvoľní meno. API to obmedzuje na pending —
    /// existujúci aktívny účet sa týmto mazať nemá.
    pub fn delete_account(&mut self, id: &[u8; 32]) -> Result<(), StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        // FK bez CASCADE (sessions/device_keys viažú na accounts) — mazať
        // od listov po koreň, inak SQLite odmietne DELETE účtu
        tx.execute("DELETE FROM sessions WHERE account_id = ?1", params![id.as_slice()])?;
        tx.execute("DELETE FROM device_keys WHERE account_id = ?1", params![id.as_slice()])?;
        tx.execute("DELETE FROM media WHERE account_id = ?1", params![id.as_slice()])?;
        let n = tx.execute("DELETE FROM accounts WHERE id = ?1", params![id.as_slice()])?;
        if n == 0 {
            return Err(StoreError::NoSuchAccount);
        }
        tx.commit()?;
        Ok(())
    }

    /// **F14a bootstrap pri štarte** (O2): ak uzol nemá admina a účet z
    /// `bootstrap_admin` už existuje (migrácia staršieho DB, alebo účet
    /// vytvorený skôr), povýš ho. Podmienka `NOT EXISTS(role=2)` je
    /// súčasťou UPDATE — atomické, bez TOCTOU. Vráti `true` ak povýšil.
    pub fn bootstrap_admin_at_startup(
        &mut self,
        username: &str,
    ) -> Result<bool, StoreError> {
        let n = self.conn.execute(
            "UPDATE accounts SET role = 2, status = 0 \
             WHERE username = ?1 AND NOT EXISTS (SELECT 1 FROM accounts WHERE role = 2)",
            params![username.trim()],
        )?;
        Ok(n == 1)
    }

    /// Runtime override politiky registrácie (meta KV). `None` = žiadny
    /// override → platí `[auth]` z TOML (O11).
    pub fn policy_override(&self) -> Result<Option<String>, StoreError> {
        Ok(self.meta_get(META_POLICY)?.map(|b| String::from_utf8_lossy(&b).into_owned()))
    }

    pub fn set_policy_override(&mut self, policy: Option<&str>) -> Result<(), StoreError> {
        match policy {
            None => {
                self.conn.execute("DELETE FROM meta WHERE key = ?1", params![META_POLICY])?;
                Ok(())
            }
            Some(p) => self.meta_set(META_POLICY, p.as_bytes()),
        }
    }
    // --- pomocné -------------------------------------------------------

    fn meta_get_in(tx: &rusqlite::Transaction<'_>, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(tx
            .query_row("SELECT value FROM meta WHERE key = ?1", params![key], |row| row.get(0))
            .ok())
    }

    fn meta_set_in(tx: &rusqlite::Transaction<'_>, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        tx.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }
}

fn arr32(v: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    if v.len() >= 32 {
        out.copy_from_slice(&v[..32]);
    } else {
        out[..v.len()].copy_from_slice(v);
    }
    out
}

/// Riadok logu pre čítací pohľad (B6): pozícia + stĺpce potrebné na
/// vyhodnotenie mazacích kindov. `hash` berieme zo stĺpca, nie z
/// `BLAKE3(raw)`, lebo po erase sa stĺpec `hash` stal novým hashom
/// nahradenej obálky a presne ten chceme porovnávať s cieľmi.
struct Row {
    pos: SeqPos,
    hash: [u8; 32],
    kind: i64,
    author: [u8; 32],
    raw: Vec<u8>,
}

/// Cieľ, na ktorý mazací záznam mieri (B6). Neplatná alebo nečitateľná
/// obálka vráti `None` — taký záznam sa do pohľadu dostane, len nič
/// nemaže (uzol ho prijíma až po overení, takže to je len poistka).
fn deletion_target(raw: &[u8]) -> Option<[u8; 32]> {
    let env = Envelope::decode(raw).ok()?;
    match env.payload().ok()? {
        Payload::Tombstone { target } => Some(target),
        Payload::Hide { target, .. } => Some(target),
        Payload::Erase { target, .. } => Some(target),
        _ => None,
    }
}

/// Rozlíši **vymenený rad po erase** od **akcie erase**. `Envelope::erased`
/// nastaví podpis autora na NIL (obsah už nie je čo podpisovať) a uzol pri
/// fyzickej výmene obsahu podpis autora nedopĺňa — naproti tomu erase
/// záznam, ktorý poslal klient, MUSÍ mať podpis autora (`deletion::evaluate`
/// inak záznam odmietne). NIL je teda spoľahlivý znak:
///
/// * `true`  → „tento rad už neobsahuje to, čo obsahoval“ (placeholder),
/// * `false` → „niekto niečo vymazal“ (akcia, klient podľa nej zmaže svoju
///   cache kópiu cieľa).
///
/// Oba druhy mienia ten istý cieľ, a preto sa v pohľade nesmú objaviť
/// naraz — inak by čitateľ videl placeholder dvakrát.
fn erased_view_sig_nil(raw: &[u8]) -> bool {
    Envelope::decode(raw)
        .ok()
        .map(|e| e.body_sig.is_nil())
        .unwrap_or(false)
}

/// **Fyzická náhrada obsahu cieľa** (B6, MYHSN-8, D-30) v bežiacej
/// transakcii. Číta obálku cieľa, zostaví pohľad `Envelope::erased(reason)`,
/// znova ho podpíše pečiatkou uzla a zapíše ho na **pôvodnú pozíciu**.
///
/// Menia sa stĺpce odvodené od obsahu (`hash`, `kind`, `body_hash`,
/// `blind_hash`, `raw`); pozícia `(channel, node_epoch, node_seq)`, `author`
/// a `client_hash` ostávajú zachované — záznam je stále ten istý záznam na
/// tom istom mieste logu, len bez obsahu. `blind_hash` ide na `NIL`, lebo
/// bez obsahu už slepý hash nič neindexuje (D-30).
fn apply_erase_in_tx(
    tx: &rusqlite::Transaction<'_>,
    target: &RecordHash,
    reason: EraseReason,
    seed: &[u8; 32],
) -> Result<(), StoreError> {
    let raw: Vec<u8> = tx
        .query_row(
            "SELECT raw FROM records WHERE hash = ?1",
            params![target.as_slice()],
            |row| row.get(0),
        )
        .map_err(|_| StoreError::EraseTargetMissing(*target))?;
    let env = Envelope::decode(&raw).map_err(StoreError::NotEnvelope)?;
    if env.kind == RecordKind::Erase {
        // Dvojitý erase by zahodil prvý dôvod — to je strata dôkazu, nie
        // idempotentná operácia. Volajúci (WS) to odmietne skôr, než vôbec
        // alokuje poradie; tu je to poistka voči priamemu volaniu.
        return Err(StoreError::IndexMismatch {
            reason: "cieľ erase je už vymazaný — dôvod by sa prepísal",
        });
    }

    let mut view = env.erased(reason);
    // **Pečiatku patrí súčasnému uzlu.** Nahradená obálka viaže inú
    // kombináciu (pozícia, nový `body_hash`), takže pôvodný podpis pečiatky
    // platil pre staré bajty a musíme ho podpísať znova. `signed_by_node`
    // pri tom prepíšeme na aktuálny operačný kľúč: D-25 hovorí, že poradie
    // (a tým aj pečiatka) prideľuje **domáci** uzol, a tým, že obsah
    // nahradzujeme, o ňom rozhodujeme práve my. Bez tohto prepisu by výmena
    // operačného kľúča (rotácia, obnova na inom stroji) znemožnila erase
    // starších záznamov — ich pečiatka by niesla starý kľúč a overenie by
    // zlyhalo.
    view.stamp.signed_by_node = myhsn_core::identity::public_from_seed(seed);
    view.stamp_sig = Some(myhsn_core::identity::sign(seed, &view.stamp_signing_bytes()));
    // Podpis musí sedieť k bajtom, ktoré práve ukladáme — inak by index
    // klamal (rovnaká kontrola ako pri bežnom appende).
    if !view.verify_stamp_sig() {
        return Err(StoreError::IndexMismatch {
            reason: "pečiatka nahradenej obálky sa nepodarilo overiť",
        });
    }
    let view_raw = view.encode();
    let view_hash = view.hash();

    let changed = tx.execute(
        "UPDATE records \
         SET hash = ?1, kind = ?2, body_hash = ?3, blind_hash = ?4, raw = ?5 \
         WHERE hash = ?6",
        params![
            view_hash.as_slice(),
            view.kind.code() as i64,
            view.body_hash.as_slice(),
            view.blind_hash.as_slice(),
            view_raw,
            target.as_slice(),
        ],
    )?;
    if changed != 1 {
        return Err(StoreError::EraseTargetMissing(*target));
    }
    Ok(())
}

// --- traity z core (D-29) ----------------------------------------------

impl RecordStore for Store {
    type Error = StoreError;

    /// Pridaj obálku na pozíciu `pos`. **Idempotentné podľa hashu** (D-25):
    /// druhý append rovnakého hashu nepridá duplikát. Bez `client_hash`
    /// (cesta B2/B3); WS append z B5 volá [`Store::insert_record`] priamo.
    fn append(&mut self, pos: &SeqPos, hash: &RecordHash, raw: &[u8]) -> Result<(), StoreError> {
        self.insert_record(pos, hash, raw, None)
    }

    /// Záznam podľa hashu — kanonický identifikátor (D-25).
    fn get(&self, hash: &RecordHash) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT raw FROM records WHERE hash = ?1",
                params![hash.as_slice()],
                |row| row.get(0),
            )
            .ok())
    }

    /// Rozsahový dotaz od watermarku nahor, zoradený podľa poradia.
    fn range(&self, q: &RangeQuery) -> Result<Vec<(SeqPos, Vec<u8>)>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT channel, node_epoch, node_seq, raw FROM records \
             WHERE channel = ?1 AND (node_epoch > ?2 OR (node_epoch = ?2 AND node_seq >= ?3)) \
             ORDER BY node_epoch, node_seq LIMIT ?4",
        )?;
        let rows = stmt.query_map(
            params![
                q.channel.as_slice(),
                q.from_epoch as i64,
                q.from_seq as i64,
                q.limit as i64
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )?;
        let mut out = Vec::new();
        for r in rows {
            let (ch, epoch, seq, raw) = r?;
            out.push((
                SeqPos::new(arr32(&ch), epoch as u64, seq as u64),
                raw,
            ));
        }
        Ok(out)
    }
}

impl MetaStore for Store {
    type Error = StoreError;

    fn meta_get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", params![key], |row| row.get(0))
            .ok())
    }

    fn meta_set(&mut self, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        Self::meta_set_in(&tx, key, value)?;
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use myhsn_core::channel::{ClientView, ChannelKind, reconcile};
    use myhsn_core::record::{EraseReason, NodeStamp, Payload};
    use myhsn_core::storage::RangeQuery;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Dočasný súbor s DB — nezávislý od iných testov.
    fn temp_db(label: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "myhsn-b2b3-{}-{}-{}-{}.db",
            label,
            std::process::id(),
            n,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        p
    }

    const AUTHOR_SEED: [u8; 32] = [0x21; 32];
    const NODE_SEED: [u8; 32] = [0x31; 32];

    fn envelope(channel: ChannelId, epoch: u64, seq: u64, text: &str) -> Envelope {
        Envelope::build(
            &AUTHOR_SEED,
            &Payload::Post {
                text: text.to_string(),
                media_ref: None,
            },
            NodeStamp::new(channel, epoch, seq, myhsn_core::identity::public_from_seed(&NODE_SEED)),
            b"so1",
            Some(&NODE_SEED),
        )
    }

    /// Schéma + WAL: migrácia je v kóde, verzia 6 (F14c), súbory používajú WAL.
    #[test]
    fn schema_version_2_and_wal_enabled() {
        let path = temp_db("schema");
        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), 6);
        assert_eq!(
            store.journal_mode().unwrap().to_lowercase(),
            "wal",
            "súborová DB musí mať WAL"
        );
        // opakované otvorenie nepadne a nemení schému
        drop(store);
        let again = Store::open(&path).unwrap();
        assert_eq!(again.schema_version().unwrap(), 6);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// **Migrácia B3 → B4 → B7 → B8:** súbor so schémou v1 (bez účtov/
    /// sessions/media) sa pri otvorení povýši na v4 a staré dáta prežijú.
    #[test]
    fn migrate_v1_file_upgrades_to_v2_keeping_data() {
        let path = temp_db("migrate");
        {
            // simuluj B3 uzol: schéma v1 + kanál + jeden záznam
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.pragma_update(None, "journal_mode", "WAL").unwrap();
            conn.execute_batch(MIGRATE_V1).unwrap();
            conn.pragma_update(None, "user_version", 1).unwrap();
            conn.execute(
                "INSERT INTO channels (id, name, kind, salt, node_epoch) VALUES (?1, 'stara', 0, ?2, 0)",
                params![vec![0x11u8; 32], vec![0x22u8; 32]],
            )
            .unwrap();
            conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
        }
        let mut store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), 6, "súbor musí povýšiť na v6");

        // staré dáta neprešli zmenou
        let chans = store.list_channels().unwrap();
        assert_eq!(chans.len(), 1);
        assert_eq!(chans[0].name, "stara");

        // nové tabuľky existujú a dajú sa používať
        let pass = crate::auth::hash_password("heslo").unwrap();
        let acc = store.create_account("jano", &pass, 100).unwrap();
        assert_eq!(acc.username, "jano");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// **Kritérium B2:** append → range v poradí podľa seq; duplicitný
    /// append podľa hashu nepridá záznam.
    #[test]
    fn append_range_order_and_idempotent_append() {
        let mut store = Store::open_in_memory().unwrap();
        let ch = [0x0c; 32];

        let e1 = envelope(ch, 0, 1, "prvy");
        let e2 = envelope(ch, 0, 2, "druhy");
        let e3 = envelope(ch, 0, 3, "treti");

        for e in [&e1, &e2, &e3] {
            let pos = SeqPos::new(ch, e.stamp.node_epoch, e.stamp.node_seq);
            store.append(&pos, &e.hash(), &e.encode()).unwrap();
        }
        assert_eq!(store.record_count().unwrap(), 3);

        // duplicitný append toho istého hashu → žiadny duplikát
        let pos1 = SeqPos::new(ch, 0, 1);
        store.append(&pos1, &e1.hash(), &e1.encode()).unwrap();
        store.append(&pos1, &e1.hash(), &e1.encode()).unwrap();
        assert_eq!(store.record_count().unwrap(), 3, "idempotentita podla hashu");

        // get podľa hashu vráti presne tie isté bajty
        assert_eq!(store.get(&e2.hash()).unwrap().as_deref(), Some(&e2.encode()[..]));
        assert!(store.get(&RecordHash([0u8; 32])).unwrap().is_none());

        // range od seq 2 nahor → [2, 3] v tomto poradí
        let q = RangeQuery {
            channel: ch,
            from_epoch: 0,
            from_seq: 2,
            limit: 10,
        };
        let got = store.range(&q).unwrap();
        assert_eq!(
            got.iter().map(|(p, _)| p.node_seq).collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert_eq!(got[0].1, e2.encode());

        // range s limitom 1 vráti len najstarší
        let q1 = RangeQuery {
            channel: ch,
            from_epoch: 0,
            from_seq: 1,
            limit: 1,
        };
        assert_eq!(store.range(&q1).unwrap().len(), 1);
    }

    /// Range triedi podľa (epocha, seq) — stará epocha je pred novou.
    #[test]
    fn range_orders_epoch_before_seq() {
        let mut store = Store::open_in_memory().unwrap();
        let ch = [0x0d; 32];
        // schválne vkladané v neporiadku
        let new1 = envelope(ch, 1, 1, "nova epocha 1");
        let old5 = envelope(ch, 0, 5, "stara epocha 5");
        for e in [&new1, &old5] {
            let pos = SeqPos::new(ch, e.stamp.node_epoch, e.stamp.node_seq);
            store.append(&pos, &e.hash(), &e.encode()).unwrap();
        }
        let q = RangeQuery {
            channel: ch,
            from_epoch: 0,
            from_seq: 0,
            limit: 10,
        };
        let got = store.range(&q).unwrap();
        assert_eq!(
            got.iter().map(|(p, _)| (p.node_epoch, p.node_seq)).collect::<Vec<_>>(),
            vec![(0, 5), (1, 1)]
        );
    }

    /// Pozícia obsadená iným záznamom → `PositionConflict` (nie tichý prepis).
    #[test]
    fn append_rejects_conflicting_position() {
        let mut store = Store::open_in_memory().unwrap();
        let ch = [0x0e; 32];
        let a = envelope(ch, 0, 1, "A");
        let b = envelope(ch, 0, 1, "B"); // iný obsah, rovnaká pozícia
        store
            .append(&SeqPos::new(ch, 0, 1), &a.hash(), &a.encode())
            .unwrap();
        let err = store
            .append(&SeqPos::new(ch, 0, 1), &b.hash(), &b.encode())
            .unwrap_err();
        assert!(matches!(err, StoreError::PositionConflict { node_seq: 1, .. }));
        assert_eq!(store.record_count().unwrap(), 1, "pôvodný záznam ostal");
    }

    /// Úloža odmietne bajty, ktoré nie sú obálkou, a hash, ktorý nesedí.
    #[test]
    fn append_rejects_non_envelope_and_wrong_hash() {
        let mut store = Store::open_in_memory().unwrap();
        let ch = [0x0f; 32];
        let pos = SeqPos::new(ch, 0, 1);
        let err = store.append(&pos, &RecordHash([1u8; 32]), b"nie je obalka").unwrap_err();
        assert!(matches!(err, StoreError::NotEnvelope(_)));

        let e = envelope(ch, 0, 1, "X");
        let err = store.append(&pos, &RecordHash([9u8; 32]), &e.encode()).unwrap_err();
        assert!(matches!(err, StoreError::IndexMismatch { .. }));
        assert_eq!(store.record_count().unwrap(), 0);
    }

    /// Meta KV (MetaStore trait) — roundtrip a prepis.
    #[test]
    fn meta_kv_roundtrip() {
        let mut store = Store::open_in_memory().unwrap();
        assert_eq!(store.meta_get(b"watermark").unwrap(), None);
        store.meta_set(b"watermark", b"0:5").unwrap();
        assert_eq!(store.meta_get(b"watermark").unwrap().as_deref(), Some(&b"0:5"[..]));
        store.meta_set(b"watermark", b"1:2").unwrap(); // prepis
        assert_eq!(store.meta_get(b"watermark").unwrap().as_deref(), Some(&b"1:2"[..]));
    }

    /// ID uzla je stabilné pri reštarte a uložené v meta.
    #[test]
    fn node_id_is_persistent() {
        let path = temp_db("nodeid");
        let id1 = {
            let mut s = Store::open(&path).unwrap();
            let id = s.node_id().unwrap();
            assert_eq!(s.meta_get(b"node_id").unwrap().unwrap().len(), 32);
            id
        };
        let id2 = {
            let mut s = Store::open(&path).unwrap();
            s.node_id().unwrap()
        };
        assert_eq!(id1, id2, "ID uzla musi prezit reštart");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// **Kritérium B3a:** dva zápisy do kanála dostanú seq 1, 2.
    #[test]
    fn two_writes_get_seq_one_and_two() {
        let mut store = Store::open_in_memory().unwrap();
        let ch = store
            .create_channel("nastienka", ChannelKind::Wall)
            .unwrap();
        let a = store.alloc_seq(&ch.id).unwrap();
        let b = store.alloc_seq(&ch.id).unwrap();
        assert_eq!((a.node_seq, b.node_seq), (1, 2), "poradie zacina na 1");
        assert_eq!(a.channel, ch.id);
        assert_eq!(a.node_epoch, 0);
        // a alokátor pokračuje
        assert_eq!(store.alloc_seq(&ch.id).unwrap().node_seq, 3);
    }

    /// Alokácia neznámeho kanála zlyhá (poradie nemôže visieť nad ničím).
    #[test]
    fn alloc_seq_requires_existing_channel() {
        let mut store = Store::open_in_memory().unwrap();
        let err = store.alloc_seq(&[0xab; 32]).unwrap_err();
        assert!(matches!(err, StoreError::NoSuchChannel(_)));
    }

    /// Kanály: vytvorenie, zoznam, druh, soľ; duplicitný názov sa odmietne.
    #[test]
    fn channel_crud_and_unique_name() {
        let mut store = Store::open_in_memory().unwrap();
        let wall = store.create_channel("nastienka", ChannelKind::Wall).unwrap();
        let chat = store.create_channel("chat-partia", ChannelKind::Chat).unwrap();
        assert_ne!(wall.id, chat.id, "id kanálov sa líšia");
        assert_ne!(wall.salt, chat.salt, "soľ je per kanál (D-25)");

        let list = store.list_channels().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "chat-partia"); // ORDER BY name
        assert_eq!(list[0].kind, ChannelKind::Chat);
        assert_eq!(list[1].kind, ChannelKind::Wall);
        assert_eq!(store.get_channel(&wall.id).unwrap().unwrap().name, "nastienka");

        let err = store.create_channel("nastienka", ChannelKind::Chat).unwrap_err();
        assert!(matches!(err, StoreError::ChannelNameTaken(_)));
        // prázdny názov sa tiež odmietne
        assert!(matches!(
            store.create_channel("   ", ChannelKind::Wall).unwrap_err(),
            StoreError::ChannelNameTaken(_)
        ));
    }

    /// **Kritérium B3b:** obnova zo zálohy → epocha +1, žiadny záznam
    /// nestratený, seq reštart z 1 v novej epoche.
    #[test]
    fn restore_from_backup_bumps_epoch_without_losing_records() {
        let path = temp_db("restore");
        let (ch, e1, e2) = {
            let mut store = Store::open(&path).unwrap();
            let ch = store.create_channel("nastienka", ChannelKind::Wall).unwrap();
            let mut written = Vec::new();
            for (seq, text) in [(1u64, "prvy"), (2u64, "druhy")] {
                let e = envelope(ch.id, 0, seq, text);
                store
                    .append(&SeqPos::new(ch.id, 0, seq), &e.hash(), &e.encode())
                    .unwrap();
                written.push(e);
            }
            assert_eq!(store.record_count().unwrap(), 2);
            (ch, written[0].clone(), written[1].clone())
        };

        // ZÁLOHA: skopíruj súbor (vrátane WAL, inak by sme o časti prišli)
        let backup = temp_db("restore-backup");
        for suffix in ["", "-wal", "-shm"] {
            let src = format!("{}{}", path.display(), suffix);
            if std::fs::metadata(&src).is_ok() {
                let _ = std::fs::copy(&src, format!("{}{}", backup.display(), suffix));
            }
        }

        // OBNOVA zo zálohy: z úložne sa stane stav pred výpadkom a uzol
        // zdvihne epochu (D-25).
        let mut store = Store::open(&backup).unwrap();
        assert_eq!(store.record_count().unwrap(), 2, "obnova nestratila záznamy");
        let epochs = store.restore_new_epoch().unwrap();
        assert_eq!(epochs, vec![(ch.id, 1)], "epocha +1");
        assert_eq!(store.channel_epoch(&ch.id).unwrap(), 1);

        // žiadny záznam nestratený — staré poradie je stále v logu
        assert_eq!(store.record_count().unwrap(), 2);
        assert!(store.get(&e1.hash()).unwrap().is_some());
        assert!(store.get(&e2.hash()).unwrap().is_some());
        let q = RangeQuery {
            channel: ch.id,
            from_epoch: 0,
            from_seq: 0,
            limit: 10,
        };
        let old = store.range(&q).unwrap();
        assert_eq!(
            old.iter().map(|(p, _)| (p.node_epoch, p.node_seq)).collect::<Vec<_>>(),
            vec![(0, 1), (0, 2)]
        );

        // seq reštart z 1 v novej epoche
        let fresh = store.alloc_seq(&ch.id).unwrap();
        assert_eq!((fresh.node_epoch, fresh.node_seq), (1, 1), "seq restart z 1");
        assert_eq!(store.alloc_seq(&ch.id).unwrap().node_seq, 2);

        // nový záznam v novej epoche sa uloží vedľa starých bez kolízie
        let e3 = envelope(ch.id, 1, 1, "po obnove");
        store
            .append(&SeqPos::new(ch.id, 1, 1), &e3.hash(), &e3.encode())
            .unwrap();
        assert_eq!(store.record_count().unwrap(), 3);
        let all = store.range(&q).unwrap();
        assert_eq!(
            all.iter().map(|(p, _)| (p.node_epoch, p.node_seq)).collect::<Vec<_>>(),
            vec![(0, 1), (0, 2), (1, 1)]
        );

        for p in [path.as_path(), backup.as_path()] {
            for suffix in ["", "-wal", "-shm"] {
                let f = format!("{}{}", p.display(), suffix);
                let _ = std::fs::remove_file(f);
            }
        }
    }

    /// **Kritérium B3c:** reconciliation nad range z úložne vráti presne
    /// chýbajúce hashe (jadro + SQLite spolu).
    #[test]
    fn reconcile_over_store_returns_exactly_missing_hashes() {
        let mut store = Store::open_in_memory().unwrap();
        let ch = store.create_channel("nastienka", ChannelKind::Wall).unwrap();

        // uzol má 4 záznamy v epoche 0
        let mut envs = Vec::new();
        for seq in 1..=4u64 {
            let e = envelope(ch.id, 0, seq, &format!("zaznam {seq}"));
            store
                .append(&SeqPos::new(ch.id, 0, seq), &e.hash(), &e.encode())
                .unwrap();
            envs.push(e);
        }

        // klient má 1, 2, 4 — chýba mu 3
        let mut client = ClientView::new(ch.id, 0);
        for seq in [1u64, 2, 4] {
            client.insert(seq, envs[(seq - 1) as usize].hash().0);
        }

        let log = store.channel_hashes(&ch.id).unwrap();
        let diff = reconcile(&log, &client);
        assert_eq!(diff.missing.len(), 1);
        assert_eq!(diff.missing[0].0.node_seq, 3);
        assert_eq!(diff.missing[0].1, envs[2].hash());
        assert!(diff.mismatched.is_empty());
        assert!(diff.client_extra.is_empty());
        assert!(!diff.stale_epoch);

        // a chýbajúci záznam vieme doviesť presne podľa range dotazu
        let q = RangeQuery {
            channel: ch.id,
            from_epoch: 0,
            from_seq: diff.missing[0].0.node_seq,
            limit: 1,
        };
        let fetched = store.range(&q).unwrap();
        assert_eq!(fetched[0].1, envs[2].encode());
    }

    /// Po obnove epochy reconciliation hlási starú epochu klienta a chýbajú
    /// záznamy novej epochy (B3b + B3c spolu).
    #[test]
    fn reconcile_after_epoch_restore_asks_for_new_epoch() {
        let mut store = Store::open_in_memory().unwrap();
        let ch = store.create_channel("nastienka", ChannelKind::Wall).unwrap();
        let old = envelope(ch.id, 0, 1, "stary");
        store
            .append(&SeqPos::new(ch.id, 0, 1), &old.hash(), &old.encode())
            .unwrap();

        store.restore_new_epoch().unwrap();
        let pos = store.alloc_seq(&ch.id).unwrap();
        assert_eq!((pos.node_epoch, pos.node_seq), (1, 1));
        let new1 = envelope(ch.id, 1, 1, "novy");
        store
            .append(&pos, &new1.hash(), &new1.encode())
            .unwrap();

        // klient je v epoche 0 a má seq 1 zo starej epochy
        let mut client = ClientView::new(ch.id, 0);
        client.insert(1, old.hash().0);

        let diff = reconcile(&store.channel_hashes(&ch.id).unwrap(), &client);
        assert!(diff.stale_epoch);
        // seq 1 novej epochy NIE je tá istá pozícia → chýba, nie nezhoda
        assert_eq!(diff.missing.len(), 1);
        assert_eq!((diff.missing[0].0.node_epoch, diff.missing[0].0.node_seq), (1, 1));
        assert!(diff.mismatched.is_empty());
    }

    /// Erase v logu (D-30): **nový záznam** s payloadom `Erase` na vlastnom
    /// poradí, ktorý sa uloží aj načíta bez straty dôvodu ani cieľa.
    ///
    /// Zároveň tu držíme invariant, na ktorom stojí B6: `Envelope::erased()`
    /// je *pohľad* na pôvodný záznam (rovnaká pozícia, nový hash) a **append**
    /// ho pod obsadenú pozíciu nesmie ticho prepísať. Fyzické nahradenie
    /// obsahu preto B6 nerobí appendom, ale explicitným `UPDATE`-om v tej
    /// istej transakcii ako vloženie erase záznamu
    /// ([`Store::insert_record_erasing`]).
    #[test]
    fn erase_record_roundtrips_through_store() {
        let mut store = Store::open_in_memory().unwrap();
        let ch = [0x1a; 32];
        let original = envelope(ch, 0, 1, "utriet obsah");
        store
            .append(&SeqPos::new(ch, 0, 1), &original.hash(), &original.encode())
            .unwrap();

        // erase záznam: uzol ho podpísal, cieľom je hash nahrádzaného
        // záznamu (to je to, čo pozná klient), dôvod zostáva
        let erase = Envelope::build(
            &NODE_SEED,
            &Payload::Erase {
                target: original.hash().0,
                reason: EraseReason::AuthorRequest,
                target_kind: RecordKind::Post,
            },
            NodeStamp::new(
                ch,
                0,
                2,
                myhsn_core::identity::public_from_seed(&NODE_SEED),
            ),
            b"so1",
            Some(&NODE_SEED),
        );
        store
            .append(&SeqPos::new(ch, 0, 2), &erase.hash(), &erase.encode())
            .unwrap();

        let raw = store.get(&erase.hash()).unwrap().unwrap();
        let back = Envelope::decode(&raw).unwrap();
        assert!(back.is_erased());
        assert_eq!(back.erased_reason(), Some(EraseReason::AuthorRequest));
        match back.payload().unwrap() {
            Payload::Erase { target, .. } => assert_eq!(target, original.hash().0),
            _ => panic!("erase payload"),
        }
        assert!(!String::from_utf8_lossy(&back.body_bytes).contains("utriet obsah"));

        // pohľad `erased()` (rovnaká pozícia) sa cez obálku prenesie, ale
        // pod obsadenú pozíciu ho úloža odmietne — nahradenie obsahu je B6
        let view = original.erased(EraseReason::Retention);
        let view_raw = view.encode();
        let decoded_view = Envelope::decode(&view_raw).unwrap();
        assert_eq!(decoded_view, view);
        assert_eq!(decoded_view.erased_reason(), Some(EraseReason::Retention));
        let err = store
            .append(&SeqPos::new(ch, 0, 1), &view.hash(), &view_raw)
            .unwrap_err();
        assert!(
            matches!(err, StoreError::PositionConflict { .. }),
            "pohľad po erase má pôvodnú pozíciu → kolízia, nie tichý prepis"
        );
    }

    // --- B6 (MYHSN-8): aplikačná vrstva mazania, rozhodnutie D-30 --------

    /// Dotaz na čítací pohľad od seq 1 (celý kanál).
    fn view_query(channel: ChannelId, from_seq: u64) -> RangeQuery {
        RangeQuery { channel, from_epoch: 0, from_seq, limit: 50 }
    }

    /// **Kritérium B6a:** tombstone cieľ **zmizne z pohľadu**. Surový log ho
    /// má stále (append-only, D-25), `visible_range` ho nevráti — a
    /// tombstone záznam áno, aby ho klient stihol vymazať aj zo svojej cache.
    #[test]
    fn tombstone_removes_target_from_the_read_view() {
        let mut store = Store::open_in_memory().unwrap();
        let ch = [0x2b; 32];
        let post = envelope(ch, 0, 1, "muj prispevok");
        store
            .append(&SeqPos::new(ch, 0, 1), &post.hash(), &post.encode())
            .unwrap();
        assert_eq!(store.range(&view_query(ch, 1)).unwrap().len(), 1, "surový log má príspevok");

        let ts = Envelope::build(
            &AUTHOR_SEED,
            &Payload::Tombstone { target: post.hash().0 },
            NodeStamp::new(ch, 0, 2, myhsn_core::identity::public_from_seed(&NODE_SEED)),
            b"so1",
            Some(&NODE_SEED),
        );
        store
            .append(&SeqPos::new(ch, 0, 2), &ts.hash(), &ts.encode())
            .unwrap();

        // čítací pohľad od nuly: príspevok už nikdy neuzrie
        let view = store.visible_range(&view_query(ch, 1), None).unwrap();
        assert_eq!(view.len(), 1, "cieľ zmizne, ostane len tombstone");
        assert_eq!((view[0].0.node_epoch, view[0].0.node_seq), (0, 2));
        assert_eq!(Envelope::decode(&view[0].1).unwrap().kind, RecordKind::Tombstone);

        // catch-up klienta, ktorý príspevok už má (watermark = seq 1):
        // dostane práve tombstone → vie, čo má vo svojej cache zmazať
        let catch_up = store.visible_range(&view_query(ch, 2), None).unwrap();
        assert_eq!(catch_up.len(), 1);
        assert_eq!(Envelope::decode(&catch_up[0].1).unwrap().kind, RecordKind::Tombstone);

        // surový log stále dokazuje, že niečo bolo (D-30: tombstone nie je erase)
        assert_eq!(store.range(&view_query(ch, 1)).unwrap().len(), 2);
    }

    /// **Kritérium B6b:** hide skryje cieľ **len pre účet, ktorý ho
    /// podpísal**. Bez čitateľa sa filter nedá aplikovať (WS ani REST nemajú
    /// autentizáciu) — hide záznam sa vráti a filter aplikuje klient.
    #[test]
    fn hide_hides_only_for_the_account_that_signed_it() {
        let mut store = Store::open_in_memory().unwrap();
        let ch = [0x2c; 32];
        let post = envelope(ch, 0, 1, "skry predo mnou");
        store
            .append(&SeqPos::new(ch, 0, 1), &post.hash(), &post.encode())
            .unwrap();

        // hide poslal iný účet, než je autor príspevku — hide smie ktokoľvek
        let hider_seed = [0x77u8; 32];
        let hider = myhsn_core::identity::public_from_seed(&hider_seed);
        let hide = Envelope::build(
            &hider_seed,
            &Payload::Hide { target: post.hash().0, reason: "nechcem to vidiet".into() },
            NodeStamp::new(ch, 0, 2, myhsn_core::identity::public_from_seed(&NODE_SEED)),
            b"so1",
            Some(&NODE_SEED),
        );
        store
            .append(&SeqPos::new(ch, 0, 2), &hide.hash(), &hide.encode())
            .unwrap();

        // bez čitateľa: viditeľné obidva (uzol nevie, kto číta)
        let anon = store.visible_range(&view_query(ch, 1), None).unwrap();
        assert_eq!(anon.len(), 2);

        // autor hide: jeho príspevok zmizne, hide záznam ostáva
        let me: Vec<_> = store
            .visible_range(&view_query(ch, 1), Some(&hider))
            .unwrap()
            .iter()
            .map(|(_, raw)| Envelope::decode(raw).unwrap().kind)
            .collect();
        assert_eq!(me, vec![RecordKind::Hide], "príspevok skrytý len pre autora hide");

        // cudzí čitateľ vidí príspevok ďalej — hide sa ho netýka
        let stranger = myhsn_core::identity::public_from_seed(&[0x12u8; 32]);
        let them: Vec<_> = store
            .visible_range(&view_query(ch, 1), Some(&stranger))
            .unwrap()
            .iter()
            .map(|(_, raw)| Envelope::decode(raw).unwrap().kind)
            .collect();
        assert_eq!(them, vec![RecordKind::Post, RecordKind::Hide]);
    }

    /// **Kritérium B6c (D-30, GDPR):** erase **fyzicky** nahradí bajty
    /// obsahu. Priamy SQL dotaz potvrdí, že text nie je v `raw`, zatiaľ čo
    /// pozícia, autor a **dôvod** ostávajú. Čítací pohľad ukáže práve jeden
    /// placeholder — nie dva.
    #[test]
    fn erase_replaces_body_bytes_and_keeps_reason() {
        let mut store = Store::open_in_memory().unwrap();
        let ch = [0x2d; 32];
        let post = envelope(ch, 0, 1, "tajny obsah na vymazanie");
        let target = post.hash();
        store
            .append(&SeqPos::new(ch, 0, 1), &target, &post.encode())
            .unwrap();
        assert!(
            String::from_utf8_lossy(&store.range(&view_query(ch, 1)).unwrap()[0].1)
                .contains("tajny obsah"),
            "pred erase je obsah v bajtoch"
        );

        let erase = Envelope::build(
            &AUTHOR_SEED,
            &Payload::Erase {
                target: target.0,
                reason: EraseReason::LegalOrder,
                target_kind: RecordKind::Post,
            },
            NodeStamp::new(ch, 0, 2, myhsn_core::identity::public_from_seed(&NODE_SEED)),
            b"so1",
            Some(&NODE_SEED),
        );
        store
            .insert_record_erasing(
                &SeqPos::new(ch, 0, 2),
                &erase.hash(),
                &erase.encode(),
                None,
                Some((&target, EraseReason::LegalOrder)),
            )
            .unwrap();

        // 1) priamy SQL: bajty sú preč, meta a dôvod ostávajú
        let (raw, kind, author, blind, epoch, seq): (Vec<u8>, i64, Vec<u8>, Vec<u8>, i64, i64) =
            store
                .conn
                .query_row(
                    "SELECT raw, kind, author, blind_hash, node_epoch, node_seq \
                     FROM records WHERE channel = ?1 AND node_seq = 1",
                    params![ch.as_slice()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
                )
                .unwrap();
        assert!(
            !String::from_utf8_lossy(&raw).contains("tajny obsah"),
            "bajty obsahu musia byť preč (D-30: fyzické nahradenie)"
        );
        assert_eq!(kind, RecordKind::Erase.code() as i64);
        assert_eq!(author, post.author.0, "autor ostáva — dôkaz, že niečo bolo");
        assert_eq!(blind, vec![0u8; 32], "slepý hash sa po erase ruší (D-30)");
        assert_eq!((epoch, seq), (0, 1), "pozícia v logu ostáva");
        let erased = Envelope::decode(&raw).unwrap();
        assert_eq!(
            erased.erased_reason(),
            Some(EraseReason::LegalOrder),
            "dôvod ostáva (kritérium: erase zmizne obsah ale zostane dôvod)"
        );
        assert_eq!(erased.stamp.signed_by_node, store.node_pub().unwrap());
        assert!(erased.verify_stamp_sig(), "uzol znova podpísal pečiatku nahradenej obálky");

        // 2) starý hash neexistuje — identifikátor je hash bajtov (D-25)
        assert!(store.get(&target).unwrap().is_none());

        // 3) čítací pohľad: práve JEDEN placeholder (akcia erase sa neopakuje)
        let kinds: Vec<_> = store
            .visible_range(&view_query(ch, 1), None)
            .unwrap()
            .iter()
            .map(|(_, raw)| Envelope::decode(raw).unwrap())
            .collect();
        assert_eq!(kinds.len(), 1, "vymenený rad + akcia → len vymenený rad");
        assert_eq!(kinds[0].kind, RecordKind::Erase);
        assert_eq!(kinds[0].erased_reason(), Some(EraseReason::LegalOrder));
    }

    /// **Hranica čítacieho pohľadu:** klient so watermarkom **nad** cieľom
    /// vymenený rad nevidí — potrebuje teda *akciu* erase, aby vedel, že má
    /// svoj cache záznam zmazať. To je dôvod, preho sa akcia nemaže vždy.
    #[test]
    fn erase_action_survives_for_reader_whose_watermark_skips_the_target() {
        let mut store = Store::open_in_memory().unwrap();
        let ch = [0x2e; 32];
        let post = envelope(ch, 0, 1, "prispevok nad watermarkom");
        let target = post.hash();
        store
            .append(&SeqPos::new(ch, 0, 1), &target, &post.encode())
            .unwrap();
        let erase = Envelope::build(
            &AUTHOR_SEED,
            &Payload::Erase {
                target: target.0,
                reason: EraseReason::AuthorRequest,
                target_kind: RecordKind::Post,
            },
            NodeStamp::new(ch, 0, 2, myhsn_core::identity::public_from_seed(&NODE_SEED)),
            b"so1",
            Some(&NODE_SEED),
        );
        store
            .insert_record_erasing(
                &SeqPos::new(ch, 0, 2),
                &erase.hash(),
                &erase.encode(),
                None,
                Some((&target, EraseReason::AuthorRequest)),
            )
            .unwrap();

        // watermark seq 1 → dobieha od seq 2, teda už nevidí vymenený rad
        let rows = store.visible_range(&view_query(ch, 2), None).unwrap();
        assert_eq!(rows.len(), 1);
        let env = Envelope::decode(&rows[0].1).unwrap();
        assert_eq!(env.kind, RecordKind::Erase);
        assert!(!env.body_sig.is_nil(), "je to akcia erase, nie vymenený rad");
        match env.payload().unwrap() {
            Payload::Erase { target: t, .. } => assert_eq!(
                t,
                post.hash().0,
                "akcia ukazuje na hash, pod ktorým má klient príspevok vo cache"
            ),
            _ => panic!("erase payload"),
        }
    }

    /// **Kritérium B6d (idempotentná aplikácia, D-29):** ten istý mazací
    /// záznam vložený dvakory nepridá druhý rad ani nedruhé mazanie.
    #[test]
    fn duplicate_deletion_record_is_idempotent() {
        let mut store = Store::open_in_memory().unwrap();
        let ch = [0x2f; 32];
        let post = envelope(ch, 0, 1, "duplikovany tombstone");
        let target = post.hash();
        store
            .append(&SeqPos::new(ch, 0, 1), &target, &post.encode())
            .unwrap();
        let ts = Envelope::build(
            &AUTHOR_SEED,
            &Payload::Tombstone { target: target.0 },
            NodeStamp::new(ch, 0, 2, myhsn_core::identity::public_from_seed(&NODE_SEED)),
            b"so1",
            Some(&NODE_SEED),
        );
        let pos = SeqPos::new(ch, 0, 2);
        store
            .insert_record(&pos, &ts.hash(), &ts.encode(), Some(&[5u8; 32]))
            .unwrap();
        // druhý pokus s tým istým `client_hash` (opakovaná WS správa)
        store
            .insert_record(&pos, &ts.hash(), &ts.encode(), Some(&[5u8; 32]))
            .unwrap();

        assert_eq!(store.record_count().unwrap(), 2, "druhý vklad nepridal rad");
        let view = store.visible_range(&view_query(ch, 1), None).unwrap();
        assert_eq!(view.len(), 1, "tombstone platí raz a príspevok je preč");
    }

    // --- B4 (MYHSN-6): účty, device keys, sessions ------------------------

    /// **Kritérium B4:** duplicitný username → `UsernameTaken`; účty s
    /// rôznymi menami vzniknú a hash hesla prežije načítanie.
    #[test]
    fn account_create_and_duplicate_username() {
        let mut store = Store::open_in_memory().unwrap();
        let pass = crate::auth::hash_password("dobre-heslo").unwrap();

        let acc = store.create_account("juraj", &pass, 1_000).unwrap();
        assert_eq!(acc.username, "juraj");
        assert_eq!(acc.created, 1_000);
        assert!(acc.password_argon2id_hash.starts_with("$argon2id$"));

        let dup = store.create_account("juraj", &pass, 1_001).unwrap_err();
        assert!(
            matches!(&dup, StoreError::UsernameTaken(u) if u == "juraj"),
            "duplicitný username → UsernameTaken, nie tichý prepis"
        );

        // načítanie podľa mena vráti ten istý hash (overenie prebieha až voči nemu)
        let loaded = store.account_by_username("juraj").unwrap().unwrap();
        assert_eq!(loaded.id, acc.id);
        assert_eq!(loaded.password_argon2id_hash, pass);
        assert!(crate::auth::verify_password("dobre-heslo", &loaded.password_argon2id_hash));
        assert!(store.account_by_username("nikto").unwrap().is_none());
    }

    /// **Kľúčové kritérium B4:** dve zariadenia toho istého účtu atestujú
    /// kľúče → oba aktívne; revokácia jedného → jeho podpis sa pri append
    /// odmietne (`device_account_if_active` → None), druhý ostáva platný.
    #[test]
    fn two_devices_then_revoke_one() {
        let mut store = Store::open_in_memory().unwrap();
        let pass = crate::auth::hash_password("heslo").unwrap();
        let acc = store.create_account("peto", &pass, 10).unwrap();

        let phone_seed = [0xe1; 32];
        let laptop_seed = [0xe2; 32];
        let phone = store
            .attest_device_key(&acc.id, &DevicePublicKey::from_seed(&phone_seed), "mobil", 11)
            .unwrap();
        let laptop = store
            .attest_device_key(&acc.id, &DevicePublicKey::from_seed(&laptop_seed), "notebook", 12)
            .unwrap();
        assert_ne!(phone.id, laptop.id);

        // oba kľúče aktívne → podpisy oboch zariadení sú overiteľné voči
        // device keys (overenie podpisu robí Envelope::validate + tento dotaz)
        let phone_pub = phone.key.public_key.0;
        let laptop_pub = laptop.key.public_key.0;
        assert_eq!(store.device_account_if_active(&phone_pub).unwrap(), Some(acc.id));
        assert_eq!(store.device_account_if_active(&laptop_pub).unwrap(), Some(acc.id));

        // skutočný podpis zariadenia overený voči atestovanému kľúču
        let msg = b"zaznam z mobilu";
        let sig = myhsn_core::identity::sign(&phone_seed, msg);
        assert!(phone.key.public_key.verify(msg, &sig));

        // revokácia notebooku
        assert!(store.revoke_device(&acc.id, laptop.id, 20).unwrap());
        assert_eq!(store.device_account_if_active(&laptop_pub).unwrap(), None);
        assert_eq!(store.device_account_if_active(&phone_pub).unwrap(), Some(acc.id));

        // idempotentná revokácia + revokácia cudzieho kľúča
        assert!(store.revoke_device(&acc.id, laptop.id, 21).unwrap());
        let other = store.create_account("inev", &pass, 30).unwrap();
        assert!(matches!(
            store.revoke_device(&other.id, laptop.id, 31).unwrap_err(),
            StoreError::NoSuchDevice(id) if id == laptop.id
        ));

        // zoznam ukazuje obe, s časom revokácie len pri revokovanom
        let devs = store.list_devices(&acc.id).unwrap();
        assert_eq!(devs.len(), 2);
        let revoked: Vec<_> = devs.iter().filter(|d| d.key.revoked_at.is_some()).collect();
        assert_eq!(revoked.len(), 1);
        assert_eq!(revoked[0].id, laptop.id);
        assert_eq!(revoked[0].key.revoked_at, Some(20));
    }

    /// Jeden kľúč nemôže patriť dvom účtom (D-26: množina kľúčov je
    /// per-účet, kľúč je identita zariadenia v uzle).
    #[test]
    fn device_key_is_unique_across_accounts() {
        let mut store = Store::open_in_memory().unwrap();
        let pass = crate::auth::hash_password("heslo").unwrap();
        let a = store.create_account("ucet-a", &pass, 1).unwrap();
        let b = store.create_account("ucet-b", &pass, 1).unwrap();
        let pk = DevicePublicKey::from_seed(&[0x77; 32]);

        store.attest_device_key(&a.id, &pk, "prvy", 2).unwrap();
        let err = store.attest_device_key(&b.id, &pk, "druhy", 3).unwrap_err();
        assert!(matches!(err, StoreError::DeviceKeyTaken));
        // ani ten istý účet nemôže atestovať ten istý kľúč dvakrát
        assert!(matches!(
            store.attest_device_key(&a.id, &pk, "znova", 4).unwrap_err(),
            StoreError::DeviceKeyTaken
        ));
        // neexistujúci účet → NoSuchAccount
        assert!(matches!(
            store.attest_device_key(&[9u8; 32], &DevicePublicKey::from_seed(&[1; 32]), "x", 5)
                .unwrap_err(),
            StoreError::NoSuchAccount
        ));
    }

    /// **Session tokeny (B4):** ukladá sa len hash; platný hash vráti
    /// účet, neplatný nic; expirovaná relácia nevráti nic a pri ďalšej
    /// registrácii sa vymaže.
    #[test]
    fn session_tokens_hashed_with_expiry() {
        let mut store = Store::open_in_memory().unwrap();
        let pass = crate::auth::hash_password("heslo").unwrap();
        let acc = store.create_account("sessionista", &pass, 100).unwrap();

        let token = crate::auth::new_session_token();
        let token_hash = crate::auth::hash_session_token(&token);
        store.put_session(&token_hash, &acc.id, 100, 30 * 86_400).unwrap();

        // platná relácia — vyhľadáva sa výhradne hashom
        assert_eq!(store.session_account(&token_hash, 200).unwrap(), Some(acc.id));
        assert_eq!(store.session_account(&[0u8; 32], 200).unwrap(), None);

        // expirácia: o 31 dní neskôr už relácia neplatí
        let later = 100 + 31 * 86_400;
        assert_eq!(store.session_account(&token_hash, later).unwrap(), None);

        // pri ďalšej relácii sa prešlé rady zmažú (údržba bez cronu)
        let t2 = crate::auth::new_session_token();
        let h2 = crate::auth::hash_session_token(&t2);
        store.put_session(&h2, &acc.id, later, 3_600).unwrap();
        let rows: i64 = store
            .conn
            .query_row("SELECT COUNT(1) FROM sessions", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 1, "expirovaná relácia mala byť vymazaná");
    }

    /// **D-27 (čiastočne):** operačný kľúč uzla je perzistentný, ID uzla
    /// sa odvodzuje od neho a pečiatky ním podpísané sa overia.
    #[test]
    fn node_sign_key_persistent_and_stamps_verify() {
        let path = temp_db("nodekey");
        let (seed, pubk);
        {
            let mut store = Store::open(&path).unwrap();
            seed = store.node_sign_seed().unwrap();
            pubk = store.node_pub().unwrap();
            assert_eq!(store.node_id().unwrap(), pubk, "node_id = verejný kľúč pečiatok");
            assert_eq!(store.node_sign_seed().unwrap(), seed, "seed je cache-stabilný");
        }
        // prežije reštart (perzistencia v meta)
        let mut again = Store::open(&path).unwrap();
        assert_eq!(again.node_sign_seed().unwrap(), seed);

        // obálka podpísaná týmto kľúčom sa overí voči node_id
        let ch = [0x0d; 32];
        let env = Envelope::build(
            &AUTHOR_SEED,
            &Payload::Post {
                text: "overitelna peciatka".to_string(),
                media_ref: None,
            },
            myhsn_core::record::NodeStamp::new(ch, 0, 1, pubk),
            b"so1",
            Some(&seed),
        );
        assert!(env.verify_stamp_sig(), "pečiatka musí sedieť s node_id");
        env.validate().unwrap();

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    // --- B5 (MYHSN-7): client_hash idempotencia ---------------------------

    /// **Kritérium B5c (úloža):** vklad s `client_hash` je unikátny —
    /// druhý vklad rovnakej správy vráti `ClientHashTaken` a dotaz
    /// vráti pôvodnú pozíciu + finálny hash (presné hodnoty pre `Ack`).
    #[test]
    fn insert_record_client_hash_idempotent() {
        let mut store = Store::open_in_memory().unwrap();
        let ch = store.create_channel("b5kanal", ChannelKind::Wall).unwrap();
        let seed = store.node_sign_seed().unwrap().to_vec();
        let mut seed32 = [0u8; 32];
        seed32.copy_from_slice(&seed);
        let node_pub = store.node_pub().unwrap();

        let client_raw = Envelope::build(
            &AUTHOR_SEED,
            &Payload::Post {
                text: "b5 sprava".to_string(),
                media_ref: None,
            },
            myhsn_core::record::NodeStamp::new(ch.id, 0, 0, [0u8; 32]),
            b"",
            None,
        )
        .encode();
        let client_hash = RecordHash::from_raw(&client_raw).0;

        // uzol opečiatkuje a vloží
        let pos = store.alloc_seq(&ch.id).unwrap();
        let mut env = Envelope::decode(&client_raw).unwrap();
        env.stamp = myhsn_core::record::NodeStamp::new(ch.id, pos.node_epoch, pos.node_seq, node_pub);
        env.blind_hash = ch.blind(&env.body_hash);
        env.stamp_sig = Some(myhsn_core::identity::sign(
            &seed32,
            &env.stamp_signing_bytes(),
        ));
        let raw = env.encode();
        let final_hash = env.hash();
        store.insert_record(&pos, &final_hash, &raw, Some(&client_hash)).unwrap();

        // druhý vklad tej istej správy — realistický pretek: alokovala sa
        // nová pozícia, finálny hash je iný, ale client_hash je ten istý
        // → UNIQUE index ho odmietne
        let pos2 = store.alloc_seq(&ch.id).unwrap();
        let mut env2 = env.clone();
        env2.stamp =
            myhsn_core::record::NodeStamp::new(ch.id, pos2.node_epoch, pos2.node_seq, node_pub);
        env2.stamp_sig = Some(myhsn_core::identity::sign(
            &seed32,
            &env2.stamp_signing_bytes(),
        ));
        let raw2 = env2.encode();
        let err = store
            .insert_record(&pos2, &env2.hash(), &raw2, Some(&client_hash))
            .unwrap_err();
        assert!(matches!(err, StoreError::ClientHashTaken));

        // dotaz vráti presne pôvodnú pozíciu a finálny hash
        let (found_pos, found_hash) = store.record_by_client_hash(&client_hash).unwrap().unwrap();
        assert_eq!((found_pos.node_epoch, found_pos.node_seq), (0, 1));
        assert_eq!(found_hash, final_hash);
        assert_eq!(store.record_position(&final_hash).unwrap(), Some(found_pos));
        assert_eq!(store.record_count().unwrap(), 1, "žiadny duplikát");
    }

    // --- B8 (MYHSN-22): migrácia v4, triedy médií, obálky, avatary ---------

    /// **Kritérium B8 (doc 24 §5.5):** migrácia v3 → v4 je len ADD COLUMN a
    /// zachová dáta. Súbor so schémou v3 (účty + kanály + media, bez
    /// display_name/cover/class) povýši na v4 a staré riadky prežijú; nové
    /// stĺpce existujú s správnymi defaultmi.
    #[test]
    fn migrate_v3_file_upgrades_to_v4_keeping_data() {
        let path = temp_db("migrate_v4");
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.pragma_update(None, "journal_mode", "WAL").unwrap();
            conn.execute_batch(MIGRATE_V1).unwrap();
            conn.execute_batch(MIGRATE_V2).unwrap();
            conn.execute_batch(MIGRATE_V3).unwrap();
            conn.pragma_update(None, "user_version", 3).unwrap();
            // staré dáta: kanál, účet, pominuteľný media riadok
            conn.execute(
                "INSERT INTO channels (id, name, kind, salt, node_epoch) VALUES (?1, 'stara', 0, ?2, 0)",
                params![vec![0x11u8; 32], vec![0x22u8; 32]],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO accounts (id, username, pass_hash, created_at) VALUES (?1, 'jano', 'phc', 100)",
                params![vec![0x33u8; 32]],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO media (id, account_id, size, hash, created_at, expires_at) \
                 VALUES ('malka', ?1, 42, ?2, 100, 200)",
                params![vec![0x33u8; 32], vec![0x44u8; 32]],
            )
            .unwrap();
            conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), 6, "súbor musí povýšiť na v6");

        // staré dáta prežili
        assert_eq!(store.list_channels().unwrap().len(), 1);
        assert_eq!(store.list_channels().unwrap()[0].name, "stara");
        let acc = store.account_by_username("jano").unwrap().unwrap();
        assert_eq!(acc.username, "jano");
        // starý media riadok má triedu 0 a mime NULL (default migrácie)
        let m = store.get_media("malka").unwrap().unwrap();
        assert_eq!(m.class, 0, "staré riadky dostanú triedu 0");
        assert_eq!(m.mime, None, "staré riadky nemajú mime → octet-stream");
        // nové stĺpce existujú a majú správne defaulty
        let covers = store.channel_cover_rows().unwrap();
        assert_eq!(covers.len(), 1);
        assert!(covers[0].cover.is_none(), "kanál bez obálky");
        assert_eq!(covers[0].meta_version, 0, "meta_version default 0");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    /// **Kritérium B8 (doc 24 §2):** kvota 200 MiB počíta **len triedu 0**.
    /// Avatar a obálka (trieda 1/2) sa do kvoty nezapočítavajú.
    #[test]
    fn quota_counts_only_ephemeral_class() {
        let mut store = Store::open_in_memory().unwrap();
        let pass = crate::auth::hash_password("heslo").unwrap();
        let acc = store.create_account("kvota", &pass, 100).unwrap();
        let now = 1_000i64;

        // pominuteľný 1000 B sa počíta
        store
            .insert_media("eph1", &acc.id, 1000, &[0xAA; 32], now, now + 86_400)
            .unwrap();
        assert_eq!(store.active_media_bytes(&acc.id, now).unwrap(), 1000);

        // avatar (trieda 1) a obálka (trieda 2) sa NEpočítavajú
        store
            .put_account_avatar(&acc.id, "av1", "image/png", 500_000, &[0xBB; 32], now)
            .unwrap();
        let ch = store.create_channel("nastienka", myhsn_core::channel::ChannelKind::Wall).unwrap();
        store
            .put_channel_cover(&ch.id, &acc.id, "cov1", "image/jpeg", 2_000_000, &[0xCC; 32], now)
            .unwrap();
        assert_eq!(
            store.active_media_bytes(&acc.id, now).unwrap(),
            1000,
            "trieda 1/2 nezvyšuje kvotu"
        );
        // trvalé bloby majú expires_at = i64::MAX
        assert_eq!(store.get_media("av1").unwrap().unwrap().expires_at, i64::MAX);
        assert_eq!(store.get_media("cov1").unwrap().unwrap().expires_at, i64::MAX);
        assert_eq!(store.get_media("cov1").unwrap().unwrap().class, 2);
    }

    /// **Kritérium B8 (doc 24 §2):** lazy cleanup maže **len triedu 0**.
    /// Aj keby trvalý riadok mal expiráciu v minulosti, filter ho chráni.
    #[test]
    fn cleanup_removes_only_class_zero() {
        let mut store = Store::open_in_memory().unwrap();
        let pass = crate::auth::hash_password("heslo").unwrap();
        let acc = store.create_account("upratovac", &pass, 100).unwrap();
        let now = 1_000i64;

        // pominuteľný expirovaný
        store
            .insert_media("eph-old", &acc.id, 10, &[0x11; 32], 100, 500)
            .unwrap();
        // pominuteľný živý
        store
            .insert_media("eph-new", &acc.id, 20, &[0x22; 32], 100, 5_000)
            .unwrap();
        // trvalý (avatar) — aj keby mal expires_at v minulosti, filter ho nechá
        store
            .put_account_avatar(&acc.id, "av-perm", "image/png", 30, &[0x33; 32], now)
            .unwrap();

        let removed = store.take_expired_media(1_000).unwrap();
        assert_eq!(removed, vec!["eph-old".to_string()], "len pominuteľný expirovaný");
        assert!(store.get_media("eph-new").unwrap().is_some());
        assert!(
            store.get_media("av-perm").unwrap().is_some(),
            "trvalý blob cleanup nesmie zmazať"
        );
    }

    /// **Kritérium B8 (doc 24 §2):** atomická výmena obálky — starý riadok
    /// zmizne, `meta_version` rastie, `set_by`/`set_at` sedia; clear vráti
    /// None a zmaže riadok.
    #[test]
    fn put_and_clear_channel_cover_atomic() {
        let mut store = Store::open_in_memory().unwrap();
        let pass = crate::auth::hash_password("heslo").unwrap();
        let acc = store.create_account("obalkar", &pass, 100).unwrap();
        let ch = store.create_channel("nastienka", myhsn_core::channel::ChannelKind::Wall).unwrap();
        let now = 2_000i64;

        let u1 = store
            .put_channel_cover(&ch.id, &acc.id, "cov-a", "image/jpeg", 100, &[0xA1; 32], now)
            .unwrap();
        assert_eq!(u1.meta_version, 1);
        assert_eq!(u1.old_media_id, None);

        let rows = store.channel_cover_rows().unwrap();
        let row = rows.iter().find(|r| r.id == ch.id).unwrap();
        let cover = row.cover.as_ref().expect("obálka nastavená");
        assert_eq!(cover.media_id, "cov-a");
        assert_eq!(cover.set_by.as_deref(), Some("obalkar"), "set_by = username");
        assert_eq!(cover.set_at, Some(now));
        assert_eq!(row.meta_version, 1);

        // výmena: starý riadok preč, nový tam, meta_version 2
        let u2 = store
            .put_channel_cover(&ch.id, &acc.id, "cov-b", "image/png", 200, &[0xB2; 32], now + 10)
            .unwrap();
        assert_eq!(u2.old_media_id.as_deref(), Some("cov-a"));
        assert_eq!(u2.meta_version, 2);
        assert!(store.get_media("cov-a").unwrap().is_none(), "starý riadok zmazaný");
        assert!(store.get_media("cov-b").unwrap().is_some());

        // clear: None, meta_version 3, riadok preč
        let cleared = store.clear_channel_cover(&ch.id).unwrap();
        assert_eq!(cleared.as_deref(), Some("cov-b"));
        assert!(store.get_media("cov-b").unwrap().is_none());
        let rows = store.channel_cover_rows().unwrap();
        assert!(rows.iter().find(|r| r.id == ch.id).unwrap().cover.is_none());
        assert_eq!(rows.iter().find(|r| r.id == ch.id).unwrap().meta_version, 3);

        // clear bez obálky = idempotentné None
        assert_eq!(store.clear_channel_cover(&ch.id).unwrap(), None);
        // clear neexistujúceho kanála = NoSuchChannel
        assert!(matches!(
            store.clear_channel_cover(&[0xEE; 32]),
            Err(StoreError::NoSuchChannel(_))
        ));
    }

    /// **Kritérium B8 (doc 24 §2):** atomická výmena avatara + clear.
    #[test]
    fn put_and_clear_account_avatar() {
        let mut store = Store::open_in_memory().unwrap();
        let pass = crate::auth::hash_password("heslo").unwrap();
        let acc = store.create_account("avatarac", &pass, 100).unwrap();
        let now = 3_000i64;

        let old = store
            .put_account_avatar(&acc.id, "av-1", "image/jpeg", 100, &[0x11; 32], now)
            .unwrap();
        assert_eq!(old, None);
        let row = store.account_by_id(&acc.id).unwrap().unwrap();
        assert_eq!(row.avatar.as_ref().unwrap().0, "av-1");
        assert_eq!(row.avatar.as_ref().unwrap().2.as_deref(), Some("image/jpeg"));

        let old = store
            .put_account_avatar(&acc.id, "av-2", "image/png", 200, &[0x22; 32], now + 1)
            .unwrap();
        assert_eq!(old.as_deref(), Some("av-1"));
        assert!(store.get_media("av-1").unwrap().is_none());

        let cleared = store.clear_account_avatar(&acc.id).unwrap();
        assert_eq!(cleared.as_deref(), Some("av-2"));
        assert!(store.account_by_id(&acc.id).unwrap().unwrap().avatar.is_none());
        // idempotentné
        assert_eq!(store.clear_account_avatar(&acc.id).unwrap(), None);
    }

    /// **Kritérium B8 (doc 24 §2):** sweep zmaže trvalé riadky bez
    /// ukazovateľa; pominuteľné a referencované nechá.
    #[test]
    fn sweep_removes_unreferenced_permanent_media() {
        let mut store = Store::open_in_memory().unwrap();
        let pass = crate::auth::hash_password("heslo").unwrap();
        let acc = store.create_account("sweepac", &pass, 100).unwrap();
        let ch = store.create_channel("nastienka", myhsn_core::channel::ChannelKind::Wall).unwrap();
        let now = 4_000i64;

        // referencované: obálka + avatar
        store
            .put_channel_cover(&ch.id, &acc.id, "cov-ref", "image/jpeg", 10, &[0x11; 32], now)
            .unwrap();
        store
            .put_account_avatar(&acc.id, "av-ref", "image/png", 10, &[0x22; 32], now)
            .unwrap();
        // sirota: trvalý riadok, na ktorý nič neukazuje (nahratý ale nepripojený)
        store
            .put_account_avatar(&acc.id, "av-orphan", "image/png", 10, &[0x33; 32], now)
            .unwrap();
        // tento PUT prepíše avatar na av-final a zmaže av-orphan riadok;
        // preto si orfana vytvoríme znova priamo, aby ostal sirota
        store
            .put_account_avatar(&acc.id, "av-final", "image/png", 10, &[0x44; 32], now)
            .unwrap();
        // av-orphan už bol zmazaný predchádzajúcim PUT-om; pridajme novú sirotu
        // priamo INSERT-om triedy 2 bez ukazovateľa
        store
            .insert_media_row_raw("cov-orphan", &acc.id, 10, &[0x55; 32], now, i64::MAX, 2, Some("image/jpeg"))
            .unwrap();
        // pominuteľný nechá sweep na pokoji
        store
            .insert_media("eph", &acc.id, 10, &[0x66; 32], now, now + 100)
            .unwrap();

        let dead = store.take_unreferenced_permanent_media().unwrap();
        assert_eq!(dead, vec!["cov-orphan".to_string()], "len trvalá sirota");
        assert!(store.get_media("cov-ref").unwrap().is_some());
        assert!(store.get_media("av-final").unwrap().is_some());
        assert!(store.get_media("eph").unwrap().is_some(), "pominuteľný sweep nerieši");
    }

    /// **Kritérium B8 (doc 24 §4):** display_name sa nastavuje a maza.
    #[test]
    fn display_name_set_and_clear() {
        let mut store = Store::open_in_memory().unwrap();
        let pass = crate::auth::hash_password("heslo").unwrap();
        let acc = store.create_account("meniac", &pass, 100).unwrap();
        assert_eq!(store.account_by_id(&acc.id).unwrap().unwrap().display_name, None);
        store.set_display_name(&acc.id, Some("Pokusník")).unwrap();
        assert_eq!(
            store.account_by_id(&acc.id).unwrap().unwrap().display_name.as_deref(),
            Some("Pokusník")
        );
        store.set_display_name(&acc.id, None).unwrap();
        assert_eq!(store.account_by_id(&acc.id).unwrap().unwrap().display_name, None);
        // neexistujúci účet → NoSuchAccount
        assert!(matches!(
            store.set_display_name(&[0xFF; 32], Some("x")),
            Err(StoreError::NoSuchAccount)
        ));
    }
    // --- F14a (MYHSN-56): roly, registrácia, pozvánky -------------------

    #[test]
    fn register_account_first_admin_is_atomic_and_second_is_user() {
        let path = temp_db("f14a-first-admin");
        let mut store = Store::open(&path).unwrap();
        assert!(!store.has_admin().unwrap());

        let o1 = store.register_account("adminka", "h", 1, true, false, false, None).unwrap();
        assert!(o1.became_admin, "prvý registrujúci s kandidatúrou sa stáva adminom");
        assert_eq!(o1.role, 2);
        assert!(store.has_admin().unwrap());

        // druhý už admina nenájde voľného — ostáva user, aj keby chcel
        let o2 = store.register_account("druhy", "h", 2, true, false, false, None).unwrap();
        assert!(!o2.became_admin && o2.role == 0);

        // duplicitné meno rollbackne aj pozvánku (nesmie sa minúť)
        let (id, token) = store.create_invite(None, [9u8; 32], 3, None).unwrap();
        let err = store
            .register_account("adminka", "h", 4, false, false, false, Some(&token))
            .unwrap_err();
        assert!(matches!(err, RegError::UsernameTaken(n) if n == "adminka"));
        let _ = id;
        // token je stále voľný
        let o3 = store
            .register_account("nova", "h", 5, false, false, false, Some(&token))
            .unwrap();
        assert!(o3.invite_consumed);
    }

    #[test]
    fn register_account_bootstrap_name_gating_and_startup_bootstrap() {
        // bootstrap_admin nastavený → povýši sa len zhodné meno
        let path = temp_db("f14a-bootstrap");
        let mut store = Store::open(&path).unwrap();
        let o = store.register_account("inejmeno", "h", 1, false, false, false, None).unwrap();
        assert_eq!(o.role, 0);
        assert!(!store.has_admin().unwrap());

        let o = store.register_account("manager_test", "h", 2, true, false, false, None).unwrap();
        assert!(o.became_admin, "zhodné meno s bootstrap_admin získa admina");

        // startup bootstrap na DB, kde účet existuje skôr a admin chýba
        let path2 = temp_db("f14a-bootstrap-startup");
        let mut s2 = Store::open(&path2).unwrap();
        s2.register_account("manager_test", "h", 1, false, false, false, None).unwrap();
        assert!(s2.bootstrap_admin_at_startup("manager_test").unwrap());
        assert!(s2.has_admin().unwrap());
        // druhý pokus už nepovýši (admin existuje — NOT EXISTS v UPDATE)
        assert!(!s2.bootstrap_admin_at_startup("manager_test").unwrap());
        // cudzie meno sa nikdy nepovýši
        s2.register_account("cudzinec", "h", 2, false, false, false, None).unwrap();
        assert!(!s2.bootstrap_admin_at_startup("cudzinec").unwrap());
    }

    #[test]
    fn invite_only_requires_valid_single_use_invite() {
        let path = temp_db("f14a-invites");
        let mut store = Store::open(&path).unwrap();
        let creator = [7u8; 32];
        let (_id, token) = store.create_invite(Some("susedka".into()), creator, 10, None).unwrap();

        let o = store
            .register_account("pozvany", "h", 10, false, true, false, Some(&token))
            .unwrap();
        assert!(o.invite_consumed && !o.pending);

        // single-use: rovnaký token druhýkrát → InviteInvalid
        let err = store
            .register_account("druhy", "h", 11, false, true, false, Some(&token))
            .unwrap_err();
        assert!(matches!(err, RegError::InviteInvalid));

        // bez pozvánky pod invite_only → InviteRequired
        let err = store.register_account("bez", "h", 12, false, true, false, None).unwrap_err();
        assert!(matches!(err, RegError::InviteRequired));

        // expirácia: expires_at=50, registrácia v 60 → InviteInvalid
        let (_id2, expired) = store.create_invite(None, creator, 20, Some(50)).unwrap();
        let err = store
            .register_account("neskory", "h", 60, false, true, false, Some(&expired))
            .unwrap_err();
        assert!(matches!(err, RegError::InviteInvalid));

        // list + mazanie: moderator vidí len vlastné, použitú nezmaže
        let list_all = store.list_invites(None).unwrap();
        assert_eq!(list_all.len(), 2);
        assert_eq!(list_all.iter().filter(|i| i.used_by.is_some()).count(), 1);
        let used_id = list_all.iter().find(|i| i.used_by.is_some()).unwrap().id;
        assert!(!store.delete_invite(used_id, &creator, true).unwrap(), "použitú nemožno zmazať");
        let other = [8u8; 32];
        let unused_id = list_all.iter().find(|i| i.used_by.is_none()).unwrap().id;
        assert!(
            !store.delete_invite(unused_id, &other, false).unwrap(),
            "moderator nema pravo k cudzej pozvanke"
        );
        assert!(store.delete_invite(unused_id, &creator, false).unwrap());
    }

    #[test]
    fn admin_approved_pending_blocks_ws_and_grant_activates() {
        let path = temp_db("f14a-pending");
        let mut store = Store::open(&path).unwrap();
        let o = store
            .register_account("cakajuci", "h", 10, false, false, true, None)
            .unwrap();
        assert!(o.pending, "admin_approved bez pozvánky → status 1");

        // pending nesmie písať cez WS: device_account_if_active ho vylúči
        let seed = [3u8; 32];
        let pk = myhsn_core::identity::public_from_seed(&seed);
        store
            .attest_device_key(&o.account.id, &myhsn_core::identity::DevicePublicKey(pk), "d", 10)
            .unwrap();
        assert_eq!(store.device_account_if_active(&pk).unwrap(), None);

        // grant = schválenie (Z2): rola moderator + aktivácia
        let granter = [5u8; 32];
        let env = store
            .apply_role_change(&o.account.id, 1, 5, false, Some((granter, [6u8; 32])))
            .unwrap();
        assert_eq!(env.kind, RecordKind::GrantRole);
        let (role, perms, status) = store.account_role(&o.account.id).unwrap().unwrap();
        assert_eq!((role, perms, status), (1, 5, 0), "grant schváli a nastaví perms");
        assert_eq!(store.device_account_if_active(&pk).unwrap(), Some(o.account.id));

        // audit záznam leží v systémovom kanáli a dekoduje sa
        let sys = store.system_channel_id().unwrap().unwrap();
        assert_eq!(env.stamp.channel, sys);
        let rows = store
            .visible_range(
                &RangeQuery { channel: sys, from_epoch: 0, from_seq: 0, limit: 10 },
                None,
            )
            .unwrap();
        assert_eq!(rows.len(), 1, "audit práve jeden záznam");
        let raw = rows[0].1.clone();
        let env2 = Envelope::decode(&raw).unwrap();
        assert_eq!(env2.kind, RecordKind::GrantRole);
        match env2.payload().unwrap() {
            Payload::GrantRole { target, target_name, role, perms, by, .. } => {
                assert_eq!(target, o.account.id);
                assert_eq!(target_name, "cakajuci");
                assert_eq!((role, perms), (1, 5));
                assert_eq!(by, granter);
            }
            other => panic!("očakával sa GrantRole, prišlo {other:?}"),
        }
    }

    #[test]
    fn apply_role_change_last_admin_invariant_and_second_admin() {
        let path = temp_db("f14a-last-admin");
        let mut store = Store::open(&path).unwrap();
        let admin = store
            .register_account("admin", "h", 1, true, false, false, None)
            .unwrap()
            .account;
        let druhy = store.register_account("druhy", "h", 2, false, false, false, None).unwrap();

        // posledného admina nemožno odomocniť (vrátane revokácie)
        let err = store
            .apply_role_change(&admin.id, 0, 0, true, Some((admin.id, [1u8; 32])))
            .unwrap_err();
        assert!(matches!(err, RoleError::LastAdmin));
        assert_eq!(store.account_role(&admin.id).unwrap().unwrap().0, 2, "rola ostala");

        // druhý admin → demota prvého už prejde
        store.apply_role_change(&druhy.account.id, 2, 0, false, Some((admin.id, [1u8; 32]))).unwrap();
        store.apply_role_change(&admin.id, 0, 0, false, Some((druhy.account.id, [2u8; 32]))).unwrap();
        assert_eq!(store.account_role(&admin.id).unwrap().unwrap().0, 0);
        assert!(store.has_admin().unwrap(), "druhy drží admina");

        // neexistujúci cieľ
        let err = store.apply_role_change(&[0u8; 32], 1, 0, false, None).unwrap_err();
        assert!(matches!(err, RoleError::NoSuchAccount));
    }

    #[test]
    fn system_channel_is_idempotent_and_name_reserved() {
        let path = temp_db("f14a-syschan");
        let mut store = Store::open(&path).unwrap();
        let a = store.ensure_system_channel().unwrap();
        let b = store.ensure_system_channel().unwrap();
        assert_eq!(a, b, "idempotentné");
        assert_eq!(store.system_channel_id().unwrap(), Some(a));
        // meno je obsadené → bežný create_channel ho nedostane
        assert!(matches!(
            store.create_channel("system", ChannelKind::Mixed),
            Err(StoreError::ChannelNameTaken(_))
        ));
        // auditné obálky majú korektný slepý hash so soľou kanála (D-25)
        let ch = store.get_channel(&a).unwrap().unwrap();
        let rows = store
            .visible_range(
                &RangeQuery { channel: a, from_epoch: 0, from_seq: 0, limit: 10 },
                None,
            )
            .unwrap();
        assert!(rows.is_empty(), "bez auditu je log prázdny");
        let granter = [4u8; 32];
        let u = store.register_account("uci", "h", 1, false, false, false, None).unwrap();
        let env = store
            .apply_role_change(&u.account.id, 1, 1, false, Some((granter, [5u8; 32])))
            .unwrap();
        assert_eq!(env.blind_hash, ch.blind(&env.body_hash));
        assert!(env.validate().is_ok(), "node-authored obálka prejde validate()");
    }

    // =====================================================================
    // F14c (MYHSN-58): skupinové kanály — migrácia V6, členstvo, role,
    // stíšenie, transfer a rebuild z append-only logu
    // =====================================================================

    /// Registrovaný účet → jeho id (testy pracujú s id, nie s heslami).
    fn acct(store: &mut Store, name: &str) -> [u8; 32] {
        store
            .register_account(name, "h", 1, false, false, false, None)
            .unwrap()
            .account
            .id
    }

    /// `.pre-v6.<ts>.bak` súbory vedľa `path` — robí ich migrácia V6.
    fn pre_v6_backups(path: &std::path::Path) -> Vec<std::path::PathBuf> {
        let dir = path.parent().unwrap();
        let stem = path.file_name().unwrap().to_string_lossy().to_string();
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let p = entry.unwrap().path();
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            if name.starts_with(&stem) && name.contains(".pre-v6.") {
                out.push(p);
            }
        }
        out.sort();
        out
    }

    /// Súbor so schémou **v5** — presne nasadený uzol pred F14c.
    fn db_at_v5(path: &std::path::Path) {
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
        for mig in [MIGRATE_V1, MIGRATE_V2, MIGRATE_V3, MIGRATE_V4, MIGRATE_V5] {
            conn.execute_batch(mig).unwrap();
        }
        conn.pragma_update(None, "user_version", 5).unwrap();
        conn.execute(
            "INSERT INTO channels (id, name, kind, salt, node_epoch) VALUES (?1, 'stara', 0, ?2, 0)",
            params![vec![0x11u8; 32], vec![0x22u8; 32]],
        )
        .unwrap();
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
        drop(conn);
    }

    fn rm_db(path: &std::path::Path) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{}", path.display(), suffix));
        }
    }

    /// **Migrácia V6:** súbory v5 dostanú `channels.owner` + `channel_members`,
    /// pred tým vznikne `.pre-v6.*.bak` s verziou 5 a do `meta` sadne
    /// `schema_compat = 6` (rozhodnutie F14c §5 — bez toho nie je rollback).
    #[test]
    fn v6_migration_adds_membership_tables_and_backups_first() {
        let path = temp_db("f14c-v6");
        db_at_v5(&path);
        assert!(pre_v6_backups(&path).is_empty(), "pred otvorením záloha nie je");

        let mut store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), 6, "súbor musí povýšiť na v6");
        assert_eq!(
            store.meta_get(META_SCHEMA_COMPAT).unwrap().as_deref(),
            Some(b"6".as_ref()),
            "schema_compat musí byť zapísané"
        );

        // staré dáta prežili a sú stále legacy (bez ownera, rozhodnutie §1)
        let chans = store.list_channels().unwrap();
        assert_eq!(chans.len(), 1);
        assert_eq!(chans[0].name, "stara");
        assert_eq!(store.channel_owner(&chans[0].id).unwrap(), Some(None));

        // nová tabuľka sa dá písať: group kanál vznikne a má ownera
        let owner = acct(&mut store, "v6owner");
        let (ch, env) = store
            .create_group_channel(
                "v6skupina",
                ChannelKind::Mixed,
                &owner,
                "v6owner",
                (owner, [1u8; 32]),
            )
            .unwrap();
        assert_eq!(store.channel_owner(&ch.id).unwrap(), Some(Some(owner)));
        assert_eq!(env.payload().unwrap().kind(), RecordKind::CreateChannel);

        // **záloha existuje a je to DB verzie 5** — bez nej nie je rollback
        let backups = pre_v6_backups(&path);
        assert_eq!(backups.len(), 1, "V6 migrácia urobí práve jednu zálohu");
        {
            let bak = rusqlite::Connection::open(&backups[0]).unwrap();
            let v: i64 = bak
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap();
            assert_eq!(v, 5, "záloha musí obsahovať stav PRED migráciou");
            let tables: i64 = bak
                .query_row(
                    "SELECT COUNT(1) FROM sqlite_master WHERE name = 'channel_members'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(tables, 0, "v zálohe ešte nie je tabuľka členov");
        }
        for b in &backups {
            let _ = std::fs::remove_file(b);
        }
        rm_db(&path);
    }

    /// **Guard `SchemaTooNew`:** novšiu schému binárka bez `schema_compat`
    /// odmietne a s ním ju otvorí bez prepísania (rozhodnutie F14c §5).
    #[test]
    fn schema_too_new_guard_respects_schema_compat() {
        let path = temp_db("f14c-compat");
        db_at_v5(&path);
        {
            // ruku simulujeme „novší uzol už tu písal“: schéma 7, žiadny compat
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(MIGRATE_V6).unwrap();
            conn.pragma_update(None, "user_version", 7).unwrap();
            conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
        }
        match Store::open(&path) {
            Ok(_) => panic!("bez compat kľúča musí byť migrácia fatálna"),
            Err(err) => assert!(
                matches!(err, StoreError::SchemaTooNew { found: 7, supported: 6 }),
                "dostali sme {err:?}"
            ),
        }
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
                params![META_SCHEMA_COMPAT, b"6".to_vec()],
            )
            .unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), 7, "novšiu schému nesmieme prepísať");
        rm_db(&path);
    }

    /// **Group vs. legacy:** group kanál má ownera a audit kind 8 žije v
    /// kanáli, ktorého sa týka; legacy kanál a systémový kanál ownera
    /// **nedostanú** (rozhodnutie F14c §1, §2).
    #[test]
    fn group_channel_has_owner_and_audit_legacy_does_not() {
        let mut store = Store::open_in_memory().unwrap();
        let owner = acct(&mut store, "gardas");
        let by = (owner, [2u8; 32]);
        let (ch, env) = store
            .create_group_channel("partia", ChannelKind::Mixed, &owner, "gardas", by)
            .unwrap();
        assert_eq!(store.channel_owner(&ch.id).unwrap(), Some(Some(owner)));
        assert!(
            store.channel_members(&ch.id).unwrap().is_empty(),
            "owner nie je riadok tabuľky členov (rozhodnutie §1)"
        );
        assert!(matches!(
            env.payload().unwrap(),
            Payload::CreateChannel { .. }
        ));

        // audit je v kanáli, nie v systémovom kanáli
        let rows = store
            .visible_range(
                &RangeQuery { channel: ch.id, from_epoch: 0, from_seq: 0, limit: 10 },
                None,
            )
            .unwrap();
        assert_eq!(rows.len(), 1, "create_channel audit v tomto kanáli");
        let audit = Envelope::decode(&rows[0].1).unwrap();
        assert_eq!(audit.payload().unwrap().kind(), RecordKind::CreateChannel);

        // legacy kanál: owner NULL
        let legacy = store.create_channel("verejny", ChannelKind::Wall).unwrap();
        assert_eq!(store.channel_owner(&legacy.id).unwrap(), Some(None));
        // systémový kanál (audit rolí) je tiež legacy — main ho tvorí pri
        // štarte uzla, tu ho zavoláme ručne
        let sys = store.ensure_system_channel().unwrap();
        assert_eq!(store.system_channel_id().unwrap(), Some(sys));
        assert_eq!(store.channel_owner(&sys).unwrap(), Some(None));
        // neexistujúci kanál = None, nie Some(None)
        assert_eq!(store.channel_owner(&[0x7fu8; 32]).unwrap(), None);

        // `channel_owners` vidí všetky tri stavy naraz
        let owners = store.channel_owners().unwrap();
        let found = |id: &ChannelId| owners.iter().find(|(c, _)| c == id).map(|(_, o)| *o);
        assert_eq!(found(&ch.id), Some(Some(Some(owner))));
        assert_eq!(found(&legacy.id), Some(Some(None)));
        assert_eq!(found(&[0x7fu8; 32]), None);
    }

    /// **Členstvo:** pridanie, povýšenie, odobranie + všetky strojové stavy
    /// chýb (`already_member`, `not_member`, `account_not_found`,
    /// `not_group_channel`, owner nesmie byť odobraný).
    #[test]
    fn group_membership_add_role_remove_and_error_states() {
        let mut store = Store::open_in_memory().unwrap();
        let owner = acct(&mut store, "owner");
        let member = acct(&mut store, "member");
        let stranger = acct(&mut store, "cudzie");
        let ghost = [0x9eu8; 32];
        let by = (owner, [1u8; 32]);
        let (ch, _) = store
            .create_group_channel("skupina", ChannelKind::Mixed, &owner, "owner", by)
            .unwrap();

        store.channel_add_member(&ch.id, &member, by).unwrap();
        let rows = store.channel_members(&ch.id).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].account, member);
        assert_eq!(rows[0].role, 0, "pridaný účet je member");
        assert_eq!(rows[0].username, "member");
        assert_eq!(rows[0].added_by, Some(owner));

        // duplicita + owner (ten už v kanáli je) + neznámy účet
        assert!(matches!(
            store.channel_add_member(&ch.id, &member, by),
            Err(ChannelError::AlreadyMember)
        ));
        assert!(matches!(
            store.channel_add_member(&ch.id, &owner, by),
            Err(ChannelError::AlreadyMember)
        ));
        assert!(matches!(
            store.channel_add_member(&ch.id, &ghost, by),
            Err(ChannelError::NoSuchAccount)
        ));

        // povýšenie na channel admina + právomoc
        store.channel_set_role(&ch.id, &member, 1, by).unwrap();
        assert_eq!(store.channel_members(&ch.id).unwrap()[0].role, 1);
        let auth = store.channel_authority(&ch.id, &member).unwrap().unwrap();
        assert!(auth.group && auth.is_member() && auth.can_delete());
        assert_eq!(auth.rank(), 2, "channel admin má hodnosť 2");
        // neznáma rola (2 = owner) je chyba, nie tichý prepis
        assert!(matches!(
            store.channel_set_role(&ch.id, &member, 2, by),
            Err(ChannelError::InvalidRole)
        ));
        // role pre člena, ktorý v kanáli nie je
        assert!(matches!(
            store.channel_set_role(&ch.id, &stranger, 1, by),
            Err(ChannelError::NotMember)
        ));

        // owner: efektívna rola z `channels.owner`, nie z tabuľky
        let owner_auth = store.channel_authority(&ch.id, &owner).unwrap().unwrap();
        assert_eq!(owner_auth.role, Some(2));
        assert_eq!(owner_auth.rank(), 3);
        assert!(owner_auth.is_member() && owner_auth.can_delete());

        // cudziec: nie člen, bez práva mazať
        let s_auth = store.channel_authority(&ch.id, &stranger).unwrap().unwrap();
        assert!(!s_auth.is_member() && !s_auth.can_delete() && s_auth.rank() == 0);
        // neexistujúci kanál
        assert!(store.channel_authority(&[0x5au8; 32], &member).unwrap().is_none());

        // odobranie + duplikát + owner
        store.channel_revoke_member(&ch.id, &member, by).unwrap();
        assert!(store.channel_members(&ch.id).unwrap().is_empty());
        assert!(matches!(
            store.channel_revoke_member(&ch.id, &member, by),
            Err(ChannelError::NotMember)
        ));
        assert!(matches!(
            store.channel_revoke_member(&ch.id, &owner, by),
            Err(ChannelError::OwnerCannotBeRemoved)
        ));

        // legacy kanál nemá membership model vôbec
        let legacy = store.create_channel("legacy", ChannelKind::Wall).unwrap();
        assert!(matches!(
            store.channel_add_member(&legacy.id, &member, by),
            Err(ChannelError::NotGroupChannel)
        ));
        assert!(matches!(
            store.channel_revoke_member(&legacy.id, &member, by),
            Err(ChannelError::NotGroupChannel)
        ));
        assert!(matches!(
            store.channel_transfer_owner(&legacy.id, &member, 1, by),
            Err(ChannelError::NotGroupChannel)
        ));
        let legacy_auth = store.channel_authority(&legacy.id, &member).unwrap().unwrap();
        assert!(!legacy_auth.group && legacy_auth.role.is_none());
        // v legacy kanáli môže mazť len server-level správca
        assert!(!legacy_auth.can_delete());
    }

    /// **Transfer ownera (rozhodnutie §8):** jeden audit, kanál nemá okamih
    /// bez ownera; `previous_role` rozhodne o osude predošlého ownera;
    /// transfer samému sebe je 409.
    #[test]
    fn transfer_owner_moves_owner_and_applies_previous_role() {
        let mut store = Store::open_in_memory().unwrap();
        let owner = acct(&mut store, "povodny");
        let member = acct(&mut store, "clen");
        let ghost = [0x33u8; 32];
        let by = (owner, [1u8; 32]);
        let (ch, _) = store
            .create_group_channel("dedictvo", ChannelKind::Mixed, &owner, "povodny", by)
            .unwrap();
        store.channel_add_member(&ch.id, &member, by).unwrap();

        let env = store.channel_transfer_owner(&ch.id, &member, 1, by).unwrap();
        assert!(matches!(
            env.payload().unwrap(),
            Payload::TransferChannelOwner { .. }
        ));
        assert_eq!(store.channel_owner(&ch.id).unwrap(), Some(Some(member)));
        let rows = store.channel_members(&ch.id).unwrap();
        assert_eq!(rows.len(), 1, "nový owner nie je riadok, predošlý áno");
        assert_eq!(rows[0].account, owner);
        assert_eq!(rows[0].role, 1, "previous_role=admin");
        // nový owner má hodnosť ownera, predošlý klesol na channel admina
        assert_eq!(store.channel_authority(&ch.id, &member).unwrap().unwrap().rank(), 3);
        assert_eq!(store.channel_authority(&ch.id, &owner).unwrap().unwrap().rank(), 2);

        // transfer samému sebe
        assert!(matches!(
            store.channel_transfer_owner(&ch.id, &member, 1, by),
            Err(ChannelError::AlreadyOwner)
        ));
        // neznámy cieľ
        assert!(matches!(
            store.channel_transfer_owner(&ch.id, &ghost, 1, by),
            Err(ChannelError::NoSuchAccount)
        ));
        // neplatná previous_role
        assert!(matches!(
            store.channel_transfer_owner(&ch.id, &owner, 7, by),
            Err(ChannelError::InvalidRole)
        ));

        // previous_role = none → predošlý owner z kanála odíde
        let by_new = (member, [1u8; 32]);
        store.channel_transfer_owner(&ch.id, &owner, u8::MAX, by_new).unwrap();
        assert_eq!(store.channel_owner(&ch.id).unwrap(), Some(Some(owner)));
        assert!(store.channel_members(&ch.id).unwrap().is_empty());
        assert!(!store.channel_authority(&ch.id, &member).unwrap().unwrap().is_member());
    }

    /// **Stíšenie (rozhodnutie §7):** materializovaný stav bez auditu,
    /// hranica `now == muted_until` už stíšenie ukončuje, ownera stíšiť
    /// nemožno.
    #[test]
    fn mute_is_materialized_expires_and_skips_owner() {
        let mut store = Store::open_in_memory().unwrap();
        let owner = acct(&mut store, "owner");
        let member = acct(&mut store, "member");
        let by = (owner, [1u8; 32]);
        let (ch, _) = store
            .create_group_channel("ticho", ChannelKind::Mixed, &owner, "owner", by)
            .unwrap();
        store.channel_add_member(&ch.id, &member, by).unwrap();

        let now = Store::now_secs();
        let until = now + 3600;
        store.channel_set_mute(&ch.id, &member, until).unwrap();
        let auth = store.channel_authority(&ch.id, &member).unwrap().unwrap();
        assert_eq!(auth.muted_until, Some(until));
        assert!(auth.muted(now), "v čase pred hranicou je stíšený");
        assert!(!auth.muted(until), "práve na hranici už stíšený nie je");
        assert_eq!(
            store.channel_members(&ch.id).unwrap()[0].muted_until,
            Some(until)
        );
        // stíšenie nemení rolu ani nepíše audit (log má len 8 – 11)
        assert_eq!(store.channel_members(&ch.id).unwrap()[0].role, 0);

        // owner sa stíšiť nedá, nečlen tiež nie
        assert!(matches!(
            store.channel_set_mute(&ch.id, &owner, until),
            Err(ChannelError::OwnerNotMutable)
        ));
        assert!(matches!(
            store.channel_set_mute(&ch.id, &[0x41u8; 32], until),
            Err(ChannelError::NotMember)
        ));

        // zrušenie a duplikát
        store.channel_clear_mute(&ch.id, &member).unwrap();
        assert!(!store.channel_authority(&ch.id, &member).unwrap().unwrap().muted(now));
        assert!(matches!(
            store.channel_clear_mute(&ch.id, &member),
            Err(ChannelError::NotMuted)
        ));
        assert!(matches!(
            store.channel_clear_mute(&ch.id, &[0x41u8; 32]),
            Err(ChannelError::NotMember)
        ));
    }

    /// **Zdroj 5. prvku `HelloAck`:** zoznam group kanálov s efektívnou
    /// rolou — utriedený podľa bajtov kanála, bez kanálov bez vzťahu,
    /// stíšenie sa prenáša a owner nie je nikdy `muted`.
    #[test]
    fn channel_roles_for_account_is_sorted_and_scoped_to_groups() {
        let mut store = Store::open_in_memory().unwrap();
        let owner = acct(&mut store, "owner");
        let member = acct(&mut store, "member");
        let by = (owner, [1u8; 32]);

        let (g1, _) = store
            .create_group_channel("skupina-a", ChannelKind::Mixed, &owner, "owner", by)
            .unwrap();
        let (g2, _) = store
            .create_group_channel("skupina-b", ChannelKind::Chat, &owner, "owner", by)
            .unwrap();
        store.channel_add_member(&g1.id, &member, by).unwrap();
        store.channel_add_member(&g2.id, &member, by).unwrap();
        store.channel_set_role(&g2.id, &member, 1, by).unwrap();
        let until = Store::now_secs() + 60;
        store.channel_set_mute(&g1.id, &member, until).unwrap();
        // legacy kanál sa v zozname neobjaví
        let legacy = store.create_channel("verejny", ChannelKind::Wall).unwrap();

        let roles = store.channel_roles_for_account(&member, Store::now_secs()).unwrap();
        assert_eq!(roles.len(), 2, "len group kanály, v ktorých je člen");
        assert_eq!(roles.iter().find(|(c, _, _)| *c == g1.id).unwrap().1, 0);
        assert!(roles.iter().find(|(c, _, _)| *c == g1.id).unwrap().2, "stíšenie sa prenáša");
        assert_eq!(roles.iter().find(|(c, _, _)| *c == g2.id).unwrap().1, 1);
        assert!(!roles.iter().any(|(c, _, _)| *c == legacy.id));
        // zoznam je utriedený podľa bajtov id (deterministický na drôte)
        let mut sorted = roles.clone();
        sorted.sort_by_key(|(c, _, _)| *c);
        assert_eq!(roles, sorted);

        // owner: rola 2 a nikdy nie stíšený; v kanáli, kde nie je, nie je
        let owner_roles = store.channel_roles_for_account(&owner, Store::now_secs()).unwrap();
        assert_eq!(owner_roles.len(), 2);
        assert!(owner_roles.iter().all(|(_, code, muted)| *code == 2 && !muted));
        let stranger = acct(&mut store, "cudzie");
        assert!(store.channel_roles_for_account(&stranger, Store::now_secs()).unwrap().is_empty());

        // exportovaný zoznam sa zmení, keď člena odoberieme
        store.channel_revoke_member(&g1.id, &member, by).unwrap();
        let after = store.channel_roles_for_account(&member, Store::now_secs()).unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].0, g2.id);
    }

    /// **Rebuild z logu:** materializovaný stav členstva je derivát auditov
    /// kind 8 – 11 — po premazaní tabuľky sa postaví znova. `muted_until`
    /// z logu nevystopovateľné, rebuild ho zruší (zdokumentované §7).
    #[test]
    fn rebuild_members_from_log_restores_materialized_state() {
        let mut store = Store::open_in_memory().unwrap();
        let owner = acct(&mut store, "rebuild-owner");
        let a1 = acct(&mut store, "rebuild-a1");
        let a2 = acct(&mut store, "rebuild-a2");
        let by = (owner, [3u8; 32]);
        let (ch, _) = store
            .create_group_channel("rebuild", ChannelKind::Mixed, &owner, "rebuild-owner", by)
            .unwrap();
        store.channel_add_member(&ch.id, &a1, by).unwrap();
        store.channel_add_member(&ch.id, &a2, by).unwrap();
        store.channel_set_role(&ch.id, &a1, 1, by).unwrap();
        store.channel_set_mute(&ch.id, &a2, Store::now_secs() + 3600).unwrap();
        // transfer: a1 je owner, predošlý owner ostane admin
        store.channel_transfer_owner(&ch.id, &a1, 1, by).unwrap();

        let before = store.channel_members(&ch.id).unwrap();
        let owner_before = store.channel_owner(&ch.id).unwrap();
        assert_eq!(owner_before, Some(Some(a1)));
        assert_eq!(before.len(), 2, "a1 je owner (nie riadok), a2 member, predošlý admin");

        // simuluj stratu materializovaného stavu (tabuľka členov preč)
        store.conn.execute_batch("DELETE FROM channel_members;").unwrap();
        assert!(store.channel_members(&ch.id).unwrap().is_empty());

        let written = store.rebuild_channel_members_from_log().unwrap();
        assert_eq!(written, 2, "rebuild napíše práve dvoch členov");
        assert_eq!(
            store.channel_owner(&ch.id).unwrap(),
            owner_before,
            "owner kanála zostáva z auditu kind 11"
        );
        let after = store.channel_members(&ch.id).unwrap();
        let role_of = |rows: &[ChannelMemberRow], id: &[u8; 32]| {
            rows.iter().find(|r| r.account == *id).map(|r| r.role)
        };
        assert_eq!(role_of(&after, &a1), None, "owner nie je riadok");
        assert_eq!(role_of(&after, &a2), Some(0));
        assert_eq!(role_of(&after, &owner), Some(1));
        // stíšenie nie je v logu → rebuild ho zruší (vlastnosť, nie chyba)
        assert_eq!(
            after.iter().find(|r| r.account == a2).unwrap().muted_until,
            None
        );
        // rebuild je idempotentný
        assert_eq!(store.rebuild_channel_members_from_log().unwrap(), 2);
        assert_eq!(store.channel_members(&ch.id).unwrap().len(), 2);
    }

    /// **Deaktivácia účtu (rozhodnutie §15):** členstvo **nepatrí** mazť,
    /// ale nový zápis do kanála pre neaktívny účet nesmie prejsť.
    #[test]
    fn inactive_account_keeps_membership_but_cannot_be_added() {
        let mut store = Store::open_in_memory().unwrap();
        let owner = acct(&mut store, "owner");
        let member = acct(&mut store, "member");
        let by = (owner, [1u8; 32]);
        let (ch, _) = store
            .create_group_channel("nesmrtelna", ChannelKind::Mixed, &owner, "owner", by)
            .unwrap();
        store.channel_add_member(&ch.id, &member, by).unwrap();

        // deaktivuj účet priamo (api vrstva to robí rovnakým UPDATE-om)
        store
            .conn
            .execute("UPDATE accounts SET status = 1 WHERE id = ?1", params![member.as_slice()])
            .unwrap();

        // členstvo prežíva (GDPR/audit: log sa neprepisuje)
        assert_eq!(store.channel_members(&ch.id).unwrap().len(), 1);
        // ale pridať ho znova nesmie
        assert!(matches!(
            store.channel_add_member(&ch.id, &member, by),
            Err(ChannelError::AccountInactive) | Err(ChannelError::AlreadyMember)
        ));
        // transfer na neaktívny účet je 409
        assert!(matches!(
            store.channel_transfer_owner(&ch.id, &member, 1, by),
            Err(ChannelError::AccountInactive)
        ));
    }
}
