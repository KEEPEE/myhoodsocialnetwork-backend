//! Role a bitmask práva (F14a, MYHSN-56).
//!
//! Sans-IO: tento modul obsahuje **len typy a ich kódovanie** — žiadne
//! rozhodovanie o oprávneniach (to patrí do uzla, vedľa [`crate`]-level
//! pravidlá v `crates/node/src/roles.rs` a `deletion.rs` — jadro nesmie
//! poznať politiku, D-29).
//!
//! Model (rozhodnutie F14a, wiki doc 32 §1.3):
//! - [`Role::User`] (0) — default, žiadne práva navyše;
//! - [`Role::Moderator`] (1) — práva podľa **bitmasky** [`perms`];
//! - [`Role::Admin`] (2) — supermnožina: menuje role, mení nastavenia uzla;
//!   jeho bitmaska je implicitne VŠETKY práva a v úložni sa drží `perms = 0`
//!   (jediná kanonická forma, aby „admin s perms=17“ nemohol existovať).
//!
//! Bitmaska je **u32** (nie u64): JSON/Dart safe integer siaha do 2^53 a
//! SQLite INTEGER je i64 — u32 sa zmestí bez straty do oboch. Nové práva
//! pribúdajú nastavením ďalšieho bitu a rozšírením [`KNOWN_PERMS`];
//! neznáme bity sa **odmietajú** (inak by bit definovaný neskôr dostali
//! spätne tí, čo ho mali omylom nastavený — Opus RIZIKÁ 7).

/// Role účtu na uzle. Kódy sú stabilné (ukladajú sa do DB aj do audit
/// záznamov `GrantRole`), mená do drôtu/JSON: `"user" | "moderator" | "admin"`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Role {
    User = 0,
    Moderator = 1,
    Admin = 2,
}

/// **F14c (MYHSN-58):** per-kanálová role účtu v **skupinovom** kanáli.
/// Kódy zrkadlia [`Role`] (0/1/2), mená do drôtu/JSON:
/// `"member" | "admin" | "owner"`.
///
/// Model (rozhodnutie F14c, wiki doc 32 §5): owner **nie je** riadok v
/// `channel_members` — drží sa v `channels.owner` a práve jeden owner
/// plynie zo štruktúry schémy. `ChannelRole::Owner` preto existuje len
/// ako **efektívna** rola (odvodená z `channels.owner`) pre API/WS tvary;
/// audit `GrantChannelRole` nesmie niesť kód 2 (ownera mení len
/// `TransferChannelOwner`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum ChannelRole {
    /// Pridávať príspevky; mazať/odísť len vlastné veci.
    Member = 0,
    /// Mazať cudzie príspevky (nižšej hodnosti), pridávať/odoberať
    /// memberov, stíšiť memberov, meniť obálku kanála.
    Admin = 1,
    /// Všetko v kanáli + prenechať ownera. Zdroj pravdy: `channels.owner`.
    Owner = 2,
}

impl Role {
    pub fn code(self) -> u8 {
        self as u8
    }

    pub fn from_code(v: u8) -> Option<Self> {
        match v {
            0 => Some(Role::User),
            1 => Some(Role::Moderator),
            2 => Some(Role::Admin),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Role::User => "user",
            Role::Moderator => "moderator",
            Role::Admin => "admin",
        }
    }

    /// Meno → role (presná zhoda, case-sensitive — mená posielapka/API).
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "user" => Some(Role::User),
            "moderator" => Some(Role::Moderator),
            "admin" => Some(Role::Admin),
            _ => None,
        }
    }
}

impl ChannelRole {
    pub fn code(self) -> u8 {
        self as u8
    }

    pub fn from_code(v: u8) -> Option<Self> {
        match v {
            0 => Some(ChannelRole::Member),
            1 => Some(ChannelRole::Admin),
            2 => Some(ChannelRole::Owner),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            ChannelRole::Member => "member",
            ChannelRole::Admin => "admin",
            ChannelRole::Owner => "owner",
        }
    }

    /// Meno → kanálová role. Presná zhoda, case-sensitive. `PUT
    /// /channels/{id}/members/{acct}` prijíma len `member`/`admin`
    /// (owner → 400 `use_transfer`) — toto pole je širšie pre API,
    /// ktoré ownerovu rolu vracia.
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "member" => Some(ChannelRole::Member),
            "admin" => Some(ChannelRole::Admin),
            "owner" => Some(ChannelRole::Owner),
            _ => None,
        }
    }
}

// --- bitmask práv moderátora ---------------------------------------------

/// Vymazať/odstrániť cudzí príspevok (aplikačná vrstva ho vynúti neskôr;
/// vo F14a je deklaratívne).
pub const MODERATE_CHANNELS: u32 = 1 << 0;
/// Vymazať cudzí príspevok (deklaratívne vo F14a).
pub const DELETE_POSTS: u32 = 1 << 1;
/// Vytvárať pozvánky (`POST /invites`) — **vynucované už vo F14a**.
pub const INVITE_USERS: u32 = 1 << 2;
/// Stíšiť účet (deklaratívne vo F14a).
pub const MUTE_ACCOUNT: u32 = 1 << 3;
/// Spravovať kanály (deklaratívne vo F14a).
pub const MANAGE_CHANNELS: u32 = 1 << 4;

/// Maska všetkých známych bitov. `perms` s bitom mimo tejto masky je
/// neplatný — uzol ho odmietne (400), aby sa budúce bity nedostali
/// „zadarmo“ súčasným moderátorom.
pub const KNOWN_PERMS: u32 =
    MODERATE_CHANNELS | DELETE_POSTS | INVITE_USERS | MUTE_ACCOUNT | MANAGE_CHANNELS;

/// `true` práve vtedy, keď `perms` neobsahuje neznámy bit.
pub fn perms_valid(perms: u32) -> bool {
    perms & !KNOWN_PERMS == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_codes_are_stable() {
        assert_eq!(
            (
                Role::User.code(),
                Role::Moderator.code(),
                Role::Admin.code()
            ),
            (0, 1, 2)
        );
        for r in [Role::User, Role::Moderator, Role::Admin] {
            assert_eq!(Role::from_code(r.code()), Some(r));
            assert_eq!(Role::from_name(r.name()), Some(r));
        }
        assert_eq!(Role::from_code(3), None);
        assert_eq!(Role::from_name("Admin"), None, "case-sensitive");
    }

    /// **F14c:** kódy/mená `ChannelRole` sú stabilné a zrkadlia `Role`
    /// (0/1/2); `from_name` je case-sensitive a rešpektuje množinu
    /// `{member, admin, owner}`.
    #[test]
    fn channel_role_codes_are_stable() {
        assert_eq!(
            (
                ChannelRole::Member.code(),
                ChannelRole::Admin.code(),
                ChannelRole::Owner.code()
            ),
            (0, 1, 2)
        );
        for r in [ChannelRole::Member, ChannelRole::Admin, ChannelRole::Owner] {
            assert_eq!(ChannelRole::from_code(r.code()), Some(r));
            assert_eq!(ChannelRole::from_name(r.name()), Some(r));
        }
        assert_eq!(ChannelRole::from_code(3), None);
        assert_eq!(ChannelRole::from_name("Owner"), None, "case-sensitive");
        assert_eq!(ChannelRole::from_name("moderator"), None, "nie serverova rola");
    }

    #[test]
    fn perms_mask_rejects_unknown_bits() {        assert!(perms_valid(0));
        assert!(perms_valid(KNOWN_PERMS));
        assert!(perms_valid(INVITE_USERS | DELETE_POSTS));
        assert!(!perms_valid(1 << 5), "neznámy bit sa musí odmietnuť");
        assert!(!perms_valid(1 << 31));
        // bity sú navzájom rôzne
        let bits = [
            MODERATE_CHANNELS,
            DELETE_POSTS,
            INVITE_USERS,
            MUTE_ACCOUNT,
            MANAGE_CHANNELS,
        ];
        for (i, a) in bits.iter().enumerate() {
            for (j, b) in bits.iter().enumerate() {
                if i != j {
                    assert_eq!(a & b, 0);
                }
            }
        }
    }
}
