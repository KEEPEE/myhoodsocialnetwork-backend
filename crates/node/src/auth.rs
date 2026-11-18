//! Argon2id heslá a session tokeny (B4, MYHSN-6, rozhodnutie **D-26**).
//!
//! Prečo tu a nie v jadre: jadro (`core`) je sans-IO a stavia sa aj pre
//! WASM — tam `argon2` so generovaním soli pridáva zbytočnú váhu. Login
//! obsluhuje **uzol**: apka mu pošle heslo po TLS a uzol hashuje/overuje.
//! Jadro drží len tvar dát ([`myhsn_core::identity::Account`]).
//!
//! Parametre (zapísané aj v README, OWASP low-end minimum pre Argon2id):
//! - `m_cost = 19 456 KiB` (19 MiB), `t_cost = 2`, `p_cost = 1`,
//! - digest 32 bajtov, 16-bajtová náhodná soľ,
//! - výstup je PHC reťazec `$argon2id$v=19$m=19456,t=2,p=1$…` — parametre
//!   sú súčasťou hashu, takže ich zmena si nevyžaduje migráciu schémy
//!   (D-22: verzia algoritmu v dátach, nie v dohode).
//!
//! Session tokeny (D-26): 32 náhodných bajtov z OS RNG, klientovi
//! ukázané ako hex; v úložni sa udržiava **len BLAKE3 hash** tokena,
//! nikdy nie jeho hodnotu — a nikdy nelogovať token.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
// OsRng cez rand_core s feature `getrandom` (argon2-ov `rand` feature
// getrandom nespúšťa — viz Cargo.toml)
use rand_core::{OsRng, RngCore};
use std::sync::OnceLock;

/// Pamäťový parameter v KiB (19 MiB — OWASP minimum pre Argon2id).
pub const ARGON2_M_KIB: u32 = 19_456;
/// Počet iterácií.
pub const ARGON2_T: u32 = 2;
/// Paralelizmus.
pub const ARGON2_P: u32 = 1;
/// Dĺžka digestu a soli v bajtoch.
pub const ARGON2_OUT_LEN: usize = 32;

/// Dĺžka session tokena v bajtoch (32 B náhody, hex = 64 znakov).
pub const SESSION_TOKEN_LEN: usize = 32;

/// Explicitné Parametre (nie default `Argon2::default()`, ktorý má iné
/// hodnoty) — aby boli zapísané parametre skutočne tie, ktoré hlásime.
fn argon2() -> Argon2<'static> {
    // Parametre sú konštanty mimo rozsahu chybových stavov (m ≥ 8 MiB,
    // p ≥ 1); panic tu je „bug v konštante“, nie prevádzková chyba.
    let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(ARGON2_OUT_LEN))
        .expect("parametre Argon2id sú platné");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Chyby auth vrstvy — klient ich nikdy nevidí celé (vnútorné).
#[derive(Debug)]
pub enum AuthError {
    /// Kryptografická operácia zlyhala (náhoda, kódovanie).
    Crypto(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Crypto(m) => write!(f, "auth: {m}"),
        }
    }
}

impl std::error::Error for AuthError {}

impl From<argon2::password_hash::Error> for AuthError {
    fn from(e: argon2::password_hash::Error) -> Self {
        // chybové texty `password-hash` neobsahujú heslo ani soľ
        AuthError::Crypto(e.to_string())
    }
}

/// Vytvor Argon2id hash hesla (PHC reťazec). Soľ je náhodná, takže dva
/// hashy toho istého hesla sa líšia — to je v poriadku, overuje sa
/// `verify_password`, nie porovnanie reťazcov.
pub fn hash_password(password: &str) -> Result<String, AuthError> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2().hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

/// Overí heslo voči uloženej PHC hodnote. `false` = zlé heslo **alebo**
/// poškodený hash (to je jedno, obe znamenajú 401).
pub fn verify_password(password: &str, phc: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    argon2()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Hash neznámeho používateľa na vyrovnanie času overenia (útok
/// časovaním: pri neexistujúcom účte by inak login bol o Argon2
/// výpočet rýchlejší a útočník by zistil, ktoré mená existujú).
fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| {
        hash_password("myhsn-dummy-password")
            .expect("hashovanie dummy hesla nesmie zlyhať")
    })
}

/// Overenie pri neexistujúcom účte: rovnaká práca ako pri platnom, ale
/// výsledok je vždy `false`.
pub fn verify_password_unknown_user(password: &str) -> bool {
    let _ = verify_password(password, dummy_hash());
    false
}

/// Nový session token: 32 náhodných bajtov z OS RNG.
pub fn new_session_token() -> [u8; SESSION_TOKEN_LEN] {
    let mut buf = [0u8; SESSION_TOKEN_LEN];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Hash tokena, ktorý sa ukladá do úložne — nikdy nie samotný token.
pub fn hash_session_token(token: &[u8; SESSION_TOKEN_LEN]) -> [u8; 32] {
    *blake3::hash(token).as_bytes()
}

/// 32 náhodných bajtov (generovanie kľúčov/seedov uzla).
pub fn random_32() -> [u8; 32] {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Kritérium B4 (roundtrip):** hashnuté heslo sa overí správnym
    /// heslom a zlé heslo nie.
    #[test]
    fn argon2id_roundtrip_accepts_and_rejects() {
        let phc = hash_password("NejakeHeslo123!").unwrap();
        assert!(phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "PHC reťazec musí niesť parametre, ktoré deklarujeme: {phc}");
        assert!(verify_password("NejakeHeslo123!", &phc));
        assert!(!verify_password("nejakeheslo123!", &phc));
        assert!(!verify_password("", &phc));
    }

    /// Náhodná soľ: dva hashy rovnakého hesla sa líšia, oba sa overia.
    #[test]
    fn salt_is_random_per_hash() {
        let a = hash_password("same").unwrap();
        let b = hash_password("same").unwrap();
        assert_ne!(a, b, "soľ musí byť per-hash náhodná");
        assert!(verify_password("same", &a) && verify_password("same", &b));
    }

    /// Poškodený/cudzí hash sa overí ako `false`, nespadne.
    #[test]
    fn corrupt_hash_verifies_false() {
        assert!(!verify_password("h", "to nie je phc"));
        assert!(!verify_password("h", "$argon2id$v=19$m=19456,t=2,p=1$xx$yy"));
    }

    /// Cesta pre neznámeho používateľa vždy `false` (a pritom odvedie
    /// rovnakú kryptografickú prácu).
    #[test]
    fn unknown_user_path_denies() {
        assert!(!verify_password_unknown_user("hocijake"));
    }

    /// Tokeny sú náhodné a ich hash je deterministický (ukladáme hash).
    #[test]
    fn session_tokens_random_hashed_stably() {
        let a = new_session_token();
        let b = new_session_token();
        assert_ne!(a, b, "dva tokeny sa nesmú rovnať");
        assert_eq!(hash_session_token(&a), hash_session_token(&a));
        assert_ne!(hash_session_token(&a), hash_session_token(&b));
    }

    /// `random_32` vracia rôzne hodnoty (RNG nie je zamrznutý).
    #[test]
    fn random_32_differs() {
        assert_ne!(random_32(), random_32());
    }
}
