//! **F14a (MYHSN-56):** politika registrácie a `[auth]` konfigurácia uzla.
//!
//! Rozhodnutia O11/O18 (wiki doc 32): efektívna politika sa skladá v
//! poradí **meta override (runtime, `PUT /admin/settings`) → TOML
//! `[auth]` → `open`**. Reštart uzla nie je potrebný; TOML zostáva
//! deklarovaný stav a pri štarte sa WARN-ne, ak ho override tieni.
//!
//! Kľúčové pravidlá (kód sú v `api.rs::register`):
//! - `open` — registrácia voľná (pôvodné správanie, výchozia hodnota;
//!   starý `node.toml` bez sekcie `[auth]` sa SPRAVÁ IDENTICKY).
//! - `invite_only` — bez platnej pozvánky 403 `invite_required`.
//! - `admin_approved` — bez pozvánky vznikne čakajúci účet
//!   (`status = 1`); schválenie = `POST /admin/roles` (grant),
//!   zamietnutie = `DELETE /admin/users/{id}` (rozhodnutie Z2).
//!
//! Prvý admin: ak uzol nemá admina a nie je nastavený
//! `bootstrap_admin`, pridá sa prvý registrovaný (Z4). S `bootstrap_admin`
//! povýši sa len účet s presne týmto menom (O2), a to buď pri
//! registrácii, alebo jednorazovo pri štarte uzla (`main.rs`).

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Politika registrácie nových účtov.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationPolicy {
    /// Otvorený server — hocikto sa zaregistruje (výchozie správanie).
    #[default]
    Open,
    /// Len s platnou jednorazovou pozvánkou.
    InviteOnly,
    /// Registrácia prebehne, ale účet čaká na schválenie adminom.
    AdminApproved,
}

impl RegistrationPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            RegistrationPolicy::Open => "open",
            RegistrationPolicy::InviteOnly => "invite_only",
            RegistrationPolicy::AdminApproved => "admin_approved",
        }
    }
}

impl fmt::Display for RegistrationPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RegistrationPolicy {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "open" => Ok(RegistrationPolicy::Open),
            "invite_only" => Ok(RegistrationPolicy::InviteOnly),
            "admin_approved" => Ok(RegistrationPolicy::AdminApproved),
            other => Err(format!(
                "neplatná politika {other:?}, povolené: open | invite_only | admin_approved"
            )),
        }
    }
}

/// Sekcia `[auth]` v `node.toml`. Všetky polia voliteľné — **starý
/// konfig bez sekcie sa deserializuje na defaulty a uzol sa správa
/// presne ako pred F14a** (spätná kompatibilita je viazaná).
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// Politika registrácie. Default `open` (rozhodnutie O18).
    #[serde(default)]
    pub registration_policy: RegistrationPolicy,
    /// Meno účtu, ktorý smie byť prvým adminom uzla (`None` = ktokoľvek
    /// za predpokladu, že uzol ešte admina nemá — Z4).
    #[serde(default)]
    pub bootstrap_admin: Option<String>,
}

impl AuthConfig {
    /// `true` ak smie účet s týmto menom získať admina (prázdny uzol).
    pub fn may_bootstrap(&self, username: &str) -> bool {
        match &self.bootstrap_admin {
            None => true,
            Some(expected) => expected.trim() == username.trim(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_is_open_and_toml_section_optional() {
        // TOML bez sekcie `[auth]` → defaulty (spätná kompatibilita)
        let cfg: AuthConfig = toml::from_str("").unwrap();
        assert_eq!(cfg.registration_policy, RegistrationPolicy::Open);
        assert_eq!(cfg.bootstrap_admin, None);

        // AuthConfig je *obsah* sekcie `[auth]` — v `NodeConfig` sedí na
        // kľúči `auth`, tu testujeme priamo telo sekcie
        let cfg: AuthConfig =
            toml::from_str("registration_policy = \"invite_only\"\nbootstrap_admin = \"admin\"\n")
                .unwrap();
        assert_eq!(cfg.registration_policy, RegistrationPolicy::InviteOnly);
        assert_eq!(cfg.bootstrap_admin.as_deref(), Some("admin"));
    }

    #[test]
    fn unknown_policy_is_rejected() {
        assert!(toml::from_str::<AuthConfig>("registration_policy = \"anarchia\"\n").is_err());
    }

    #[test]
    fn bootstrap_name_must_match_exactly() {
        let cfg = AuthConfig {
            registration_policy: RegistrationPolicy::Open,
            bootstrap_admin: Some("manager_test".into()),
        };
        assert!(cfg.may_bootstrap("manager_test"));
        assert!(cfg.may_bootstrap("  manager_test "));
        assert!(!cfg.may_bootstrap("manager_test2"));
        assert!(!cfg.may_bootstrap("Manager_Test")); // case-sensitive (BINARY)
        let open = AuthConfig::default();
        assert!(open.may_bootstrap("hocijako"));
    }

    #[test]
    fn roundtrip_str_display() {
        for p in [
            RegistrationPolicy::Open,
            RegistrationPolicy::InviteOnly,
            RegistrationPolicy::AdminApproved,
        ] {
            assert_eq!(p.to_string().parse::<RegistrationPolicy>().unwrap(), p);
        }
        assert!("nope".parse::<RegistrationPolicy>().is_err());
    }
}
