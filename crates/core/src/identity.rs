//! Identita člena a kľúče (rozhodnutia D-26, D-27).
//!
//! Model z D-26 (záväzný):
//! - **device kľúče nikdy neopustia zariadenie** (žiadny escrow v MVP),
//! - **účet = množina device kľúčov atestovaná uzlom** — login je len
//!   meno + heslo (Argon2id, ideálne OPAQUE); pri prihlásení z nového
//!   zariadenia uzol atestuje nový kľúč a história platí,
//! - strata zariadenia nie je strata účtu.
//!
//! Kľúče uzla (D-27): **root kľúč** drží admin offline (QR pinuje root),
//! root podpisuje **operačný kľúč**, ktorým uzol pečiatkuje záznamy;
//! rotácia operačného kľúča sa zaobíde bez zásahu členov.
//!
//! B2 (MYHSN-4) prináša **skutočnú ed25519 kryptografiu**: podpis tela
//! záznamu robí device kľúč autora ([`sign`]), overenie robí
//! [`DevicePublicKey::verify`] / [`verify_signature`]. Pečiatku uzla
//! podpisuje operačný kľúč — overuje sa cez [`verify_node_sig`]
//! (kľúčová infraštruktúra uzla je B4/B5, rozhranie je pripravené už tu).
//!
//! Sans-IO: ed25519-dalek je výpočet, nie I/O — preto môže byť v jadre.
//! D-29 zakazuje v jadre tokio/axum/rusqlite, nie kryptografiu.

// `Signer` treba pre `sign()`, `verify_strict` je vlastná metóda
// `VerifyingKey` — preto tu nie je `Verifier`.
use ed25519_dalek::Signer as _;

/// ID domáceho uzla = verejný root kľúč uzla (D-27, pinovaný v QR).
pub type NodeId = [u8; 32];

/// ID účtu člena v rámci uzla (Account@Node, D-08).
pub type AccountId = [u8; 32];

/// Dĺžka ed25519 podpisu v bajtoch.
pub const SIGNATURE_LEN: usize = 64;

/// Verejná časť device kľúča (ed25519, 32 bajtov). Súkromná časť
/// neopustí zariadenie — tu držíme len to, čo atestoval uzol (D-26).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct DevicePublicKey(pub [u8; 32]);

/// Ed25519 podpis (64 bajtov). Podľa RFC 8032 je deterministický —
/// rovnaký kľúč + rovnaká správa = rovnaký podpis, čo využívame
/// v golden vektoroch (pevný vstup → pevný hex podpisu).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Signature(pub [u8; SIGNATURE_LEN]);

impl Signature {
    /// Nil podpis: obálka po erase (D-30) už nemá podpísateľný obsah.
    pub const NIL: Signature = Signature([0u8; SIGNATURE_LEN]);

    pub fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }

    pub fn is_nil(&self) -> bool {
        self.0 == [0u8; SIGNATURE_LEN]
    }

    pub fn hex(&self) -> String {
        crate::record::to_hex(&self.0)
    }
}

/// Zostav verejný kľúč z 32-bajtového seedu súkromného kľúča.
///
/// Seed je to, čo drží zariadenie (D-26). Ide len o odvodenie verejnej
/// časti — súkromný seed sa nikam neukladá.
pub fn public_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
}

/// Podpíš správu `msg` súkromným kľúčom (seed `seed`).
pub fn sign(seed: &[u8; 32], msg: &[u8]) -> Signature {
    let key = ed25519_dalek::SigningKey::from_bytes(seed);
    Signature(key.sign(msg).to_bytes())
}

/// Overí ed25519 podpis `sig` správy `msg` verejným kľúčom `public`.
///
/// Používame `verify_strict` (nie `verify`): odmieta nekanonické body
/// krivky aj malleable tvary podpisu — podpis musí byť ten jediný
/// správny, čo je požiadavka nezmeniteľnosti záznamu (D-25).
pub fn verify_signature(public: &[u8; 32], msg: &[u8], sig: &Signature) -> bool {
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(public) else {
        return false; // nekanonický verejný kľúč => nedá sa overiť
    };
    key.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&sig.0))
        .is_ok()
}

impl DevicePublicKey {
    /// Verejný kľúč odvodený zo seedu súkromného kľúča zariadenia.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(public_from_seed(seed))
    }

    /// Overí, že podpis `sig` nad správou `msg` vytvoril **tento** kľúč.
    ///
    /// Kľúčové kritérium B2: podpis je overiteľný len kľúčom autora —
    /// cudzí (hoci platný) device kľúč podpis neoverí.
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> bool {
        verify_signature(&self.0, msg, sig)
    }

    pub fn hex(&self) -> String {
        crate::record::to_hex(&self.0)
    }
}

/// Overí podpis operačného kľúča uzla nad správou `msg`.
///
/// `node` je kľúč, ktorý uzol použil na pečiatkovanie (pole
/// `signed_by_node` v obálke). V B4/B5 pribudne atestácia operačného
/// kľúča root kľúčom (D-27); dovtedy uzol pečiatkuje kľúčom, ktorého
/// verejná časť je práve `signed_by_node` — na overenie poradie (B3)
/// to stačí.
pub fn verify_node_sig(node: &NodeId, msg: &[u8], sig: &Signature) -> bool {
    verify_signature(node, msg, sig)
}

/// Atestácia device kľúča uzlom: „uzol `node` potvrdil, že device kľúč
/// patrí účtu `account` od epochy `node_epoch`“. Pečiatkuje operačný kľúč
/// uzla; formát podpisu doplníme v B4.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DeviceAttestation {
    pub account: AccountId,
    pub device: DevicePublicKey,
    pub node: NodeId,
    pub node_epoch: u64,
}

/// Rezervovaný typ `identity_link` (D-25): viaže zmenu identity
/// (pridanie/revokáciu device kľúča) do append-only logu. Detail B4.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IdentityLink {
    pub account: AccountId,
    pub device: DevicePublicKey,
    /// true = pridaný, false = revokovaný.
    pub added: bool,
}

// --- B4 (MYHSN-6): účtovný model podľa D-26 ------------------------------
//
// Tu sú čisté dáta (sans-IO). Argon2id hashovanie **nie je v jadre** —
// prihlasovanie obsluhuje uzol (`node::auth`), apka heslo len pošle po
// TLS. Jadro drží tvar dát, aby ho uzol aj klient videli rovnako.

/// Účet člena na uzle (Account@Node, D-08 + D-26).
///
/// Heslo sa udržiava ako **Argon2id PHC reťazec** (`$argon2id$v=…`) —
/// parameter rozumný a čitateľný aj pre migrácie algoritmu (D-22).
/// Samotné heslo sa v uzle nikdy neuchováva.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Account {
    pub id: AccountId,
    pub username: String,
    /// Argon2id hash vo formáte PHC string (node::auth ho vytvára/overuje).
    pub password_argon2id_hash: String,
    /// Vytvorené (unix sekundy).
    pub created: u64,
}

/// Device kľúč atestovaný uzlom (D-26: účet = množina takýchto kľúčov).
///
/// `revoked_at = None` ⇒ kľúč je **aktívny** a uzol ním overuje podpisy
/// záznamov pri append. Revokovaný kľúč zostáva v zázname (história
/// platí — D-26), ale nové podpisy sa ním už neprijímajú.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DeviceKey {
    pub account_id: AccountId,
    pub public_key: DevicePublicKey,
    /// Ľudský popis zariadenia („telefón“, „notebook“).
    pub label: String,
    /// Čas atestácie (unix sekundy).
    pub attested_at: u64,
    /// Čas revokácie (unix sekundy); `None` = aktívny.
    pub revoked_at: Option<u64>,
}

impl DeviceKey {
    /// Je kľúč aktívny (nie je revokovaný)?
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }

    /// Revokácia: nastaví čas zrušenia (idempotentné — prvý čas ostáva).
    pub fn revoke(&mut self, at: u64) {
        if self.revoked_at.is_none() {
            self.revoked_at = Some(at);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pomočník: hex → 32 bajtov.
    fn seed_from_hex(h: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    /// **Golden vektor G1** — RFC 8032 §7.1 TEST 1: odvodenie verejného
    /// kľúča. Nezávislý referenčný zdroj (RFC, nie naša implementácia).
    #[test]
    fn golden_g1_rfc8032_test1_public_key() {
        let seed = seed_from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        assert_eq!(
            DevicePublicKey::from_seed(&seed).hex(),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
    }

    /// **Golden vektor G2** — RFC 8032 §7.1 TEST 1: podpis prázdnej
    /// správy je presne tento 64-bajtový hex a overí sa kľúčom z RFC.
    #[test]
    fn golden_g2_rfc8032_test1_signature() {
        let seed = seed_from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let sig = sign(&seed, b"");
        assert_eq!(
            sig.hex(),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        let public = seed_from_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        assert!(verify_signature(&public, b"", &sig));
    }

    /// **Golden vektor G3** — RFC 8032 §7.1 TEST 2: 1-bajtová správa.
    #[test]
    fn golden_g3_rfc8032_test2_signature() {
        let seed = seed_from_hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        let msg = [0x72u8];
        let sig = sign(&seed, &msg);
        assert_eq!(
            sig.hex(),
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        );
        let public = seed_from_hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        assert!(verify_signature(&public, &msg, &sig));
    }

    /// Podpis je deterministický (RFC 8032) — bez toho sa golden vektory
    /// nedajú písať.
    #[test]
    fn signature_is_deterministic() {
        let seed = [3u8; 32];
        let a = sign(&seed, b"myhood");
        let b = sign(&seed, b"myhood");
        let c = sign(&seed, b"myhooD");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    /// **Záväzný test B2:** podpis overí len kľúč autora; cudzí platný
    /// kľúč ani zmenená správa ho neoveria.
    #[test]
    fn verify_accepts_only_the_signing_key() {
        let author = [1u8; 32];
        let other = [2u8; 32];
        let msg = b"telo zaznamu";
        let sig = sign(&author, msg);

        assert!(DevicePublicKey::from_seed(&author).verify(msg, &sig));
        assert!(!DevicePublicKey::from_seed(&other).verify(msg, &sig));
        assert!(!DevicePublicKey::from_seed(&author).verify(b"telo zaznamu?", &sig));
    }

    /// Nil podpis je jasne identifikovateľný (erase, D-30).
    #[test]
    fn nil_signature_marker() {
        assert!(Signature::NIL.is_nil());
        assert!(!sign(&[5u8; 32], b"x").is_nil());
    }

    #[test]
    fn attestation_binds_device_to_account() {
        let att = DeviceAttestation {
            account: [7u8; 32],
            device: DevicePublicKey([9u8; 32]),
            node: [3u8; 32],
            node_epoch: 1,
        };
        assert_eq!(att.account, [7u8; 32]);
        assert_eq!(att.device.0.len(), 32);
    }

    // --- B4 (MYHSN-6): účtovný model -----------------------------------

    /// **D-26:** účet je len obal okolo device kľúčov — kľúč účtu sa
    /// nepoužíva na podpis záznamov, podpisuje device kľúč.
    #[test]
    fn account_holds_argon2id_hash_not_password() {
        let acc = Account {
            id: [1u8; 32],
            username: "juraj".to_string(),
            // PHC reťazec Argon2id — uzol nevidí heslo, len hash
            password_argon2id_hash: "$argon2id$v=19$m=19456,t=2,p=1$...".to_string(),
            created: 1_794_000_000,
        };
        assert!(acc.password_argon2id_hash.starts_with("$argon2id$"));
        assert!(!acc.password_argon2id_hash.contains("heslo"));
    }

    /// **Kľúčové kritérium B4:** aktívny vs. revokovaný kľúč — revokácia
    /// je časovo raz (prvý čas revokácie sa neprepisuje) a kľúč po nej
    /// nie je aktívny.
    #[test]
    fn device_key_active_until_revoked() {
        let mut dk = DeviceKey {
            account_id: [2u8; 32],
            public_key: DevicePublicKey([3u8; 32]),
            label: "telefon".to_string(),
            attested_at: 100,
            revoked_at: None,
        };
        assert!(dk.is_active(), "čerstvo atestovaný kľúč je aktívny");

        dk.revoke(200);
        assert!(!dk.is_active(), "po revokácii už nie je aktívny");
        assert_eq!(dk.revoked_at, Some(200));

        dk.revoke(300); // idempotentné — druhý čas neprepíše prvý
        assert_eq!(dk.revoked_at, Some(200));
    }

    /// Dve zariadenia toho istého účtu: oba kľúče patria rovnakému
    /// `account_id` a ich podpisy sa overujú každým kľúčom osobitne
    /// (kritérium „dve zariadenia píšu, oba podpisy overiteľné“).
    #[test]
    fn two_devices_of_one_account_both_verify() {
        let account = [4u8; 32];
        let phone_seed = [10u8; 32];
        let laptop_seed = [11u8; 32];
        let msg = b"zaznam z mobilu";

        let phone = DeviceKey {
            account_id: account,
            public_key: DevicePublicKey::from_seed(&phone_seed),
            label: "mobil".to_string(),
            attested_at: 1,
            revoked_at: None,
        };
        let laptop = DeviceKey {
            account_id: account,
            public_key: DevicePublicKey::from_seed(&laptop_seed),
            label: "notebook".to_string(),
            attested_at: 1,
            revoked_at: None,
        };
        assert_eq!(phone.account_id, laptop.account_id);

        let sig_phone = sign(&phone_seed, msg);
        let sig_laptop = sign(&laptop_seed, msg);
        assert!(phone.public_key.verify(msg, &sig_phone));
        assert!(laptop.public_key.verify(msg, &sig_laptop));
        // krížové overenie zmysluplné nie je — každý podpis patrí svojmu kľúču
        assert!(!phone.public_key.verify(msg, &sig_laptop));
    }
}
