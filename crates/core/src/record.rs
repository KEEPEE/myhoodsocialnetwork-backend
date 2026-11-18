//! Obálka záznamu (rozhodnutia **D-25** a **D-30**).
//!
//! Záznam je **raw bajty**; identifikátor je `hash = BLAKE3(raw)`. Obálka má
//! dve vrstvy (D-25):
//!
//! 1. **telo od autora** — raw bajty podpísané device kľúčom zariadenia
//!    ([`crate::identity::sign`], D-26),
//! 2. **sekvenčná pečiatka domáceho uzla** — `(channel, node_epoch,
//!    node_seq, signed_by_node)`; poradie prideľuje domáci uzol, detail v
//!    [`crate::seq`] a [`crate::channel`].
//!
//! Ďalšie povinné náležitosti z D-25/D-30, ktoré tu sú:
//! - `body_hash = BLAKE3(body_bytes)` — kanonický hash obsahu,
//! - **slepý hash payloadu so soľou** `BLAKE3(salt || body_hash)` — soľ má
//!   len domáci uzol a len per kanál, takže bez nej sa rovnaký obsah
//!   nepozná (test `blind_hash_hides_content_without_salt`),
//! - **tagy algoritmov a verzie oddelené** — [`AlgoTag`] (hash/podpis) a
//!   [`ENVELOPE_FORMAT_V1`] (formát obálky) sú samostatné polia (D-22),
//! - **tri druhy mazania** (D-30): `Tombstone` (autor), `Hide` (moderátor),
//!   `Erase` (operátor, s kódmi dôvodu, záväzný pre repliky aj cache) —
//!   erase odstráni obsah a nechá dôvod ([`Envelope::erased`]).
//!
//! Serilizácia je **deterministická**: pevné poradie polí, definite arrays,
//! minicbor integer v shortest-form. Rovnaký záznam dáva vždy rovnaké
//! bajty, teda aj rovnaký hash (test `serialization_is_deterministic`).

use crate::identity::{DevicePublicKey, NodeId, Signature, SIGNATURE_LEN};
use crate::seq::ChannelId;

/// Pomocné hex-zobrazenie (bez externé knižnice, len pre hash/diagnostiku).
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Opak `to_hex`: hex reťazec → bajty. Nepárna dĺžka, nepoznaná číslica
/// ani nehex znaky (veľkosť písmen nevadí) sú `None`.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in b.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// Verzia formátu obálky. Rastie len pri nekompatibilnej zmene štruktúry —
/// od verzie algoritmov ([`AlgoTag`]) je **oddelená** (D-25, D-22).
pub const ENVELOPE_FORMAT_V1: u8 = 1;

/// Doménový prefix podpisu pečiatky uzla: uzol podpisuje **poradie**, nie
/// obsah, a podpis sa nesmie zameniť s podpisom obsahu.
pub const STAMP_DOMAIN: &[u8] = b"myhsn:stamp:v1:";

/// Tag algoritmu hash/podpis (D-22, D-25): F0 používa BLAKE3 + Ed25519.
/// Tag zverejňujeme, aby sa dal algoritmus meniť bez domniek.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AlgoTag {
    /// BLAKE3 pre hash, Ed25519 pre podpisy (default F0).
    Blake3Ed25519,
}

impl AlgoTag {
    pub fn code(self) -> u8 {
        match self {
            AlgoTag::Blake3Ed25519 => 0,
        }
    }

    pub fn from_code(v: u8) -> Option<Self> {
        match v {
            0 => Some(AlgoTag::Blake3Ed25519),
            _ => None,
        }
    }
}

/// Druh záznamu (D-25 + D-30). Druhy mazania sú súčasť druhu, aby sa osud
/// záznamu dal čítať bez dekódovania obsahu.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecordKind {
    /// Príspevok na nástienke (D-10: kanál `wall`).
    Post = 0,
    /// Reakcia na iný záznam (emoji, reakcia na príspevok).
    Reaction = 1,
    /// Správa chatu (D-10: kanál `chat`).
    ChatMsg = 2,
    /// Autor svoje dáta odznakoval (tombstone) — replikuje sa ďalej (D-30).
    Tombstone = 3,
    /// Moderátor skryl záznam pred členením (hide, D-30).
    Hide = 4,
    /// Operátor vymazal s kódom dôvodu (erase) — záväzný pre repliky aj
    /// cache (D-30); obsah už v obálke nie je.
    Erase = 5,
    /// **F14a (MYHSN-56):** udelenie/ zmena role účtu — auditný záznam
    /// operácie `GrantRole`. Píše ho **uzol** (author = operačný kľúč),
    /// lebo device kľúč admina neopustí zariadenie (D-26); patrí len do
    /// systémového kanála, kam externí klienti nemôžu appendovať.
    GrantRole = 6,
    /// **F14a:** odobratie role (späť na `user`) — audit `RevokeRole`.
    RevokeRole = 7,
    /// **F14c (MYHSN-58):** vytvorenie skupinového kanála — audit operácie
    /// `CreateChannel`, ktorý nesie **ownera**. Píše ho uzol (author =
    /// operačný kľúč, D-26/O9) ako záznam **seq 1 priamo v novom kanáli** —
    /// história členstva patrí ku kanálu a replikuje sa s ním. Kindy 6 – 11
    /// smie písať len uzol a nesmú byť cieľom mazania (`deletion.rs`).
    /// Kóduje sa ako `[8, channel, name, kind_code, owner, owner_name, by,
    /// by_device]` (arity 8); `channel` je v tele zámerné aj keď ho nesie
    /// pečiatka — `body_sig` nekryje pečiatku, a tak telo bez kanála by sa
    /// dalo pod novou pečiatkou preniesť do iného kanála (replikácia).
    CreateChannel = 8,
    /// **F14c:** udelenie/per-kanálovej role `channel_role` (kód z
    /// [`crate::roles::ChannelRole`], semanticky `member`/`admin` — owner
    /// sa mení len auditom [`Payload::TransferChannelOwner`]) účtu
    /// `target` v kanáli `channel`. `[9, channel, target, target_name,
    /// channel_role, by, by_device]` (arity 7).
    GrantChannelRole = 9,
    /// **F14c:** odobratie členstva v kanáli (member/admin). Owner sa týmto
    /// nesmie odobrať — invariant „group kanál má vždy ownera“ rieši
    /// 409 `owner_must_transfer` na REST a transfer.
    /// `[10, channel, target, target_name, by, by_device]` (arity 6).
    RevokeChannelRole = 10,
    /// **F14c:** prenechanie ownera kanála — jeden atómový audit (dva
    /// záznamy grant+revoke by medzi sebou nechali kanál bez ownera alebo
    /// s dvoma). Pôvodný owner dostane rolu `prev_role` (kód
    /// [`crate::roles::ChannelRole`], alebo 255 = „none“ = odchod z
    /// kanála). `[11, channel, from, from_name, to, to_name, prev_role,
    /// by, by_device]` (arity 9); `by` je vykonávateľ (owner, server admin
    /// alebo moderator s `MANAGE_CHANNELS`).
    TransferChannelOwner = 11,
    // Kind 12 je rezervovaný pre budúci `SetChannelMute` (F14d) — pridávať
    // len po dohode, číslo sa už nesmie voľne použiť.
}

impl RecordKind {
    pub fn code(self) -> u8 {
        self as u8
    }

    pub fn from_code(v: u8) -> Option<Self> {
        match v {
            0 => Some(RecordKind::Post),
            1 => Some(RecordKind::Reaction),
            2 => Some(RecordKind::ChatMsg),
            3 => Some(RecordKind::Tombstone),
            4 => Some(RecordKind::Hide),
            5 => Some(RecordKind::Erase),
            6 => Some(RecordKind::GrantRole),
            7 => Some(RecordKind::RevokeRole),
            8 => Some(RecordKind::CreateChannel),
            9 => Some(RecordKind::GrantChannelRole),
            10 => Some(RecordKind::RevokeChannelRole),
            11 => Some(RecordKind::TransferChannelOwner),
            _ => None,
        }
    }
}

/// Kód dôvodu erase (D-30: „erase … podpísaný uzlom s kódom dôvodu“).
/// Dôvod sa po erase **ponecháva** — je to jediné, čo z obsahu zostane.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EraseReason {
    /// GDPR žiadosť autora „vymaž to teraz“ (D-30).
    AuthorRequest,
    /// Retenčná politika uzla — prune je naplánovaný erase (D-33).
    Retention,
    /// Moderátorský erase (flag → erase).
    Moderation,
    /// Právny príkaz operátora.
    LegalOrder,
    /// Iný dôvod s vlastným kódom, ktorý si definuje operátor.
    /// (Kódy 1..=4 sú vyhradené variantom vyššie.)
    Other(u16),
}

impl EraseReason {
    pub fn code(self) -> u16 {
        match self {
            EraseReason::AuthorRequest => 1,
            EraseReason::Retention => 2,
            EraseReason::Moderation => 3,
            EraseReason::LegalOrder => 4,
            EraseReason::Other(c) => c,
        }
    }

    pub fn from_code(v: u16) -> Self {
        match v {
            1 => EraseReason::AuthorRequest,
            2 => EraseReason::Retention,
            3 => EraseReason::Moderation,
            4 => EraseReason::LegalOrder,
            c => EraseReason::Other(c),
        }
    }
}

/// Referencia na **pominuteľný** blob v chate (B7/MYHSN-9, rozhodnutie
/// **D-33**). Sám súbor nežije v logu (D-33: inak by sa nedal zmysť) — v
/// tele správy je len táto referencia a klient si blob stiahne z
/// `GET /media/{id}` (D-24: bloby mimo WS). `media_id` a `hash` sú hex
/// reťazce (id blobu = 32 náhodných bajtov, hash = BLAKE3 obsahu pre
/// kontrolu integrity), `width`/`height` rozmer náhľadu počíta klient pri
/// výbere obrázka (kvôli aspect ratio bez sťahovania).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ChatMedia {
    pub media_id: String,
    pub hash: String,
    pub width: u32,
    pub height: u32,
}

/// Typizovaný payload podľa druhu záznamu (B2: „enum s payload typmi“).
///
/// [`Payload::encode`] je deterministické CBOR pole `[druh, …polia]` —
/// tieto bajty sú `body_bytes` autora, idú do podpisu aj do `body_hash`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Payload {
    Post {
        text: String,
        /// Referencia na médium (blob); `None` = len text.
        media_ref: Option<String>,
    },
    Reaction {
        /// Hash cieľového záznamu, na ktorý sa reakcia viaže.
        target: [u8; 32],
        emoji: String,
    },
    ChatMsg {
        text: String,
        /// Pominuteľný obrázok v správe (D-33); `None` = čisto textová
        /// správa. Textová správa sa kóduje ako `[2, text]` (arity 2,
        /// spätná kompatibilita so všetkými staršími správami), správa s
        /// obrázkom ako `[2, text, media_id, hash, width, height]` (arity 6).
        media: Option<ChatMedia>,
    },
    Tombstone {
        target: [u8; 32],
    },
    Hide {
        target: [u8; 32],
        reason: String,
    },
    /// Erase (D-30): `target` je hash vymazaného záznamu, `reason` kód
    /// dôvodu a `target_kind` druh, ktorým záznam **bol** — bez neho by
    /// čitateľ nevedel, kam patrí placeholder „obsah bol vymazaný“ (nástenka
    /// × chat). Kóduje sa ako `[5, target, reason, target_kind]` (arity 4);
    /// staršie bajty `[5, target, reason]` (arity 3) sa čítajú s
    /// `target_kind = Post`, čo je jediná semantika, akú B2 – B5 produkovali.
    Erase {
        target: [u8; 32],
        reason: EraseReason,
        target_kind: RecordKind,
    },
    /// **F14a (MYHSN-56):** udelenie role `role` (kód z
    /// [`crate::roles::Role`]) s bitmaskou `perms` účtu `target`.
    /// Kóduje sa ako `[6, target, target_name, role_code, perms, by,
    /// by_device]` (arity 7). `by` je účet, ktorý zmenu **nariadil**
    /// (overený session tokenom), `by_device` zariadenie jeho relácie —
    /// audit bez toho, aby uzol musel poznať súkromný kľúč admina (D-26).
    /// `by`/`by_device` môžu byť nulové (bootstrap zo konfigurácie).
    GrantRole {
        target: [u8; 32],
        target_name: String,
        role: u8,
        perms: u32,
        by: [u8; 32],
        by_device: [u8; 32],
    },
    /// **F14a:** odobratie role — účet `target` sa vracia na `user`
    /// (perms 0). Kóduje sa ako `[7, target, target_name, by, by_device]`
    /// (arity 5).
    RevokeRole {
        target: [u8; 32],
        target_name: String,
        by: [u8; 32],
        by_device: [u8; 32],
    },
    /// **F14c (MYHSN-58):** vytvorenie skupinového kanála s vlastníkmi.
    /// `[8, channel, name, kind_code, owner, owner_name, by, by_device]`
    /// (arity 8). `kind_code` je kód [`crate::channel::ChannelKind`] —
    /// skupinovosť NIE je nový `ChannelKind`, ale prítomnosť ownera
    /// (`channels.owner NOT NULL`), takže stará apka vidí `kind` známy.
    /// Autorom je uzol; `by`/`by_device` sú aktér REST operácie.
    CreateChannel {
        channel: [u8; 32],
        name: String,
        kind: u8,
        owner: [u8; 32],
        owner_name: String,
        by: [u8; 32],
        by_device: [u8; 32],
    },
    /// **F14c:** udelenie kanálovej role. `[9, channel, target,
    /// target_name, channel_role, by, by_device]` (arity 7);
    /// `channel_role` je kód [`crate::roles::ChannelRole`] (`member`=0 /
    /// `admin`=1 — `owner`=2 sa týmto auditom neposkytuje, mení ho len
    /// [`Payload::TransferChannelOwner`]).
    GrantChannelRole {
        channel: [u8; 32],
        target: [u8; 32],
        target_name: String,
        channel_role: u8,
        by: [u8; 32],
        by_device: [u8; 32],
    },
    /// **F14c:** odobratie členstva v kanáli.
    /// `[10, channel, target, target_name, by, by_device]` (arity 6).
    RevokeChannelRole {
        channel: [u8; 32],
        target: [u8; 32],
        target_name: String,
        by: [u8; 32],
        by_device: [u8; 32],
    },
    /// **F14c:** prenechanie ownera. `[11, channel, from, from_name, to,
    /// to_name, prev_role, by, by_device]` (arity 9); `prev_role` je kód
    /// [`crate::roles::ChannelRole`] pôvodného ownera po transfere, alebo
    /// 255 = „none“ (z kanála odchádza).
    TransferChannelOwner {
        channel: [u8; 32],
        from: [u8; 32],
        from_name: String,
        to: [u8; 32],
        to_name: String,
        prev_role: u8,
        by: [u8; 32],
        by_device: [u8; 32],
    },
}

impl Payload {
    pub fn kind(&self) -> RecordKind {
        match self {
            Payload::Post { .. } => RecordKind::Post,
            Payload::Reaction { .. } => RecordKind::Reaction,
            Payload::ChatMsg { .. } => RecordKind::ChatMsg,
            Payload::Tombstone { .. } => RecordKind::Tombstone,
            Payload::Hide { .. } => RecordKind::Hide,
            Payload::Erase { .. } => RecordKind::Erase,
            Payload::GrantRole { .. } => RecordKind::GrantRole,
            Payload::RevokeRole { .. } => RecordKind::RevokeRole,
            Payload::CreateChannel { .. } => RecordKind::CreateChannel,
            Payload::GrantChannelRole { .. } => RecordKind::GrantChannelRole,
            Payload::RevokeChannelRole { .. } => RecordKind::RevokeChannelRole,
            Payload::TransferChannelOwner { .. } => RecordKind::TransferChannelOwner,
        }
    }

    /// Počet polí CBOR poľa pre daný druh (kvôli prísnej dekodovacej kontrole).
    /// Niekoľko druhov má viac arit: `ChatMsg` 2 (text) / 6 (text + médium,
    /// D-33) a `Erase` 3 (B2 – B5) / 4 (B6, s cieľovým kindom). Tu je arita,
    /// ktorú píše `encode`; `decode` pripúšťa aj staršiu (`arity_ok`).
    fn arity(kind: RecordKind) -> u64 {
        match kind {
            RecordKind::Post => 4,
            RecordKind::Reaction => 3,
            RecordKind::ChatMsg => 2,
            RecordKind::Tombstone => 2,
            RecordKind::Hide => 3,
            RecordKind::Erase => 4,
            RecordKind::GrantRole => 7,
            RecordKind::RevokeRole => 5,
            RecordKind::CreateChannel => 8,
            RecordKind::GrantChannelRole => 7,
            RecordKind::RevokeChannelRole => 6,
            RecordKind::TransferChannelOwner => 9,
        }
    }

    /// Deterministické CBOR bajty payloadu (raw bajty autora).
    pub fn encode(&self) -> Vec<u8> {
        // každá varianta má vlastné pevné poradie polí — to je záruka
        // determinizmu (rovnaký payload => rovnaké bajty)
        let mut enc = minicbor::Encoder::new(Vec::new());
        match self {
            Payload::Post { text, media_ref } => {
                let _ = enc.array(4);
                let _ = enc.u8(RecordKind::Post.code());
                let _ = enc.str(text);
                match media_ref {
                    None => {
                        let _ = enc.bool(false);
                        let _ = enc.str("");
                    }
                    Some(m) => {
                        let _ = enc.bool(true);
                        let _ = enc.str(m);
                    }
                }
            }
            Payload::Reaction { target, emoji } => {
                let _ = enc.array(3);
                let _ = enc.u8(RecordKind::Reaction.code());
                let _ = enc.bytes(target);
                let _ = enc.str(emoji);
            }
            Payload::ChatMsg { text, media } => {
                // Text: `[2, text]` (arity 2 — nezmenené, spätná kompat.).
                // Médium: `[2, text, media_id, hash, width, height]` (arity 6).
                let arity = if media.is_some() { 6 } else { 2 };
                let _ = enc.array(arity);
                let _ = enc.u8(RecordKind::ChatMsg.code());
                let _ = enc.str(text);
                if let Some(m) = media {
                    let _ = enc.str(&m.media_id);
                    let _ = enc.str(&m.hash);
                    let _ = enc.u32(m.width);
                    let _ = enc.u32(m.height);
                }
            }
            Payload::Tombstone { target } => {
                let _ = enc.array(2);
                let _ = enc.u8(RecordKind::Tombstone.code());
                let _ = enc.bytes(target);
            }
            Payload::Hide { target, reason } => {
                let _ = enc.array(3);
                let _ = enc.u8(RecordKind::Hide.code());
                let _ = enc.bytes(target);
                let _ = enc.str(reason);
            }
            Payload::Erase { target, reason, target_kind } => {
                let _ = enc.array(4);
                let _ = enc.u8(RecordKind::Erase.code());
                let _ = enc.bytes(target);
                let _ = enc.u16(reason.code());
                let _ = enc.u8(target_kind.code());
            }
            Payload::GrantRole { target, target_name, role, perms, by, by_device } => {
                let _ = enc.array(7);
                let _ = enc.u8(RecordKind::GrantRole.code());
                let _ = enc.bytes(target);
                let _ = enc.str(target_name);
                let _ = enc.u8(*role);
                let _ = enc.u32(*perms);
                let _ = enc.bytes(by);
                let _ = enc.bytes(by_device);
            }
            Payload::RevokeRole { target, target_name, by, by_device } => {
                let _ = enc.array(5);
                let _ = enc.u8(RecordKind::RevokeRole.code());
                let _ = enc.bytes(target);
                let _ = enc.str(target_name);
                let _ = enc.bytes(by);
                let _ = enc.bytes(by_device);
            }
            Payload::CreateChannel { channel, name, kind, owner, owner_name, by, by_device } => {
                let _ = enc.array(8);
                let _ = enc.u8(RecordKind::CreateChannel.code());
                let _ = enc.bytes(channel);
                let _ = enc.str(name);
                let _ = enc.u8(*kind);
                let _ = enc.bytes(owner);
                let _ = enc.str(owner_name);
                let _ = enc.bytes(by);
                let _ = enc.bytes(by_device);
            }
            Payload::GrantChannelRole { channel, target, target_name, channel_role, by, by_device } => {
                let _ = enc.array(7);
                let _ = enc.u8(RecordKind::GrantChannelRole.code());
                let _ = enc.bytes(channel);
                let _ = enc.bytes(target);
                let _ = enc.str(target_name);
                let _ = enc.u8(*channel_role);
                let _ = enc.bytes(by);
                let _ = enc.bytes(by_device);
            }
            Payload::RevokeChannelRole { channel, target, target_name, by, by_device } => {
                let _ = enc.array(6);
                let _ = enc.u8(RecordKind::RevokeChannelRole.code());
                let _ = enc.bytes(channel);
                let _ = enc.bytes(target);
                let _ = enc.str(target_name);
                let _ = enc.bytes(by);
                let _ = enc.bytes(by_device);
            }
            Payload::TransferChannelOwner { channel, from, from_name, to, to_name, prev_role, by, by_device } => {
                let _ = enc.array(9);
                let _ = enc.u8(RecordKind::TransferChannelOwner.code());
                let _ = enc.bytes(channel);
                let _ = enc.bytes(from);
                let _ = enc.str(from_name);
                let _ = enc.bytes(to);
                let _ = enc.str(to_name);
                let _ = enc.u8(*prev_role);
                let _ = enc.bytes(by);
                let _ = enc.bytes(by_device);
            }
        }
        enc.into_writer()
    }

    /// Dekoduj payload z raw bajtov; `kind` musí sedieť s druhom v poli.
    pub fn decode(kind: RecordKind, bytes: &[u8]) -> Result<Payload, EnvelopeError> {
        use EnvelopeError::BadCbor;
        let mut dec = minicbor::Decoder::new(bytes);
        let head = dec.array().map_err(|_| BadCbor)?;
        // ChatMsg má variabilnú aritu (D-33): 2 = čisto text, 6 = text +
        // pominuteľný obrázok. Erase má 3 (B2 – B5) alebo 4 (B6, cieľový
        // druh, D-30). Ostatné druhy majú prísne jednu aritu.
        let arity_ok = match kind {
            RecordKind::ChatMsg => head == Some(2) || head == Some(6),
            RecordKind::Erase => head == Some(3) || head == Some(4),
            _ => head == Some(Payload::arity(kind)),
        };
        if !arity_ok {
            return Err(BadCbor);
        }
        let code = dec.u8().map_err(|_| BadCbor)?;
        if code != kind.code() {
            return Err(EnvelopeError::PayloadKindMismatch {
                envelope: kind.code(),
                payload: code,
            });
        }
        match kind {
            RecordKind::Post => {
                let text = dec.str().map_err(|_| BadCbor)?.to_string();
                let has_media = dec.bool().map_err(|_| BadCbor)?;
                let media = dec.str().map_err(|_| BadCbor)?.to_string();
                Ok(Payload::Post {
                    text,
                    media_ref: has_media.then_some(media),
                })
            }
            RecordKind::Reaction => {
                let target = arr32(&fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "target")?);
                let emoji = dec.str().map_err(|_| BadCbor)?.to_string();
                Ok(Payload::Reaction { target, emoji })
            }
            RecordKind::ChatMsg => {
                let text = dec.str().map_err(|_| BadCbor)?.to_string();
                // Arity 6 → nasledujú 4 polia média (D-33); arity 2 → None.
                let media = if head == Some(6) {
                    let media_id = dec.str().map_err(|_| BadCbor)?.to_string();
                    let hash = dec.str().map_err(|_| BadCbor)?.to_string();
                    let width = dec.u32().map_err(|_| BadCbor)?;
                    let height = dec.u32().map_err(|_| BadCbor)?;
                    Some(ChatMedia {
                        media_id,
                        hash,
                        width,
                        height,
                    })
                } else {
                    None
                };
                Ok(Payload::ChatMsg { text, media })
            }
            RecordKind::Tombstone => {
                let target = arr32(&fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "target")?);
                Ok(Payload::Tombstone { target })
            }
            RecordKind::Hide => {
                let target = arr32(&fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "target")?);
                let reason = dec.str().map_err(|_| BadCbor)?.to_string();
                Ok(Payload::Hide { target, reason })
            }
            RecordKind::Erase => {
                let target = arr32(&fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "target")?);
                let code = dec.u16().map_err(|_| BadCbor)?;
                // Arity 4 prináša aj druh vymazaného záznamu (B6, D-30).
                // Stará arity 3 ho nemá — jediná semantika, akú B2 – B5
                // produkovali, bol príspevok na nástienke.
                let target_kind = if head == Some(4) {
                    let k = dec.u8().map_err(|_| BadCbor)?;
                    RecordKind::from_code(k).ok_or(BadCbor)?
                } else {
                    RecordKind::Post
                };
                Ok(Payload::Erase {
                    target,
                    reason: EraseReason::from_code(code),
                    target_kind,
                })
            }
            RecordKind::GrantRole => {
                let target = arr32(&fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "target")?);
                let target_name = dec.str().map_err(|_| BadCbor)?.to_string();
                let role = dec.u8().map_err(|_| BadCbor)?;
                let perms = dec.u32().map_err(|_| BadCbor)?;
                let by = arr32(&fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "by")?);
                let by_device = arr32(&fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "by_device")?);
                Ok(Payload::GrantRole {
                    target,
                    target_name,
                    role,
                    perms,
                    by,
                    by_device,
                })
            }
            RecordKind::RevokeRole => {
                let target = arr32(&fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "target")?);
                let target_name = dec.str().map_err(|_| BadCbor)?.to_string();
                let by = arr32(&fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "by")?);
                let by_device = arr32(&fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "by_device")?);
                Ok(Payload::RevokeRole {
                    target,
                    target_name,
                    by,
                    by_device,
                })
            }
            RecordKind::CreateChannel => {
                let channel = arr32(&fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "channel")?);
                let name = dec.str().map_err(|_| BadCbor)?.to_string();
                let kind = dec.u8().map_err(|_| BadCbor)?;
                let owner = arr32(&fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "owner")?);
                let owner_name = dec.str().map_err(|_| BadCbor)?.to_string();
                let by = arr32(&fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "by")?);
                let by_device = arr32(&fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "by_device")?);
                Ok(Payload::CreateChannel {
                    channel,
                    name,
                    kind,
                    owner,
                    owner_name,
                    by,
                    by_device,
                })
            }
            RecordKind::GrantChannelRole => {
                let channel = arr32(&fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "channel")?);
                let target = arr32(&fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "target")?);
                let target_name = dec.str().map_err(|_| BadCbor)?.to_string();
                let channel_role = dec.u8().map_err(|_| BadCbor)?;
                let by = arr32(&fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "by")?);
                let by_device = arr32(&fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "by_device")?);
                Ok(Payload::GrantChannelRole {
                    channel,
                    target,
                    target_name,
                    channel_role,
                    by,
                    by_device,
                })
            }
            RecordKind::RevokeChannelRole => {
                let channel = arr32(&fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "channel")?);
                let target = arr32(&fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "target")?);
                let target_name = dec.str().map_err(|_| BadCbor)?.to_string();
                let by = arr32(&fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "by")?);
                let by_device = arr32(&fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "by_device")?);
                Ok(Payload::RevokeChannelRole {
                    channel,
                    target,
                    target_name,
                    by,
                    by_device,
                })
            }
            RecordKind::TransferChannelOwner => {
                let channel = arr32(&fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "channel")?);
                let from = arr32(&fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "from")?);
                let from_name = dec.str().map_err(|_| BadCbor)?.to_string();
                let to = arr32(&fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "to")?);
                let to_name = dec.str().map_err(|_| BadCbor)?.to_string();
                let prev_role = dec.u8().map_err(|_| BadCbor)?;
                let by = arr32(&fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "by")?);
                let by_device = arr32(&fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "by_device")?);
                Ok(Payload::TransferChannelOwner {
                    channel,
                    from,
                    from_name,
                    to,
                    to_name,
                    prev_role,
                    by,
                    by_device,
                })
            }
        }
    }
}

/// Hash záznamu: BLAKE3(raw bajtov) — kanonický identifikátor (D-25).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct RecordHash(pub [u8; 32]);

/// Nil hash — po erase sa slepý hash ruší (D-30): bez obsahu nie je čo
/// indexovať a slepý hash by inak stále dokazoval prítomnosť obsahu.
pub const NIL_HASH: RecordHash = RecordHash([0u8; 32]);

impl RecordHash {
    /// `hash = BLAKE3(raw)` — hash surových bajtov, nie štruktúry (D-25).
    pub fn from_raw(raw: &[u8]) -> Self {
        Self(*blake3::hash(raw).as_bytes())
    }

    /// Slepý hash payloadu: **`BLAKE3(salt || payload)`** (D-25).
    ///
    /// Soľ je per kanál a drží ju len domáci uzol. Bez soli sa z slepého
    /// hashu nedá zistiť, či dva záznamy majú rovnaký obsah — ani navzájom
    /// porovnaním slepých hashov z rôznych kanálov.
    pub fn blind(salt: &[u8], payload: &[u8]) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(salt);
        h.update(payload);
        Self(*h.finalize().as_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Pohľad na bajty (pre SQL parametre a drôt).
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn is_nil(&self) -> bool {
        self.0 == [0u8; 32]
    }

    pub fn hex(&self) -> String {
        to_hex(&self.0)
    }
}

/// Vrstva 2: sekvenčná pečiatka domáceho uzla (D-25).
///
/// `(channel, node_epoch, node_seq)` je poradie, ktoré prideľuje **domáci
/// uzol** — nie autor ani hodiny. `signed_by_node` je verejný kľúč uzla,
/// ktorý pečiatku vytvoril (D-27: v praxi operačný kľúč, B4/B5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NodeStamp {
    pub channel: ChannelId,
    pub node_epoch: u64,
    pub node_seq: u64,
    pub signed_by_node: NodeId,
}

impl NodeStamp {
    pub fn new(channel: ChannelId, node_epoch: u64, node_seq: u64, signed_by_node: NodeId) -> Self {
        Self {
            channel,
            node_epoch,
            node_seq,
            signed_by_node,
        }
    }
}

/// Chyby obálky — jeden typ pre čisté zavolanie `decode`/`validate`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EnvelopeError {
    /// Nepoznaná verzia formátu obálky (D-22: verzia je v dátach, nie v dohode).
    BadFormatVersion { got: u8 },
    /// Nepoznaný tag algoritmu.
    UnknownAlgo { code: u8 },
    /// Nepoznaný druh záznamu.
    UnknownKind { code: u8 },
    /// Pole má inú dĺžku, než formát vyžaduje.
    BadField {
        field: &'static str,
        expected: usize,
        got: usize,
    },
    /// Payload nie je platné CBOR pre daný druh.
    BadCbor,
    /// Druh v hlavičke obálky nesedí s druhom v payloade.
    PayloadKindMismatch { envelope: u8, payload: u8 },
    /// `body_hash` nesedí s `body_bytes` — obsah bol zmenený.
    BodyHashMismatch,
    /// Podpis autora neplatí nad `body_bytes` kľúčom `author`.
    AuthorSignatureInvalid,
    /// Podpis pečiatky neplatí nad pečiatkou kľúčom `signed_by_node`.
    StampSignatureInvalid,
}

/// Plná obálka záznamu = telo od autora + pečiatka uzla + hashe (D-25).
///
/// `hash` sa **neserializuje** — je to BLAKE3 kanonických bajtov obálky,
/// takže sa nedá falšovať nezhodou s obsahom.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Envelope {
    /// Verzia formátu obálky ([`ENVELOPE_FORMAT_V1`]).
    pub fmt: u8,
    /// Tag algoritmu hash/podpis — oddelený od verzie formátu (D-25).
    pub algo: AlgoTag,
    /// Druh záznamu (Post/Reaction/ChatMsg/Tombstone/Hide/Erase).
    pub kind: RecordKind,
    /// Verejný device kľúč autora (D-26).
    pub author: DevicePublicKey,
    /// Raw bajty autora — idú do podpisu aj do `body_hash` (D-25).
    pub body_bytes: Vec<u8>,
    /// Ed25519 podpis `body_bytes` kľúčom `author`.
    pub body_sig: Signature,
    /// Pečiatka domáceho uzla (vrstva 2).
    pub stamp: NodeStamp,
    /// Podpis pečiatky kľúčom uzla; `None` = zatiaľ nepodpísané
    /// (uzol bez kľúča, alebo obálka po erase — B6 ju znova podpíše).
    pub stamp_sig: Option<Signature>,
    /// `BLAKE3(body_bytes)` — hash obsahu (D-25).
    pub body_hash: RecordHash,
    /// `BLAKE3(salt || body_hash)` — slepý hash so soľou kanála (D-25).
    pub blind_hash: RecordHash,
}

/// Skontroluj dĺžku bajtového poľa a vráť kópiu.
fn fixed(bytes: &[u8], n: usize, field: &'static str) -> Result<Vec<u8>, EnvelopeError> {
    if bytes.len() != n {
        return Err(EnvelopeError::BadField {
            field,
            expected: n,
            got: bytes.len(),
        });
    }
    Ok(bytes.to_vec())
}

fn arr32(v: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&v[..32]);
    out
}

fn arr64(v: &[u8]) -> [u8; SIGNATURE_LEN] {
    let mut out = [0u8; SIGNATURE_LEN];
    out.copy_from_slice(&v[..SIGNATURE_LEN]);
    out
}

impl Envelope {
    /// Zostav obálku a podpíš obe vrstvy.
    ///
    /// `author_seed` je seed device kľúča autora — v produkcii ho drží len
    /// zariadenie (D-26); parameter existuje, lebo jadro je sans-IO a testy
    /// aj uzol musia podpísať deterministicky.
    ///
    /// `node_seed` je `Some`, ak uzol pečiatku podpíše (B3); `None` ponechá
    /// `stamp_sig = None`.
    pub fn build(
        author_seed: &[u8; 32],
        payload: &Payload,
        stamp: NodeStamp,
        salt: &[u8],
        node_seed: Option<&[u8; 32]>,
    ) -> Envelope {
        let body_bytes = payload.encode();
        let body_hash = RecordHash::from_raw(&body_bytes);
        let author = DevicePublicKey::from_seed(author_seed);
        let body_sig = crate::identity::sign(author_seed, &body_bytes);

        let mut env = Envelope {
            fmt: ENVELOPE_FORMAT_V1,
            algo: AlgoTag::Blake3Ed25519,
            kind: payload.kind(),
            author,
            body_bytes,
            body_sig,
            stamp,
            stamp_sig: None,
            body_hash,
            blind_hash: RecordHash::blind(salt, body_hash.as_bytes()),
        };
        if let Some(seed) = node_seed {
            let pre = env.stamp_signing_bytes();
            env.stamp_sig = Some(crate::identity::sign(seed, &pre));
        }
        env
    }

    /// Bajty, ktoré uzol podpisuje pri pečiatkovaní: doménový prefix +
    /// CBOR pole `[fmt, algo, channel, node_epoch, node_seq, body_hash]`.
    ///
    /// Uzol teda atestuje **poradie obsahu**, nie obsah sám, a podpis sa
    /// nedá zneužiť ako podpis obsahu (doménová separácia).
    pub fn stamp_signing_bytes(&self) -> Vec<u8> {
        let mut inner = minicbor::Encoder::new(Vec::new());
        let _ = inner.array(6);
        let _ = inner.u8(self.fmt);
        let _ = inner.u8(self.algo.code());
        let _ = inner.bytes(&self.stamp.channel);
        let _ = inner.u64(self.stamp.node_epoch);
        let _ = inner.u64(self.stamp.node_seq);
        let _ = inner.bytes(self.body_hash.as_bytes());
        let mut out = STAMP_DOMAIN.to_vec();
        out.extend_from_slice(&inner.into_writer());
        out
    }

    /// Kanonické (deterministické) bajty obálky — idú na drôt aj do úloža;
    /// `hash` je BLAKE3 týchto bajtov.
    ///
    /// 13 polí v pevnom poradí, definite arrays, integer shortest-form.
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = minicbor::Encoder::new(Vec::new());
        let _ = enc.array(13);
        let _ = enc.u8(self.fmt);
        let _ = enc.u8(self.algo.code());
        let _ = enc.u8(self.kind.code());
        let _ = enc.bytes(&self.author.0);
        let _ = enc.bytes(&self.body_bytes);
        let _ = enc.bytes(self.body_sig.as_bytes());
        let _ = enc.bytes(&self.stamp.channel);
        let _ = enc.u64(self.stamp.node_epoch);
        let _ = enc.u64(self.stamp.node_seq);
        let _ = enc.bytes(&self.stamp.signed_by_node);
        // neprítomnosť podpisu = prázdne bajty (reálny podpis má vždy 64 B)
        let _ = enc.bytes(
            self.stamp_sig
                .as_ref()
                .map(|s| s.as_bytes().as_slice())
                .unwrap_or(&[]),
        );
        let _ = enc.bytes(self.body_hash.as_bytes());
        let _ = enc.bytes(self.blind_hash.as_bytes());
        enc.into_writer()
    }

    /// Dekoduj obálku z kanonických bajtov. Kontroluje verzie, dĺžky polí a
    /// známosť tagov — **nepreveruje podpisy** (na to je
    /// [`Envelope::validate`], lebo overenie je drahé a voliteľné).
    pub fn decode(bytes: &[u8]) -> Result<Envelope, EnvelopeError> {
        use EnvelopeError::*;
        let mut dec = minicbor::Decoder::new(bytes);
        if dec.array().map_err(|_| BadCbor)? != Some(13) {
            return Err(BadCbor);
        }
        let fmt = dec.u8().map_err(|_| BadCbor)?;
        if fmt != ENVELOPE_FORMAT_V1 {
            return Err(BadFormatVersion { got: fmt });
        }
        let algo_code = dec.u8().map_err(|_| BadCbor)?;
        let algo = AlgoTag::from_code(algo_code).ok_or(UnknownAlgo { code: algo_code })?;
        let kind_code = dec.u8().map_err(|_| BadCbor)?;
        let kind = RecordKind::from_code(kind_code).ok_or(UnknownKind { code: kind_code })?;
        let author_b = fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "author")?;
        let body_bytes = dec.bytes().map_err(|_| BadCbor)?.to_vec();
        let body_sig_b = fixed(dec.bytes().map_err(|_| BadCbor)?, SIGNATURE_LEN, "body_sig")?;
        let channel = fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "channel")?;
        let node_epoch = dec.u64().map_err(|_| BadCbor)?;
        let node_seq = dec.u64().map_err(|_| BadCbor)?;
        let signed_by_node = fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "signed_by_node")?;
        let stamp_sig_raw = dec.bytes().map_err(|_| BadCbor)?;
        let stamp_sig = if stamp_sig_raw.is_empty() {
            None
        } else {
            Some(Signature(arr64(&fixed(
                stamp_sig_raw,
                SIGNATURE_LEN,
                "stamp_sig",
            )?)))
        };
        let body_hash_b = fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "body_hash")?;
        let blind_hash_b = fixed(dec.bytes().map_err(|_| BadCbor)?, 32, "blind_hash")?;

        Ok(Envelope {
            fmt,
            algo,
            kind,
            author: DevicePublicKey(arr32(&author_b)),
            body_bytes,
            body_sig: Signature(arr64(&body_sig_b)),
            stamp: NodeStamp {
                channel: arr32(&channel),
                node_epoch,
                node_seq,
                signed_by_node: arr32(&signed_by_node),
            },
            stamp_sig,
            body_hash: RecordHash(arr32(&body_hash_b)),
            blind_hash: RecordHash(arr32(&blind_hash_b)),
        })
    }

    /// `hash = BLAKE3(kanonických bajtov obálky)` — idempotentná aplikácia
    /// aj set-reconciliation prebiehajú podľa tohto hashu (D-24, D-25).
    pub fn hash(&self) -> RecordHash {
        RecordHash::from_raw(&self.encode())
    }

    /// Dekoduj payload (obsah) obálky.
    pub fn payload(&self) -> Result<Payload, EnvelopeError> {
        Payload::decode(self.kind, &self.body_bytes)
    }

    /// Overí podpis autora nad `body_bytes`.
    pub fn verify_author_sig(&self) -> bool {
        self.author.verify(&self.body_bytes, &self.body_sig)
    }

    /// Overí podpis pečiatky uzla; `false` ak podpis chýba.
    pub fn verify_stamp_sig(&self) -> bool {
        match &self.stamp_sig {
            Some(sig) => crate::identity::verify_node_sig(
                &self.stamp.signed_by_node,
                &self.stamp_signing_bytes(),
                sig,
            ),
            None => false,
        }
    }

    /// Plná kontrola obálky: verzia, hash obsahu, podpis autora aj podpis
    /// pečiatky. `Err` pri prvej skutočnej neplatnosti.
    ///
    /// Výnimka: erase už nemá podpísateľný obsah, preto `Signature::NIL`
    /// je pre `RecordKind::Erase` v poriadku (D-30).
    pub fn validate(&self) -> Result<(), EnvelopeError> {
        use EnvelopeError::*;
        if self.fmt != ENVELOPE_FORMAT_V1 {
            return Err(BadFormatVersion { got: self.fmt });
        }
        let p = self.payload()?;
        if p.kind() != self.kind {
            return Err(PayloadKindMismatch {
                envelope: self.kind.code(),
                payload: p.kind().code(),
            });
        }
        if RecordHash::from_raw(&self.body_bytes) != self.body_hash {
            return Err(BodyHashMismatch);
        }
        let erased_nil_ok = self.kind == RecordKind::Erase && self.body_sig.is_nil();
        if !erased_nil_ok && !self.verify_author_sig() {
            return Err(AuthorSignatureInvalid);
        }
        if let Some(sig) = &self.stamp_sig {
            if !crate::identity::verify_node_sig(
                &self.stamp.signed_by_node,
                &self.stamp_signing_bytes(),
                sig,
            ) {
                return Err(StampSignatureInvalid);
            }
        }
        Ok(())
    }

    // --- tri druhy mazania (D-30) --------------------------------------

    /// Autor odznakoval svoj záznam (tombstone).
    pub fn is_tombstone(&self) -> bool {
        self.kind == RecordKind::Tombstone
    }

    /// Moderátor záznam skryl pred členením (hide).
    pub fn is_hidden(&self) -> bool {
        self.kind == RecordKind::Hide
    }

    /// Operátor záznam vymazal (erase) — obsah v obálke už nie je.
    pub fn is_erased(&self) -> bool {
        self.kind == RecordKind::Erase
    }

    /// Kód dôvodu erase, ak ide o erase (D-30: dôvod sa ponecháva).
    pub fn erased_reason(&self) -> Option<EraseReason> {
        match self.payload().ok()? {
            Payload::Erase { reason, .. } => Some(reason),
            _ => None,
        }
    }

    /// **D-30: erase odstráni obsah a nechá dôvod.**
    ///
    /// Vráti novú obálku v rovnakej pozícii (kanál, epocha, seq, autor),
    /// ktorej `body_bytes` už neobsahujú pôvodný obsah — len payload
    /// `Erase { target, reason, target_kind }`. Obsah je preč z úložiska aj
    /// z replík; `target` je hash, teda to obsah nie je.
    ///
    /// **`target` je hash nahrádzaného záznamu** (`self.hash()`), nie hash
    /// jeho obsahu. Uzol pri erase vloží do logu aj *akciu* erase a tá
    /// mierí na hash, pod ktorým má príspevok klient vo cache — vymenený
    /// rad musí mierit na **tú istú** hodnotu, inak sa v čítacom pohľade
    /// nespárujú a čitateľ uvidí placeholder dvakrát. Hash obsahu by klient
    /// nepoznal a práve ten sa erase ruší.
    ///
    /// Zároveň: podpis autora sa ruší ([`Signature::NIL`]), lebo nad
    /// vymazaným obsahom už nedáva zmysel; slepý hash sa stáva nil, lebo
    /// by inak stále dokazoval existenciu obsahu; a podpis pečiatky sa
    /// ruší, lebo pôvodná pečiatka atestovala **iný** `body_hash` — uzol
    /// ju po erase znova podpíše (B6, mazanie v logu).
    ///
    /// NIL podpis autora je zároveň **rozlišovací znak** pre čítací pohľad:
    /// erase záznam s NIL podpisom je vymenený rad („tento záznam už
    /// neobsahuje to, čo obsahoval“), erase s reálnym podpisom je akcia
    /// („niekto niečo vymazal“). Uzol preto NIL podpis vyhradzuje pre seba
    /// a klient ho pri erase zázname nesmie posielať.
    ///
    /// Výsledok má **iný `hash`**: erase je nový bod v živote záznamu,
    /// nie prepis histórie. `target_kind` je druh, ktorým bol záznam pred
    /// výmazom, aby čitateľ vedel placeholder vykresliť na správnom mieste
    /// (nástenka × chat).
    ///
    /// Uzol túto obálku **znova podpíše pečiatkou** (`stamp_sig = None`
    /// preto, lebo teleso sa zmenilo a pôvodná pečiatka platila pre staré
    /// bajty) a uloží ju na pôvodnú pozíciu — B6 to robí v úložni uzla
    /// atomicky spolu s erase záznamom (`crates/node/src/store.rs`).
    pub fn erased(&self, reason: EraseReason) -> Envelope {
        let stub = Payload::Erase {
            // **Cieľ = hash nahrádzaného záznamu**, nie hash jeho obsahu.
            // Dôvod: uzol pri erase vloží do logu *akciu* erase, ktorej cieľ
            // je hash, pod ktorým má príspevok klient vo cache (to pozná).
            // Vymenený rad musí mierit na **tú istú** hodnotu, inak sa
            // akcia a vymenený rad v čítacom pohľade nespárujú a čitateľ
            // uvidí placeholder dvakrát. (Hash obsahu by klient nepoznal —
            // ten je práve ten, ktorý sa erase ruší.)
            target: self.hash().0,
            reason,
            target_kind: self.kind,
        };
        let body_bytes = stub.encode();
        Envelope {
            fmt: self.fmt,
            algo: self.algo,
            kind: RecordKind::Erase,
            author: self.author,
            body_sig: Signature::NIL,
            body_bytes: body_bytes.clone(),
            stamp: self.stamp,
            stamp_sig: None,
            body_hash: RecordHash::from_raw(&body_bytes),
            blind_hash: NIL_HASH,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pevné vstupy golden vektorov — nemenné konštanty.
    const AUTHOR_SEED: [u8; 32] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10,
    ];
    const NODE_SEED: [u8; 32] = [0xa1; 32];
    const CHANNEL: [u8; 32] = [0xc0; 32];
    const SALT: &[u8] = b"wall-salt-0001";

    fn post(text: &str) -> Payload {
        Payload::Post {
            text: text.to_string(),
            media_ref: None,
        }
    }

    fn sample() -> Envelope {
        Envelope::build(
            &AUTHOR_SEED,
            &post("moj prvy prispevok"),
            NodeStamp::new(
                CHANNEL,
                0,
                1,
                crate::identity::public_from_seed(&NODE_SEED),
            ),
            SALT,
            Some(&NODE_SEED),
        )
    }

    /// `from_hex` je presný opak `to_hex`; nepárna dĺžka a nehex vstupy
    /// sa odmietnu (B4: REST telá posielajú kľúce ako hex).
    #[test]
    fn from_hex_roundtrip_and_rejects() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        assert_eq!(from_hex(&to_hex(&bytes)).unwrap(), bytes);
        assert_eq!(from_hex("0AFF").unwrap(), vec![0x0a, 0xff]); // veľké písmená OK
        assert_eq!(from_hex("0a0"), None); // nepárna dĺžka
        assert_eq!(from_hex("zz"), None); // nehex znak
        assert_eq!(from_hex("").unwrap(), Vec::<u8>::new());
    }

    // --- BLAKE3 golden vektory (referencia: `b3sum` CLI) ---------------

    /// **G4** — BLAKE3 prázdneho vstupu (oficiálny vektor BLAKE3).
    #[test]
    fn golden_g4_blake3_empty() {
        assert_eq!(
            RecordHash::from_raw(&[]).hex(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    /// **G5** — BLAKE3 fixného textu, overené referenčným `b3sum` CLI.
    #[test]
    fn golden_g5_blake3_known_text() {
        assert_eq!(
            RecordHash::from_raw(b"myhood post 1").hex(),
            "8f60188b7a93aa38e00ec6035a27078facaaaf0eb9c1ef6f5401a1a2463fd3ed"
        );
        assert_eq!(
            RecordHash::from_raw(b"myhood chat").hex(),
            "ae274152736d5fd1a6c78e0f6c300786ae7efb6af08e788c07f656bfe0d57f79"
        );
    }

    /// **G6** — slepý hash `BLAKE3(salt || body_hash)`, overený `b3sum`
    /// CLI (reťazenie bajtov soli a raw hashu).
    #[test]
    fn golden_g6_blind_hash_matches_b3sum() {
        let body_hash = RecordHash::from_raw(b"myhood post 1");
        let blind = RecordHash::blind(SALT, body_hash.as_bytes());
        assert_eq!(
            blind.hex(),
            "4205c68b84bc574219fad1ad2bf0357bbb9fb5125a9b5a43c1866d53425cfe63"
        );
    }

    // --- deterministickosť serilizácie ---------------------------------

    /// Rovnaký záznam dáva **rovnaké bajty** → rovnaký hash.
    #[test]
    fn serialization_is_deterministic() {
        let a = sample();
        let b = sample();
        assert_eq!(a.encode(), b.encode(), "dva buildy musia dat rovnake bajty");
        assert_eq!(a.hash(), b.hash());
        // aj po roundtripe cez decode sú bajty identické
        let c = Envelope::decode(&a.encode()).unwrap();
        assert_eq!(c.encode(), a.encode());
        assert_eq!(c, a);
    }

    /// Payload je deterministický a roundtripovateľný pre všetky druhy.
    #[test]
    fn payload_roundtrip_all_kinds() {
        let target = [7u8; 32];
        let cases = vec![
            Payload::Post {
                text: "ahoj".into(),
                media_ref: Some("blob/1".into()),
            },
            Payload::Post {
                text: "len text".into(),
                media_ref: None,
            },
            Payload::Reaction {
                target,
                emoji: "👍".into(),
            },
            Payload::ChatMsg {
                text: "sprava".into(),
                media: None,
            },
            Payload::ChatMsg {
                text: "".into(),
                media: Some(ChatMedia {
                    media_id: "aa".repeat(32),
                    hash: "bb".repeat(32),
                    width: 1024,
                    height: 768,
                }),
            },
            Payload::Tombstone { target },
            Payload::Hide {
                target,
                reason: "spam".into(),
            },
            Payload::Erase {
                target,
                reason: EraseReason::AuthorRequest,
                target_kind: RecordKind::Post,
            },
            Payload::Erase {
                target,
                reason: EraseReason::Other(42),
                target_kind: RecordKind::ChatMsg,
            },
        ];
        for p in cases {
            let bytes = p.encode();
            assert_eq!(bytes, p.encode(), "determinizmus payloadu {:?}", p.kind());
            let back = Payload::decode(p.kind(), &bytes).expect("decode payload");
            assert_eq!(back, p);
        }
    }

    /// **Spätná kompatibilita (D-33):** textová správa sa naďalej kóduje
    /// ako `[2, text]` (definite array dĺžky 2, prefix `0x82 0x02`) a staré
    /// telo `[2, text]` sa dekoduje s `media = None`. Médium pridáva arity 6.
    #[test]
    fn chat_media_is_backward_compatible() {
        // text → arity 2, zhodné so starým formátom
        let text = Payload::ChatMsg {
            text: "ahoj".into(),
            media: None,
        };
        let tb = text.encode();
        assert_eq!(&tb[..2], &[0x82, 0x02], "text ChatMsg = definite array(2), druh 2");
        match Payload::decode(RecordKind::ChatMsg, &tb).unwrap() {
            Payload::ChatMsg { text: t, media } => {
                assert_eq!(t, "ahoj");
                assert!(media.is_none(), "staré telo → media None");
            }
            other => panic!("ocakaval ChatMsg, prisel {other:?}"),
        }

        // médium → arity 6, roundtrip
        let media = ChatMedia {
            media_id: "cc".repeat(32),
            hash: "dd".repeat(32),
            width: 640,
            height: 480,
        };
        let m = Payload::ChatMsg {
            text: "fotka".into(),
            media: Some(media.clone()),
        };
        let mb = m.encode();
        assert_eq!(mb[0], 0x86, "médium ChatMsg = definite array(6)");
        let back = Payload::decode(RecordKind::ChatMsg, &mb).unwrap();
        assert_eq!(back, m, "roundtrip média je identický");
    }

    // --- záväzné testy B2 ----------------------------------------------

    /// **Záväzný 1:** podpis je overiteľný len kľúčom autora.
    #[test]
    fn author_signature_verifies_only_with_authors_key() {
        let env = sample();
        assert!(env.verify_author_sig());
        // cudzí (hoci platný) kľúč podpis neoverí
        let other = DevicePublicKey::from_seed(&[0xee; 32]);
        assert!(!other.verify(&env.body_bytes, &env.body_sig));
        // ani podpis iného autora k rovnakému telu nesedí
        let other_env = Envelope::build(
            &[0xee; 32],
            &post("moj prvy prispevok"),
            env.stamp,
            SALT,
            None,
        );
        assert!(!env.author.verify(&env.body_bytes, &other_env.body_sig));
    }

    /// **Záväzný 2:** zmena jedného bajtu v tele → hash aj podpis neplatia.
    #[test]
    fn tampered_body_breaks_hash_and_signature() {
        let mut env = sample();
        let original_hash = env.hash();
        // Layout tela Post: [0x84 array(4), 0x00 druh, 0x72 text(18), …].
        // Index 10 je písmeno uprostred textu — istíme si ho, nech test
        // nekope náhodou do hlavičky.
        assert_eq!(env.body_bytes[10], b'y');
        env.body_bytes[10] ^= 0x01; // single byte flip v raw bajtoch autora

        assert!(!env.verify_author_sig(), "poškodené telo neplatí podpis");
        assert_ne!(
            RecordHash::from_raw(&env.body_bytes),
            env.body_hash,
            "poškodené telo neplatí body_hash"
        );
        assert!(matches!(
            env.validate(),
            Err(EnvelopeError::BodyHashMismatch)
        ));
        // hash obálky sa zmenil → idempotentná aplikácia duplikát neprehlási
        assert_ne!(env.hash(), original_hash);
    }

    /// `validate` prepúšťa len platnú obálku; poškodenie podpisu pečiatky
    /// odhalí ako `StampSignatureInvalid`.
    #[test]
    fn validate_rejects_bad_stamp_signature() {
        let mut env = sample();
        assert_eq!(env.validate(), Ok(()));
        let good = env.stamp_sig.unwrap();
        env.stamp_sig = Some(Signature([0x55; 64]));
        assert!(matches!(
            env.validate(),
            Err(EnvelopeError::StampSignatureInvalid)
        ));
        env.stamp_sig = Some(good);
        assert_eq!(env.validate(), Ok(()));
    }

    /// **Záväzný 3:** slepý hash neodhalí rovnaký obsah bez soli.
    #[test]
    fn blind_hash_hides_content_without_salt() {
        let h1 = RecordHash::from_raw(b"ten isty obsah");
        let h2 = RecordHash::from_raw(b"ten isty obsah");
        assert_eq!(h1, h2, "otvorený hash rovnaký obsah prezradí");

        // dva kanály s rôznou soľou → slepé hashe rovnakého obsahu nesedia
        let b1 = RecordHash::blind(b"so1", h1.as_bytes());
        let b2 = RecordHash::blind(b"so2", h2.as_bytes());
        assert_ne!(b1, b2, "bez soli sa rovnaky obsah nedá spoznat");

        // bez soli neviem slepý hash ani vypočítať (domnienka zlyhá)
        let guess = RecordHash::blind(b"hadana", h1.as_bytes());
        assert_ne!(guess, b1);
        // so správnou soľou sa zhoda potvrdí
        assert_eq!(RecordHash::blind(b"so1", h1.as_bytes()), b1);
    }

    /// **Záväzný 4:** tombstone / hide / erase správanie (D-30).
    #[test]
    fn deletion_kinds_behave_per_d30() {
        let target = [9u8; 32];
        let env = sample();

        // tombstone: autor príznakoval, pozícia aj autor ostávajú
        let ts = Envelope::build(&AUTHOR_SEED, &Payload::Tombstone { target }, env.stamp, SALT, None);
        assert!(ts.is_tombstone() && !ts.is_erased() && !ts.is_hidden());
        assert_eq!(ts.author, env.author);
        assert_eq!(ts.stamp, env.stamp);

        // hide: moderátor skryl s dôvodom, dôvod zostáva v obálke
        let hide = Envelope::build(
            &AUTHOR_SEED,
            &Payload::Hide {
                target,
                reason: "hruby".into(),
            },
            env.stamp,
            SALT,
            None,
        );
        assert!(hide.is_hidden());
        match hide.payload().unwrap() {
            Payload::Hide { reason, .. } => assert_eq!(reason, "hruby"),
            _ => panic!("hide payload"),
        }

        // erase: obsah je preč, dôvod zostáva (D-30)
        let erased = env.erased(EraseReason::AuthorRequest);
        assert!(erased.is_erased());
        assert_eq!(erased.erased_reason(), Some(EraseReason::AuthorRequest));
        assert!(
            !String::from_utf8_lossy(&erased.body_bytes).contains("moj prvy prispevok"),
            "erase musí odstrániť obsah"
        );
        match erased.payload().unwrap() {
            Payload::Erase { target, reason, target_kind } => {
                assert_eq!(target, env.hash().0, "cieľom je hash nahrádzaného záznamu");
                assert_eq!(reason, EraseReason::AuthorRequest);
                assert_eq!(
                    target_kind,
                    env.kind,
                    "cieľový druh = druh vymazaného záznamu (kam patrí placeholder)"
                );
            }
            _ => panic!("erase payload"),
        }
        // pozícia a autor ostávajú; slepý hash aj podpisy sa zrušili
        assert_eq!(erased.stamp, env.stamp);
        assert_eq!(erased.author, env.author);
        assert!(erased.blind_hash.is_nil());
        assert!(erased.body_sig.is_nil());
        assert!(erased.stamp_sig.is_none(), "pečiatku znova podpíše uzol (B6)");
        assert!(!erased.verify_stamp_sig());
        // erase je nový bod života záznamu → iný hash
        assert_ne!(erased.hash(), env.hash());
        // vymazaná obálka je stále platná (nil podpis je pre erase v poriadku)
        assert_eq!(erased.validate(), Ok(()));
        // a naopak: nil podpis NIE JE platný pre bežný záznam
        let mut normal_with_nil = sample();
        normal_with_nil.body_sig = Signature::NIL;
        assert!(matches!(
            normal_with_nil.validate(),
            Err(EnvelopeError::AuthorSignatureInvalid)
        ));
    }

    /// **Spätná kompatibilita erase (B6, D-30):** staré telo arity 3
    /// `[5, target, reason]` (B2 – B5 nevedeli, aký druh sa vymazal) sa
    /// naďalej dekoduje — s `target_kind = Post`, čo je jediná semantika,
    /// ktorú vtedy uzol produkoval. Nové telo arity 4 prenesie aj ChatMsg.
    #[test]
    fn erase_payload_accepts_legacy_arity_3() {
        let target = [7u8; 32];
        let legacy = {
            let mut e = minicbor::Encoder::new(Vec::new());
            let _ = e.array(3);
            let _ = e.u8(RecordKind::Erase.code());
            let _ = e.bytes(&target);
            let _ = e.u16(EraseReason::LegalOrder.code());
            e.into_writer()
        };
        let back = Payload::decode(RecordKind::Erase, &legacy).expect("stará arity 3");
        assert_eq!(
            back,
            Payload::Erase {
                target,
                reason: EraseReason::LegalOrder,
                target_kind: RecordKind::Post,
            },
            "arity 3 sa číta ako vymazaný príspevok"
        );

        // nová arity 4 drží aj chat
        let chat = Payload::Erase {
            target,
            reason: EraseReason::LegalOrder,
            target_kind: RecordKind::ChatMsg,
        };
        let bytes = chat.encode();
        assert_eq!(bytes[0] & 0x1f, 4, "definite array arity 4");
        assert_eq!(Payload::decode(RecordKind::Erase, &bytes).unwrap(), chat);

        // neznámy cieľový druh je chyba, nie tichá domnienka
        let mut bogus = bytes.clone();
        *bogus.last_mut().unwrap() = 99;
        assert!(Payload::decode(RecordKind::Erase, &bogus).is_err());
    }

    /// Kódy dôvodov erase prežijú serilizáciu (D-30).
    #[test]
    fn erase_reason_codes_survive_roundtrip() {
        for reason in [
            EraseReason::AuthorRequest,
            EraseReason::Retention,
            EraseReason::Moderation,
            EraseReason::LegalOrder,
            EraseReason::Other(7),
        ] {
            let env = sample().erased(reason);
            let back = Envelope::decode(&env.encode()).unwrap();
            assert_eq!(back.erased_reason(), Some(reason));
            assert_eq!(reason.code(), EraseReason::from_code(reason.code()).code());
        }
    }

    /// **F14c (MYHSN-58):** audity skupín roundtripujú a majú kanonické
    /// arity 8/7/6/9. Prísna arita platí aj pre ne — skrátené pole je
    /// chyba, nie tichá domnienka.
    #[test]
    fn channel_audit_payloads_roundtrip() {
        let create = Payload::CreateChannel {
            channel: [1u8; 32],
            name: "rybacky".into(),
            kind: 0,
            owner: [2u8; 32],
            owner_name: "juraj".into(),
            by: [2u8; 32],
            by_device: [3u8; 32],
        };
        let b = create.encode();
        assert_eq!(b[0] & 0x1f, 8, "definite array arity 8");
        assert_eq!(Payload::decode(RecordKind::CreateChannel, &b).unwrap(), create);

        let grant = Payload::GrantChannelRole {
            channel: [1u8; 32],
            target: [4u8; 32],
            target_name: "zuzana".into(),
            channel_role: 1,
            by: [2u8; 32],
            by_device: [3u8; 32],
        };
        let b = grant.encode();
        assert_eq!(b[0] & 0x1f, 7, "definite array arity 7");
        assert_eq!(
            Payload::decode(RecordKind::GrantChannelRole, &b).unwrap(),
            grant
        );

        let revoke = Payload::RevokeChannelRole {
            channel: [1u8; 32],
            target: [4u8; 32],
            target_name: "zuzana".into(),
            by: [2u8; 32],
            by_device: [3u8; 32],
        };
        let b = revoke.encode();
        assert_eq!(b[0] & 0x1f, 6, "definite array arity 6");
        assert_eq!(
            Payload::decode(RecordKind::RevokeChannelRole, &b).unwrap(),
            revoke
        );

        let transfer = Payload::TransferChannelOwner {
            channel: [1u8; 32],
            from: [2u8; 32],
            from_name: "juraj".into(),
            to: [4u8; 32],
            to_name: "zuzana".into(),
            prev_role: 1,
            by: [2u8; 32],
            by_device: [3u8; 32],
        };
        let b = transfer.encode();
        assert_eq!(b[0] & 0x1f, 9, "definite array arity 9");
        assert_eq!(
            Payload::decode(RecordKind::TransferChannelOwner, &b).unwrap(),
            transfer
        );

        // cross-kind zámena (9 teleso v 10 obálke) = chyba
        let b = grant.encode();
        assert!(Payload::decode(RecordKind::RevokeChannelRole, &b).is_err());
    }

    /// Nepoznaná verzia formátu, tag algoritmu ani druh sa odmietnu (D-22).    ///
    /// Kanonické bajty začínajú `0x8d` (definite array 13), potom `fmt`,
    /// `algo`, `kind`. Testované hodnoty držíme ≤ 23, lebo CBOR single-byte
    /// integer kóduje hodnotu priamo len v tomto rozsahu (0x2a napr. nie je
    /// 42, ale 10 — additional info je spodných 5 bitov).
    #[test]
    fn decode_rejects_unknown_versions_and_tags() {
        let bytes = sample().encode();
        assert_eq!(bytes[0], 0x8d, "čakali sme definite array(13)");

        let mut b = bytes.clone();
        b[1] = 9;
        assert!(matches!(
            Envelope::decode(&b),
            Err(EnvelopeError::BadFormatVersion { got: 9 })
        ));

        let mut b = bytes.clone();
        b[2] = 7; // algo: poznáme len 0 (BLAKE3+Ed25519)
        assert!(matches!(
            Envelope::decode(&b),
            Err(EnvelopeError::UnknownAlgo { code: 7 })
        ));

        let mut b = bytes.clone();
        b[3] = 12; // kind: poznáme 0..=11 (F14c pridalo 8–11 — audity skupín; 12 rezervovaný)
        assert!(matches!(
            Envelope::decode(&b),
            Err(EnvelopeError::UnknownKind { code: 12 })
        ));

        // payload s iným druhom než hlavička obálky
        let raw = post("x").encode();
        assert!(matches!(
            Payload::decode(RecordKind::ChatMsg, &raw),
            Err(EnvelopeError::BadCbor)
        ));
    }

    /// Skrátené alebo poškodené bajty sa neprepúšia ako platná obálka.
    #[test]
    fn decode_rejects_truncated_input() {
        let bytes = sample().encode();
        assert!(Envelope::decode(&bytes[..bytes.len() - 1]).is_err());
        assert!(Envelope::decode(&[]).is_err());
        assert!(Envelope::decode(&[0x80]).is_err());
        // skrátený verejný kľúč autora (pole 4)
        let mut b = bytes.clone();
        b[0] = 0x8c; // array(12) — zámenná hlavička => BadCbor
        assert!(matches!(Envelope::decode(&b), Err(EnvelopeError::BadCbor)));
    }

    /// Pečiatka uzla viaže poradie k obsahu: zmena seq zmení hash obálky
    /// a zneplatní podpis pečiatky.
    #[test]
    fn stamp_is_bound_to_position_and_content() {
        let env = sample();
        assert!(env.verify_stamp_sig());
        let mut moved = env.clone();
        moved.stamp.node_seq = 2;
        assert!(!moved.verify_stamp_sig(), "posunutá pečiatka neplatí");
        assert_ne!(moved.hash(), env.hash());
    }

    /// **G7** — zlatý vektor celej obálky: pevné vstupy → pevné hex.
    ///
    /// Nezávislé overenie (2026-11-11, B2):
    /// - `body_hash`, `blind_hash`, `hash` sedia na výstup referenčného
    ///   `b3sum` CLI (BLAKE3 referenčná implementácia, verzia 1.8.7),
    /// - `author` aj `body_sig` overené knižnicou `cryptography` (OpenSSL)
    ///   — druhou, nezávislou implementáciou ed25519; jej podpis je
    ///   bajtovo zhodný s ed25519-dalek (determinizmus RFC 8032).
    ///
    /// Postup obnovenia/overenia je opísaný v README (sekcia Golden vektory).
    #[test]
    fn golden_g7_envelope_vectors() {
        let env = sample();
        assert_eq!(
            env.author.hex(),
            "873600d1521917ecef71ad1c1003f76cea9c9814e839915a757072a62844ab0d"
        );
        assert_eq!(
            env.body_hash.hex(),
            "c7ddc5870083178937b14ca0b4dae782e332d1dc5523fde5d97e923f651ee931"
        );
        assert_eq!(
            env.blind_hash.hex(),
            "1992e94b716c74ca676e760c8cf6548ba6c9e6e458b5707797b76686a19fe87b"
        );
        assert_eq!(
            env.hash().hex(),
            "cf1675f8ec4bf1925d188cdaa9302d114414beee02ec3fae76cc2b22f7a447c5"
        );
        assert_eq!(
            env.body_sig.hex(),
            "4a44c73c40b652f7852b139491076d4480c4a766e8f28f310cce58da1879f99c\
             63e19d3d09f269a8c6898db0ab2c698f0d46063d9eacc577594e4d1ccb18f30f"
        );
    }

    /// Ladiaci nástroj: vytlač hodnoty pre zlaté vektory
    /// (`cargo test -p core -- --ignored --nocapture dump_golden_vectors`).
    #[test]
    #[ignore = "len pre rucne vygenerovanie golden vektorov"]
    fn dump_golden_vectors() {
        let env = sample();
        println!("AUTHOR      = {}", env.author.hex());
        println!("BODY_HASH   = {}", env.body_hash.hex());
        println!("BLIND_HASH  = {}", env.blind_hash.hex());
        println!("ENV_HASH    = {}", env.hash().hex());
        println!("BODY_SIG    = {}", env.body_sig.hex());
        println!("ENV_BYTES   = {}", to_hex(&env.encode()));
    }
}
