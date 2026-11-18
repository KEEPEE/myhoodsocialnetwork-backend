//! Framing prepravnej vrstvy (rozhodnutie D-24).
//!
//! Vlastná tenká vrstva nad WSS: **8B hlavička**
//! `verzia (u8) | typ správy (u8) | kanál (u16) | dlžka payloadu (u32)`
//! a payload kódovaný **minicbor**. Verzia protokolu je v hlavičke každého
//! frame od F0 (D-22), handshake je `Hello`/`HelloAck`/`Reject` — naša
//! session vrstva, transport ju nevidí.
//!
//! B1 scaffold: header + Hello/Reject payload a roundtrip testy;
//! Noise handshake (`snow`) a `Link`/`Session` vrstva prídu v B5.

/// Dĺžka hlavičky frame v bajtoch (D-24: ver, type, channel, len).
pub const HEADER_LEN: usize = 8;

/// Verzia drôtu B1. Rastie len po dohodnutej zmene formátu (D-22).
pub const WIRE_VERSION: u8 = 0;

/// Bezpečná horná medza dĺžky payloadu pre B1 (4 MiB); reálne limity
/// nastavia kvóty uzla (D-33).
pub const MAX_PAYLOAD_LEN: u32 = 4 * 1024 * 1024;

/// Typy správ session vrstvy (hodnoty idú do hlavičky ako u8).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum MsgType {
    /// Handshake: proto_min/proto_max + capabilities.
    Hello = 1,
    /// Handshake OK: dohodnutá verzia + caps uzla.
    HelloAck = 2,
    /// Handshake zamietnutý (dôvod v payloade).
    Reject = 3,
    /// Heartbeat.
    Ping = 4,
    Pong = 5,
    /// Sync request/response (set-reconciliation, B5).
    Sync = 6,
    /// Prenos záznamu/obálky (B5).
    Record = 7,
    /// Potvrdenie prevzatia záznamu: hash + pozícia uzla (B5).
    Ack = 8,
    /// **F14a (MYHSN-56):** zmena role účtu — broadcast uzla po aplikovaní
    /// admin operácie. Posiela sa **len klientom, ktorí v `Hello`
    /// deklarovali cap `"roles"`** — starí klienti (Dart `MhFrame.decode`)
    /// na neznámy typ reláciu zahodia a reconnectujú, takže broadcast bez
    /// gate by spôsobil reconnect loop.
    RoleUpdate = 9,
    /// **F14c (MYHSN-58):** zmena kanálovej role / členstva / stíšenia v
    /// skupinovom kanáli — broadcast uzla po aplikovaní REST operácie.
    /// Posiela sa **len klientom s cap `"channels"`** (práve preto existuje
    /// nový cap: starí klienti vrátane F14b by na neznámy typ padli na
    /// reconnect loop). Pozor: číslo 10 zdieľa s `RecordKind::
    /// RevokeChannelRole` — iný menný priestor (typ frame vs. druh záznamu),
    /// zámena hrozí len nečitateľnému kódu, nie drôtu.
    ChannelRoleUpdate = 10,
}

impl MsgType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Hello),
            2 => Some(Self::HelloAck),
            3 => Some(Self::Reject),
            4 => Some(Self::Ping),
            5 => Some(Self::Pong),
            6 => Some(Self::Sync),
            7 => Some(Self::Record),
            8 => Some(Self::Ack),
            9 => Some(Self::RoleUpdate),
            10 => Some(Self::ChannelRoleUpdate),
            _ => None,
        }
    }
}

/// Hlavička frame: 8 bajtov, big-endian.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Header {
    pub version: u8,
    pub msg_type: u8,
    /// Multiplex kanál relácie (nie ChannelId — ten je v payloade).
    pub channel: u16,
    /// Dĺžka payloadu za hlavičkou.
    pub len: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FrameError {
    /// Buffer kratší ako 8B hlavička.
    TooShort,
    /// Nesúhlas verzie drôtu (poslucháč odpovie `Reject`).
    VersionMismatch { got: u8 },
    /// `len` v hlavičke nesedí s veľkosťou bufferu.
    BadLength { declared: u32, actual: usize },
    /// `len` nad MAX_PAYLOAD_LEN.
    TooLong { declared: u32 },
    /// Neznámy typ správy.
    UnknownType { got: u8 },
}

/// Zostav frame: 8B hlavička + payload.
pub fn encode_frame(header: &Header, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.push(header.version);
    out.push(header.msg_type);
    out.extend_from_slice(&header.channel.to_be_bytes());
    out.extend_from_slice(&header.len.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Rozparsov hlavičku a vráť (Header, payload). Kontroluje verziu, dĺžku
/// a známosť typu — podklad pre `Reject` (D-24).
pub fn decode_frame(bytes: &[u8]) -> Result<(Header, &[u8]), FrameError> {
    if bytes.len() < HEADER_LEN {
        return Err(FrameError::TooShort);
    }
    let version = bytes[0];
    if version != WIRE_VERSION {
        return Err(FrameError::VersionMismatch { got: version });
    }
    let msg_type = bytes[1];
    MsgType::from_u8(msg_type).ok_or(FrameError::UnknownType { got: msg_type })?;
    let channel = u16::from_be_bytes([bytes[2], bytes[3]]);
    let len = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if len > MAX_PAYLOAD_LEN {
        return Err(FrameError::TooLong { declared: len });
    }
    let actual = bytes.len() - HEADER_LEN;
    if len as usize != actual {
        return Err(FrameError::BadLength { declared: len, actual });
    }
    Ok((Header { version, msg_type, channel, len }, &bytes[HEADER_LEN..]))
}

/// Chyby dekódovania payloadov session vrstvy — jasný typ kvôli kontrole
/// dĺžok polí (minicbor sám o sebe 32-bajtovú dĺžku nekontroluje).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WireDecodeError {
    /// Payload nie je platné CBOR pre danú správu.
    BadCbor,
    /// Pole má inú dĺžku, než protokol vyžaduje.
    BadFieldLen {
        field: &'static str,
        expected: usize,
        got: usize,
    },
}

/// Dekoduj 32-bajtové pole s kontrolou dĺžky.
fn dec_arr32(dec: &mut minicbor::Decoder<'_>, field: &'static str) -> Result<[u8; 32], WireDecodeError> {
    let raw = dec.bytes().map_err(|_| WireDecodeError::BadCbor)?;
    if raw.len() != 32 {
        return Err(WireDecodeError::BadFieldLen {
            field,
            expected: 32,
            got: raw.len(),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    Ok(out)
}

/// Watermark kanála v `Hello` (D-29): klient oznámi, že má aplikované
/// záznamy kanála po pozíciu `(node_epoch, node_seq)` vrátane.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HelloWatermark {
    pub channel: [u8; 32],
    pub node_epoch: u64,
    pub node_seq: u64,
}

/// Payload `Hello` (D-24): obojsmerná kompatibilita verzií (D-22)
/// + deklarované capabilities + watermarky per kanál (D-29, B5).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Hello {
    pub proto_min: u16,
    pub proto_max: u16,
    pub caps: Vec<String>,
    /// Watermarky kanálov, ktoré klient už stíha (prázdne = nový klient).
    pub watermarks: Vec<HelloWatermark>,
    /// **F14a:** voliteľný 5. prvok — session token (hex) viazaný na
    /// reláciu, aby uzol mohol v `HelloAck` oznámiť `role`/`perms` a
    /// posielať `RoleUpdate`. Starí klienti ho neposielajú (`None`);
    /// uzol ho **nikde neloguje** (je to tajomstvo ako Bearer token).
    pub session: Option<String>,
}

/// Kóduj `Hello` ako minicbor pole
/// `[proto_min, proto_max, [caps...], [[channel, epoch, seq]...]]`.
/// (API minicbor 2.x: `Encoder::new(Vec)`, `array(len)`, `str`, `into_writer`.)
pub fn encode_hello(h: &Hello) -> Vec<u8> {
    let mut enc = minicbor::Encoder::new(Vec::new());
    // pole s presnou dĺžkou: 4 položky (starí klienti) alebo 5 s tokenom
    // (**F14a** — 5. prvok posielame len keď naozaj existuje)
    enc.array(if h.session.is_some() { 5 } else { 4 }).expect("in-memory encoder");
    enc.u16(h.proto_min).expect("in-memory encoder");
    enc.u16(h.proto_max).expect("in-memory encoder");
    enc.array(h.caps.len() as u64).expect("in-memory encoder");
    for c in &h.caps {
        enc.str(c).expect("in-memory encoder");
    }
    enc.array(h.watermarks.len() as u64).expect("in-memory encoder");
    for w in &h.watermarks {
        enc.array(3).expect("in-memory encoder");
        enc.bytes(&w.channel).expect("in-memory encoder");
        enc.u64(w.node_epoch).expect("in-memory encoder");
        enc.u64(w.node_seq).expect("in-memory encoder");
    }
    if let Some(s) = &h.session {
        enc.str(s).expect("in-memory encoder");
    }
    enc.into_writer()
}

/// Dekóduj `Hello` z minicbor payloadu.
///
/// Verzie 3-prvkového poľa (B1, bez watermarkov) sa stále akceptujú —
/// watermarky sú prázdne. 4-prvkové pole je forma od B5.
pub fn decode_hello(bytes: &[u8]) -> Result<Hello, WireDecodeError> {
    use WireDecodeError::BadCbor;
    let mut dec = minicbor::Decoder::new(bytes);
    let len = dec.array().map_err(|_| BadCbor)?;
    if !matches!(len, Some(3) | Some(4) | Some(5)) {
        return Err(BadCbor);
    }
    let proto_min = dec.u16().map_err(|_| BadCbor)?;
    let proto_max = dec.u16().map_err(|_| BadCbor)?;
    let n = dec.array().map_err(|_| BadCbor)?;
    let mut caps = Vec::new();
    for _ in 0..n.unwrap_or(0) {
        caps.push(dec.str().map_err(|_| BadCbor)?.to_string());
    }
    let mut watermarks = Vec::new();
    if len == Some(4) || len == Some(5) {
        let m = dec.array().map_err(|_| BadCbor)?;
        for _ in 0..m.unwrap_or(0) {
            if dec.array().map_err(|_| BadCbor)? != Some(3) {
                return Err(BadCbor);
            }
            let channel = dec_arr32(&mut dec, "channel")?;
            let node_epoch = dec.u64().map_err(|_| BadCbor)?;
            let node_seq = dec.u64().map_err(|_| BadCbor)?;
            watermarks.push(HelloWatermark { channel, node_epoch, node_seq });
        }
    }
    // **F14a:** 5. prvok = session token (hex reťazec). Prázdny reťazec
    // znamená „bez relácie“ — normalizujeme na `None`, aby uzol nemusel
    // riešiť dve formy neúspechu.
    let session = if len == Some(5) {
        match dec.str() {
            Ok(s) if !s.is_empty() => Some(s.to_string()),
            _ => None,
        }
    } else {
        None
    };
    Ok(Hello { proto_min, proto_max, caps, watermarks, session })
}

/// Epocha kanála v `HelloAck` — klient podľa nej zistí, či je za
/// epochou (D-25: obnova zo zálohy mení poradie).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ChannelEpoch {
    pub channel: [u8; 32],
    pub node_epoch: u64,
}

/// **F14c (MYHSN-58):** jedna položka 5. prvku `HelloAck` — kanálová rola
/// volajúceho v skupinovom kanáli: `[channel32, role_str, muted_bool]`.
/// `role_str ∈ "owner" | "admin" | "member"`, `muted` = stíšený (nemože
/// prispievať). Položiek je len toľko, koľko group kanálov sa volajúceho
/// niečoho týka (owner/admin/member), zoradené podľa bajtov kanála.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ChannelRoleEntry {
    pub channel: [u8; 32],
    pub role: String,
    pub muted: bool,
}

/// Payload `HelloAck` (B5): dohodnutá verzia + caps uzla (autorita
/// protokolu, D-29) + aktuálne epochy kanálov.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HelloAck {
    pub version: u8,
    pub caps: Vec<String>,
    pub epochs: Vec<ChannelEpoch>,
    /// **F14a:** voliteľný 4. prvok `[role, perms]` — plní ho uzol len
    /// klientom s cap `"roles"`. Starí klienti trvajú na 3 prvkoch
    /// (`decodeHelloAck` → `_definiteList(bytes, 3)`), preto musí ostať
    /// `None` pre relácie bez capu.
    pub role: Option<(String, u64)>,
    /// **F14c:** voliteľný 5. prvok `[[channel, role_str, muted]...]` —
    /// plní ho uzol len klientom s cap `"channels"` **a** `"roles"` a
    /// platnou session (rovnaká brána ako 4. prvok, aby 5. prvok nemohol
    /// existovať bez 4. — žiadne pozičné `null`). F14b klient akceptuje
    /// 3|4 prvky, 5 by zahodil → gating je povinný.
    pub channel_roles: Option<Vec<ChannelRoleEntry>>,
}

/// Kóduj `HelloAck` ako `[version, [caps...], [[channel, epoch]...]]`.
pub fn encode_hello_ack(a: &HelloAck) -> Vec<u8> {
    let mut enc = minicbor::Encoder::new(Vec::new());
    // 4. prvok len keď ho klient môže prečítať (cap "roles") — inak
    // presne 3 prvky, ako ich čakajú starí klienti. 5. prvok len s 4.
    // (F14c: cap "channels" + "roles" + session).
    let len = if a.channel_roles.is_some() {
        5
    } else if a.role.is_some() {
        4
    } else {
        3
    };
    enc.array(len).expect("in-memory encoder");
    enc.u8(a.version).expect("in-memory encoder");
    enc.array(a.caps.len() as u64).expect("in-memory encoder");
    for c in &a.caps {
        enc.str(c).expect("in-memory encoder");
    }
    enc.array(a.epochs.len() as u64).expect("in-memory encoder");
    for e in &a.epochs {
        enc.array(2).expect("in-memory encoder");
        enc.bytes(&e.channel).expect("in-memory encoder");
        enc.u64(e.node_epoch).expect("in-memory encoder");
    }
    if let Some((role, perms)) = &a.role {
        enc.array(2).expect("in-memory encoder");
        enc.str(role).expect("in-memory encoder");
        enc.u64(*perms).expect("in-memory encoder");
    }
    if let Some(entries) = &a.channel_roles {
        enc.array(entries.len() as u64).expect("in-memory encoder");
        for e in entries {
            enc.array(3).expect("in-memory encoder");
            enc.bytes(&e.channel).expect("in-memory encoder");
            enc.str(&e.role).expect("in-memory encoder");
            enc.bool(e.muted).expect("in-memory encoder");
        }
    }
    enc.into_writer()
}

/// Dekóduj `HelloAck`.
pub fn decode_hello_ack(bytes: &[u8]) -> Result<HelloAck, WireDecodeError> {
    use WireDecodeError::BadCbor;
    let mut dec = minicbor::Decoder::new(bytes);
    // **F14a:** pripúšťame 3 (starí klienti) aj 4 prvky (s `[role, perms]`).
    // **F14c:** pripúšťame aj 5 prvkov (so zoznamom kanálových rolí).
    let len = dec.array().map_err(|_| BadCbor)?;
    if !matches!(len, Some(3) | Some(4) | Some(5)) {
        return Err(BadCbor);
    }
    let version = dec.u8().map_err(|_| BadCbor)?;
    let n = dec.array().map_err(|_| BadCbor)?;
    let mut caps = Vec::new();
    for _ in 0..n.unwrap_or(0) {
        caps.push(dec.str().map_err(|_| BadCbor)?.to_string());
    }
    let m = dec.array().map_err(|_| BadCbor)?;
    let mut epochs = Vec::new();
    for _ in 0..m.unwrap_or(0) {
        if dec.array().map_err(|_| BadCbor)? != Some(2) {
            return Err(BadCbor);
        }
        let channel = dec_arr32(&mut dec, "channel")?;
        let node_epoch = dec.u64().map_err(|_| BadCbor)?;
        epochs.push(ChannelEpoch { channel, node_epoch });
    }
    let role = if len >= Some(4) {
        if dec.array().map_err(|_| BadCbor)? != Some(2) {
            return Err(BadCbor);
        }
        let role = dec.str().map_err(|_| BadCbor)?.to_string();
        let perms = dec.u64().map_err(|_| BadCbor)?;
        Some((role, perms))
    } else {
        None
    };
    let channel_roles = if len == Some(5) {
        let k = dec.array().map_err(|_| BadCbor)?;
        let mut entries = Vec::new();
        for _ in 0..k.unwrap_or(0) {
            if dec.array().map_err(|_| BadCbor)? != Some(3) {
                return Err(BadCbor);
            }
            let channel = dec_arr32(&mut dec, "channel")?;
            let role = dec.str().map_err(|_| BadCbor)?.to_string();
            let muted = dec.bool().map_err(|_| BadCbor)?;
            entries.push(ChannelRoleEntry { channel, role, muted });
        }
        Some(entries)
    } else {
        None
    };
    Ok(HelloAck {
        version,
        caps,
        epochs,
        role,
        channel_roles,
    })
}

/// **F14a (MYHSN-56):** payload `RoleUpdate` (MsgType 9) —
/// `[account32, username, role, perms]`. Broadcastuje ho uzol po
/// aplikovaní zmeny role, a to len reláciám s cap `"roles"`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RoleUpdate {
    pub account: [u8; 32],
    pub username: String,
    pub role: String,
    pub perms: u64,
}

pub fn encode_role_update(u: &RoleUpdate) -> Vec<u8> {
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.array(4).expect("in-memory encoder");
    enc.bytes(&u.account).expect("in-memory encoder");
    enc.str(&u.username).expect("in-memory encoder");
    enc.str(&u.role).expect("in-memory encoder");
    enc.u64(u.perms).expect("in-memory encoder");
    enc.into_writer()
}

pub fn decode_role_update(bytes: &[u8]) -> Result<RoleUpdate, WireDecodeError> {
    use WireDecodeError::BadCbor;
    let mut dec = minicbor::Decoder::new(bytes);
    if dec.array().map_err(|_| BadCbor)? != Some(4) {
        return Err(BadCbor);
    }
    let account = dec_arr32(&mut dec, "account")?;
    let username = dec.str().map_err(|_| BadCbor)?.to_string();
    let role = dec.str().map_err(|_| BadCbor)?.to_string();
    let perms = dec.u64().map_err(|_| BadCbor)?;
    Ok(RoleUpdate { account, username, role, perms })
}

/// **F14c (MYHSN-58):** payload `ChannelRoleUpdate` (MsgType 10) —
/// `[channel32, account32, username, channel_role, muted_bool]`.
/// **Stavový** (nie akčný) tvar: hovorí, čím účet v kanáli JE —
/// `channel_role ∈ "owner" | "admin" | "member" | "none"` (`none` = už
/// nie je člen) a `muted` = stíšený. Broadcast uzla po grant/revoke/
/// transfer/mute, len reláciám s cap `"channels"`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ChannelRoleUpdate {
    pub channel: [u8; 32],
    pub account: [u8; 32],
    pub username: String,
    pub channel_role: String,
    pub muted: bool,
}

pub fn encode_channel_role_update(u: &ChannelRoleUpdate) -> Vec<u8> {
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.array(5).expect("in-memory encoder");
    enc.bytes(&u.channel).expect("in-memory encoder");
    enc.bytes(&u.account).expect("in-memory encoder");
    enc.str(&u.username).expect("in-memory encoder");
    enc.str(&u.channel_role).expect("in-memory encoder");
    enc.bool(u.muted).expect("in-memory encoder");
    enc.into_writer()
}

pub fn decode_channel_role_update(bytes: &[u8]) -> Result<ChannelRoleUpdate, WireDecodeError> {
    use WireDecodeError::BadCbor;
    let mut dec = minicbor::Decoder::new(bytes);
    if dec.array().map_err(|_| BadCbor)? != Some(5) {
        return Err(BadCbor);
    }
    let channel = dec_arr32(&mut dec, "channel")?;
    let account = dec_arr32(&mut dec, "account")?;
    let username = dec.str().map_err(|_| BadCbor)?.to_string();
    let channel_role = dec.str().map_err(|_| BadCbor)?.to_string();
    let muted = dec.bool().map_err(|_| BadCbor)?;
    Ok(ChannelRoleUpdate {
        channel,
        account,
        username,
        channel_role,
        muted,
    })
}

// --- kódy `Reject` (D-24: Reject s kódom) --------------------------------

/// Nekompatibilná verzia protokolu (hlavička alebo rozsah z `Hello`).
pub const REJECT_VERSION: u16 = 1;
/// Chýbajúca/neplatná handshake (prvá správa nie je Hello).
pub const REJECT_HANDSHAKE: u16 = 2;
/// Záznam zamietnutý pri append (zlá obálka, neplatný/revokovaný kľúč,
/// neznámy kanál) — relácia môže pokračovať ďalej.
pub const REJECT_RECORD: u16 = 3;
/// Porušenie poradia správ (neočakávaný typ, neznámy typ).
pub const REJECT_PROTOCOL: u16 = 4;

/// Payload `Reject` (D-24): strojovo čitateľný kód + ľudský dôvod.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Reject {
    pub code: u16,
    pub reason: String,
}

/// Kóduj `Reject` ako `[code, reason]`.
pub fn encode_reject(r: &Reject) -> Vec<u8> {
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.array(2).expect("in-memory encoder");
    enc.u16(r.code).expect("in-memory encoder");
    enc.str(&r.reason).expect("in-memory encoder");
    enc.into_writer()
}

/// Dekóduj `Reject`.
pub fn decode_reject(bytes: &[u8]) -> Result<Reject, WireDecodeError> {
    use WireDecodeError::BadCbor;
    let mut dec = minicbor::Decoder::new(bytes);
    if dec.array().map_err(|_| BadCbor)? != Some(2) {
        return Err(BadCbor);
    }
    let code = dec.u16().map_err(|_| BadCbor)?;
    let reason = dec.str().map_err(|_| BadCbor)?.to_string();
    Ok(Reject { code, reason })
}

/// Payload `Ack` (B5): uzol potvrdí prevzatie záznamu — `hash` je
/// kanonický hash **uloženej** obálky (po opečiatkovaní) a `(channel,
/// node_epoch, node_seq)` je pozícia v logu. Pri duplikáte vráti uzol
/// rovnaké hodnoty (idempotentná aplikácia, D-25/D-29).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ack {
    pub hash: [u8; 32],
    pub channel: [u8; 32],
    pub node_epoch: u64,
    pub node_seq: u64,
}

/// Kóduj `Ack` ako `[hash, channel, epoch, seq]`.
pub fn encode_ack(a: &Ack) -> Vec<u8> {
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.array(4).expect("in-memory encoder");
    enc.bytes(&a.hash).expect("in-memory encoder");
    enc.bytes(&a.channel).expect("in-memory encoder");
    enc.u64(a.node_epoch).expect("in-memory encoder");
    enc.u64(a.node_seq).expect("in-memory encoder");
    enc.into_writer()
}

/// Dekóduj `Ack`.
pub fn decode_ack(bytes: &[u8]) -> Result<Ack, WireDecodeError> {
    use WireDecodeError::BadCbor;
    let mut dec = minicbor::Decoder::new(bytes);
    if dec.array().map_err(|_| BadCbor)? != Some(4) {
        return Err(BadCbor);
    }
    let hash = dec_arr32(&mut dec, "hash")?;
    let channel = dec_arr32(&mut dec, "channel")?;
    let node_epoch = dec.u64().map_err(|_| BadCbor)?;
    let node_seq = dec.u64().map_err(|_| BadCbor)?;
    Ok(Ack { hash, channel, node_epoch, node_seq })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity test 2: roundtrip frame — 8B hlavička + minicbor payload.
    #[test]
    fn frame_roundtrip() {
        let hello = Hello {
            proto_min: 0,
            proto_max: 1,
            caps: vec!["sync".to_string(), "media".to_string()],
            watermarks: vec![],
            session: None,
        };
        let payload = encode_hello(&hello);
        let header = Header {
            version: WIRE_VERSION,
            msg_type: MsgType::Hello as u8,
            channel: 7,
            len: payload.len() as u32,
        };
        let bytes = encode_frame(&header, &payload);
        assert_eq!(bytes.len(), HEADER_LEN + payload.len());

        let (hdr, got_payload) = decode_frame(&bytes).unwrap();
        assert_eq!(hdr, header);
        assert_eq!(decode_hello(got_payload).unwrap(), hello);
    }

    /// Roundtrip prázdneho payloadu (Ping/Pong).
    #[test]
    fn empty_payload_roundtrip() {
        let header = Header {
            version: WIRE_VERSION,
            msg_type: MsgType::Ping as u8,
            channel: 0,
            len: 0,
        };
        let bytes = encode_frame(&header, &[]);
        let (hdr, payload) = decode_frame(&bytes).unwrap();
        assert_eq!(hdr, header);
        assert!(payload.is_empty());
    }

    /// Odmietnutie: zlá verzia, skrátený buffer, neznámy typ, nesúlad dĺžky.
    #[test]
    fn decode_rejects_bad_frames() {
        let header = Header { version: WIRE_VERSION, msg_type: MsgType::Pong as u8, channel: 0, len: 2 };
        let mut bytes = encode_frame(&header, b"ab");

        // zlá verzia
        let mut bad = bytes.clone();
        bad[0] = WIRE_VERSION + 9;
        assert_eq!(decode_frame(&bad), Err(FrameError::VersionMismatch { got: WIRE_VERSION + 9 }));

        // skrátený buffer
        bytes.truncate(HEADER_LEN + 1);
        assert!(matches!(decode_frame(&bytes), Err(FrameError::BadLength { .. })));

        // neznámy typ
        let bad_type = Header { version: WIRE_VERSION, msg_type: 99, channel: 0, len: 0 };
        assert!(matches!(
            decode_frame(&encode_frame(&bad_type, &[])),
            Err(FrameError::UnknownType { got: 99 })
        ));

        // buffer kratší ako hlavička
        assert_eq!(decode_frame(b"abc"), Err(FrameError::TooShort));
    }

    // --- B5 (MYHSN-7): payloady session protokolu ------------------------

    /// **Kritérium B5 (Hello):** watermarky per kanál prejdú roundtripom
    /// presne — epocha aj seq pre každých 32 bajtov kanála.
    #[test]
    fn hello_watermarks_roundtrip() {
        let hello = Hello {
            proto_min: 0,
            proto_max: 0,
            caps: vec!["sync".to_string()],
            watermarks: vec![
                HelloWatermark { channel: [0xaa; 32], node_epoch: 0, node_seq: 1 },
                HelloWatermark { channel: [0xbb; 32], node_epoch: 3, node_seq: 4_000_000 },
            ],
            session: None,
        };
        let bytes = encode_hello(&hello);
        assert_eq!(decode_hello(&bytes).unwrap(), hello);
    }

    /// Späťová kompatibilita: 3-prvkové `Hello` z B1 (bez watermarkov)
    /// sa dekóduje s prázdnych zoznamom — stará apka nesmie spadnúť.
    #[test]
    fn hello_accepts_legacy_three_field_array() {
        let mut enc = minicbor::Encoder::new(Vec::new());
        enc.array(3).unwrap();
        enc.u16(0).unwrap();
        enc.u16(0).unwrap();
        enc.array(1).unwrap();
        enc.str("sync").unwrap();
        let bytes = enc.into_writer();

        let hello = decode_hello(&bytes).unwrap();
        assert_eq!(hello.proto_min, 0);
        assert_eq!(hello.caps, vec!["sync".to_string()]);
        assert!(hello.watermarks.is_empty());
    }

    /// `HelloAck` roundtrip: verzia, caps aj epochy kanálov.
    #[test]
    fn hello_ack_roundtrip() {
        let ack = HelloAck {
            version: WIRE_VERSION,
            caps: vec!["sync".to_string()],
            epochs: vec![
                ChannelEpoch { channel: [0x01; 32], node_epoch: 0 },
                ChannelEpoch { channel: [0x02; 32], node_epoch: 7 },
            ],
            role: None,
            channel_roles: None,
        };
        let bytes = encode_hello_ack(&ack);
        assert_eq!(decode_hello_ack(&bytes).unwrap(), ack);

        // prázdne zoznamy sú legitímne (uzol bez kanálov)
        let empty = HelloAck {
            version: WIRE_VERSION,
            caps: vec![],
            epochs: vec![],
            role: None,
            channel_roles: None,
        };
        assert_eq!(decode_hello_ack(&encode_hello_ack(&empty)).unwrap(), empty);
    }

    /// `Reject` roundtrip + kódy sú stabilné konštanty (D-24).
    #[test]
    fn reject_roundtrip_and_codes() {
        let r = Reject { code: REJECT_VERSION, reason: "proto 5..9 nepodporujeme".to_string() };
        let bytes = encode_reject(&r);
        assert_eq!(decode_reject(&bytes).unwrap(), r);
        // kódy sa nesmú meniť — klienti na ne reagujú strojovo
        assert_eq!((REJECT_VERSION, REJECT_HANDSHAKE, REJECT_RECORD, REJECT_PROTOCOL), (1, 2, 3, 4));
    }

    /// `Ack` roundtrip: hash + pozícia (hash aj channel sú 32B, dlhé
    /// hodnoty seq prechádzajú bez skrátenia — CBOR integer shortest-form).
    #[test]
    fn ack_roundtrip() {
        let a = Ack { hash: [0xf1; 32], channel: [0xc2; 32], node_epoch: 2, node_seq: 123_456_789 };
        let bytes = encode_ack(&a);
        assert_eq!(decode_ack(&bytes).unwrap(), a);
    }

    /// Typ `Ack` je známy hlavičke (inak by `decode_frame` zahodil správu).
    /// **F14a:** typ 9 (`RoleUpdate`) je odteraz známy tiež.
    /// **F14c:** typ 10 (`ChannelRoleUpdate`) — typ 11 už nie.
    #[test]
    fn ack_msg_type_known() {
        assert_eq!(MsgType::from_u8(8), Some(MsgType::Ack));
        assert_eq!(MsgType::Ack as u8, 8);
        assert_eq!(MsgType::from_u8(9), Some(MsgType::RoleUpdate));
        assert_eq!(MsgType::RoleUpdate as u8, 9);
        assert_eq!(MsgType::from_u8(10), Some(MsgType::ChannelRoleUpdate));
        assert_eq!(MsgType::ChannelRoleUpdate as u8, 10);
        assert_eq!(MsgType::from_u8(11), None);
    }

    /// **F14a — spätná kompatibilita `Hello`:** starý 4-prvký `Hello`
    /// (Dart apka posiela `caps=["sync"]` + watermarky, bez tokena) sa
    /// MUSÍ dekódovať s `session: None`. Nový 5-prvký s tokenom likewise.
    #[test]
    fn hello_v4_still_decodes_and_v5_carries_session() {
        // 4 prvky: [proto_min, proto_max, caps, watermarks]
        let old = Hello {
            proto_min: 0,
            proto_max: 0,
            caps: vec!["sync".to_string()],
            watermarks: vec![HelloWatermark { channel: [0x11; 32], node_epoch: 0, node_seq: 5 }],
            session: None,
        };
        let bytes = encode_hello(&old);
        assert_eq!(decode_hello(&bytes).unwrap(), old);

        let new = Hello { session: Some("aa".repeat(32)), ..old.clone() };
        let bytes5 = encode_hello(&new);
        assert_eq!(decode_hello(&bytes5).unwrap(), new);

        // prázdny token = žiadna relácia (normalizácia na None)
        let blank = Hello { session: Some(String::new()), ..old };
        let decoded = decode_hello(&encode_hello(&blank)).unwrap();
        assert_eq!(decoded.session, None, "prázdny token sa normalizuje na None");
    }

    /// **F14a — spätná kompatibilita `HelloAck`:** 3-prvký tvar (starí
    /// klienti trvajú na presne 3) musí ostať 3-prvký; 4-prvký s
    /// `[role, perms]` sa dekóduje roundtripom.
    #[test]
    fn hello_ack_3_and_4_element_forms() {
        let plain = HelloAck {
            version: WIRE_VERSION,
            caps: vec!["sync".to_string()],
            epochs: vec![ChannelEpoch { channel: [0x01; 32], node_epoch: 0 }],
            role: None,
            channel_roles: None,
        };
        let bytes = encode_hello_ack(&plain);
        // prvý prvok CBOR definite array 3 = 0x83
        assert_eq!(bytes[0], 0x83, "bez role MUSÍ byť definite array 3");
        assert_eq!(decode_hello_ack(&bytes).unwrap(), plain);

        let with_role = HelloAck { role: Some(("moderator".to_string(), 5)), ..plain };
        let bytes4 = encode_hello_ack(&with_role);
        assert_eq!(bytes4[0], 0x84, "s role je definite array 4");
        assert_eq!(decode_hello_ack(&bytes4).unwrap(), with_role);
    }

    /// **F14a:** `RoleUpdate` roundtrip + frame s typom 9 prejde
    /// `decode_frame` (inak by ho uzol sám zahodil).
    #[test]
    fn role_update_roundtrip_and_frame() {
        let u = RoleUpdate {
            account: [0x22; 32],
            username: "jano".to_string(),
            role: "moderator".to_string(),
            perms: 5,
        };
        assert_eq!(decode_role_update(&encode_role_update(&u)).unwrap(), u);
        let payload = encode_role_update(&u);
        let f = encode_frame(
            &Header {
                version: WIRE_VERSION,
                msg_type: MsgType::RoleUpdate as u8,
                channel: 0,
                len: payload.len() as u32,
            },
            &payload,
        );
        let (h, p) = decode_frame(&f).unwrap();
        assert_eq!(h.msg_type, MsgType::RoleUpdate as u8);
        assert_eq!(decode_role_update(p).unwrap(), u);
    }

    /// **F14c:** `ChannelRoleUpdate` roundtrip + frame s typom 10 prejde
    /// `decode_frame` (inak by ho uzol aj klient zahodili).
    #[test]
    fn channel_role_update_roundtrip_and_frame() {
        let u = ChannelRoleUpdate {
            channel: [7u8; 32],
            account: [3u8; 32],
            username: "juraj".into(),
            channel_role: "admin".into(),
            muted: true,
        };
        let payload = encode_channel_role_update(&u);
        assert_eq!(decode_channel_role_update(&payload).unwrap(), u);
        let f = encode_frame(
            &Header {
                version: WIRE_VERSION,
                msg_type: MsgType::ChannelRoleUpdate as u8,
                channel: 0,
                len: payload.len() as u32,
            },
            &payload,
        );
        let (h, p) = decode_frame(&f).unwrap();
        assert_eq!(h.msg_type, MsgType::ChannelRoleUpdate as u8);
        assert_eq!(decode_channel_role_update(p).unwrap(), u);
        // "none" po revokácii je platná hodnota
        let none = ChannelRoleUpdate { channel_role: "none".into(), muted: false, ..u };
        assert_eq!(decode_channel_role_update(&encode_channel_role_update(&none)).unwrap(), none);
    }

    /// **F14c — spätná kompatibilita `HelloAck`:** 3-prvkový (starí
    /// klienti, F14b bez capu) aj 4-prvkový (F14b s capom „roles“)
    /// zostávajú bitovo identické s F14a; 5. prvok vznikne len keď
    /// `channel_roles` je `Some`. Dekóder prijíma 3|4|5.
    #[test]
    fn hello_ack_3_4_5_elements_compatible() {
        let base = HelloAck {
            version: WIRE_VERSION,
            caps: vec!["sync".into()],
            epochs: vec![ChannelEpoch { channel: [1u8; 32], node_epoch: 4 }],
            role: None,
            channel_roles: None,
        };
        let b3 = encode_hello_ack(&base);
        assert_eq!(&b3[..1], &[0x83], "definite array(3)");
        assert_eq!(decode_hello_ack(&b3).unwrap(), base);

        let with_role = HelloAck { role: Some(("moderator".into(), 3)), ..base.clone() };
        let b4 = encode_hello_ack(&with_role);
        assert_eq!(&b4[..1], &[0x84], "definite array(4)");
        assert_eq!(decode_hello_ack(&b4).unwrap(), with_role);

        let with_channels = HelloAck {
            channel_roles: Some(vec![
                ChannelRoleEntry { channel: [2u8; 32], role: "owner".into(), muted: false },
                ChannelRoleEntry { channel: [3u8; 32], role: "member".into(), muted: true },
            ]),
            ..with_role.clone()
        };
        let b5 = encode_hello_ack(&with_channels);
        assert_eq!(&b5[..1], &[0x85], "definite array(5)");
        assert_eq!(decode_hello_ack(&b5).unwrap(), with_channels);
        // 5-prvký prečítajú aj staršie dekódery: F14b by 5 zahodil, preto
        // uzol 5. prvok posiela len klientom s oboma capmi (test v node).
    }

    /// Krátke 32B polia sa odmietnu (nie ticho doplnia nulami).
    #[test]
    fn decode_rejects_short_hash_field() {
        let mut enc = minicbor::Encoder::new(Vec::new());
        enc.array(4).unwrap();
        enc.bytes(&[1u8; 8]).unwrap(); // hash má byt 32B
        enc.bytes(&[2u8; 32]).unwrap();
        enc.u64(0).unwrap();
        enc.u64(1).unwrap();
        assert_eq!(
            decode_ack(&enc.into_writer()),
            Err(WireDecodeError::BadFieldLen { field: "hash", expected: 32, got: 8 })
        );
    }
}
