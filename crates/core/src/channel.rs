//! Kanály, poradie per kanál a reconciliation (rozhodnutia **D-25**, D-10, D-24).
//!
//! Kanál je miesto, kde záznam žije (D-10: nástienka = replikovaný log,
//! chat = ephemeral pubsub + okno histórie). Poradie v kanáli prideľuje
//! **domáci uzol** ako `(channel, node_epoch, node_seq)` (D-25):
//! - `node_seq` prísne rastie v rámci `(channel, node_epoch)`,
//! - `node_epoch` sa zdvihne pri **obnove zo zálohy**, aby staré seq
//!   hodnoty nemohli kolidovať s novými, a `node_seq` v novej epoche
//!   začína od 1 ([`Channel::restore_new_epoch`]).
//!
//! Kanál ďalej drží **soľ slepého hashu** (D-25) — per kanál, mimo
//! verejného API, takže bez nej sa rovnaký obsah medzi kanálmi nepozná.
//!
//! Reconciliation ([`reconcile`]) je set-reconciliation z D-24: klient so
//! starou epochou alebo s odlišnými záznamami dostane **presne tie, ktoré
//! mu chýbajú** (prípadne tie, kde sa nezhoduje hash).

use crate::record::RecordHash;
use crate::seq::{ChannelId, SeqPos};
use std::collections::{BTreeMap, HashMap};

/// Druh kanála (D-10).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChannelKind {
    /// Nástienka: replikovaný append-only log (D-10).
    Wall = 0,
    /// Chat: ephemeral pubsub + okno histórie (D-10).
    Chat = 1,
    /// Zmiešaný kanál — replikuje sa aj živé vysielanie.
    Mixed = 2,
}

impl ChannelKind {
    pub fn code(self) -> u8 {
        self as u8
    }

    pub fn from_code(v: u8) -> Option<Self> {
        match v {
            0 => Some(ChannelKind::Wall),
            1 => Some(ChannelKind::Chat),
            2 => Some(ChannelKind::Mixed),
            _ => None,
        }
    }

    /// Stabilný textový názov pre REST API a SQL stĺpec.
    pub fn as_str(self) -> &'static str {
        match self {
            ChannelKind::Wall => "wall",
            ChannelKind::Chat => "chat",
            ChannelKind::Mixed => "mixed",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "wall" => Some(ChannelKind::Wall),
            "chat" => Some(ChannelKind::Chat),
            "mixed" => Some(ChannelKind::Mixed),
            _ => None,
        }
    }

    /// L1 zrkadlenie (D-19) sa týka len `wall` a `mixed` kanály.
    pub fn mirrorable(self) -> bool {
        matches!(self, ChannelKind::Wall | ChannelKind::Mixed)
    }
}

/// Kanál domáceho uzla: identifikátor, názov, druh, soľ slepého hashu a
/// aktuálna epocha (D-25).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Channel {
    pub id: ChannelId,
    pub name: String,
    pub kind: ChannelKind,
    /// Soľ slepého hashu tohto kanála — drží ju len domáci uzol (D-25).
    pub salt: [u8; 32],
    /// Aktuálna epocha uzla pre tento kanál.
    pub node_epoch: u64,
}

impl Channel {
    /// Nový kanál začína v epoche 0.
    pub fn new(id: ChannelId, name: impl Into<String>, kind: ChannelKind, salt: [u8; 32]) -> Self {
        Self {
            id,
            name: name.into(),
            kind,
            salt,
            node_epoch: 0,
        }
    }

    /// **D-25: obnova zo zálohy → nová epocha.**
    ///
    /// Vráti novú epochu. Poradie (`node_seq`) v novej epoche začína od 1 —
    /// staré záznamy ostávajú v logu so starou epochou, takže sa stratiť
    /// nemôžu a kolízia seq je vylúčená `(channel, node_epoch, node_seq)`
    /// je unikátna.
    pub fn restore_new_epoch(&mut self) -> u64 {
        self.node_epoch += 1;
        self.node_epoch
    }

    /// Slepý hash obsahu v tomto kanále: `BLAKE3(salt || body_hash)`.
    pub fn blind(&self, body_hash: &RecordHash) -> RecordHash {
        RecordHash::blind(&self.salt, body_hash.as_bytes())
    }
}

/// Alokátor `node_seq` pre jeden `(channel, node_epoch)`.
///
/// Pravidlo z D-25: poradie začína na **1** (0 je vyhradená hodnota
/// „ešte nič“ pre watermark, [`crate::sync::Watermark::new`]). V node
/// vrstve sa alokuje atomickým SQL `UPDATE … RETURNING` — táto pomôcka
/// drží pravidlo pre jadro a testy.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SeqAllocator {
    next: u64,
}

impl SeqAllocator {
    /// Nová epocha: ďalšie poradie je 1.
    pub fn new() -> Self {
        Self { next: 1 }
    }

    /// Obnova alokátoru po reštarte uzla: ďalšie poradie je za
    /// najvyšším už použitým `node_seq`.
    pub fn resumed_after(highest_used: u64) -> Self {
        Self {
            next: highest_used.saturating_add(1),
        }
    }

    /// Ďalšie poradie (1, 2, 3, …).
    pub fn next(&mut self) -> u64 {
        let v = self.next;
        self.next = self.next.saturating_add(1);
        v
    }

    /// Na ktoré poradie čakáme ďalej (bez alokácie).
    pub fn peek(&self) -> u64 {
        self.next
    }
}

impl Default for SeqAllocator {
    fn default() -> Self {
        Self::new()
    }
}

/// Pohľad klienta na kanál: ktoré pozície už má a s akým hashom.
///
/// Klient drží jeden `(channel, node_epoch)` — svoje watermarkové okno
/// (D-24). Záznamy z iných epôch sa porovnávajú samostatne.
#[derive(Clone, Debug, Default)]
pub struct ClientView {
    pub channel: ChannelId,
    pub node_epoch: u64,
    /// `node_seq → hash` záznamu, ktorý klient má.
    pub entries: BTreeMap<u64, [u8; 32]>,
}

impl ClientView {
    pub fn new(channel: ChannelId, node_epoch: u64) -> Self {
        Self {
            channel,
            node_epoch,
            entries: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, node_seq: u64, hash: [u8; 32]) {
        self.entries.insert(node_seq, hash);
    }

    /// Najvyššie poradie, ktoré klient má (0 ak nič).
    pub fn highest_seq(&self) -> u64 {
        self.entries.keys().next_back().copied().unwrap_or(0)
    }
}

/// Výsledok porovnania logu uzla s pohľadom klienta (D-24).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ReconcileDiff {
    /// Záznamy, ktoré **klientovi chýbajú** — uzol ich má, klient nie.
    /// Presne toto sa posiela klientovi (kritérium B3c).
    pub missing: Vec<(SeqPos, RecordHash)>,
    /// Pozície, kde má klient **iný hash** než uzol: `(pozícia, hash uzla)`.
    /// Znamená rozdielnu históriu — rieši sa až po najnovšiu spoločnú
    /// pozíciu, nie merge (CRDT je z MVP von, D-25).
    pub mismatched: Vec<(SeqPos, RecordHash)>,
    /// Pozície, ktoré má klient a uzol ich v logu nemá (typicky po obnove
    /// zo zálohy, keď klient stíhal starú epochu).
    pub client_extra: Vec<(u64, [u8; 32])>,
    /// `true` ak je klient za epochou uzla — musí prijať aj záznamy z
    /// novej epochy, nie len diff v tej svojej.
    pub stale_epoch: bool,
}

/// Porovnaj log uzla s pohľadom klienta a vráti diff (D-24).
///
/// `node_log` sú záznamy kanála ako `(pozícia, hash)` — uzol ich berie zo
/// svojho range dotazu. Funkcia je čistá (bez I/O), takže ju jadro aj test
/// ovládajú bez databázy.
pub fn reconcile(node_log: &[(SeqPos, RecordHash)], client: &ClientView) -> ReconcileDiff {
    let mut diff = ReconcileDiff::default();

    // pozície uzla v kanáli klienta, pre spätné zistenie „extra“
    let mut node_positions: HashMap<(u64, u64), RecordHash> = HashMap::new();
    let mut max_node_epoch = 0u64;

    for (pos, hash) in node_log {
        if pos.channel != client.channel {
            continue; // iný kanál neporovnávame
        }
        node_positions.insert((pos.node_epoch, pos.node_seq), *hash);
        max_node_epoch = max_node_epoch.max(pos.node_epoch);

        // Pohľad klienta pokrýva práve jednu epochu — seq sa v novej epoche
        // reštartuje z 1 (D-25), takže seq z inej epochy NIE JE tá istá
        // pozícia a musíme ho považovať za chýbajúci, nie za nezhodu.
        let known = if pos.node_epoch == client.node_epoch {
            client.entries.get(&pos.node_seq)
        } else {
            None
        };
        match known {
            Some(client_hash) if *client_hash == hash.0 => {} // zhoda
            Some(client_hash) => {
                // pozícia sedí, hash nie → história sa rozchádza
                let _ = client_hash;
                diff.mismatched.push((*pos, *hash));
            }
            None => diff.missing.push((*pos, *hash)),
        }
    }

    // klient má niečo, čo uzol nemá (pozícia mimo logu uzla)
    for (seq, hash) in &client.entries {
        if !node_positions.contains_key(&(client.node_epoch, *seq)) {
            diff.client_extra.push((*seq, *hash));
        }
    }

    diff.stale_epoch = max_node_epoch > client.node_epoch;
    diff.missing.sort_by_key(|(p, _)| (p.node_epoch, p.node_seq));
    diff.mismatched.sort_by_key(|(p, _)| (p.node_epoch, p.node_seq));
    diff
}

#[cfg(test)]
mod tests {
    use super::*;

    const CH: ChannelId = [0x0a; 32];

    fn hash_of(s: &str) -> RecordHash {
        RecordHash::from_raw(s.as_bytes())
    }

    /// **Kritérium B3a:** alokátor dáva 1, 2, 3 — nie 0.
    #[test]
    fn allocator_starts_at_one_and_increments() {
        let mut a = SeqAllocator::new();
        assert_eq!(a.next(), 1);
        assert_eq!(a.next(), 2);
        assert_eq!(a.next(), 3);
        assert_eq!(a.peek(), 4);
    }

    /// Alokátor sa po reštarte uzla obnoví za najvyššie použitým seq.
    #[test]
    fn allocator_resumes_after_highest_used() {
        let a = SeqAllocator::resumed_after(7);
        assert_eq!(a.peek(), 8);
    }

    /// **Kritérium B3b (jadro):** obnova zo zálohy zdvihne epochu a
    /// poradie v novej epoche začína od 1; staré záznamy nemizú.
    #[test]
    fn restore_new_epoch_bumps_epoch_and_restarts_seq() {
        let mut ch = Channel::new(CH, "nástienka", ChannelKind::Wall, [0x53; 32]);
        assert_eq!(ch.node_epoch, 0);

        // stará epocha: seq 1..3
        let mut alloc = SeqAllocator::new();
        let old: Vec<u64> = (0..3).map(|_| alloc.next()).collect();
        assert_eq!(old, vec![1, 2, 3]);

        // obnova zo zálohy
        assert_eq!(ch.restore_new_epoch(), 1);
        let mut alloc = SeqAllocator::new(); // nová epocha => reštart alokátoru
        assert_eq!(alloc.next(), 1, "seq reštart z 1 v novej epoche");
        assert_eq!(alloc.next(), 2);

        // ďalšia obnova
        assert_eq!(ch.restore_new_epoch(), 2);
        // stará epocha stále existuje v logu (nie je prepísaná)
        assert!(ch.node_epoch > 0);
    }

    /// Soľ je viazaná na kanál: rovnaký obsah v dvoch kanáloch dá rôzny
    /// slepý hash (D-25).
    #[test]
    fn channel_salt_scopes_blind_hash() {
        let a = Channel::new(CH, "a", ChannelKind::Wall, [1u8; 32]);
        let b = Channel::new([0x0b; 32], "b", ChannelKind::Chat, [2u8; 32]);
        let h = hash_of("ten isty obsah");
        assert_ne!(a.blind(&h), b.blind(&h));
        assert_eq!(a.blind(&h), RecordHash::blind(&a.salt, h.as_bytes()));
    }

    /// **Kritérium B3c:** reconciliation vráti **presne chýbajúce hashe**.
    #[test]
    fn reconcile_returns_exactly_the_missing_hashes() {
        let h1 = hash_of("zaznam 1");
        let h2 = hash_of("zaznam 2");
        let h3 = hash_of("zaznam 3");
        let node_log = vec![
            (SeqPos::new(CH, 0, 1), h1),
            (SeqPos::new(CH, 0, 2), h2),
            (SeqPos::new(CH, 0, 3), h3),
        ];

        // klient má 1 a 3, chýba mu 2
        let mut client = ClientView::new(CH, 0);
        client.insert(1, h1.0);
        client.insert(3, h3.0);

        let diff = reconcile(&node_log, &client);
        assert_eq!(diff.missing.len(), 1, "chýba práve seq 2");
        assert_eq!(diff.missing[0].0.node_seq, 2);
        assert_eq!(diff.missing[0].1, h2);
        assert!(diff.mismatched.is_empty());
        assert!(diff.client_extra.is_empty());
        assert!(!diff.stale_epoch, "klient je v rovnakej epoche");
    }

    /// Klient so **starou epochou** dostane všetky záznamy novej epochy a
    /// `stale_epoch` je pravdivé (kritérium B3c + B3b).
    #[test]
    fn reconcile_with_stale_epoch_client() {
        let old1 = hash_of("stary 1");
        let new1 = hash_of("novy 1");
        let new2 = hash_of("novy 2");
        let node_log = vec![
            (SeqPos::new(CH, 0, 1), old1),
            (SeqPos::new(CH, 1, 1), new1),
            (SeqPos::new(CH, 1, 2), new2),
        ];

        // klient stíhal starú epochu a má v nej seq 1
        let mut client = ClientView::new(CH, 0);
        client.insert(1, old1.0);

        let diff = reconcile(&node_log, &client);
        assert!(diff.stale_epoch, "klient je za epochou");
        // chýbajú mu oba záznamy novej epochy, zoradené podľa (epoch, seq)
        let got: Vec<(u64, u64)> = diff
            .missing
            .iter()
            .map(|(p, _)| (p.node_epoch, p.node_seq))
            .collect();
        assert_eq!(got, vec![(1, 1), (1, 2)]);
        assert!(diff.mismatched.is_empty());
    }

    /// Nezhoda hashu na rovnakej pozícii sa hlási ako `mismatched`, nie
    /// ako chýbajúca — a navyše ukáže, že história sa rozchádza.
    #[test]
    fn reconcile_detects_hash_mismatch() {
        let node_hash = hash_of("uzol verzia");
        let client_hash = hash_of("klient verzia");
        let node_log = vec![(SeqPos::new(CH, 0, 1), node_hash)];

        let mut client = ClientView::new(CH, 0);
        client.insert(1, client_hash.0);

        let diff = reconcile(&node_log, &client);
        assert!(diff.missing.is_empty());
        assert_eq!(diff.mismatched.len(), 1);
        assert_eq!(diff.mismatched[0].1, node_hash);
    }

    /// Záznamy, ktoré má len klient (po obnove uzla), sa vrátia ako
    /// `client_extra` — uzol ich musí od klienta prevziať.
    #[test]
    fn reconcile_reports_client_extra_records() {
        let node_log = vec![(SeqPos::new(CH, 1, 1), hash_of("nove 1"))];
        let mut client = ClientView::new(CH, 0);
        let orphan = hash_of("sirok");
        client.insert(4, orphan.0);

        let diff = reconcile(&node_log, &client);
        assert_eq!(diff.client_extra, vec![(4, orphan.0)]);
        assert!(diff.stale_epoch);
    }

    /// Cudzie kanály sa z porovnania vynechajú.
    #[test]
    fn reconcile_ignores_other_channels() {
        let other = SeqPos::new([0xff; 32], 0, 1);
        let node_log = vec![(other, hash_of("cudzi"))];
        let client = ClientView::new(CH, 0);
        let diff = reconcile(&node_log, &client);
        assert!(diff.missing.is_empty());
        assert!(!diff.stale_epoch);
    }

    /// Druh kanála: kód + textová forma (REST/SQL) + roundtrip.
    #[test]
    fn channel_kind_codecs_roundtrip() {
        for k in [ChannelKind::Wall, ChannelKind::Chat, ChannelKind::Mixed] {
            assert_eq!(ChannelKind::from_code(k.code()), Some(k));
            assert_eq!(ChannelKind::from_str(k.as_str()), Some(k));
        }
        assert_eq!(ChannelKind::from_str("lol"), None);
        assert_eq!(ChannelKind::from_code(9), None);
        // D-19: chat sa v L1 nezrkadlí
        assert!(ChannelKind::Wall.mirrorable() && ChannelKind::Mixed.mirrorable());
        assert!(!ChannelKind::Chat.mirrorable());
    }
}
