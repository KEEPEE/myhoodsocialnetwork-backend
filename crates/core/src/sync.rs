//! Sync: watermark per kanál + idempotentná aplikácia podľa hashu.
//!
//! Sync je **set-reconciliation** (D-24): klient požiada o záznamy kanála
//! od svojho watermarku, uzol pošle range; aplikácia je idempotentná
//! podľa `hash = BLAKE3(raw)` (D-25) — rovnaký záznam sa aplikuje práve
//! raz, poradie správ na drôte nie je sémantika.

use crate::seq::{ChannelId, SeqPos};
use std::collections::HashSet;

/// Watermark: najvyššia aplikovaná pozícia v kanáli.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Watermark {
    pub channel: ChannelId,
    pub node_epoch: u64,
    pub node_seq: u64,
}

impl Watermark {
    /// Začiatok kanála: epocha 0, seq 0 (ešte nič aplikované).
    pub fn new(channel: ChannelId) -> Self {
        Self { channel, node_epoch: 0, node_seq: 0 }
    }

    /// Posun watermarku o pozíciu `pos`. Vráti `true`, ak bola pozícia
    /// novšia (vyššia epocha alebo seq); starú/duplicitnú ponechá na mieste.
    pub fn advance(&mut self, pos: &SeqPos) -> bool {
        if pos.channel != self.channel {
            return false;
        }
        if (pos.node_epoch, pos.node_seq) > (self.node_epoch, self.node_seq) {
            self.node_epoch = pos.node_epoch;
            self.node_seq = pos.node_seq;
            true
        } else {
            false
        }
    }
}

/// Množina už aplikovaných hashov — základ idempotentnej aplikácie (D-25).
#[derive(Debug, Default)]
pub struct SeenSet {
    seen: HashSet<[u8; 32]>,
}

impl SeenSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Aplikuj záznam práve raz: vráti `true` pri prvom videní hashu,
    /// `false` pri duplike (idempotentná aplikácia podľa hashu).
    pub fn apply_once(&mut self, hash: &[u8; 32]) -> bool {
        self.seen.insert(*hash)
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity test 3 (watermark placeholder): rastie len po novších
    /// pozíciách, staré a duplicitné odmietne.
    #[test]
    fn watermark_advances_only_forward() {
        let ch = [4u8; 32];
        let mut wm = Watermark::new(ch);
        assert!(wm.advance(&SeqPos::new(ch, 0, 1)));
        assert!(wm.advance(&SeqPos::new(ch, 0, 5)));
        // staršia / duplicitná pozícia
        assert!(!wm.advance(&SeqPos::new(ch, 0, 3)));
        assert!(!wm.advance(&SeqPos::new(ch, 0, 5)));
        // nová epocha je novšia aj pri seq 0
        assert!(wm.advance(&SeqPos::new(ch, 1, 0)));
        assert_eq!((wm.node_epoch, wm.node_seq), (1, 0));
        // iný kanál watermark neposunie
        assert!(!wm.advance(&SeqPos::new([5u8; 32], 9, 9)));
    }

    /// Idempotentná aplikácia: rovnaký hash prejde práve raz.
    #[test]
    fn seen_set_is_idempotent() {
        let mut seen = SeenSet::new();
        let h = [1u8; 32];
        assert!(seen.apply_once(&h));
        assert!(!seen.apply_once(&h));
        assert!(seen.apply_once(&[2u8; 32]));
        assert_eq!(seen.len(), 2);
    }
}
