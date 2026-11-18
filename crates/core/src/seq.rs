//! Poradie per kanál (rozhodnutie D-25).
//!
//! Poradie NEPRIDELUJE autor ani hodiny — prideľuje ho **domáci uzol** pri
//! prevzatí záznamu, ako trojicu `(channel, node_epoch, node_seq)`:
//! - `channel` — kanál, v ktorom záznam žije (nástienka/chat, D-10),
//! - `node_epoch` — epocha uzla; zdvihne sa pri obnove po výpadku/resete,
//!   aby staré `node_seq` hodnoty nemohli kolidovať,
//! - `node_seq` — prísne rastúce poradie v rámci `(channel, node_epoch)`.
//!
//! CRDT je z MVP von (D-25) — merge dvoch uzlov je set-reconciliation
//! podľa hashov ([`crate::sync`]), poradie je len pohľad domáceho uzla.

/// Identifikátor kanála (32 bajtov, priradí domáci uzol).
pub type ChannelId = [u8; 32];

/// Pozícia v poradí kanála: `(channel, node_epoch, node_seq)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SeqPos {
    pub channel: ChannelId,
    pub node_epoch: u64,
    pub node_seq: u64,
}

impl SeqPos {
    pub fn new(channel: ChannelId, node_epoch: u64, node_seq: u64) -> Self {
        Self { channel, node_epoch, node_seq }
    }

    /// Porovnanie platí len v rámci jedného kanála.
    pub fn same_channel(&self, other: &Self) -> bool {
        self.channel == other.channel
    }

    /// Lexikografické poradie vnútri kanála: najprv `node_epoch`, potom `node_seq`.
    pub fn precedes(&self, other: &Self) -> bool {
        self.same_channel(other)
            && (self.node_epoch, self.node_seq) < (other.node_epoch, other.node_seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_is_epoch_then_seq_within_channel() {
        let ch = [1u8; 32];
        let a = SeqPos::new(ch, 0, 5);
        let b = SeqPos::new(ch, 0, 6);
        let c = SeqPos::new(ch, 1, 0); // nová epocha je až PO všetkých seq
        assert!(a.precedes(&b));
        assert!(b.precedes(&c));
        assert!(!c.precedes(&a));
    }

    #[test]
    fn cross_channel_comparison_is_false() {
        let a = SeqPos::new([1u8; 32], 0, 1);
        let b = SeqPos::new([2u8; 32], 0, 2);
        assert!(!a.precedes(&b));
        assert!(!b.precedes(&a));
    }
}
