//! Storage trait (rozhodnutie D-29).
//!
//! Core definuje len **log/KV rozhranie s rozsahovými dotazmi** — žiadne
//! SQL mimo core. SQLite je kandidát implementácie všade (rusqlite s
//! feature `bundled` žije v `crates/node`; v apke FFI/WASM verzie).
//! Indexy sú v core, nie v databáze (D-29).
//!
//! Poznámka pre B2: pridáme `trait-variant` (D-24 — futures vo WASM nie
//! sú `Send`), tu držíme synchronné trait signature pre sans-IO jadro.

use crate::record::RecordHash;
use crate::seq::{ChannelId, SeqPos};

/// Rozsahový dotaz na log kanála: od `(from_epoch, from_seq)` nahor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RangeQuery {
    pub channel: ChannelId,
    pub from_epoch: u64,
    pub from_seq: u64,
    /// Horná medza počtu záznamov (chráni pred veľkým result-setom).
    pub limit: u32,
}

/// Append-only log záznamov + prístup podľa hashu (D-29).
pub trait RecordStore {
    type Error: std::fmt::Debug;

    /// Pridaj záznam na pozíciu `pos` s hashom `hash` a raw bajtami.
    /// Implementácia MUSÍ byť idempotentná podľa hashu (D-25).
    fn append(&mut self, pos: &SeqPos, hash: &RecordHash, raw: &[u8]) -> Result<(), Self::Error>;

    /// Najdi záznam podľa hashu (kanonický identifikátor, D-25).
    fn get(&self, hash: &RecordHash) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Rozsahový dotaz: pozície + raw bajty od watermarku nahor.
    fn range(&self, q: &RangeQuery) -> Result<Vec<(SeqPos, Vec<u8>)>, Self::Error>;
}

/// Meta KV: watermarky, soľ slepých hashov, manifest, konfigurácia uzla.
pub trait MetaStore {
    type Error: std::fmt::Debug;

    fn meta_get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;

    fn meta_set(&mut self, key: &[u8], value: &[u8]) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory implementácia — dokazuje, že trait je použiteľný
    /// bez akejkoľvek databázy (sans-IO test).
    struct MemStore {
        log: Vec<(SeqPos, RecordHash, Vec<u8>)>,
        meta: std::collections::BTreeMap<Vec<u8>, Vec<u8>>,
    }

    impl RecordStore for MemStore {
        type Error = std::convert::Infallible;

        fn append(&mut self, pos: &SeqPos, hash: &RecordHash, raw: &[u8]) -> Result<(), Self::Error> {
            if !self.log.iter().any(|(_, h, _)| h == hash) {
                self.log.push((*pos, *hash, raw.to_vec()));
            }
            Ok(())
        }

        fn get(&self, hash: &RecordHash) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.log.iter().find(|(_, h, _)| h == hash).map(|(_, _, r)| r.clone()))
        }

        fn range(&self, q: &RangeQuery) -> Result<Vec<(SeqPos, Vec<u8>)>, Self::Error> {
            let mut out: Vec<(SeqPos, Vec<u8>)> = self
                .log
                .iter()
                .filter(|(p, _, _)| {
                    p.channel == q.channel
                        && (p.node_epoch, p.node_seq) >= (q.from_epoch, q.from_seq)
                })
                .map(|(p, _, r)| (*p, r.clone()))
                .collect();
            out.sort_by_key(|p| (p.0.node_epoch, p.0.node_seq));
            out.truncate(q.limit as usize);
            Ok(out)
        }
    }

    impl MetaStore for MemStore {
        type Error = std::convert::Infallible;

        fn meta_get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.meta.get(key).cloned())
        }

        fn meta_set(&mut self, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
            self.meta.insert(key.to_vec(), value.to_vec());
            Ok(())
        }
    }

    #[test]
    fn store_trait_works_in_memory() {
        let ch = [8u8; 32];
        let mut s = MemStore { log: Vec::new(), meta: Default::default() };

        let raw1 = b"prvy";
        let raw2 = b"druhy";
        let h1 = RecordHash::from_raw(raw1);
        let h2 = RecordHash::from_raw(raw2);

        s.append(&SeqPos::new(ch, 0, 1), &h1, raw1).unwrap();
        s.append(&SeqPos::new(ch, 0, 1), &h1, raw1).unwrap(); // duplicita podľa hashu
        s.append(&SeqPos::new(ch, 0, 2), &h2, raw2).unwrap();
        assert_eq!(s.log.len(), 2, "idempotentita podla hashu");

        assert_eq!(s.get(&h1).unwrap().as_deref(), Some(&raw1[..]));
        let q = RangeQuery { channel: ch, from_epoch: 0, from_seq: 2, limit: 10 };
        let got = s.range(&q).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1, raw2);

        s.meta_set(b"watermark", b"0:5").unwrap();
        assert_eq!(s.meta_get(b"watermark").unwrap().as_deref(), Some(&b"0:5"[..]));
    }
}
