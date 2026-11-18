//! MyHoodSocialNetwork — sans-IO jadro (D-02, D-29).
//!
//! Knižnica bez I/O: obálka záznamov, poradie per kanál, identita člena,
//! sync watermark, storage trait a wire framing. Jadro NESMIE závisieť od
//! tokio/axum/rusqlite — tie patria len do `crates/node` (a budúcich
//! implementácií traitov). Cargo features `client` (apka) a `server`
//! (full node) sú voliteľné nadstavby; default je prázdny.
//!
//! Moduly (B1 scaffold — typy a doc-komentáre, implementácia v B2+):
//! - [`record`]   obálka záznamu (D-25, D-30)
//! - [`channel`]  kanály, epochy, alokátor seq a reconciliation (D-25, D-10)
//! - [`seq`]      poradie per kanál (D-25)
//! - [`identity`] account + device keys + atesty (D-26, D-27)
//! - [`sync`]     watermark per kanál, idempotentná aplikácia (D-24)
//! - [`storage`]  storage trait — log + meta KV (D-29)
//! - [`wire`]     framing s verziou v hlavičke, Hello/Reject (D-24)

pub mod channel;
pub mod identity;
pub mod record;
pub mod roles;
pub mod seq;
pub mod storage;
pub mod sync;
pub mod wire;

/// Verzia drôtu (wire) — je v hlavičke každého frame od F0 (D-22, D-24).
pub const PROTO_VERSION: u8 = wire::WIRE_VERSION;
