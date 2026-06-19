//! # cheetah-curve 🐆
//!
//! Pure-Rust implementation of Nockchain's cryptographic primitives:
//!
//! - **`belt`** — the Goldilocks field `p = 2^64 − 2^32 + 1` (Montgomery arithmetic).
//! - **`cheetah`** — the Cheetah elliptic curve over a sextic extension `F6` of the
//!   Goldilocks field (generator `A_GEN`, point add/neg/scalar-mul, 97-byte
//!   big-endian wire encoding, `trunc_g_order` scalar reduction).
//! - **`tip5`** — the Tip5 algebraic hash (`hash_varlen`).
//!
//! Together these define Nockchain's key-prefixed Schnorr signatures, whose
//! verifier is standard nonce-agnostic Schnorr with a Tip5 challenge:
//!
//! ```text
//! R' = s·G − c·P;   accept iff  trunc_g_order(Tip5(R'.x ‖ R'.y ‖ P.x ‖ P.y ‖ m)) == c
//! ```
//!
//! Vendored from nockchain's `nockchain-math` (MIT OR Apache-2.0) with the
//! `nockvm` / `noun-serde` coupling removed — no Nock VM dependency, builds on
//! stable Rust. The one intentional change is [`cheetah::f6_inv`], reimplemented
//! via Fermat's little theorem (`f^(p^6−2)`); a field inverse is unique, so the
//! result is identical, guarded by the `test_f6inv` known-answer test. Byte-exact
//! parity with the on-chain Nockchain verifier and `@nockchain/rose-ts` is
//! enforced by the in-crate known-answer + golden-vector tests.

#[macro_use]
pub mod belt;
pub mod cheetah;
pub mod tip5;

#[cfg(test)]
mod golden;

// Ergonomic re-exports of the most-used items.
pub use crate::belt::{Belt, PRIME};
pub use crate::cheetah::{
    ch_add, ch_neg, ch_scal_big, trunc_g_order, CheetahPoint, F6lt, A_GEN, A_ID, G_ORDER,
};
pub use crate::tip5::hash::hash_varlen;
