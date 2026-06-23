//! # cheetah-curve 🐆
//!
//! Pure-Rust implementation of Nockchain's cryptographic primitives:
//!
//! - **`belt`** — the Goldilocks field `p = 2^64 − 2^32 + 1` (Montgomery arithmetic).
//! - **`cheetah`** — the Cheetah elliptic curve over a sextic extension `F6` of the
//!   Goldilocks field (generator `A_GEN`, point add/neg/scalar-mul, 97-byte
//!   big-endian wire encoding, `trunc_g_order` scalar reduction).
//! - **`tip5`** — the Tip5 algebraic hash (`hash_varlen`).
//! - **`schnorr`** — the high-level signature API ([`PublicKey`], [`PrivateKey`],
//!   [`Signature`], [`sign`](PrivateKey::sign) / [`verify`], chain-signatures
//!   [`derive_child`], and the additive (FROST-core) threshold helpers).
//! - **`message`** — the signing-payload ⇄ Tip5-digest codecs
//!   ([`message_from_digest`] / [`digest_from_message`]) and domain-separated
//!   Tip5 hashes ([`tip5_to_scalar`] / [`tip5_to_bytes`]).
//!
//! Together these define Nockchain's key-prefixed Schnorr signatures, whose
//! verifier is standard nonce-agnostic Schnorr with a Tip5 challenge:
//!
//! ```text
//! R' = s·G − c·P;   accept iff  R' ≠ O  and  trunc_g_order(Tip5(R'.x ‖ R'.y ‖ P.x ‖ P.y ‖ m)) == c
//! ```
//!
//! Because the verifier is nonce-agnostic, the same `(c, s)` shape covers single
//! signers and threshold/FROST signing, and the pure arithmetic compiles to
//! `wasm32-unknown-unknown` so a NEAR contract can [`verify`] on-chain.
//!
//! The whole signing path is constant time — scalar field
//! ([`crypto_bigint::U256`]), Goldilocks field, Tip5, and curve point
//! add/double/scalar-mul are free of secret-dependent branches — and secret keys
//! are zeroized on drop. See `SECURITY.md` for the audit (NCC Group findings).
//!
//! Vendored from nockchain's `nockchain-math` (MIT OR Apache-2.0) with the
//! `nockvm` / `noun-serde` coupling removed — no Nock VM dependency, builds on
//! stable Rust. The one intentional change is [`cheetah::f6_inv`], reimplemented
//! via Fermat's little theorem (`f^(p^6−2)`); a field inverse is unique, so the
//! result is identical, guarded by the `test_f6inv` known-answer test. Byte-exact
//! parity with the on-chain Nockchain verifier and `@nockchain/rose-ts` is
//! enforced by the in-crate known-answer + golden-vector tests.

#![cfg_attr(not(test), no_std)]
#[macro_use]
extern crate alloc;

#[macro_use]
pub mod belt;
pub mod cheetah;
pub mod message;
pub mod schnorr;
pub mod tip5;

#[cfg(test)]
mod golden;

// Re-export the scalar big-int types so downstream crates can name them without
// depending on `crypto-bigint` directly (and stay on the same version).
pub use crypto_bigint::{NonZero, U256, U512};

// Ergonomic re-exports of the most-used items.
pub use crate::belt::{Belt, PRIME};
pub use crate::cheetah::{
    ch_add, ch_neg, ch_scal_big, trunc_g_order, CheetahError, CheetahPoint, F6lt, A_GEN, A_ID,
    G_ORDER, G_ORDER_NZ,
};
pub use crate::message::{digest_from_message, message_from_digest, tip5_to_bytes, tip5_to_scalar};
pub use crate::schnorr::{
    aggregate_pubkeys, aggregate_responses, challenge, derive_child, partial_sign,
    tweak_from_le_bytes, verify, PrivateKey, PublicKey, Signature,
};
pub use crate::tip5::hash::hash_varlen;
