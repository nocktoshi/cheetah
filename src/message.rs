//! Signing-payload ⇄ Tip5-digest codecs and domain-separated Tip5 hashes.
//!
//! These are the low-level message-encoding primitives shared by the MPC signer,
//! the FROST ciphersuite, and the on-chain verifier.

use alloc::vec::Vec;

use crypto_bigint::U256;

use crate::belt::{Belt, PRIME};
use crate::cheetah::trunc_g_order;
use crate::tip5::hash::hash_varlen;

/// Encode a 5-belt Tip5 digest as the 40-byte little-endian signing payload
pub fn message_from_digest(digest: &[u64; 5]) -> [u8; 40] {
    let mut m = [0u8; 40];
    for (chunk, &belt) in m.chunks_mut(8).zip(digest) {
        chunk.copy_from_slice(&belt.to_le_bytes());
    }
    m
}

/// Decode a signing payload back into 5 Goldilocks belts: each belt is eight
/// little-endian bytes reduced into the field (`% PRIME`).
pub fn digest_from_message(message: &[u8]) -> [u64; 5] {
    let mut d = [0u64; 5];
    for (i, slot) in d.iter_mut().enumerate() {
        let s = i * 8;
        let mut a = [0u8; 8];
        if s + 8 <= message.len() {
            a.copy_from_slice(&message[s..s + 8]);
        }
        *slot = u64::from_le_bytes(a) % PRIME;
    }
    d
}

/// Domain-separated Tip5 hash to a scalar in `[0, G_ORDER)`:
/// `trunc_g_order(Tip5(domain ‖ m))`, with each input byte lifted to a belt.
pub fn tip5_to_scalar(domain: &[u8], m: &[u8]) -> U256 {
    let mut t: Vec<Belt> = Vec::with_capacity(domain.len() + m.len());
    t.extend(domain.iter().map(|&b| Belt(u64::from(b))));
    t.extend(m.iter().map(|&b| Belt(u64::from(b))));
    trunc_g_order(&hash_varlen(&t))
}

/// Domain-separated Tip5 hash to 32 bytes: the first four belts of
/// `Tip5(domain ‖ m)` as little-endian u64s.
pub fn tip5_to_bytes(domain: &[u8], m: &[u8]) -> [u8; 32] {
    let mut t: Vec<Belt> = Vec::with_capacity(domain.len() + m.len());
    t.extend(domain.iter().map(|&b| Belt(u64::from(b))));
    t.extend(m.iter().map(|&b| Belt(u64::from(b))));
    let d = hash_varlen(&t);
    let mut o = [0u8; 32];
    for i in 0..4 {
        o[i * 8..i * 8 + 8].copy_from_slice(&d[i].to_le_bytes());
    }
    o
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn digest_message_roundtrips() {
        let digest = [1u64, 2, 3, 4, 5];
        let msg = message_from_digest(&digest);
        assert_eq!(msg.len(), 40);
        assert_eq!(digest_from_message(&msg), digest);
    }

    #[test]
    fn digest_from_short_message_zero_pads() {
        assert_eq!(digest_from_message(&[]), [0u64; 5]);
        assert_eq!(
            digest_from_message(&[7, 0, 0, 0, 0, 0, 0, 0]),
            [7, 0, 0, 0, 0]
        );
    }

    #[test]
    fn tip5_hashes_are_deterministic_and_domain_separated() {
        assert_eq!(tip5_to_scalar(b"A", b"msg"), tip5_to_scalar(b"A", b"msg"));
        assert_ne!(tip5_to_scalar(b"A", b"msg"), tip5_to_scalar(b"B", b"msg"));
        assert_eq!(tip5_to_bytes(b"A", b"msg"), tip5_to_bytes(b"A", b"msg"));
        assert_ne!(tip5_to_bytes(b"A", b"msg"), tip5_to_bytes(b"B", b"msg"));
    }
}
