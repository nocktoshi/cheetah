//! Byte-exact parity regression against `@nockchain/rose-ts` and nockchain-math.
//!
//! Drives the crate's **public** [`crate::schnorr`] API so that matching the
//! exact `(c, s)` rose-ts produced confirms the published signing/verification
//! surface — not just internal helpers — is byte-identical to rose-ts and the
//! on-chain Nockchain verifier. Covers the deterministic single-signer
//! ([`PrivateKey::sign`]) and the 2-party additive (FROST core) path
//! ([`partial_sign`] / [`aggregate_responses`]).

use crypto_bigint::U256;
use serde_json::Value;

use super::cheetah::{ch_scal_big, A_GEN};
use super::schnorr::{
    aggregate_pubkeys, aggregate_responses, challenge, partial_sign, verify, PrivateKey, PublicKey,
};

const GOLDEN: &str = include_str!("golden-vectors.json");

fn hex_to_bytes(h: &str) -> Vec<u8> {
    (0..h.len() / 2)
        .map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}
/// Golden `c`/`s`/`x_i`/`k_i` are little-endian hex of the scalar value
/// (trailing zero bytes may be trimmed), zero-extended to 32 bytes.
fn u256_le(h: &str) -> U256 {
    let raw = hex_to_bytes(h);
    let mut b = [0u8; 32];
    b[..raw.len()].copy_from_slice(&raw);
    U256::from_le_slice(&b)
}
/// `keyHex` is big-endian; left-pad to 32 bytes.
fn u256_be(h: &str) -> U256 {
    let raw = hex_to_bytes(h);
    let mut b = [0u8; 32];
    b[32 - raw.len()..].copy_from_slice(&raw);
    U256::from_be_slice(&b)
}
fn belts5(v: &Value) -> [u64; 5] {
    let a = v.as_array().unwrap();
    let mut o = [0u64; 5];
    for i in 0..5 {
        o[i] = a[i].as_str().unwrap().parse().unwrap();
    }
    o
}

#[test]
fn golden_deterministic_single_matches_rose_ts() {
    let g: Value = serde_json::from_str(GOLDEN).unwrap();
    let d = &g["deterministic_single"];
    let secret = PrivateKey(u256_be(d["keyHex"].as_str().unwrap()));
    let m = belts5(&d["digestBelts"]);

    let pk = secret.public_key().unwrap();
    let sig = secret.sign(&m).unwrap();

    assert_eq!(
        pk.to_hex().unwrap(),
        d["pubkeyHex"].as_str().unwrap(),
        "pubkey bytes"
    );
    assert_eq!(sig.c, u256_le(d["c"].as_str().unwrap()), "challenge c");
    assert_eq!(sig.s, u256_le(d["s"].as_str().unwrap()), "response s");
    assert!(pk.verify(&sig, &m), "self-verify via public API");
}

#[test]
fn golden_additive_2party_matches_rose_ts() {
    let g: Value = serde_json::from_str(GOLDEN).unwrap();
    let a = &g["additive_2party"];
    let x1 = u256_le(a["x1"].as_str().unwrap());
    let x2 = u256_le(a["x2"].as_str().unwrap());
    let k1 = u256_le(a["k1"].as_str().unwrap());
    let k2 = u256_le(a["k2"].as_str().unwrap());
    let m = belts5(&a["m"]);

    let agg_pk = aggregate_pubkeys(&[
        ch_scal_big(&x1, &A_GEN).unwrap(),
        ch_scal_big(&x2, &A_GEN).unwrap(),
    ])
    .unwrap();
    let agg_r = aggregate_pubkeys(&[
        ch_scal_big(&k1, &A_GEN).unwrap(),
        ch_scal_big(&k2, &A_GEN).unwrap(),
    ])
    .unwrap();

    let (c1, s1) = partial_sign(&x1, &k1, &agg_r, &agg_pk, &m);
    let (c2, s2) = partial_sign(&x2, &k2, &agg_r, &agg_pk, &m);
    let sig = aggregate_responses(c1, &[s1, s2]);

    // Cross-check the challenge against the canonical transcript helper too.
    assert_eq!(c1, c2, "all signers agree on the challenge");
    assert_eq!(
        c1,
        challenge(&agg_r, &agg_pk, &m),
        "challenge over canonical transcript"
    );

    assert_eq!(
        PublicKey(agg_pk).to_hex().unwrap(),
        a["pubkeyHex"].as_str().unwrap(),
        "aggregate pubkey bytes"
    );
    assert_eq!(sig.c, u256_le(a["c"].as_str().unwrap()), "challenge c");
    assert_eq!(sig.s, u256_le(a["s"].as_str().unwrap()), "aggregate s");
    assert!(
        verify(&agg_pk, &sig, &m),
        "threshold signature verifies via public API"
    );
}
