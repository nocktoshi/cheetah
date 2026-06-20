//! Key-prefixed Schnorr signatures over the Cheetah curve with a Tip5 challenge.
//!
//! This is Nockchain's signature scheme. The verifier is standard, nonce-agnostic
//! Schnorr:
//!
//! ```text
//! R' = s·G − c·P;   accept iff  R' ≠ O  and  trunc_g_order(Tip5(R'.x ‖ R'.y ‖ P.x ‖ P.y ‖ m)) == c
//! ```
//!
//! Because verification only checks `s·G == R + c·P`, any nonce-generation
//! strategy that yields a valid `(c, s)` verifies — including FROST-style
//! threshold signing.
//!
//! Scalars are 256-bit values modulo [`G_ORDER`], implemented with constant-time
//! [`crypto_bigint::U256`] arithmetic. A signature is two 32-byte little-endian
//! scalars `(c, s)` (64 bytes); a public key is the 97-byte big-endian point
//! encoding (see [`CheetahPoint::to_be_bytes`]). The 5-belt `message` is the
//! signing digest.
//!
//! Security note: the entire signing path is constant time.
//! See `SECURITY.md`.

use crypto_bigint::{MulMod, NonZero, U256};
use subtle::{Choice, ConstantTimeEq, ConstantTimeLess};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::belt::Belt;
use crate::cheetah::{
    ch_add, ch_neg, ch_scal_big, trunc_g_order, CheetahError, CheetahPoint, A_GEN, A_ID, G_ORDER,
};
use crate::tip5::hash::hash_varlen;

const G_ORDER_NZ: NonZero<U256> = NonZero::<U256>::new_unwrap(G_ORDER);

/// Constant-time check that `x ∈ [1, G_ORDER)`
/// - the valid range for a private key, challenge, or response scalar.
fn is_canonical_scalar(x: &U256) -> Choice {
    !x.ct_eq(&U256::ZERO) & x.ct_lt(&G_ORDER)
}

fn reduce(x: &U256) -> U256 {
    x.rem(&G_ORDER_NZ)
}

/// A Cheetah Schnorr signature: challenge `c` and response `s`, both scalars in
/// `[1, G_ORDER)`. The wire form is `c` ‖ `s`, each a 32-byte little-endian
/// scalar (64 bytes total).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub c: U256,
    pub s: U256,
}

impl Signature {
    /// 64-byte wire form: `c` (32 LE bytes) followed by `s` (32 LE bytes).
    pub fn to_le_bytes(&self) -> [u8; 64] {
        let mut o = [0u8; 64];
        o[..32].copy_from_slice(&self.c.to_le_bytes());
        o[32..].copy_from_slice(&self.s.to_le_bytes());
        o
    }

    /// Parse the 64-byte wire form (two 32-byte little-endian scalars). Does not
    /// range-check the scalars; [`verify`] rejects out-of-range values.
    pub fn from_le_bytes(bytes: &[u8; 64]) -> Self {
        Signature {
            c: U256::from_le_slice(&bytes[..32]),
            s: U256::from_le_slice(&bytes[32..]),
        }
    }
}

/// A Cheetah public key (a curve point), carrying Nockchain's 97-byte wire form
/// and hex helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(pub CheetahPoint);

impl PublicKey {
    /// 97-byte big-endian point encoding.
    pub fn to_be_bytes(&self) -> Result<[u8; CheetahPoint::BYTES], CheetahError> {
        self.0.to_be_bytes()
    }

    /// Parse the 97-byte big-endian point encoding (validates on-curve).
    pub fn from_be_bytes(bytes: &[u8]) -> Result<Self, CheetahError> {
        Ok(PublicKey(CheetahPoint::from_be_bytes(bytes)?))
    }

    /// Hex of the 97-byte encoding. **Not constant time** — public keys are
    /// public, so this is acceptable; never feed secret material through it.
    pub fn to_hex(&self) -> Result<String, CheetahError> {
        Ok(self
            .to_be_bytes()?
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect())
    }

    /// Parse a hex-encoded 97-byte public key. **Not constant time** (public data).
    pub fn from_hex(hex: &str) -> Result<Self, CheetahError> {
        Self::from_be_bytes(&hex_to_bytes(hex)?)
    }

    /// Nockchain base58 address form.
    pub fn to_base58(&self) -> Result<String, CheetahError> {
        self.0.into_base58()
    }

    /// Verify `sig` over the 5-belt `message` digest against this key.
    pub fn verify(&self, sig: &Signature, message: &[u64; 5]) -> bool {
        verify(&self.0, sig, message)
    }

    /// Chain-signatures child derivation: `child = self + tweak·G`.
    pub fn derive_child(&self, tweak: &U256) -> Result<Self, CheetahError> {
        Ok(PublicKey(derive_child(&self.0, tweak)?))
    }
}

/// A Cheetah private key (a scalar in `[1, G_ORDER)`).
///
/// The scalar is zeroized on drop. `Debug` is redacted so the secret never lands
/// in logs, and equality is constant time.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey(pub U256);

impl core::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PrivateKey(<redacted>)")
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}
impl Eq for PrivateKey {}

impl PrivateKey {
    /// Parse a canonical 32-byte big-endian scalar. Returns `None` unless the
    /// value is in `[1, G_ORDER)`. The fixed length is enforced by the type and
    /// there is no silent reduction — out-of-range or zero input is rejected
    /// rather than wrapped (cf. NCC finding FQT, "inexact secret-key
    /// deserialization").
    pub fn from_be_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let x = U256::from_be_slice(bytes);
        bool::from(is_canonical_scalar(&x)).then_some(PrivateKey(x))
    }

    /// Parse a canonical 32-byte little-endian scalar (see [`Self::from_be_bytes`]).
    pub fn from_le_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let x = U256::from_le_slice(bytes);
        bool::from(is_canonical_scalar(&x)).then_some(PrivateKey(x))
    }

    /// 32-byte little-endian scalar encoding.
    pub fn to_le_bytes(&self) -> [u8; 32] {
        self.0.to_le_bytes()
    }

    /// `P = x·G`.
    pub fn public_key(&self) -> Result<PublicKey, CheetahError> {
        Ok(PublicKey(ch_scal_big(&self.0, &A_GEN)?))
    }

    /// deterministic nonce:
    /// `trunc_g_order(Tip5(P.x ‖ P.y ‖ m ‖ limbs(secret_le32)))`, where the
    /// secret's 32 little-endian bytes are split into eight little-endian 32-bit
    /// limbs. `pubkey` is `P = x·G`.
    pub fn nonce_for(&self, pubkey: &CheetahPoint, message: &[u64; 5]) -> U256 {
        let le = self.0.to_le_bytes();
        let mut limbs = [0u64; 8];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let mut v = 0u64;
            for j in 0..4 {
                v |= (le[i * 4 + j] as u64) << (j * 8);
            }
            *limb = v;
        }
        let mut t: Vec<Belt> = Vec::with_capacity(25);
        t.extend_from_slice(&pubkey.x.0);
        t.extend_from_slice(&pubkey.y.0);
        t.extend(message.iter().map(|&u| Belt(u)));
        t.extend(limbs.iter().map(|&u| Belt(u)));
        trunc_g_order(&hash_varlen(&t))
    }

    /// Single-signer sign with the deterministic nonce. Byte-identical to
    /// `@nockchain/rose-ts`'s `signDigest`.
    pub fn sign(&self, message: &[u64; 5]) -> Result<Signature, CheetahError> {
        let pubkey = ch_scal_big(&self.0, &A_GEN)?;
        let nonce = self.nonce_for(&pubkey, message);
        let r = ch_scal_big(&nonce, &A_GEN)?;
        let c = challenge(&r, &pubkey, message);
        let cs = MulMod::mul_mod(&c, &self.0, &G_ORDER);
        let s = nonce.add_mod(&cs, &G_ORDER);
        Ok(Signature { c, s })
    }

    /// Chain-signatures child secret: `x + tweak (mod G_ORDER)`. The matching
    /// child public key is [`PublicKey::derive_child`] with the same `tweak`, so
    /// `self.derive_child(t).public_key() == self.public_key().derive_child(t)`.
    pub fn derive_child(&self, tweak: &U256) -> Self {
        PrivateKey(self.0.add_mod(&reduce(tweak), &G_ORDER))
    }
}

/// `c = trunc_g_order(Tip5(R.x ‖ R.y ‖ P.x ‖ P.y ‖ m))` — the Fiat–Shamir
/// challenge over the canonical 29-belt transcript (`R`, then the public key
/// `P`, then the 5-belt message).
pub fn challenge(r: &CheetahPoint, pubkey: &CheetahPoint, message: &[u64; 5]) -> U256 {
    let mut t: Vec<Belt> = Vec::with_capacity(29);
    t.extend_from_slice(&r.x.0);
    t.extend_from_slice(&r.y.0);
    t.extend_from_slice(&pubkey.x.0);
    t.extend_from_slice(&pubkey.y.0);
    t.extend(message.iter().map(|&u| Belt(u)));
    trunc_g_order(&hash_varlen(&t))
}

/// Verify a Cheetah Schnorr signature against `pubkey` and the 5-belt `message`
/// digest. Mirrors the on-chain Nockchain verifier and `@nockchain/rose-ts`'s
/// `verifySignature`, with the additional non-malleability check below.
///
/// Rejects:
/// - out-of-range scalars (`c` or `s` not in `[1, G_ORDER)`),
/// - the point at infinity as a public key,
/// - **`R' = s·G − c·P` equal to the identity** — without this an attacker who
///   knows the secret key can mint a second valid `(c, s)` for the same message
///   (set `R' = O`, `c = Tip5(O ‖ P ‖ m)`, `s = c·x`), the Cheetah analogue of
///   NCC finding CRR / BIP-340 verification step 7. Honest signatures never
///   produce `R' = O`,
/// - any curve-arithmetic failure.
pub fn verify(pubkey: &CheetahPoint, sig: &Signature, message: &[u64; 5]) -> bool {
    if !bool::from(is_canonical_scalar(&sig.c) & is_canonical_scalar(&sig.s)) {
        return false;
    }
    if pubkey.inf {
        return false;
    }
    // R' = s·G − c·P
    let sg = match ch_scal_big(&sig.s, &A_GEN) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let cp = match ch_scal_big(&sig.c, pubkey) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let rprime = match ch_add(&sg, &ch_neg(&cp)) {
        Ok(p) => p,
        Err(_) => return false,
    };
    if rprime.inf {
        return false;
    }
    challenge(&rprime, pubkey, message).ct_eq(&sig.c).into()
}

/// Interpret `bytes` as a little-endian integer reduced mod `G_ORDER`.
///
/// This is the chain-signatures epsilon/tweak convention: the 32-byte SHA3-256
/// derivation output (`SHA3-256("near-mpc-recovery v0.1.0 epsilon derivation:" +
/// predecessor + "," + path)`) is read little-endian and reduced into the
/// scalar field, matching the MPC signer's `tweak_scalar`. Inputs shorter than
/// 32 bytes are zero-extended; longer inputs use the low 32 bytes.
pub fn tweak_from_le_bytes(bytes: &[u8]) -> U256 {
    let mut buf = [0u8; 32];
    let n = bytes.len().min(32);
    buf[..n].copy_from_slice(&bytes[..n]);
    reduce(&U256::from_le_slice(&buf))
}

/// Derive a child public key from a root: `child = root + tweak·G`.
///
/// Matches `deriveChild` in `@nockchain/rose-ts` and the MPC signer's tweak
/// application, so the key the contract derives equals the key the signer
/// produces signatures for.
pub fn derive_child(root: &CheetahPoint, tweak: &U256) -> Result<CheetahPoint, CheetahError> {
    let tg = ch_scal_big(&reduce(tweak), &A_GEN)?;
    ch_add(root, &tg)
}

/// Sum a set of public-key shares into the aggregate group key `P = Σ Pᵢ`.
pub fn aggregate_pubkeys(shares: &[CheetahPoint]) -> Result<CheetahPoint, CheetahError> {
    let mut acc = A_ID;
    for p in shares {
        acc = ch_add(&acc, p)?;
    }
    Ok(acc)
}

/// One signer's contribution in additive (FROST-core) threshold signing. Given
/// this signer's secret share `xᵢ` and nonce share `kᵢ` (both in `[0, G_ORDER)`),
/// the aggregate nonce point `R = Σ Rⱼ`, and the aggregate public key
/// `P = Σ Pⱼ`, returns the shared challenge `c` and this signer's partial
/// response `sᵢ = kᵢ + c·xᵢ`.
pub fn partial_sign(
    secret_share: &U256,
    nonce_share: &U256,
    aggregate_r: &CheetahPoint,
    aggregate_pubkey: &CheetahPoint,
    message: &[u64; 5],
) -> (U256, U256) {
    let c = challenge(aggregate_r, aggregate_pubkey, message);
    let cs = MulMod::mul_mod(&c, secret_share, &G_ORDER);
    let s_i = nonce_share.add_mod(&cs, &G_ORDER);
    (c, s_i)
}

/// Aggregate partial responses into the final signature `s = Σ sᵢ mod G_ORDER`.
pub fn aggregate_responses(c: U256, partials: &[U256]) -> Signature {
    let mut s = U256::ZERO;
    for p in partials {
        s = s.add_mod(p, &G_ORDER);
    }
    Signature { c, s }
}

/// Decode a hex string into bytes. **Not constant time** — used only for public
/// (non-secret) values such as public keys.
fn hex_to_bytes(h: &str) -> Result<Vec<u8>, CheetahError> {
    if h.len() % 2 != 0 {
        return Err(CheetahError::InvalidLength(h.len()));
    }
    (0..h.len() / 2)
        .map(|i| {
            u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).map_err(|_| CheetahError::ArrayConversion)
        })
        .collect()
}

#[cfg(test)]
mod test {
    use super::*;

    // A small, fixed secret for round-trip tests (0x42..42 < G_ORDER, non-zero).
    fn sk() -> PrivateKey {
        PrivateKey::from_be_bytes(&[0x42; 32]).expect("0x42..42 is a canonical scalar")
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let sk = sk();
        let pk = sk.public_key().unwrap();
        let m = [1u64, 2, 3, 4, 5];
        let sig = sk.sign(&m).unwrap();
        assert!(pk.verify(&sig, &m), "fresh signature verifies");
    }

    #[test]
    fn verify_rejects_tampering() {
        let sk = sk();
        let pk = sk.public_key().unwrap();
        let m = [1u64, 2, 3, 4, 5];
        let sig = sk.sign(&m).unwrap();

        // Wrong message.
        assert!(!pk.verify(&sig, &[9, 9, 9, 9, 9]));

        // Tampered response.
        let bad = Signature {
            c: sig.c,
            s: sig.s.add_mod(&U256::ONE, &G_ORDER),
        };
        assert!(!pk.verify(&bad, &m));

        // Out-of-range scalar (zero) is rejected.
        let zero_c = Signature {
            c: U256::ZERO,
            s: sig.s,
        };
        assert!(!pk.verify(&zero_c, &m));
    }

    #[test]
    fn verify_rejects_identity_rprime() {
        // NCC finding CRR: an attacker knowing the secret key can forge a second
        // valid (c, s) by forcing R' = O. With c = Tip5(O ‖ P ‖ m) and s = c·x,
        // we get s·G − c·P = O, so without the identity check verify would accept.
        let sk = sk();
        let pk = sk.public_key().unwrap();
        let m = [3u64, 1, 4, 1, 5];
        let c = challenge(&A_ID, &pk.0, &m);
        let s = MulMod::mul_mod(&c, &sk.0, &G_ORDER);
        let forged = Signature { c, s };
        assert!(
            !pk.verify(&forged, &m),
            "identity R' signature must be rejected"
        );
    }

    #[test]
    fn signature_wire_form_roundtrips() {
        let sk = sk();
        let m = [10u64, 20, 30, 40, 50];
        let sig = sk.sign(&m).unwrap();
        let bytes = sig.to_le_bytes();
        let parsed = Signature::from_le_bytes(&bytes);
        assert_eq!(sig, parsed);
    }

    #[test]
    fn pubkey_be_bytes_and_hex_roundtrip() {
        let pk = sk().public_key().unwrap();
        let bytes = pk.to_be_bytes().unwrap();
        assert_eq!(PublicKey::from_be_bytes(&bytes).unwrap(), pk);
        let hex = pk.to_hex().unwrap();
        assert_eq!(PublicKey::from_hex(&hex).unwrap(), pk);
    }

    #[test]
    fn private_key_bytes_roundtrip() {
        let sk = sk();
        let le = sk.to_le_bytes();
        assert_eq!(PrivateKey::from_le_bytes(&le).unwrap(), sk);
        // Big-endian is the little-endian bytes reversed.
        let mut be = le;
        be.reverse();
        assert_eq!(PrivateKey::from_be_bytes(&be).unwrap(), sk);
    }

    #[test]
    fn private_key_rejects_out_of_range() {
        // All-0xFF is ≥ G_ORDER, and all-zero is not a valid key.
        assert!(PrivateKey::from_be_bytes(&[0xff; 32]).is_none());
        assert!(PrivateKey::from_be_bytes(&[0x00; 32]).is_none());
    }

    #[test]
    fn derive_child_signature_verifies_under_child_key() {
        // The MPC signer applies the tweak to its share so the aggregate signs
        // for child = root + tweak·G. Secret-side derive (x + tweak) and
        // public-side derive (P + tweak·G) must agree, and a signature from the
        // child secret must verify under the publicly-derived child key.
        let root_sk = sk();
        let root_pk = root_sk.public_key().unwrap();
        let tweak = tweak_from_le_bytes(&[0xab; 32]);

        let child_sk = root_sk.derive_child(&tweak);
        let child_pk_from_sk = child_sk.public_key().unwrap();
        let child_pk_derived = root_pk.derive_child(&tweak).unwrap();
        assert_eq!(
            child_pk_from_sk, child_pk_derived,
            "secret- and public-side derivation agree"
        );

        let m = [7u64, 7, 7, 7, 7];
        let sig = child_sk.sign(&m).unwrap();
        assert!(
            child_pk_derived.verify(&sig, &m),
            "child signature verifies under derived key"
        );
    }

    #[test]
    fn additive_threshold_two_party_verifies() {
        let x1 = U256::from_u64(111);
        let x2 = U256::from_u64(222);
        let k1 = U256::from_u64(333);
        let k2 = U256::from_u64(444);
        let m = [2u64, 4, 6, 8, 10];

        let p1 = ch_scal_big(&x1, &A_GEN).unwrap();
        let p2 = ch_scal_big(&x2, &A_GEN).unwrap();
        let r1 = ch_scal_big(&k1, &A_GEN).unwrap();
        let r2 = ch_scal_big(&k2, &A_GEN).unwrap();

        let agg_pk = aggregate_pubkeys(&[p1, p2]).unwrap();
        let agg_r = aggregate_pubkeys(&[r1, r2]).unwrap();

        let (c1, s1) = partial_sign(&x1, &k1, &agg_r, &agg_pk, &m);
        let (c2, s2) = partial_sign(&x2, &k2, &agg_r, &agg_pk, &m);
        assert_eq!(c1, c2, "all signers compute the same challenge");

        let sig = aggregate_responses(c1, &[s1, s2]);
        assert!(
            verify(&agg_pk, &sig, &m),
            "aggregate threshold signature verifies"
        );
    }
}
