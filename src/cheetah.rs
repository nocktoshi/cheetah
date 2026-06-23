use alloc::string::String;
use alloc::vec::Vec;

use bs58;
use crypto_bigint::{NonZero, U256, U384};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use crate::belt::Belt;

/// Order of the Cheetah prime-order subgroup (255-bit). All scalar-field
/// arithmetic is performed modulo this value using constant-time `crypto-bigint`
/// operations (`add_mod` / `sub_mod` / `mul_mod`).
pub const G_ORDER: U256 =
    U256::from_be_hex("7af2599b3b3f22d0563fbf0f990a37b5327aa72330157722d443623eaed4accf");

/// `G_ORDER` as a non-zero modulus
/// (`add_mod` / `sub_mod` / `mul_mod` / `rem`) take `&NonZero`.
pub const G_ORDER_NZ: NonZero<U256> = NonZero::<U256>::new_unwrap(G_ORDER);

// Powers of the Goldilocks prime P = 2^64 − 2^32 + 1, used by `trunc_g_order` to
// fold a Tip5 hash output (base-P limbs) into the scalar field. Each is already
// reduced (< G_ORDER), so they are valid operands to `mul_mod`.
const P_BIG: U256 =
    U256::from_be_hex("000000000000000000000000000000000000000000000000ffffffff00000001");
const P_BIG_2: U256 =
    U256::from_be_hex("00000000000000000000000000000000fffffffe00000002fffffffe00000001");
const P_BIG_3: U256 =
    U256::from_be_hex("0000000000000000fffffffd00000005fffffff900000005fffffffd00000001");

pub const A_GEN: CheetahPoint = CheetahPoint {
    x: F6lt([
        Belt(2754611494552410273),
        Belt(8599518745794843693),
        Belt(10526511002404673680),
        Belt(4830863958577994148),
        Belt(375185138577093320),
        Belt(12938930721685970739),
    ]),
    y: F6lt([
        Belt(15384029202802550068),
        Belt(2774812795997841935),
        Belt(14375303400746062753),
        Belt(10708493419890101954),
        Belt(13187678623570541764),
        Belt(9990732138772505951),
    ]),
    inf: false,
};

#[derive(Debug, thiserror::Error)]
pub enum CheetahError {
    #[error("base58 decode error: {0}")]
    Base58(bs58::decode::Error),

    #[error("used zpub import key instead of address")]
    ZPubUsed,

    #[error("invalid base58 string length, got {0}")]
    InvalidLength(usize),

    #[error("invalid base58 format prefix byte, got {0:#x}")]
    BadPrefix(u8),

    #[error("array conversion failed")]
    ArrayConversion,

    #[error("point is not on the curve")]
    NotOnCurve,

    #[error("field element is not invertible")]
    NotInvertible,

    #[error("message limb is not a canonical field element (>= PRIME)")]
    NonCanonicalMessage,
}

impl From<bs58::decode::Error> for CheetahError {
    fn from(e: bs58::decode::Error) -> Self {
        CheetahError::Base58(e)
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct CheetahPoint {
    pub x: F6lt,
    pub y: F6lt,
    pub inf: bool,
}

impl CheetahPoint {
    ///  A pubkey consists of a leading 1 byte and 12 base field elements that are 8 bytes each. (12*8) + 1 = 97.
    pub const BYTES: usize = 97;
    ///  The documented format/version prefix byte written by `into_base58`.
    const FORMAT_PREFIX: u8 = 0x1;

    /// Nockchain's 97-byte big-endian wire form:
    /// `0x01 ‖ y-limbs(reversed, big-endian) ‖ x-limbs(reversed, big-endian)`.
    ///
    /// This is the raw byte encoding that `into_base58` base58-encodes and that
    /// the NEAR MPC contract carries as an opaque public-key blob.
    pub fn to_be_bytes(&self) -> Result<[u8; Self::BYTES], CheetahError> {
        if self.inf {
            return Err(CheetahError::NotOnCurve);
        }
        let mut o = [0u8; Self::BYTES];
        o[0] = Self::FORMAT_PREFIX;
        let mut i = 1;
        for belt in self.y.0.iter().rev().chain(self.x.0.iter().rev()) {
            o[i..i + 8].copy_from_slice(&belt.0.to_be_bytes());
            i += 8;
        }
        Ok(o)
    }

    /// Parse the 97-byte big-endian wire form produced by [`Self::to_be_bytes`].
    /// Validates the format prefix and that the decoded point lies on the curve.
    pub fn from_be_bytes(v: &[u8]) -> Result<Self, CheetahError> {
        if v.len() != Self::BYTES {
            return Err(CheetahError::InvalidLength(v.len()));
        }
        //  The first byte is the format/version prefix (always 0x01). Require it
        //  so the encoding of a point is unique.
        if v[0] != Self::FORMAT_PREFIX {
            return Err(CheetahError::BadPrefix(v[0]));
        }

        let mut v64 = v[1..]
            .chunks_exact(8)
            .map(|a| {
                let arr = <[u8; 8]>::try_from(a).map_err(|_| CheetahError::ArrayConversion)?;
                Ok(Belt(u64::from_be_bytes(arr)))
            })
            .collect::<Result<Vec<Belt>, CheetahError>>()?;

        v64.reverse();

        let c_pt = CheetahPoint {
            x: F6lt(<[Belt; 6]>::try_from(&v64[..6]).map_err(|_| CheetahError::ArrayConversion)?),
            y: F6lt(<[Belt; 6]>::try_from(&v64[6..]).map_err(|_| CheetahError::ArrayConversion)?),
            inf: false,
        };

        if c_pt.in_curve() {
            Ok(c_pt)
        } else {
            Err(CheetahError::NotOnCurve)
        }
    }

    pub fn into_base58(&self) -> Result<String, CheetahError> {
        Ok(bs58::encode(self.to_be_bytes()?).into_string())
    }
    pub fn from_base58(b58: &str) -> Result<Self, CheetahError> {
        let v = bs58::decode(b58).into_vec()?;
        if v.len() != Self::BYTES && b58.starts_with("zpub") {
            return Err(CheetahError::ZPubUsed);
        }
        Self::from_be_bytes(&v)
    }

    /// Whether `(x, y)` satisfies the curve equation `y² = x³ + x + b`
    /// (`a = 1`, `b = u + 395`). Cheap (no scalar multiplication) and branch-free.
    /// This is the *definitive* on-curve test; [`Self::in_curve`]
    fn satisfies_curve_eq(&self) -> Choice {
        let lhs = f6_square(&self.y);
        let x2 = f6_square(&self.x);
        let x3 = f6_mul(&x2, &self.x);
        let rhs = f6_add(&f6_add(&x3, &self.x), &B);
        f6_ct_eq(&lhs, &rhs)
    }

    /// Full point validation: the point is the identity, or it lies on the curve
    /// **and** generates the prime-order subgroup `G`.
    pub fn in_curve(&self) -> bool {
        if self.inf {
            return true;
        }
        if !bool::from(self.satisfies_curve_eq()) {
            return false;
        }
        // Subgroup membership: [n]P == O, computed with the *affine* group law.
        //
        // The fast RCB ladder (`ch_scal_big`) must NOT be used here. RCB
        // Algorithm 1 is complete only on the prime-order subgroup;
        affine_scal_order(self) == A_ID
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct F6lt(pub [Belt; 6]);

#[inline(always)]
pub fn f6_div(f1: &F6lt, f2: &F6lt) -> Result<F6lt, CheetahError> {
    let f2_inv = f6_inv(f2)?;
    Ok(f6_mul(f1, &f2_inv))
}

#[inline(always)]
fn karat3(a: &[Belt; 3], b: &[Belt; 3]) -> [Belt; 5] {
    let m = [a[0] * b[0], a[1] * b[1], a[2] * b[2]];
    [
        m[0],
        (a[0] + a[1]) * (b[0] + b[1]) - (m[0] + m[1]),
        (a[0] + a[2]) * (b[0] + b[2]) - (m[0] + m[2]) + m[1],
        (a[1] + a[2]) * (b[1] + b[2]) - (m[1] + m[2]),
        m[2],
    ]
}

#[inline(always)]
pub fn f6_mul(f: &F6lt, g: &F6lt) -> F6lt {
    let f0g0 = karat3(&[f.0[0], f.0[1], f.0[2]], &[g.0[0], g.0[1], g.0[2]]);
    let f1g1 = karat3(&[f.0[3], f.0[4], f.0[5]], &[g.0[3], g.0[4], g.0[5]]);

    let foil = karat3(
        &[f.0[0] + f.0[3], f.0[1] + f.0[4], f.0[2] + f.0[5]],
        &[g.0[0] + g.0[3], g.0[1] + g.0[4], g.0[2] + g.0[5]],
    );

    let cross = [
        foil[0] - (f0g0[0] + f1g1[0]),
        foil[1] - (f0g0[1] + f1g1[1]),
        foil[2] - (f0g0[2] + f1g1[2]),
        foil[3] - (f0g0[3] + f1g1[3]),
        foil[4] - (f0g0[4] + f1g1[4]),
    ];
    F6lt([
        f0g0[0] + Belt(7) * (cross[3] + f1g1[0]),
        f0g0[1] + Belt(7) * (cross[4] + f1g1[1]),
        f0g0[2] + Belt(7) * f1g1[2],
        f0g0[3] + cross[0] + Belt(7) * f1g1[3],
        f0g0[4] + cross[1] + Belt(7) * f1g1[4],
        cross[2],
    ])
}

/// Exponent `p^6 - 2` for Fermat inversion in F_{p^6} (the multiplicative group
/// order is `p^6 - 1`). A fixed 384-bit public constant.
const FERMAT_EXP: U384 =
    U384::from_be_hex("fffffffa00000014ffffffce00000059ffffff820000008cffffff8200000059ffffffce00000014fffffff9ffffffff");

/// `base^exp` in F_{p^6} by square-and-multiply (LSB-first, fixed 384 iterations).
///
/// `exp` is the fixed public Fermat exponent, so the operation sequence is
/// data-independent — the only secret is `base`, and `f6_mul`/`f6_square` run on
/// it identically every call regardless of its value.
fn f6_pow(base: &F6lt, exp: &U384) -> F6lt {
    let mut b = *base;
    let mut acc = F6_ONE;
    let le_bytes: [u8; 48] = exp.to_le_bytes().into();
    for byte in le_bytes {
        for bit in 0..8 {
            if (byte >> bit) & 1 == 1 {
                acc = f6_mul(&acc, &b);
            }
            b = f6_square(&b);
        }
    }
    acc
}

/// Multiplicative inverse in F_{p^6} via Fermat's little theorem: `f^(p^6 - 2)`.
///
/// Replaces nockchain-math's polynomial extended-GCD (which would pull in the
/// `bpoly`/`poly`/`felt` modules). The field inverse is unique, so the result is
/// byte-identical — guarded by the `test_f6inv` known-answer test below.
#[inline(always)]
pub fn f6_inv(f: &F6lt) -> Result<F6lt, CheetahError> {
    if f == &F6_ZERO {
        return Err(CheetahError::NotInvertible);
    }
    Ok(f6_pow(f, &FERMAT_EXP))
}

#[inline(always)]
fn f6_add(f1: &F6lt, f2: &F6lt) -> F6lt {
    F6lt([
        f1.0[0] + f2.0[0],
        f1.0[1] + f2.0[1],
        f1.0[2] + f2.0[2],
        f1.0[3] + f2.0[3],
        f1.0[4] + f2.0[4],
        f1.0[5] + f2.0[5],
    ])
}

fn f6_scal(s: Belt, f: &F6lt) -> F6lt {
    F6lt([
        f.0[0] * s,
        f.0[1] * s,
        f.0[2] * s,
        f.0[3] * s,
        f.0[4] * s,
        f.0[5] * s,
    ])
}

// TODO: Try karat3-square if performance is an issue
#[inline(always)]
fn f6_square(f: &F6lt) -> F6lt {
    f6_mul(f, f)
}

#[inline(always)]
fn f6_neg(f: &F6lt) -> F6lt {
    F6lt([-f.0[0], -f.0[1], -f.0[2], -f.0[3], -f.0[4], -f.0[5]])
}

#[inline(always)]
fn f6_sub(f1: &F6lt, f2: &F6lt) -> F6lt {
    f6_add(f1, &f6_neg(f2))
}

pub const A_ID: CheetahPoint = CheetahPoint {
    x: F6_ZERO,
    y: F6_ONE,
    inf: true,
};
pub const F6_ZERO: F6lt = F6lt([Belt(0); 6]);
pub const F6_ONE: F6lt = F6lt([Belt(1), Belt(0), Belt(0), Belt(0), Belt(0), Belt(0)]);

// ---- constant-time helpers --------------------------------------------------
//
// `Belt` is a canonical field element (`#[derive(PartialEq)]` over its `u64`),
// so constant-time equality and selection on the raw `u64` are sound — they are
// the timing-invariant equivalents of the `==` the curve code used previously.

/// Constant-time equality of two `F6` elements.
fn f6_ct_eq(a: &F6lt, b: &F6lt) -> Choice {
    a.0.iter()
        .zip(b.0.iter())
        .fold(Choice::from(1u8), |eq, (x, y)| eq & x.0.ct_eq(&y.0))
}

// Constant-time selection via `subtle::ConditionallySelectable`:
// `T::conditional_select(a, b, choice)` returns `choice ? b : a` with no branch
impl ConditionallySelectable for F6lt {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut o = [Belt(0); 6];
        for (oi, (ai, bi)) in o.iter_mut().zip(a.0.iter().zip(b.0.iter())) {
            *oi = Belt(u64::conditional_select(&ai.0, &bi.0, choice));
        }
        F6lt(o)
    }
}

impl ConditionallySelectable for CheetahPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        CheetahPoint {
            x: F6lt::conditional_select(&a.x, &b.x, choice),
            y: F6lt::conditional_select(&a.y, &b.y, choice),
            // `bool` isn't `ConditionallySelectable`; round-trip through `u8`.
            inf: u8::conditional_select(&(a.inf as u8), &(b.inf as u8), choice) != 0,
        }
    }
}

/// Point doubling `2P`, constant time. The identity and 2-torsion points
/// (`y = 0`) map to the identity; all timing is independent of `P`.
#[inline(always)]
pub fn ch_double(p: CheetahPoint) -> Result<CheetahPoint, CheetahError> {
    // λ = (3x² + a) / 2y, with a = 1. `f6_pow(·, p^6−2)` is the field inverse and
    // returns 0 for a 0 input (no error), so the degenerate cases below are safe.
    let num = f6_add(&f6_scal(Belt(3), &f6_square(&p.x)), &F6_ONE);
    let den = f6_scal(Belt(2), &p.y);
    let lambda = f6_mul(&num, &f6_pow(&den, &FERMAT_EXP));
    let x_out = f6_sub(&f6_square(&lambda), &f6_scal(Belt(2), &p.x));
    let y_out = f6_sub(&f6_mul(&lambda, &f6_sub(&p.x, &x_out)), &p.y);
    let doubled = CheetahPoint {
        x: x_out,
        y: y_out,
        inf: false,
    };
    // 2·O = O and 2·(2-torsion) = O.
    let to_identity = Choice::from(p.inf as u8) | f6_ct_eq(&p.y, &F6_ZERO);
    Ok(CheetahPoint::conditional_select(
        &doubled,
        &A_ID,
        to_identity,
    ))
}

#[inline(always)]
pub fn ch_neg(p: &CheetahPoint) -> CheetahPoint {
    CheetahPoint {
        x: p.x,
        y: f6_neg(&p.y),
        inf: p.inf,
    }
}

/// Point addition `P + Q`, constant time for points in the prime-order subgroup.
///
/// Uses a unified affine formula: the slope numerator/denominator are chosen in
/// constant time between the general-addition and doubling cases, a single field
/// inversion is performed, and the degenerate results (`P + (−P) = O`, identity
/// operands, 2-torsion doubling) are fixed up with constant-time selects.
#[inline(always)]
pub fn ch_add(p: &CheetahPoint, q: &CheetahPoint) -> Result<CheetahPoint, CheetahError> {
    let same_x = f6_ct_eq(&p.x, &q.x);
    let same_y = f6_ct_eq(&p.y, &q.y);
    let doubling = same_x & same_y;

    // General addition: λ = (y_p − y_q)/(x_p − x_q).
    let num_add = f6_sub(&p.y, &q.y);
    let den_add = f6_sub(&p.x, &q.x);
    // Doubling: λ = (3·x_p² + 1)/(2·y_p).
    let num_dbl = f6_add(&f6_scal(Belt(3), &f6_square(&p.x)), &F6_ONE);
    let den_dbl = f6_scal(Belt(2), &p.y);

    let num = F6lt::conditional_select(&num_add, &num_dbl, doubling);
    let den = F6lt::conditional_select(&den_add, &den_dbl, doubling);
    let lambda = f6_mul(&num, &f6_pow(&den, &FERMAT_EXP));

    let x_out = f6_sub(&f6_sub(&f6_square(&lambda), &p.x), &q.x);
    let y_out = f6_sub(&f6_mul(&lambda, &f6_sub(&p.x, &x_out)), &p.y);
    let general = CheetahPoint {
        x: x_out,
        y: y_out,
        inf: false,
    };

    // P + (−P) = O (same x, opposite y), or doubling a 2-torsion point (y = 0).
    let to_identity = (same_x & !same_y) | (doubling & f6_ct_eq(&p.y, &F6_ZERO));
    let result = CheetahPoint::conditional_select(&general, &A_ID, to_identity);
    // Identity operands: O + Q = Q, P + O = P.
    let result = CheetahPoint::conditional_select(&result, q, Choice::from(p.inf as u8));
    let result = CheetahPoint::conditional_select(&result, p, Choice::from(q.inf as u8));
    Ok(result)
}

#[inline(always)]
pub fn ch_scal(n: u64, p: &CheetahPoint) -> Result<CheetahPoint, CheetahError> {
    let mut n = n;
    let mut p_copy = *p;
    let mut acc = A_ID;
    while n > 0 {
        if n & 1 == 1 {
            acc = ch_add(&acc, &p_copy)?;
        }
        p_copy = ch_double(p_copy)?;
        n >>= 1;
    }
    Ok(acc)
}

// ---- projective coordinates (RCB complete addition) -------------------------
//
// Homogeneous projective points `(X : Y : Z)` represent the affine `(X/Z, Y/Z)`
// with identity `(0 : 1 : 0)`. Scalar multiplication runs here to avoid a field
// inversion per point operation: the Renes–Costello–Batina complete addition
// formula (EUROCRYPT 2016, Algorithm 1) is branchless and exception-free for the
// prime-order subgroup, so only one inversion is needed at the very end to return
// to affine.

/// `b` for the Cheetah curve `y² = x³ + x + b` (`a = 1`, `b = u + 395`).
const B: F6lt = F6lt([Belt(395), Belt(1), Belt(0), Belt(0), Belt(0), Belt(0)]);

/// `b3 = 3·b` for the Cheetah curve `y² = x³ + x + b` (`a = 1`), as an `F6`
/// element — the only curve-specific constant the RCB formula needs.
const B3: F6lt = F6lt([Belt(1185), Belt(3), Belt(0), Belt(0), Belt(0), Belt(0)]);

#[derive(Clone, Copy)]
struct ProjPoint {
    x: F6lt,
    y: F6lt,
    z: F6lt,
}

impl ProjPoint {
    const IDENTITY: ProjPoint = ProjPoint {
        x: F6_ZERO,
        y: F6_ONE,
        z: F6_ZERO,
    };

    /// `(x, y, 1)` for a finite point, else the identity `(0 : 1 : 0)`.
    #[inline(always)]
    fn from_affine(p: &CheetahPoint) -> Self {
        let finite = ProjPoint {
            x: p.x,
            y: p.y,
            z: F6_ONE,
        };
        ProjPoint::conditional_select(&finite, &ProjPoint::IDENTITY, Choice::from(p.inf as u8))
    }

    /// Back to affine `(X/Z, Y/Z)`, or the identity when `Z = 0`. One inversion.
    #[inline(always)]
    fn to_affine(self) -> CheetahPoint {
        let zinv = f6_pow(&self.z, &FERMAT_EXP); // 0 when Z == 0 (no error)
        let affine = CheetahPoint {
            x: f6_mul(&self.x, &zinv),
            y: f6_mul(&self.y, &zinv),
            inf: false,
        };
        CheetahPoint::conditional_select(&affine, &A_ID, f6_ct_eq(&self.z, &F6_ZERO))
    }
}

impl ConditionallySelectable for ProjPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        ProjPoint {
            x: F6lt::conditional_select(&a.x, &b.x, choice),
            y: F6lt::conditional_select(&a.y, &b.y, choice),
            z: F6lt::conditional_select(&a.z, &b.z, choice),
        }
    }
}

/// Renes–Costello–Batina complete addition (Algorithm 1, specialized to `a = 1`,
/// so the three `a·_` multiplications drop out). Branchless and exception-free
/// for points in the prime-order subgroup, and unified — it also yields `2P`
/// when `P = Q` and handles the identity, so the scalar-mul loop needs no special
/// cases.
fn proj_add(p: &ProjPoint, q: &ProjPoint) -> ProjPoint {
    let (x1, y1, z1) = (p.x, p.y, p.z);
    let (x2, y2, z2) = (q.x, q.y, q.z);

    let mut t0 = f6_mul(&x1, &x2);
    let mut t1 = f6_mul(&y1, &y2);
    let mut t2 = f6_mul(&z1, &z2);
    let mut t3 = f6_add(&x1, &y1);
    let mut t4 = f6_add(&x2, &y2);
    t3 = f6_mul(&t3, &t4);
    t4 = f6_add(&t0, &t1);
    t3 = f6_sub(&t3, &t4);
    t4 = f6_add(&x1, &z1);
    let mut t5 = f6_add(&x2, &z2);
    t4 = f6_mul(&t4, &t5);
    t5 = f6_add(&t0, &t2);
    t4 = f6_sub(&t4, &t5);
    t5 = f6_add(&y1, &z1);
    let mut x3 = f6_add(&y2, &z2);
    t5 = f6_mul(&t5, &x3);
    x3 = f6_add(&t1, &t2);
    t5 = f6_sub(&t5, &x3);
    let mut z3 = t4; // a · t4 with a = 1
    x3 = f6_mul(&B3, &t2);
    z3 = f6_add(&x3, &z3);
    x3 = f6_sub(&t1, &z3);
    z3 = f6_add(&t1, &z3);
    let mut y3 = f6_mul(&x3, &z3);
    t1 = f6_add(&t0, &t0);
    t1 = f6_add(&t1, &t0);
    // a · t2 with a = 1 → t2 unchanged.
    t4 = f6_mul(&B3, &t4);
    t1 = f6_add(&t1, &t2);
    t2 = f6_sub(&t0, &t2);
    // a · t2 with a = 1 → t2 unchanged.
    t4 = f6_add(&t4, &t2);
    t0 = f6_mul(&t1, &t4);
    y3 = f6_add(&y3, &t0);
    t0 = f6_mul(&t5, &t4);
    x3 = f6_mul(&t3, &x3);
    x3 = f6_sub(&x3, &t0);
    t0 = f6_mul(&t3, &t1);
    z3 = f6_mul(&t5, &z3);
    z3 = f6_add(&z3, &t0);

    // NOTE: RCB Algorithm 1 is complete only on the prime-order subgroup. On the
    // full group it has exceptional inputs — It is sound
    // here because every scalar multiplication in the signing path operates on
    // prime-order-subgroup points. Subgroup-membership validation must therefore
    // NOT use this ladder; `CheetahPoint::in_curve` uses the affine law instead.
    ProjPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// Scalar multiplication `n·p`, constant time.
///
/// Fixed 256-iteration double-and-add in homogeneous projective coordinates: each
/// step does one [`proj_add`] doubling and one addition (with **no** per-operation
/// field inversion — a single inversion at the end converts back to affine) and
/// selects the sum in constant time, so neither the bit length nor the Hamming
/// weight of `n` is revealed. RCB addition is branchless and exception-free in the
/// prime-order subgroup. See `SECURITY.md`.
#[inline(always)]
pub fn ch_scal_big(n: &U256, p: &CheetahPoint) -> Result<CheetahPoint, CheetahError> {
    let pp = ProjPoint::from_affine(p);
    let mut acc = ProjPoint::IDENTITY;
    let be: [u8; 32] = n.to_be_bytes().into();
    for byte in be {
        for bit in (0..8).rev() {
            acc = proj_add(&acc, &acc); // double
            let acc_plus = proj_add(&acc, &pp); // add
            let take = Choice::from((byte >> bit) & 1);
            acc = ProjPoint::conditional_select(&acc, &acc_plus, take);
        }
    }
    Ok(acc.to_affine())
}

/// Fold a Tip5 hash output into the scalar field:
/// `(a[0] + P·a[1] + P²·a[2] + P³·a[3]) mod G_ORDER`, where `P` is the Goldilocks
/// prime. Computed with constant-time `crypto-bigint` modular multiply/add (each
/// `mul_mod` reduces the wide product, so nothing overflows 256 bits). `a[4]`,
/// if present, is unused — only four base-P limbs fit below the subgroup order.
pub fn trunc_g_order(a: &[u64]) -> U256 {
    let mut result = U256::from_u64(a[0]);
    result = result.add_mod(
        &P_BIG.mul_mod(&U256::from_u64(a[1]), &G_ORDER_NZ),
        &G_ORDER_NZ,
    );
    result = result.add_mod(
        &P_BIG_2.mul_mod(&U256::from_u64(a[2]), &G_ORDER_NZ),
        &G_ORDER_NZ,
    );
    result = result.add_mod(
        &P_BIG_3.mul_mod(&U256::from_u64(a[3]), &G_ORDER_NZ),
        &G_ORDER_NZ,
    );
    result
}

/// `[G_ORDER]·p` via the affine, 2-torsion-aware group law (`ch_add`/`ch_double`).
///
/// Used by [`CheetahPoint::in_curve`] as the subgroup-membership oracle. The
/// affine `ch_add`/`ch_double` carry explicit identity / `P + (−P)` / 2-torsion
/// overrides and so are correct for *every* on-curve point — including the
/// even-order cofactor points where the RCB projective ladder is incomplete
fn affine_scal_order(p: &CheetahPoint) -> CheetahPoint {
    let be: [u8; 32] = G_ORDER.to_be_bytes().into();
    let mut acc = A_ID;
    for byte in be {
        for bit in (0..8).rev() {
            acc = ch_double(acc).expect("ch_double is infallible");
            if (byte >> bit) & 1 == 1 {
                acc = ch_add(&acc, p).expect("ch_add is infallible");
            }
        }
    }
    acc
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::belt::Belt;

    #[test]
    fn test_base58_prefix_validation() {
        // Canonical encoding round-trips.
        let b58 = A_GEN.into_base58().expect("A_GEN encodes to base58");
        assert_eq!(
            CheetahPoint::from_base58(&b58).expect("canonical base58 decodes"),
            A_GEN
        );

        // Tamper only the format prefix byte: the coordinate bytes (and hence the
        // decoded point) are unchanged, but the string must now be rejected so it
        // cannot alias the canonical encoding.
        let mut raw = bs58::decode(&b58)
            .into_vec()
            .expect("base58 string decodes to bytes");
        assert_eq!(raw[0], CheetahPoint::FORMAT_PREFIX);
        raw[0] = 0x02;
        let bad = bs58::encode(raw).into_string();
        assert!(matches!(
            CheetahPoint::from_base58(&bad),
            Err(CheetahError::BadPrefix(0x02))
        ));
    }

    const F6_TEST: F6lt = F6lt([
        Belt(13724052584687643294),
        Belt(6944593306454870014),
        Belt(10082672435494154603),
        Belt(6450272673873704561),
        Belt(2898784811200916299),
        Belt(15463938240345685194),
    ]);

    #[test]
    fn test_f6mul() {
        let f0 = F6_ZERO;
        let f1 = F6_ONE;
        let f2 = F6lt([Belt(1), Belt(2), Belt(3), Belt(4), Belt(5), Belt(6)]);

        assert_eq!(f6_mul(&f1, &f2), f2);
        assert_eq!(f6_mul(&f2, &f1), f2);
        assert_eq!(f6_mul(&f0, &f2), f0);
        assert_eq!(f6_mul(&f2, &f0), f0);
    }

    #[test]
    fn test_f6inv() -> Result<(), CheetahError> {
        let f = F6_ONE;
        let f_inv = f6_inv(&f)?;
        assert_eq!(f_inv, f);

        let f = F6_ZERO;
        let f_inv = f6_inv(&f);
        assert!(f_inv.is_err());

        let f = F6lt([Belt(1), Belt(1), Belt(1), Belt(1), Belt(1), Belt(1)]);
        let f_inv = f6_inv(&f)?;
        assert_eq!(
            f_inv,
            F6lt([
                Belt(3074457344902430720),
                Belt(15372286724512153601),
                Belt(0),
                Belt(0),
                Belt(0),
                Belt(0)
            ])
        );

        let f = F6_TEST;
        let f_inv = f6_inv(&f)?;
        assert_eq!(
            f_inv,
            F6lt([
                Belt(129083178215983407),
                Belt(16804250925345184998),
                Belt(6447171951354165736),
                Belt(16181730381532049633),
                Belt(9179768094922373417),
                Belt(8139613426717722210)
            ])
        );

        Ok(())
    }

    #[test]
    fn test_f6_div() -> Result<(), CheetahError> {
        let f1 = F6_TEST;
        let f2 = F6lt([
            Belt(0xdeadbeef),
            Belt(0xdead0001),
            Belt(0),
            Belt(0),
            Belt(0),
            Belt(0),
        ]);
        let res = f6_div(&f1, &f2)?;
        assert_eq!(
            res,
            F6lt([
                Belt(7542375812088865094),
                Belt(15664235984267184732),
                Belt(2705725317242016633),
                Belt(4831474931498658260),
                Belt(4259601222882849719),
                Belt(5901377836576087143)
            ])
        );
        Ok(())
    }

    #[test]
    fn test_ch_scal() -> Result<(), CheetahError> {
        let n = 3;

        let exp_pt = CheetahPoint {
            x: F6lt([
                Belt(12461929372724418873),
                Belt(16567359094004701986),
                Belt(18139376982535661051),
                Belt(3904128592858427998),
                Belt(1409597492055585669),
                Belt(10004445677131924957),
            ]),
            y: F6lt([
                Belt(11902197035441682466),
                Belt(5072010750673887563),
                Belt(16590571040514665822),
                Belt(11686652568553538253),
                Belt(9569866106958470758),
                Belt(6839548852764696901),
            ]),
            inf: false,
        };

        let res = ch_scal(n, &A_GEN)?;

        assert_eq!(res, exp_pt);
        Ok(())
    }

    #[test]
    fn ch_add_edge_cases() -> Result<(), CheetahError> {
        let g = A_GEN;
        let two_g = ch_double(g)?;
        let three_g = ch_scal(3, &g)?;

        // Identity operands.
        assert_eq!(ch_add(&g, &A_ID)?, g, "P + O = P");
        assert_eq!(ch_add(&A_ID, &g)?, g, "O + P = P");
        assert_eq!(ch_add(&A_ID, &A_ID)?, A_ID, "O + O = O");
        // P + (-P) = O.
        assert_eq!(ch_add(&g, &ch_neg(&g))?, A_ID, "P + (-P) = O");
        // Doubling via ch_add (P == Q).
        assert_eq!(ch_add(&g, &g)?, two_g, "P + P = 2P");
        // General addition (distinct points).
        assert_eq!(ch_add(&g, &two_g)?, three_g, "G + 2G = 3G");
        // Consistency with scalar-mul by the subgroup order: order·G = O.
        assert_eq!(ch_scal_big(&G_ORDER, &g)?, A_ID, "n·G = O");
        Ok(())
    }

    #[test]
    fn ch_scal_big_matches_affine_reference() -> Result<(), CheetahError> {
        // The projective (RCB) scalar mul must agree with the affine
        // double-and-add `ch_scal` for a range of scalars.
        for k in [
            1u64,
            2,
            3,
            7,
            8,
            255,
            256,
            65_537,
            0x1234_5678,
            u32::MAX as u64,
        ] {
            assert_eq!(
                ch_scal_big(&U256::from_u64(k), &A_GEN)?,
                ch_scal(k, &A_GEN)?,
                "k = {k}"
            );
        }
        // Linearity: (a+b)·G == a·G + b·G.
        let a = U256::from_u64(123_456);
        let b = U256::from_u64(987_654);
        let sum = ch_scal_big(&a.add_mod(&b, &G_ORDER_NZ), &A_GEN)?;
        let parts = ch_add(&ch_scal_big(&a, &A_GEN)?, &ch_scal_big(&b, &A_GEN)?)?;
        assert_eq!(sum, parts, "(a+b)·G == a·G + b·G");
        Ok(())
    }

    #[test]
    fn in_curve_accepts_generator_and_identity() {
        assert!(
            A_GEN.in_curve(),
            "the generator is in the prime-order subgroup"
        );
        assert!(A_ID.in_curve(), "the identity is accepted");
    }

    #[test]
    fn in_curve_rejects_off_curve_point() {
        let mut bad = A_GEN;
        bad.y.0[0] = Belt(bad.y.0[0].0 ^ 1);
        assert!(
            !bool::from(bad.satisfies_curve_eq()),
            "tampered point is off-curve"
        );
        assert!(!bad.in_curve(), "in_curve rejects an off-curve point");
    }

    fn two_torsion_point() -> CheetahPoint {
        CheetahPoint {
            x: F6lt([
                Belt(16464216994076148022),
                Belt(10762729315666779701),
                Belt(13396543320389503071),
                Belt(6901070379872838024),
                Belt(3684827223278792538),
                Belt(13601246634833184273),
            ]),
            y: F6_ZERO,
            inf: false,
        }
    }

    #[test]
    fn in_curve_rejects_low_order_point() {
        // The curve's lone non-trivial rational 2-torsion point (paper §5.2):
        // it IS on the curve, but has order 2, so it lies in the cofactor part,
        // not the prime-order subgroup `G`. The equation check passes; the
        // `[n]P == O` subgroup check must reject it (n is odd ⇒ [n]·T = T ≠ O).
        assert!(
            bool::from(two_torsion_point().satisfies_curve_eq()),
            "the 2-torsion point is genuinely on the curve"
        );
        assert!(
            !two_torsion_point().in_curve(),
            "in_curve rejects an on-curve point outside the prime-order subgroup"
        );
    }

    // Low-order points generated by a try-and-increment hash-to-curve in
    // F_{p^6} (Tonelli–Shanks sqrt), then cofactor-cleared to exact order `d`.
    // Each satisfies [d]Q = O and [n]Q != O, so `in_curve` must reject it.
    fn low_order_points() -> [(u64, CheetahPoint); 5] {
        [
            (5, CheetahPoint { x: F6lt([Belt(5167438881558601205), Belt(1967079362885488533), Belt(6353066307535555988), Belt(2857292020134133713), Belt(7092920336497073817), Belt(4452868260558128301)]), y: F6lt([Belt(7515824561339875226), Belt(16468941116044771186), Belt(846268578125393631), Belt(3625633647896666980), Belt(14557034899430828307), Belt(7795971589867338376)]), inf: false }),
            (29, CheetahPoint { x: F6lt([Belt(1980090423654265686), Belt(16147158697790097196), Belt(680944181821193568), Belt(4823925916584749845), Belt(15545956157381410871), Belt(6439861153358820698)]), y: F6lt([Belt(5274253300058465560), Belt(9863917181709659972), Belt(6162984455364062800), Belt(11207984427594523123), Belt(586243587132928293), Belt(15497183565636576260)]), inf: false }),
            (181, CheetahPoint { x: F6lt([Belt(15791578662007859293), Belt(13951751726558661900), Belt(6752851328618893236), Belt(4893875307938373163), Belt(12879442199657115392), Belt(12065365338679529080)]), y: F6lt([Belt(15808288111329598588), Belt(10730647466724232640), Belt(13379428348422112633), Belt(1530262791301897734), Belt(7532652432700942444), Belt(2388398893276941315)]), inf: false }),
            (10, CheetahPoint { x: F6lt([Belt(7839799843891977397), Belt(10984321810721329306), Belt(10017801997908119106), Belt(6703297338141384153), Belt(13710317544236357924), Belt(1925808567393037895)]), y: F6lt([Belt(6128533183582499334), Belt(13164345926002157274), Belt(6176566102451720837), Belt(10060810356060809489), Belt(11372809157850782143), Belt(12793843137085492617)]), inf: false }),
            (58, CheetahPoint { x: F6lt([Belt(13956875740325627343), Belt(15710534777101010437), Belt(13737350887133062184), Belt(11260260421232960668), Belt(16888531191332762936), Belt(9342074570973628701)]), y: F6lt([Belt(13291940141693833851), Belt(10466260784118385830), Belt(6174536700377931153), Belt(3186999313045076936), Belt(14515430652016314960), Belt(9547824820716303220)]), inf: false }),
        ]
    }

    #[test]
    fn low_order_points_are_on_curve_but_rejected() {
        for (d, p) in low_order_points() {
            // genuinely on the curve …
            assert!(bool::from(p.satisfies_curve_eq()), "order-{d} point is on-curve");
            // … of exact order d, checked with the affine law (`ch_scal`, correct
            // on cofactor points): [d]·P = O …
            assert_eq!(ch_scal(d, &p).unwrap(), A_ID, "[{d}]·P = O");
            // … but NOT in the prime-order subgroup, so in_curve rejects it.
            assert!(!p.in_curve(), "order-{d} point is rejected by in_curve");
        }
    }

    #[test]
    fn rcb_ladder_is_unsound_on_even_order_points() {
        // Regression guard for the audit finding: on even-order cofactor points
        // the fast RCB ladder (`ch_scal_big`) disagrees with the affine law —
        // which is exactly why `in_curve`'s membership test must use the affine
        // `affine_scal_order` and NOT the fast ladder. `[n]·P` for the order-10
        // point is a finite non-identity point under both laws, but they differ.
        let (_, p10) = low_order_points()[3]; // the order-10 point
        let affine = affine_scal_order(&p10);
        let fast = ch_scal_big(&G_ORDER, &p10).unwrap();
        assert_ne!(affine, A_ID, "P is genuinely outside the prime-order subgroup");
        assert_ne!(fast, affine, "RCB ladder disagrees with the affine law on [n]·P");
    }
}
