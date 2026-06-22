# cheetah-curve 🐆

Port of [Nockchain](https://nockchain.org)'s cryptographic primitives stripped of the nockvm / noun-serde deps:

- **`cheetah`** — the Cheetah elliptic curve over a sextic extension `F6` of the
  Goldilocks field: generator `A_GEN`, point add / negate / scalar-mul, the
  97-byte big-endian point wire encoding (`CheetahPoint::to_be_bytes` /
  `from_be_bytes`), and `trunc_g_order` scalar reduction.
- **`tip5`** — the Tip5 algebraic hash (`hash_varlen`).
- **`belt`** — the Goldilocks field `p = 2^64 − 2^32 + 1`.
- **`schnorr`** — the high-level signature API: `PublicKey` / `PrivateKey` /
  `Signature`, `sign` / `verify` / `challenge`, chain-signatures child
  derivation (`derive_child` / `tweak_from_le_bytes`), and the additive
  (FROST-core) threshold helpers (`aggregate_pubkeys` / `partial_sign` /
  `aggregate_responses`).
- **`message`** — signing-payload ⇄ digest codecs (`message_from_digest` /
  `digest_from_message`) and domain-separated Tip5 hashes (`tip5_to_scalar` /
  `tip5_to_bytes`).

Together these define Nockchain's key-prefixed Schnorr signature scheme, whose
verifier is standard, nonce-agnostic Schnorr with a Tip5 challenge:

```text
R' = s·G − c·P
accept iff  R' ≠ O  and  trunc_g_order(Tip5(R'.x ‖ R'.y ‖ P.x ‖ P.y ‖ messageBelts)) == c
```

Because the verifier is nonce-agnostic, this curve+hash instantiation supports
threshold / FROST-style Schnorr (any joint nonce verifies), which is what makes
it usable as a NEAR-MPC signing domain. `no_std`-friendly arithmetic compiles to
`wasm32-unknown-unknown`, so a NEAR contract can verify Nockchain signatures
on-chain:

```rust
use cheetah_curve::{PublicKey, Signature};

// pubkey_bytes: 97-byte BE point;  sig_bytes: 64-byte (c‖s) LE;  digest: 5 belts
let pk = PublicKey::from_be_bytes(&pubkey_bytes)?;
let child = pk.derive_child(&tweak)?;            // chain-signatures derivation
let sig = Signature::from_le_bytes(&sig_bytes);
assert!(child.verify(&sig, &digest));
```

## Mathematical background

The Cheetah curve was designed by Toposware; the original write-up is
[*The Cheetah curve*](https://toposware.com/blog/cheetah-curve/).

**Base field.** Everything is built over the Goldilocks prime field $\mathbb{F}_p$
with

$$p = 2^{64} - 2^{32} + 1 = 18446744069414584321.$$

This is the field implemented by the **`belt`** module.

**Sextic extension.** The curve lives over the degree-6 extension
$\mathbb{F}_{p^6}$, realized as the quotient

$$\mathbb{F}_{p^6} = \mathbb{F}_p[X]\,/\,(X^6 - 7).$$

Writing $u$ for the image of $X$, every element is a polynomial of degree at most
$5$ in $u$ with coefficients in $\mathbb{F}_p$ (six Goldilocks limbs — the
`F6lt` type), and $u$ satisfies the defining relation

$$u^6 = 7.$$

This is why F6 multiplication folds the high terms back in with a factor of
`7` (see `Belt(7)` in [`src/cheetah.rs`](src/cheetah.rs)).

**Curve equation.** Over $\mathbb{F}_{p^6}$, Cheetah is the short Weierstrass
curve

$$E : y^2 = x^3 + x + (u + 395),$$

with the constant term taken in $\mathbb{F}_{p^6}$ via $u^6 = 7$.

**Group and prime-order subgroup.** The $\mathbb{F}_{p^6}$-rational points of $E$,
together with the point at infinity $\mathcal{O}$, form a finite abelian group
under the usual chord-and-tangent addition law. Cheetah uses its $255$-bit
prime-order subgroup of order

$$q = 55610362957290864006699123731285679659474893560816383126640993521607086746831.$$

The generator `A_GEN` ($G$) generates this subgroup, so $q\cdot G = \mathcal{O}$,
and all scalar arithmetic in this crate is performed modulo $q$ — the constant
`G_ORDER`. Pollard's rho on a $255$-bit subgroup gives roughly $2^{127}$ generic
discrete-log security.

## Sage Verification

Parameters verified via: `sage load("verify.sage")`

```
===========================================================================
CHEETAH CURVE VERIFICATION
Paper: Security Analysis of Elliptic Curves over Sextic Extension
       of Small Prime Fields (eprint 2022/277), Section 5.1
===========================================================================

[1] Base prime p = 18446744069414584321  (Goldilocks, 2^64 - 2^32 + 1)
    Sextic extension F6 = F_p[u]/( x^6 + 18446744069414584314 ) created.
    (7 confirmed quadratic AND cubic non-residue in F_p)

[2] Curve parameters
    a = 1
    b = u + 395   (= u + 395)
    Generator g constructed on the curve.
    Subgroup order n = 0x7af2599b3b3f22d0563fbf0f990a37b5327aa72330157722d443623eaed4accf  (255-bit)
    Cofactor h = 708537115134665106932687062569690615370  (130-bit)

--------------------------------------------------
CORE CHECKS
--------------------------------------------------
[OK] Generator lies on the curve
[OK] Subgroup order n is prime
[OK] Generator has exact order n  (n*G = O, G != O, n prime)
[OK] Full order #E = h*n verified (384-bit, unique in Hasse interval)
===========================================================================
VERIFICATION SUMMARY  (all constants match eprint 2022/277 Sec 5.1)
===========================================================================

  [OK] p, F_{p^6} = F_p[u]/(u^6 - 7)
  [OK] E : y^2 = x^3 + x + (u + 395),  a = 1
  [OK] generator g matches paper / Rust A_GEN
  [OK] generator has exact prime order n  (= Rust G_ORDER)
  [OK] cofactor h and full order #E = h*n verified within Hasse bound

```

## Security

The whole signing path is **constant time** — the scalar field
([`crypto-bigint`](https://crates.io/crates/crypto-bigint) `U256`), the Goldilocks
field (branchless reductions), Tip5, and the curve point add/double/scalar-mul
have no secret-dependent branches. Private keys are zeroized on drop, compare in
constant time, and have a redacted `Debug`. `verify` rejects out-of-range scalars
and `R' = O` (signature non-malleability). See [`SECURITY.md`](SECURITY.md) for
the full audit against the NCC Group cryptography review (crypto-bigint / k256).

## Provenance & parity

Vendored from nockchain's [`nockchain-math`](https://github.com/nockchain/nockchain)
(MIT OR Apache-2.0) with the `nockvm` / `noun-serde` coupling removed, so it has
no Nock VM dependency and builds on stable Rust. The one intentional change is
`cheetah::f6_inv`, reimplemented via Fermat's little theorem (`f^(p^6−2)`) to drop
the `bpoly`/`poly`/`felt` modules; a field inverse is unique, so the output is
identical (guarded by the `test_f6inv` known-answer test).

Byte-exact parity with the on-chain Nockchain verifier and `@nockchain/rose-ts`
is enforced by the in-crate known-answer tests (Tip5 public vectors, `3·G`, F6
mul/inv/div, MDS reference) and the golden-vector tests reproducing rose-ts's
exact `(c, s)` signatures.

## License

`MIT OR Apache-2.0`, matching the upstream `nockchain-math`. See `LICENSE-MIT`
and `LICENSE-APACHE`.
