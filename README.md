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
