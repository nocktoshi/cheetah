# cheetah-curve — Security Audit & Hardening

This document records a security review of `cheetah-curve` carried out against the
findings of the **NCC Group cryptography review of RustCrypto `crypto-bigint`,
`crypto-primes`, and `k256`** (report *NCC-E008526*, "Entropy/Rust Cryptography
and Implementation Review", 2023-08-25). Each NCC finding was assessed for
applicability to this crate; the applicable ones were fixed in **v0.3.0**, which
also migrates **all** big-integer arithmetic from the variable-time `ibig` bignum
to constant-time `crypto-bigint` — the scalar field (`U256`) and the `F6`
inversion exponent (`U384`). `ibig` is no longer a dependency.

It also states the crate's threat model and the residual side-channel surface so
that integrators (in particular the NEAR MPC Cheetah signer and the on-chain
verifier) can make an informed risk decision.

---

## 1. What this crate is

`cheetah-curve` implements Nockchain's key-prefixed Schnorr signature primitives:

- the Goldilocks field `p = 2^64 − 2^32 + 1` (`belt`),
- the Cheetah curve over the sextic extension `F6` (`cheetah`),
- the Tip5 algebraic hash (`tip5`),
- a high-level Schnorr API — `PrivateKey` / `PublicKey` / `Signature`, `sign`,
  `verify`, chain-signatures `derive_child`, and additive (FROST-core) threshold
  helpers (`schnorr`),
- signing-payload ⇄ digest codecs and domain-separated Tip5 hashes (`message`).

The verifier is standard, nonce-agnostic Schnorr:

```text
R' = s·G − c·P;   accept iff  R' ≠ O  and  trunc_g_order(Tip5(R'.x‖R'.y‖P.x‖P.y‖m)) == c
```

Byte-for-byte parity with `@nockchain/rose-ts` and the on-chain Nockchain
verifier is enforced by golden-vector tests (`src/golden.rs`) reproducing the
exact `(c, s)` produced by rose-ts for both deterministic single-signer and
additive 2-party threshold signatures. **These parity tests still pass after the
crypto-bigint migration**, so the migration changed the implementation, not the
output.

---

## 2. Threat model

- **Primary deployment:** a threshold (FROST) MPC signer cluster and an on-chain
  (NEAR/wasm) verifier. The full private key is never reconstructed; each node
  holds a Shamir secret *share*. Nonces are ephemeral per signature.
- **In scope:** logical signature-validation flaws (forgery, malleability),
  out-of-range / malformed input handling, secret-material hygiene, and timing
  side channels across the whole signing path (scalar field, Goldilocks field,
  Tip5, and curve point arithmetic).
- **Constant time:** as of v0.3.x the entire secret path is free of
  secret-dependent branches and memory accesses — scalar arithmetic, the
  Goldilocks field reductions, the Tip5 permutation, point addition/doubling, and
  scalar multiplication (see §4.3 and §5). The only remaining preconditions are
  benign: branches on *public* lengths (the fixed transcript size) and the
  *public* Fermat exponent in `f6_inv`.

---

## 3. NCC findings — applicability and status

The NCC report covers libraries this crate now depends on (`crypto-bigint`) or is
analogous to (`k256` Schnorr/ECDSA). Each finding is mapped below.

| NCC ID | Finding | Applies here? | Status in cheetah-curve |
|--------|---------|---------------|--------------------------|
| **CRR** (High) | Missing Schnorr verification check — `R = O` not rejected, enabling a second valid signature (BIP-340 step 7) | **Yes** | **Fixed.** `verify` now rejects `R' = O`. See §4.1. |
| **2VF** (High) | Missing low-`s` validation → ECDSA signature malleability | Partial analogue | **Addressed by design.** Cheetah Schnorr has no high-`s`/low-`s` duality; `verify` enforces `c, s ∈ [1, G_ORDER)` (constant time). The malleability that *does* exist (identity-`R'`) is closed by CRR. See §4.1. |
| **FQT** (Low, Risk-Accepted upstream) | Inexact secret-key deserialization (variable length, silent zero-padding) | **Yes** | **Fixed.** `PrivateKey::from_be_bytes` / `from_le_bytes` take a fixed `&[u8; 32]` and reject any value not in `[1, G_ORDER)` — no silent reduction. See §4.2. |
| **UNR** (Low) | Minor timing leaks in wide scalar arithmetic | **Yes** (root cause) | **Fixed at the source.** All scalar arithmetic moved from variable-time `ibig` to constant-time `crypto-bigint` `add_mod` / `sub_mod` / `mul_mod` / `rem`. See §4.3. |
| **ENP** (Low, Risk-Accepted upstream) | Timing variability in signature generation | **Yes** | **Fixed.** `ch_scal_big` is a fixed 256-iteration double-and-add that *always* doubles, *always* adds, and selects the sum in constant time; `ch_add` / `ch_double` use a unified branchless affine formula; and the Goldilocks reductions were made branchless (§4.3 / §5). No secret-dependent branch remains. |
| **K34** (Low) | Square-root not constant time | No | Not applicable — the crate computes no integer square roots. `f6_inv` is `f^(p^6−2)` with a fixed *public* exponent, so its control flow is data-independent (see §5). |
| **VVV** (Low) | Hex decoding not constant time | Partial | **Annotated.** `PublicKey::to_hex` / `from_hex` are documented as **not** constant time and used only for public keys; no secret is ever hex-encoded. |
| **HRB** (Low) | Timing leak in saturating arithmetic | No (dependency-internal) | Inherited fixed in `crypto-bigint` ≥ 0.5.3. |
| **K2E / QTR / NEW** | crypto-primes prime-gen / overflow / test issues | No | This crate does no prime generation. |
| **YTT** (Info) | Missing toolchain spec / outdated deps | **Yes** | **Fixed.** `rust-version = "1.85"` is pinned; dependencies are current (`crypto-bigint 0.6`, `subtle 2.6`, `zeroize 1.8`). |

---

## 4. Hardening implemented in v0.3.0

### 4.1 Non-malleable verification (NCC-CRR)

`verify` now rejects `R' = s·G − c·P` equal to the point at infinity. Without this
check, an adversary **who already knows the secret key** can mint a *second*
valid signature for the same message and key:

```text
c = trunc_g_order(Tip5(O ‖ P ‖ m));  s = c·x   ⇒   s·G − c·P = c·x·G − c·(x·G) = O
```

so the recomputed challenge equals `c` and verification would (wrongly) succeed.
Honest signatures never have `R' = O`. This violates signature non-malleability,
which matters wherever a signature byte-string identifies a transaction (the
bridge/consensus setting). The fix is the Cheetah analogue of BIP-340
verification step 7 and is covered by the `verify_rejects_identity_rprime` test.

`verify` additionally enforces, in constant time, that `c` and `s` are in
`[1, G_ORDER)` and that the public key is not the point at infinity.

### 4.2 Exact, validated secret-key deserialization (NCC-FQT)

`PrivateKey::from_be_bytes` / `from_le_bytes` accept exactly 32 bytes (enforced by
the `&[u8; 32]` type) and return `None` unless the value lies in `[1, G_ORDER)`.
There is no silent zero-padding or modular reduction of out-of-range input, which
removes a malleability/interoperability footgun. Covered by
`private_key_rejects_out_of_range`.

### 4.3 Constant-time scalar field (NCC-UNR / ENP)

All scalar-field values — private keys, nonces, challenges, and signature
components — are now `crypto_bigint::U256`. Modular `+`, `−`, `×`, and reduction
use `add_mod` / `sub_mod` / `mul_mod` / `rem`, which are constant time with
respect to the operand *values* (the modulus `G_ORDER` is public). Scalar
comparisons (range and equality checks) use `subtle`'s `ConstantTimeLess` /
`ConstantTimeEq`. This replaces `ibig`, whose arbitrary-precision routines branch
and allocate based on operand magnitude.

`ch_scal_big` (scalar multiplication) is a **fixed 256-iteration** double-and-add
that always performs one doubling and one addition per bit and selects the sum in
constant time (`subtle`), so neither the bit length nor the Hamming weight of the
scalar leaks. The point and field layers it sits on are constant time too — see
§5.

### 4.4 Secret-material hygiene

`PrivateKey` now:
- **zeroizes on drop** (`ZeroizeOnDrop`, via `crypto-bigint`'s `zeroize` feature),
- has a **redacted `Debug`** (`PrivateKey(<redacted>)`) so secrets cannot leak
  into logs,
- compares in **constant time** (`PartialEq` via `ct_eq`).

### 4.5 Dead code / dependency hygiene (NCC-YTT)

- Removed unused `belt_schnorr_t8_to_ubig` / `met5`.
- **`ibig` is fully removed.** The last remaining use — the `F6` Fermat inversion
  exponent `p^6 − 2` — is now a `crypto_bigint::U384` constant, and `f6_pow`
  iterates it as a fixed 384-bit square-and-multiply. `once_cell` was dropped with
  it (all moduli/exponents are now compile-time `const`s). The crate no longer
  depends on any variable-time bignum.
- Pinned `rust-version` and updated to current dependency majors.

---

## 5. Constant-time point and field arithmetic

Earlier releases left the affine point operations and the Goldilocks reductions
with value-dependent branches; v0.3.x removes them so the whole signing path is
constant time. The changes, top to bottom:

- **`ch_add`** — a single *unified* affine formula. The slope numerator and
  denominator are selected in constant time (`subtle`) between the
  general-addition and doubling cases, one field inversion is performed, and the
  degenerate results (`P + (−P) = O`, identity operands, 2-torsion doubling) are
  fixed up with constant-time point selects. No branch or memory access depends
  on the point values.
- **`ch_double`** — always computes the doubling formula and selects the identity
  for `O` / 2-torsion inputs, again branchlessly.
- **`ch_scal_big`** — fixed 256-iteration double-and-add in **homogeneous
  projective coordinates** using the Renes–Costello–Batina complete addition
  formula (`proj_add`, EUROCRYPT 2016, Alg. 1, specialized to `a = 1`). RCB
  addition is branchless and exception-free in the prime-order subgroup and is
  *unified* (it also doubles), so each step does one projective doubling and one
  projective addition and selects the sum by the (secret) scalar bit via
  `subtle` — no early exit, no conditional add, and **no per-operation field
  inversion** (a single inversion converts the result back to affine). This is
  both the constant-time and the fast path. The affine `ch_add` / `ch_double`
  above remain for the (non-hot) public API and as the byte-exact reference.
- **Goldilocks field** — the reductions behind `Belt` multiply (`reduce_159`) and
  the Montgomery reduction (`mont_reduction`), plus negation (`bneg`), were the
  last conditional subtracts; they are now applied through carry/borrow **masks**
  rather than `if`, so the field multiply/add/sub/neg are branchless. (Addition
  and subtraction already used this pattern.) All changes are byte-identical to
  the branchy forms, validated by the Tip5 known-answer and curve golden vectors.
- **`f6_inv`** — `f^(p^6−2)` by square-and-multiply over a *fixed public*
  exponent, so its operation sequence is identical on every call; the only secret
  is the element being inverted, and the field multiply is branchless.
- **Tip5** — the sponge/permutation contain no value-dependent branches; the one
  loop bound (`tip5_absorb_input`) is the *public* input length.

### Preconditions and standing caveats

- **Prime-order subgroup.** The unified `ch_add` is exact because, for points in
  the prime-order subgroup, the selected denominator is never zero. Every key,
  nonce, aggregate, and child point the library produces lives in that subgroup,
  and deserialized public keys are validated on-curve. (Degenerate inputs still
  return the correct result via the identity overrides; only the "denominator ≠
  0" timing argument is specific to the subgroup.)
- **`ch_scal` (the `u64` variant) is *not* constant time** — it is a
  variable-length loop intended only for small *public* multipliers. Secret
  scalars must go through `ch_scal_big`.
- **RCB completeness** depends on the same prime-order-subgroup precondition: the
  formula is exception-free there, so `proj_add` never hits the (homogeneous)
  point-at-infinity degeneracy. `in_curve` validates subgroup membership, and all
  internally-produced points are subgroup elements.
- Constant-time selects rely on `subtle`'s optimization barriers; as always,
  "constant time in source" is not a guarantee about every backend's machine
  code, but no data-dependent branches or table indices are emitted.

Performance: scalar multiplication now performs a single field inversion (the
final projective→affine conversion) instead of one per point operation — the
constant-time path is also the fast path.

---

## 6. Verification

- `cargo test` — 24 tests, including:
  - `golden_*` — byte-exact `(c, s)` parity with `@nockchain/rose-ts` (single +
    threshold). These pass unchanged after the crypto-bigint migration, the
    branchless-arithmetic rewrite, **and** the projective scalar-mul rewrite —
    that is how byte-for-byte equivalence of the constant-time formulas is
    established;
  - `tip5_hash_varlen_public_vectors` / `test_f6inv` — Tip5 and F6-inverse
    known-answer tests, the byte-exactness check for the branchless reductions;
  - `ch_add_edge_cases` — `O`, `P + (−P)`, doubling-via-add, general add, and
    `n·G = O`;
  - `ch_scal_big_matches_affine_reference` — the projective (RCB) scalar mul
    agrees with the affine double-and-add over a range of scalars, plus linearity
    `(a+b)·G = a·G + b·G`;
  - `verify_rejects_identity_rprime` (CRR), `private_key_rejects_out_of_range`
    (FQT), `verify_rejects_tampering`,
    `derive_child_signature_verifies_under_child_key`,
    `additive_threshold_two_party_verifies`, message-codec round-trips.
- `cargo build --target wasm32-unknown-unknown` — the verifier compiles for the
  on-chain (NEAR contract) target.
- `cargo clippy` — clean.

## 7. Changelog (v0.2.0 → v0.3.0)

Breaking: scalar-bearing types now use `crypto_bigint::U256` instead of
`ibig::UBig` (`Signature.{c,s}`, `PrivateKey.0`, `G_ORDER`, `trunc_g_order`,
`ch_scal_big`, `challenge`, `derive_child`, `tweak_from_le_bytes`,
`partial_sign`, `aggregate_responses`). `PrivateKey::from_be_bytes` /
`from_le_bytes` now take `&[u8; 32]` and return `Option`. New `message` module
(`message_from_digest`, `digest_from_message`, `tip5_to_scalar`, `tip5_to_bytes`).
The `ibig` and `once_cell` dependencies are removed; the `F6` inversion exponent
is now a `crypto_bigint::U384` constant.

The curve point arithmetic (`ch_add`, `ch_double`) and the Goldilocks field
reductions (`reduce_159`, `mont_reduction`, `bneg`) were made **branchless /
constant time**, and `ch_scal_big` was moved to **constant-time projective
(RCB) scalar multiplication** with a single final inversion (see §5). These are
internal changes — the public signatures are unchanged and all golden /
known-answer vectors still match byte-for-byte.

`tip5::hash::hash_varlen` / `hash_10` / `assert_all_based` now take an immutable
`&[Belt]` slice (matching iris's API) instead of `&mut Vec<Belt>`; callers that
passed `&mut t` should pass `&t`.
