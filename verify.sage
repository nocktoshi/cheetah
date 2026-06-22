# verify.sage
# Verification script for the Cheetah curve.
#
# Constants cross-checked against:
#   - Salen, Singh, Soukharev, "Security Analysis of Elliptic Curves over
#     Sextic Extension of Small Prime Fields", eprint 2022/277, Section 5.1.
#   - nocktoshi/cheetah/src/cheetah.rs (A_GEN, G_ORDER, F6 multiplication).

print("="*75)
print("CHEETAH CURVE VERIFICATION")
print("Paper: Security Analysis of Elliptic Curves over Sextic Extension")
print("       of Small Prime Fields (eprint 2022/277), Section 5.1")
print("="*75)

# ============================================================
# 1. BASE FIELD (Goldilocks)
# ============================================================
p = 2^64 - 2^32 + 1
assert p == 0xFFFFFFFF00000001
F = GF(p)
print(f"\n[1] Base prime p = {p}  (Goldilocks, 2^64 - 2^32 + 1)")

# ============================================================
# 2. SEXTIC EXTENSION  F_{p^6} = F_p[u] / (u^6 - 7)
# ============================================================
# Paper Sec 5.1: "Let the sextic field extension F_{p^6} of F_p be defined by
# the (irreducible over F_p) polynomial u^6 - 7", with 7 a quadratic AND cubic
# non-residue in F_p. This matches the Rust F6 multiplication, which reduces
# the wrap-around terms with a factor of 7 (u^6 = 7).
R.<x> = F[]
f = x^6 - 7
assert f.is_irreducible(), "u^6 - 7 must be irreducible over F_p"
assert not F(7).is_square(),       "7 must be a quadratic non-residue"
assert F(7)^((p - 1)//3) != 1,     "7 must be a cubic non-residue"
F6.<u> = F.extension(f)
print(f"    Sextic extension F6 = F_p[u]/( {f} ) created.")
print( "    (7 confirmed quadratic AND cubic non-residue in F_p)")

# ============================================================
# 3. CURVE PARAMETERS
# ============================================================
print("\n[2] Curve parameters")

# Curve form (paper Sec 5.1):  E : y^2 = x^3 + a*x + b   with a = 1.
a = F6(1)

# b = u + 395   (paper Sec 5.1).
# NOTE: the Rust constant B3 = F6lt([1185, 3, 0, 0, 0, 0]) is 3*b, the tripled
# coefficient used by the Renes-Costello-Batina complete-addition formula --
# NOT b itself. Here we need b, so 1185/3 = 395 and 3/3 = 1, giving b = u + 395.
b = u + F6(395)
assert F6(3) * b == F6(1185) + F6(3)*u, "b must satisfy 3*b == Rust B3 constant"
print(f"    a = {a}")
print(f"    b = {b}   (= u + 395)")

# Generator g = (gx, gy)  (paper Sec 5.1; identical to Rust A_GEN).
Gx = ( 2754611494552410273
     + 8599518745794843693  * u
     + 10526511002404673680 * u^2
     + 4830863958577994148  * u^3
     + 375185138577093320   * u^4
     + 12938930721685970739 * u^5 )

Gy = ( 15384029202802550068
     + 2774812795997841935  * u
     + 14375303400746062753 * u^2
     + 10708493419890101954 * u^3
     + 13187678623570541764 * u^4
     + 9990732138772505951  * u^5 )

E = EllipticCurve(F6, [a, b])
assert E.discriminant() != 0, "curve is singular!"
G = E(Gx, Gy)
print("    Generator g constructed on the curve.")

# Prime subgroup order  #G  (paper Sec 5.1; = Rust G_ORDER).
n = 0x7af2599b3b3f22d0563fbf0f990a37b5327aa72330157722d443623eaed4accf
assert n == 55610362957290864006699123731285679659474893560816383126640993521607086746831
print(f"    Subgroup order n = {hex(n)}  ({n.nbits()}-bit)")

# Cofactor h  (paper Sec 5.1).
h = 2 * 5 * 29 * 181 * 155833 * 86621679593707472449686472361
print(f"    Cofactor h = {h}  ({h.nbits()}-bit)")

# ============================================================
# 4. CORE SECURITY CHECKS
# ============================================================
print("\n" + "-"*50)
print("CORE CHECKS")
print("-"*50)

# (a) Generator on the curve.
assert G in E
print("[OK] Generator lies on the curve")

# (b) n is prime.
assert is_prime(n)
print("[OK] Subgroup order n is prime")

# (c) Generator has order exactly n.
#     Avoid G.order() (full point counting over a ~384-bit field is infeasible).
#     Since n is prime: G != O and n*G == O  =>  ord(G) = n exactly.
O = E(0)
assert G != O
assert n * G == O, "n*G != O -- generator does NOT have order n"
print("[OK] Generator has exact order n  (n*G = O, G != O, n prime)")

# (d) Cofactor / full order, verified cheaply via Hasse + uniqueness.
#     n | #E(F_{p^6}) from (c).  Hasse: #E in [p^6+1-2p^3, p^6+1+2p^3], an
#     interval of width 4p^3 < n, so it holds at most one multiple of n.
#     Hence #E is the unique multiple of n in that interval; we check h*n is it.
N = h * n
p6 = p^6
lo, hi = p6 + 1 - 2*p^3, p6 + 1 + 2*p^3
assert lo <= N <= hi, "h*n is outside the Hasse interval"
assert 4*p^3 < n,     "Hasse interval wider than n -- order not pinned down"
print(f"[OK] Full order #E = h*n verified ({N.nbits()}-bit, unique in Hasse interval)")

# ============================================================
# SUMMARY
# ============================================================
print("="*75)
print("VERIFICATION SUMMARY  (all constants match eprint 2022/277 Sec 5.1)")
print("="*75)
print("""
  [OK] p, F_{p^6} = F_p[u]/(u^6 - 7)
  [OK] E : y^2 = x^3 + x + (u + 395),  a = 1
  [OK] generator g matches paper / Rust A_GEN
  [OK] generator has exact prime order n  (= Rust G_ORDER)
  [OK] cofactor h and full order #E = h*n verified within Hasse bound
""")
