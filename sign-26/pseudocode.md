# sign-26 SQIsign2d-push1/2 — algorithm summary

Isogeny-based signature over supersingular elliptic curves in characteristic
p = c·2^e1·3^e2 − 1, built from a three-move Σ-protocol whose hardness rests on
the Deuring correspondence (finding the secret isogeny/ideal between E0 and Epk).
Made non-interactive by **Fiat–Shamir with aborts (FSwA) combined with
Fiat–Shamir with hints (FSwH)** — signing may output ⊥ and restart. Responses are
computed as (2,2)-isogenies between products of elliptic curves ("2-dimensional
representation"). It is an improved variant of SQIsign2d-push [NO25].

Specification: `sign-26-spec.pdf` (59 pages), §4 (scheme), §5 (parameters),
§6 (security), §8.1 (sizes). Algorithms 24–28 are the scheme proper.

## Parameters

| parameter | Level-1 | Level-2 | Level-3 | Level-4 | meaning |
|---|---|---|---|---|---|
| λ | 128 | 160 | 256 | 512 | security parameter |
| p | 2^131·3^78 − 1 | 2^191·3^118 − 1 | 2^263·3^156 − 1 | 2^527·3^324 − 1 | field characteristic (§5.2) |
| e1 | 131 | 191 | 263 | 527 | 2-adic exponent, basis ⟨P0,Q0⟩ of E0[2^e1] |
| e2 | 78 | 118 | 156 | 324 | 3-adic exponent, basis ⟨U0,V0⟩ of E0[3^e2] |
| L (p−1 cofactor) | 5·53·173·863 | 5·7·59·937 | 11·17·59·947 | 401·691·2153 | needs L ≥ (log p)² |
| D_chl | 3^e2 | ← | ← | ← | challenge isogeny degree |
| D_com | 3^{2e2} | ← | ← | ← | commitment isogeny degree |
| D_rsp | 2^ersp, ersp ≤ e1−1 | ← | ← | ← | response bound (§4.2) |
| E0 | y² = x³ + x | ← | ← | ← | starting curve |
| claimed security | 128 classical | 80 quantum | 256 cl. / 128 q. | 512 cl. / 256 q. | spec's own claim (§5.2) |

Sizes (bytes), specification (§8.1 Table 1) vs the built reference library:

| instance | pk spec | pk impl | sk spec | sk impl | sig spec | sig impl | match |
|---|---|---|---|---|---|---|---|
| SQIsign2D-lvl1 | 64 | 64 | **518** | **456** | 150 | 150 | sk MISMATCH |
| SQIsign2D-lvl2 | 96 | 96 | **768** | **676** | 218 | 218 | sk MISMATCH |
| SQIsign2D-lvl3 | 128 | 128 | **1024** | **900** | 293 | 293 | sk MISMATCH |
| SQIsign2D-lvl4 | 262 | 262 | **2096** | **1838** | 593 | 593 | sk MISMATCH |

pk and sig agree at every level. **Every secret key size disagrees with the spec.**

## Pseudocode

### KeyGen — Algorithm 25 (§4.3)
```
(Epk, γ, Isk1, Isk2, Ppk, Qpk, Upk, Vpk) <- DoublePath(0)      // Alg. 24
   // γ ∈ O0 of norm 2^{2e1}·3^{2e2}; two equivalent isogenies
   // φsk1: E0 -> Epk of degree 2^{2e1} and φsk2: E0 -> Epk of degree 3^{2e2},
   // with Isk1·Isk2 = γO0
(Ũpk, Ṽpk) <- TorsionofBasis(Epk, 3, e2)                       // deterministic basis
Msk1 <- ChangeofBasis(Ũpk, Ṽpk, Upk, Vpk, 3, e2)
sk <- (Epk, Ppk, Qpk, γ, Isk1, Msk1)        // §4.3 bullet list: 6 components
pk <- Epk
return (sk, pk)
```
Spec's stated secret key (§4.3, verbatim list): the curve Epk; the two points
Ppk = φsk2(P0), Qpk = φsk2(Q0); the ideal Isk1; the quaternion γ ∈ O0 of norm
2^{2e1}3^{2e2}; and the change-of-basis matrix Msk1 with
(Ũpk,Ṽpk) = (Upk,Vpk)·Msk1. Counting that as 5 Fp2 elements (Epk, Ppk, Qpk) plus
matrix entries gives the §8.1 numbers — see "Implementation vs specification".

### Sign — Algorithm 27 (§4.4)
```
do
  // Commitment (§4.4.1): random φcom: E0 -> Ecom of degree D_com = 3^{2e2}
  (K0, Km, Em, Pm, Qm, Pcom, Qcom, Icom) <- DoublePath(1)
  // Challenge (§4.4.2)
  chl <- HASH(pk || j(Ecom) || msg)              // chl ∈ Z_{D_chl}
  // Response (§4.4.3)
  I'chl <- KerToIdeal(a0, a1)   where (a0,b0) = Msk1·(1,chl)^T mod D_chl
  Ichl  <- [Isk1]_* I'chl
  I     <- Icom · Isk1 · Ichl · γ̄ / n(Isk1)
  (found, Irsp) <- RandomEquivalentIdeal3(I)     // Alg. 18; fail prob < 2^-18
while (not found)                                // <- FS with ABORTS
Mᾱ  such that ε(ᾱrsp)(P0,Q0) = (P0,Q0)·Mᾱ
drsp <- n(Irsp);  nrsp <- v2(drsp);  qrsp <- drsp / 2^nrsp
qaux <- 2^ersp − qrsp;  v <- (qaux ≡ 0 mod 3) ? 1 : 0;  e'rsp <- ersp + v
qaux <- 2^{e'rsp} − qrsp
Echl, Pchl, Qchl <- ThreeIsogenyChain(Epk, Ũpk + [chl]Ṽpk, {Ppk,Qpk})
(Prsp, Qrsp) <- ([3^{-3e2}]Pchl, [3^{-3e2}]Qchl) · Mᾱ
Eaux, Paux, Qaux <- GenerateAuxiliaryIsogeny(K0,Km,P0,Q0,Em,Pm,Qm,Ecom,qaux,e'rsp)  // Alg. 26
P̃aux,Q̃aux <- TorsionofBasis(Eaux,2,e1);  P̃chl,Q̃chl <- TorsionofBasis(Echl,2,e1)
Maux <- ChangeofBasis(P̃aux,Q̃aux,Paux,Qaux,2,e1)
Mchl <- ChangeofBasis(Prsp,Qrsp,P̃chl,Q̃chl,2,e1)
Mrsp <- Mchl · Maux mod 2^e1
return sig = (Eaux, Mrsp, chl, nrsp, v)
```

### Verify — Algorithm 28 (§4.5)
```
parse sig = (Eaux, Mrsp, chl, nrsp, v);  e'rsp <- ersp + v;  n1 <- e1 − e'rsp
(Ũpk,Ṽpk) <- TorsionofBasis(Epk, 3, e2)
Echl <- ThreeIsogenyChain(Epk, Ũpk + [chl]Ṽpk, ∅)
(P̃aux,Q̃aux) <- TorsionofBasis(Eaux,2,e1); (P̃chl,Q̃chl) <- TorsionofBasis(Echl,2,e1)
(Pchl,Qchl) <- (P̃chl,Q̃chl) · Mrsp
K3 <- generator of Echl[3] ∩ ker(φ̂chl)
if nrsp != 0:  strip the even part with TwoIsogenyChainSmall(...,nrsp) -> E'chl,K3',P'chl,Q'chl
else:          E'chl <- Echl, K3' <- K3, ...
(P'aux,Q'aux) <- [2^{nrsp+n1}](P̃aux,Q̃aux);  (P̃'chl,Q̃'chl) <- [−2^{n1}](P̃chl,Q̃chl)
E1, E2, {K3'} <- 2X2IsogenyChain( (P'aux,P'chl), (Q'aux,Q'chl), e'rsp − nrsp, {(K3',O)} )
   // the (2^{e'rsp−nrsp}, 2^{e'rsp−nrsp})-isogeny Φ: Eaux × E'chl -> E'com × F'
chl' <- HASH(pk || j(E1) || msg)
return (chl' = chl) AND (K3' != O_Ecom)      // second test = condition (a), §4.5
```
Condition (a) — ker(φ̂rsp ∘ φchl) must not contain Epk[3], equivalently
φ̂rsp(K3) ≠ O_Ecom — is what gives special soundness (§6.2).

### Hash
`HASH(pk || j(Ecom) || msg) -> Z_{D_chl}` is the only Fiat–Shamir hash
(Alg. 27 line 5, Alg. 28 line 21). The spec fixes the input ordering but does
**not** give a byte-level encoding for it, nor a domain separator, nor an XOF
name; the ICCS build substitutes `src/iccs/xof_iccs.c` (a pseudo-XOF over
`auxfunc.c`) for SHAKE. That is a spec gap, not an implementation deviation.

## Implementation vs specification

What was checked. The Makefile builds `Implementations/sqisign2d_lvlN` (four
byte-identical copies of one CMake project; level selected by
`-DSQISIGN_VARIANT=lvlN`), so all four instances share the same C sources and
differ only in `src/precomp/ref/lvlN/*`. I checked
`src/SQIsign2D-lvl3/src/sqisign.c` (key/signature encoding, `sqisign_keypair`,
`sqisign_sign`, `sqisign_open`), `src/sqisigndim2/ref/sqisigndim2x/{keygen,sign,
doublepath}.c`, and the per-level constants in
`src/precomp/ref/lvlN/include/{encoded_sizes.h,torsion_constants.h}`.

Agreements.
- Parameter sampling (6 constants, level-3): `FP_ENCODED_BYTES 64` matches
  ⌈263/8⌉ for p ≈ 2^{263}·3^{156}; `TORSION_2POWER_BYTES 33` = ⌈263/8⌉ for e1=263;
  `TORSION_3POWER_BYTES 31` = ⌈156·log2(3)/8⌉ for e2=156; `PUBLICKEY_BYTES
  (2*FP_ENCODED_BYTES)` = 128 = observed. The Makefile's per-level field files
  `fp_13178.c / fp_191118.c / fp_263156.c / fp_527324.c` encode exactly the
  (e1,e2) pairs (131,78), (191,118), (263,156), (527,324) of §5.2.
- `SIGNATURE_LEN (2*FP_ENCODED_BYTES + 4*TORSION_2POWER_BYTES +
  TORSION_3POWER_BYTES + 2)` — i.e. Eaux ‖ Mrsp(2×2 mod 2^e1) ‖ chl ‖ nrsp ‖ v —
  reproduces 150 / 218 / 293 / 593, matching §8.1 Table 1 at every level. The
  signature layout is exactly Alg. 27's return tuple.
- The FSwA abort loop of Alg. 27 lines 1–11 is present; verification performs
  both §4.5 checks (hash equality and K3' ≠ O).

**Discrepancy 1 (real deviation, all four levels) — secret-key encoding.**
`src/SQIsign2D-lvl3/src/precomp/ref/lvl3/include/encoded_sizes.h:15-16` reads:
```
//#define SECRETKEY_BYTES (10 * FP_ENCODED_BYTES + 6 * TORSION_2POWER_BYTES + 6 * TORSION_3POWER_BYTES)
#define SECRETKEY_BYTES 900
```
The **commented-out** formula is the specification's encoding: it evaluates to
518 / 768 / 1024 / 2096 for levels 1–4, i.e. exactly §8.1 Table 1. It corresponds
to the likewise commented-out `secret_key_encode()` at
`src/SQIsign2D-lvl3/src/sqisign.c:380-401` (5 fp2 elements plus 2-power and
3-power components), which is the §4.3 component list.
The **live** `secret_key_encode()` at `src/SQIsign2D-lvl3/src/sqisign.c:408-464`
writes a different structure: `public_key_to_bytes` (2·FP) ‖ norm_exp (2 B) ‖ a
quaternion ideal generator, 4 coords × FP ‖ transporter_denom (2 B) ‖
`two_to_three_transporter`, 4 coords × FP ‖ `mat_BAcan_to_BA0_two` 4 × T2 ‖
`mat_BAcan_to_BA0_three` 4 × T3. That is
`2·FP + 2 + 4·FP + 2 + 4·FP + 4·T2 + 4·T3` = 456 / 676 / 900 / 1838 — the
observed sizes. So the shipped key format is a *different* serialization from
the one specified (a quaternion generator with its denominator deliberately
dropped — see the comment "we skip encoding the denominator since it won't
change the generated ideal" at sqisign.c:428 — plus two change-of-basis matrices,
instead of the §4.3 tuple). Classification: (a) real deviation. The document was
never updated to the shipped format.

**Discrepancy 2 (real, already known) — level-3 KAT is internally inconsistent.**
`Test_Vectors/KAT_SIG_SQIsign2D-lvl3.txt` contains 12 secret-key records: ten
with `SK_Len = 676` and two with `SK_Len = 900`, while `PK_Len = 128`
(level-3) in all twelve, and `Count = 8` appears three times. 676 is the *level-2*
secret-key length. The file is therefore a partially-regenerated splice of level-2
and level-3 material, which is why the built library's level-3 KAT hashes
mismatch the manifest (see `security_findings.md`). Levels 1/2/4 KATs are
internally consistent (456 / 676 / 1838) and pass. This is a test-vector defect,
not an encoding bug in the level-3 code path — the level-3 encoder is
self-consistent at 900 bytes.

**Known, not re-derived.** The spec explicitly disclaims SUF-CMA while claiming
EUF-CMA (§6.4.3, physical PDF p. 42): a valid signature can be turned into a
second valid signature by manipulating the auxiliary isogeny, because
2-dimensional representations are not unique. The observed same-message
malleability is inside that stated boundary.

Not verified. I did not check `GenerateAuxiliaryIsogeny` (Alg. 26) or
`2X2IsogenyChain` (§7) line-by-line against the C — these are several thousand
lines of theta-coordinate arithmetic and were out of time budget. I did not run
any code. The hash instantiation (`xof_iccs.c`) was not compared against a
specified XOF because the spec names none.
