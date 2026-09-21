# sign-27 SQIsignTriangle — algorithm summary

Isogeny-based signature on supersingular curves over Fp², p = c·2^f − 1. A
Σ-protocol made non-interactive by Fiat–Shamir, in which the response isogeny
φrsp is never computed in dimension 1: it is represented by a 2-dimensional
(2^ersp)-isogeny Φ : Epk × Eaux → E1 × E2 via Kani's lemma, and the verifier
recovers the commitment curve Ecom as a component of the split codomain. The
"triangle" is the (E0, Epk, Ecom) diagram of Figure 4 (§4.1). Hardness: the
supersingular endomorphism-ring / Deuring problem; security is argued in the
hint-assisted weak-HVZK + FSwA framework (§6).

Specification: `sign-27-spec.pdf` (63 pages), §4 (Algorithms 4.1–4.3),
§7.2 (parameter sets, Table 8), §7.3 (sizes, Table 9).

## Parameters

| parameter | lvl1 | lvl2 | lvl5 | lvl6 | meaning |
|---|---|---|---|---|---|
| λ | 128 | 160 | 256 | 512 | security level (Table 8) |
| p | 5·2^248 − 1 | 9·2^309 − 1 | 27·2^500 − 1 | 113·2^1016 − 1 | base-field prime, p = c·2^f − 1 |
| f | 248 | 309 | 500 | 1016 | 2-adic valuation of p+1; full 2^f-torsion |
| ⌈log2 p⌉ | 251 | 313 | 505 | 1023 | |
| Fp bytes | 32 | 40 | 64 | 128 | |
| Dmix | prime, ≈ 2^{4λ} | ← | ← | ← | secret-ideal norm (§4.1) |
| challenge bytes | 8 | 10 | 16 | 32 | λ/2 bits per candidate (§7.2) |
| aux. basis coeff / q bytes | 28 | 35 | 56 | 112 | Table 9 |
| claimed security | 128 | 160 | 256 | 512 | bits (spec's own claim) |

Build labels lvl1/lvl2/lvl5/lvl6 map to λ = 128/160/256/512 respectively
(confirmed via `SQISIGNTRIANGLE_Q_BYTES` = 28/35/56/112 matching Table 9).

Sizes (bytes), specification (§7.3 Table 9) vs the built reference library:

| instance | pk spec | pk impl | sk spec | sk impl | sig spec | sig impl | match |
|---|---|---|---|---|---|---|---|
| SQIsignTriangle_lvl1 (λ=128) | 65 | 65 | 353 | 353 | 204 | 204 | yes |
| SQIsignTriangle_lvl2 (λ=160) | 81 | 81 | 437 | 437 | 255 | 255 | yes |
| SQIsignTriangle_lvl5 (λ=256) | 129 | 129 | 701 | 701 | 408 | 408 | yes |
| SQIsignTriangle_lvl6 (λ=512) | 257 | 257 | 1409 | 1409 | 816 | 816 | yes |

All twelve numbers agree. pk = ⌈2·Fp bytes⌉ + 1 hint byte; sig = A_Eaux (2·Fp)
+ 4 basis coefficients + q.

## Pseudocode

### KeyGen — Algorithm 4.1 (§4.2)
```
loop:
  Isk <- RandomIdealGivenNorm(Dmix, True)         // random left O0-ideal, prime norm Dmix
  repeat:
     Isk <- RandomEquivalentPrimeIdeal(Isk)       // shrink the norm; may fail
  until Isk != False
  (Epk, φsk(P0), φsk(Q0)) <- IdealToIsogeny(Isk)  // Qlapoti, §2.4.2
  (Ppk, Qpk, hint_pk) <- TorsionBasisToHint(Epk, 2^f)   // deterministic basis + hint
  Msk <- ChangeOfBasis(Epk, (φsk(P0), φsk(Q0)), (Ppk, Qpk))
         //  Msk · (φsk(P0), φsk(Q0))^T = (Ppk, Qpk)^T
  sk <- (Isk, Msk)                 // plus the torsion-point data, per §4.2 prose
  pk <- (Epk, hint_pk)
  return (sk, pk)
```

### Sign — Algorithm 4.2 (§4.3)
```
parse sk = (Isk, Msk);  parse pk = (Epk, hint_pk, Ppk, Qpk)
// commitment (described in §4.3 prose; the numbered box omits these lines):
Icom <- RandomIdealGivenNorm(Dmix, True);  Icom <- RandomEquivalentPrimeIdeal(Icom)
(Ecom, φcom(P0), φcom(Q0)) <- IdealToIsogeny(Icom)
// challenge:
(c1, c2) <- hash(Epk || msg || Ecom)            // c1 prime, c1 ≡ 3 mod 4; |ci| = λ/2 bits
// response:
I_rsp^(1) <- Isk · Icom
I_rsp     <- EquivalentSpecialIdeal(I_rsp^(1), c1, c2)   // norm q with q ≡ c2 (mod c1)
q     <- n(I_rsp)
ersp  <- ceil(log2 q)
I_aux^(1) <- RandomIdealGivenNorm(2^ersp − q, False)      // Kani complement
I_aux <- (Isk · I_rsp) ∩ I_aux^(1)
(Eaux, P'aux, Q'aux) <- IdealToIsogeny(I_aux)
(Paux, Qaux) <- Msk · (P'aux, Q'aux)
return σ <- (Eaux, Paux, Qaux, q)
```

### Verify — Algorithm 4.3 (§4.4)
```
parse pk = (Epk, hint_pk);  parse σ = (Eaux, Paux, Qaux, q)
check Epk supersingular, else return False
check Eaux supersingular, else return False        // box says "Esig", undefined; see below
(Ppk, Qpk) <- TorsionBasisFromHint(Epk, 2^f, hint_pk)
ersp <- ceil(log2 q);   cff <- 2^{f − ersp}
(Ppk, Qpk) <- [cff](Ppk, Qpk);   (Paux, Qaux) <- [cff](Paux, Qaux)
(F1 × F2, _) <- Isogeny22Chain( ([q]Ppk, Paux), ([q]Qpk, Qaux) )
       // the 2^ersp-isogeny Φ : Epk × Eaux -> F1 × F2 of Kani's lemma
(c1, c2) <- hash(Epk || msg || Ecom)   where Ecom is the recovered F1 (or F2)
check q ≡ c2 (mod c1), else return False
return (F1 = Ecom) or (F2 = Ecom)
```

### Hash / challenge derivation (§7.2)
```
hash_to_challenge_prime_with_pk_j(j(Epk), j(Ecom), msg):
  absorb enc(j(Epk)) || enc(j(Ecom)) || msg into incremental SHAKE256
  squeeze one block, split into two λ/2-bit candidates
  c1 <- the first candidate that is ≡ 3 (mod 4) and passes 40 Miller-Rabin rounds
  c2 <- the other half of the same SHAKE256 block
```
Note: the built library does **not** use Keccak. Per the Makefile, the bundled
`common/generic/fips202.c` is replaced by the candidate's SM3/pseudo-XOF adapter
over `auxfunc.c`, so "SHAKE256" in §7.2 is not what is compiled here. That is an
ICCS-harness substitution, not a defect of the submission's own code.

## Implementation vs specification

What was checked. The Makefile builds
`Implementations/Reference_Implementation/SQIsignTriangle_lvlN/sqisigntriangle/src`
with `SVARIANT_S=lvlN`. I read `verification/ref/lvlx/verify.c` (the whole of
`new_protocols_verify`), `verification/ref/lvlx/encode_verification.c` (the
key/signature codecs), `sqisign.c` (the API layer), and the per-level
`precomp/ref/lvlN/include/encoded_sizes.h`.

Agreements.
- `new_protocols_verify` implements Alg. 4.3 faithfully, including the two
  supersingularity/curve-validity checks (`ec_curve_verify_A`,
  `ec_curve_init_from_A`), the `[cff]` cofactor scaling, the
  `theta_chain_compute_and_eval_verify` (2^ersp,2^ersp)-chain, and the
  `q ≡ c2 (mod c1)` congruence.
- It is in fact *stricter* than the spec box: it also rejects q ≤ 0, even q,
  and ersp outside [3, TORSION_EVEN_POWER], and it tests the exact order of
  both 2^ersp-bases (`test_basis_order_twof`) before building the kernel —
  checks the spec does not mention.
- Parameter sampling (5 constants, per level): `SQISIGNTRIANGLE_Q_BYTES` and
  `SQISIGNTRIANGLE_BASIS_COEFF_BYTES` = 28/35/56/112 match Table 9's "Aux.
  basis coeff." and "q bytes" columns; `PUBLICKEY_BYTES` 65/81/129/257 =
  2·(Fp bytes) + 1 hint byte for Fp bytes 32/40/64/128 of Table 8;
  `NEW_SIGNATURE_BYTES` 204/255/408/816 = 2·Fp + 4·coeff + q_bytes.
  `SECRETKEY_BYTES` 353/437/701/1409 matches Table 9 exactly.

**Discrepancy 1 (real deviation, all four levels; already known) — the verifier
aborts on a malformed signature instead of rejecting it.**
`new_signature_from_bytes()` is called *before* `new_protocols_verify()`
(`.../sqisigntriangle/src/sqisign.c:76` and `:108`), and its helper
`compressed_aux_basis_from_bytes()` computes `e_rsp = ibz_bitsize(q)` from the
attacker-supplied q and then executes
`.../verification/ref/lvlx/encode_verification.c:216`:
```
assert(e_rsp >= 3 && e_rsp <= TORSION_EVEN_POWER);
```
For an all-zero signature q = 0, so e_rsp = 0 and the assertion fires, aborting
the process with SIGABRT (exit −6) — reproduced on lvl1/lvl2/lvl5/lvl6 in
`security_findings.md`. The same function has three further unguarded
`assert(ok)` on `ec_biscalar_mul` (:226, :228, :235) and `assert(valid_curve)`
(:220). `sign-27/Makefile` line 63 does **not** define `NDEBUG`, so these
assertions are live in the built library; with `-DNDEBUG` they would instead
silently fall through into `ec_dbl_iter_basis` with `TORSION_EVEN_POWER - 0`,
which is not obviously safe either.
The specification gives no explicit decoding/validation contract: Alg. 4.3 lines
3–4 mandate only the two supersingularity checks and line 7 the congruence, and
§7.3 describes the serialization purely as an encoder ("serializes the auxiliary
basis by four scalar coefficients and serializes q in the same short length").
Nothing in §4.4 or §7.3 states what the verifier must do on an out-of-range q.
Classification: (a) a real implementation defect (the correct rejection logic
exists in `verify.c:19-24` but is unreachable because the decoder aborts first),
compounded by (b) a spec gap — no canonical-decoding requirement is stated.

**Discrepancy 2 (spec defect, presentational) — Algorithm 4.3 is circular as
written.** Line 6 computes `c1, c2 <- hash(Epk || msg || Ecom)` but Ecom is not
part of σ and is only produced at line 12 as F1 or F2; likewise line 7 checks
the congruence before Ecom exists. §7.2 states the intended order ("verification
recomputes the same challenge from the recovered commitment curve and checks
this congruence"), and `verify.c:65-75` implements that order — it runs the
2-dimensional chain first, then hashes against `codomain.E1`, and if the
congruence fails retries against `codomain.E2`. Classification: (b) spec
presentation error; the implementation is the correct reading.

**Discrepancy 3 (spec defect, minor).** Alg. 4.3 line 4 checks that "Esig" is
supersingular; no Esig is defined anywhere in the spec. From the code this is
Eaux. Alg. 4.2's numbered box likewise omits the commitment lines (Icom, φcom,
Ecom) that its own §4.3 prose specifies, so `Ecom` in line 3 is undefined in the
box. Alg. 4.2 also has a duplicated `return` (lines 12 and 13). Classification:
(b) spec sloppiness, no implementation impact.

**Discrepancy 4 (minor, sk contents).** §4.2 concludes "the secret key
sk = (Isk, Msk)" but the same paragraph states that (φsk(P0), φsk(Q0)) "is
stored in the secret key sk". The 353-byte encoding necessarily holds more than
an ideal and a matrix. Classification: (b) spec ambiguity; the size column
nonetheless matches, so the shipped encoding is the one Table 9 was measured
from.

Not verified. I did not check `EquivalentSpecialIdeal`, `Qlapoti`, or the theta
(2,2)-chain arithmetic against the spec — these are several thousand lines and
out of the time budget. I did not run any code; the crash above is quoted from
`security_findings.md` and confirmed by reading the assertion site. The
`ec_dlog_2_tate`-based basis compression of §7.3 was read but not
cross-validated for injectivity, so canonical-encoding/SUF questions stay open.
