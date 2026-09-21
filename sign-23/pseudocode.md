# sign-23 Shuttle — algorithm summary

Module-lattice signature in the Fiat–Shamir-with-aborts paradigm over `R_q = Z_q[X]/(X^n+1)`;
security reduced to MLWE (key indistinguishability, zero knowledge) and MSIS / Self-Target-MSIS
(unforgeability), §3.1. Distinguishing features: a *rejection-free* iterative rejection sampler
(IRS, after Gärtner) replacing the data-dependent abort loop, asymmetric public-key rounding
(`RoundB`), MakeHint/UseHint commitment compression, and a static rANS-coded signature.

Specification: `sign-23-spec.pdf` (109 pages), §2.3–2.7; parameters §2.7 Table 10.

**Language note.** The brief flagged this candidate as Chinese-language; it is not.
`sign-23-spec.pdf` and `Algorithm specifications/Shuttle 算法设计文档（V4）.pdf` are the same
*English* document (identical title page, 2026-06-30). Only the `中文资料/` supplements
(基本信息表, 知识产权声明, 算法文本) are Chinese. Every "spec" column and all pseudocode below is
read from the English algorithm boxes, not inferred from code.

## Parameters

Spec column = §2.7 Table 10 verbatim; implementation spot-checks are listed in the last section.

| parameter | SHUTTLE-128 | SHUTTLE-256 | SHUTTLE-512 | meaning |
|---|---|---|---|---|
| λ | 128 | 256 | 512 | design level; fixes seed/digest lengths |
| n / q | 256 / 15361 | 512 / 61441 | 1024 / 59393 | ring dimension, modulus |
| ℓ / m | 3 / 3 | 3 / 2 | 3 / 2 | components of `s1` / `s2` |
| σ1, σ2 | 0.85, 0.85 | 0.9, 1.0 | 0.9, 0.9 | Gaussian widths for `s1`, `s2` |
| r | 825 | 825 | 825 | masking-vector Gaussian rate |
| τ | 42 | 58 | 115 | Hamming weight of binary challenge `c` |
| α_h / α_b | 1024 / 2 | 1024 / 2 | 2048 / 4 | commitment / public-key compression |
| α1, α_s, α_e | 90, 10, 5 | 135, 5, 5 | 144, 3, 3 | CompressY / StretchS divisors |
| d_s, d_e | 5, 5 | 5, 5 | 5, 5 | packed coeff widths of `s1`, `s'2` |
| B_s^enc, B_e^enc | 9, 10 | 10, 12 | 10, 12 | encoding offsets |
| B_k / B_k' | 295.06 / 290 | 296.19 / 290 | 292.76 / 290 | KeyGen norm window |
| B_v | 7356.68 | 10385.53 | 25194.90 | verification ℓ2 bound |
| N, B_bdry | 29, 15 | 29, 15 | 29, 15 | IRS series truncation, boundary pairs |
| κ_a, κ_b | 80, 57 | 80, 57 | 80, 57 | SamplerU exponent / mantissa bits |
| claimed security | 128 | 256 | 512 | bits; MLWE 138.0/279.7/625.0 classical Core-SVP |

Sizes (bytes), specification (Table 10 / Table 8) vs the built reference library (OBSERVED):

| instance | pk spec | pk impl | sk spec | sk impl | sig spec | sig impl | match |
|---|---|---|---|---|---|---|---|
| SHUTTLE-128 | 1264 | 1264 | 2288 | 2288 | 1183 | 1183 | yes |
| SHUTTLE-256 | 1952 | 1952 | 3680 | 3680 | 2417 | 2417 | yes |
| SHUTTLE-512 | 3648 | 3648 | 7104 | 7104 | 5001 | 5001 | yes |

## Pseudocode

### KeyGen — spec Algorithm 1 (§2.4.1)
```
KeyGen(xi in B_lambda):
  kappa <- 0
  repeat:
    kappa <- kappa + 1
    (seedA, seedsk, K) <- ExpandSeeds(xi || I2B(m,2) || I2B(kappa,4), 5*lambda/8)
        # |seedA| = lambda/8 bytes, |seedsk| = |K| = lambda/4 bytes
    (a_gen, Ahat_gen) <- ExpandA(seedA)            # Ahat_gen in NTT domain
    (s1, s2)          <- ExpandS(seedsk)           # discrete Gaussians sigma1 / sigma2
    b0  <- a_gen + NTT^-1(Ahat_gen o NTT(s1)) + s2          (mod q)
    b   <- RoundB(b0, alpha_b)        # Alg 14: zero the centered low part mod alpha_b
    s2' <- s2 + ((b - b0) mod^± q)    # absorb the rounding error into the error vector
  until  B_k' <= ||StretchS(1, s1, s2')||_2 <= B_k          # Alg 1, lines 12-14
  pk <- pkEncode(seedA, b)            # Alg 10: seedA || PolyToBytes(b/alpha_b, d_b) x m
  tr <- H_pk(pk)                      # XOF tag 0x05, lambda/4 bytes
  sk <- skEncode(seedA, b, K, tr, s1, s2')                  # Alg 12
  return (pk, sk)
```
Derived public matrix used by Sign/Verify: `A = [ 2(a_gen - b) + q·j | 2A_gen | 2I_m ]`, giving
`A·[1,s1,s2']^T ≡ q·j (mod 2q)`; Lemma 1 gives `LSB(A·u) = LSB(u_0)·j`.

### Sign — spec Algorithm 2 (§2.4.2)
```
Sign(sk, M, rnd):
  (seedA, b, K, tr, s1, s2') <- skDecode(sk);   s <- [1, s1, s2']^T
  (a_gen, Ahat_gen) <- ExpandA(seedA)
  Ahat <- [ NTT(2(a_gen-b) + q*j) | 2*Ahat_gen | 2*Ihat_m ]
  mu <- H_msg(tr || M);   kappa <- 0              # tag 0x06
  loop:
    seedy <- ExpandSigningSeeds(K || rnd || mu || I2B(kappa,4), lambda/8);  kappa++
    y  <- SampleY(seedy)                          # Alg 17, tag 0x08, wide Gaussian rate r
    y' <- CompressY(y)                            # Alg 18: round(x_i / alpha_i)
    w  <- NTT^-1(Ahat . NTT(y')) mod q
    w  <- LiftToModTwoQ(w, LSB(y'_0)*j)           # lift to [0,2q) via Lemma 1
    w0 <- LSB(w);   w_h <- round(w / alpha_h) mod H_h
    seedc <- H_ch(EncodeCom(w_h, w0) || mu)       # tag 0x04, 2*lambda bits, sent verbatim
    c     <- SampleC(seedc)                       # Alg 24: tau entries = +1, rest 0
    s~    <- StretchS(s)                          # Alg 19: exact integer scaling by alpha_i
    ctx_R <- XOF.Init(0x09 || seedy)
    (ctx_R, z~) <- RejectSample(ctx_R, y, c, s~)  # Alg 23
    z <- CompressY(z~);   (z1, z2) <- z           # z1 = first ell+1 polys, z2 = next m
    h   <- MakeHint(z2, w)                        # Alg 20
    w0' <- LSB(z_0 - c)*j                         # z_0 = first poly of z1; verifier's formula
    w~  <- w - 2*z2 mod 2q
    w_app <- alpha_h*( h + round(w~/alpha_h) mod H_h ) + w0'
    z2'   <- (w_app - w~)/2 mod^± q               # reconstructed exactly as UseHint does
    if ||(z1, z2')||_2 > B_v: continue
    sigma <- sigEncode(seedc, z1, h)              # Alg 32, static rANS (§2.5.10)
    if sigma != FAIL: return sigma
```
IRS core, Algorithms 22–23 (§2.5.6): `RejectSample` walks `j = 0..n-1` in fixed ascending order
and, for every `c_j = 1`, applies one transition `R(ctx, z, s~·X^j, V)` with `V = <s~,s~>`.
`R` draws `ℓ ≈ log2 U` via `SamplerU(ctx, κ_a, κ_b)`, sets `u = 2r²ln2·ℓ` and `t = <y,v>`
(sign-normalised so `t>0`), and sets `flg = +1` iff some `i ∈ [0, ceil(N/2))` satisfies
`-2(2i+1)t - (2i+1)²V < u <= -4i·t - 4i²V`; it returns `y + flg·v`. There is no abort branch:
control flow is data-independent, the scheme's headline claim (§4.4.1).

### Verify — spec Algorithm 3 (§2.4.3)
```
Verify(pk, M, sigma):
  (seedA, b) <- pkDecode(pk);  tr <- H_pk(pk);  mu <- H_msg(tr || M)
  (seedc, z1, h) <- sigDecode(sigma)            # reject if any field is out of range
  c <- SampleC(seedc);   (a_gen, Ahat_gen) <- ExpandA(seedA)
  w0'    <- LSB(z_0 - c)*j                      # z_0 = first poly of z1
  Ahat_1 <- [ NTT(2(a_gen - b) + q*j) | 2*Ahat_gen ]
  (w_h, z2') <- UseHint(h, z1, w0', Ahat_1, c)  # Alg 21
  seedc' <- H_ch(EncodeCom(w_h, w0') || mu)
  accept iff seedc' = seedc  and  ||(z1, z2')||_2 <= B_v
```
`UseHint` (Alg 21): `w~ <- LiftToModTwoQ(NTT^-1(Ahat_1·NTT(z1)) - q·c·j, w0')`;
`w_h <- h + round(w~/alpha_h) mod H_h`; `z2' <- (alpha_h·w_h + w0' - w~)/2 mod^± q`.

### Hashing
One XOF with disjoint one-byte domain tags (§2.3.2–2.3.3): `0x00 ExpandSeeds,
0x01 ExpandSigningSeeds, 0x02 ExpandA, 0x03 ExpandS, 0x04 H_ch, 0x05 H_pk, 0x06 H_msg,
0x07 SampleC, 0x08 SampleY, 0x09 IRS`. All three digests are `H_x(S) := XOF(tag || S, λ/4)`,
i.e. 2λ bits. Two instantiations: SHA-3 mode (SHAKE128 for tag 0x02, SHAKE256 elsewhere) and
the default NGCC mode, an SM3 Hash-DRBG in which both strength classes collapse to one
primitive and each `XOF.Squeeze` is one DRBG generate, so the fixed squeeze-block sizes
(392 B per ExpandS mini-batch, etc.) become part of the byte schedule.

## Implementation vs specification

Built sources (`sign-23/Makefile`): `Reference_Implementation/SHUTTLE-{128,256,512}`, scheme
sources plus `ntt/<qset>/ntt_ref.c`. Source read only — no build or binary was run here.

- **Step map.** `sign.c:222 keygen_from_xi` = Alg 1 (norm window at the `stretch_s` call,
  `sign.c:294`); `sign.c:362 sign_internal` = Alg 2 line for line, including the deliberate
  "reconstruct z2' the verifier's way" via `use_hint` (`sign.c:575`) rather than an independent
  `+2·z2` formula, with a comment explaining why; `sign.c:640 crypto_sign_verify` = Alg 3,
  re-checking `BV_SQ` at `sign.c:774`. Alg 22/23 → `irs.c` (`reject_sample`, `sign.c:526`);
  Alg 17 → `sampler.c`; Alg 10–13 → `packing.c`; Alg 32/33 → `rans.c`.
- **Parameter spot-check (sampled 6+ of Table 10, mode 128 unless noted); all agree.**
  `params.h` carries each primary constant with an explicit `tab:suf-parameters` provenance
  comment: `N 256` / `Q 15361`, `TAU 42` (`115` for mode 512), `ALPHA_H 1024` (`2048` for 512),
  `ALPHA_B 2` (`4` for 512), `(ALPHA_1, ALPHA_S, ALPHA_E) = (90,10,5)`, `RY 825`,
  `IRS_N 29`/`IRS_BDRY 15`, `KAPPA_A 80`/`KAPPA_B 57`. σ1,σ2 are RCDT table selectors, not
  `#define`s: `sampler.h:142-158` maps (0.85,0.85)/(0.90,1.00)/(0.90,0.90) for 128/256/512,
  exactly Table 10.
- **Norm bounds (c: equivalent encoding).** Real-valued `B_k`, `B_k'`, `B_v` appear as exact
  integer squares `BK_SQ 87060`, `BK_LOW_SQ 84100`, `BV_SQ 54120740` (`@@AUTOGEN:bounds@@`),
  a compare-of-squares with no `sqrt`. 84100 = 290²; 295.06² = 87060.4, so the upper gate is
  the floor of the square — conservative, not a deviation.
- **Sizes agree end to end, no mismatch.** `CRYPTO_PUBLICKEYBYTES = SEEDBYTES + m·416 = 1264`
  and `CRYPTO_SECRETKEYBYTES = 16+32+32+480+480+1248 = 2288` reproduce the Alg 10/12 layouts;
  `CRYPTO_BYTES` is pinned to 1183/2417/5001, matching Table 8's `|σ|` column and OBSERVED.
- **Domain tags agree.** `xof.h:45-52` lists exactly the 0x00–0x09 assignment of §2.3.2 and
  notes that IRS (0x09) opens a *fresh* context on `0x09 || seed_y` instead of continuing
  SampleY's (0x08) — which is what Alg 2 line 21 specifies.
- **Documented spec drift (not deviations).** `params.h:88-90`: τ for mode 512 moved 114 → 115
  in the 2026-06-25 update so `binom(1024,τ) ≥ 2^512`; shipped Table 10 already says 115.
  `params.h:346-352`: the older signature targets 1005/2155/4552 lay below the source-law
  entropy (Shannon floor ≈ 1115/2316/4866 B) and were replaced in the spec by 1183/2417/5001.
  Both are self-consistent in the version reviewed.
- **Not verified (time box).** The rANS frequency-table construction (§2.5.10, Alg 27–33) vs
  `rans.c`; the ApproxLog/ApproxExp coefficients (§2.5.8, Table 1, `(g,d,Q) = (2,13,62)`) vs
  `approx_*_poly.h`; the NTT twiddle tables vs Alg 4/5 — only the derived scalars
  `ZETA`/`NINV`/`HH`/`DH_BITS` were read. KAT status (PASS ×3) is taken from RESULTS.md.
