# kem-36 TRIKE — algorithm summary

TRIKE ("Triple Quasi-Cyclic Code KEM") is a code-based IND-CCA2 KEM over
`R = F2[x]/(x^r - 1)`. Security rests on Quasi-Cyclic Syndrome Decoding (QCSD)
and on a new Ratio Quasi-Cyclic Codeword Finding (RQCCF) assumption: the sparse
secret `(h0,h1,h2)` is hidden behind two *ring divisions*, which is what lets the
public key shrink to one ring element. An IND-CPA PKE is built first, then the
Fujisaki–Okamoto transform with implicit rejection gives the KEM. Decoding uses a
BIKE-style bit-flipping decoder plus a key-generation-time weak-key rejection test.

Specification: `kem-36-spec.pdf` (35 pages), section 1.4 (Algorithms 1–8),
parameters in section 1.5 (Tables 1–3).

## Parameters

| parameter | TRIKE-2 | TRIKE-5 | TRIKE-7 | TRIKE-9 | meaning |
|---|---|---|---|---|---|
| r | 15581 | 35363 | 69691 | 114043 | block length (prime, 2 primitive mod r) |
| w | 105 | 165 | 249 | 333 | total secret weight; d = w/3 odd |
| d = w/3 | 35 | 55 | 83 | 111 | per-block secret weight (`PARAM_D`) |
| t | 263 | 429 | 659 | 877 | total error weight over the 3 blocks |
| l | 256 | 256 | 512 | 512 | seed/message length in bits (`PARAM_M`) |
| c_a | 0.0026330727 | 0.0018298784 | 0.0013203507 | 0.0010658397 | affine threshold slope |
| c_b | 16.52 | 21.05 | 25.52 | 30.25 | affine threshold intercept |
| δ | 4 | 6 | 6 | 7 | threshold offset |
| I_max | 7 | 7 | 7 | 7 | BF iterations (**not in the spec**, see below) |
| claimed security | 128 | 256 | 384 | 512 | classical bits (quantum 80/128/192/256) |
| claimed DFR | 2^-128 | 2^-256 | 2^-384 | 2^-512 | spec Table 1 |

Spec size formulas (§2.2): `|sk| = 4w + 3⌈r/8⌉ + 2⌈l/8⌉`, `|pk| = ⌈r/8⌉ + ⌈l/8⌉`,
`|ct| = 2⌈r/8⌉ + ⌈l/8⌉`. Sizes (bytes), spec Table 3 vs the built reference library:

| instance | pk spec | pk impl | sk spec | sk impl | ct spec | ct impl | ss | match |
|---|---|---|---|---|---|---|---|---|
| TRIKE-2 | 1980 | 1980 | 6328 | 6328 | 3928 | 3928 | 32 | yes |
| TRIKE-5 | 4453 | 4453 | 13988 | 13988 | 8874 | 8874 | 32 | yes |
| TRIKE-7 | 8776 | 8776 | 27260 | 27260 | 17488 | 17488 | 64 | yes |
| TRIKE-9 | 14320 | 14320 | 44228 | 44228 | 28576 | 28576 | 64 | yes |

All four match exactly. (`sizeof(secret_key_t)` rounds up to a 4-byte multiple
because of the `uint32_t` index arrays; spec Table 3 already reflects this, e.g.
TRIKE-5 13987 → 13988.)

## Pseudocode

Hash functions (spec §1.4.1): `H1,H2: M → R_even`, `H3: M → R_odd`,
`H4: M × R_odd → E(t)`, `K: M×R×R → M`, `L: E(t) → M`, where
`K(w) = {(h0,h1,h2) : wt(hi) = w/3}` and `E(t) = {(e0,e1,e2) : Σ wt(ei) = t}`.

### KeyGen (Algorithm 4)
```
1: (h0,h1,h2) <-$ K(w);  sigma <-$ M;  sigma' <-$ M
2: t1,t2,r1 <- H1(sigma), H2(sigma), H3(sigma)
3: t0 <- (h0*r1 + h1) / (t1 + r1)          # ring division in R
   r2 <- (t0*t2 + h2) / (t0 + h0)
4: pk <- (sigma, r2)
   sk <- (sigma, sigma', h0, h1, h2)       # impl also caches h0, t0, r2
5: return (pk, sk)
```

### Encaps (Algorithm 5)
```
1: m <-$ M                                  # l bits
2: (e0,e1,e2) <- H4(m, r2)                  # weight t over the 3 blocks
3: t1,t2,r1 <- H1(sigma), H2(sigma), H3(sigma)
4: u <- e0 + e1*r1 + e2*r2
5: v <- e0 + e1*t1 + e2*t2
6: c <- (u, v, m + L(e0,e1,e2))
7: K <- K(m, c)
8: return (K, c)
```

### Decaps (Algorithm 6)
```
1: (u, v, c2) <- c
2: t1,t2,r1 <- H1(sigma), H2(sigma), H3(sigma)
3: t0 <- (h0*r1+h1)/(t1+r1);  r2 <- (t0*t2+h2)/(t0+h0)
4: s <- (h0 + t0)*u - t0*v                  # over F2 "-" is "+"
5: (e0',e1',e2') <- Decoder(h0,h1,h2, s)
6: m' <- c2 + L(e0',e1',e2')
7: if (e0',e1',e2') == H4(m', r2) then K <- K(m', c)
8: else                                      K <- K(sigma', c)   # implicit rejection
```

### Bit-Flipping Decoder (Algorithm 8)
```
e' <- 0;  s' <- s;  w <- wt(s)
for it = 1..I_max:
    T <- threshold(w, wt(s'), it)
    for j in {0,1,2}: for i in 0..r-1:
        if wt(Col_i(hj) * s') >= T then flip bit i of e'_j     # "*" = Schur product
    s' <- h0*e'0 + h1*e'1 + h2*e'2
return e'

threshold(w, w', it):  M <- (d+1)/2;  Tnow <- ca*w' + cb;  Tinit <- ca*w + cb
    T' <- Tinit + d            if it = 1
          (2*Tinit + M)/3 + d  if it = 2
          (Tinit + 2*M)/3 + d  if it = 3
          M + d                if it >= 4
    return max(Tnow, T')       # <-- implementation returns min, see below
```

## Implementation vs specification

Checked: `src/TRIKE-*/src/{KEM_AlgorithmInstance.c, sample.c, decoder.c, gf2x.c,
trike_params.h, trike_types.h}` for all four built instances, and
`src/*/ICCS/{drng.c,auxfunc.c}` for the RNG/hash plumbing.

**Agreements.** Every parameter in the table above was read out of
`trike_params.h` for all four instances and matches spec Tables 1–2 exactly,
including the fixed-point encodings `COA/1e10` and `COB/1e2`. Key generation
draws three independent values (`seed`, `sigma2`, `sigma`) from the official
`drng_algorithm` (`KEM_AlgorithmInstance.c:178-180`) — the secret
`(h0,h1,h2)` is derived from `seed`, *not* from the public `sigma`, so the
published `sigma` does not expose the key. The FO re-encryption check, the
implicit-rejection branch keyed on `sigma'`, the `E(t)` sampler (t distinct
positions out of `3r`, then split across the blocks — `sample.c:230-255`), and
the parity forcing that realises `R_even`/`R_odd` (`sample.c:204-213`, which also
zeroes the unused high bits of the last byte, so the encoding is canonical) all
follow the spec. `gf2x.c` multiplication is masked/branch-free and `gf2x_mod`
masks the high bits.

**(a) Real deviation — decoder threshold uses `min` where the spec says `max`.**
`decoder.c:44-48`:
```c
uint32_t fs = (uint32_t)ceil(COA_FP * unsat + COB_FP);
uint32_t mask = -(fs < t);
return (t & ~mask) | (fs & mask);     /* fs < t  ->  returns fs */
```
This returns `min(Tnow, T')`, but Algorithm 8's `threshold()` (spec p. 9, line 13)
specifies `return max(Tnow, T')`. The effect is not cosmetic: `T'` is meant to be
a *floor* that keeps the threshold at `M + δ` (≈ 22 for TRIKE-2) once the
syndrome shrinks; with `min` the floor never applies and the threshold decays
towards `c_b` (16.52 → 17). On the first iteration `unsat == wt(s)`, so the
implementation returns `ceil(Tp)` while the spec returns `ceil(Tp) + δ` — a
flat δ (4…7) difference. The spec's DFR figures in Table 1 (2^-128 … 2^-512),
which the IND-CCA2 claim depends on, were derived for the documented rule
("The decoder uses the larger of the two values as the threshold", §1.4.4), so
the shipped decoder is not the one that was analysed. The KATs pass, which only
shows the vectors were generated with this same code.

**(a) Real deviation — constant-time claims not met.** Spec §2.3 states "The
reference implementation ... is designed to be constant-time" and that the
decoder uses "fixed-point arithmetic, ensuring both predictable runtime and
resistance against timing side-channel attacks". In fact:
- `decoder.c:22-44` computes the threshold in double-precision floating point
  (`double`, `ceil()`) from secret-dependent syndrome weights. Besides the
  side-channel claim this is a cross-platform reproducibility hazard (x87 excess
  precision, FMA contraction, `-ffast-math`).
- `sample.c:22-144` `weak_key_test` is fully branchy, allocates with `calloc`
  (return value unchecked), and `sample.c:189-194` retries key generation a
  *data-dependent* number of times on the secret support.
- `KEM_AlgorithmInstance.c:131-134` `compare_vec` implements the FO
  re-encryption comparison with `memcmp`, which is early-exit and not
  constant-time, on secret-derived data.

**(a) Memory leak in decapsulation.** `KEM_AlgorithmInstance.c:306` allocates
`h0` with `aligned_alloc`, but the free list at lines 367–377 omits `free(h0)`
(every other buffer is freed). Each `kem_dec` call leaks `PADDED_R_SIZE_BYTES`
(2 KiB for TRIKE-2, 16 KiB for TRIKE-9). No `aligned_alloc`/`calloc` return value
is checked anywhere in the file; `sample.c:233` and `decoder.c:89,119` instead
return silently on allocation failure, which would leave an all-zero error vector
or an undecoded syndrome rather than signalling an error.

**(b) Spec ambiguity — weak-key rejection is undocumented.** `sample.c` rejects
keys whose secret-block distance spectra exceed `PARAM_S` / `PARAM_SS`
(46/83, 105/172, 235/405, 433/737 for TRIKE-2/5/7/9). The spec advertises weak-key
rejection (§1.1, Appendix A) but neither the two thresholds nor the spectrum
statistic appear in any parameter table, so the rule cannot be checked against
the specification.

**(b) Spec ambiguity — `I_max` is never given.** Algorithm 8 takes `I_max` as an
input and §2.3 says "fixed-iteration", but no table lists it; the implementation
hard-wires `BIT_FLIP_ITER 7` for all four instances.

**(b) Spec internal inconsistencies.** §1.4.3 prose writes `pk = (σ, σ′, r2)`
while Algorithm 4 line 4 writes `pk ← (σ, r2)`; the size formula `⌈r/8⌉ + ⌈l/8⌉`
and the implementation both agree with Algorithm 4 (publishing σ′ would destroy
implicit rejection). Algorithm 7 line 6 tests `H4(m, r2)` where `m′` is meant.
Algorithm 8 line 19 sets `s′ = h0e0′+h1e1′+h2e2′` without adding the input
syndrome; the implementation computes the residual `s′ = s + Σ hj ej′`
(`decoder.c:87`), which is the only form that decodes — the spec line is a typo.

**(c) Deliberate equivalents.** `H1,H2,H3` are instantiated as three successive
reads from one DRNG stream seeded with σ rather than three separate functions
(`sample.c:216-227`); `L` is evaluated over the zero-padded ZMM-aligned error
buffer rather than `3⌈r/8⌉` packed bytes (`KEM_AlgorithmInstance.c:262`) —
consistent between encaps and decaps, so behaviour is unaffected. Secret keys
store `h0`, `t0`, `r2` and the support lists, the time/space trade-off §2.2
describes.

**Not verified.** The DFR claims of Table 1 and the weak-key analysis of
Appendix A were not re-derived; the `min`/`max` finding above means the shipped
decoder differs from the analysed one, but quantifying the resulting DFR was out
of scope. `gf2x_inv` (used for the two ring divisions) was read only for its
structure (Itoh–Tsujii style, `INV_MAX_ITER 14`), not verified against r.
