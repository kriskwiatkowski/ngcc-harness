# kem-05 BIKE_MLThre — algorithm summary

Code-based KEM: quasi-cyclic moderate-density parity-check (QC-MDPC) codes over
R = F_2[X]/(X^r - 1), hardness = QC syndrome decoding / QC codeword finding. The KEM
envelope is stock BIKE (FO-style transform with implicit rejection via a secret
fallback σ). The submission's only novelty is inside decapsulation: the BGF
bit-flipping decoder's per-iteration threshold is a *reference affine threshold plus a
learned residual correction* produced by a small neural net (hence "MLThre").

Specification: `kem-05-spec.pdf` (37 pages, English, produced by python-docx — the
maths is rendered as plain text and several formulae lost their braces/parentheses).
§1.2 parameters, §1.3 KEM algorithms, §1.4 learning-assisted decoder, §1.5 offline
training, §4.3 Table 9 sizes.

## Parameters

| parameter | BIKE_MLThre_128 | BIKE_MLThre_256 | BIKE_MLThre_512 | meaning |
|---|---|---|---|---|
| r | 12,323 | 40,973 | 150,001 | QC block length, R = F_2[X]/(X^r-1) |
| w | 142 | 274 | 546 | secret parity weight, \|h_0\|=\|h_1\|=w/2 |
| d_v = w/2 | 71 | 137 | 273 | column weight per block |
| t | 134 | 264 | 524 | error weight, \|e_0\|+\|e_1\| = t |
| ℓ (shared secret) | 256 bits | 256 bits | 512 bits | KDF output |
| μ (seed) | 256 bits | 256 bits | 512 bits | m and c_1 length (implied by \|c\|=r+μ) |
| NbIter | — (spec: "prescribed number") | — | — | spec gives no number; impl: 5 |
| τ (grey margin) | — (not in spec) | — | — | impl: 3 |
| target DFR | 2^-128 | 2^-256 | 2^-512 | spec Table 1 |
| claimed security | 128 | 256 | 512 | bits (spec's own claim) |

Sizes (bytes), specification vs the built reference library:

| instance | pk spec | pk impl | sk spec | sk impl | ct spec | ct impl | ss spec | ss impl | match |
|---|---|---|---|---|---|---|---|---|---|
| BIKE_MLThre_128 | 1541 (12,323 b) | 1541 | **280.5** (2,244 b) | 3114 | 1573 (12,579 b) | 1573 | 32 | 32 | pk/ct/ss yes, **sk no** |
| BIKE_MLThre_256 | 5122 (40,973 b) | 5122 | **580** (4,640 b) | 10276 | 5154 (41,229 b) | 5154 | 32 | 32 | pk/ct/ss yes, **sk no** |
| BIKE_MLThre_512 | 18751 (150,001 b) | 18751 | **1292.5** (10,340 b) | 37566 | 18815 (150,513 b) | 18815 | 64 | 64 | pk/ct/ss yes, **sk no** |

Spec Table 9 quotes the secret key in the *compact sparse* representation
(2·(w/2)·⌈log2 r⌉ + μ bits: 2·71·14 + 256 = 2244 for level 128, exactly). The
implementation stores h_0, h_1 as **dense** r-bit polynomials: 2·⌈r/8⌉ + μ/8 bytes =
3114 / 10276 / 37566, which reproduces OBSERVED exactly. This is a representation
choice, not a protocol change, but the spec's storage table does not describe the
shipped key format.

## Pseudocode

### KeyGen (spec §1.3, "Key Generation")

```
KeyGen_λ():
  1. (h0, h1) <-$ H_w   = {(h0,h1) in R^2 : |h0| = |h1| = w/2}
  2. if h0 not invertible in R_r: resample (h0, h1)
  3. h := h1 * h0^{-1}  in R_r
  4. sigma <-$ {0,1}^mu                       # secret implicit-rejection fallback
  5. return sk = (h0, h1, sigma),  pk = h
```

### Encaps (spec §1.3, "Encapsulation")

```
Encaps_λ(pk = h):
  1. m  <-$ {0,1}^mu
  2. (e0, e1) := H_err(m)                     # constant-weight sampler, |e0|+|e1| = t
  3. c0 := e0 + e1 * h   in R_r
  4. c1 := m XOR L(e0, e1)                    # L : E_t -> {0,1}^mu
  5. K  := KDF(m, c0, c1)   in {0,1}^ell
  6. return c = (c0, c1), K
```

### Decaps (spec §1.3, "Decapsulation")

```
Decaps_λ(sk = (h0,h1,sigma), c = (c0,c1)):
  1. s  := c0 * h0   in R_r                   # decoding syndrome
  2. e' := BIKE_MLThre.Decoder_theta(s, h0, h1, lambda)
     if decoding fails: e' := (0, 0)
  3. m' := c1 XOR L(e')
  4. e* := H_err(m')
  5. b  := 1 if e' = e*  else 0
  6. K  := KDF(m', c0, c1)   if b = 1
           KDF(sigma, c0, c1) if b = 0        # implicit rejection
     "shall be implemented without secret-dependent timing or branching"
  7. return K in {0,1}^ell
```

### The novel part: the adaptive threshold decoder (spec §1.4)

```
BIKE_MLThre.Decoder_theta(s, h0, h1, lambda):
  1. e := 0;  s_1 := s;  i := 1;  S_init := wt(s)
  2. repeat for the prescribed number of iterations:
     a. compute all UPC counters ctr_j from s_i and the sparse parity structure
     b. S_i := wt(s_i)
     c. x_i := (level, i, S_init, S_prev,i, S_i, dS_i, z0_i, z1_i, T_var,i, T_lb, T_base,i)
            dS_i := max(S_prev,i - S_i, 0)
            z1_i := |supp(s_i) INTERSECT supp(s_{i-1})|      # persistent unsatisfied checks
            z0_i := |supp(s_i) \ supp(s_{i-1})|              # newly unsatisfied checks
     d. z_i := f_theta(x_i)                   # trained residual threshold selector
     e. dT_i := D_sec[ argmax_k z_{i,k} ]     # residual correction from the action set
     f. T_i := clip(T_base,i + dT_i, T_min, T_max)
     g. apply the BGF flipping rule with threshold T_i; update e and s_i
  3. e' := e;  return e' if wt(s_final) = 0, else the failure symbol ⊥
```

**Threshold rule, exactly as the spec states it.** The *reference* (baseline) threshold
is affine in the syndrome weight S, spec Table 2:

```
  T(S) = max( 0.0069722 * S + 13.530  , 36 )    # BIKE_MLThre-128
  T(S) = max( 0.0052650 * S + 15.2588 , 52 )    # BIKE_MLThre-256
  T(S) = max( 0.0001734 * S + 136.5610, 138 )   # BIKE_MLThre-512
```

The effective threshold is `T_i = clip(T_base,i + ΔT_i, T_min, T_max)` with ΔT_i drawn
from the per-category action set of Table 4:
`D_128 = {-7..0}` (8), `D_256 = {-10..0}` (11), `D_512 = {-2,-1,0,1,2}` (5).
Spec §1.4 prescribes f_theta as "a small **quantized** multilayer perceptron with 11
input features, **one hidden layer of width 16**, and |D_sec| output classes", to "be
implemented using **fixed-size integer arithmetic** and a fixed execution schedule",
with an *optional* confidence gate forcing ΔT_i = 0 below τ_conf. T_min, T_max, τ_conf,
the quantization format and the normalization constants are declared part of the
algorithm instance but are **never given numerically anywhere in the spec**.

Difference from stock BIKE: stock BIKE (round 3) uses the affine threshold alone with
no learned term; the residual ΔT_i, the 11-feature state vector and the action sets are
what BIKE_MLThre adds.

## Implementation vs specification

Checked: `Implementations/reference/` as wired by `kem-05/Makefile`
(`-DBIKE_SECURITY_{128,256,512} -DBIKE_MLTHRE_ENABLED=1 -DNIST_RAND=1`). `kem.c` =
KeyGen/Encaps/Decaps; `decode_ml.c:270-378` = the decoder loop; `mlthre_policy.c` =
T_base and ΔT selection; `mlthre_model.c` = f_theta; `threshold.c` =
`compute_threshold`; `defs.h:82-190` = parameters; `sampling.c` = H_err;
`hash_wrapper.c` = functionH/functionL/functionK.

Agreements:
- Parameter constants sampled from `defs.h` agree with spec Table 1 for all three
  levels: `R_BITS` 12323/40973/150001, `DV` (= w/2) 71/137/273, `T1` (= t)
  134/264/524, and `ELL_BITS` 256/256/512 (`defs.h:44-51`) matching ℓ. (6 constants
  per instance sampled; the r=24659 block was also inspected, see Discrepancy 1.)
- pk, ct and ss byte counts match OBSERVED exactly.
- `crypto_kem_dec` (`kem.c:212-298`) implements Decaps steps 1-6 in order, and the
  **implicit-rejection branch is live and correct**: `safe_cmp` (`utilities.h:31-43`,
  an accumulate-then-compare over the full N_SIZE) sets `failed`, and only *after*
  that is `l_ss->raw` written, from σ (`kem.c:283`) or from m' (`kem.c:289`). Unlike
  kem-01, the fallback key genuinely reaches the output.
- The decoder loop structure (UPC counters, black/grey sets, τ-margin grey threshold
  `T - tau`, the extra two masked iterations on iteration 1) matches BGF as described.
- The feature vector assembled in `mlthre_select_delta` is the spec's 11-tuple in the
  spec's order.

### Discrepancy 1 — the spec's Table 2 threshold functions are not what the library computes (real deviation)

With `BIKE_MLTHRE_ENABLED=1` (the build setting), `decode_ml.c:321` takes the base
threshold from `mlthre_compute_base_threshold`, **not** from `VAR_TH_FCT`. The
`VAR_TH_FCT` macros in `defs.h` — which are the only place spec Table 2's coefficients
appear — are reachable only on the dead `#else` branch at `decode_ml.c:325`. The
coefficients actually used are in `mlthre_policy.c:27-46`:

| level | spec Table 2 | implemented (`mlthre_var_threshold`) |
|---|---|---|
| 128 | max(0.0069722·S + 13.530, 36) | 0.006254868353074983·S + 11.101432337243956 |
| 256 | max(0.0052650·S + 15.2588, 52) | 0.0036083738659016262·S + 15.430866686308178 |
| 512 | max(0.0001734·S + 136.5610, 138) | **not affine at all** — see Discrepancy 2 |

In addition the implementation imposes a per-iteration *lower bound*
(`mlthre_lower_bound`, `mlthre_policy.c:48-105`: `t0 + c`, `t0 + c - x`, `t0 + c - 2x`
for iterations 1/2/3 then `(d_v+1)/2 + c`, with c = 3/5/6 by level and
x = (t0 - (d_v+1)/2)/3) which the specification does not mention anywhere.

Separately, spec Table 2's **256-bit row** (`0.005265·S + 15.2588`, floor 52) is in fact
the coefficient pair `defs.h:168` attaches to the `BIKE_SECURITY_192` block
(r = 24,659, d_v = 103, t = 199) — a block the source itself labels "Legacy middle
parameter set". The built 256-bit instance is r = 40,973 and its `VAR_TH_FCT` is
`max(17.8785 + 0.00402312·S, 69)` (`defs.h:153`). So the spec's 256-bit threshold row
belongs to a different parameter set than the spec's own 256-bit Table 1 row.

### Discrepancy 2 — the 512-bit instance has no specified threshold and no ML correction (real deviation)

- `BIKE_512_TH_A`, `TH_B`, `TH_MIN` all default to `0.0`/`0` (`defs.h:103-123`), so
  `VAR_TH_FCT` for the 512 build is identically `max(0, 0)` = 0. Spec Table 2's
  512-bit affine function is simply absent from the source.
- Instead, for `model_security_level == 7` (the 512 build), `mlthre_compute_base_threshold`
  falls through to `mlthre_dynamic_threshold` (`mlthre_policy.c:21-25`), which calls
  `compute_threshold()` in `threshold.c` — BIKE's *older probabilistic* threshold
  (binomial PMF over UPC counters, `lgamma`/`exp`). That rule is not in the spec at all.
- `mlthre_select_delta` (`mlthre_policy.c:136-143`) returns 0 unconditionally for level 7
  unless `BIKE_MLTHRE_512_MODEL_ENABLED` is set; it defaults to 0 (`defs.h:69-71`) and
  the Makefile does not set it. **The headline ML threshold feature is therefore inert in
  the built 512-bit instance** — it decodes with a plain (non-spec) probabilistic
  threshold.

### Discrepancy 3 — f_theta does not match its specified shape, quantization or action sets (real deviation)

`mlthre_model.c` / `mlthre_model.h`:
- Two hidden layers, widths 32 and 16 (`MLTHRE_MODEL_HIDDEN1_DIM 32`,
  `HIDDEN2_DIM 16`), where §1.4 prescribes **one** hidden layer of width 16.
- All weights, biases, feature means/stds and the arithmetic are IEEE `float`
  (`mlthre_model.c:1313-1361`). §1.4 requires a **quantized** model implemented in
  **fixed-size integer arithmetic**; `mlthre_policy.c` additionally uses `double`,
  `ceil`, and (via `threshold.c`) `exp`/`lgamma` inside decapsulation. Floating point
  in the reject path is also a constant-time hazard, which §1.3 explicitly forbids.
- A single shared output head of 13 classes with
  `output_labels = {-12,…,-1,0}` (`mlthre_model.c:31-33`) replaces the three
  per-category action sets of Table 4 (sizes 8 / 11 / 5). In particular
  `D_512 = {-2,-1,0,1,2}` contains **positive** corrections that this label set cannot
  express, and levels 128/256 can receive corrections as large as -12, outside their
  specified sets.
- No confidence gate / τ_conf is implemented (the spec calls it optional, so this is
  (b), a permitted omission, but τ_conf is nonetheless listed as part of the instance).

### Discrepancy 4 — the correction is applied on only the first two iterations (real deviation)

`mlthre_policy.c:145-148`: `if (state->iteration > 2U) return 0;`. Spec §1.4 step 2
applies steps (d)-(f) at **every** decoding iteration. With `NbIter = 5`
(`defs.h:157/173/188/133`), three of the five iterations run with ΔT_i = 0.

### Discrepancy 5 — clipping bounds and NbIter are unspecified (spec ambiguity)

The spec never gives T_min, T_max or the iteration count. The implementation clips
twice — once inside `mlthre_compute_base_threshold` and again at `decode_ml.c:347-354`
— both to `[(d_v+1)/2, d_v]`, and uses `NbIter = 5`. These are defensible choices but
cannot be checked against the document.

### Discrepancy 6 — Decaps step 2's failure handling is omitted (minor, equivalent)

`kem.c:260` captures `rc = BGF_decoder(...)` and then never uses it; spec step 2 says
"if decoding fails, set e' ← (0,0)". Because a failed decode yields e' ≠ e*, `safe_cmp`
still forces the σ branch, so the behaviour is equivalent — but the explicit
zeroisation the spec asks for is not performed. Also, the b = 1 / b = 0 selection is a
C `if/else` (`kem.c:281-292`) rather than the constant-time select §1.3 demands
(different `functionK` inputs, same code path shape — so the leak is small, but it is
a branch on a secret-derived bit).

### Discrepancy 7 — a file-writing telemetry path is compiled into the library (observation)

`mlthre_runtime_sampling.c` opens files (`fopen`, lines 95-96) and `fprintf`s the
per-iteration decoder state and error vector; `decode_ml.c:368,372` and `kem.c:186`
call into it on every encapsulation/decapsulation. It is inert in this build —
`mlthre_runtime_sampling_init` has no caller in the shipped tree, so `g_sampling.enabled`
stays 0 — but a training-data-collection path that logs the decoder's internal state
and the plaintext error vector should not be present in a production decapsulation
routine. Not a spec deviation; flagged for triage.

### Not verified

- `mlthre_model.c`'s 1300+ lines of weight tables were not audited beyond the
  dimensions and the label array.
- The affine coefficients used at levels 128/256 were not traced back to any training
  artefact in `model/`; whether they correspond to a real trained baseline is unknown.
- The claimed target DFRs (2^-128 / 2^-256 / 2^-512) were not re-derived, and no DFR
  measurement was made. Given Discrepancies 1-4, the DFR claims rest on a decoder that
  differs from the specified one, so the spec's DFR analysis does not apply to this
  build.
- Section 2/3 of the spec (security reduction, side-channel discussion) was skimmed
  only.
