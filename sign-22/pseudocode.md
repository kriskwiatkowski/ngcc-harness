# sign-22 Rhyme — algorithm summary

Bimodal Fiat-Shamir lattice signature in the HAETAE / G+G line (`As = qj mod 2q`,
challenge `c ∈ {0,1}^n` of weight τ, no hints). Its distinguishing feature is
**3C sampling**: the masking vector's tail is produced as `y_bottom = 2·B_sig·X' +
e_bottom` from a *short unimodular* basis, so only `σ ≥ η_ε(Z^{nd})` is needed for
statistical hiding. Security rests on **GA-MLWE** (MLWE plus a partial Gram matrix
of the unimodular basis — a weakening of module-LIP), reduced to MSIS/MLWE and
BimodalSelfTargetMSIS in the (Q)ROM. Signatures are entropy-coded with rANS.

Specification: the submission's spec/basic-information PDFs are **swapped** (known,
RESULTS.md). The 71-page algorithm specification is `Basic information.pdf`;
`Algorithm specifications.pdf` is the 3-page basic-information sheet. All citations
below are to `Basic information.pdf`: §3.3.2–3.3.4 (Constructions 1–3), §3.4
(Algorithms 5–7), §4.1 (ID protocol), §5.1 Table 3 (parameters).

## Parameters

Spec §5.1 Table 3. SHAKE and SM3 instances of a level share all parameters
(`Makefile`: same sources, `-DRHYME_MODE=<n>`, only the XOF backend differs), so
one column per level covers both.

| parameter | 128 | 256 | 384 | 512 | meaning |
|---|---|---|---|---|---|
| n | 256 | 512 | 512 | 1024 | ring degree, R = Z[x]/(x^n+1) |
| q | 3329 | 9473 | 11777 | 18433 | odd modulus (arithmetic mod 2q) |
| (k, l) | (2,3) | (2,3) | (3,4) | (2,3) | module dims; d = k+l-1 |
| D | 10 | 10 | 14 | 10 | widened unimodular dimension (D > 4k+1) |
| τ | 30 | 58 | 113 | 115 | challenge Hamming weight |
| η | 2 | 4 | 5 | 6 | CBD width of the short rows |
| σ_y | 122.0 | 180.0 | 182.0 | 266.0 | std. dev. of y1 |
| B1 (‖z1‖∞) | 388 | 598 | 605 | 916 | bound, code name `RHYME_B0` |
| B2 (‖z_bottom‖∞) | 581 | 1219 | 1654 | 2209 | bound, code name `RHYME_B1` |
| B_L2 (‖z‖2) | 4685.06 | 12842.68 | 20258.77 | 31350.08 | bound |
| repetitions | 2.73 | 2.99 | 2.95 | 2.69 | expected signing iterations |
| claimed security | 128 | 256 | 384 | 512 | bits, classical (forgery 130.25 / 257.99 / 384.94 / 518.97) |

Sizes (bytes). Spec column = Table 3's "Public/Secret/Signature key size" rows.
Impl column = `OBSERVED/sign-22.txt` (identical for the `-SHAKE-` and `-SM3-`
instance of each level).

| instance | pk spec | pk impl | sk spec | sk impl | sig spec | sig impl | match |
|---|---|---|---|---|---|---|---|
| Rhyme-{SHAKE,SM3}-128 | 800 | 800 | 11072 | 11072 | 1483 | 5156 | pk/sk yes; sig see below |
| Rhyme-{SHAKE,SM3}-256 | 1824 | 1824 | 22336 | 22336 | 3258 | 10308 | " |
| Rhyme-{SHAKE,SM3}-384 | 2720 | 2720 | 45760 | 45760 | 4743 | 14436 | " |
| Rhyme-{SHAKE,SM3}-512 | 3872 | 3872 | 44864 | 44864 | 7002 | 20612 | " |

## Pseudocode

### KeyGen (spec Algorithm 5, §3.4)
```
seed <- {0,1}^ρ0 ;  (seed_A, seed_sk, K) <- H_gen(seed)
A_gen <- expandA(seed_A) ∈ R_q^{k×(l-1)}
(B_ext, s'_tail) <- GenUnimod(1^λ, D)             # D×D unimodular over Z, first column s'_tail
(s_gen, e_gen, v) <- s'_tail                      # s_gen∈R_q^{l-1}, e_gen∈R_q^k, v∈R_q^{D-(k+l-1)} discarded
b_gen <- A_gen·s_gen + e_gen  mod q  ∈ R_q^k
A     <- (-2 b_gen + q j | 2 A_gen | 2 I_k) mod 2q ∈ R_2q^{k×(k+l)}
s     <- (1, s_gen, e_gen) = (1, s_tail)          # so that A·s = q j mod 2q
B_sig <- B_ext[1:k+l-1, 2:D] ∈ R_2q^{(k+l-1)×(D-1)}   # drop col 1 and the trailing D-d rows
return sk = (s, B_sig, K),  pk = (seed_A, b_gen)
```

### Sign (spec Algorithm 6, §3.4)
```
A_gen <- expandA(seed_A);  A <- (-2b_gen + qj | 2A_gen | 2I_k) mod 2q
µ <- H_gen(seed_A, b_gen, M)
rnd <- 0^ρ0        # zeroes = deterministic mode; from RBG = randomized mode
seed_sig <- H_gen(K, µ, rnd);  count <- 0;  (z1, 2x) <- ⊥
while (z1, 2x) = ⊥:
    (rt1, rt2, rt3) <- expand(seed_sig, count)
    y1       <- Sample_Y1(rt1) ∈ Z^n                     # truncated to B1+R
    X'       <- Sample_Gaussian(σ,  rt2) ∈ R_2q^{D-1}
    e_bottom <- Sample_Gaussian(2σ, rt3) ∈ R_2q^{k+l-1}
    y_bottom <- 2·B_sig·X' + e_bottom ∈ R_2q^{k+l-1}
    w  <- A·(y1, y_bottom)^T mod 2q
    c  <- SampleInBall(w, µ) ∈ R_2                       # weight-τ binary challenge
    (z1, 2x) <- Sample_Z(c, y1, rt2)                     # Alg. 3, lightweight rejection
    if failed: count++ ; continue
    2X0      <- 2x + c ∈ R_2q                            # fix parity
    z_bottom <- y_bottom + 2·s_tail·X0 ∈ R_2q^{k+l-1}
    z        <- (z1, z_bottom)
    if ‖z1‖∞ > B1 or ‖z_bottom‖∞ > B2 or ‖z‖2 > B_L2:  count++ ; (z1,2x) <- ⊥
z_comp <- rANSEncode(z)
return σ = (z_comp, c)
```

### Verify (spec Algorithm 7, §3.4)
```
z <- rANSDecode(z')
A_gen <- expandA(seed_A);  A <- (-2b_gen + qj | 2A_gen | 2I_k) mod 2q
w' <- A·z - q·c·j  mod 2q
µ  <- H_gen(seed_A, b_gen, M)
return 1 iff  c = SampleInBall(w', µ)
          and ‖z1‖∞ ≤ B1 and ‖z_bottom‖∞ ≤ B2 and ‖z‖2 ≤ B_L2
```
Hash/XOF instantiation (spec §3.4, last paragraph): "we use **SHAKE256/SM3** for the
hash functions and extendable output functions" — `H_gen`, `expandA` and `expand`.
No further padding or domain-separation detail is given.

## Implementation vs specification

What was checked. `sign-22/Makefile` (8 instances = 4 levels × 2 XOF backends).
Mapped: `src/sign.c` → Alg. 5/6/7 (`crypto_sign_keypair` / `_signature` /
`_verify`), `src/keygen/kg_main.c` + `kg_solver.c` → `GenUnimod`, `src/sampler.c`
→ `Sample_Y1`/`Sample_Gaussian`/`Sample_Z`, `src/encoding.c` + `rans_*.h` →
rANSEncode/Decode, `src/packing.c` → pk/sk/sig serialisation, `src/fips202.c`
(SHAKE) vs `sm3.c` + `sm3_xof.c` + `rhyme_xof.c` (SM3) → the XOF layer.

Agreements. Spot-checked `include/params_tables.h` of `Rhyme-SHAKE-128` and
`-384` against Table 3: `RHYME_N` 256/512, `RHYME_Q` 3329/11777, `(K,L)` (2,3)/(3,4),
`RHYME_DMAT` (= D) 10/14, `RHYME_ETA` 2/5, `RHYME_TAU` 30/113, `RHYME_SIGMAY`
122/182, `RHYME_B0` 388/605, `RHYME_B1` 581/1654 — all agree. `RHYME_L2SQ`
21949787 = floor(4685.06²) and 410418166 ≈ 20258.77², agreeing with B_L2.
`CRYPTO_PUBLICKEYBYTES = SEEDBYTES + K·POLYQ_PACKEDBYTES` and
`CRYPTO_SECRETKEYBYTES = pk + d·D·n·8/8 + SEEDBYTES` reproduce all eight
spec table values exactly. Verify enforces all three spec bounds
(`src/sign.c:495,499,502`) before the challenge comparison — no missing check.
The SM3 backend is a spec-sanctioned substitution: `Rhyme-SM3-*/rhyme_xof.c`
redirects the `rhyme_shake256_*` names to `sm3_xof256_*` over the ICCS
`pseudoXOF()`, and `src/sign.c` is written against the `rhyme_*` names only.

**(c) Equivalent optimisation — the "sig impl" column is a buffer cap, not the
signature size.** `CRYPTO_BYTES = 2 + CTILDEBYTES + 2 + (1+d)·N·4`
(`include/params.h:99`, commented "CRYPTO_BYTES is the padded cap") reserves 4
bytes per coefficient, i.e. the worst case before rANS compression; the wire
format is `[u16 total_len][c̃][u16][rANS z-block]`. The submitted KATs report
`Sn_Len = 1480 / 1491 / 1481 …` for Rhyme-SHAKE-128, i.e. right at the spec's
1483. So the spec and the code agree on the actual signature; only
`sig_get_sn_len_bytes()` reports the cap. Worth flagging for any bandwidth
comparison: 5156 vs 1483 is a 3.5× difference in the advertised size.

**(b) Spec-internal inconsistency — secret-key formula vs. secret-key table.**
§5.1 states `|sk| = (k+l-1)·D·n·⌈log2(2η+1)⌉/8 + n/8`, which at level 128 gives
4·10·256·3/8 + 32 = 3872 bytes, not the 11072 in its own Table 3. The
implementation stores the short block at 8 bits/coefficient
(`params.h:86 SK_SMALL_BITS 8`) and prepends the public key, giving
800 + 4·10·256 + 32 = 11072 — matching the table and OBSERVED. The formula's
⌈log2(2η+1)⌉ = 3-bit packing is simply not what is implemented; the table is the
correct column.

**(b) Naming/indexing drift between spec and code.** The spec's `B1` (bound on
`‖z1‖∞`) is `RHYME_B0` in the code and the spec's `B2` is `RHYME_B1`; values
match, but a reader comparing symbol-for-symbol will be misled. Likewise the
code's `params.h:25-55` header comment calls the implemented variant
"**Construction 4** (compressed unimodular, `cut-F`)" while the spec's §3.3.4 is
"Construction 3 (Extended Unimodular Matrix)", and §3.4 says the algorithms
instantiate the practical variant of Construction 3. The described mechanism is
the same one — retain only the d = k+l-1 short rows of a D×D unimodular basis,
never assemble the long row F, and rely on `D > 4k+1` to kill the algebraic
distinguisher (spec §4's "Parameter constraint") — so this is a naming, not a
design, divergence.

**(c) Verify compares the challenge *hash*, not the challenge.** Spec Alg. 7
line 6 tests `c = SampleInBall(w', µ)`; `src/sign.c:513-527` instead recomputes
`c̃' = XOF(pack(w') ‖ µ)` and compares it with the transmitted `c̃`
(`CTILDEBYTES = RHYME_MODE/4`), expanding `c` from `c̃` via `SampleChallenge`.
This is the standard Dilithium-style equivalent and is strictly less malleable,
but the spec's signature is written `σ = (z_comp, c)` while the wire format
carries `c̃`.

Not verified. `GenUnimod` (spec §3.3.3-3.3.4) was read only at the level of the
`kg_main.c` header comment and the coprimality-backend switch
(`USE_DP1_CHECK` / `USE_FULL_MNTRU_SOLVER` / `kg_solve_coprime_descent`); the
spec gives no algorithm box for it, so the resampling and coprimality criteria
could not be checked against spec text. The rANS frequency tables
(`rans_freqs.h`) and `Sample_Z` (spec Alg. 3, Appendix A) were not verified
line-by-line. No instance was built or run.
