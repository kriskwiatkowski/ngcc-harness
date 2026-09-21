# kem-07 BRQC (Blockwise RQC) — algorithm summary

Code-based KEM in the **rank metric**. BRQC.PKE is an RQC-style quasi-cyclic (ideal-code)
encryption whose IND-CPA security reduces tightly to the **Ideal Blockwise Rank Syndrome
Decoding (IBRSD)** problem (blockwise = sum-rank errors whose per-block supports are in
direct sum, Def. 2.3); a **salted Fujisaki–Okamoto** transform with implicit rejection gives
the IND-CCA2 KEM. Message recovery uses a public **Gabidulin code** decoded by the
Welch–Berlekamp-like (WBL) linear-reconstruction algorithm; DFR is claimed *null*
(deterministic decoding), not probabilistic.

Specification: `kem-07-spec.pdf` (34 pages), §3 "Specifications" (Algorithms 1–9), §4
"Parameters". Spec is in **English**; the `中文资料/` directory holds only the Chinese
versions of the basic-information and IP-declaration forms, not the algorithm spec.

## Parameters

| parameter | BRQC-128 | BRQC-256 | BRQC-512 | meaning |
|---|---|---|---|---|
| q | 2 | 2 | 2 | base field |
| m | 127 | 163 | 229 | extension degree, F_{q^m} |
| n | 119 | 161 | 227 | code length / ring degree |
| k | 3 | 3 | 3 | Gabidulin dimension (plaintext length) |
| w_x, w_y | 5, 5 | 5, 6 | 6, 7 | secret-key block rank weights |
| w_r1, w_r2, w_e | 5, 5, 8 | 6, 7, 8 | 8, 8, 8 | encryption block rank weights |
| r | 58 | 79 | 112 | decoded rank weight = w_x·w_r2 + w_y·w_r1 + w_e |
| ⌊(n−k)/2⌋ | 58 | 79 | 112 | Gabidulin correction bound (r must be ≤ this) |
| P(X) | X^119+X^8+1 | X^161+X^18+1 | X^227+X^10+X^9+X^4+1 | irreducible, R = F_{q^m}[X]/⟨P⟩ |
| salt len | 512 | 512 | 512 | bits |
| claimed security | 2^181 cl. / 2^90 q. | 2^295 / 2^147 | 2^566 / 2^283 | spec Table 3 (MM attack) |

Sizes (bytes), specification (Table 3) vs the built reference library:

| instance | pk spec | pk impl | sk spec | sk impl | ct spec | ct impl | ss | match |
|---|---|---|---|---|---|---|---|---|
| BRQC-128 | 1954 | 1954 | 112 | **2066** | 3844 | 3844 | 64 | sk mismatch |
| BRQC-256 | 3345 | 3345 | 126 | **3471** | 6626 | 6626 | 64 | sk mismatch |
| BRQC-512 | 6562 | 6562 | 150 | **6712** | 13060 | 13060 | 64 | sk mismatch |

Spec formulas hold for pk (⌈mn/8⌉+64) and ct (2⌈mn/8⌉+64, the 64 being the salt). The
sk difference is exactly +pk bytes (see below).

## Pseudocode

### KeyGen — Alg. 7 (KEM) over Alg. 3 (PKE)
```
BRQC.PKE.KGen(par):                       # Algorithm 3
  1  g  <- F_{q^m}^n  from seed θ1, with ||g||_R = n (full weight m)
  2  h  <- F_{q^m}^n  from seed θ1
  3  (x, y) <- S^{(n,n)}_{(w_x,w_y)}  from seed θ2     # blockwise: Supp(x) ⊕ Supp(y)
  4  s  = x + h·y                                       # in R = F_{q^m}[X]/<P(X)>
     return pk' = (g, h, s), sk' = (x, y)

BRQC.KEM.KGen(par):                       # Algorithm 7
  1  (pk', sk') <- BRQC.PKE.KGen(par)
  2  σ <-$ F_{q^m}^k                                    # implicit-rejection secret
  3  return pk = pk', sk = (sk', σ)
```

### Encaps — Alg. 8 over Alg. 4
```
BRQC.KEM.Encaps(pk):                      # Algorithm 8
  1  m <-$ F_{q^m}^k ;  salt <-$ {0,1}^512
  2  θ = G(pk, m, salt)                                 # 64-byte output, used as a seed
  3  ct' = BRQC.PKE.Enc(pk, m; θ):                      # Algorithm 4
       3a  G <- generator matrix of the [n,k]_{q^m} Gabidulin code defined by g
       3b  (r1, e, r2) <- S^{(n,n,n)}_{(w_r1,w_e,w_r2)} from θ   # direct-sum supports
       3c  u = r1 + h·r2 ;  v = m·G + s·r2 + e
  4  ct = (ct', salt) = (u, v, salt)
  5  K  = H(pk, m, ct', salt)                           # 64-byte shared secret
```

### Decaps — Alg. 9 over Alg. 5, with rank decoding by Alg. 1
```
BRQC.KEM.Decaps(sk, ct):                  # Algorithm 9
  1  parse sk = (sk'=(x,y), σ) ;  ct = (u, v, salt)
  2  m  <- BRQC.PKE.Dec(sk', (u,v)):                    # Algorithm 5
       2a  z = v - u·y = m·G + (x·r2 + e - r1·y)        # §3.3 correctness
           rank of the residual error is bounded by
             ||x·r2 + e - r1·y||_R <= w_x·w_r2 + w_y·w_r1 + w_e = r
           and parameters are chosen so r <= floor((n-k)/2)  => DFR is null
       2b  m = Gab.Decode(z)                            # Algorithm 1, WBL decoder:
             i.   solve LR(g, z): find q-polynomials (v(x), u(x)),
                  deg_q v <= r, deg_q u <= k+r-1, with v(z_i) = u(g_i)
                  init: u0 = annihilator of g1..gk, u1 = interpolator of z1..zk
                        on g1..gk, v0 = 0, v1 = x ; then iterate the
                        interpolation recurrence over i = k+1..n
             ii.  f(x) = v(x) \ u(x)      (symbolic left division)
             iii. if deg_q f <= k-1 and ||z - f(g)||_R <= r:
                    return m = coefficients of f, e = z - f(g)
                  else return ⊥
  3  θ = G(pk, m, salt)
  4  (u', v') = BRQC.PKE.Enc(pk, m; θ)                  # re-encryption check
  5  if (u', v') != (u, v)  or  m = ⊥ : K = H(pk, σ, ct, salt)
     else                              : K = H(pk, m, ct, salt)
```

Hashes (§3.1): `G` and `H` are the NGCC `pseudohash` construction over **SM3 / HMAC-SM3**
with 64-byte output; the seed expander is the NGCC 64-byte-seeded expander; the DRBG is the
SM3-based NGCC DRNG (55-byte state). No domain-separation label distinguishes G from H —
separation comes only from the differing input lengths/shapes.

## Implementation vs specification

Checked against `src/BRQC-128/` (= `Implementations/Reference_Implementation/BRQC-128`,
per `Makefile`; the 256/512 instances differ only in `parameters.h` and the `rbc-m` subdir,
m = 127/163/229). Mapping: `src/kem.c` = Alg. 7/8/9, `src/brqc.c` = Alg. 3/4/5,
`src/gabidulin.c` = Alg. 1 (rank decoding), `src/qpoly.c` = q-polynomial arithmetic,
`src/parsing.c` = serialization, `src/rbc-*/rbc_vspace.c` = blockwise support sampling.

**Parameter spot-check** (sampled: q, m, n, k, all five weights, salt length, and the
derived decoding bound — all three instances' `src/parameters.h`): `BRQC_PARAM_Q/M/N/K`
and `BRQC_PARAM_W_x/W_y/W_r1/W_r2/W_e` match spec Table 2 exactly for all three sets.
`BRQC_SALT_BYTES 64` matches the 512-bit salt. `gabidulin.c:100` sets `t = (n-k)/2`,
i.e. 58 / 79 / 112 — exactly the spec's r column, confirming r = ⌊(n−k)/2⌋ is tight for
every instance (no slack; an error of rank r+1 is uncorrectable).

Agreements: the blockwise (direct-sum) structure is genuinely implemented — `brqc.c:70-81`
and `:179-189` draw **one** full-rank F_q-subspace of dimension w_x+w_y (resp.
w_r1+w_r2+w_e) and slice it, so the per-block supports are in direct sum as Def. 2.3
requires. The salted FO is present with pk, ciphertext and salt bound into both G and H
(`kem.c:98-141`, `:262-268`), and the reject path is branchless: an OR-accumulator over all
2·VEC_N_BYTES ciphertext bytes yields a mask, and m/σ are selected by XOR (`kem.c:233-259`),
matching the constant-time claim of §5.

Discrepancies / notes:

- **(a) Secret-key size.** Spec Table 3 says sks = ⌈mk/8⌉+64 = 112/126/150 bytes, but the
  implementation stores `sk = sk_seed(64) || σ(VEC_K_BYTES) || pk` (`kem.c:33`, `:65`),
  i.e. 2066/3471/6712 = spec value + pk. This matches OBSERVED exactly. The pk copy is
  needed because Decaps hashes pk (`kem.c:212`) and re-encrypts; the spec's size table
  simply does not account for it. Reporting-level deviation, not a security flaw.
- **(b) Spec ambiguity in Alg. 9.** Line 3 rebinds `ct ← Enc(...)`, so line 4's
  `K := H(pk, σ, ct, salt)` literally names the *re-encrypted* ciphertext, which on the
  rejection branch differs from the received one. The implementation hashes the **received**
  (u, v) on both branches (`kem.c:265-267`), which is the standard and correct FO reading.
- **(c) No ⊥ from the decoder.** Alg. 1 line 8 returns ⊥; `rbc_gabidulin_decode` is `void`
  and always produces some m (`gabidulin.c:94`), relying entirely on the FO re-encryption
  check to reject. Equivalent in effect, but the spec's explicit failure symbol is absent.
- **(c) Randomness inside decoding.** `gabidulin.c:120-126` draws a random vector and uses
  it in `rbc_elt_set_mask1/2` (`:196-201`) to make the pivot search branchless. Not in the
  spec; it is an RQC-reference constant-time device, and it means Decaps consumes PRNG
  output. Output is unaffected (KATs pass, per `security_findings.md`: 3/3 PASS).
- **(note)** The `Makefile` links the XKCP Keccak sources, but no `src/*.c` file references
  SHAKE/Keccak — all hashing goes through `pseudohash` (SM3/HMAC-SM3) as §3.1 states. The
  Keccak objects are dead code in this build. Likewise `SHA512_BYTES` in `parameters.h` is
  named after SHA2/SHA3 but only sizes the 64-byte `pseudohash` output.
- **Not verified:** the `rbc-*` field/polynomial layer (`rbc_elt.c`, `rbc_qre.c`) was not
  read line by line, so the constant-timeness of the underlying F_{q^m} arithmetic and the
  exact seed-expander byte consumption are unconfirmed. The WBL interpolation recurrence
  in `gabidulin.c:130-310` was read structurally, not verified term by term against [8].
- The append/truncate length-metadata observations in `security_findings.md` are ABI
  artifacts of the fixed-size buffer, not scheme-level ciphertext malleability.
