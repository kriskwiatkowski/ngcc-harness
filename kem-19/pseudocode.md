# kem-19 Lore — algorithm summary

Module-LWR-style KEM in the LPR framework over `R_tq = Z_tq[x]/(x^n+1)` with two
stated novelties: **Variable Modulus** (`tq` with a fixed base `q = 257` and a
per-level power-of-two `t ∈ {2,4}`, so the DFR can be tuned just under `2^-λ`)
and **CRT Compression** (an element of `Z_tq` is carried as the residue pair
`(x_q, x_t)`; rounding pushes one residue into a small set `S_R`, which is the
LWR-style noise). IND-CPA `Lore.PKE` is lifted to IND-CCA2 `Lore.KEM` by an
FO transform with implicit rejection; the plaintext is protected by a repetition
code (λ=128) or a BCH code (λ≥256) to drive the DFR down further.

Specification: `kem-19-spec.pdf` (36 pages), §3 (Algorithms 1–18), Table 2 (§5.1).

## Parameters

| parameter | Lore-L1 | Lore-L2 | Lore-L3 | Lore-L4 | meaning |
|---|---|---|---|---|---|
| n | 512 | 512 | 512 | 768 | ring degree |
| κ | 128 | 256 | 384 | 512 | message bits |
| k | 1 | 2 | 3 | 3 | module rank |
| q | 257 | 257 | 257 | 257 | fixed base modulus (all levels) |
| t | 2 | 2 | 4 | 4 | variable modulus factor; full modulus `tq` |
| \|S_R\| | 1 | 1 | 2 | 2 | rounding set for the `Z_t` part (0/0/1/1 stored bits) |
| l | 1 | 1 | 1 | 1 | bits kept of the `Z_q` part of `Cv` |
| secret distribution | FW{1,50,·,50,1} | FW{12,140,·,140,12} | FW{60,270,·,270,60} | FW{60,420,·,420,60} | fixed-weight counts of `{−2,−1,0,1,2}` over all k polys |
| ECC | REP, kvec=4 | BCH(512,256,28) | BCH(512,384,14) | BCH(768,512,25) | error correction before encryption |
| DFR (log2) | −130.78 | −259.28 | −395.97 | −528.55 | spec Table 2 |
| claimed security | 128 | 256 | 384 | 512 | classical bits (MATZOV model) |

Sizes (bytes), specification (Table 2/3) vs the built reference library. The
same four sizes are reported by **both** the SHAKE and the SM3 backend.

| instance | pk spec | pk impl | sk spec | sk impl | ct spec | ct impl | ss | match |
|---|---|---|---|---|---|---|---|---|
| Lore-L1 | 545 | 610 | 821 | 2108 | 641 | 706 | 32 | **no** |
| Lore-L2 | 1058 | 1186 | 1942 | 4518 | 1153 | 1282 | 32 | **no** |
| Lore-L3 | 1763 | 1954 | 3704 | 7736 | 1921 | 2114 | 32 | **no** |
| Lore-L4 | 2626 | 2914 | 5373 | 11432 | 2886 | 3170 | 32 | **no** |

All 8 built instances (4 levels × 2 backends) PASS their own KAT files; the two
backends ship separate, differing KAT sets.

## Pseudocode

### CRT compression — spec Algorithms 3–6
```
Compression(x_q, x_t):                   # for pk and Cu; shrinks the Z_t part
   x'_t  <- floor(x_t / 2)               # target set S_R subset of Z_t
   x''_t <- 2*x'_t mod t
   x'_q  <- x_q + (x''_t - x_t mod± t) mod q     # same epsilon added to both residues
   return (x'_q in Z_q, x'_t in Z_{t/2})

CompressionCv(x_q, x_t, l):              # for Cv; shrinks the Z_q part to l bits
   x'_q  <- floor(2^l * x_q / q + 1/2) mod 2^l
   x''_q <- floor(q/2^l * x'_q + 1/2) mod q
   x'_t  <- x_t + (x''_q - x_q mod± q) mod t
Decompression / DecompressionCv rebuild x' in Z_tq by CRT:
   x' = [ x_q * t * (t^-1 mod q) + x_t * q * (q^-1 mod t) ] mod tq
Lossless coding (Alg. 1/2): x <= 254 -> 8 bits; x in {255,256} -> 0xFF || 1 bit.
```

### PKE.KeyGen — spec Algorithm 7
```
seed <- {0,1}^rho0 ;  (seedA, seedsk) <- Hgen(seed)
A  <- expandA(seedA)              in R_tq^{k x k}
s  <- expandS(chi, seedsk)        in R_tq^k     # fixed-weight
b_q <- A s mod q ;  b_t <- A s mod t
(b'_q, b'_t) <- Compression(b_q, b_t)
pk <- (seedA, EncodeToByte(b'_q), b'_t) ;  sk <- s
```

### PKE.Encrypt(pk, µ, seed_r) — spec Algorithm 11 (+ 8/9/10 for Encode)
```
A  <- expandA(seedA)
s' <- expandS(chi, seed_r) in R_tq^k ;  e'' <- expandS(U(-t/2, t/2], seed_r) in R_tq
Cu_q <- A^T s' mod q ;  Cu_t <- A^T s' mod t
(C'u_q, C'u_t) <- Compression(Cu_q, Cu_t)
M  <- Encode(µ, n, κ, λ)          # REP (λ=128) or BCH, coefficients µ_i * tq/2
Cv_q <- b'_q^T s' + M + e'' mod q ;  Cv_t <- (2 b'_t)^T s' + M + e'' mod t
(C'v_q, C'v_t) <- CompressionCv(Cv_q, Cv_t, l)
C <- (EncodeToByte(C'u_q), C'u_t, C'v_q, C'v_t)
```

### PKE.Decrypt(sk, C) — spec Algorithm 15 (+ 12/13/14 for Decode)
```
C'u_q <- DecodeFromByte(C''u_q)
res_q <- floor(q/2^l * C'v_q + 1/2) - C'u_q^T s   mod q
res_t <- C'v_t - (2 C'u_t)^T s                    mod t
res   <- [ res_q*t*(t^-1 mod q) + res_t*q*(q^-1 mod t) ] mod tq
µ'    <- Decode(res, n, κ, λ)     # REP majority vote, or BCH hard decision
```

### KEM.KeyGen / Encaps / Decaps — spec Algorithms 16, 17, 18
```
KeyGen:  z <- {0,1}^256 ; (sk',pk) <- PKE.KeyGen() ; sk <- (sk', pk, H(pk), z)
Encaps:  m <- {0,1}^λ
         (Kbar, r) <- G( H(m) || H(pk) )
         c <- PKE.Encrypt(pk, m, r)
         K <- KDF( Kbar || H(c) )
Decaps:  m'         <- PKE.Decrypt(sk, c)
         (Kbar',r') <- G( H(m') || H(pk) )
         c'         <- PKE.Encrypt(pk, m', r')
         if c' == c:  K <- KDF(Kbar' || H(c'))
         else:        K <- KDF(z || H(c))          # implicit rejection
```

Hash structure: the spec (§3.5) names `Hgen`, `expandA`, `expandS`, `H`, `G`,
`KDF`, each "instantiated with SHAKE256/SM3", and explicitly notes that neither
SHAKE nor SM3 offers more than 256-bit security, so the 256-bit variants are
used "as temporary references" at λ = 384 and 512.

## The two hash backends

The submission ships two complete, independent reference trees —
`.../Reference_Implementation/Lore-SHAKE/Lore-L<n>` and `.../Lore-SM3/Lore-L<n>` —
built here as eight instances. They differ only in the symmetric layer:

| role | Lore-SHAKE | Lore-SM3 |
|---|---|---|
| XOF for `expandA` / `prf` (`symmetric.h`) | SHAKE128 stream (`fips202.c`), rate 168 | `sm3_xof128`, rate `SM3_XOF128_RATE` (`sm3_xof.c`) |
| `H` (`hash_h`, `kem.c:32`) | **SHA3-256** | `sm3()` |
| `G` (`hash_g`, `kem.c:46`) | SHAKE256, 64-byte output | `sm3_kdf()`, 64-byte output |
| `KDF` (`kem.c:138,216,230`) | SHAKE256 | `sm3_kdf()` |
| `rkprf` | `lore_shake256_rkprf` | `lore_sm3_rkprf` |

The SM3 XOF is not a sponge: `sm3_xof.c` buffers the whole input, prepends a
one-byte domain tag (`0x11` for XOF128, `0x12` for XOF256) and calls the
counter-mode `sm3_kdf()`. Because each squeeze re-derives the stream from the
start (`state_squeeze`, `sm3_xof.c:57-85`) the cost is quadratic in the total
output, and on `malloc` failure or on absorbing more than the fixed input buffer
(`state->overflow`) it **silently emits zeros** instead of failing. Both
backends produce identical key/ciphertext lengths but different KAT values, and
`ntt.c/poly.c/polyvec.c/indcpa.c` also differ textually between the two trees.

## Implementation vs specification

Checked: `params.h` (constants), `kem.c` (FO wrapper), `indcpa.c`/`pke.c`
(Algorithms 7/11/15), `poly.c`+`polyvec.c` (Compression/CompressionCv, lossless
coding), `sampler.c` (fixed-weight `expandS`), `verify.c`, and both
`symmetric-*.c`. Sampling: `LORE_Q`, `LORE_N`, `LORE_KAPPA`, `LORE_K`, `LORE_T`,
`LORE_L`, `LORE_R_BITS`, the four fixed-weight counts and the BCH `(m, τ)` pairs,
for all four levels.

- **Agreement.** `LORE_Q 257`, `LORE_N/KAPPA/K/T/L` match Table 2 exactly for all
  levels (`params.h:17-70`). `LORE_R_BITS` is 0,0,1,1 — the spec's "0, 0, 1, 1
  bits" for `S_R` (§3.2). The fixed-weight constants are stored *per polynomial*
  and scale to the spec's totals: L1 `{1,50,50,1}×k=1`, L2 `{6,70,70,6}×2 =
  {12,140,140,12}`, L3 `{20,90,90,20}×3 = {60,270,270,60}`, L4
  `{20,140,140,20}×3 = {60,420,420,60}` — all four match Notes [1]–[4].
  BCH: `(M,T) = (9,28),(9,14),(10,25)` matches `(512,256,28)`, `(512,384,14)`,
  `(768,512,25)`. The FO transform, the `z`-based implicit rejection and the
  `H(c)`-binding of the KDF are present as specified, and `verify()`
  (`verify.c:27-36`) returns a proper 0/1 so `cmov` selects in constant time.

- **Discrepancy 1 — every size differs (spec ambiguity, not a bug).** The spec's
  Table 2/3 sizes use the *average* cost of its variable-length code, 8.008 bits
  per `Z_q` coefficient (§5.1). A fixed-length API cannot do that, so the
  implementation reserves the worst case, 9 bits (one byte plus an overflow
  bitmap) plus a 2-byte length field:
  `LORE_PUBLICKEYBYTES = 32 + k·n + ceil(k·n/8) + k·ceil(n·R_BITS/8) + 2`
  (`params.h:108`) and the analogous `LORE_INDCPA_BYTES` (`params.h:116`).
  These reproduce the OBSERVED numbers exactly at all four levels (e.g. L1
  `32+512+64+0+2 = 610`; ct `512+64+0+64+64+2 = 706`). The spec never states a
  worst-case size, so the published bandwidth figures are unachievable as a
  fixed API length; the gap is 65–288 bytes on pk and ct.

- **Discrepancy 2 — secret key is 2.2–2.6× the spec figure (real deviation).**
  Spec §5.1 stores the secret as `k×(2+512) + TotalHWT×2` bytes. The
  implementation uses `LORE_SECRETKEYBYTES = k·2 + k·HWT_TOTAL·4 + k·(2n)`
  (`params.h:96-99`): 4 bytes per sparse term instead of 2, and the `q`-part as
  `n` *int16* (2 bytes/coefficient) instead of the ~`n`-byte lossless coding. The
  KEM key then appends `pk || H(pk) || z` per Algorithm 16 — which the spec's
  bandwidth accounting omits entirely. L1: `1434 + 610 + 32 + 32 = 2108`.
  Separately, the spec's own Table 2 secret-key numbers (821, 1942, 3704, 5373)
  do not follow the spec's own formula (which gives 718 and 1636 for L1/L2), so
  the document is internally inconsistent here.

- **Discrepancy 3 — `H` is SHA3-256, not SHAKE256 (real but minor).** §3.5 says
  all of `H`, `G`, `KDF` are SHAKE256; `kem.c:32` uses `sha3_256`. `G` and `KDF`
  are SHAKE256 as written. No security impact, but the document does not
  describe the deployed function.

- **Discrepancy 4 — shared secret is 256 bits at every level.** `LORE_SYMBYTES`
  is fixed at 32 (`params.h:18`), so Lore-L3 and Lore-L4 claim 384- and 512-bit
  classical security while emitting a 256-bit shared secret derived through
  256-bit hashes. The spec acknowledges this openly (§3.5, "temporary
  references"), so it is a documented limitation rather than an implementation
  error — but it caps the achievable security of those two parameter sets.

- Already known (RESULTS.md): this candidate ships modified `drng.c`/`auxfunc.c`
  with output-neutral edits. Not re-examined here.

- **Not verified.** The DFR derivation (Theorem 4.1, §4.1), the CRT-LWR → LWR
  reduction (§2.7), the lattice-estimator hardness figures, and the constant-time
  claim for the fixed-weight sampler and the BCH decoder.
