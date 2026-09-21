# kem-34 Rudraksh2 — algorithm summary

Lightweight module-LWE KEM. An IND-CPA PKE (Kyber-like: Â·ŝ+ê with NTT-domain
public matrix, ciphertext compression to moduli p and t) is turned into an
IND-CCA2 KEM by the FrodoKEM-style FO transform with implicit rejection. The
distinguishing feature is the message encoder: an *extended 2-dimensional Minal
lattice code* ("B2-Minal") that packs 4 message bits into 2 Z_q coefficients,
so the message space is µ = 2n bits and n can be as small as 64.

Specification: `kem-34-spec.pdf` (33 pages), section 1.1–1.4 (Algorithms 1–15,
parameters Table 1, sizes Table 2).

## Parameters

Only the "-I" variants are implemented (spec also defines -II sets, not built).

| parameter | lwekem128 | lwekem256 | lwekem512 | meaning |
|---|---|---|---|---|
| ℓ | 9 | 9 | 8 | module rank |
| n | 64 | 128 | 256 | ring degree, R_q = Z_q[x]/(x^n+1) |
| q | 3329 | 3329 | 7681 | prime modulus |
| ⌈log2 q⌉ | 12 | 12 | 13 | bits per uncompressed coefficient |
| p | 2^12 | 2^11 | 2^13 | compression modulus for u = b′ |
| t | 2^6 | 2^9 | 2^7 | compression modulus for v = c_m |
| η | 2 | 1 | 2 | CBD parameter for s, e, s′, e′, e″ |
| (B, β) | (2, 220) | (2, 220) | (2, 510) | Minal dimension, tailoring parameter |
| lenK | 128 | 256 | 512 | seed/shared-secret size, **bits** |
| µ = 2n | 128 | 256 | 512 | message bits |
| failure prob (log2) | −100 | −161 | −160 | spec's DFR claim |
| claimed security | 128 | 256 | 512 | classical bits (quantum 80/128/256) |

Sizes (bytes), specification (Table 2) vs the built reference library:

| instance | pk spec | pk impl | sk spec | sk impl | ct spec | ct impl | ss | match |
|---|---|---|---|---|---|---|---|---|
| lwekem128 | 880 | 880 | 1776 | 1776 | 912 | 912 | 16 | yes |
| lwekem256 | 1760 | 1760 | 3552 | 3552 | 1728 | 1728 | 32 | yes |
| lwekem512 | 3392 | 3392 | 6848 | 6848 | 3552 | 3552 | 64 | yes |

## Pseudocode

Symmetric primitives (spec §1.1): one XOF instantiated three ways —
H(x) = XOF(x, lenK), G(x) = XOF(x, 2·lenK), PRF = XOF. In the implementation
all three are the ICCS `pseudoXOF()` (SM3-based), `symmetric.h:12-15`.

### KeyGen — spec Alg. 10 (PKE) + Alg. 13 (KEM)
```
(seedA, seedse) <- U({0,1}^lenK x {0,1}^lenK)        # Alg.10 l.1
Â  <- SampleMatrix(seedA)            in R_q,n^{lxl}  # Alg.5, samples NTT(A) directly
s  <- SampleCBDvec_eta(seedse, 0)    in R_q,n^l      # Alg.4/Alg.3
e  <- SampleCBDvec_eta(seedse, l)    in R_q,n^l
ŝ <- NTT(s);  ê <- NTT(e)
b̂ <- Â o ŝ + ê                                    # pointwise (NTT domain)
pk <- seedA || PolyToBytes_q(b̂)                     # Alg.1
sk_pke <- PolyToBytes_q(ŝ)
pkh <- H(pk);  z <- U({0,1}^lenK)                    # Alg.13 l.2-3
sk <- sk_pke || pk || pkh || z
return (pk, sk)
```

### Encaps — spec Alg. 14, calling Alg. 11 (PKE.Encrypt)
```
m <- U({0,1}^lenK)
(K, seed_r) <- G(H(pk), m)                           # Alg.14 l.2
c <- PKE.Encrypt(pk, m; seed_r);   return (c, K)

PKE.Encrypt(pk, m; seed_r):                          # Alg.11
  (seedA || b̂) <- BytesToPoly_q(pk);  Â <- SampleMatrix(seedA)
  s'  <- SampleCBDvec_eta(seed_r, 0)
  e'  <- SampleCBDvec_eta(seed_r, l)
  e'' <- SampleCBDpoly_eta(seed_r, 2l)
  ŝ' <- NTT(s')
  b'  <- INTT(Â^T o ŝ') + e'
  c_m <- INTT(b̂^T o ŝ') + e'' + Rudraksh2.Encode(m)  # Alg.8 / MinalB2.Encode Alg.6
  u <- Compress_p(b');  v <- Compress_t(c_m)
  return PolyToBytes_p(u) || PolyToBytes_t(v)
```
Encode (Alg. 6/8): for i = 0..µ/4−1, (c[i], c[i+n/2]) = G2·(m[4i..4i+3]) where
G2 = [[⌊q/4⌉, β],[β, ⌊q/4⌉]] on the inner 2 bits plus ⌊q/2⌉·(outer 2 bits).

### Decaps — spec Alg. 15, calling Alg. 12 (PKE.Decrypt)
```
(sk_pke || pk || pkh || z) <- sk
m' <- PKE.Decrypt(sk_pke, c):                        # Alg.12
       u' <- Decompress_p(u);  v' <- Decompress_t(v)
       m'' <- v' - INTT( NTT(u')^T o ŝ )
       m'  <- Rudraksh2.Decode(m'')                  # Alg.9 / MinalB2.Decode Alg.7
(K', seed_r') <- G(pkh, m')
c* <- PKE.Encrypt(pk, m'; seed_r')
K'' <- H(c, z)
return  K'  if c = c*  else  K''                     # implicit rejection
```
MinalB2.Decode (Alg. 7): phase 1 reduces c mod ⌊q/2⌉ and does minimum-distance
decoding against the 4 pure-Minal codewords to get (m2,m3); phase 2 recovers
(m0,m1) from ⌊|δ|/⌊q/4⌉⌋ where δ = c − G1·(m2,m3) mod ± q.

## Implementation vs specification

Checked: `src/<inst>/{params.h, indcpa.c, poly.c, polyvec.c, cbd.c, minal.c,
reduce.c, KEM_lwekem<NNN>.c}` for all three instances (`api.c`, `kex.c` are not
built, per the Makefile note).

Agreements:
- All 11 spec parameters of Table 1 (ℓ, n, q, ⌈log2 q⌉, p, t, η, lenK) match
  `params.h` in all three instances, and the β of the Minal code matches per
  instance (`lwekem128/minal.c:11`, `lwekem256/minal.c:15`,
  `lwekem512/minal.c:15` = 220 / 220 / 510, matching spec 220 / 220 / 510).
- All nine pk/sk/ct sizes reproduce Table 2 exactly from the `params.h`
  formulas; ss = lenK/8 bytes as specified.
- The FO transform is complete: re-encryption (`KEM_lwekem128.c:124`),
  constant-time compare `verify()` (`:126`), and constant-time `cmov()` to the
  rejection key H(c‖z) (`:131-132`). Implicit rejection is genuinely implemented.
- All randomness in KeyGen and Encaps is drawn from the official
  `drng_algorithm` (`indcpa.c:262`, `KEM_lwekem128.c:66,82`); no other entropy
  source is linked.

Deviations and notes:
- **(a) API contract:** `kem_keygen`/`kem_enc`/`kem_dec` never write the
  `[out]` length parameters `*pk_len_bytes`, `*sk_len_bytes`, `*ss_len_bytes`,
  `*ct_len_bytes` (`KEM_lwekem128.c:51-141` and the 256/512 twins), although
  `api/API_PKC/.../KEM_AlgorithmInstance.h:47-52` declares them as outputs. A
  caller that does not pre-initialise them reads uninitialised memory.
- **(b)/(c) seed derivation:** Alg. 10 l.1 says seedA and seedse are two
  independent uniform lenK-bit draws. The implementation draws a *single*
  lenK-bit value from the DRNG and expands it with G to get both
  (`indcpa.c:262-264`), so key generation consumes lenK, not 2·lenK, bits of
  entropy. Standard Kyber practice, but not what the spec writes.
- **(b) hash argument order:** the spec writes G(H(pk), m) (Alg. 14 l.2) and
  G(pkh, m′) (Alg. 15 l.3); the code computes G(m ‖ H(pk))
  (`KEM_lwekem128.c:82-87`, `:113-121`). Consistent between Encaps and Decaps,
  so only the serialisation order differs from the spec text.
- **(c) matrix sampling byte order:** Alg. 5 extracts ⌈log2 q⌉-bit integers
  LSB-first from the PRF stream. `gen_matrix()` instead reverses the byte order
  *within each aligned 8-byte block* of the XOF output before rejection
  sampling (`indcpa.c:206-211` and again at `:226-232`). The result is still
  uniform, but the encoding is non-canonical and cannot be reproduced from the
  spec text alone. `rej_uniform()` also uses a 12-bit extraction hard-wired for
  ⌈log2 q⌉ = 12 (`indcpa.c:149-150`); the 512 instance has its own 13-bit copy.
- **(c) unbounded failure:** `gen_matrix()` calls `abort()` if 256 XOF blocks
  fail to fill one polynomial (`indcpa.c:220`). Probability is negligible but
  it is a hard process kill rather than an error return.
- **(a, minor) missing reduction before decoding:** `minal_b2_code_decode()`
  documents the precondition "0 ≤ target[i] < q" but the 128 and 256 instances
  do not enforce it (`lwekem128/minal.c:122-126`); only lwekem512 calls
  `freeze()` on both coordinates first (`lwekem512/minal.c:146-147`). In the
  built code `poly_sub()` applies `barrett_reduce()` (`poly.c`, output in
  {0,…,2q}), so the input can exceed q and the decode is being fed a
  non-canonical representative. KATs still pass, so this is at worst a
  correctness-margin issue, but the three instances are inconsistent.
- No unpacking range check: `poly_frombytes`/`polyvec_frombytes` accept any
  ⌈log2 q⌉-bit word, so a ciphertext or public key with coefficients in
  [q, 2^⌈log2 q⌉) is accepted. Harmless for the KEM (decaps re-encrypts and
  compares), but it means public keys have many non-canonical encodings.

Not verified: the NTT twiddle tables and Montgomery/Barrett constants were not
recomputed; the AVX2 and Cortex-M4 trees were not reviewed; the -II parameter
sets are not implemented and were not checked.
