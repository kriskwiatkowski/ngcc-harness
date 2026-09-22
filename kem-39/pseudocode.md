# kem-39 Weaver — algorithm summary

Module-LWR ("MLWR-type", pure rounding — no explicit error vectors e, e′, e″) IND-CPA
PKE over R_q = Z_q[X]/(X^n+1), lifted to an IND-CCA KEM by an FO transform with
implicit rejection. Two features distinguish it from ML-KEM: (a) *randomized lifting*
`Inv_q` — during encryption the compressed public key is lifted to a **uniformly random**
preimage in its compression bucket instead of being canonically decompressed, derived
deterministically from the FO coins so the encryption stays derandomised; (b) a
*two-layer message encoding* (BCH on the high bits, BCH + 4-way repetition with
soft-decision decoding on the low bits) which buys enough noise tolerance for very
aggressive compression (d_t, d_u, d_v).

Specification: `kem-39-spec.pdf` (56 pages), §2.1–2.5; Algorithms 1–9; Tables 1–4.
Language: English.

## Parameters

| parameter | Weaver-640 | Weaver-1024 | Weaver-2048 | meaning |
|---|---|---|---|---|
| level | 1 | 3 | 5 | NGCC/NIST category |
| n | 128 | 256 | 512 | ring degree |
| k | 5 | 4 | 4 | module rank |
| q | 3329 | 7681 | 7681 | modulus |
| ⌈log2 q⌉ | 12 | 13 | 13 | sk coefficient width |
| η1, η2 | 3, 2 | 7, 7 | 9, 9 | CBD widths for s and r |
| (d_t, d_u, d_v) | (9, 9, 6) | (10, 10, 8) | (11, 11, 9) | compression widths |
| \|µ\| = 8·len_ss | 128 | 256 | 512 | message / shared secret bits |
| 8·len_seed | 256 | 256 | 512 | seed bits |
| 8·len_H | 256 | 512 | 1024 | H output bits |
| ℓ1 (high payload) | 112 | 220 | 448 | bits, BCH(127,113,2) / (255,223,4) / (511,448,7) |
| ℓ2 (low payload) | 16 | 36 | 64 | bits, BCH(31,21,2) / (63,59,4) / (127,78,7) |
| ℓ3 (low codeword) | 26 | 60 | 113 | bits |
| stp | 32 | 64 | 128 | repetition stride |
| Core-SVP classical / quantum | 153 / 137 | 264 / 237 | 527 / 473 | bits (spec Table 4) |
| DFR log2 δ | −166.3 | −231.7 | −488.3 | spec Table 3 |

Sizes (bytes), specification vs the built reference library:

| instance | pk spec | pk impl | sk spec | sk impl | ct spec | ct impl | ss spec | ss impl | match |
|---|---|---|---|---|---|---|---|---|---|
| WeaverKEM-128 | 752 | 752 | **1760** | **1776** | 816 | 816 | 16 | 16 | sk **NO** |
| WeaverKEM-256 | 1312 | 1312 | 3072 | 3072 | 1536 | 1536 | 32 | 32 | yes |
| WeaverKEM-512 | 2880 | 2880 | 6400 | 6400 | 3392 | 3392 | 64 | 64 | yes |

sk spec = ⌈log2 q⌉·k·n/8 + |pk| + len_H + len_ss (Algorithm 7; the "12·k·n/8" printed
in the Algorithm 7 header is a spec typo — it must be ⌈log2 q⌉ and is 13 for q = 7681,
which is what reproduces 3072 / 6400). See the discrepancy list for the 1776 case.

## Pseudocode

### Weaver.CPAPKE.KeyGen (Algorithm 1)
```
seed0  ←$ B^len_seed
(seedA, seed_sk) = XOF(seed0)                      # 2·len_seed bytes
for i,j in [0,k):  Â[i][j] = ParseUniform_q(XOF_pub(seedA, i, j))   # NTT domain
ctr = 0
for i in [0,k):  s[i] ← CBD_η1(PRF(seed_sk, ctr));  ctr++
ŝ = NTT(s)
t = NTT^-1(Â ∘ ŝ)                                  # pure MLWR, NO error e
sk = Encode_{⌈log2 q⌉}(ŝ)
pk = (Encode_{d_t}(Compress_q(t, d_t)), seedA)
```

### Inv_q — randomized lifting (Algorithm 3)
```
ρ = PRF(seed)
for i in [0,k), j in [0,n):
    B = Preim±_q(t'^(i)[j], d_t)                   # error bucket of this coefficient
    ι = SampleIndex(ρ, i·n + j, |B|)               # rejection-sample ⌈log2|B|⌉-bit blocks
    t_lift^(i)[j] = Decompress_q(t'^(i)[j], d_t) + B[ι]
```
Property (spec §2.1): if x ←$ Z_q^+ and y = Compress_q(x,d) then Inv_q(y,d) is *exactly*
uniform on Z_q^+ — this is what the tight security reduction needs, and is why
encryption must not use the canonical Decompress.

### Weaver.CPAPKE.Enc(pk, µ; seed1) (Algorithm 2)
```
t'    = Decode_{d_t}(pk[0 : d_t·k·n/8]);  seedA = pk[d_t·k·n/8 : ...]
ctr = 0
t_lift = Inv_q(t', d_t; PRF(seed1, ctr));  ctr++    # randomized lift, NOT Decompress
t̂ = NTT(t_lift)
for i,j:  Â^T[i][j] = ParseUniform_q(XOF_pub(seedA, j, i))
for i in [0,k):  r[i] ← CBD_η2(PRF(seed1, ctr));  ctr++
r̂ = NTT(r)
w  = MsgEncode(µ)                                   # w ∈ Z_q^n
u  = NTT^-1(Â^T ∘ r̂)                                # NO error e′
v0 = NTT^-1(t̂^T ∘ r̂)                                # NO error e″
c1 = Encode_{d_u}(Compress_q(u, d_u))
c2 = Encode_{d_v}(Compress_q(v0 + w, d_v))
return ct = c1 ‖ c2
```

### MsgEncode (Algorithm 4)
```
µ̄ = µ[0 : ℓ1);  µ̇ = µ[ℓ1 : |µ|)
µ̃ = ECCEncode1(µ̄)                                   # high-layer BCH
µ̈ = ECCEncode2(µ̇)                                   # low-layer BCH
w = 0
for i in [0,n):      w_i += ((q−1)/2)·µ̃_i           # high layer
for i in [0,ℓ3):                                     # low layer, 4-way repetition
    w_{i}, w_{i+stp}, w_{i+2stp}, w_{i+3stp} += ⌊q/4⌋·µ̈_i
```

### Weaver.CPAPKE.Dec / MsgDecode (Algorithms 5, 6)
```
u = Decompress_q(Decode_{d_u}(c1), d_u)              # canonical (deterministic) here
v = Decompress_q(Decode_{d_v}(c2), d_v)
w' = v − NTT^-1(ŝ^T ∘ NTT(u))  mod+ q
# MsgDecode, successive interference cancellation:
for i in [0,ℓ3):                                     # 1. soft-decision on low layer
    ee = Σ_{r=0..3} | (w'_{i+r·stp} mod+ (q−1)/2) − ⌊q/4⌋ |
    µ'_i = (ee ≥ (q−1)/2) ? 0 : 1
µ̇ = ECCDecode2(µ');  µ̈ = ECCEncode2(µ̇)              # 2. BCH correct, 3. re-encode
w̄ = w' with ⌊q/4⌋·µ̈ subtracted at the 4·ℓ3 positions  # interference cancellation
for i in [0,n):  µ''_i = ⌈(2/q)·w̄_i⌋ mod 2          # 4. high layer
µ̄ = ECCDecode1(µ'')                                  # 5. BCH
return µ = µ̄ ‖ µ̇                                     # 6.
```

### KEM (Algorithms 7–9)
```
KeyGen:  z ←$ B^len_ss; (pk, sk_PKE) = CPAPKE.KeyGen
         sk_KEM = sk_PKE ‖ pk ‖ H(pk) ‖ z
Encaps:  m ←$ B^len_ss;  (K, r) = G(m ‖ H(pk));  ct = CPAPKE.Enc(pk, m; r);  return (ct, K)
Decaps:  m' = CPAPKE.Dec(sk_PKE, ct);  (K, r') = G(m' ‖ h_pk)
         ct' = CPAPKE.Enc(pk, m'; r');  if ct ≠ ct' then K = J(z, ct);  return K
```
Hashes (spec §2.4): XOF: B^len_seed → B^{2·len_seed}; G: B^{len_ss+len_H} →
B^{len_ss+len_seed}; H: {0,1}* → B^len_H; J: B^len_ss × {0,1}* → B^len_ss;
XOF_pub is level-independent (pseudorandomness only) and its output is parsed by a
fixed rejection-sampling parser ParseUniform_q that reads non-overlapping ⌈log2 q⌉-bit
little-endian candidates and keeps those < q.

## Implementation vs specification

Checked (reference tree `Implementations/Reference_Implementation/WeaverKEM-*`, the
files the Makefile builds): `params.h` (all constants), `kem_cca.c` (FO), `indcpa.c`
(Alg. 1/2/5), `poly_invq.c` + `invq_table_d9.h` (Alg. 3), `msgenc.c` (Alg. 4/6),
`symmetric-iccs.c` + `../api/auxfunc.c` (H/G/J/XOF/PRF), `bch_high.c`/`bch_low.c`.

Agreements:
- Every Table-2 constant (n, k, q, η1, η2, d_t, d_u, d_v) appears verbatim in
  `params.h` for all three modes, with the spec's own table quoted in a comment.
- The FO transform in `kem_cca.c` is exactly Algorithms 7–9: `hash_h(pk)` stored in sk,
  `hash_g(m ‖ H(pk))` giving `K ‖ r`, re-encryption, constant-time `verify` + `cmov`,
  `rkprf(z, ct)` fallback. `WEAVER_GBYTES = SSBYTES + SYMBYTES` = len_ss + len_seed ✓.
- Randomized lifting is *active*: `indcpa.c:14-15` defines `INV_Q_LIFTING` unless
  `NO_INV_Q_LIFTING` (which is commented out in `params.h:11`), so `indcpa_enc` takes the
  `polyvec_fromcompressed_pk` + `polyvec_invq` path, not `unpack_pk`. Decryption uses
  canonical `Decompress` (`unpack_ciphertext`) as the spec's asymmetric design requires.
- Randomness comes from the seeded DRNG: `kem_cca.c:20-23` defines `randombytes()` over
  `drng_algorithm` (the OpenSSL AES-CTR-DRBG `rng.c` is only reachable under
  `WEAVER_USE_SHAKE`, which the build does not define).
- No explicit error polynomials are sampled anywhere in `indcpa_keypair_derand` /
  `indcpa_enc` — MLWR as specified.

Discrepancies:
1. **(a) real deviation — secret-key size, Weaver-640.** Spec Algorithm 7 sets
   z ∈ B^len_ss (16 bytes at level 1). `params.h:104`
   `#define WEAVER_SECRETKEYBYTES (WEAVER_SK_Z_OFFSET + WEAVER_SYMBYTES)` uses
   `WEAVER_SYMBYTES` (= 32) instead, and `kem_cca.c:56` copies 32 bytes of z. Result:
   sk = 1776 bytes where the spec gives 1760. Levels 3 and 5 are unaffected only because
   there len_ss = len_seed. Not a weakening (z is longer), but the stated size is wrong
   and a spec-conformant implementation would not interoperate on sk parsing.
2. **(a) real deviation — PRF counter reuse in Enc.** Spec Algorithm 2 spends exactly
   one counter value on the lift (`ctr = 0`, then `ctr++`) so that r[i] uses counters
   1..k. `indcpa.c:351` calls `polyvec_invq(&pkpv, coins, nonce++)` — the callee
   (`poly_invq.c:88-104`) increments its *own copy* of the nonce once per module
   component (and again on every rejection restart), consuming nonces 0..k−1 (or more),
   while the caller's `nonce` has only advanced to 1. The CBD loop at `indcpa.c:365`
   then samples r[0..k−1] from PRF(coins, 1..k). So the PRF substreams 1..k−1 are used
   **twice**: once as lifting randomness for t_lift components 1..k−1 and once as the
   CBD noise r[0..k−2]. Both values stay secret in an honest execution, so this is not
   an immediate break, but it destroys the domain separation the spec's counter
   discipline is there to provide and makes the "Inv_q output is exactly uniform and
   independent of r" argument of §2.1 false for this code. It is also a KAT-visible
   incompatibility with any spec-faithful re-implementation.
3. **(c) equivalent-but-non-canonical — SampleIndex block width.** Spec §2.1 says
   SampleIndex reads ⌈log2 m⌉-bit blocks, m = |B|. `poly_invq.c:52-84` always reads
   3-bit blocks and accepts when the value is < `BUCKET_SZ[y]`. Bucket sizes are ≤ 8 for
   all three parameter sets (6/7 at d_t = 9, 7/8 at d_t = 10, 3/4 at d_t = 11), so the
   resulting distribution is still exactly uniform, but at d_t = 11 the spec would use
   2-bit blocks, so the consumed byte stream — and hence every ciphertext — differs from
   a literal reading of the spec.
4. **(b) spec ambiguity / typo — high-layer scale.** Algorithm 4 line 7 uses (q−1)/2;
   `msgenc.c:110` uses `WEAVER_HALFQ = (q+1)/2` (1665 vs 1664 at q = 3329), and
   MsgDecode's threshold in `poly_tomsg` likewise compares against (q+1)/2 rather than
   the spec's (q−1)/2. For odd q, (q+1)/2 is the natural centre; the spec text is
   almost certainly the typo, but the two are not the same map.
5. **(b) spec table appears wrong / (a) size deviation — layer-2 code.** Table 3 gives
   the low-layer codeword length ℓ3 as 26 / 60 / 113 bits. `msgenc.h` uses byte- or
   nibble-aligned codewords: `LOW_CODEWORD_BYTES` 4 (32 bits) at level 1,
   `LOW_CODEWORD_NIBBLES` 15 (60 bits) at level 3 ✓, `LOW_CODEWORD_BYTES` 15 (120 bits)
   at level 5. So ℓ3 is 32 and 120 where the spec says 26 and 113. Relatedly, Table 3's
   Weaver-1024 layer-2 entry "BCH(63,59,4)" is not a 4-error-correcting BCH code
   (4 parity bits cannot correct 4 errors); the code actually shipped is (63,39,4)
   (`msgenc.h:19`, 6 parity nibbles = 24 bits), which is the consistent one. Likewise
   level 5 ships 56 parity bits, not the 49 that BCH(127,78,7) implies.
6. **(non-crypto, robustness) unbounded-squeeze truncation.** `symmetric-iccs.c:27-31`
   caps a squeeze at `ICCS_XOF_MAX_BYTES` = 8192 with
   `outlen = ICCS_XOF_MAX_BYTES - state->pos;` — if `state->pos` ever exceeded 8192 this
   underflows to a huge `size_t` and the following `memcpy` overruns. Reaching it needs
   rejection sampling to consume > 8 KiB for one matrix entry (probability far below
   2^-100), so it is unreachable in practice, but it is an unchecked subtraction. Note
   also that each squeeze re-runs `pseudoXOF` over the whole prefix, i.e. matrix
   generation is O(len²); correctness holds because `pseudoXOF` is SM3 in counter mode
   and therefore prefix-stable (`api/auxfunc.c:482`).

Not verified: the BCH encoder/decoder tables in `bch31_21_2.h` / `bch127_112_2.h` were
not checked against generator polynomials, and the DFR claims of Table 3 were not
recomputed. The Weaver-256/512 instance sources were only spot-checked (`params.h`,
`msgenc.h`); the detailed line-level reading above is of the Weaver-128 tree, which is
byte-identical to the others apart from `params.h`/`msgenc.h` and the `invq` tables.
