# hash-01 AFS-TrEDM — algorithm summary

A 1600-bit permutation-based hash in an "aligned TrEDM" (Truncated Encrypted
Davies-Meyer) sponge: the permutation `P = h o g` is split in half, and each
absorbed block is processed as `X ^= B; T = proj_S(X); X = g(X); X[S] ^= T;
X = h(X)`, i.e. a Davies-Meyer feed-forward of the capacity window *between*
the two halves. The feed-forward window, the chaining window and the squeezing
window are all the same bit set `S` (the whole capacity) — that is what
"aligned" means. There is **no squeezing loop**: the digest is the leftmost `d`
bits of the capacity after the last absorb, and `c = d + 64` for every
instance. The permutation `AFS-p-S6[1600, nr]` is an ARX design: 25 lanes each
through a 64-bit ARX-Feistel S-box (AFS64_t5_k2), then a GF(32) Cauchy-MDS
linear layer rotated among 6 projective directions.

Specification: `hash-01-spec.pdf` (76 pages), §1.3 (Table 1, parameters),
§1.4 (Alg. 1-2, parsing and frame encoding), §1.5 (Alg. 3, S-box), §1.6
(linear layer, Alg. 4-5), §1.7 (round constants), §1.8 (Alg. 6, permutation and
the g/h split), §1.9 (Alg. 7, IV), §1.10 (Alg. 8, the mode), §3.1 Table 8
(security claims). English-language spec.

## Parameters

| parameter | AFS-TrEDM-512 | AFS-TrEDM-768 | AFS-TrEDM-1024 | meaning |
|---|---|---|---|---|
| state width `b` | 1600 | 1600 | 1600 | 25 x 64-bit lanes (5x5x64) |
| rate `r` | 1024 | 768 | 512 | bits absorbed per call |
| capacity `c` | 576 | 832 | 1088 | `c = b - r = d + 64` |
| feed-forward width `a` | 576 | 832 | 1088 | `a = c`, the whole capacity |
| alignment window `S` | lanes 16..24 | lanes 12..24 | lanes 8..24 | `state[r..1599]` |
| rounds `nr` | 12 (6+6) | 20 (10+10) | 24 (12+12) | `g` = rounds 0..s-1, `h` = s..2s-1 |
| split `s = nr/2` | 6 | 10 | 12 | |
| S-box | AFS64_t5_k2 | same | same | 64-bit ARX-Feistel, A8=11000011, K8=[17,24,1,1,16,31,24,0] |
| linear layer | AFS-LMDS-1600-S6 | same | same | `mu o pi o rho o M_col`, 6-direction rotation |
| round constants | 300 | 500 | 600 | `RC32(ir,l)`, SplitMix64, 32-bit, one per (round, lane) |
| digest `d` | 512 | 768 | 1024 | leftmost `d` bits of `S` |
| status | mandatory | optional | mandatory | §1.3 |
| classical collision | 256 | 384 | 512 | `d/2` (Table 8) |
| classical preimage | 512 | 768 | 1024 | `d` |
| classical 2nd-preimage | 512 | 768 | 1024 | `min{d, c-log2(lmax)} = d` |
| quantum collision | 170.7 | 256 | 341.3 | `d/3` |
| quantum pre / 2nd-pre | 256 | 384 | 512 | `d/2` |

Digest sizes, specification vs the built reference library
(`OBSERVED/hash-01.txt`):

| instance | digest spec (bits) | digest impl (bits) | bytes | match |
|---|---|---|---|---|
| AFS-TrEDM-512 | 512 | 512 | 64 | yes |
| AFS-TrEDM-768 | 768 | 768 | 96 | yes |
| AFS-TrEDM-1024 | 1024 | 1024 | 128 | yes |

## Pseudocode

### Padding / frame encoding — spec Alg. 2 (§1.4)

```
suffix <- enc64(|M|) || enc16(d) || enc16(r) || enc16(c) || enc16(2)   # 128 bits
j      <- ( -|M| - 1 - 128 ) mod r
F      <- M || 1 || 0^j || suffix                    # |F| is a multiple of r
```

The 128-bit suffix commits to the message length *and* to `(d, r, c, version)`,
so the three instances have different absorbed inputs even for the same bytes.
The last frame occupies one rate block if `(|M| mod r) + 1 + 128 <= r`, else
two. The IV additionally binds `nr`, the S-box name and the linear-layer name.
Max message length: `2^64 - 1` bits.

### Hash — spec Alg. 8 (§1.10)

```
 1  (r, c, nr) <- by d: (1024,576,12) / (768,832,20) / (512,1088,24)
 2  s <- nr/2 ;  X <- IV_d                            # 25 lanes, Alg. 7
 3  B_0..B_{L-1} <- parse( frame_d(M, r, d, c), r )   # no tail block
 4  for k = 0 .. L-1:                                 # absorb
 5      X[0 .. r-1] <- X[0 .. r-1] XOR B_k            # rate lanes only
 6      T <- proj_S(X)                                # back up the capacity
 7      X <- g(X)                                     # rounds 0 .. s-1
 8      X[S] <- X[S] XOR T                            # EDM feed-forward
 9      X <- h(X)                                     # rounds s .. 2s-1
10  return left_d( proj_S(X) )                        # lanes r/64 .. r/64+d/64-1
```

There is no separate squeezing phase: `d <= c` always (`c = d + 64`), so one
truncation of the capacity suffices.

### Permutation AFS-p-S6[1600, nr] — spec Alg. 6 (§1.8)

```
round(A, ir):
    for l = 0..24:  A[l] <- AFS64( A[l], RC32(ir, l) )     # nonlinear layer
    A <- L(A, ir)                                          # linear layer
permute(A, nr):  for ir = 0..nr-1: A <- round(A, ir)
g(A) = rounds 0..s-1 ;  h(A) = rounds s..2s-1   # round index CONTINUES into h,
                                                # so RC32 and the S6 direction
                                                # schedule do not reset
```

### AFS-64 S-box — spec Alg. 3 (§1.5), 8 ARX-Feistel steps

```
x <- W >> 32 ;  y <- W mod 2^32
x <- (x + ROTR32(y,17)) XOR k        # step 0, modular add
y <- (y + ROTR32(x,24)) XOR k        # step 1, modular add
x <- x XOR ROTR32(y, 1)              # step 2
y <- y XOR ROTR32(x, 1)              # step 3
x <- x XOR ROTR32(y,16)              # step 4
y <- y XOR ROTR32(x,31)              # step 5
x <- (x + ROTR32(y,24)) XOR k        # step 6, modular add
y <- (y + ROTR32(x, 0)) XOR k        # step 7, modular add (ROTR by 0 = identity)
return (x << 32) | y
```

The four modular additions are the only nonlinearity. `k = RC32(ir, l)`.

### Linear layer — spec Alg. 4-5 (§1.6)

```
L(A, ir):  dir <- [INF,0,1,2,3,4][ir mod 6]
           if dir != INF: A <- tau_dir(A)      # lane rewiring, tau_d(x,y)=((y-d*x) mod 5, x)
           A <- L_P(A)
           if dir != INF: A <- tau_dir^{-1}(A)

L_P(A) = mu o pi_AFS o rho_AFS o M_col :
  M_col : per coordinate x, U_x = A[x,0] + a*A[x,1] + ... + a^4*A[x,4] in GF(32)
          (bit-sliced, 64 parallel symbols);  V = C * U  with the Cauchy matrix C
  rho   : A[x,y] <- ROTR64(A[x,y], rho[x,y])         # Table 3
  pi    : A[x,y] -> A[(x+y) mod 5, 3x mod 5]         # 1 + 24 orbit structure
  mu    : A[i]  <- A[i] XOR ROTR64(A[i],17) XOR ROTR64(A[i],32)
```

`GF(32) = F2[a]/(a^5+a^2+1)`; `a*(s0..s4) = (s4, s0, s1^s4, s2, s3)`.

### Round constants — §1.7

```
idx <- 25*ir + l
z   <- SplitMix64( 0xB4C5F1D62E1738A9 + idx * 0x9E3779B97F4A7C15 )
RC32(ir,l) <- low32( z XOR (z >> 32) )
```

### IV — spec Alg. 7 (§1.9)

```
s  <- "AFS-TrEDM-v2|d=<d>|r=<r>|c=<c>|b=1600|nr=<nr>|sbox=AFS64_t5_k2|linear=AFS-LMDS-1600-S6"
x  <- FNV-1a64(s)
for i = 0..24:  x += 0x9E3779B97F4A7C15 ; IV[i] <- splitmix64_finalize(x)
```

### Variable digest lengths

Not an XOF; `d` is fixed per instance. `CryptHash()` rejects any
`digest_len_bits != DIGEST_BIT_LENGTH` with `-11`, and the digest is the
leftmost `d` bits of the capacity window (a whole number of lanes for all three
instances).

## Implementation vs specification

Checked: `hash-01/src/AFS-TrEDM-512/{afs_sbox64.c, afs_lmds1600_s6.c,
afs_p1600.c, afs_tredm.c, CryptHash_AlgorithmInstance.c}`. The three instance
directories ship **byte-identical** `.c` sources; only
`CryptHash_AlgorithmInstance.h` differs (`ALGORITHM_INSTANCE`,
`DIGEST_BIT_LENGTH`), and `afs_p1600.h` derives the round split from
`DIGEST_BIT_LENGTH`.

Verified agreements (computed, not just eyeballed):

- **S-box**: `afs64_t5_k2()` reproduces Alg. 3 line for line, including the
  explicit `ROTR32(x, 0)` in step 7 and the `^= k` placement on steps 0/1/6/7
  only.
- **Round constants**: `afs_round_lane_constant()` is exactly the §1.7 formula.
  I recomputed all 300 / 500 / 600 constants for the three tiers: each set is
  entirely **nonzero and collision-free**, confirming the check the spec
  attributes to `check_round_constants.py`.
- **IVs**: I re-derived `IV_512`, `IV_768`, `IV_1024` from the domain strings
  of Alg. 7 (FNV-1a64 seed + 25 SplitMix64 outputs) and they match the
  hard-coded tables in `afs_tredm.c:12-34`.
- **Cauchy MDS matrix `C`** (`afs_lmds1600_s6.c:34-40`) matches Table 2. I
  verified over `GF(32) = F2[a]/(a^5+a^2+1)` that **every** square minor of `C`
  is non-singular (so `C` really is MDS, branch number 6), and I solved for the
  Cauchy sets: `X = {1F, 0C, 1A, 09, 06}`, `Y = {07, 02, 0D, 1E, 08}`, which
  matches the (partly garbled) sets printed in §1.6.2 — they are disjoint with
  distinct elements, as required.
- **`xtime`** (`gf32_xtime`) is exactly the §1.6.1 map `(s4, s0, s1^s4, s2, s3)`.
- **`rho` table** matches Table 3 entry for entry; **`pi`** is
  `(x,y) -> ((x+y) mod 5, 3x mod 5)`; **`mu`** is
  `X ^ ROTR64(X,17) ^ ROTR64(X,32)` — all as §1.6.3-§1.6.5.
- **`tau_dir` and its inverse**: `tau_d(x,y) = ((y - d*x) mod 5, x)` and
  `tau_d^{-1}(x,y) = (y, (x + d*y) mod 5)`; I checked these compose to the
  identity. Direction schedule `[INF,0,1,2,3,4][ir mod 6]` matches Table 4.
- **Layer order** `M_col -> rho -> pi -> mu` matches Alg. 4, and
  `tau -> L_P -> tau^{-1}` matches Alg. 5.
- **Round counts are the specified ones**: `AFS_P1600_SPLIT_ROUNDS` = 6/10/12
  for `DIGEST_BIT_LENGTH` 512/768/1024 (`afs_p1600.h`), giving 12/20/24 total
  rounds, matching Table 1. The round index passed to `h` starts at `s`, not 0
  (`afs_p1600_h()`), so `RC32` and the direction schedule are continuous across
  the g/h boundary exactly as §1.8 requires. The per-directory
  `PERF_SPLIT_ROUNDS` defaults in the shipped Makefiles are also 6/10/12, so
  even the "performance profile" build is full-round.
- **Mode**: `absorb_prepared_block()` is exactly the five steps of §1.10 in
  order, with `T` taken after the block XOR and the feed-forward applied to the
  capacity lanes between `g` and `h`.
- **Rate/capacity split**: `rate_bits/capacity_bits` = 1024/576, 768/832,
  512/1088, and `S` starts at lane `r/64`, matching Table 1 and §1.3
  (`A[16..24]`, `A[12..24]`, `A[8..24]`).
- **Frame encoding**: `absorb_final_framed_blocks()` builds
  `M||1||0^j||enc64(|M|)||enc16(d)||enc16(r)||enc16(c)||enc16(2)` with
  big-endian fields and MSB-first bit placement, matching Alg. 2. The
  byte-aligned fast path writes the same bytes (I checked that `suffix_byte`
  can never collide with the `0x80` byte, because the suffix always ends the
  final rate block and `zero_pad = 7 mod 8` in that case).
- **Digest extraction**: `extract_digest()` writes `d/64` big-endian lanes from
  `A[r/64]`, i.e. `left_d(proj_S(X))`.

Discrepancies and observations:

- **(b) spec gap — the lane serialisation `l <-> (x,y)` is never defined.**
  §1.7 indexes round constants by a flat lane index `l in [0,24]`, §1.10
  places the rate in "lanes A[0..r/64-1]", and §1.6 indexes `rho` and `pi` by
  `(x,y)` — but the spec only says "under the lane-serialization convention of
  §1.2", and §1.2 defines no such convention. The implementation uses
  `l = x + 5y` (`AFS_IDX` in `afs_lmds1600_s6.c:23`). The alternative
  `l = 5x + y` would give a different (and incompatible) hash with the same
  written specification. This is a genuine reproducibility gap: an independent
  implementer has a 50/50 chance of not matching the KATs. **Worth reporting.**
- **(b) latent hazard — the round count is a compile-time constant while the
  mode is run-time dispatched.** `afs_tredm_hash()` (`afs_tredm.c:312-326`)
  selects `r`, `c` and the IV at run time from `digest_len_bits` and happily
  accepts all three values, but `g`/`h` use `AFS_P1600_SPLIT_ROUNDS`, fixed at
  compile time from `DIGEST_BIT_LENGTH`. In the `AFS-TrEDM-512` build,
  `afs_tredm_hash(768, ...)` would run the 768-bit rate/capacity/IV through a
  **12-round** permutation instead of the specified 20. The exported
  `CryptHash()` guards this (`digest_len_bits != DIGEST_BIT_LENGTH` -> `-11`),
  so the built library and the KATs are unaffected, but `afs_tredm_hash()` is
  an exported symbol with no such guard and its own API contract advertises all
  three lengths. This is the "hard-wired round count" pattern; here it is
  currently unreachable, so I classify it as a latent defect, not a KAT-visible
  deviation.
- **(b) no length-limit enforcement.** §1.4 caps `|M|` at `2^64 - 1` bits; the
  code accepts any `unsigned long long` (so `|M| = 2^64 - 1` is the natural
  cap) but never rejects out-of-range values — harmless in practice.
- **(b) `absorb_final_framed_blocks()` uses `unsigned` for bit offsets.** All
  the quantities involved are bounded by `2r <= 2048`, so no overflow; noted
  only because the surrounding code mixes `unsigned` and `unsigned long long`.
- **Not verified:** the claimed active-S-box lower bounds and solver UNSAT
  results of §3.3, the indifferentiability argument of §3.2, and the claim that
  the cumulative `rho` offset along the 24-lane `pi` orbit is 23 (I did not
  recompute it). No differential/linear/rotational analysis was run. The
  candidate's KATs pass in the build for all three instances
  (`hash-01/security_findings.md`), which shows self-consistency only.
- **No deviation found** in round count, padding/frame rule, rate/capacity
  split, IV, round constants, S-box, or MDS matrix. Everything the spec states
  numerically that I could recompute, I recomputed and it matched.
