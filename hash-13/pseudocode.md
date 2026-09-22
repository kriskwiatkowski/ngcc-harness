# hash-13 JuziHash — algorithm summary

Permutation-based hash family built on one 24-round, 2048-bit SPN permutation
`P2048` (8-bit Feistel S-box, AES MixColumns MDS, byte permutations, round
constants from pi). Two modes share the permutation and the message-injection
path: **JuziHash-512** is a plain sponge (rate 1024 / capacity 1024) truncated
to 512 bits; **JuziHash-1024** is a *full-state Davies–Meyer-like* mode that
feeds the old capacity branch forward and outputs the 1024-bit capacity
projection (the rate half stays hidden, which is what kills length extension).

Specification: `hash-13-spec.pdf` (37 pages, English), Sect. 2–4 + Appendix A/B.

## Parameters

| parameter | JuziHash-512 | JuziHash-1024 | meaning |
|---|---|---|---|
| b | 2048 | 2048 | permutation state width (bits) |
| h | 2048 | 2048 | chaining state width |
| m (rate) | 1024 | 1024 | message block / rate (S0,S1,S4,S5) |
| capacity | 1024 | 1024 | S2,S3,S6,S7 |
| rounds r | 24 | 24 | `P2048^(24)`, r a multiple of 4 |
| mode | sponge `f_sp` | full-state DM `f_DM` | Sect. 3.5.1 / 3.5.2 |
| d (digest) | 512 | 1024 | Sect. 4.4 |
| output projection | `Tr512 = S0‖S1` (rate) | `Cap1024 = S2‖S3‖S6‖S7` | Sect. 4.4 |
| H(-1) domain constant | `0x0200‖0^2032` | `0x0400‖0^2032` | Sect. 4.2 (only domain sep.) |
| max message ℓ | < 2^64 bits | < 2^64 bits | Sect. 4.1 |
| claimed collision | 2^256 | 2^512 | spec Table 2 |
| claimed (2nd-)preimage | 2^512 | 2^1024 | spec Table 2 |

Digest length, specification vs the built reference library
(`OBSERVED/hash-13.txt`):

| instance | d spec | digest_bits impl | digest_bytes impl | match |
|---|---|---|---|---|
| JuziHash-512 | 512 | 512 | 64 | yes |
| JuziHash-1024 | 1024 | 1024 | 128 | yes |

Only two instances exist; there is no XOF variant and no variable-output mode.
`CryptHash()` rejects any `digest_len_bits != DIGEST_BIT_LENGTH`, so digest
length is fixed per library, not a runtime parameter.

## Pseudocode

### Permutation `P2048^(r)` (spec Algorithm 1, Sect. 3.3; layout Appendix A)
```
state = 8 words S0..S7, each 256 bits = 32 bytes  (2048 bits total)
RC(i) = r(i) ‖ 0^1536   # 512 bits, xored into S0‖S1 only
r(0)  = floor((pi-3)*2^512)  as 8 big-endian 64-bit words
r(i+1)_j = rotl64(r(i)_j,3) ^ rotl64(r(i)_j,7) ^ rotl64(r(i)_j,12)

for t = 0 .. r-1:                       # r = 24
    if t mod 4 == 0: S0‖S1 ^= r(t/4)    # AddConstant
    SubBytes:  every byte  b <- S(b)
    MDS:       for each byte index j<32:
                   (S0j,S1j,S2j,S3j)^T <- A * (...)^T   # A = AES MixColumns
                   (S4j,S5j,S6j,S7j)^T <- A * (...)^T
    BytePerm_t:  (depends on t mod 3, Appendix A.4)
        t≡0 (3): rotate each 4-byte group of S_i left by (i mod 4)
        t≡1 (3): rotate each 16-byte group of S_i left by 4*(i mod 4)
        t≡2 (3): rotate the 512-bit pair (S_i‖S_{i+4}) left by 16*i bytes, i<4
```
8-bit S-box (Sect. 3.1), 3-round Feistel over the 4-bit S4 table:
```
x = L0‖R0;  R1 = L0 ^ S4(R0);  R2 = R0 ^ S4(R1);  R3 = R1 ^ S4(R2)
S(x) = R2‖R3
```

### Update functions (Sect. 3.5)
```
In(M) = (M0, M1, 0, 0, M2, M3, 0, 0)          # M = M0‖M1‖M2‖M3, 256 bits each
f_sp(S, M) = P2048^(24)( S ^ In(M) )
f_DM(S, M): Y = f_sp(S, M)
            return (Y0,Y1, S2^Y2, S3^Y3, Y4,Y5, S6^Y6, S7^Y7)
```

### Hash(M, ℓ)  (Sect. 4.1–4.4)
```
# 1. padding (Sect. 4.1) — zero extension + mandatory length block
z = (-ℓ) mod 1024
Padded = M ‖ 0^z ‖ Len1024(ℓ),  Len1024(ℓ) = 0^960 ‖ enc64_BE(ℓ)
split into N blocks M(1..N);  M(N) is always the length block

# 2. initial state (Sect. 4.2) — the only domain separation
H(-1) = 0x0200‖0^2032   (512)      |  0x0400‖0^2032   (1024)
H(0)  = f_sp(H(-1), 0^1024)        |  f_DM(H(-1), 0^1024)
        # concrete H(0) values are tabulated in Appendix B

# 3. absorb (Sect. 4.3)
for i = 1..N:  H(i) = f_sp(H(i-1), M(i))   |   f_DM(H(i-1), M(i))

# 4. output (Sect. 4.4) — no squeezing loop, single truncation
return S0‖S1 of H(N)              (512-bit digest)
return S2‖S3‖S6‖S7 of H(N)        (1024-bit digest)
```
There is no squeeze phase and no output-length encoding: the digest is one
fixed projection of the final state. Variable digest lengths are not supported.

## Implementation vs specification

Checked: `src/JuziHash-512/CryptHash_AlgorithmInstance.c` and
`src/JuziHash-1024/CryptHash_AlgorithmInstance.c` (the two files differ only in
the 5 lines listed below). `drng.c` is the KAT RNG only; `KAT_CryptHash.c` is
the shipped KAT driver and is excluded by `hash-13/Makefile`.

Agreements verified line by line:

- **Rounds:** `juzi_ref_permute` runs `group = 0..5` x `k = 0..3` = **24 rounds**,
  round constant added once per group of 4 — exactly spec Algorithm 1.
- **Round constants:** the 8 pi words match Sect. 3.4 verbatim
  (`CryptHash_AlgorithmInstance.c:202-207`), the update
  `rotl(3)^rotl(7)^rotl(12)` matches, and `juzi_ref_add_rc` xors them into
  `s[0..63]` = S0‖S1 only, i.e. `RC = r(i)‖0^1536` (Appendix A.5).
- **S-box:** `juzi_sbox8` is the 3-round Feistel of Sect. 3.1 with the exact S4
  table of Table 1.
- **MDS:** `juzi_ref_mds_group` implements the AES MixColumns rows
  (02 03 01 01 / 01 02 03 01 / 01 01 02 03 / 03 01 01 02) over
  z^8+z^4+z^3+z+1, applied to (S0..S3) and (S4..S7) per byte column — Appendix A.3.
- **BytePerm:** `juzi_ref_byteperm` uses `round % 3` with shifts
  `w%4`, `4*(w%4)`, `16*w` — matches Appendix A.4 exactly. (Note Sect. 3.3's
  prose says the MDS diffusion dimension cycles with period 4, whereas the
  normative eight-word description in Appendix A puts a period-3 cycle in the
  byte-permutation layer with a fixed MDS grouping. These are the two views of
  the same 4-D array; the implementation follows Appendix A. Classified as a
  **spec presentation ambiguity**, not a deviation.)
- **Injection / modes:** `juzi_update_sp` xors the block into S0,S1,S4,S5
  (`In(M)`, Appendix A.6); `juzi_update_dm` additionally xors the *saved old*
  capacity into the new capacity — `f_DM` of Sect. 3.5.2.
- **Padding:** `juzi_make_data_block` zero-fills the tail, and
  `juzi_make_length_block` always appends a separate 1024-bit block with
  `enc64_BE(ℓ)` in the last 8 bytes — `M‖0^z‖0^960‖enc64(ℓ)`, Sect. 4.1. The
  length block is appended unconditionally, including for ℓ = 0 and for ℓ a
  multiple of 1024.
- **Initialisation / domain separation:** `state[0] = 0x02` (512) vs `0x04`
  (1024), then one absorb of an all-zero block with the variant's own update
  function — Sect. 4.2.
- **Output:** 512 → first 64 bytes (S0‖S1); 1024 → S2‖S3‖S6‖S7 copied
  explicitly — Sect. 4.4.
- **Strong end-to-end check:** I compiled the two reference permutation files
  standalone (in a scratch copy, nothing in the submission tree was touched or
  built) and printed the computed `H(0)`. Both reproduce **Appendix B.1 and
  B.2 byte for byte**, which validates the S-box, MDS, byte-permutation, round
  constants, round count and both update functions against the specification.

Discrepancies: **none found.** No round-count reduction, no padding change, no
rate/capacity mismatch, no hard-wired constant that the spec says should vary.

Remarks (not deviations):

- Domain separation between the two instances rests entirely on the 16-bit
  `H(-1)` prefix (0x0200 / 0x0400); the spec states this explicitly (Sect. 4.1
  "No separate finalization domain constant is used"). Since the two variants
  also use different update functions and different output projections, a
  cross-variant prefix relation is not possible.
- The bit-oriented API masks the unused low bits of the final partial byte
  (`juzi_make_data_block`), so two byte buffers that differ only in bits beyond
  `msg_len_bits` hash identically. This is the intended bit-string semantics.
- The AVX2/bitsliced constant-time claims of Sect. 5.9 / Appendix C are not
  exercised by this reference code, which uses a 16-entry `JUZI_S4[]` array
  lookup (`CryptHash_AlgorithmInstance.c:86`). The lookup is on a 16-byte table
  and the index is message-derived; the spec's cache-timing claim is explicitly
  scoped to the optimized implementations, so this is a documented scope
  limitation rather than a deviation.
- Not verified: the MILP active-S-box claim (>=200 active S-boxes over 8
  rounds) and all security claims in Sect. 5 — no cryptanalysis was attempted.
