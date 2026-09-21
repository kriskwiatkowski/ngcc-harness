# hash-15 Litchi — algorithm summary

Sponge-style hash family over a 1600-bit SPN permutation `P` (16 rounds of
ι, χ, θ, π). The mode is a sponge *with a Davies–Meyer-like feed-forward on the
capacity* ("Sponge-FP,pd" variant): after each permutation call the rate is
overwritten and the capacity is XORed back with the previous capacity. The
squeeze is a **parallel counter mode**: every `c`-bit output block is an
independent permutation call on `S_{l-1} ⊕ (M_{l-1} ‖ [i]_c)`.

Litchi is a sibling of hash-14 (Laurus) and uses the **identical permutation P**
(same 5-bit S-box, same five `Theta[t0..t4]` parameter vectors, same π, same 16
round constants `RC_r = 2^r ⊙ e_frac` in GF(2^64)); only the mode of operation
differs.

Specification: `hash-15-spec.pdf` (42 pages, English), Sect. 2.2–2.5.

## Parameters

| parameter | Litchi-512 | Litchi-768 | Litchi-1024 | Litchi-XOF | meaning |
|---|---|---|---|---|---|
| b (state width) | 1600 | 1600 | 1600 | 1600 | `P: {0,1}^1600 -> {0,1}^1600` |
| c (capacity) | 576 | 832 | 1088 | 1024 | Sect. 2.4 / 2.5 |
| r = 1600 - c (rate) | 1024 | 768 | 512 | 576 | bits absorbed per call |
| N (rounds) | 16 | 16 | 16 | 16 | Sect. 2.3 |
| fid | 0 | 0 | 0 | 1 | hash vs XOF |
| squeeze block | c = 576 | c = 832 | c = 1088 | c = 1024 | Sect. 2.2 step (4) |
| digest `|h|` | 512 | 768 | 1024 | arbitrary | must satisfy `|h| <= c-64` for fid=0 |
| claimed collision (classical) | 256 | 384 | 512 | min(d/2,512) | Table 4-11 |
| claimed preimage | 512 | 768 | 1024 | min(d,1024) | Table 4-11 |
| claimed 2nd preimage | 512 | 768 | 1024 | min(d,960) | Table 4-11 |
| claimed collision (quantum) | 128 | 192 | 256 | min(d/4,256) | Table 4-11 |

Digest length, specification vs the built reference library
(`OBSERVED/hash-15.txt`):

| instance | ALGORITHM_INSTANCE | c (impl) | d spec | digest_bits impl | digest_bytes impl | match |
|---|---|---|---|---|---|---|
| Litchi-512 | litchi_512 | 576 | 512 | 512 | 64 | yes |
| Litchi-768 | litchi_768 | 832 | 768 | 768 | 96 | yes |
| Litchi-1024 | litchi_1024 | 1088 | 1024 | 1024 | 128 | yes |
| Litchi-XOF | litchi_xof | 1024 | arbitrary | 1024 | 128 | yes (library pins d = 1024) |

Note the constraint `|h| <= c-64` for fid = 0 holds for all three hashes
(512<=512, 768<=768, 1024<=1024) — it is tight in every case.

## Pseudocode

### Permutation `P` (Sect. 2.3) — identical to Laurus, state = 25 lanes of 64 b
```
for r = 0 .. 15:
    iota:  A[0][0] ^= RC_r                       # RC_r = 2^r (*) 0xb7e151628aed2a6a
                                                 # in GF(2)[x]/(x^64+x^63+x^62+x^54+x^40+x^35+x^15+x+1)
    chi (320 parallel 5-bit S-boxes, plane-wise):
           B[0] = A0&A2&A3 ^ A2&A3&A4 ^ A0&A4 ^ A3&A4 ^ A1
           B[1] = A1&A3&A4 ^ A0&A1 ^ A2
           B[2] = A1&A2 ^ A3
           B[3] = A2&A3 ^ A4
           B[4] = A3&A4 ^ A0
    theta (per plane i, params t0..t4):
           E = X0^..^X4 ;  F = XOR_j (Xj <<< tj) ;  Yj = Xj ^ (E >>> tj) ^ F
           params: [31,1,4,21,22] [19,12,15,34,13] [28,35,58,9,23]
                   [55,18,5,27,44] [14,43,53,20,25]
    pi:    B[i][j] = A[(i+2j) mod 5][(3i+3j) mod 5]
```

### Hash / XOF: `h = Litchi[c,fid](M, |h|)`  (Sect. 2.2, steps (1)–(5))
```
r = 1600 - c

# (1) padding — plain 10* to a multiple of r, no length encoding
Mpad = M ‖ 1 ‖ 0^(r-1-(|M| mod r)) = M_0 ‖ .. ‖ M_{l-1},  l = ceil((|M|+1)/r)

# (2) initial state — the ONLY domain separation between instances
S_0 = [ 2^63 * fid + c ]_1600           # 1600-bit big-endian integer

# (3) absorb blocks M_0 .. M_{l-2}   (the LAST block M_{l-1} is not absorbed here)
for i = 1 .. l-1:
    S_i = P( S_{i-1} XOR (M_{i-1} ‖ 0^c) )  XOR  (0^r ‖ LSB_c(S_{i-1}))
                                            #  ^ DM-like capacity feed-forward

# (4) squeeze — parallel, counter-indexed, one permutation call per block
for i = 1 .. ceil(|h|/c):
    ST  = S_{l-1} XOR ( M_{l-1} ‖ [i]_c )   # counter XORed into the capacity
    h_i = LSB_c( P(ST) ) XOR LSB_c(ST)

# (5)
return MSB_|h|( h_1 ‖ h_2 ‖ ... )
```
Variable digest lengths: only `Litchi-XOF` (fid = 1, c = 1024) is variable.
A shorter XOF output is a prefix of a longer one — the defined XOF semantics,
with a single `Litchi-XOF` object in the spec. The four instances are separated
by `S_0 = [2^63·fid + c]_1600`: `c` differs for the three hashes and `fid`
differs for the XOF, so `Litchi-XOF` (c = 1024, fid = 1) and `Litchi-1024`
(c = 1088, fid = 0) — which both produce 1024 bits in the built library —
differ in *both* the initial state and the rate, and neither output is a
truncation of the other.

## Implementation vs specification

Checked: `src/Litchi-512/litchi_512.c` and the 768/1024/XOF files. Diff shows
the four differ only in the final wrapper call:
`litchi(h, 512, in, inlen, 576, 0)` / `(768, …, 832, 0)` / `(1024, …, 1088, 0)` /
`litchi(out, outlen, in, inlen, 1024, 1)`. `CryptHash_AlgorithmInstance.c` is a
3-line wrapper; `drng.c`/`KAT_CryptHash.c` are the KAT harness.

Verified agreements:

- **Rounds:** `#define NROUNDS 16` = spec N = 16 (`litchi_512.c`). Full count.
- **Permutation:** χ, θ (all 25 rotation constants), π and the 16 round
  constants match Sect. 2.3 / Table 2-1 / Table 2-2 exactly. I diffed the
  permutation source against Laurus's `F1600_StatePermute` — byte-identical up
  to whitespace, consistent with the two specs carrying the same Sect. 2.3.
- **Rate/capacity:** `r = 1600 - c` and the per-instance `c` values
  576 / 832 / 1088 / 1024 match Sect. 2.4 and Sect. 2.5 exactly. No mismatch.
- **Initial state / domain separation:** `S[24] = (fid << 63) + c`
  = `S_0 = [2^63·fid + c]_1600` (word 24 is the least-significant lane).
- **Absorb:** rate words `A[j] = M[j] ^ S[j]`, capacity words `A[j] = S[j]`,
  permute, then `S[j] = A[j]` on the rate and `S[j] ^= A[j]` on the capacity —
  literally `P(S ⊕ (M‖0^c)) ⊕ (0^r ‖ LSB_c(S))` of step (3).
- **Block count:** the absorb loop runs `floor(|M|/r)` times, which equals
  `l-1` for `l = ceil((|M|+1)/r)` for every `|M|` (including `|M| = 0` and
  `|M|` a multiple of `r`), so exactly `M_0..M_{l-2}` are absorbed and
  `M_{l-1}` is the padded tail used in the squeeze — as the spec requires.
- **Padding:** plain `10*` to a multiple of `r`, with the bit-level tail mask
  `in[pos/8] & (0xFF << (8-pos%8)) | 1 << (7-pos%8)` and `0x80` when the tail is
  byte-aligned. Matches Sect. 2.2 "Padding". No length encoding, as specified.
- **Squeeze:** `S[24] ^= i+1` before building `ST` (so the counter is part of
  both `P(ST)` and the `LSB_c(ST)` feed-forward, as in step (4)), permute,
  `A[j] ^= S[j]` on the capacity words, output `A[r/64 .. 24]` = `LSB_c`,
  restore `S[24]`. Counter starts at 1 (`i+1` with loop `i` from 0), matching
  the spec's `1 <= i <= ceil(|h|/c)`.
- **Output truncation:** `MSB_|h|` with a bit-level mask on the last partial
  byte.

Discrepancies: **none found.** Round count, padding rule, rate/capacity split,
domain-separation constant and the counter-mode squeeze all match the spec
exactly; nothing that the spec says should vary is hard-wired (unlike Laurus's
`g1`, where the 1088 constant is fixed — Litchi's squeeze correctly uses
`c/64` words per instance).

Notes (not deviations):

- `CryptHash()` in Litchi-512/768/1024 ignores its `digest_len_bits` argument
  and always writes `DIGEST_BIT_LENGTH/8` bytes; `litchi_xof` is called with
  the compile-time `DIGEST_BIT_LENGTH` (1024), not the caller's value, so the
  shared library pins the XOF to 1024 bits. Same API shortcut as hash-14.
- `ROL/ROR` would be UB on a 0-bit rotation; no `theta` constant is 0.
- Litchi's claimed quantum collision resistance (Table 4-11) is `c/4`, *lower*
  than the generic `2^{|h|/3}`; the spec acknowledges this is a proof artefact.
  Not independently checked.
- Not verified: the mode security proofs of Sect. 4.1.1 and the permutation
  cryptanalysis of Sect. 4.1.2. Because Litchi and Laurus share the same
  permutation, any structural result on `P` (e.g. the zero-sum distinguisher
  the Laurus spec reports for full 16 rounds) applies to both candidates.
