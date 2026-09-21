# hash-14 Laurus — algorithm summary

Sponge-like ("VFB variant", FWP-inspired) hash family over a 1600-bit SPN
permutation `P` with 16 rounds (ι, χ, θ, π — Keccak-shaped but with a
different 5-bit S-box, a 12-branch-number θ, and a different π). The mode is
*not* a plain sponge: a 1536-bit chaining state `S` is kept, the permutation is
run on `[counter]64 ‖ 1536-bit` input, and the permutation output is fed back
with an XOR of a rotated copy of the absorbed data (`g0`). The squeeze is a
*parallel counter mode*: every output block is produced by an independent
permutation call whose only difference is the 64-bit counter word.

Specification: `hash-14-spec.pdf` (40 pages, English), Sect. 2.2–2.5.

## Parameters

| parameter | Laurus-512 | Laurus-768 | Laurus-1024 | Laurus-XOF | meaning |
|---|---|---|---|---|---|
| permutation width | 1600 | 1600 | 1600 | 1600 | `P: {0,1}^1600 -> {0,1}^1600` |
| t | 64 | 64 | 64 | 64 | counter/domain lane (A[0][0]) |
| b | 1536 | 1536 | 1536 | 1536 | chaining state `S_i` (t+b = 1600) |
| c (security param.) | 512 | 768 | 1024 | 512 | Sect. 2.2 "The Laurus Algorithm" |
| r = 1536 - c (rate) | 1024 | 768 | 512 | 1024 | bits absorbed per permutation call |
| last block `M_l` | 512 | 512 | 512 | 512 | fixed 512 bits, spec "Padding" |
| N (rounds) | 16 | 16 | 16 | 16 | Sect. 2.3 |
| fid | 0 | 0 | 0 | 1 | hash vs XOF |
| squeeze block | 1088 | 1088 | 1088 | 1088 | spec step (5); see note below |
| digest `|h|` | 512 | 768 | 1024 | arbitrary | Sect. 2.4 / 2.5 |
| claimed collision (classical) | 256 | 384 | 512 | min(d/2,256) | Table 4-11 |
| claimed (2nd-)preimage | 512 | 768 | 1024 | min(d,512) | Table 4-11 |
| claimed collision (quantum) | 512/3 | 256 | 1024/3 | min(d/3,512/3) | Table 4-11 |

Digest length, specification vs the built reference library
(`OBSERVED/hash-14.txt`):

| instance | ALGORITHM_INSTANCE | d spec | digest_bits impl | digest_bytes impl | match |
|---|---|---|---|---|---|
| Laurus-512 | laurus_512 | 512 | 512 | 64 | yes |
| Laurus-768 | laurus_768 | 768 | 768 | 96 | yes |
| Laurus-1024 | laurus_1024 | 1024 | 1024 | 128 | yes |
| Laurus-XOF | laurus_xof | arbitrary (`d < 2^64`) | 2048 | 256 | yes (library pins d = 2048) |

## Pseudocode

### Permutation `P` (Sect. 2.3), state A[5][5][64] = 25 lanes of 64 bits
```
for r = 0 .. N-1:                       # N = 16
    iota:  A[0][0] ^= RC_r              # RC_r = 2^r (*) C in GF(2^64)/(x^64+x^63+x^62+x^54+x^40+x^35+x^15+x+1)
                                        # C = 0xb7e151628aed2a6a  (frac. part of e)
    chi:   (plane-wise, 320 5-bit S-boxes in parallel)
           B[0] = A0&A2&A3 ^ A2&A3&A4 ^ A0&A4 ^ A3&A4 ^ A1
           B[1] = A1&A3&A4 ^ A0&A1 ^ A2
           B[2] = A1&A2 ^ A3
           B[3] = A2&A3 ^ A4
           B[4] = A3&A4 ^ A0
    theta: per plane i, with parameters (t0..t4) = theta[i][*]:
           E = X0^X1^X2^X3^X4 ;  F = XOR_j (Xj <<< tj)
           Yj = Xj ^ (E >>> tj) ^ F
           theta[0..4] = [31,1,4,21,22] [19,12,15,34,13] [28,35,58,9,23]
                         [55,18,5,27,44] [14,43,53,20,25]
    pi:    B[i][j] = A[(i+2j) mod 5][(3i+3j) mod 5]
```

### Hash / XOF: `h = Laurus[c,fid](M, |h|)`  (Sect. 2.2, steps (1)–(6))
```
g0(x) = MSB_b(x) ‖ ( LSB_r(x) ‖ MSB_c(x) )        # x = M_{i-1} ‖ S_{i-1},  |x| = r+b
g1(x) = LSB_b(x) ‖ LSB_1088(x)                    # x = S_l ‖ M_l,  |x| = 512+1536

# (1) padding, Pad[c]
if |M| == 0 or (|M| - 512) mod r != 0:
        Mpad = M ‖ 1 ‖ 0^(r-1-((|M|-512) mod r))  ;  d = 0
else:   Mpad = M                                  ;  d = 1
split Mpad = M_0 ‖ .. ‖ M_{l-1} ‖ M_l   with |M_i| = r, |M_l| = 512,
             l = max(0, ceil((|M|-512)/r))

# (2) initial state — this is the ONLY domain separation
S_0 = [ 2^63 * fid + c ]_1536        # 1536-bit big-endian int; c and fid both enter

# (3) absorb
for i = 1 .. l:
    x   = M_{i-1} ‖ S_{i-1}
    S_i = LSB_1536( P( 0 ‖ [i-1]_63 ‖ MSB_1536(g0(x)) ) ) XOR LSB_1536( g0(x) )

# (5) squeeze — parallel, counter-indexed, NOT chained
y = g1(S_l ‖ M_l)
for i = 0 .. ceil(|h|/1088) - 1:
    h_i = LSB_1088( P( 1 ‖ d ‖ [i]_62 ‖ MSB_1536(y) ) ) XOR LSB_1088(y)

# (6)
return MSB_|h|( h_0 ‖ h_1 ‖ ... )
```
Variable digest lengths: only `Laurus-XOF` is variable (`fid = 1`). A shorter
XOF output is a prefix of a longer one — that is the defined XOF semantics
(as in SHAKE), and there is a single `Laurus-XOF` object in the spec, so it is
not a cross-instance domain-separation problem. The three fixed-length hashes
are separated from each other and from the XOF by `S_0 = [2^63*fid + c]`
(different `c`, different `fid`), *and* they use different rates `r = 1536-c`, so
no output is a truncation of another.

## Implementation vs specification

Checked: `src/Laurus-512/laurus_512.c` (and the 768/1024/XOF files, which
differ from it only in the top-level wrapper line — verified by diff: the only
change is `laurus(h, D, in, inlen, c, fid)` with `(512,512,0) / (768,768,0) /
(1024,1024,0) / (outlen,512,1)`). `CryptHash_AlgorithmInstance.c` is a 3-line
wrapper; `drng.c`/`KAT_CryptHash.c` are the KAT harness (driver excluded by
`hash-14/Makefile`).

Verified agreements:

- **Rounds:** `#define NROUNDS 16` (`laurus_512.c:6`) = spec N = 16. Full
  round count, no reduction.
- **Round constants:** all 16 values in `RC[]` (`laurus_512.c:29-47`) match
  spec Table 2-1 entry for entry.
- **χ:** the five plane equations in `F1600_StatePermute` are literally spec
  Sect. 2.3 χ(1)–(5).
- **θ:** `P = XOR X_j`, `Q = XOR ROL(X_j,t_j)`, `B = X_j ^ ROR(P,t_j) ^ Q`
  = spec `Theta[t0..t4]`; the 25 rotation amounts in `theta[5][5]` match the
  five parameter vectors of Sect. 2.3 exactly.
- **π:** `A[5i+j] = B[((i+2j)%5)*5 + ((3i+3j)%5)]` = spec π.
- **ι:** `B[0] ^= RC[round]` = `A[0][0] ^= RC_r`.
- **g0 / g1:** `G0()` builds `MSB_1536(x)` and `LSB_r(x)‖MSB_c(x)` with the
  *variable* `r = 1536-c`, as in the spec; `G1()` builds `LSB_1536(x)` and
  `LSB_1088(x)`.
- **Rate:** `r = 1536 - c` (`laurus_512.c:159`), i.e. 1024/768/512 for
  c = 512/768/1024. Matches the spec; no rate/capacity mismatch.
- **Padding:** the `d` test `(res == 0 && r == rp && inlen != 0) || res == rp`
  is exactly `(|M| != 0) and ((|M|-512) mod r == 0)`, and the `10*` padding with
  the bit-level tail mask (`tmp[pos/8] = in[...] & (0xFF << (8-pos%8)) | 1 <<
  (7-pos%8)`) implements `M‖1‖0^*`. The `res >= 512` case correctly absorbs one
  extra full `r`-block and then sets `M_l = 0^512`; the `res < 512` case makes
  the padded tail the 512-bit `M_l`. I traced |M| = 0, |M| = 512, |M| = 1024 and
  |M| = l·r + 600 by hand against `Pad[c]`; all agree.
- **Domain separation:** `S[23] = (fid << 63) + c` = `S_0 = [2^63·fid + c]_1536`.
- **Squeeze:** `A[0] = ((2+d) << 62) + i` = `1 ‖ d ‖ [i]_62`; the output XOR
  `A[j+8] ^= LSB[j]` for `j < 17` is `LSB_1088(P(..)) XOR LSB_1088(g1(..))`.

Discrepancies / notes:

- **(b) Spec internal inconsistency, faithfully implemented.** Sect. 2.2's
  *generic* mode text says the squeeze output block `h_i` has length `t+b-c`,
  which would be 1088 / 832 / 576 bits for c = 512 / 768 / 1024. The *concrete*
  algorithm steps (5)–(6) and `g1` instead write the literal constant **1088**
  for every instance, because the same sentence "we fix t = 64, b = 1536,
  r = 512, c = 512" reuses the symbols `r` and `c` for the fixed final-block
  parameters. `G1()` and the squeeze loop hard-wire 1088 (17 words, offset 15)
  and so follow the concrete steps. This is a **spec notation collision**, not
  an implementation deviation — but for Laurus-768/1024 the implementation
  exposes 1088 bits of squeeze material per permutation call where the generic
  mode picture would expose only 832/576. Worth a spec clarification; the
  claimed bounds in Table 4-11 are derived from Sect. 4.1.1, which I did not
  re-derive.
- **(a) Minor API deviation.** `CryptHash()` in Laurus-512/768/1024 ignores its
  `digest_len_bits` argument entirely (`CryptHash_AlgorithmInstance.c`) and
  always writes `DIGEST_BIT_LENGTH/8` bytes; it returns 0 even for a wrong
  requested length. Laurus-XOF likewise passes the compile-time
  `DIGEST_BIT_LENGTH` (2048), not the caller's value, so the shared-library XOF
  is pinned to 2048 bits. No memory-safety issue for the harness, which always
  passes the declared length, but a caller requesting fewer bits would get a
  buffer overrun.
- No round-count reduction, no altered padding rule, no rate/capacity mismatch,
  and no constant that the spec says should vary is hard-wired in the
  permutation or in `g0`.
- `ROL/ROR` are undefined for a 0 rotation; none of the 25 `theta` constants is
  0, so this is not reachable. (Style note only.)
- Not verified: the security bounds of Sect. 4.1.1, the differential/linear
  bounds of Sect. 4.1.2, and the zero-sum distinguisher of Table 4-10 (the spec
  itself admits a 2^1505 zero-sum distinguisher on the full 16-round `P`).
