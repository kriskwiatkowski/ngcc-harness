# hash-03 C Hash (Chìtù) — algorithm summary

A JH-style wide-pipe hash ("Rocket-JH") built on a single 1536-bit public
permutation **C-Engine**, in which every iteration uses a *different* derived
permutation obtained by counter-based domain separation: the 1536-bit
permutation input is split into a 1472-bit block `x` and a 64-bit counter
`ctr`, and only the leftmost 1472 bits of the output are kept (CTR-Perm), with
an optional feed-forward XOR of `x` (CTR-Func). Message absorption is a JH
round (`x1 = h1 ⊕ m`, `h2' = y2 ⊕ m`) at a 736-bit rate; finalisation is a
separate lane. Short messages (`|M| < 1472`) take a mandatory fast path, LDRH,
which is the XOR of two domain-separated permutation calls. It is **not** a
sponge: there is no capacity/rate split in the usual sense.

Specification: `hash-03-spec.pdf` (63 physical pages), §1.2 (Rocket-JH, Alg. 1),
§1.2.4 (CTR-Perm/CTR-Func), §1.2.5 (LDRH, Alg. 2), §1.3 (C-Engine, Alg. 3),
§1.4 + Table 5 (parameters), §3.1 + Table 6 (security claims), App. A
(endianness / padding / LMB clarifications), App. D (the M64 matrix).
English-language spec; source comments are Chinese.

## Parameters

| parameter | C-Hash-512 | C-Hash-1024 | meaning |
|---|---|---|---|
| permutation width `b` | 1536 | 1536 | C-Engine state (spec §1.3) |
| counter width `w` | 64 | 64 | domain-separation suffix |
| effective block `n = b - w` | 1472 | 1472 | "state width" seen by the mode |
| message block / rate `n/2` | 736 | 736 | bits absorbed per permutation call |
| "capacity" `n/2` | 736 | 736 | the un-XORed half of the JH state |
| discarded counter bits | 64 | 64 | truncated from every permutation output |
| rounds of C-Engine | 28 | 28 | §1.3.1, Alg. 3 |
| state geometry | 6 x 64 nibbles | same | 384 nibbles = 1536 bits |
| S-box | 4-bit, `1 4 0 c 3 2 5 b a 8 6 f 7 9 d e` | same | Table 3 |
| column S-box | 24-bit SPS = S, `M6x6`, `^0xC908B2`, S | same | §1.3.2, Eq. (4) |
| M-layer | 64x64 binary matrix `M64` over GF(2^4), per row | same | App. D, branch number 18 |
| round constants | 28 x 32-bit, from frac(pi) | same | Table 4 |
| mode | CTR-Perm | CTR-Func | Table 5 |
| `IV_hashlen` | `[512]_736` | `[1024]_736` | big-endian, 92 bytes |
| output block `h` | 736 | 1472 | Table 5 |
| `z = ceil(hashlen/h)` | 1 | 1 | one finalisation call |
| LaneIDs (VIL, FIL, LDRH) | 0x01, 0x02, 0x03 | 0x81, 0x82, 0x83 | Table 5 |
| LDXOF LaneID (not in the hash API) | 0x04 | 0x84 | App. B |
| digest length | 512 | 1024 | |
| claimed indifferentiability | 538 bits | 708 bits | Table 6 |
| claimed collision (classical) | 256 | 512 | Table 6 |
| claimed preimage / 2nd-preimage | 512 / 512 | 1024 / 1024 | Table 6 |
| claimed quantum coll / pre | ~171 / 256 | ~341 / 512 | Table 6 |

Digest sizes, specification vs the built reference library
(`OBSERVED/hash-03.txt`):

| instance (impl label) | digest spec (bits) | digest impl (bits) | bytes | match |
|---|---|---|---|---|
| C-Hash-512 (`CHash_512`) | 512 | 512 | 64 | yes |
| C-Hash-1024 (`CHash_1024`) | 1024 | 1024 | 128 | yes |

## Pseudocode

### Padding (spec §1.2.2, App. A)

```
Pad(M): return M || 1 || 0^k,  k = min{j>=0 : |M|+1+j = 0 mod 736}
        -> l blocks m_1..m_l of 736 bits
# byte-oriented: the 1 bit goes at bit position (7 - |M| mod 8) of byte |M|/8
LDRH/LDXOF use a different, fixed-width padding: x = M || 1 || 0^(1471-|M|)
```

### CTR-Perm / CTR-Func and the counter (spec §1.2.4, Table 1)

```
ctr  = [LaneID]_8 || [Payload]_56                     # big-endian, 8 bytes
P_ctr (x)  = LMB(1472, C-Engine(x || ctr))            # CTR-Perm   (C-Hash-512)
P'_ctr(x)  = LMB(1472, C-Engine(x || ctr)) XOR x      # CTR-Func   (C-Hash-1024)
```

### Hash(M, hashlen) — spec Alg. 1, with the mandatory short-message route

```
 1  if |M| < n (=1472):  return LDRH(M, hashlen, IDldrh)      # Alg. 2, mandatory
 2  IV <- [hashlen]_736
 3  h_{0,1} || h_{0,2} <- P_{ctr(IDvil,0)}(IV || 0^736)  XOR  (0^736 || IV)
 4  m_1..m_l <- Pad(M)
 5  for i = 1..l:                                            # VIL compression
 6      x <- (h_{i-1,1} XOR m_i) || h_{i-1,2}
 7      y_1 || y_2 <- P_{ctr(IDvil,i)}(x)                    # |y_1|=|y_2|=736
 8      h_{i,1} <- y_1 ;  h_{i,2} <- y_2 XOR m_i
 9  z <- ceil(hashlen / h)                                   # = 1 for both
10  for i = 1..z:                                            # FIL finalisation
11      h_{l+i,1} || h_{l+i,2} <- P_{ctr(IDfil,i)}(h_{l+i-1,1} || h_{l+i-1,2})
12      r_i <- h_{l+i,1}                                     # leftmost h bits
13  return LMB(hashlen, r_1 || ... || r_z)
```

`P_ctr` is CTR-Perm for C-Hash-512 and CTR-Func for C-Hash-1024 in **all three
phases** (init, VIL, FIL); LDRH always uses CTR-Perm.

### LDRH(M, hashlen, LaneID) — spec Alg. 2 (|M| < 1472)

```
 1  x    <- M || 1 || 0^(1471-|M|)                # a single 1472-bit block
 2  y1   <- LMB(1472, C-Engine(x || [LaneID||1]_64))
 3  y2   <- LMB(1472, C-Engine(x || [LaneID||2]_64))
 4  return LMB(hashlen, y1 XOR y2)
```

### C-Engine(X) — spec Alg. 3, 28 rounds on a 6x64 nibble state

```
S <- ParseToMatrix(X)            # row i = bytes X[32i..32i+31]; hi nibble -> even col
for r = 0..27:
    # S-Layer: 64 independent 24-bit S-boxes, one per column (SPS structure)
    for j = 0..63:
        b_i  <- S4(s_{i,j})                   i = 0..5        # 4-bit S-box
        c    <- M6x6 * b                                      # binary, over GF(2^4)
        c    <- c XOR (0xC,0x9,0x0,0x8,0xB,0x2)               # = 0xC908B2, frac(sqrt 2)
        s_{i,j} <- S4(c_i)                    i = 0..5
    # M-Layer: 64x64 binary matrix M64 applied to each of the 6 rows
    for i = 0..5:  (s_{i,0..63}) <- M64 * (s_{i,0..63})^T
    # K-Layer: 32-bit round constant into the first 8 nibbles of row 0
    (s_{0,0..7}) <- (s_{0,0..7}) XOR EightNibbles(RC[r])      # high nibble first
return Serialize(S)
```

`M6x6` (Eq. 4) as XOR equations:
`c0=b0+b2+b3, c1=b0+b1+b4, c2=b1+b2+b5, c3=b0+b1+b2+b3+b4,
c4=b0+b1+b2+b4+b5, c5=b0+b1+b2+b3+b5`.

`M64` (App. D) is generated by a 4-round extended Lai-Massey network on the two
32-nibble halves `L`, `R` of a row with rotation amounts `(15, 7, 23, 16)`:

```
for a in (15, 7, 23, 16):
    T <- rotl32(L XOR R, a)          # rotate by a nibble positions
    L <- L XOR T
    R <- rotr32(R XOR T, 1)
```

### Variable digest lengths

Not an XOF. `CryptHash()` accepts exactly `digest_len_bits in {512, 1024}` and
selects the whole parameter set (mode, IV, lanes, `h`) from it; any other value
is rejected with `-1`. The spec does define an XOF, LDXOF (App. B, LaneID
0x04/0x84), but it is outside the hash API and is not reachable through it.

## Implementation vs specification

Checked: `hash-03/src/CHash_512/CryptHash_AlgorithmInstance.c` and
`hash-03/src/CHash_1024/CryptHash_AlgorithmInstance.c` (598/597 lines). The two
files are **byte-identical apart from three Chinese comment lines and one blank
line** — both contain the full 512+1024 logic and select on `digest_len_bits`;
only the headers differ (`ALGORITHM_INSTANCE`, `DIGEST_BIT_LENGTH`). Nothing
else in the tree implements the algorithm.

Verified agreements (not merely spot-checked):

- **4-bit S-box** `SBOX[16]` matches Table 3 exactly.
- **All 28 round constants** `RC_U32[]` match Table 4 exactly, and the K-layer
  injects them into the first 8 nibbles of row 0, high nibble first
  (`nib = (rc >> (28-4k)) & 0xF`), matching §1.3.2.
- **`M6x6`** is implemented as nine in-place `row_xor_row` operations
  (`CryptHash_AlgorithmInstance.c:131-133`). I expanded them symbolically and
  they reproduce Eq. (4) exactly, all six output equations.
- **`COL_CONST = {0xC,0x9,0x0,0x8,0xB,0x2}`** = 0xC908B2, applied after `M6x6`
  and before the second S-box, matching the SPS order in §1.3.2.
- **`M64`**: I built the 64x64 GF(2) matrix of the implementation's 4-round
  Lai-Massey loop (`:148-164`, amounts 15/7/23/16 plus a 1-position right
  rotation of `R`) by feeding the 64 unit vectors, and compared it entry-by-
  entry with the 64x64 matrix printed in Appendix D. **All 4096 entries match**
  (the transpose does not, so the orientation is also right). The matrix has
  full rank 64 over GF(2), row/column weights in {21,29}, and a short random
  search found an input/output nibble-weight pair summing to 18, consistent
  with the spec's claimed differential branch number of 18.
- **Round count is 28**, not fewer (`C_Engine1536_Perm28_plain:183`), and the
  round order is `S-Layer -> M-Layer -> K-Layer` as in Alg. 3.
- **Mode parameters** (`make_variant:234-254`) match Table 5 exactly:
  512 -> `h=736`, CTR-Perm, lanes `0x01/0x02/0x03`; 1024 -> `h=1472`, CTR-Func,
  lanes `0x81/0x82/0x83`.
- **`b/w/n` constants** `1536/64/1472/736` match §1.4.
- **Initialization** (`:535-546`) computes `P(IV||0^736)` then XORs `IV` into
  the *right* half, matching Alg. 1 line 1.
- **VIL loop** (`:551-566`) matches Alg. 1 lines 4-6, with counter `i` starting
  at 1 and the init call using `i = 0`.
- **Padding** (`pad_message:482-511`) is `M||1||0*` to a multiple of 736 bits,
  with the trailing partial byte masked and the 1 bit at position
  `0x80 >> (|M| mod 8)`, matching §1.2.2 and the App. A worked example.
- **Counter serialisation** (`make_CTR_bytes:259-265`) is big-endian with
  LaneID in the most significant byte, matching §1.2.4 / App. A.
- **IV** (`build_IV:224-228`) writes `hashlen` big-endian into the last two of
  92 bytes, matching the App. A example (0x02 at offset 90, 0x00 at 91).
- **LDRH routing** (`C_HASH:530`) triggers on `|M| < 1472` as §1.2.5 mandates,
  with counters `[LaneID||1]` and `[LaneID||2]` and CTR-Perm (never CTR-Func),
  matching Alg. 2 and the App. A note.
- **LDXOF** (`C_HASH_LDXOF:422-475`) matches App. B Alg. 4 including the
  counter layout `[LaneID]8||[OutputByteLen]24||[0x00]8||[i]24` from Table 1.

Discrepancies / observations:

- **(c) presentational, not a deviation — `M64` is realised as a network, not a
  matrix.** The spec's Alg. 3 line 13 says "the matrix `M64` is a 64 x 64
  binary matrix" and App. D prints it; the implementation instead runs the
  4-round Lai-Massey network that generates it. I verified the two are the same
  linear map, so this is a deliberate equivalent optimisation. Note that App. D
  says the matrix is "provided below in hexadecimal row format, with each
  16-bit hex value representing four consecutive GF(2^4) elements", but what is
  actually printed is a 0/1 matrix — a **spec text/figure inconsistency**, not
  an implementation one.
- **(b) dead/misleading constant.** `CH_LANE_INJECT` (0x01) and `CH_LANE_GEN`
  (0x03) are defined at `:200-201` but never used; `CH_LANE_GEN` is set to
  `0x03`, which is the LDRH lane, not the FIL lane `0x02`. The live code path
  (`make_variant`) uses the correct `0x02`/`0x82`, so the KATs are unaffected,
  but anyone reusing the macro would silently collide the FIL and LDRH lanes
  and destroy the domain separation the whole security argument rests on.
  Worth flagging to the submitters.
- **(b) robustness.** `pad_message()` `calloc`s the entire padded message
  (`l * 92` bytes) and never checks for `NULL`; the caller dereferences it
  immediately. A long message therefore turns an allocation failure into a
  crash, and the whole message must be buffered even though the mode is
  streamable. Not a spec deviation.
- **(b) unenforced spec bound.** §1.1 limits messages to `|M| < n * 2^(w-8) =
  1472 * 2^56` bits so the 56-bit VIL round index cannot wrap; the code does
  not check this. Unreachable in practice (~2^66 bits).
- **(b) exported symbol.** `C_HASH_LDXOF` is non-static and is therefore
  exported from the built shared library, but it is not declared in
  `CryptHash_AlgorithmInstance.h`. Harmless; noted only because it is not part
  of the ICCS API.
- **Not verified:** I did not independently check the claimed branch number of
  18 exhaustively (only an upper bound of 18 via random search, plus the
  trivial bounds 22 from the minimum row/column weights of `M64` and its
  inverse), did not check the indifferentiability proofs in App. C, and ran no
  differential/algebraic analysis of C-Engine. The KAT check for both instances
  passes in the build (`hash-03/security_findings.md`), which only shows the C
  code is self-consistent with the shipped vectors.
- **No deviation found** in round count, padding rule, rate/capacity split,
  lane identifiers, IV, or digest truncation. On the dimensions this review was
  asked to probe, hash-03 is the most faithful of the four hash candidates
  examined.
