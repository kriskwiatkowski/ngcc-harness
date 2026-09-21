# hash-26 CHIME — algorithm summary

CHIME is a permutation-based hash family over a 1536-bit state split into six
256-bit arrays `A0, A1, B0, B1, C0, C1`. **CHIME-512** is a plain sponge
(r = 512, c = 1024, 15 rounds); **CHIME-1024** is a *sponge with feed-forward*
(r = 448, c = 1088, 20 rounds) in which the capacity part of the pre-permutation
state is XORed back after each permutation call. The round function is
`RP = τ · χ · AC · λ`: a shift/rotate/shuffle linear layer λ, a round-constant
XOR into `A0`, a Keccak-style χ over 3-bit S-boxes formed from
(A, B, C) triples, and a branch rotation τ. Only two instances exist — there is
no CHIME-768.

Specification: `hash-26-spec.pdf` (23 pages), §1.5 (modes), §1.6 (round
function), §3 (parameters), §4 (claims).

## Parameters

| parameter | CHIME-512 | CHIME-1024 | meaning |
|---|---|---|---|
| construction | sponge | sponge with feed-forward | §1.5.1 / §1.5.2 |
| state b | 1536 | 1536 | bits = 6 × 256 |
| rate r | 512 | 448 | bits |
| capacity c | 1024 | 1088 | bits |
| digest n | 512 | 1024 | bits |
| rounds | 15 | 20 | of `RP`, §1.5.1 / §1.5.2 / §3.3 |
| S-box | 3-bit, DDT max 2⁻² | idem | §1.6.3, Table 1/9 |
| S-boxes per round | 512 | 512 | 2 triples × 256 bit-slices |
| round constants | `RC_i` = 4 copies of `X_i` | idem | Table 7, §3.2 |
| digest taken from | first 512 bits (= A0‖A1, the rate) | **last** 1024 bits (= B0‖B1‖C0‖C1) | §1.5 |
| collision claim | 2²⁵⁶ | 2⁵¹² | Table 8 |
| preimage claim | 2⁵¹² | 2¹⁰²⁴ | Table 8 |
| 2nd-preimage claim | 2⁵¹² | 2¹⁰²⁴ | Table 8 |

Claim consistency: CHIME-512 uses the sponge bounds (Property 1)
`min{2^{n/2}, 2^{c/2}} = 2²⁵⁶`, `min{2^n, 2^{c/2}} = 2⁵¹²`, which is exactly met
because `c/2 = 512 = n` — **no capacity margin above the digest size**.
CHIME-1024 uses the feed-forward bounds (Property 2), with second-preimage
`min{2^n, 2^{c-64}} = min{2¹⁰²⁴, 2¹⁰²⁴}` — again exactly met.

Sizes (bytes), specification vs the built reference library:

| instance | digest spec | digest impl (OBSERVED) | match |
|---|---|---|---|
| CHIME-512 | 64 | digest_bits=512, digest_bytes=64 | yes |
| CHIME-1024 | 128 | digest_bits=1024, digest_bytes=128 | yes |

## Pseudocode

### Padding (§1.5.1, §1.5.2) — same `10*1` rule, different block size
```
Pad(M, r):                                  # r = 512 (CHIME-512) or 448 (CHIME-1024)
    k = smallest k >= 0 with (|M| + 2 + k) == 0 (mod r)
    M' = M || 1 || 0^k || 1
    split M' into m blocks M'_0 .. M'_{m-1} of r bits
```

### CHIME-512 — plain sponge (§1.5.1)
```
S_0 = 0^1536
for i = 0 .. m-1:
    S_{i+1} = P( S_i XOR (M'_i || 0^c) )      # P = 15 rounds of RP
H = Truncate_512(S_final)                     # the first 512 bits = the rate
```
No squeeze loop: n = r, so one rate read suffices.

### CHIME-1024 — sponge with feed-forward (§1.5.2)
```
S_0 = 0^1536
for i = 0 .. m-1:
    if i == m-1:  S_i = S_i XOR (0^r || 0^{c-1} || 1)    # anti-length-extension bit
    S_{i+1} = P( S_i XOR (M'_i || 0^c) ) XOR ( 0^r || Truncate'_1088(S_i) )
H = Truncate'_1024(S_final)                   # the LAST 1024 bits = B0||B1||C0||C1
```
`P` = 20 rounds of `RP`. The feed-forward covers only the 1088-bit capacity, so
the rate part of the output is the raw permutation output. The single `1` bit
XORed into the capacity before the *last* block is the spec's stated
length-extension countermeasure.

### Variable digest length
Only two lengths exist, and they differ in construction, rate, capacity, round
count **and** which end of the state the digest is read from, so no explicit
domain-separation constant is needed and none is present. There is no XOF mode
and `digest_len_bits` is not used by the implementation (see below).

### Round function RP = τ · χ · AC · λ (§1.6)

**λ (§1.6.1)**, executed in this order:
```
B1 ^= Pi_perm32(C1)
B0 ^= A1
C0 ^= (A0 <<<  29)          # rotation
B1 ^= (A1 <<<  31)          # rotation
C1 ^= (A0 <<<  13)          # rotation
C0 ^= B1
A0  = Pi_perm64(A0)
C1 ^= Pi_perm32(B1)
A1  = Pi_swap128(A1)
A0 ^= Pi_swap64(C0)
A1 ^= Pi_perm32(B0)
B1 ^= (A0 <<   7)           # plain LEFT SHIFT (see discrepancy 1)
C1 ^= (A1 >>   5)           # plain RIGHT SHIFT
```
with, on each 256-bit array,
```
Pi_perm32 : within each 128-bit half, (a,b,c,d) of 32-bit words -> (d,a,b,c)
Pi_perm64 : (a,b,c,d) of 64-bit words -> (b,c,d,a)
Pi_swap64 : (a,b,c,d) of 64-bit words -> (b,a,d,c)
Pi_swap128: (a,b) of 128-bit halves   -> (b,a)
```

**AC (§1.6.2)**: `A0 ^= RC_r`, where `RC_r` is four copies of the 64-bit word
```
X_i = 0xDEADBEEF00000000 XOR i XOR (0x9E3779B97F4A7C15 * (i+1))   # low 64 bits of the product
```
(X_0 = 0x409AC7567F4A7C15, … , X_19 = 0x82F83C92F1D1B1B7; spec Table 7).

**χ (§1.6.3)**: 3-bit S-box `S = [0,5,3,2,6,1,4,7]`, bitsliced as
`A' = A ^ (~B & C)`, `B' = B ^ (~C & A)`, `C' = C ^ (~A & B)` applied to
```
even round r:  (A0,B0,C0)  and  (A1,B1,C1)
odd  round r:  (A0,B1,C1)  and  (A1,B0,C0)
```

**τ (§1.6.4)**: branch rotation whose direction depends on `k = floor(r/3)`
```
k even:  A0'=C1, C1'=C0, C0'=B1, B1'=B0, B0'=A1, A1'=A0
k odd :  A0'=A1, A1'=B0, B0'=B1, B1'=C0, C0'=C1, C1'=A0
```

## Implementation vs specification

Checked: `src/CHIME-{512,1024}/CryptHash_AlgorithmInstance.c` (905 / 949 lines;
the permutation half is common, the mode half differs). **The reference tree is
self-contained** — the only includes are `<string.h>`, `<stdint.h>`,
`<stddef.h>`, `<stdio.h>`, `<stdlib.h>`; OpenSSL (`sha_openssl.h`, `-lcrypto`)
appears only in the Optimized_Implementation tree, which is not built.
`drng.c` is the unmodified official DRNG. Both instances PASS KAT.

Verified:

- **Round counts.** `p_pn(&s, 15)` per block in
  `chime_512_p_512_1024_blocks_ref()` and `p_pn(&s, 20)` in
  `chime_1024_p_448_1088_blocks_ref()` ✓ §1.5.1 / §1.5.2. No shortfall.
- **Round constants.** `ARC[20]` reproduces spec Table 7 verbatim; I re-derived
  `X_0` from the §3.2 formula (0x9E3779B97F4A7C15 ⊕ 0xDEADBEEF00000000 ⊕ 0 =
  0x409AC7567F4A7C15) and it matches ✓. Applied to all four lanes of `A0` only
  ✓ §1.6.2. CHIME-512 consumes `ARC[0..14]`, CHIME-1024 `ARC[0..19]`.
- **χ.** `chi3()` computes `A ^= ~B & C`, `B ^= ~C & A_old`, `C ^= ~A_old &
  B_old` using saved copies, exactly the §1.6.3 equations ✓; `chi_e` pairs
  (A0,B0,C0)/(A1,B1,C1) and `chi_o` pairs (A0,B1,C1)/(A1,B0,C0) ✓, selected by
  `r & 1` ✓.
- **τ.** `rp_fwd()` is literally the k-even rule and `rp_rev()` the k-odd rule,
  selected by `((r/3) & 1) == 0` ✓ §1.6.4.
- **Round order.** `rp()` = λ, then AC, then χ; τ is applied by `p_pn()` after
  `rp()` ✓ `RP = τ·χ·AC·λ`.
- **λ shuffles.** `pq_0x93`, `p128_0x01`, `sh_0x39`, `sh_0x4e` implement
  Π_perm64, Π_swap128, Π_perm32, Π_swap64 respectively; I checked each against
  its §1.6.1 definition word by word (see discrepancy 2 for the index
  convention).
- **λ statement order.** The code hoists `T = Pi_swap64(C0)` two statements
  earlier than §1.6.1 places it. This is a **(c) equivalent reordering**: the
  intervening statements touch only `C1` and `A1`, never `C0`, so `T` has the
  same value. Every other statement is in spec order.
- **Padding.** `chime_{512,1024}_build_padded_blocks_bit_level()` implements
  `M‖1‖0^k‖1` with three cases (`rem ≤ r−2` → one final block; `rem = r−1` →
  the first `1` closes the block and a whole extra `0^{r−1}‖1` block follows;
  `rem = 0`) ✓ §1.5.1/§1.5.2, with trailing partial-byte bits masked off.
- **CHIME-512 rate/digest.** Message XORed into `A0‖A1` = the first 512 bits ✓;
  digest read from `A0‖A1` ✓ `Truncate_512`.
- **CHIME-1024 rate/capacity split.** `load_rate448_to_A0_A1()` fills `A0`
  (256 bits) and three lanes of `A1` (192 bits) = 448, setting the fourth `A1`
  lane to zero, so exactly 1088 bits (that lane + B0,B1,C0,C1) stay in the
  capacity ✓ §1.5.2.
- **Feed-forward.** `feedforward_inner_1088()` XORs the *pre-permutation*
  state's `A1[0], B0, B1, C0, C1` into the post-permutation state, i.e.
  `⊕ (0^r ‖ Truncate'_1088(S_i))` ✓.
- **Digest extraction (1024).** `B0‖B1‖C0‖C1` = bits 512..1535 = the last 1024
  bits ✓ `Truncate'_1024`.

Discrepancies:

1. **(a)/(b) The specification cannot be implemented as written: shift and
   rotation use the same symbol.** §1.3 defines two operations with the
   *identical* Unicode character U+226A (`≪`) — "left-shift by n bits" and
   "left-rotation (circular shift) by n bits" — and §1.6.1 then uses U+226A for
   all four left operations (29, 31, 13, 7). The reference implementation
   resolves this as **29, 31, 13 = rotations (`rol64`), 7 = plain left shift
   (`<< 7`)**, and the single `≫ 5` (U+226B, which §1.3 never defines at all)
   as a **plain right shift (`>> 5`)**. Nothing in §1.6.1, §3.1 or elsewhere
   distinguishes them; §3.1's title ("Choice of the Shift and rotation
   offsets") confirms both kinds are intended but gives no assignment. An
   independent implementer has no way to reproduce CHIME from the document.
   This is the highest-value finding for this candidate.
2. **(b) Direction ambiguity of Π_perm64 / Π_perm32.** §1.6.1 writes these with
   a leftward arrow (`b‖c‖d‖a ←− a‖b‖c‖d`). Read literally as "output ← input",
   `Π_perm64` is the left rotation `(a,b,c,d) → (b,c,d,a)`; the code's
   `pq_0x93` performs `(a,b,c,d) → (d,a,b,c)`, the **inverse**, and `sh_0x39`
   is likewise the inverse of the literal `Π_perm32`. Both are inverted in the
   same direction, so the code is self-consistent under the opposite reading of
   the arrow (or, equivalently, under a reversed word-index convention); the
   involutions `Π_swap64`/`Π_swap128` cannot discriminate. Combined with §1.1's
   stated "big-endian" convention against the code's `load64_le`/`store64_le`,
   the byte/word ordering of the whole permutation is under-specified and only
   the KAT files pin it down.
3. **(b) §1.5.2 contradicts itself about when the anti-length-extension bit is
   injected.** The prose says "**After** absorbing the (m−1)-th message block,
   execute `S_{m−1} ← S_{m−1} ⊕ (0^{c−1}‖1)`", but `S_{m−1}` is by definition
   the state *before* block m−1 is absorbed (`S_{i+1} = P(S_i ⊕ …)`), so the
   formula and the prose describe different points in the loop. The
   implementation follows the **formula**: `if (i == num_blocks-1) s.C1[0] ^= 1;`
   runs immediately *before* the last block's message XOR.
4. **(a) `digest_len_bits` is ignored, with a buffer-overflow hazard.**
   `CryptHash()` in both instances is `#if DIGEST_BIT_LENGTH == 512 → return
   CryptHash512(...)` and never inspects `digest_len_bits`. The CHIME-1024
   library therefore writes **128 bytes** into `digest` even when the caller
   asks for `digest_len_bits = 512`, which would overflow a 64-byte caller
   buffer. The NGCC KAT driver always passes `DIGEST_BIT_LENGTH`, so this does
   not affect conformance, but it is a live memory-safety issue for any other
   caller. (Pavelor and Qilin also ignore the argument, but they at least derive
   the output length from it.)
5. **No round-count, padding, rate/capacity or digest-separation deviation was
   found.** 15 and 20 rounds, the `10*1` pads at 512 and 448 bits, the
   (512,1024) and (448,1088) splits, the feed-forward and the final-block bit
   are all implemented as specified.
6. **Weak round-count justification (spec-side).** §3.3 is a single sentence
   ("This selection relies on the round margins established in the security
   analysis") with no number; the supporting evidence in §3.1 is a 3–6 round
   avalanche table and in §5.2 a SAT active-S-box count. Given a 3-bit S-box
   with DDT maximum 2⁻², 15 rounds is a modest budget and deserves a concrete
   active-S-box figure, which the document does not give in §3.3.

Coverage: no independent differential, linear or algebraic analysis was
attempted; §5's SAT results were read but not re-derived. The Optimized_
Implementation tree (the one that links OpenSSL) was not examined.
