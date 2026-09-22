# hash-23 Qilin (QILIN) — algorithm summary

Qilin is a sponge hash family over a 3136-bit (7 × 7 × 64) permutation
**Qilin-f**. The round is `p = C ∘ ρL ∘ Q ∘ ρQ ∘ L`: a 7-word shifted-XOR linear
layer applied column-wise, a row rotation, 448 parallel 7-bit χ-like S-boxes
applied row-wise in bitsliced form, a column rotation, and a 64-bit LFSR-derived
round constant on one word. Security is the standard sponge
indifferentiability argument with capacity `c = 2h`.

Specification: `hash-23-spec.pdf` (37 pages), §1.2 (construction), §1.3
(permutation), §3.4 (round numbers), §4.1 (claims).

## Parameters

| parameter | Qilin-512 | Qilin-768 | Qilin-1024 | meaning |
|---|---|---|---|---|
| state width b | 3136 | 3136 | 3136 | bits, 7 × 7 × 64 |
| rate r | 2112 | 1600 | 1088 | bits |
| capacity c | 1024 | 1536 | 2048 | b − r, always c = 2h |
| digest l | 512 | 768 | 1024 | bits |
| rounds Nr | 12 | 14 | 16 | §1.3 |
| S-box | 7-bit, DU = 8, linearity 40 | idem | idem | §4.3.1 |
| S-boxes / round | 448 | 448 | 448 | 7 rows × 64 bit-slices |
| shifted XORs per L | 28 | 28 | 28 | §1.3.1, Table 1.2 |
| IV | 0^{c/2} = 0⁵¹² | 0⁷⁶⁸ | 0¹⁰²⁴ | §1.2 (all-zero initial state) |
| squeeze blocks ⌈l/r⌉ | 1 | 1 | 1 | l < r for all three |
| collision | 2²⁵⁶ | 2³⁸⁴ | 2⁵¹² | spec Table 4.1 |
| 2nd-preimage | 2⁵¹² | 2⁷⁶⁸ | 2¹⁰²⁴ | spec Table 4.1 |
| preimage | 2⁵¹² | 2⁷⁶⁸ | 2¹⁰²⁴ | spec Table 4.1 |

Sizes (bytes), specification vs the built reference library:

| instance | digest spec | digest impl (OBSERVED) | match |
|---|---|---|---|
| QILIN-512 | 64 | digest_bits=512, digest_bytes=64 | yes |
| QILIN-768 | 96 | digest_bits=768, digest_bytes=96 | yes |
| QILIN-1024 | 128 | digest_bits=1024, digest_bytes=128 | yes |

Round-count margin: §3.4 states that "6 rounds of the permutation offer
sufficient protection against collision attacks and preimage attacks" and that
"we adopt 12 or more rounds for high security margins" — i.e. a claimed 2×–2.7×
margin.

## Pseudocode

### Hash(M, l) — sponge with IV (Algorithm 1, §1.2)
```
# absorbing
M^1 .. M^n  <-  M || 1 || 0* || 1            # split into r-bit blocks
S  <- f( M^1 || 0^{c/2} || IV )              # IV = 0^{c/2}, so S starts all-zero
for i = 2 .. n:
    S <- f( (S_r XOR M^i) || S_c )
# squeezing
H_1 <- S_r
for i = 2 .. t = ceil(l/r):
    S <- f(S);  H_i <- S_r
return floor(H_1 || .. || H_t)_l
```
The padding `10*1` is injective and the last 1 always lands on the final bit of
a rate block; a new all-zero-but-last block is appended when the message ends
exactly one bit short of a block boundary.

**Variable digest lengths:** only l ∈ {512, 768, 1024} are defined, each with its
own (r, c, Nr). `t = ⌈l/r⌉ = 1` for all three, so the digest is always the first
l bits of the rate after the last absorb — no squeeze permutation is ever
executed. There is **no digest-length domain-separation suffix**; the IV is
all-zero for every variant and separation comes only from r, c and Nr differing.

### Qilin-f (Algorithm 2, §1.3) — Nr rounds of p = C ∘ ρL ∘ Q ∘ ρQ ∘ L
```
state x[0..6][0..6] of 64-bit words;  S = x_{0,0} || x_{1,0} || .. || x_{6,6}

for t = 0 .. Nr-1:
    # L : linear diffusion, applied to each COLUMN j independently
    for j = 0..6:  (y_{0,j},..,y_{6,j}) <- L(x_{0,j},..,x_{6,j})

    # rhoQ : row rotation, row i rotated right by i
    for i = 0..6:  (y_{i,0},..,y_{i,6}) <- (y_{i,-i}, y_{i,1-i}, .., y_{i,6-i})

    # Q : nonlinear layer, applied to each ROW i independently
    for i = 0..6:  (x_{i,0},..,x_{i,6}) <- Q(y_{i,0},..,y_{i,6})

    # rhoL : column rotation, column j rotated down by j
    for j = 0..6:  (x_{0,j},..,x_{6,j}) <- (x_{-j,j}, x_{1-j,j}, .., x_{6-j,j})

    # C : constant addition
    x_{0,0} <- x_{0,0} XOR C_t
```

### L — linear layer (Algorithm 3, §1.3.1)
```
L(y_0..y_6):
    for i = 7 .. 34:
        y_i = y_{n1[i]} XOR ( y_{n2[i]} <<< m_i )     # 28 shifted XORs
    return (y_28, .., y_34)

n1 = 5,2,4,1,6,3,0,7,10,11,14,8,16,12, 9,13,11, 8,18,19,20,24,22,25,23,21,26,27
n2 = 2,4,1,6,3,0,7,5,12, 9,13,15,17,18,19,20,21,22,23,24,24,22,25,23,21,26,27,20
m  = 0,0,0,0,0,0,1,39,23,18,46,54, 5,15,26,33,46,44, 9,30, 0, 0, 0, 0, 0, 0, 1,39
```

### Q — 7-bit S-box, bitsliced (Algorithm 4 + Figure 1.3, §1.3.2)
```
Q(a0..a6):
    t0 = (a1 AND a2) XOR a0
    t1 = (a2 OR  a3) XOR a1
    t2 = (a3 AND a4) XOR a2
    t3 = (a4 OR  a5) XOR a3
    t4 = (a5 AND a6) XOR a4
    t5 = (NOT a6 AND a0) XOR a5      # <-- NOT is in Figure 1.3, NOT in Algorithm 4
    t6 = (a0 OR  a1) XOR a6
    b0 = (t0 AND t5) XOR t2
    b1 = (t5 OR  t3) XOR t0
    b2 = (t3 AND t1) XOR t5
    b3 = (t1 OR  t6) XOR t3
    b4 = (t6 AND t4) XOR t1
    b5 = (NOT t4 AND t2) XOR t6      # <-- same, complement present only in the figure
    b6 = (t2 OR  t0) XOR t4
    return (b0..b6)
```
This is two cascaded χ₇-like S-boxes in lane-complemented form (§3.2.1, §3.2.2).

### C — round constants (§1.3.4)
15-bit LFSR over `P(x) = x^15 + x^14 + x^2 + x + 1`, initialised to all-ones,
`s_{t+1} = s_t ⊕ s_{t-1} ⊕ s_{t-13} ⊕ s_{t-14}`; the 15 state bits are scattered
into bit positions 0,1,2,4,6,7,8,9,10,11,12,13,14,17,24 of the 64-bit `C_t`.
Table 1.3 lists C_0 = 0x0000000001027fd7 … C_15 = 0x0000000000025b52.

## Implementation vs specification

Checked: `src/QILIN-{512,768,1024}/CryptHash_AlgorithmInstance.c` (512 and 768
are byte-identical; 1024 differs only in the type of two locals — `int` vs
`unsigned long long` for `remaining_bits`/`remaining_bytes`, no behavioural
difference since `remaining_bits < rate_bits ≤ 2112`). All 3 instances PASS KAT.

Verified:

- **Rate/capacity**: `rate_bits = 3136 - 2*digest_len_bits` gives 2112 / 1600 /
  1088, matching spec Table 4.1 exactly, with c = 2h ✓.
- **Round counts**: `R = 12`, `14` for 768, `16` for 1024 — matches §1.3 ✓.
  No reduced-round shortcut.
- **Round constants**: the 16-entry `rc[]` table reproduces spec Table 1.3
  verbatim, and rounds consume `rc[0..R-1]` ✓.
- **Linear layer**: `n1[28]`, `n2[28]`, `m[28]` reproduce spec Table 1.2
  entry for entry (all 84 values checked) ✓, applied per column ✓.
- **ρQ**: `y[i][j] = y_L[i][(7-i+j)%7]` = `y_{i,j-i}` ✓.
- **ρL**: output component k of row i is written to `x[(i+k)%7][k]`, i.e.
  `x_{i,j} → x_{i+j,j}`, the inverse-indexed form of `x_{i,j} ← x_{i-j,j}` ✓.
- **Constant addition**: `x[0][0] ^= rc[r]` ✓ §1.3.4.
- **Padding**: `10*1`, with the first 1 placed MSB-first at bit
  `remaining_bits`, the extra all-zero block inserted exactly when
  `remaining_bits + 1 == rate_bits`, and the trailing 1 set as the last bit of
  the rate (`last_block[rate_bytes-1] |= 0x01`) ✓ Algorithm 1.
- **State/byte order**: word index j ↔ `x[j%7][j/7]`, i.e. column-major, which
  matches the spec's `S = x_{0,0}‖x_{1,0}‖…‖x_{6,6}` ✓.
- **IV**: `uint64_t x[7][7] = {0}` = all-zero state = `0^{c/2} ‖ IV` with
  `IV = 0^{c/2}` ✓ §1.2.
- **Squeeze**: `digest_len_bits/64` words read straight from the rate, no extra
  permutation — correct because `⌈l/r⌉ = 1` for all three instances ✓.

Discrepancies:

1. **(a)/(b) The specification's Algorithm 4 does not match the specification's
   own Figure 1.3, and the implementation follows the figure.** Algorithm 4
   writes `t5 = (a6 ∧ a0) ⊕ a5` and `b5 = (t4 ∧ t2) ⊕ t6`, with **no
   complement anywhere in the S-box**. Figure 1.3 draws the wrap-around gate of
   each half with an extra constant-`1` input (the standard notation for a
   complemented input), and the reference code implements exactly that:
   `t[i][5] = ((~y[i][6]) & y[i][0]) ^ y[i][5];` and
   `x[(i+5)%7][5] = ((~t[i][4]) & t[i][2]) ^ t[i][6];`
   (`CryptHash_AlgorithmInstance.c:53` and `:60`).
   Corroborating evidence that the figure/code are right and Algorithm 4 is the
   typo: §2 ("Features") and §3.2.2 both discuss *lane-complementing transforms
   to reduce the number of NOT operations in the S-box*, which presupposes NOTs
   that Algorithm 4 does not contain; and the mixed AND/OR pattern of Algorithm
   4 is precisely the lane-complemented form of χ₇ ∘ χ₇, whose odd 7-cycle
   forces exactly one `¬x ∧ y` gate per half. **An implementer working from
   Algorithm 4 alone would build a different hash function that fails the KATs.**
   This is the highest-value finding for this candidate.
2. **(a) Undefined behaviour: 64-bit rotate by zero.**
   `CryptHash_AlgorithmInstance.h:30` defines
   `#define ROL64(a, offset) ((((uint64_t)a) << (offset)) | (((uint64_t)a) >> (64-(offset))))`
   and `m[]` contains **twelve zero offsets** (indices 0–5 and 20–25). Every one
   of those evaluates `a >> 64`, which is undefined in C. It happens to yield
   `a` on x86-64 (the shift count is taken mod 64) so the KATs pass, but a
   compiler that constant-folds the shift is free to produce 0, which would
   silently change the hash. The spec explicitly *chose* zero offsets
   ("for x86_64 architectures, we have optimized the number of rotate
   operations by setting several offsets to zero", §2), so this is not a rare
   path — it is 12 of 28 shifted XORs in every round.
3. **(a) No validation of `digest_len_bits`.** `CryptHash()` never compares the
   argument against `DIGEST_BIT_LENGTH` and never range-checks it. Any value is
   accepted: `rate_bits = 3136 - 2*digest_len_bits` goes to 0 at 1568 (the
   absorb loop then never terminates / divides state indices by zero-length
   blocks) and negative beyond that; non-multiples of 64 silently truncate
   `rate_words` and desynchronise `rate_bytes` from `rate_words*8`. Robustness
   defect only — the KAT driver always passes `DIGEST_BIT_LENGTH`.
4. **(a) Endianness.** The state words are loaded and stored with
   `memcpy(&val, ptr, 8)`, i.e. host byte order. The reference implementation is
   therefore little-endian-only, and the spec does not define the byte encoding
   of `x_{i,j}`, so the KAT files are only reproducible on LE hosts.
5. **(a) Header/portability defects** (already captured in `hash-23/Makefile`):
   `CryptHash_AlgorithmInstance.h:28-29` contains
   `typedef unsigned long long uint64_t; typedef unsigned char uint8_t;`
   which collides with `<stdint.h>` on LP64 (where `uint64_t` is `unsigned
   long`) as soon as both headers are visible in one translation unit; and the
   shipped `KAT_CryptHash.c` includes the Windows-only `<direct.h>` and
   `<io.h>`. Neither affects the algorithm; the uniform build works around both.
6. **No digest-length domain separation.** All three variants start from the
   all-zero state with the same `10*1` pad and no suffix bits. This follows the
   spec (IV = 0^{c/2}), and the variants are still structurally distinct because
   r, c and Nr all differ, so no cross-variant relation follows — but it is
   worth recording that Qilin, unlike SHA-3, has no domain-separation bits at
   all, which constrains any future extension of the family to AEAD/MAC/PRNG
   modes (which §2 advertises) sharing the same permutation.

Coverage: no independent differential/linear or algebraic analysis of Qilin-f
was attempted; §3.3.3/§4.3 bounds were read but not re-derived.
