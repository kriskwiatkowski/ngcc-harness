# hash-25 TaiChi — algorithm summary

TaiChi is a permutation-based hash family in an **Interleaved Feistel Sponge
(IFS)** mode: the state is a triple `(S, L, R)` with one r-bit rate branch and
**two** c-bit capacity branches, and each Step makes **two** calls to the same
1920-bit permutation `P1920`, domain-separated by a parameter `b ∈ {1,2}` that
only changes the round-constant stream. The permutation is a 12-round
Keccak-like SPN on a 6 × 5 array of 64-bit lanes: a 6-word MRM shifted-XOR
diffusion layer per column, 384 parallel 5-bit S-boxes per row, a static lane
permutation Π₁₀, and row-0 round constants.

Specification: `hash-25-spec.pdf` (51 pages), §1.3–1.7 (mode and permutation),
§2.1 (claims), §4.3 (round-number rationale).

## Parameters

| parameter | TaiChi-512 | TaiChi-768 | TaiChi-1024 | meaning |
|---|---|---|---|---|
| digest d | 512 | 768 | 1024 | bits |
| rate r | 1408 | 1152 | 896 | bits = 1920 − d |
| capacity branch c | 512 | 768 | 1024 | bits, c = d for all three |
| primitive width n = r+c | 1920 | 1920 | 1920 | P1920 input size |
| IFS state r + 2c | 2432 | 2688 | 2944 | bits |
| hidden capacity 2c | 1024 | 1536 | 2048 | bits (L and R, never output) |
| rate words / capacity words | 22 / 8 | 18 / 12 | 14 / 16 | 64-bit lanes, 30 total |
| permutation rounds | 12 | 12 | 12 | §1.6.2 |
| permutation calls per Step | 2 (P1, P2) | 2 | 2 | §1.4 |
| S-boxes per round | 384 | 384 | 384 | 6 rows × 64 bit-slices, 5-bit S-box |
| shifted XORs per MRM core | 16 (+6 output rotations) | idem | idem | §1.6.5, Table 1.3 |
| round constants | 120 total (q = 0..59 for P1, 60..119 for P2) | idem | idem | 7-bit LFSR, §1.6.6 |
| squeeze Steps | 0 | 0 | 1 | d < r for 512/768; d = r+128 for 1024 |
| collision claim | 2²⁵⁶ | 2³⁸⁴ | 2⁵¹² | `min{2^{d/2}, 2^c}`, Table 2.1 |
| preimage claim | 2⁵¹² | 2⁷⁶⁸ | 2¹⁰²⁴ | `min{2^d, 2^c}`, Table 2.1 |
| 2nd-preimage claim | ≤ 2⁵¹² | ≤ 2⁷⁶⁸ | ≤ 2¹⁰²⁴ | upper bound only, §2.1 |

Sizes (bytes), specification vs the built reference library:

| instance | digest spec | digest impl (OBSERVED) | match |
|---|---|---|---|
| TaiChi-512 | 64 | digest_bits=512, digest_bytes=64 | yes |
| TaiChi-768 | 96 | digest_bits=768, digest_bytes=96 | yes |
| TaiChi-1024 | 128 | digest_bits=1024, digest_bytes=128 | yes |

Round budget: 12 rounds per permutation × 2 permutations per Step, so one
absorbed r-bit block costs 24 rounds. §4.3 justifies 12 rounds with a MILP bound
of ≥80 active S-boxes over 12 rounds (weight ≥ 320, since DP_max = 2⁻⁴) and
avalanche saturating from round 3.

## Pseudocode

### Padding (§1.3)
```
pad_r(M) = M || 1 || 0^j || 1,   j >= 0 smallest with |M| + 2 + j == 0 (mod r)
pad_r(M) = M_0 || M_1 || ... || M_{alpha-1},   |M_i| = r
```
Injective and prefix-free; the last block always carries padding.

### Domain separation (§1.4)
```
enc(Ab)  = 0^{c-2} || 01
enc(Fin) = 0^{c-2} || 10
enc(Sq)  = 0^{c-2} || 11
# 0^{c-2}||00 is reserved and never used
```
Only two bits per Step, XORed into the capacity input of the **first**
permutation call.

### TaiChi Step T_{r,c} (Algorithm 1, §1.4)
```
T(S, L, R; M, D):
    X          = S XOR M
    (A, B)     = P1( X || (L XOR enc(D)) )      # |A| = r, |B| = c
    (S', C)    = P2( A || (R XOR B) )           # |S'| = r, |C| = c
    L'         = C
    R'         = B XOR C
    return (S', L', R')
```
The two capacity branches interleave: `B` feeds P2 *and* is carried into `R'`,
while P2's capacity output `C` becomes `L'`.

### Hash (Algorithm 2, §1.5) — absorb / finalize / squeeze
```
M_0..M_{alpha-1} = pad_r(M)
S = 0^r ; L = 0^c ; R = 0^c                     # all-zero initial state
for i = 0 .. alpha-2:  (S,L,R) = T(S,L,R; M_i, Ab)
(S,L,R) = T(S,L,R; M_{alpha-1}, Fin)            # finalization
Z = S                                           # first rate output S0
while |Z| < d:
    (S,L,R) = T(S,L,R; 0^r, Sq)                 # squeeze with all-zero block
    Z = Z || S
return floor(Z)_d
```
**Variable digest length:** only d ∈ {512, 768, 1024}. TaiChi-512 and -768 have
d < r, so the digest is `⌊S0⌋_d` with no squeeze Step. TaiChi-1024 has
d = r + 128 > r, so exactly one squeeze Step runs and
`H = S0 || ⌊S1⌋_128` (§1.7.3). There is no XOF mode; each instance fixes
(d, r, c) so there is no shared-prefix relation between the three.

### P1920 (Algorithm 3, §1.6.2) — 12 rounds
```
state X = (x_{i,j}),  0<=i<6, 0<=j<5, lanes of 64 bits, lane index n = 5i+j
for t = 0 .. 11:
    X = L(X)        # MRM diffusion, per COLUMN j
    X = Q(X)        # 5-bit S-box layer, per ROW i
    X = Pi10(X)     # static lane permutation
    X = A_{b,t}(X)  # round constants into row 0
```

### L — MRM core, applied to each column (Algorithm 6, §1.6.5)
```
L(y0..y5):
    for i = 6 .. 21:  y_i = y_{n1[i]} XOR ( y_{n2[i]} <<< m_i )
    return (y16<<<0, y17<<<15, y18<<<48, y19<<<63, y20<<<6, y21<<<33)

n1 = 0, 1, 2, 4, 3, 5, 6, 7,13,14,15,16,15,18,11,20
n2 = 1, 2, 4, 3, 5, 6, 0,11, 8, 9,10,12,17,14,19,13
m  = 8, 0, 0, 0, 0, 0,23,62,35,14,48, 1,57,63,58,22
```

### Q — 5-bit S-box, bitsliced, applied to each row (Algorithm 4, §1.6.4)
```
b0 = a1 ^ (a0&a1) ^ a2 ^ (a1&a2) ^ a3 ^ (a3&a4)
b1 = ~0 ^ a1 ^ (a0&a3) ^ (a1&a3) ^ a4 ^ (a2&a4)
b2 = (a1&a2) ^ a3 ^ (a2&a3) ^ a4 ^ (a0&a4)
b3 = (a0&a2) ^ (a1&a3) ^ (a2&a3) ^ a4
b4 = a0 ^ (a2&a3) ^ (a1&a4)
```

### Π10 (Algorithm 9, §1.6.7) and A_{b,t} (Algorithm 8, §1.6.6)
```
Pi10:  n = 5i+j  ->  n' = (10*(n+1) mod 31) - 1,  i' = n'/5, j' = n' mod 5
       (10 has order 15 mod the prime 31, so this is a bijection of 30 lanes)

A_{b,t}:  for j = 0..4:  q = (b-1)*60 + 5t + j ;  x_{0,j} ^= C_q

C_q from a 7-bit LFSR, p(z) = z^7 + z + 1, s_0 = (1,0,0,0,0,0,0):
    s'_0 = s_6 ; s'_1 = s_0 XOR s_6 ; s'_l = s_{l-1} for 2 <= l <= 6
    C_q  = XOR_{l=0..6} s_{q,l} * 2^{p_l},  (p_0..p_6) = (0,2,3,6,13,28,59)
P1 uses q = 0..59, P2 uses q = 60..119 — the ONLY difference between P1 and P2.
```

## Implementation vs specification

Checked: `src/TaiChi-{512,768,1024}/CryptHash_AlgorithmInstance.c`. The three
files are identical apart from `#define TAICHI_INSTANCE` and the output stage
(512 and 768 differ only in that `#define` and a comment; 1024 adds the squeeze
Step). `drng.c` is the unmodified official DRNG. All 3 instances PASS KAT.

Verified:

- **Rate/capacity split.** `RATE_BITS` = 1408 / 1152 / 896 and
  `CAPACITY_WORDS = (1920 - RATE_BITS)/64` = 8 / 12 / 16, so
  (r, c) = (1408,512), (1152,768), (896,1024) and r + c = 1920 with 30 lanes in
  every case ✓ Table 1.2. c = d holds ✓.
- **Round count is 12** (`for(t = 0; t < 12; t++)`) for both P1 and P2 ✓ §1.6.2.
  No reduced-round shortcut.
- **Round order** inside the loop is MRM → S-box → Π10 → constants ✓ Algorithm 3.
- **MRM parameters.** `n1[16]`, `n2[16]`, `m[16]` reproduce spec Table 1.3
  entry for entry (all 48 values checked), and the six output rotations
  (0, 15, 48, 63, 6, 33) match Algorithm 6 ✓.
- **S-box.** All five equations match Algorithm 4 verbatim, including the
  `~0ULL ^ a1` complement in `b1` ✓.
- **Π10.** `np = (10*(n+1) % 31) - 1; ip = np/5; jp = np%5` ✓ Algorithm 9.
- **Round constants.** `precompute_RC()` reproduces the §1.6.6 LFSR exactly
  (taps `s'_0 = s_6`, `s'_1 = s_0 ⊕ s_6`, shift for the rest; bit positions
  {0,2,3,6,13,28,59}). I computed q = 0..9 by hand from the code and they match
  spec Table 1.4 exactly (1, 4, 8, 0x40, 0x2000, 0x10000000,
  0x0800000000000000, 5, 0xc, 0x48) ✓. `q = (b-1)*60 + 5t + j` and the XOR into
  lanes 0..4 (row 0) after Π10 ✓ Algorithm 8. **The P1/P2 domain separation via
  the constant offset 60 is present** (`TaiChi_P1` → b=1, `TaiChi_P2` → b=2).
- **Step function.** `TaiChi_Step()` matches Algorithm 1 line for line,
  including `L' = C` and `R' = B ⊕ C` ✓.
- **Domain tags.** `enc(Ab)=1, enc(Fin)=2, enc(Sq)=3` XORed into `state[29]`,
  the last capacity lane, before P1 ✓ §1.4; the reserved value 0 is never used.
- **Padding.** `TaiChi_Padding()` appends `1`, advances to the smallest
  `total_bits ≡ r−1 (mod r)`, then appends the second `1`, giving a total
  length ≡ 0 (mod r). I checked the boundary case `|M| ≡ r−1 (mod r)`: it
  correctly produces `j = r−1` and one extra block, matching
  `|M| + 2 + j ≡ 0 (mod r)` ✓ §1.3. Trailing partial-byte message bits are
  masked off before the `1` is written.
- **Initial state** `S = L = R = 0` ✓ §1.5; absorb tag `Ab` on all blocks but
  the last, `Fin` on `M_{α−1}` ✓ Algorithm 2.
- **Output.** 512 and 768 take `⌊S0⌋_d` with no squeeze ✓ §1.7.1/§1.7.2.
  **1024 performs exactly one squeeze Step** with an all-zero block and tag
  `Sq`, writing 112 bytes of S0 then 16 bytes of S1 — precisely
  `H = S0 || ⌊S1⌋_128` of §1.7.3 ✓.
- **`ROTL64(x, 0)`** is `(x << 0) | (x >> ((64-0)&63))` = `x`, i.e. the `&63`
  mask makes the six zero rotation amounts in `m[]` well-defined (contrast
  hash-23, which has the same situation without the mask) ✓.
- **Digest-length check.** `CryptHash()` returns −1 unless
  `digest_len_bits == TAICHI_INSTANCE` ✓.

Discrepancies and notes:

- **No round-count, padding, rate/capacity or domain-separation deviation was
  found.** All three instances implement 12 rounds, the `10*1` pad, the Table
  1.2 splits, the three-way phase tag and the P1/P2 constant-offset separation
  as specified, and the per-instance squeeze schedule (0/0/1) is correct.
- **(b) Spec ambiguity — bit order of `enc(D)` inside the c-bit capacity
  string.** §1.4 says `enc(D)` is "zero except in its two least-significant
  bits" but never fixes how the c-bit string maps onto the capacity lanes. The
  implementation XORs into bit 0 of `state[29]` (the last lane). This is the
  natural reading given §1.6.1's "each lane a 64-bit little-endian word", and
  the KATs make it normative, but the spec does not state it.
- **(a) Non-reentrancy / redundant work:** `precompute_RC()` is called at the
  top of **every** `P1920()` invocation and writes a file-scope mutable
  `static uint64_t RC[120]`. This recomputes the 120-constant table twice per
  Step (pure waste) and makes the library **not thread-safe**: two threads
  hashing concurrently race on `RC[]`. The values written are always identical,
  so the race is benign on any real platform, but it is a data race by the C
  memory model and the array should be `const`/computed once.
- **(a) Minor error handling:** on `malloc` failure `TaiChi_Hash()` returns
  without writing `digest`, yet `CryptHash()` still returns 0 — a silent
  success with an uninitialised digest buffer.
- **Spec-acknowledged claim ceiling (not an implementation defect):** §2.1 caps
  preimage security at `2^c` because of the "projected inverse-rate route", and
  since `c = d` for all three instances the spec explicitly states that TaiChi
  has **no capacity margin beyond the digest size**. §2.1 also says second-
  preimage resistance is only an upper bound (`λ_sec ≤ min{d, c}`) and that no
  proof is given. Worth carrying forward: the 2c-bit hidden state does *not*
  buy security above 2^c under the spec's own analysis.

Coverage: no independent differential/linear/algebraic analysis of P1920 was
attempted; §2.4–§2.5's MILP and statistical screening results were read but not
re-derived. The IFS-mode proof of §2.2 was not audited.
