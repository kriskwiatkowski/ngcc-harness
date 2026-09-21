# hash-27 Vedak — algorithm summary

Vedak is a plain sponge hash family over **Vedak-p**, a 2560-bit, 40-round,
nibble-oriented SPN permutation designed for SIMD. The state is 640 nibbles
seen as a 10 × 4 array of 64-bit words; each round applies 640 parallel 4-bit
S-boxes (ν), a 10 × 10 binary matrix down each of the 4 columns (λ), a
per-row 32-bit word permutation plus blockwise 32-bit rotation (ψ), and a
32-bit round constant on the first 8 nibbles (ω). Security is the standard
sponge capacity argument with `c = 2ℓ`.

Specification: `hash-27-spec.pdf` (45 pages), §2.2–2.4 (algorithm), §3.2
(component rationale, Tables 4 and 5), §4 (claims).

## Parameters

| parameter | Vedak-512 | Vedak-768 | Vedak-1024 | meaning |
|---|---|---|---|---|
| state width | 2560 | 2560 | 2560 | bits = 640 nibbles = 40 × 64-bit words |
| rate r | 1536 | 1024 | 512 | bits, Table 1 |
| capacity c | 1024 | 1536 | 2048 | bits, c = 2ℓ |
| digest ℓ | 512 | 768 | 1024 | bits |
| rounds | 40 | 40 | 40 | §2.4, "40 iterations" |
| S-box | 4-bit bijection, 640/round | idem | idem | §2.4.1 |
| λ matrix | 10 × 10 binary, 4 copies | idem | idem | §2.4.2 |
| ψ | P_w^(i) + ≪₃₂ m_i per row | idem | idem | §2.4.3, Table 2 |
| round constants | RC₀..RC₃₉, 32 bits each | idem | idem | Table 3 |
| squeeze blocks ⌈ℓ/r⌉ | 1 | 1 | 2 | 1024 > 512 |
| collision (classical) | 2²⁵⁶ | 2³⁸⁴ | 2⁵¹² | Table 6 |
| preimage / 2nd-preimage | 2⁵¹² | 2⁷⁶⁸ | 2¹⁰²⁴ | Table 6 |
| preimage (quantum) | 2²⁵⁶ | 2³⁸⁴ | 2⁵¹² | §4 (Grover) |

Round margin: the spec's own best attacks (§4.3, Table) reach only **5 rounds**
(preimage on all three variants at 2⁵⁰⁸/2⁷⁶⁴/2¹⁰²⁰, collision on Vedak-1024 at
2⁵¹⁰) against a 40-round permutation, and §3.2.3 shows the linear layer reaches
full diffusion in 5 rounds and cannot in 4.

Sizes (bytes), specification vs the built reference library:

| instance | digest spec | digest impl (OBSERVED) | match |
|---|---|---|---|
| Vedak-512 | 64 | digest_bits=512, digest_bytes=64 | yes |
| Vedak-768 | 96 | digest_bits=768, digest_bytes=96 | yes |
| Vedak-1024 | 128 | digest_bits=1024, digest_bytes=128 | yes |

## Pseudocode

### Padding (§2.3)
```
pad_r(M) = M || 1 || 0^t || 1,   t = (-|M| - 2) mod r
|pad_r(M)| == 0 (mod r)                        # multi-rate pad10*1
```

### Vedak hash (Algorithm 1, §2.2)
```
M' = pad_r(M);  parse as M_0 .. M_{n-1}, each r bits
S  = 0^2560                                    # all-zero initial state
for i = 0 .. n-1:
    S = S XOR (M_i || 0^{2560-r})              # absorb into the first r bits
    S = Vedak-p(S)
Z* = S[0 : r-1]
while |Z*| < l:
    S  = Vedak-p(S)
    Z* = Z* || S[0 : r-1]
return Z = Z*[0 : l-1]
```
**Variable digest length:** only ℓ ∈ {512, 768, 1024}, each with its own
(r, c) = (2560−2ℓ, 2ℓ). There is **no domain-separation constant**: all three
start from the all-zero state with the same `10*1` pad and the same 40-round
permutation, and separation comes solely from the differing rate. Vedak-512 and
Vedak-768 need one squeeze block; Vedak-1024 (r = 512) needs two, with one extra
permutation between them.

### Vedak-p (Algorithm 2, §2.4) — 40 rounds
```
state X = (X_{i,j}), 0<=i<10, 0<=j<4, each X_{i,j} a 64-bit word (16 nibbles)
                                     linear index t = 4i + j
for Round = 1 .. 40:
    U = nu(X)      # S-box layer
    V = lambda(U)  # column matrix
    W = psi(V)     # row permutation + rotation
    X = omega(W)   # round constant
```

### ν (§2.4.1)
```
s = [1,0,5,6,C,9,2,8,A,7,3,F,E,B,4,D]        # 4-bit bijection
U_t = ( s(x_{t,0}), ..., s(x_{t,15}) )       # 16 S-boxes per 64-bit word
```

### λ (§2.4.2) — the same 10×10 binary matrix M on each of the 4 columns
```
(V_{0,j} .. V_{9,j})^T = M * (U_{0,j} .. U_{9,j})^T,   j = 0..3

V_0 = U0^U2^U6^U7^U8          V_5 = U0^U1^U2^U5^U7^U9
V_1 = U2^U4^U5^U8^U9          V_6 = U0^U3^U4^U5^U7^U8
V_2 = U0^U3^U5^U6^U9          V_7 = U2^U3^U4^U6^U7^U9
V_3 = U1^U4^U5^U6^U7          V_8 = U1^U2^U3^U5^U6^U8
V_4 = U1^U3^U7^U8^U9          V_9 = U0^U1^U4^U6^U8^U9
```

### ψ (§2.4.3, and its decomposition in §3.2.3)
Each row i of four 64-bit words is seen as eight 32-bit words
`V_{i,j} = Ṽ_{i,2j} ‖ Ṽ_{i,2j+1}`. `P^(i)` = a 32-bit word permutation
`P_w^(i)` followed by a blockwise 32-bit cyclic rotation by `m_i`:
```
i :   0            1            2            3            4
Pw : (5,4,7,6,     (2,3,0,1,    (6,7,4,5,    (7,6,5,4,    (3,2,1,0,
      1,0,3,2)      6,7,4,5)     2,3,0,1)     3,2,1,0)     7,6,5,4)
m  :  16            4            12           0            28

i :   5            6            7            8            9
Pw : (0,1,2,3,     (0,1,3,2,    (4,5,7,6,    (5,4,6,7,    (1,0,2,3,
      4,5,6,7)      4,5,7,6)     0,1,3,2)     1,0,2,3)     5,4,6,7)
m  :  0             20           12           20           4
```
`P_w^(i)` factors (§3.2.3) into a 64-bit word permutation `P_i` (Table 4) and a
per-position 32-bit half-swap flag `α_{i,j}` (Table 5):
```
P_i    : [2,3,0,1] [1,0,3,2] [3,2,1,0] [3,2,1,0] [1,0,3,2]
         [0,1,2,3] [0,1,2,3] [2,3,0,1] [2,3,0,1] [0,1,2,3]
alpha_i: 1111      0000      0000      1111      1111
         0000      0101      0101      1010      1010
Swap32(xL || xR) = xR || xL
```

### ω (§2.4.4)
```
X_{0,0}[0:31] ^= RC_d          # 32-bit constant on the first 8 nibbles
RC_0 = 0x2c387d69 ... RC_39 = 0xb4a0e5f1       # spec Table 3
```

## Implementation vs specification

Checked: `src/Vedak-{512,768,1024}/CryptHash_AlgorithmInstance.c`. All three are
**functionally identical** (512 differs from 768/1024 only by two blank lines;
768 and 1024 are byte-identical). `drng.c` is the unmodified official DRNG. All
3 instances PASS KAT.

Verified:

- **Round count is 40** (`#define VEDAKF_ROUNDS 40`, `for r < 40`) ✓ §2.4. No
  shortfall.
- **Round order** `apply_S → apply_L → apply_P → apply_AC` = ν, λ, ψ, ω ✓
  Algorithm 2.
- **Rate/capacity** `r_bitlen = 2560 - 2*digest_len_bits` = 1536 / 1024 / 512 ✓
  Table 1, with c = 2ℓ ✓.
- **S-box.** `S_BOX_8[256]` is the byte-wise square of the §2.4.1 table; I
  verified entries 0x00, 0x01, 0x0F, 0x40, 0x4C against
  `s = [1,0,5,6,C,9,2,8,A,7,3,F,E,B,4,D]` — all correct ✓.
- **λ.** All ten output equations in `apply_L()` reproduce the ten rows of the
  §2.4.2 matrix M exactly (checked row by row) ✓, applied per column with the
  indexing `state[j + 4*i]` = `X_{i,j}` ✓ (`t = 4i + j`, §2.4).
- **ψ word permutation.** `PI[10][4]` equals spec **Table 4** entry for entry,
  and `ALPHA[10][4]` equals spec **Table 5** entry for entry ✓. I also checked
  that composing them reproduces the `P_w^(i)` of Table 2: e.g. i = 6 gives
  (0,1,3,2,4,5,7,6) ✓, i = 8 gives (5,4,6,7,1,0,2,3) ✓, i = 3 gives
  (7,6,5,4,3,2,1,0) ✓.
- **ψ rotation magnitudes.** `RHO = {4,1,3,0,7,0,5,3,5,1}` with
  `shift = RHO[i]*4` gives {16,4,12,0,28,0,20,12,20,4} = the `m_i` column of
  spec Table 2 exactly ✓ (direction: see discrepancy 1).
- **ω.** `state[0] ^= ((u64)rc << 32)` XORs the constant into the **high** 32
  bits of word 0; with `load64_be`/`store64_be` that is the first 8 nibbles of
  the state ✓ §2.4.4. `RC[40]` reproduces spec Table 3 verbatim ✓.
- **Padding.** `zero_bits = (r - ((L+2) mod r)) mod r` and the two `1` bits at
  positions `L` and `padded_bits-1` implement `M‖1‖0^t‖1` with
  `t = (−|M|−2) mod r` ✓ §2.3; the two bits can never collide because
  `padded_bits − 1 ≥ L + 1`.
- **Absorb/squeeze.** Initial state all-zero ✓; message XORed into the first
  `r/64` words ✓; the squeeze loop reads `min(r, remaining)` and permutes only
  *between* blocks ✓ Algorithm 1 — so Vedak-512/768 do one read and Vedak-1024
  does two with one extra permutation ✓.
- **Byte order.** `load64_be`/`store64_be` throughout, consistent with the
  spec's `S[0 : r−1]` MSB-first bit indexing ✓ (unlike hash-23/hash-26, Vedak's
  reference code is endian-neutral).

Discrepancies:

1. **(a) Rotation direction in ψ contradicts the specification's notation.**
   §2.4.3 writes the blockwise 32-bit rotation as `≪₃₂ m_i`, and §2.1 defines
   `≪` (U+226A) as "left cyclic shift by m bits" — the second table entry, for
   the blockwise variant, reuses the *same glyph* and says only "blockwise
   32-bit cyclic shift by m bits" without restating the direction. The
   reference implementation performs a **right** rotation:
   `L = rotr32(L, shift); R = rotr32(R, shift);` (`CryptHash_AlgorithmInstance.c:227-228`),
   with `shift = RHO[i]*4` equal to `m_i`. Since `rotr(x,m) = rotl(x,32−m)`, the
   two readings agree only for `m_i ∈ {0, 16}` — rows 3, 5 and 0. For the other
   **seven** rows (m = 4, 12, 28, 20, 12, 20, 4) an implementer following the
   spec's left-shift notation builds a different permutation and fails the KATs.
   The magnitudes in Table 2 match the code exactly, so this is purely a
   direction/notation defect, but it makes §2.4.3 unimplementable as written.
   (Note the same glyph-collision pattern as hash-26.)
2. **(b) `≪₃₂` is never formally defined.** §2.1 gives a one-line gloss and
   §2.4.3/§3.2.3 give no formula, so even the "blockwise" granularity (each
   32-bit half rotated independently, as the code does, rather than the 64-bit
   word rotated by m) has to be inferred.
3. **No domain separation between digest lengths.** All three variants use the
   all-zero initial state, the same `10*1` pad and the same 40-round Vedak-p;
   only the rate differs. This follows Algorithm 1 as written and does not
   create a cross-variant relation (different r ⇒ different block splitting),
   but Vedak, like Qilin and unlike SHA-3, has no suffix bits at all — which
   matters if the same permutation is ever reused for other modes.
4. **(a) Minor API laxity.** `CryptHash()` validates only that
   `digest_len_bits ∈ {512, 768, 1024}`; it never compares against
   `DIGEST_BIT_LENGTH`. Because the three `.c` files are identical, the
   Vedak-512 library will happily produce a 128-byte Vedak-1024 digest. Does
   not affect KAT conformance.
5. **(a) Dead code from an earlier version.** Lines 76–93 contain a **second,
   commented-out `S_BOX_8` table** implementing a different 4-bit S-box
   (`s'(0)=3, s'(1)=0, s'(2)=6, …`). It is inert, but it is a leftover from a
   previous S-box choice and should be removed from a reference implementation.
6. **(a) Performance / portability nits.** The padded message is built one bit
   at a time (`for i < msg_len_bits: set_bit_msb_first(...)`), which is O(|M|)
   bit operations rather than a `memcpy`; and `vedak_hash_bits()` takes
   `size_t msg_len_bits` while `CryptHash()` receives `unsigned long long`, so
   messages longer than `SIZE_MAX` bits are silently truncated on 32-bit hosts.
7. **No round-count, padding or rate/capacity deviation was found.** 40 rounds,
   the multi-rate pad, and the (r, c) = (2560−2ℓ, 2ℓ) splits are all exactly as
   specified, and every parameter table (M, Table 2/3/4/5) matches the code.

Coverage: no independent differential/linear/MITM analysis of Vedak-p was
attempted; §4.1–§4.3's MILP bounds and the 5-round attacks were read but not
re-derived.
