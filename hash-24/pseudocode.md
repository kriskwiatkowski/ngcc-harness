# hash-24 QuantaSylva Hash (QSH) — algorithm summary

QSH is a **BLAKE3-style binary tree hash** whose node function is a JH-like
compression function `F_{3,w}` built on **ChaCha Bahru**, an ARX permutation
that lifts ChaCha's 4×4 column/diagonal rhythm to a 4×4×4 cube of w-bit words.
The message is padded, split into m-bit blocks, grouped into 16-block *chunks*
hashed independently (the parallelism), and the chunk chaining values are
combined by a binary tree of `PARENT` nodes; four domain-separation flags
(CHUNK_START / CHUNK_END / PARENT / ROOT) tag every compression call.

Specification: `hash-24-spec.pdf` (44 pages), §2 (parameters/flags), §3
(permutation), §4 (compression), §5 (mode), §7.1–7.2 (claims).

## Parameters

| parameter | QSH-512 | QSH-768 | QSH-1024 | meaning |
|---|---|---|---|---|
| word w | 32 | 64 | 64 | bits |
| d | 3 | 3 | 3 | cube dimension, 4³ = 64 words |
| state h | 2048 | 4096 | 4096 | bits = 4^d · w |
| words per state u | 64 | 64 | 64 | 4^d |
| message block m | 1024 | 2048 | 2048 | bits = h/2 |
| words per block v | 32 | 32 | 32 | u/2 |
| chaining value m/2 | 512 | 1024 | 1024 | bits (16 words) |
| digest n | 512 | 768 | 1024 | bits |
| full rounds n_r | 9 | 18 | 18 | `n_r = d·(3w/32)`, §3.4 |
| + final column-only layer | 1 | 1 | 1 | `R*_{d,w}` (Algorithm 2 line 5) |
| **rounds, spec Table 3** | **10** | **19** | **19** | counts the final column layer |
| G calls per full round | 48 | 48 | 48 | 3 passes × 16 |
| σ = (σ1..σ4) | (1,15,0,8) | (1,31,0,16) | (1,31,0,16) | `(1, w/2−1, 0, w/4)` |
| τ = (τ1..τ4) | (16,12,8,7) | (32,28,16,15) | (32,28,16,15) | `(w/2, w/2−4, w/4, w/4−1)` |
| blocks per chunk ρ | 16 | 16 | 16 | §2.2 |
| IV constant H⁽⁻¹⁾₀ | 17 | 1 | 7 | §5.3 — the only per-variant separator for 768 vs 1024 |
| collision (classical) | 256 | 384 | 512 | bits, spec Table 5 |
| (2nd-)preimage (classical) | 512 | 768 | 1024 | bits |
| collision (quantum) | 512/3 | 256 | 1024/3 | bits |
| (2nd-)preimage (quantum) | 256 | 384 | 512 | bits |

There is **no rate/capacity** — QSH is not a sponge. The analogous quantity is
the h-bit compression-function state against an m/2-bit chaining value: §7.2.2
cites the JH bounds Θ(2^{h/2}) for collisions and Θ(2^h) for preimages on the
full state, and notes h = 4n (512, 1024) or h = (16/3)n (768).

Sizes (bytes), specification vs the built reference library:

| instance | digest spec | digest impl (OBSERVED) | match |
|---|---|---|---|
| QSH-512 | 64 | digest_bits=512, digest_bytes=64 | yes |
| QSH-768 | 96 | digest_bits=768, digest_bytes=96 | yes |
| QSH-1024 | 128 | digest_bits=1024, digest_bytes=128 | yes |

## Pseudocode

### Pad (§5.1) and parse (§5.2)
```
Pad(M, m):   # l = |M|
    return M || 1 || 0^{2m - 129 - (l mod m)} || <l>_128        # length LITTLE-endian
    # |padded| = l + 2m - (l mod m), always a multiple of m and >= l + m + 1

N  = |padded| / m                      # m-bit blocks M^(1)..M^(N)
Pi = ceil(N / rho)                     # rho = 16 blocks per chunk
C^(t) = M^((t-1)rho+1) || .. ;  the last chunk may be short but is never empty
```

### F_{3,w} — compression (Algorithm 3, §4)
```
F(H, M, flag):                          # H: u words, M: v words, flag: one word
    for j = 0..v-1:
        S_j     = H_j
        S_{v+j} = H_{v+j} + M_j  (mod 2^w)      # first message injection
    S_0 = S_0 XOR flag                          # domain separation (Remark 1)
    S   = E_{3,w}(S)                            # ChaCha Bahru
    for j = 0..v-1:
        H'_j     = S_j + M_j  (mod 2^w)         # second (feed-forward) injection
        H'_{v+j} = S_{v+j}
    return H'
```
Flags (§2.3, Table 2): `CHUNK_START = 1, CHUNK_END = 2, PARENT = 4, ROOT = 8`,
combined with bitwise OR; a call with no applicable role uses `flag = 0`.

### E_{3,w} — ChaCha Bahru (Algorithm 2, §3.4)
```
E(S):
    A = S as 64 w-bit words, cube index i = 16*x0 + x1 + 4*x2   (d = 3, §3.3)
    repeat n_r times:  A = R_{3,w}(A)
    A = column-only layer:  G along axis 0
    return A
```

### R_{3,w} — round (Algorithm 1, §3.3), three 16-G passes
```
R(A):
    G along axis x0                                        # "columns"
    P16 on (x0,x1)-planes ; G along axis x0 ; P16^-1       # "diagonals" of (x0,x1)
    P16 on (x1,x2)-planes ; G along axis x1 ; P16^-1       # "diagonals" of (x1,x2)

P16 : a'_{i,j} = a_{i,(j+i) mod 4}      # row i cyclically left-shifted by i (§3.2)
```

### G — quadruple transformation (§3.1)
```
G(a,b,c,d):
    a = a + (b <<< s1);   d = (d XOR a) <<< t1
    c = c + (d <<< s2);   b = (b XOR c) <<< t2
    a = a + (b <<< s3);   d = (d XOR a) <<< t3
    c = c + (d <<< s4);   b = (b XOR c) <<< t4
    # (s1..s4) = (1, w/2-1, 0, w/4);  (t1..t4) = (w/2, w/2-4, w/4, w/4-1)
```
The difference from ChaCha's quarter-round is that the addend is rotated
(`a += b <<< s_i` instead of `a += b`), which §3.1/§7.3.3 say removes the three
probability-one difference patterns of the original quarter-round.

### Tree mode and indifferentiability (§5.3–§5.4, §7.2.1)
```
H^(-1) = (iv0, 0, 0, ..., 0)                 # iv0 = 17 / 1 / 7 per variant
H^(0)  = F(H^(-1), 0^m, flag = 0)            # precomputed, reused everywhere

# leaf: chunk C^(t) with L blocks (L = rho except possibly the last chunk)
ChunkCV(C, is_only_chunk):
    H = H^(0)
    for i = 1..L:
        flag = 0
        if i == 1: flag |= CHUNK_START
        if i == L: flag |= CHUNK_END
        if i == L and is_only_chunk: flag |= ROOT
        H = F(H, M^(i), flag)
    return trunc_{m/2}(H)                    # first 16 words

# internal node
Parent(cvL, cvR, is_root):
    flag = PARENT | (is_root ? ROOT : 0)
    return trunc_{m/2}( F(H^(0), cvL || cvR, flag) )

# tree shape (§5.4): left subtree is a COMPLETE binary tree whose chunk count is
# a power of two, and is >= the right subtree's chunk count.
#   Pi == 1  ->  cv_root = ChunkCV(C^(1), is_only_chunk = true)
#   Pi >= 2  ->  cv_root = topmost Parent(..., is_root = true)

Digest = trunc_n(cv_root)                    # words serialised LITTLE-endian
```
Indifferentiability rests on §7.2.1's appeal to the sound-tree-hashing results
of [21,27,19,28]: every compression call is tagged by a flag, leaves
(`CHUNK_START`/`CHUNK_END`) are separated from internal nodes (`PARENT`), the
root is separated by `ROOT`, and the tree shape is a deterministic function of
Π, which the 128-bit length field in the padding pins down. Note that, unlike
BLAKE3, **no chunk counter is mixed into leaf compressions** — the tree is made
decodable by the fixed chunk size ρ = 16 plus the length encoding, not by an
explicit index.

### Variable digest lengths
Only n ∈ {512, 768, 1024}. QSH-512 and QSH-1024 output the full root chaining
value (n = m/2); **QSH-768 truncates** a 1024-bit root CV to 768 bits. QSH-768
and QSH-1024 share every other parameter (w = 64, m = 2048, n_r = 18), so the
only thing preventing QSH-768's digest from being a 768-bit prefix of
QSH-1024's is the differing IV constant `H^(-1)_0` (1 vs 7). That separation is
present in both the spec and the code. There is no XOF mode.

## Implementation vs specification

Checked: `src/QSH-{512,768,1024}/CryptHash_AlgorithmInstance.c` — the three
files are **byte-identical** (md5 `f2171d23…`); only the `.h` (`ALGORITHM_INSTANCE`,
`DIGEST_BIT_LENGTH`) differs. `drng.c` is the unmodified official DRNG.
Non-standard tree layout: `QSH/Implementations/03_Implementations/1_Reference_Implementation`
with vectors in `QSH/Test_Vectors/04_TestVectors`; `3_Additional_Implementation`
is not built. All 3 instances PASS KAT.

Verified:

- **Round counts.** `select_params()` sets `rounds = 9` for w = 32 and `18` for
  w = 64, and `E3()` runs `rounds` full `R3` rounds **plus** a final
  `G_along(s, 0, P)` column-only layer. This exactly implements Algorithm 2
  (`n_r = d·(3w/32)` = 9 / 18, then `R*_{d,w}`). Spec **Table 3's "Rounds 10 /
  19" counts that final column-only pass as a round** — I checked this
  explicitly because a bare `rounds = 9` against a table saying 10 looks like a
  round-count shortfall. It is not: 9 + 1 = 10 and 18 + 1 = 19. The spec would
  be clearer if Table 3 said `n_r + 1`.
- **Cube indexing.** `idx(x0,x1,x2) = 16*x0 + 4*x2 + x1` reproduces §3.3's
  `i = x0·4^{d-1} + Σ_{j≥1} x_j·4^{j-1}` for d = 3 (= 16x0 + x1 + 4x2) ✓.
- **Round function.** `R3()` is exactly the three passes of Algorithm 1 for
  d = 3: G along axis 0; P16 / G-axis-0 / P16⁻¹ on the (x0,x1) planes; P16 /
  G-axis-1 / P16⁻¹ on the (x1,x2) planes ✓.
- **P16.** `src = (c + r) % 4` gives `a'_{r,c} = a_{r,(c+r) mod 4}` ✓ §3.2, with
  the inverse `(c + 4 - r) % 4` ✓.
- **G constants.** `s1=1, s2=w/2-1, s3=0, s4=w/4; t1=w/2, t2=w/2-4, t3=w/4,
  t4=w/4-1` ✓ §3.1, giving (1,15,0,8)/(16,12,8,7) for w=32 and
  (1,31,0,16)/(32,28,16,15) for w=64, matching Figure 1. `rotl()` special-cases
  `r == 0`, so the σ3 = 0 rotation is not UB.
- **Compression.** `F3()` matches Algorithm 3 line for line, including both
  modular-addition injections and `S[0] ^= flag` ✓.
- **Flags.** `1, 2, 4, 8` = `2^0..2^3` ✓ Table 2, and the flag logic in the
  chunk loop and `tree()` matches Algorithms 4 and 5 ✓.
- **Padding.** `tot_bits = L + 2m - (L % m)` is exactly §5.1's
  `l + 1 + (2m − 129 − (l mod m)) + 128` ✓. `padded_byte()` places the `1` bit
  MSB-first after the (masked) partial byte and writes the length as a 128-bit
  little-endian field in the last 16 bytes; the high 64 bits are hard-coded to
  zero, which is correct for any `msg_len_bits` representable in
  `unsigned long long` ✓. The `1` bit can never collide with the length field
  because the padding is always ≥ m + 1 ≥ 1025 bits.
- **IVs.** `iv0 = 17 / 1 / 7` for 512 / 768 / 1024 ✓ §5.3, and
  `H^(0) = F(H^(-1), 0^m, flag = 0)` ✓.
- **Tree shape.** `largest_pow2_lt(n)` returns the largest power of two
  **strictly** less than n (n=2→1, 3→2, 4→2, 5→4, 8→4), so the left subtree is
  always a complete binary tree with a power-of-two chunk count and is never
  smaller than the right one ✓ — both §5.4 rules hold.
- **Truncations and output encoding.** Chunk and parent CVs take the first
  `V/2 = 16` words = m/2 bits ✓; the digest serialises the root CV
  little-endian and stops at `n/8` bytes, so QSH-768's 768-bit truncation of a
  1024-bit CV is implemented ✓ §5.4.

Discrepancies and notes:

- **(b) Spec self-contradiction in Remark 1 (§4).** The prose says "the flag is
  mixed into the **last word** of the state by `S_0^{(i-1)} = S_0^{(i-1)} ⊕
  flag`" — "last word" contradicts the formula's `S_0`, and Algorithm 3 line 5
  also says `S_0`. The implementation uses `S[0]` (`CryptHash_AlgorithmInstance.c:155`),
  following the formula and Algorithm 3. Only the English is wrong, but an
  implementer taking the prose literally would XOR the flag into `S_63` and get
  a different function.
- **(b) Spec Table 3 round count vs §3.4's `n_r`** — see above; the two differ
  by the final column-only layer and the spec never says so.
- **(b) §7.2.1 typo:** "it remains **distinguishable** from a random oracle when
  instantiated with an ideal compression function" — evidently "indistinguishable".
  The sentence as printed asserts the opposite of the intended claim.
- **(c) Deliberate inefficiency, not a deviation:** `tree()` recomputes
  `initial_state(H0, P)` — a full `E_{3,w}` evaluation — at every parent node,
  although §5.3 says `H^(0)` "is computed once and reused". Output is identical;
  it just costs one extra permutation per internal node.
- **(a) Minor robustness:** `malloc((size_t)Pi * half * sizeof(uint64_t))` is
  unchecked for multiplication overflow (only for absurdly long messages), and
  `tree()` recurses to depth ⌈log2 Π⌉ so stack depth is fine.
- **No round-count shortfall, no padding deviation, no missing domain
  separation, and no hard-wired constant that the spec says should vary** was
  found: the per-variant IV constants 17/1/7, the per-variant word width and
  round count, and all four flags are all present and correct.

Coverage: no independent differential/linear/rotational analysis of ChaCha
Bahru was attempted; §7.3's trail bounds and the §7.2 JH-style bounds were read
but not re-derived. The claim that the tree mode is indifferentiable was checked
only structurally (flag separation + length-determined shape), not against the
formal sound-tree-hashing conditions of the cited references.
