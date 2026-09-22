# hash-34 WChain — algorithm summary

WChain is an **iterated compression-function (Merkle–Damgård-style) hash** with
three hardening features that the designers call **FChain**: (i) a wide hidden
chaining state `b = h + λ` truncated to `h` bits at the end, (ii) a two-step
feedback `H_i = CF(H_{i-1}, M_i) ⊕ H_{i-2}`, and (iii) a finalization call on a
**checksum block** `Σ = M_1 ⊕ … ⊕ M_l` over all padded message blocks. The
compression function is a Davies–Meyer-style feed-forward
`CF(V,B) = X_R ⊕ B̂_R ⊕ V` around an `R`-round keyed-by-message-expansion
permutation with round `L5w ∘ π ∘ S ∘ Iota_j` (9-bit NAND2/chi S-box, fixed
9-bit wiring `π`, 5-term rotate-XOR lane mixer `L5w`).

Specification: `hash-34-spec.pdf` (36 pages), §2 (Table 1) and §3
(Algorithms 1–2, Tables 2–5, Eqs. 1–37). English.

## Parameters

| parameter | WChain-V1-512 | WChain-V2-1024 | meaning |
|---|---|---|---|
| h | 512 | 1024 | digest bits |
| b (chaining state) | 576 | 1152 | bits = 9 / 18 lanes of 64 |
| λ = b − h | 64 | 128 | hidden state bits |
| µ (message block) | 1152 | 2304 | bits = 2·b = 144 / 288 bytes |
| R (rounds of CF) | 18 | 24 | |
| state shape | 9 × 64 | 2 × (9 × 64) | one / two halves |
| S-box | 9-bit NAND2/chi | same | deg 2 fwd, deg 5 inv, DDTmax 128, LATmax 128 |
| π | [0,7,5,3,1,8,6,4,2] | same | intra-column wiring |
| linear layer | `L5w` (Table 4) | `L^II_5w` = cross-swap + (Table 4, Table 5) | support {0,1,2,3,7} mod 9 |
| round constants | `π^(16)_j ≪ i`, i=0..8 | `≪ i` (left), `≪ i+9` (right) | 16-bit words of frac(π) |
| IV | **all-zero** | **all-zero** | `H_{-1} = H_0 = 0` (§6.1) |
| padding | 10* (no length field) | 10* | |
| digest-collision bound (§5.1) | 2^256 | 2^512 | = 2^{h/2} |
| internal-state collision (§5.1) | 2^288 | 2^576 | = 2^{b/2} |
| preimage | — | — | **no explicit numeric claim in the spec** |

Sizes (bytes), specification vs the built reference library (OBSERVED):

| instance | digest spec | digest impl | match |
|---|---|---|---|
| WChain-V1-512 | 64 | 64 | yes |
| WChain-V2-1024 | 128 | 128 | yes |

## Pseudocode

### Round function (spec §3.4, Eqs. 12–32)
```
Version I state: A[0..8], 64-bit lanes (i = 3x + y).
Round_j(A):
    Iota_j: A[i] ^= rotl64(pi16[j], i)            for i = 0..8    # Eq. 20
    S     : for each bit column z, b_i = a_i XOR NOT( NOT(a_{i+1}) AND a_{i+2} )
                                       = a_i XOR ( a_{i+1} OR NOT a_{i+2} )
    pi    : C[pi(i)] = U[i],  pi = [0,7,5,3,1,8,6,4,2]
    L5w   : out[i] = XOR over (j,a) in R_i of rotl64(C[j], a)     # Table 4
            with support R_i = { i, i+1, i+2, i+3, i+7 } (mod 9)

Version II: two halves A_L, A_R (9 lanes each).
    Iota_j: A_L[i] ^= rotl64(pi16[j], i);  A_R[i] ^= rotl64(pi16[j], i+9)
    S, pi : applied independently to each half
    cross-swap (involution) on the post-pi halves, 5 word pairs:
            (L0,R0), (L1,R3), (L3,R1), (L4,R4), (L6,R6)
    L5w   : Table 4 rotations on the left half, Table 5 (= Table 4 + delta) on
            the right, delta = (11,21,19,21,43,5,3,10,5)
```

### Message expansion (spec §3.5, Eqs. 34–37)
```
B is parsed as big-endian 64-bit lanes.
B0 <- first b bits of B ;  B1 <- second b bits of B
D(A)[i] = rotl64(A[i], d_i),  d = (0,1,10,20,25,32,41,46,50)
MEF(A)  = S( D(A) )                      # rotations + one S-box layer
Bj      = MEF(B_{j-1}) XOR B_{j-2},      j = 2 .. R
(for Version II, MEF is applied to each 9-lane half independently)
```

### Compression function CF(V, B) (spec Algorithm 2, Eqs. 10–11)
```
(B0,...,BR) <- ME(B)
X_0 <- V
for j = 1 .. R:  X_j <- Round_j( X_{j-1} XOR B_{j-1} )
return X_R XOR B_R XOR V                 # Davies-Meyer feed-forward
```

### Hash(M, h) — WChain (spec Algorithm 1, Eqs. 2–9)
```
WChain(M):
  M* <- M || 1 || 0^k ,  k minimal with |M| + 1 + k == 0 (mod mu)   # 10*, always
  parse M* = M_1 || ... || M_l,  |M_i| = mu                         # >= 1 pad bit
  Sigma <- M_1 XOR M_2 XOR ... XOR M_l          # checksum over PADDED blocks
  H_{-1} <- 0 ;  H_0 <- IV = 0
  for i = 1 .. l:
      H_i <- CF(H_{i-1}, M_i) XOR H_{i-2}       # two-step feedback
  H_{l+1} <- CF(H_l, Sigma)                     # finalization, NO feedback term
  return Trunc_h(H_{l+1})                       # leftmost h bits, lanes BE
```

## Implementation vs specification

Checked: `src/WChain-V1-512/wchain_c.c` (1083 lines; **byte-identical** in both
instance directories) plus the 8-line `CryptHash_AlgorithmInstance.c` wrapper
and the per-instance header. Built with `-DWCHAIN_NO_MAIN -DWCHAIN_DISABLE_SIMD`
(the latter removes the AVX2/AVX-512 batch compressors, which the scalar hash
path never calls anyway). Both instances KAT-PASS (`results/summary.tsv`).

Agreements (constants checked exhaustively, not sampled):

- `WCHAIN_V1_ROUNDS 18`, `WCHAIN_V2_ROUNDS 24`, 144/288-byte blocks, 9/18-lane
  states, 64/128-byte digests — Table 1 exactly.
- `PI16[24] = {0x243f, 0x6a88, 0x85a3, 0x08d3, 0x1319, 0x8a2e, 0x0370, 0x7344,
  0xa409, 0x3822, 0x299f, 0x31d0, 0x082e, 0xfa98, 0xec4e, 0x6c89, 0x4528,
  0x21e6, 0x38d0, 0x1377, 0xbe54, 0x66cf, 0x34e9, 0x0c6c}` is exactly the
  16-bit word split of frac(π) = `243F6A8885A308D313198A2E03707344…`, matching
  Eq. 18; 24 words cover V2's 24 rounds.
- `L_ROT[9][5]` = Table 4 row for row; `R_ROT[9][5]` = Table 5 row for row;
  `L_IDX[9][5]` = the support `{i,i+1,i+2,i+3,i+7} mod 9` of Eq. 28.
- `ME_ROT = {0,1,10,20,25,32,41,46,50}` = `d` of Eq. 35.
- `P9 = {0,7,5,3,1,8,6,4,2}` = Eq. 24; `P9_INV = {0,4,8,3,7,2,6,1,5}`.
- S-box: `x[i] = a_i ^ (a_{i+1} | ~a_{i+2})`. Spec Eq. 22 (read from the
  rendered page; the overlines are lost in text extraction) is
  `b_i = a_i ⊕ ¬(¬a_{i+1} ∧ a_{i+2})`, which De Morgan turns into exactly the
  code's form. **Match.**
- `pi_mix_v1_u64()` is π and `L5w` **fused**: I expanded the fusion by hand for
  output lanes 0 and 1 using `C[j] = U[π^{-1}(j)]` and both reproduce Table 4
  exactly (e.g. lane 0 = `U0≪5 ⊕ U4≪22 ⊕ U8≪3 ⊕ U3≪28 ⊕ U1≪27`, which is
  `C0≪5 ⊕ C1≪22 ⊕ C2≪3 ⊕ C3≪28 ⊕ C7≪27`). A deliberate equivalent optimisation.
- `pi_cross_mix_v2_u64()` fuses π, the 5-pair cross-swap and the split `L5w`.
  I derived all 18 swapped inputs from `C_L[j] / C_R[j]` and every one of the
  18 `cl*/cr*` assignments in the code agrees with Eq. 29 applied to the
  post-π halves (e.g. `CL[1] = P_R[3] = U_R[3]` ↔ code `cl1 = r3`;
  `CR[3] = P_L[1] = U_L[4]` ↔ code `cr3 = l4`).
- Message expansion: round `j` injects `b_prev2` (=B̂_0) for j=1, `b_prev1`
  (=B̂_1) for j=2, and `MEF(B̂_{j-1}) ⊕ B̂_{j-2}` for j≥3; after the loop
  `b_final = MEF(B̂_{R-1}) ⊕ B̂_{R-2} = B̂_R` is XORed into the output together
  with `V` — exactly Eqs. 10, 11 and 37.
- Chaining: `h_prev1 ← c ⊕ h_prev2; h_prev2 ← old h_prev1` = Eq. 7.
  Finalization `wchain_vX_compress_loaded(h, h_prev1, Σ)` with **no** `⊕H_{l-1}`
  = Eq. 8. Digest = first `h/64` lanes, big-endian = Eq. 9 / §3.2 truncation.
- Σ accumulates every **padded** block, including the final padded one, and
  does **not** include Σ itself — Eq. 5.
- Padding: `last[]` is zeroed, `0x80 >> partial_bits` (or `0x80`) places the
  single `1` bit MSB-first, and exactly one final block is absorbed. Since the
  remainder after full blocks is at most `µ − 1` bits, the `1` always fits, so
  10* never needs two blocks. A message that is a multiple of `µ` gets a full
  extra `10^{µ-1}` block, as §3.1 requires.
- `IV = 0`: `h_prev2[] = {0}, h_prev1[] = {0}` in both hash functions, matching
  §6.1 "all-zero initial values" and Eq. 6.

Discrepancies / notes:

- No parameter or constant mismatch found between spec and implementation.
- (c) Σ is accumulated with `load64_raw` (no byte swap) and byte-swapped once at
  the end; XOR commutes with byte reversal, so this equals the spec's
  big-endian accumulation. Equivalent optimisation.
- (c) `PI16_ROT[j][i] = (uint64_t)PI16[j] << i` is a left **shift**, while
  Eq. 20/21 says `rotl64`. Because the constant is a zero-extended 16-bit value
  and `i ≤ 17`, the top bits never wrap (16 + 17 = 33 < 64), so shift = rotate
  here. Equivalent, but it would silently diverge if the constant source or the
  lane count ever changed.
- (b) The spec gives **no explicit preimage or second-preimage security claim**
  for the hash — §5.1 only derives generic collision figures (2^{h/2} digest,
  2^{b/2} internal) and structural-attack cost estimates (§5.1.1–5.1.4). Table 1
  has no security columns at all. A submission-level claim table is missing.
- (b) `λ = b − h` is only 64 bits (V1) / 128 bits (V2). The spec's own
  §5.1.1 notes that enumerating the hidden bits of `H_{l+1}` costs just 2^64 for
  Version I; it argues (correctly) that this alone is not an extension attack,
  but the margin between the digest and the full chaining state is thin.
- Not verified: the diffusion / differential-trail claims of §5.2–5.3, and
  whether `L5w` (Table 4) is invertible as claimed (Eq. 33 asserts an inverse).

### Domain separation between digest lengths — the key check

**WChain's two output lengths are separated structurally, not by a domain
constant or a distinct IV.** Concretely:

- Both versions use `IV = 0` (§6.1, confirmed in the code), the same 9-bit
  S-box, the same `π`, the same round-constant source and the same Table 4
  rotation rows. There is **no** version tag, output-length encoding or
  instance-dependent IV anywhere in the input.
- What separates them is that they are genuinely different primitives:
  `b = 576` vs `1152`, `µ = 1152` vs `2304` bits, `R = 18` vs `24`, and a
  single `L5w` vs the cross-swap + asymmetric split `L^II_5w`. The digests are
  512 vs 1024 bits, so no cross-version output can coincide and there is no
  shared permutation whose outputs are truncated differently.
- `wchain_crypt_hash_c()` dispatches strictly on `digest_len_bits ∈ {512,1024}`
  and rejects anything else; `CryptHash()` additionally rejects any length other
  than the instance's compile-time `DIGEST_BIT_LENGTH`. So the one shared source
  file cannot be coaxed into producing a third, undefined variant.

This is acceptable — the concern "one permutation shared across output lengths
without domain separation" does not apply, because the two versions do not share
a permutation. It is nevertheless worth recording that if the family were ever
extended with a third digest length **at the same state width**, the all-zero IV
would leave nothing to separate it.

### Length extension

Not directly extendable, and the spec argues this explicitly in §5.1.1: the
digest is `Trunc_h` of the **post-finalization** value `H_{l+1} = CF(H_l, Σ)`,
so continuing a message requires the pre-finalization state `H_l` (and `H_{l-1}`
for the two-step feedback) plus the running checksum `Σ`, none of which is
published. `Z` also omits `λ` state bits. The spec is careful not to overclaim
("this is a generic structural argument … it does not replace dedicated analysis
of the compression function"), which is an accurate framing. Note that the 10*
padding carries **no message-length field** (§3.1), so the usual MD
length-strengthening is absent; the checksum block is what replaces it.
