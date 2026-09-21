# hash-21 Neulaser — algorithm summary

Neulaser is a PRNG-based iterated hash family (not a sponge and not a classical
Merkle–Damgård compression function). Each padded message block `M_i` is the
*seed/key* input of one invocation of a coupled-NLSR stream generator, and the
chaining value `V_i` is its *IV* input; the first `v` output bits become the next
chaining value, and the last block additionally emits `n` bits that are the
digest. Security is reduced to an ideal-PRNG assumption (indifferentiability
proof in §5.2).

Specification: `hash-21-spec.pdf` (28 pages), §2 (mode), §3 (PRNG primitive),
§4.2 (constant derivation), §5 (security claims).

## Parameters

| parameter | Neulaser-512 | Neulaser-768 | Neulaser-1024 | meaning |
|---|---|---|---|---|
| n | 512 | 768 | 1024 | digest length (bits) |
| k | 960 | 1216 | 1472 | message-block = PRNG seed/key length (bits) |
| v | 576 | 832 | 1088 | chaining-value = PRNG IV length (bits) |
| k+v | 1536 | 2048 | 2560 | coupled-NLSR state = 512·µ bits |
| µ | 3 | 4 | 5 | number of 16-stage NLSR modules |
| stage field | F_p, p = 4294967291 | idem | idem | largest prime < 2^32 |
| module state | 16 × 32 bits | idem | idem | 512 bits/module |
| blank rounds | 32 | 32 | 32 | `N_blank`, §3.3 |
| output rounds | ⌈λ/32µ⌉ | idem | idem | λ = v (non-final) or v+n (final) |
| IV | first₁₈(IV⋆) | first₂₆(IV⋆) | first₃₄(IV⋆) | §2.3 / §4.2 |
| collision (classical) | 256 | 384 | 512 | bits, spec Table 1 |
| preimage (classical) | 512 | 768 | 1024 | bits |
| 2nd-preimage (classical) | min{512, 576−λ} | min{768, 832−λ} | min{1024, 1088−λ} | λ = log₂(#blocks) |
| collision (quantum) | 128 | 192 | 256 | bits |
| preimage (quantum) | 256 | 384 | 512 | bits |

Note: Neulaser has **no fixed permutation with a "round count"** in the usual
sense. The round budget per PRNG call is `N_blank = 32` blank rounds plus one
state update per 32µ output bits — i.e. 32 + ⌈v/32µ⌉ rounds for a non-final
block and 32 + ⌈(v+n)/32µ⌉ for the final one (512: 32+6 / 32+12; 768: 32+7 /
32+13; 1024: 32+7 / 32+14).

Sizes (bytes), specification vs the built reference library:

| instance | digest spec | digest impl (OBSERVED) | match |
|---|---|---|---|
| Neulaser-512 | 64 | digest_bits=512, digest_bytes=64 | yes |
| Neulaser-768 | 96 | digest_bits=768, digest_bytes=96 | yes |
| Neulaser-1024 | 128 | digest_bits=1024, digest_bytes=128 | yes |

## Pseudocode

### Padding and block constants (§2.1, §2.2)
```
Pad(M):                                   # spec §2.1
    z = smallest z>=0 with |M| + 1 + z + 64 == 0 (mod k)
    M* = M || 1 || 0^z || len64(|M|)      # len64 big-endian, MSB first
    return M* split into l = |M*|/k blocks M_0 .. M_{l-1}

C_i = (0^{v-64} || i_high || i_low),  i_high = floor(i/2^32), i_low = i mod 2^32
                                          # v-bit block constant, §2.2
```
The terminal length field makes the encoding prefix-free (spec's own length-
extension argument, §6.3).

### Hash(M, n) — mode (§2.3)
```
IV_n  = first_{n_words}(IV*)              # 18/26/34 32-bit words, §2.3
V_0   = IV_n XOR C_0
for i = 0 .. l-2:
    V_{i+1} = PRNG_v(V_i, M_i) XOR C_{i+1}
Z     = PRNG_{v+n}(V_{l-1}, M_{l-1})
return HashOut(Z) = last n bits of Z      # = Z^R
```
`IV*` is derived (§4.2) as, for 0 <= j < 34, with γ = 0x9e3779b9 and
η* = 0x6a09e667 XOR 1024:
```
IV*_j = rotl32(γ·(j+1) mod 2^32, j mod 32) XOR rotl32(η*, 7j mod 32)
```

### PRNG(V, K) — coupled NLSR generator (§3)
```
S = (L^0..L^{µ-1}) <- (V || K) parsed as 16µ big-endian 32-bit words   # §3.3
for r = 0 .. 31: S = U_r(S)               # N_blank = 32 blank rounds
for tau = 0,1,2,...:
    S = U_{32+tau}(S)
    O_tau = O_tau^0 || .. || O_tau^{µ-1}  # 32µ bits
    where O_tau^i = ( s13^i  XOR s8^{[i+1]} ) + ( s4^{[i+2]} XOR s2^{[i+3]} ) mod 2^32
emit first λ bits of O_0 || O_1 || ...
```

### Round function U_r (§3.1, §3.2)
```
# nonlinear word function F, reused locally and globally
F(R0,R1,R2,R3):
    A = (R0 + R1) mod 2^32 ;  B = R2 XOR R3
    U || V = rotl64(A || B, 16)
    P_L = S_box(L1(U)) ;  P_R = S_box(L2(V))     # L1/L2 = ZUC rotation-xor layers
    return ((P_L XOR rotl32(R1,8)) + P_R) mod 2^32

# local feedback, per module i
l_lin  = 8193*s0 + 16777217*s4 + 4194304*s9 + 9*s13 + 524288*s15 (mod p)
Phi^i  = red_p( l_lin + F(s15, s10, s5, s0) )

# global confusion, per module i, round r
A_i=s14^i, B_i=s9^i, C_i=s6^i, D_i=s1^i
X = A_[i+r+aX] XOR rotl(B_[i+r+bX], 7)     # offsets (a,b) from the µ-table, §3.2
Y = (B_[i+r+aY] + C_[i+r+bY]) mod 2^32
Z = C_[i+r+aZ] XOR rotl(D_[i+r+bZ], 11)
W = (D_[i+r+aW] + A_[i+r+bW]) mod 2^32
kappa = rotl(0x9e3779b9 XOR r XOR i, (r+i) mod 32)
Gamma^i = F(X,Y,Z,W) XOR kappa

# shift + injection, per module i;  (e1,e2,e3) = (1,2,1) for µ=3, (1,2,3) for µ=4,5
t_j  = s_{j+1}                         for j not in {3,7,11,15}
t_3  = red_p( s4  XOR rotl(Gamma^{[i+e1]},  5) )
t_7  = red_p( s8  XOR rotl(Gamma^{[i+e2]}, 13) )
t_11 = red_p( s12 XOR rotl(Gamma^{[i+e3]}, 21) )
t_15 = red_p( Phi^i XOR Gamma^i )
```

### Variable digest length
Only the three fixed lengths 512/768/1024 exist as instances; the abstract
mentions "extensible output length" but the submitted API is one-shot fixed. The
three variants differ in (n, k, v, µ) and in the IV *prefix length* only — the IV
words themselves are a common prefix sequence and there is **no explicit
domain-separation byte** between digest lengths (spec §4.2 states this
deliberately: "only the public parameter set and the IV prefix length change").
Since µ differs per variant, the three functions are structurally distinct, so
this is a design choice rather than a defect.

## Implementation vs specification

Checked: `src/Neulaser-{512,768,1024}/CryptHash_AlgorithmInstance.c` (the three
files are **byte-identical**; only the `DIGEST_BIT_LENGTH` in the `.h` differs)
against spec §§2–4. `drng.c` is the unmodified official DRNG and plays no part
in the hash. All 3 instances PASS KAT (RESULTS.md).

Agreements verified line by line:

- Parameters `nl_params_from_digest()`: (n,k,v,µ) = (512,960,576,3),
  (768,1216,832,4), (1024,1472,1088,5) — matches Table 1 exactly.
- `NL_P 4294967291`, `NL_BLANK_ROUNDS 32`, `NL_LENGTH_FIELD_BITS 64` match §3/§3.3.
- Padding `nl_padding_zero_bits()` / `nl_build_padded_block()` implements
  `M || 1 || 0^z || len64` with MSB-first length exactly as §2.1; trailing
  partial-byte message bits are masked, so unused bits cannot leak in.
- `nl_make_iv()` *computes* IV* from the §4.2 nothing-up-my-sleeve rule instead
  of tabulating the 34 constants. I verified the derivation reproduces the
  spec's table: j=0 gives rotl32(0x9e3779b9,0) XOR rotl32(0x6a09e667^0x400,0)
  = 0xF43E9BDE = IV*_0 of §2.3. The hard-wired `1024U` in that expression is
  **spec-mandated** (η* = η ⊕ 1024 for all three variants), not an instance
  parameter that was forgotten. Word count = v/32 = 18/26/34 ✓.
- `nl_F()`: `u = (a<<16)|(b>>16)`, `v = (b<<16)|(a>>16)` is exactly
  `rotl64(A||B,16)` ✓; L1/L2 rotation constants (2,10,18,24) and (8,14,22,30) ✓.
- `nl_linear_core()`: coefficients 8193, 16777217, 4194304, 9, 524288 at taps
  0,4,9,13,15 ✓ (§3.1.1), accumulated in 64 bits then reduced mod p ✓.
- `nl_offsets()` tables tab3/tab4/tab5 reproduce the §3.2 offset table ✓.
- Tap-injection offsets: `(mu==3 ? 1 : 1)`, `2`, `(mu==3 ? 1 : 3)` = (e1,e2,e3)
  = (1,2,1) for µ=3 and (1,2,3) for µ=4,5 ✓ (written oddly, but correct).
- `kappa` and the output-extraction taps (13, 8, 4, 2 with offsets +1,+2,+3) ✓.
- Block constant: `nl_xor_block_constant()` XORs the 64-bit index into the last
  8 bytes of V, i.e. `C_i = 0^{v-64} || i`, ✓ §2.2; `C_0 = 0` so `V_0 = IV_n` ✓.
- Mode loop in `CryptHash()`: `v` bytes squeezed for non-final blocks,
  `v+n` for the final one with the digest taken from offset `v` ✓ §2.3.

Discrepancies / notes:

- **(b) spec gap → (a) minor implementation deviation: non-canonical F_p state
  words.** §3 declares every stage `s_j` to be an element of F_p, but §3.3 only
  says the state is "initialized from (V,K)" without giving the map.
  `nl_init_state()` loads V||K verbatim as 16µ big-endian words with **no
  reduction mod p**, so the 5 values {p,…,2^32−1} enter the register as
  non-canonical/out-of-field elements. `nl_redp32()`/`nl_redp64()` keep all
  *subsequent* words in [0,p), so this affects the initial state only. No
  practical consequence was established (probability ≈ 5·16µ/2^32 per call for
  random input, and the map V||K → S is still injective), but the spec should
  pin the encoding. This matches the `noncanonical field inputs` lead already
  recorded in `security_findings.md`.
- **(c) equivalent optimisation:** the round-index arithmetic uses
  `rmu = round mod µ` before the module lookup, which is identical to the
  spec's `[i + r + a]_µ`.
- **Coverage:** the abstract's "extensible output length" claim is not
  exercisable through the submitted API — `CryptHash()` returns −2 for any
  `digest_len_bits != DIGEST_BIT_LENGTH`, so there is no XOF mode to check. No
  reduced-round cryptanalysis of the coupled NLSR was attempted here; the
  primitive's resistance to guess-and-determine / correlation attacks on 32
  blank rounds is open (see `security_findings.md`).
