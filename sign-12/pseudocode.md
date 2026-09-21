# sign-12 Galas — algorithm summary

Galas is a VOLE-in-the-Head (VOLEitH) signature: a Fiat–Shamir-compiled
QuickSilver zero-knowledge proof of knowledge of a preimage of the *Gala* keyed
one-way function over F_{2^λ}. Security rests on (i) one-wayness of the
single-pair degree-3 Gala relation, (ii) soundness of the inherited
BAVC/VOLE/QuickSilver machinery, (iii) the NGCC `pseudohash`/`pseudoXOF`
interfaces as domain-separated ROs/PRGs. Transcript layout follows FAEST.
Signing is *deterministic* (spec §7.2); there is no randomized variant.

Specification: `sign-12-spec.pdf` (51 pages), §3.1 (overview), §5 (Gala OWF and
constraints), §6 (BAVC/VOLE/QuickSilver), §7 (KeyGen/Sign/Verify), §8.1
(parameters).

## Parameters

Derived: m = λ/2, d_QS = 3, ℓ = 5λ/2, B = 16 bits, ℓ̂ = ℓ + 3λ + B,
n_iv = 160 bits, k_tree = ⌊(λ−w_grind)/τ⌋+1, τ₁ = (λ−w_grind) mod τ, τ₀ = τ−τ₁,
L = τ₁·2^{k_tree} + τ₀·2^{k_tree−1}  (§8.1.1–8.1.2, Table 9).

| parameter | 160S | 160F | 256S | 256F | 384S | 384F | 512S | 512F | meaning |
|---|---|---|---|---|---|---|---|---|---|
| λ | 160 | 160 | 256 | 256 | 384 | 384 | 512 | 512 | field F_{2^λ} / security param |
| τ | 14 | 20 | 21 | 35 | 32 | 48 | 42 | 64 | VOLE/BAVC repetitions |
| w_grind | 7 | 8 | 7 | 12 | 6 | 6 | 8 | 6 | forced zero bits in Δ |
| T_open | 132 | 144 | 218 | 232 | 336 | 332 | 456 | 445 | max revealed BAVC seeds |
| k_tree | 11 | 8 | 12 | 7 | 12 | 8 | 13 | 8 | BAVC index depth |
| L | 27648 | 4096 | 79872 | 4416 | 118784 | 11520 | 172032 | 15616 | total BAVC leaves |
| ℓ = 5λ/2 | 400 | 400 | 640 | 640 | 960 | 960 | 1280 | 1280 | witness bits |
| d_QS | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | QuickSilver degree bound |
| claimed security | 128(80) | 128(80) | 256(128) | 256(128) | 384(192) | 384(192) | 512(256) | 512(256) | bits, classical(quantum), Table 6 |

Sizes (bytes), specification (Table 9 / Table 7) vs the built reference library:

| instance | pk spec | pk impl | sk spec | sk impl | sig spec | sig impl | match |
|---|---|---|---|---|---|---|---|
| Galas-160S | 40 | 40 | **20** | **40** | 4812 | 4812 | sk **MISMATCH** |
| Galas-160F | 40 | 40 | **20** | **40** | 5964 | 5964 | sk **MISMATCH** |
| Galas-256S | 64 | 64 | **32** | **64** | 12114 | 12114 | sk **MISMATCH** |
| Galas-256F | 64 | 64 | **32** | **64** | 15950 | 15950 | sk **MISMATCH** |
| Galas-384S | 96 | 96 | **48** | **96** | 27784 | 27784 | sk **MISMATCH** |
| Galas-384F | 96 | 96 | **48** | **96** | 33384 | 33384 | sk **MISMATCH** |
| Galas-512S | 128 | 128 | **64** | **128** | 49516 | 49516 | sk **MISMATCH** |
| Galas-512F | 128 | 128 | **64** | **128** | 59416 | 59416 | sk **MISMATCH** |

The spec's own size formula (§3.1.3)
`|σ| = (τ−1)ℓ̂ + (λ+B) + ℓ + (d_QS−1)λ + (2τ+T_open)λ + λ + n_iv + 32` bits
reproduces every `sig spec` entry exactly (checked for 160S: 38496 bits = 4812 B).

## Pseudocode

### Gala OWF (spec Algorithm 1) and validity predicate (Algorithm 2)
```
GalaEval(k, x):                       # c0,c1,c2 ∈ F and F2-linear M0..M2, L0..L3
  a0 ← M0(x ⊕ k ⊕ c0); a1 ← M1(k ⊕ c1); a2 ← M2(k ⊕ c2)
  b0 ← S(a0); b1 ← S(a1); b2 ← S(a2)              # S(a) = a^{-1} = a^{2^λ−2}
  z  ← L0(b0) ⊕ L1(b1) ⊕ L2(b2)
  return y ← S(z) ⊕ L3(k)

Good(k, x): k[0]=k[1]=1  AND  a0,a1,a2 ≠ 0  AND  z ≠ 0
```
The constants/maps are *public, fixed per parameter set*, generated offline by a
SHAKE256 procedure (§5.1.1); they are never sampled by KeyGen/Sign/Verify.

### KeyGen (spec Algorithm 19, §7.1)
```
repeat
  k ←$ F ;  set the first two serialized bits of k to 1
  x ←$ F
  good ← Good(k, x)
until good = 1
y  ← GalaEval(k, x)
pk ← x ‖ y          # 2λ bits (Table 7)
sk ← k              # λ bits  (Table 7)
return (pk, sk)
```

### Sign (spec Algorithms 20 and 21, §7.2) — deterministic
```
BuildWitness(pk, sk):                  # Alg. 20
  a_i as in GalaEval; σ_i ← InvNormWitness(a_i)   # m-bit subfield-compressed
  return w = (k, σ0, σ1, σ2) ∈ {0,1}^ℓ            # inverse witness, §5.2

Sign(pk, sk, M):                       # Alg. 21
  w  ← BuildWitness(pk, sk)
  µ  ← H_msg(pk, M)                              # 2λ bits
  (K_root, iv_pre) ← H_seed(k, µ)                # λ + n_iv bits
  iv ← H_iv(iv_pre)
  (h, c, u, V, st_BAVC) ← VOLE.Commit(K_root, iv)
  chall_1 ← H_FS1(µ, h, c, iv)                   # 5λ + 64 bits
  d  ← w ⊕ u[0..ℓ)
  (π_VOLE, T_VOLE) ← VOLEHash.Prove(chall_1, u, V)
  chall_2 ← H_FS2(chall_1, π_VOLE, T_VOLE, d)    # 3λ + 64 bits
  (π_QS, χ_QS) ← QS.Prove(chall_2, w, u, V, pk);  abort ⊥ on failure
  for ctr = 0 .. 2^32 − 1:                        # grinding
     Δ ← H_FS3(chall_2, χ_QS, π_QS, ctr)          # λ bits
     I_Δ ← DecodeOpenChallenge(Δ)                 # Alg. 18; ⊥ if any of the
     if I_Δ = ⊥: continue                         #   top w_grind bits is set
     π_BAVC ← BAVC.Open(st_BAVC, I_Δ)
     if π_BAVC ≠ ⊥: return c ‖ π_VOLE ‖ d ‖ π_QS ‖ π_BAVC ‖ Δ ‖ iv_pre ‖ ctr
  return ⊥
```

### Verify (spec Algorithm 22, §7.3)
```
Parse pk = x ‖ y; parse σ into the 8 fields of Table 8 (reject on wrong length)
I_Δ ← DecodeOpenChallenge(Δ);           if ⊥ → 0
iv ← H_iv(iv_pre);  µ ← H_msg(pk, M)
(h, Q) ← VOLE.Reconstruct(iv, I_Δ, π_BAVC, c)     # Q = V ⊕ Δ·u; ⊥ → 0
chall_1 ← H_FS1(µ, h, c, iv)
T_VOLE  ← VOLEHash.Verify(chall_1, π_VOLE, Q, Δ)
chall_2 ← H_FS2(chall_1, π_VOLE, T_VOLE, d)
χ_QS    ← QS.Verify(chall_2, pk, d, Q, Δ, π_QS);  if ⊥ → 0
return [ H_FS3(chall_2, χ_QS, π_QS, ctr) = Δ ]
```

### Hash layer (spec §4.2, Tables 5 and 6)
```
H_D(input, n):  X ← concat(absorbed fields, little-endian)
                B_j ← pseudohash(r_λ, X ‖ sep_D ‖ uint32_le(j)),  j = 0,1,2,…
                return first n bits of B_0‖B_1‖B_2‖…
sep: H_com=0x01, H_seed=0x03, H_iv=0x04, H_msg=0x08, H_FS1=0x09,
     H_FS2=0x0a, H_FS3=0x0b        # no ASCII label or instance name absorbed
raw pseudohash block r_λ: 512 (λ=160,256), 768 (λ=384), 1024 (λ=512) bits
PRG/XOF frame: seed ‖ iv ‖ u32le(tweak) ‖ u32le(counter)   (§4.2.4)
```

## Implementation vs specification

What was checked: `src/Galas-160S/ngcc/SIG_AlgorithmInstance.c` (`sig_keygen`,
`sig_sign`, `sig_verify`, serialization offsets, the H1–H3 challenge wrappers),
`src/Galas-160S/galas/instances.c` (parameter sets), `galas/owf.c`,
`galas/galas_params_160.h` (public constants). The eight instance directories
are byte-identical apart from `INSTANCE.txt`; the set is chosen by
`-DGALAS_INSTANCE=` (see `sign-12/Makefile`).

Agreements:
- All 32 tuples (λ, τ, w_grind, T_open) and all eight `sig_bytes` in
  `galas/instances.c:31-54` match Table 9 exactly; `w_grind`, `T_open`, `τ`
  spot-checked for 160S/256F/512F. `k_tree`/`τ0`/`τ1`/`L` are computed by the
  `K_OF`/`TAU0_OF`/`TAU1_OF`/`L_OF` macros (`instances.c:6-13`) with the same
  formulas as §8.1.2. `ℓ = 5λ/2`, `ℓ̂ = ℓ + 3λ + B`, `B = 16`, `|π_QS| = 2λ`,
  `n_iv = 160` are reproduced by `witness_bits`/`ell_hat_bits`/
  `vole_check_bytes`/`qs_proof_bytes` (`SIG_AlgorithmInstance.c:113-141`).
- The signature field order and lengths (`sig_off_*`, lines 143-152) match
  Table 8, including the fixed-length zero-padded BAVC opening.
- The transcript matches Alg. 21 step by step: µ (line 289), (K_root, iv_pre)
  from H3(k, µ) (line 296), iv = H4(iv_pre) (line 297), VOLE.Commit (310),
  chall_1 (313), d = w ⊕ u (335), VOLEHash into the H2 context (338),
  chall_2 (340), QS.Prove (345), grinding loop with DecodeOpenChallenge +
  BAVC.Open (362-367). The stored counter `ctr − 1` (line 375) is the
  successful one, since the `for` increment runs after the body.
- Signing draws no randomness, as §7.2 requires.

Discrepancies:

1. **(a) real deviation — KeyGen ignores the API DRNG (known finding; all 8
   instances KAT MISMATCH, see `security_findings.md`).** The spec is explicit
   about where randomness enters KeyGen: Algorithm 19 lines 2–3 read
   `k ←$ F; set the first two serialized bits of k to 1` and `x ←$ F`, and §9.3
   (“Gala relation hardness”) repeats the requirement — *“for a random valid
   public key (x, y) generated by k ←$ F, x ←$ F, rejection sampling on
   Good(k, x)”*. The security claim in §1.1 is conditioned on public keys being
   “generated by Algorithm 19”.
   The implementation instead builds a **private** DRNG context inside
   `sig_keygen`:
   `src/Galas-160S/ngcc/SIG_AlgorithmInstance.c:69-73`
   ```c
   DRNG_ctx drng;
   uint8_t default_seed[32] = {0};
   const uint8_t* sd = (g_kat_seed && g_kat_seed_len) ? g_kat_seed : default_seed;
   unsigned long long sd_len = (g_kat_seed && g_kat_seed_len) ? g_kat_seed_len : sizeof(default_seed);
   init_random_number(&drng, sd, sd_len);
   ```
   with `g_kat_seed` set only by the non-API helper `galas_set_kat_seed()`
   (`SIG_AlgorithmInstance.c:50-54`, declared at `SIG_AlgorithmInstance.h:45`),
   which is called only from the candidate's own `ngcc/kat_gen.c`. `k` and `x`
   are then drawn from this local `drng` (lines 81-82), never from the ICCS
   `drng_algorithm` that the NGCC API seeds. Consequence through the official
   API: **every seed yields the identical key pair** (the 32-zero-byte default),
   so the submitted KATs cannot be reproduced — the public key already differs
   at record 0. Signing itself is deterministic and correct: verified out of
   tree, feeding `k, x` from `drng_algorithm` reproduces records 0-2 of
   `KAT_SIG_Galas-160S.txt` byte-for-byte, so *only the RNG plumbing deviates*.
2. **(a) real deviation — secret-key length.** Spec Table 7 is normative:
   `sk` has one field, `k`, of `λ bits`, and §8.1.3 states “sk = k has λ bits”
   (Table 9 column `pk/sk (B)` gives 40/20, 64/32, 96/48, 128/64). The
   implementation stores `sk = x ‖ k` of `2λ` bits
   (`SIG_AlgorithmInstance.c:39-44` and `:93-96`; `sk_bytes` is set to
   `2*lambda/8` in `instances.c:31-54`, with the comment “secret keys follow the
   FAEST reference convention x‖k”). Observed `sk` is therefore twice the
   specified size for all eight instances. This is self-consistent and
   functionally harmless (`sig_sign` recomputes `y` from `sk`,
   `SIG_AlgorithmInstance.c:277-283`), but the shipped key sizes do not match
   the spec's own normative serialization table.
3. **(b) spec ambiguity, minor.** Spec Alg. 21 takes `(pk, sk, M)`; the NGCC API
   `sig_sign` takes only `sk`, and the implementation reconstructs
   `pk = x ‖ GalaEval(k, x)` from `sk = x‖k`. Equivalent given deviation 2, and
   unavoidable under the NGCC API shape.

Not verified: the internals of `bavc.c`, `vole.c`, `qs_*.c` and
`universal_hashing.c` against §6.1–6.5 (only their call sites and output
lengths were checked); and the Appendix B constant tables in
`galas_params_*.h` were not compared against the machine-readable files'
SHA-256 hashes.
