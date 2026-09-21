# sign-21 ReSolveD-α — algorithm summary

A code-based signature: a non-interactive zero-knowledge proof of knowledge of a
**regular syndrome decoding (RSD)** witness over F2, compiled with the
**VOLE-in-the-Head** framework (batch all-but-one vector commitment + SoftSpokenOT
VOLE consistency check + **QuickSilver** degree-2 proof) and made non-interactive by a
three-round Fiat–Shamir transform with proof-of-work grinding. EUF-CMA claimed in the
QROM + quantum ideal-cipher model.

Specification: `sign-21-spec.pdf` (132 pages), §4 (algorithms), §5 (parameters).
Build: `Makefile` builds the 8 reference instances with `-DXOF_PSEUDO` (NGCC SM3
pseudoXOF backend); the Keccak backend of spec Table 5 is not the built one.

## Parameters

Spec Tables 3 (RSD) and 4 (VOLEitH); ℓwit = k(1−1/ℓbs) is Eq. (9).

| parameter | 160s | 160f | 256s | 256f | 384s | 384f | 512s | 512f | meaning |
|---|---|---|---|---|---|---|---|---|---|
| λ | 160 | 160 | 256 | 256 | 384 | 384 | 512 | 512 | security parameter |
| m | 1860 | 1860 | 2988 | 2988 | 4452 | 4452 | 5940 | 5940 | RSD code length |
| k | 1056 | 1056 | 1698 | 1698 | 2532 | 2532 | 3378 | 3378 | RSD dimension |
| w | 310 | 310 | 498 | 498 | 742 | 742 | 990 | 990 | regular noise weight |
| ℓbs | 6 | 6 | 6 | 6 | 6 | 6 | 6 | 6 | noise block size (m = ℓbs·w) |
| ℓwit | 880 | 880 | 1415 | 1415 | 2110 | 2110 | 2815 | 2815 | committed witness bits |
| τ | 14 | 21 | 22 | 35 | 34 | 53 | 46 | 72 | VOLE instances / GGM trees |
| wgrind | 6 | 8 | 12 | 8 | 10 | 9 | 6 | 8 | proof-of-work bits |
| Topen | 129 | 139 | 224 | 223 | 332 | 336 | 439 | 447 | BAVC opened-node bound |
| B | 16 | 16 | 16 | 16 | 16 | 16 | 16 | 16 | universal-hash redundancy (§4.1) |
| d | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | QuickSilver constraint degree |
| PRG/TCCR | AES-192 | | AES-256 | | Rijndael-256 | | SHACAL-2 | | spec Table 6 |
| claimed security | 160c/80q | | 256c/128q | | 384c/192q | | 512c/256q | | bits (§5.1) |

Sizes (bytes), spec Table 4 vs the built reference library:

| instance | pk spec/impl | sk spec/impl | sig spec/impl | match |
|---|---|---|---|---|
| 160s / 160f | 121 / 121 | 40 / 40 | 5307 / 5307, 6851 / 6851 | yes |
| 256s / 256f | 194 / 194 | 64 / 64 | 13973 / 13973, 17932 / 17932 | yes |
| 384s / 384f | 288 / 288 | 96 / 96 | 31575 / 31575, 40469 / 40469 | yes |
| 512s / 512f | 385 / 385 | 128 / 128 | 56239 / 56239, 72611 / 72611 | yes |

Spec size formula, Eq. (6) §3.9 (bits):
`|σ| = ℓwit + (τ−1)(ℓwit + dλ + B) + (Topen + 2τ)λ + (d−1)λ + (λ+B) + λ + 120 + 32`
(masked witness `d`; correction vectors c₁..c_{τ−1}; BAVC opening; ã₁; ũ; chall₃; iv; ctr).
I evaluated this for all 8 sets: it reproduces the observed sizes **exactly**, but only when
ℓwit is rounded up to a byte boundary (880, **1416**, **2112**, **2816**) — see discrepancies.
pk = λ/8 + ⌈(m−k)/8⌉, sk = 2λ/8; both verified against the observed columns.

## Pseudocode

### KeyGen — spec §4.2.1
```
seed_pk, seed_sk  <-$ {0,1}^λ  each
H := RSD.SampleMatrix(seed_pk)          # §4.5.1: H = [I | H_B], H_B = MatHash(seed_pk)
e := RSD.SampleNoise(seed_sk)           # §4.5.2: w blocks of ℓbs bits, one 1 per block:
                                        #   r_i := PRG(seed_sk, IntToBits(i;120), 0; λ)
                                        #   e_i[BitsToInt(r_i) mod ℓbs] := 1
y := H · e                              # y in F2^(m-k)
return pk := (seed_pk, y),  sk := (seed_pk, seed_sk)
```

### Sign — spec §4.2.2
```
H := RSD.SampleMatrix(seed_pk); e := RSD.SampleNoise(seed_sk); y := H·e; pk := (seed_pk,y)
(µ, s) := MsgHash(pk, msg)                       # §4.9.1, XOF(0x00 ‖ seed_pk ‖ y ‖ msg; 3λ)
ρ <-$ {0,1}^λ                                    # ρ = 0^λ gives deterministic signing
(r, iv) := CoinHash(sk, µ, ρ)                    # §4.9.2, XOF(0x01 ‖ sk ‖ µ ‖ ρ; λ+120)
(com, decom, (c_i)_{i in [1,τ)}, u, V) := VOLE.Commit(r, iv, µ, s)     # §4.3.3
   # BAVC.Commit expands r into one interleaved pcGGM tree with L = Σ_α N_α leaves (§4.4.1);
   # per instance α: (u_α, V_α) := VOLE.ConvertToVOLE(seeds_α, iv) (§4.3.6);
   # u := u_0, c_α := u ⊕ u_α; V := [V_0 | ... | V_{τ-1}]     (rows = ℓvole, cols = λ)
V := [V, 0, ..., 0]                              # pad λ-wgrind -> λ columns
chall_1 := FSHash_1(com, (c_i))                  # §4.9.5, XOF(0x09 ‖ · ; 5λ+64)
ũ := VOLEHash(chall_1, u);  Ṽ := VOLEHash(chall_1, V)          # §4.7.1 SoftSpoken check
wit := RSD.EncodeNoise(e)                        # §4.5.3: per e_B block keep first ℓbs-1 bits
d  := wit ⊕ u[0, ℓwit)                           # de-randomise the IT-MACs
chall_2 := FSHash_2(chall_1, ũ, Ṽ, d)            # §4.9.6, XOF(0x0a ‖ · ; 3λ+64)
u := u[0, ℓwit+λ);  V := V[0, ℓwit+λ)
(ã_1, ã_0) := QS.RSDProve(wit, u, V, H, y, chall_2)            # §4.6.1
   # RSD.DecodeNoise (§4.5.4) affinely rebuilds [e_A | e_B] from the IT-MACs:
   #   e_B,i[ℓbs-1] := 1 ⊕ XOR_j w_i[j]  (block-parity), e_A := y ⊕ H_B · e_B
   # per block: deg-2 IT-MAC ⟦z_i⟧ = (Σ X^j e_i[j])(Σ X^{(ℓbs-1)j} e_i[j]) − Σ X^{ℓbs·j} e_i[j]
   #   = 0 iff the first ℓbs-1 coords hold at most one 1 (linear sketch, §3.8);
   # d_pack := ℓbs²-3ℓbs+1 checks packed per F2^λ element, ℓqs := ceil(w/ℓpack) aggregates;
   # e_A block-sum (xor-to-1) checks are degree-1, lifted to degree 2 and appended to ã_1;
   # the extra λ VOLE rows mask the batch; ZKHash (§4.7.2) compresses to (ã_1, ã_0).
ctr := 0; decom_I := ⊥
while decom_I = ⊥:                               # grinding + BAVC-size rejection loop
    chall_3 := FSHash_3(chall_2, ã_1, ã_0, ctr)  # §4.9.7, XOF(0x0b ‖ · ; λ)
    if chall_3[λ-wgrind, λ) ≠ 0^wgrind: ctr += 1; continue
    I := VOLE.ChalDecAll(chall_3)                # §4.3.2: τ leaf indices, k_1 bits for α<t_1
    decom_I := BAVC.Open(decom, I, iv)           # §4.4.2, ⊥ if > T_open nodes needed
return σ := ((c_i)_{i in [1,τ)}, ũ, d, ã_1, decom_I, chall_3, iv, ctr)
```

### Verify — spec §4.2.3
```
(µ, s) := MsgHash(pk, msg)
(com, Q) := VOLE.Reconstruct(chall_3, decom_I, (c_i), iv, µ, s)        # §4.3.4; ⊥ -> reject
   # BAVC.Verify re-derives all leaves but ∆_α; index XOR ∆_α moves the hidden leaf to 0;
   # Q_α := VOLE.Fix(Q'_α, c_α, ∆_α)   (§4.3.5: q_i := Q'[:,i] ⊕ ∆[i]·c)
Q := [Q, 0, ..., 0];  chall_1 := FSHash_1(com, (c_i))
Q' := VOLEHash(chall_1, Q);  Q̃ := VOLE.Fix(Q', ũ, chall_3; λ, λ+B)     # IT-MAC opening of ũ
chall_2 := FSHash_2(chall_1, ũ, Q̃, d);   Q := Q[0, ℓwit+λ)
ã_0 := QS.RSDVerify(d, Q, chall_2, chall_3, ã_1, H, y)                 # §4.6.2
chall_3' := FSHash_3(chall_2, ã_1, ã_0, ctr)
return 1 iff chall_3' = chall_3 AND chall_3[λ-wgrind, λ) = 0^wgrind
```

### Hashes (§4.9) — all random oracles are `XOF(domain_byte ‖ input; outlen)`
```
MsgHash 0x00 -> 3λ (µ‖s)   CoinHash 0x01 -> λ+120   BAVCHash 0x02 -> 2λ   MatHash 0x03 -> (m-k)k
FSHash_1 0x09 -> 5λ+64     FSHash_2 0x0a -> 3λ+64   FSHash_3 0x0b -> λ
BAVCHash: com_α := XOF((com^α_i)_i; 2λ) per tree, then XOF(0x02‖µ‖s‖(com_α)_α‖iv; 2λ)
LeafHash (§4.4.7): seed := x, com := PRG(x, iv, 0x00; 2λ); tree nodes via TCCR(x,s,iv) (§4.9.8)
XOF = NGCC SM3 pseudoXOF (as built) or Keccak[2λ]; PRG/TCCR = block cipher per Table 6.
```

## Implementation vs specification

Checked (reference implementation, `src/ReSolveD-alpha-*` → `Implementations/Reference_Implementation/`):
`parameters.h` + `instances.c` (constants), `voleith_impl.c` (Sign/Verify, FS hashes, grinding),
`rsd.c` (SampleMatrix/SampleNoise), `bavc.c` (BAVC hash), `random_oracle.c`.
Sampling for the constant spot-check: all 8 instances for τ / wgrind / Topen / sizes, and the
full RSD tuple (m, k, w, ℓbs) for 160s/256s/384s/512s.

Agreements:
- `TAU`, `POW_LEVEL`, `T_OPEN`, `RSD_CODE_LENGTH`, `RSD_DIMENSION`, `RSD_NOISE_WEIGHT`,
  `RSD_BLOCK_SIZE`, `PK_SIZE`, `SK_SIZE`, `SIG_SIZE` match spec Tables 3/4 for all 8
  instances (e.g. 160s: τ=14, wgrind=6, Topen=129, (m,k,w,ℓbs)=(1860,1056,310,6)); no
  size mismatch anywhere.
- Fiat–Shamir domain separators are prefix bytes 0, 1, 9, 10, 11 with exactly the §4.9
  output lengths (`voleith_impl.c:154,169,187,205,232`); BAVCHash uses prefix 2 in the
  order µ‖s‖(com_α)‖iv (`bavc.c:17-44`); MatHash uses prefix 3 (`rsd.c:47`).
- `rsd_sample_noise` (`rsd.c:31-45`) matches §4.5.2 (little-endian `IntToBits(i;120)` IV,
  tweak 0, bitwise `mod ℓbs`); the grinding/rejection loop (`voleith_impl.c:356-381`)
  matches §4.2.2 lines 22-30; `t1 = (λ−wgrind) mod τ`, `k1 = ⌊(λ−wgrind)/τ⌋+1`,
  `L = t1·2^k1 + t0·2^k0` (`instances.c:33-36`) match §4.1/§5.3.

Discrepancies:
- **(b) spec inconsistency, ℓvole.** The spec gives three different values for the VOLE
  commitment length: Eq. (8) `ℓwit + (d−1)λ` (=1040 for 160), Table 4's `ℓvole` column
  (1056 = ℓwit+λ+B), and Eq. (6)'s correction-vector length `ℓwit + dλ + B` (=1216).
  The implementation uses the third (`voleith_impl.c:24`,
  `lenwit + quicksilver_degree*csp + UNIVERSAL_HASH_B_BITS`), and only that value
  reproduces the observed signature sizes. Table 4's `ℓvole` column is mislabelled/wrong.
- **(c) undocumented byte padding of ℓwit.** Eq. (9) gives ℓwit = 1415 / 2110 / 2815 for
  λ = 256 / 384 / 512, and `parameters.h` keeps these as `RSD_WITNESS_BITS`, but the
  serialized witness length `LENWIT` is rounded up to 1416 / 2112 / 2816. Table 4's
  signature sizes were evidently computed with the padded value (they only match then).
  Harmless, but the spec never states the padding rule.
- **(a) CoinHash input.** §4.9.2 specifies `XOF(0x01 ‖ sk ‖ µ ‖ ρ)` with sk ∈ {0,1}^{2λ}
  (i.e. seed_pk ‖ seed_sk); `hash_r_iv` (`voleith_impl.c:167-183`) absorbs only
  `lambda_bytes` of the key, i.e. seed_sk alone. Not a break (seed_pk enters via µ), but
  the transcript differs from the written spec.
- **(non-issue) dead code.** `random_oracle.c` still carries the FAEST-style H0..H4 /
  H2_0..H2_3 helpers with *suffix* separators 0,1,9,10 and different semantics; they are
  unreferenced by the built sources. Only a maintenance/confusion hazard.

Not verified (time-boxed ~20 min): BAVC min-span opening and leaf interleaving
(§4.4.4-4.4.6) against `bavc.c`; `VOLEHash`/`ZKHash` (§4.7) against `universal_hashing.c`;
TCCR for λ=384/512 (§4.9.8) against `tccr.c`/`enc.c`; QuickSilver packing constants
against `quicksilver.c`; the optimized C++ tree was not inspected at all.
