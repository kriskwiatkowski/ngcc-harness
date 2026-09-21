# sign-16 ARCANE-Octarine — algorithm summary

Fiat–Shamir with aborts over a *single* radical ring `S_{q,n,k} =
(Z_q[y]/(y^n+1))[x]/(x^k − y − 2)`, with security from Radical Ring-LWR (RR-LWR)
plus a Module-SIS-type assumption over the same ring. The public key is a *rounded*
value `b = round(p/q · A·s1)` (learning with rounding, no explicit error); the
rounding residue `s2 = A·s1 − (q/p)b` is computed once in KeyGen and stored in the
secret key. `q = 2^24` and all of `p, γ1, γ2, 2η, 2^d` are powers of two, so
HighBits/LowBits/Power2Round are plain bit shifts with no Dilithium-style boundary
anomaly, and no rejection sampling is needed anywhere in the samplers.

Specification: `sign-16-spec.pdf` (53 pages, English; a Chinese translation exists at
`中文资料/Octarine_中文.pdf`, not needed). Section 4 "Algorithm Description" (pp. 14–24):
Table 2 (parameters, p. 15), Algorithm 1 (supporting routines, p. 19), Algorithm 2
(SampleInBall, p. 22), Algorithm 3 (KeyGen/Sign/Verify, p. 24).

## Parameters

Table 2, p. 15. `q = 2^{εq}`, `p = 2^{εp}`, `η = q/(2p)`, `β = τ·η`.

| parameter | Octarine-128 | Octarine-256 | Octarine-512 | meaning |
|---|---|---|---|---|
| n | 1024 | 1024 | 1024 | base cyclotomic ring degree |
| k | 1 | 2 | 5 | radical extension degree (lattice dim nk) |
| εq = log2 q | 24 | 24 | 24 | main modulus (power of two) |
| εp = log2 p | 21 | 22 | 22 | LWR rounding modulus |
| η | 4 | 2 | 2 | s1, s2 coefficients in [−η, η−1] |
| d | 11 | 13 | 14 | Power2Round bits dropped from b |
| τ | 16 | 36 | 87 | challenge Hamming weight |
| λ | 128 | 256 | 512 | security level; \|c̃\| = λ/4 bytes |
| γ1 | 2^18 | 2^19 | 2^21 | masking range |
| γ2 | 2^17 | 2^18 | 2^20 | HighBits granularity |
| β = τη | 64 | 72 | 174 | rejection bound |
| ω | 79 | 210 | 399 | max hint weight (ω+k ≡ 0 mod 4) |
| challenge entropy | 131 | 257 | 512 | bits = log2 C(n,τ) + τ |
| expected repetitions | 2.1 | 2.3 | 3.6 | signing loop |
| claimed security | 128 | 256 | 512 | classical bits (quantum ≥ 80/128/256) |

Sizes (bytes). Spec formulae, p. 20: `pk = 64 + (log2 p − d)kn/8`;
`sk = 64+64+128 + (2 log2(2η) + d)kn/8`; `sig = λ/4 + log2(2γ1)kn/8 + 10(ω+k)/8`.
"spec" = formula evaluated here (identical to Table 2's own printed sizes).

| instance | pk spec | pk impl | sk spec | sk impl | sig spec | sig impl | match |
|---|---|---|---|---|---|---|---|
| Octarine-128 | 1344 | 1344 | 2432 | 2432 | 2564 | 2564 | yes |
| Octarine-256 | 2368 | 2368 | 4608 | 4608 | 5449 | 5449 | yes |
| Octarine-512 | 5184 | 5184 | 11776 | 11776 | 14713 | 14713 | yes |

## Pseudocode

Hashing (Sect. 4 "Hashing", p. 16): prefix `P = "ARCANE-Octarine-v1"`;
`Head(L,o,t) = P ‖ |L| ‖ L ‖ λ(2B) ‖ k(1B) ‖ o(4B) ‖ t(1B)`, `Field(X) = |X|(8B LE) ‖ X`,
`H_L(X1..Xt; o) = H(Head(L,o,t) ‖ Field(X1)‖…‖Field(Xt), o)`; labels `H_KDF, H_TR, H_MU,
H_RHOPP, H_CH`. Seed-expansion XOFs use the compact header `"AOX1" ‖ id ‖ λ ‖ k ‖ o ‖ |s| ‖
s ‖ i ‖ ℓ`, id=1 `XOF_A`, id=2 `XOF_S`, label `XOF_C` for challenge expansion. H is the
SM3-based pseudoXOF in the reference family. `|ξ|=|ρ|=|K|=|rnd|=64`,
`|ρ'|=|ρ''|=|tr|=|µ|=128` bytes, `|c̃| = λ/4`.

### KeyGen — Algorithm 3, p. 24
```
 1: ξ ← U(B^64)
 2: (ρ, ρ', K) ∈ B^64 × B^128 × B^64 ← H_kdf(ξ; 256)
 3: A ← D_A(S; ρ)                # k polys, 24-bit coeffs, XOF_A, 4 lanes × 256 coeffs
 4: s1 ← D_s(S; ρ')              # coeffs uniform in [−η, η−1], log2(2η) bits each
 5: t = A·s1 ∈ S_{q,n,k}
 6: b = round(p/q · t) ∈ S_p     # u = (⟨t⟩_q + q/2p) mod q; v = u >> (εq−εp); b = ctr_p(v)
 7: s2 = t − (q/p)·b             # derived rounding error, bounded in [−η, η−1]
 8: (b1, b0) ← Power2Round_p(b, 2^d)
 9: pk ← pkEncode(ρ, b1) = ρ ‖ Pack(b1, log2 p − d)
10: tr ← H_tr(pk; 128)
11: sk ← ρ ‖ K ‖ tr ‖ Pack(s1, log2 2η) ‖ Pack(s2, log2 2η) ‖ Pack(b0, d)
12: return (pk, sk)
```

### Sign — Algorithm 3, p. 24 (hedged: `rnd` random ⇒ randomized, constant ⇒ deterministic)
```
 1: (ρ, K, tr, s1, s2, b0) ← skDecode(sk);  A ← D_A(S; ρ)
 3: µ ← H_mu(tr, M; 128);  ρ'' ← H_rhopp(K, rnd, µ; 128);  κ ← 0;  (z,h) ← ⊥
 7: while (z,h) = ⊥ do
 8:   y ← D_y(S; ρ'', κ)          # coeffs uniform [−γ1, γ1−1], seed ρ''‖κ(4B LE), XOF_S
 9:   w = A·y;   w1 = HighBits_q(w, 2γ2)
11:   c̃ = H_ch(µ, w1; λ/4);   c = SampleInBall(c̃)   # τ coeffs ±1, embedded as c(y)·x^0
13:   z = y + c·s1;   r0 = LowBits_q(w + c·s2, 2γ2)
15:   if ||r0||∞ ≥ γ2 − β or ||z||∞ ≥ γ1 − β then (z,h) ← ⊥
16:   else
17:     h = MakeHint_q(−c·(q/p)·b0,  w + c·s2 + c·(q/p)·b0,  2γ2)
18:     if ||c·(q/p)·b0||∞ ≥ γ2 or HW(h) > ω then (z,h) ← ⊥
21:   κ = κ + k
23: return σ = c̃ ‖ Pack(z, log2 2γ1) ‖ hintEncode(h)
```

### Verify — Algorithm 3, p. 24
```
 1: (ρ, b1) ← pkDecode(pk);  (c̃, z, h) ← sigDecode(σ)   # rejects non-canonical hints
 3: A ← D_A(S; ρ);  tr ← H_tr(pk; 128);  µ ← H_mu(tr, M; 128);  c ← SampleInBall(c̃)
 7: wApprox' ← A·z − c·(q/p)·b1·2^d        # = w + c·s2 + c·(q/p)·b0
 8: w1' ← UseHint_q(h, wApprox', 2γ2);   c̃' ← H_ch(µ, w1'; λ/4)
10: return [||z||∞ < γ1 − β] and [c̃ = c̃'] and [HW(h) ≤ ω]
```

### Supporting routines — Algorithm 1 (p. 19), Algorithm 2 (p. 22), encoding (p. 19-20)
```
HighBits_Q(r,m)    : r0 ← r mod m ; return ((r−r0)/m) mod Q/m
LowBits_Q(r,m)     : return r mod m                    # centered in [−m/2, m/2−1]
Power2Round_Q(r,m) : return (HighBits_Q(r,m), LowBits_Q(r,m))
MakeHint_Q(z,r,m)  : return [[ HighBits_Q(r,m) ≠ HighBits_Q(r+z,m) ]]
UseHint_Q(h,r,m)   : (r1,r0) ← Power2Round_Q(r,m); if h=1 return (r1 ± 1) mod Q/m
                     (+1 if r0>0, −1 if r0≤0); else return r1
SampleInBall(c̃)    : signs ← XOF_C(c̃,0,0; ⌈τ/8⌉); inside-out Fisher–Yates over n=1024
                     coefficients using 10-bit indices from 80-byte XOF_C(c̃,1,idx_ctr;80)
                     blocks, index redrawn unless ≤ i; exactly τ coefficients in {−1,+1}
Pack(w,b)          : Enc_b(a) = (2^{b−1} − 1 − a) mod 2^b, little-endian bit packing
hintEncode(h)      : ω 10-bit indices + k 10-bit per-poly delimiters; strictly increasing
                     within a polynomial, unused slots zero (canonical, checked on decode)
```

## Implementation vs specification

Checked against what the Makefile builds (`src/Octarine-{128,256,512}` →
`Implementations/Reference_Implementation/…`, one shared tree selected by
`-DRRLWR_SECURITY_LEVEL`): `sign.c` (`sig_keygen` L49–115, `sig_sign` L136–298,
`sig_verify` L300–396), `parameters.h`, `hash_domain.h`, `arith/packing.c`, and
`sign_ring.c` (`power2round`, `poly_sampleInBall`).

Agreements:

- **Parameters** — full sampling of all three `#if` blocks in
  `sign-16/src/Octarine-128/parameters.h:24-58`: `RRLWR_N`=1024, `RRLWR_K`=1/2/5,
  `LOGQ`=24, `LOGP`=21/22/22, `D`=11/13/14, `TAU`=16/36/87, `LOG_GAMMA1`=18/19/21,
  `LOG_GAMMA2`=17/18/20, `OMEGA`=79/210/399, `LAMBDA`=128/256/512 — all match Table 2.
  `LOG_ETA`=2/1/1 gives `ETA = 1<<LOG_ETA` = 4/2/2 (= η) and `BETA = TAU*ETA` = 64/72/174.
- **Sizes** — `parameters.h:109-116` encode the spec formulae literally
  (`PK_LEN = 64 + K*N*(LOGP−D)/8`, `SK_LEN = 64+64+128 + 2*S_LEN + B0_LEN`,
  `SIG_LEN = LAMBDA/4 + K*N*(LOG_GAMMA1+1)/8 + 10*(OMEGA+K)/8`) and evaluate to exactly
  the OBSERVED sizes. **No size discrepancy at any level.**
- **Domains** — `hash_domain.h:21-36` matches the spec verbatim: `"ARCANE-Octarine-v1"`,
  `"AOX1"`, labels `H_KDF/H_TR/H_MU/H_RHOPP/H_CH/XOF_C/XOF_A/XOF_S`, XOF ids 1/2,
  8-byte field-length prefixes.
- **Encoding** — the unusual flip `Enc_b(a) = 2^{b−1}−1−a mod 2^b` is implemented at
  `arith/packing.c:7,11,55-62`; sk field order ρ‖K‖tr‖s1‖s2‖b0 matches `skDecode`.
  Signing increments `kappa += RRLWR_K` (`sign.c:200`), matching `κ = κ + k`.
  Verify does the spec's three checks; `HW(h) ≤ ω` is enforced by the canonical
  decoder `ring_unpack_hint`, which the spec (p. 23) itself calls redundant with Verify.

Deviations:

- **(c) equivalent optimisation — rejection order.** `||r0||∞` is tested before
  `||z||∞` (`sign.c:230` then `:245`), the reverse of Algorithm 3 line 15; spec p. 21
  explicitly recommends this. The accept set is a conjunction, so no behaviour change.
- **(c) equivalent optimisation — hint.** The signer keeps `w` reduced to
  `r0 = LowBits_q(w+c·s2, 2γ2)` and calls `poly_make_hint(r0, r0 + c(q/p)b0)`
  (`sign.c:271-273`) rather than on full-precision arguments; equivalent because
  `2γ2 | q` and the carry is exactly the escape from `[−γ2, γ2−1]`.
- **(b) spec gap — bounded SampleInBall.** Algorithm 2 refills its 80-byte index
  buffer with an unbounded `idx_ctr`; the implementation caps `hash_counter` at 255 and
  returns −1 (`sign_ring.c:113-114`), which the signer turns into an extra abort
  (`sign.c:215-216`) and the verifier into a reject (`sign.c:352-354`). Negligible
  probability and signer/verifier agree, but the spec does not describe this bound.
- **KAT provenance** (already in `security_findings.md`, `kat-metadata-provenance`,
  `confirmed`): all three KAT payloads reproduce (PASS=3), but the submitted
  `Test_Vectors` were generated with `OUTPUT_BLANK_TEST_VECTORS 1` (still set at
  `src/Octarine-128/sign.h:25`), leaving `PK_Len/SK_Len/Sn_Len` blank. Metadata only —
  the advertised sizes agree with the spec formulae and with the hex lengths.

Not verified in the time box: the arithmetic layer (`crt.c`, two-prime NTT in
`poly.c`/`ring.c`, the `(y+2)` radical-ring multiplication of Eq. (6)) was read only at
interface level, and bit-exact agreement of `D_A`/`D_y`/`D_s` lane indexing with the
spec's byte-stream definitions was not traced coefficient by coefficient (reproducing
KATs are indirect evidence). Table 2's security estimates were not recomputed.
