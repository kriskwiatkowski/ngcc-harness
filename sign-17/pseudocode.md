# sign-17 OPS-SIG (OPS Digital Signature Algorithm) — algorithm summary

Module-lattice Fiat–Shamir-with-aborts signature (ML-DSA / Dilithium structure) over
`R_q = Z_q[X]/(X^n+1)`, unforgeability reduced to MLWE + MSIS + SelfTargetMSIS.
Distinctive features vs ML-DSA: a 26-bit modulus `q = 2^26 - 2^12 + 1`, SM3-based hashes
instead of SHAKE, a fused "small-polynomial multiplication with early check" signer, and a
position-list hint encoding.

Specification: `sign-17-spec.pdf` (28 pages), §3.1 (Algorithms 1–3), auxiliaries §3.2
(Algorithms 4–39), parameters Table 1 (§1.2), security claims §5, estimates Table 2 (§5.6).

## Parameters

| parameter | OPSsig-128 (L1) | OPSsig-256 (L3) | OPSsig-512 (L5) | meaning |
|---|---|---|---|---|
| n | 512 | 512 | 1024 | ring degree |
| q | 67104769 | 67104769 | 67104769 | modulus, `2^26 - 2^12 + 1` |
| (k, ℓ) | (3,3) | (4,4) | (4,4) | module ranks |
| (η1, η2) | (2,2) | (3,3) | (2,2) | secret-noise bound |
| γ1 | 2^21 | 2^20 | 2^22 | `y` coefficient range |
| γ2 | (q−1)/32 | (q−1)/96 | (q−1)/48 | low-order rounding range |
| d | 13 | 13 | 13 | `Power2Round` base exponent |
| τ | 39 | 45 | 90 | challenge Hamming weight |
| ω | 80 | 85 | 90 | max hint bits |
| β1 = β2 = β | *(undefined in spec)* | — | — | impl: `BETA = TAU*ETA` = 78 / 135 / 180 |
| \|c̃\| | 32 B | 64 B | 128 B | challenge seed (`2λ` bits) |
| \|ρ\| / \|tr\|, \|μ\| | 64 B / 128 B | same | same | seed 512 bits, CRH 1024 bits |
| Rep. | 1.12 | 1.93 | 2.02 | expected rejection iterations (spec Table 1) |
| claimed security | 128/80 | 256/128 | 512/256 | classical/quantum bits (spec Table 1) |
| est. LWE (cls/qnt) | 178/156 | 269/236 | 595/521 | spec Table 2 |

Sizes (bytes), specification Table 1 vs the built reference library:

| instance | pk spec | pk impl | sk spec | sk impl | sig spec | sig impl | match |
|---|---|---|---|---|---|---|---|
| OPSsig-128 | 2560 | 2560 | 3840 | 3840 | 4349 | 4349 | yes |
| OPSsig-256 | 3392 | 3392 | 5056 | 5056 | 5540 | 5540 | yes |
| OPSsig-512 | 6720 | 6720 | 9920 | 9920 | 12021 | 12021 | yes |

All three KATs PASS (`security_findings.md`, RESULTS.md).

## Pseudocode

### KeyGen — spec Algorithm 1 (§3.1.1)
```
(ρ, ρ') ← {0,1}^512 × {0,1}^1024
A  ← ExpandA(ρ) ∈ R_q^{k×ℓ}                   # Alg 25/26: rejection-sample t & (2^26-1), t < q
s1 ← S_η1^ℓ using ρ' ; s2 ← S_η2^k using ρ'   # Alg 27 (SampleEta)
t  ← A·s1 + s2 ∈ R_q^k
(t1, t0) ← Power2Round(t)                     # Alg 29, base 2^d
pk ← PackPK(ρ, t1)                            # Alg 7
tr ← CRH(pk)                                  # 1024-bit
sk ← PackSK(ρ, tr, s1, s2, t0)                # Alg 9
return (pk, sk)
```

### Sign — spec Algorithm 2 (§3.1.2)
```
(ρ, tr, s1, s2, t0) ← UnpackSK(sk)
Ts1 ← PrepareTable(s1, η1, ℓ) ; Ts2 ← PrepareTable(s2, η2, k)    # Alg 37
pre ← 0x00 ‖ len(ctx) ‖ ctx                                      # ctx ≤ 255 bytes
μ   ← CRH(tr ‖ pre ‖ M)                                          # 1024-bit
ρ'' ← {0,1}^1024 ;  A ← ExpandA(ρ) ;  κ ← 0
loop:
    y  ← S~_γ1^ℓ using (ρ'', κ) ; κ ← κ+1                        # Alg 28 SampleGamma1
    w  ← A·y
    (w1, w0) ← (HighBits_q(w, 2γ2), LowBits_q(w, 2γ2))           # Alg 30 Decompose
    c~ ← H_2λ(μ ‖ W1Encode(w1))                                  # Alg 22
    c  ← SampleInBall(c~) ∈ B_τ                                  # Alg 6
    if SmallPolywithEarlycheck(z, w0', c, Ts1, Ts2, w0, y,
                               γ1-β1, γ2-β2): continue           # Alg 36: z = y+c·s1, w0' = w0-c·s2
    h' ← SmallPoly(c, t0, 2^{d-1}, k)                            # Alg 35 (see discrepancy D5)
    if ‖h'‖∞ ≥ γ2: continue
    w0'' ← w0' + h'
    h  ← MakeHint(w0'', w1)                                      # Alg 31
    if ‖h‖_1 > ω: continue
    return σ ← PackSig(c~, z, h)                                 # Alg 11
```

### Verify — spec Algorithm 3 (§3.1.3)
```
(ρ, t1) ← UnpackPK(pk) ; (c~, z, h) ← UnpackSig(σ)   # Alg 12/24: reject non-canonical h
if ‖z‖∞ ≥ γ1 - β1: reject
pre ← 0x00 ‖ len(ctx) ‖ ctx
μ   ← CRH(CRH(pk) ‖ pre ‖ M)
A   ← ExpandA(ρ) ; c ← SampleInBall(c~)
w   ← A·z - c·t1·2^d
w1  ← UseHint(w, h)                                  # Alg 32
accept iff H_2λ(μ ‖ W1Encode(w1)) = c~
```

### Hashing (spec §2.3)
```
H_λ(x) = λ bytes ; CRH(x) := H_128(x) (1024-bit) ; Sample(x, outlen) = XOF
Instantiation (reference code, auxfunc.c): SM3 core.
  pseudohash_{512,768,1024} = SM3 + HMAC-SM3 cascade with fixed keys derived from π, e
  sm3hash(256)              = plain SM3
  xof_bytes                 = KDF-SM3
Spec §2.3 states verbatim that these are "for correctness testing; a production
instantiation must use cryptographically secure primitives."
```

## Implementation vs specification

Checked `src/OPSsig-{128,256,512}` → `Implementations/Reference_Implementation/*`:
`sign.c` (Alg 1/2/3), `packing.c` (Alg 7–24), `poly.c` (Alg 6, 27, 28), `rounding.c`
(Alg 29–32), `mult.c` (Alg 35–37), `ntt.c`/`reduce.c` (Alg 33/34/38/39),
`auxfunc.c` (H, CRH, XOF).

Spot-checked constants (`params.h`, all three instances) against spec Table 1:
`N`, `Q`, `D`, `K`, `L`, `ETA`, `TAU`, `GAMMA1`, `GAMMA2`, `OMEGA` — **all agree**
(e.g. L5: `N 1024`, `Q 67104769`, `K/L 4`, `ETA 2`, `TAU 90`, `GAMMA1 (1<<22)`,
`GAMMA2 ((Q-1)/48)`, `OMEGA 90`). `SEEDBYTES 64` = 512 bits and `CRHBYTES 128` = 1024 bits
match §2.5. All nine spec size figures reproduce exactly from the `params.h` formulas and
match the observed library values.

Agreements: `μ = CRH(tr ‖ 0x00 ‖ len(ctx) ‖ ctx ‖ M)` is byte-identical in signer
(`sign.c:104-111`) and verifier (`sign.c:224-231`), including the `ctxlen > 255` rejection;
verify re-derives `tr = CRH(pk)`; `unpack_h` (`packing.c:47-88`) enforces full hint canonicity
(position `< N`, strictly increasing within a lane, monotone lane bounds, trailing slots zero,
unused top bits masked for L3/L5) per Alg 24; verify rejects `siglen != CRYPTO_BYTES`.

**Discrepancies**

- **D1 (real deviation) — SampleInBall.** Spec Alg 6 specifies a *multiplication-based*
  range reduction (`m = x·(i+1)`, `j = m >> 16`, reject iff `m mod 2^16 < 2^16 mod (i+1)`)
  and the surrounding text explicitly advertises it. The code (`poly.c:238-268` in all three
  instances) instead does the classic ML-DSA mask-and-reject (`b = x & 0x01FF` / `0x03FF`;
  `while (b > i)`). Different challenge from the same seed; KATs follow the code, so the
  specification text is wrong here. Also, Alg 6 parses "τ sign bits" while the code always
  consumes 64 (L1/L3) or 128 (L5) sign bits.
- **D2 (real deviation, L1 only) — w1 bit-width.** Alg 21 gives
  `b = ⌈log2(⌊(q−1)/2γ2⌋ + 1)⌉`. For L1, `⌊(q−1)/2γ2⌋ = 16` exactly, so the spec formula
  yields 5 bits, but `OPSsig-128/params.h:31` uses `POLYW1_PACKEDBYTES (N*4/8)` = 4 bits.
  The spec formula is off by one when the quotient is a power of two (L3 → 6 and L5 → 5 both
  agree). Not exploitable (w1 is hashed, never transmitted) but the encoding in the spec does
  not reproduce the implementation.
- **D3 (spec gap) — β1, β2 are never defined.** They appear in Alg 2 line 15, Alg 3 line 3
  and throughout §5, but are absent from Table 1 and from §2. The implementation uses
  `BETA = TAU*ETA` (`params.h:18`), i.e. β1 = β2 = τη. The spec cannot be implemented from
  its own text on this point.
- **D4 (real deviation / domain separation) — H_2λ is not one function.** Spec §2.3 defines a
  single family `H` with `CRH := H_128`. OPSsig-128 computes `c~` with `sm3hash` (plain SM3-256,
  `sign.c:141-142`), while OPSsig-256/512 compute it with `pseudohash`, *the same function used
  for CRH* (`sign.c:126` / `sign.c:127`). For OPSsig-512 the challenge hash and the message hash
  are the identical 1024-bit primitive with no domain tag: `μ = F(tr‖pre‖M)`,
  `c~ = F(μ‖W1Encode(w1))`. Note also `sm3hash()` only accepts `digest_len_bits == 256`
  (`auxfunc.c:446-458`), so the L1 code path is the only one it can serve. No concrete attack is
  claimed here; this is the transcript/domain-separation item left `not_tested` in
  `security_findings.md`.
- **D5 (spec internal inconsistency).** Alg 2 line 18 writes `SmallPoly(c, t0, 2^{d-1}, k)`;
  the prose two lines below writes `h' := SmallPoly(c, t0, 2^d, k)`. The third argument is the
  coefficient bound of `t0`, which is `2^{d-1}`, so the prose is the erroneous one.
- **D6 (editorial).** Alg 10 UnpackSK returns `(ρ, key, tr, s1, s2, t0)` — a `key` field that
  PackSK (Alg 9) never writes and that the sk size does not account for (ML-DSA leftover).
  `params.h` sk = `SEEDBYTES + CRHBYTES + (L+K)·POLYETA + K·POLYT0`, with no `key`.
- **D7 (stale text).** §1.1 claims "the reference implementation ... currently realizes the
  Level-1 instance" and §6.2 benchmarks one directory `Reference_Implementation/AlgorithmInstance`
  with `test_speed_yuandunsig.c`; three complete instances are shipped (all KATs pass) and the
  file is `test_speed_OPSsig.c` — the submission was evidently renamed after the document.
- **Headline caveat (not a deviation):** §2.3 itself declares the shipped SM3-based `H`/`Sample`
  to be for correctness testing only, with production requiring "cryptographically secure
  primitives", while §5.4/§5.5 model them as (quantum) random oracles. The HMAC-SM3 cascade
  producing the 512/768/1024-bit outputs is not a standardised XOF.

**Not verified (time-boxed):** NTT/Montgomery constants (Alg 33/34/38/39); that
`PrepareTable`/`SmallPolywithEarlycheck` packed-lane arithmetic (Alg 36/37) really computes
`c·s1`, `c·s2`, `c·t0` — only its call structure and bound arguments were matched to Alg 2;
`SampleEta`/`SampleGamma1` nonce derivation; the lattice estimates of Table 2.
