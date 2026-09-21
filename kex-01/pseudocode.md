# kex-01 ADKEX — algorithm summary

Two-pass **unilaterally authenticated** key exchange following the KEMTLS-PDK template:
both the ephemeral and the static KEM are DKEM, an IND-CCA KEM built by a
one-time-pad/FO transform over DKE, a *reconciliation-based* Ding-style module-LWE key
exchange with fine-grained (2^ℓ-valued) signals. Hardness: MLWE only; no new assumption
beyond what DKEM needs. The responder B holds a static DKEM key pair; **the initiator A
holds no long-term key at all** (spec Figure 1: "The initiator A holds no long-term key;
the responder's static encapsulation key pk_B is pre-distributed").

Specification: `kex-01-spec.pdf` (53 pages). §2.2.1 Sig/Rec (Algorithms 2–3),
§2.3 DKE (Algorithms 8–12), §2.4 DKEM (Algorithms 13–16), §2.5 ADKEX
(Algorithms 17–21, Figure 1, Table 1), §2.6 Table 2. English.

## Parameters

| parameter | ADKEX-128 | ADKEX-256 | ADKEX-512 | meaning |
|---|---|---|---|---|
| n | 256 | 256 | 512 | ring degree, R_q = Z_q[X]/(X^n+1) |
| q | 3329 | 3329 | 7681 | modulus (quadratic NTT splitting) |
| k | 2 | 4 | 4 | module rank |
| η | 3 | 2 | 3 | CBD width for s, e |
| ℓ | 4 | 5 | 4 | signal bits per coefficient (2^ℓ subdomains) |
| d (= d_B) | 10 | 11 | 11 | ciphertext compression bits |
| d_A | 12 | 12 | 13 | pk coefficient width (uncompressed, ⌈log2 q⌉) |
| N | 256 | 256 | 512 | shared-key / seed bit length |
| H, KDF | SM3-256 | SM3-256 | pseudoXOF-512 | spec Table 1 |
| failure prob. | 2^-131.7 | 2^-180.2 | 2^-166.0 | spec Table 2 |
| NGCC level | 1 | 2 | 3 | |

Sizes (bytes), specification (Table 1) vs the built reference library:

| instance | passes spec | passes impl | pk | sk | st_A | st_B | total msg | ss | match |
|---|---|---|---|---|---|---|---|---|---|
| ADKEX-128 | 2 | 2 | 800 / 800 | 1600 / 1600 | 3232 / 3232 | 96 / 96 | 2400 / 2400 | 32 / 32 | yes |
| ADKEX-256 | 2 | 2 | 1568 / 1568 | 3136 / 3136 | 6336 / 6336 | 96 / 96 | 4768 / 4768 | 32 / 32 | yes |
| ADKEX-512 | 2 | 2 | 3392 / 3392 | 6784 / 6784 | 13376 / 13376 | 192 / 192 | 9664 / 9664 | 64 / 64 | yes |

(spec / impl in each cell; every value agrees, including the number of passes.)
Derived: pk = k·d_A·n/8 + |seed|; ct = k·d·n/8 + ℓ·n/8 + N/8; sk = k·d_A·n/8 + |pk| + N/8;
m1 = pk_e ‖ ct_S, m2 = ct_e; st_A = sk_e ‖ ss_s ‖ m1; st_B = ss_e ‖ ss_s ‖ T (3N bits).

## The signal / reconciliation function (the security-critical part)

Let ℓ be such that 2^{ℓ+1} | (q−1) and set **L = (q−1)/2^ℓ** (208 for q=3329, ℓ=4).
Z_q is taken **centred**, {−(q−1)/2, …, (q−1)/2}, and partitioned into 2^ℓ intervals
I_w of length L centred on wL:

```
I_0 = [−L/2, L/2],   I_w = ((2w−1)L/2, (2w+1)L/2]  for w = 1..2^ℓ−1   (wrapping at ±q/2)
```

**Sig (Algorithm 2).** For each coefficient: sample b ←$ {0,1} (fresh, per coefficient),
find the unique w with `f[i] − b[i] mod q ∈ I_w`, output w ∈ {0,…,2^ℓ−1}.
The one-bit dither b is what removes the statistical bias of the signal.

**Rec (Algorithm 3).** `ss[i] = (f[i] − w[i]·L mod q) mod 2` — subtracting wL rotates
I_w back onto I_0, then the parity of the *centred* representative is the key bit.

Property (spec §2.2.1): if x − y is even and |x − y| ≤ (q/2)(1 − 2^{−ℓ}) − 2 then
Rec(x, Sig(y)) = Rec(y, Sig(y)). ℓ = 1 is the original Ding Key Exchange; growing ℓ
widens the tolerance from ≈ q/4 − 2 to ≈ q/2 − 2 at the cost of leaking ℓ bits per
coefficient. Lemma 2.1: Rec(x,·) is still perfectly unbiased *conditioned on* the
revealed signal w — this is the claim that makes publishing w safe.

**Key-reuse exposure.** Signal-based exchanges are the classic source of key-reuse /
signal-leakage attacks (adaptively chosen ciphertexts reveal the signal's dependence on
the long-term secret; spec §5.2.5). ADKEX blocks them structurally: the DKE public key
that a party reuses is never used in a raw DKE session — the initiator's DKE key
(M_1, sk_e) is **ephemeral**, generated fresh in pass 1 and erased, and the responder's
static pk_B is only ever consumed inside `DKEM.Decaps`, which re-encapsulates and
compares the **full** ciphertext (tag included) before releasing the key, falling back to
KDF(z ‖ c_2) on mismatch. So no adaptively chosen signal ever reaches a reused secret
unfiltered.

## Pseudocode

### Underlying DKE (Algorithms 10, 11, 12)
```
DKE.Initiate(coins):                                    # A
    (r, ρ) ← XOF(coins; 2n)
    Ā ← GenMatrix(ρ);  s_A ← SampleSecret_η(r,0);  e_A ← SampleSecret_η(r,nonce)
    ū_A ← Ā ∘ NTT(s_A) + NTT(e_A)
    pk ← ByteEncode(ū_A) ‖ ρ            sk ← ByteEncode(NTT(s_A))

DKE.Response(pk, coins):                                # B, coins ∈ {0,1}^{2n} = (r, b)
    (ū_A, ρ) ← pk;   Ā^T ← GenMatrix(ρ, 1)
    s_B ← SampleSecret_η(r,0);  e_B ← SampleSecret_η(r,nonce)
    u_B ← NTT^-1(Ā^T ∘ NTT(s_B)) + e_B;   u'_B ← Compress(u_B, d_B)
    k_B ← NTT^-1(ū_A ∘ NTT(s_B)) + SampleBinomialPoly(XOF(r‖nonce))
    k_B ← 2·k_B                                        # force even -> parity is the key
    w  ← Sig(k_B, b);   c ← (u'_B ‖ w);   ss ← Rec(k_B, w)

DKE.DeriveSecret(c, sk = s̄_A):                          # A
    (u'_B, w) ← c;   k_A ← 2·NTT^-1(NTT(Decompress(u'_B, d_B)) ∘ s̄_A)
    ss ← Rec(k_A, w)
```

### DKEM = IND-CCA KEM over DKE (Algorithms 13–16)
```
KeyGen():   coins,rej ←$ {0,1}^n;  (pk,sk) ← DKE.Initiate(coins);  dk = sk‖pk‖rej
Internal(ek, coins):
    ρ ← last n bits of ek;  r ← XOF(coins‖ρ; 2n)
    (c1, ss) ← DKE.Response(ek, r)
    c2 ← coins ⊕ ss            ct = c1‖c2            K ← KDF(ss; n)
Encaps(ek): coins ←$ {0,1}^n; return Internal(ek, coins)
Decaps(dk, ct = c1‖c2):
    ss ← DKE.DeriveSecret(c1, sk);  coins ← c2 ⊕ ss
    (ct', K) ← Internal(ek, coins);  K̄ ← KDF(rej‖c2; n)
    return  ct = ct' ? K : K̄                            # implicit rejection
```

### ADKEX — pass structure (Algorithms 17–21, Figure 1)

Spec defines **2 passes**; OBSERVED reports `passes=2`. Agreement.

```
Init_A()                                   # Algorithm: none — A has NO long-term key
    pk_A = ε, sk_A = ε, st_A = ε

Init_B(ρ ∈ {0,1}^{2N})                     # Algorithm 17
    (pk_B, sk_B) ← DKEM.KeyGen(ρ)          # static CCA key pair, pre-distributed
    st_B ← ε

pass 1  A → B   (Algorithm 18, inputs ρ1 ∈ {0,1}^{2N}, ρ3 ∈ {0,1}^N)
    (M_1, sk_e) ← DKEM.KeyGen(ρ1)          # EPHEMERAL CCA key pair
    (ct_S, ss_s) ← DKEM.Encaps(pk_B; ρ3)   # encapsulate to B's static key
    m1  = M_1 ‖ ct_S                                          (|m1| = PKBITS+CTBITS)
    st_A = sk_e ‖ ss_s ‖ m1                                   (SKBITS+N+PKBITS+CTBITS)

pass 2  B → A   (Algorithm 19, input ρ2 ∈ {0,1}^N)             # final pass
    (M_1, ct_S) ← m1
    (M_2, ss_e) ← DKEM.Encaps(M_1; ρ2)     # encapsulate to A's ephemeral key
    ss_s        ← DKEM.Decaps(sk_B, ct_S)  # B authenticates itself by being able to do this
    m2 = M_2                                                   (|m2| = CTBITS)
    T  = H(LABEL ‖ pk_B ‖ m1 ‖ m2 ; N)
    st_B = ss_e ‖ ss_s ‖ T                                     (3N bits)

DeriveSS_A(m2, st_A, pk_B)                 # Algorithm 20
    (sk_e, ss_s, m1) ← st_A
    ss_e ← DKEM.Decaps(sk_e, m2)           # includes implicit rejection
    T    ← H(LABEL ‖ pk_B ‖ m1 ‖ m2 ; N)
    ss   ← KDF(ss_e ‖ ss_s ‖ T ; N)        ;  erase sk_e, m1

DeriveSS_B(st_B)                           # Algorithm 21 (sk_B and m1 are ignored here)
    ss ← KDF(st_B ; N)                     # st_B is already ss_e ‖ ss_s ‖ T
```
LABEL = "ADKEX-KEMTLS-ℓ", ℓ ∈ {128,256,512} (16 ASCII bytes). The transcript binder T is
folded into the KDF on both sides "to defend against re-encapsulation attacks even when
DKEM provides no key-binding property" (spec Figure 1 caption).

## Implementation vs specification

Checked: `ADKEX_parameters.h`, `parameters.h`, `KEX_AlgorithmInstance.c`,
`adkex_derand.c` (Alg. 17–21), `dkecca.c` (Alg. 13–16), `dkecpa.c` (Alg. 10–12),
`dke_utils.c` + `poly.c` (Sig/Rec), `random_sampling.c` (CBD, GenMatrix), `packing.c`.
The build selects `-DDKE_HASH=0 -DDKE_RANDOM=0 -DDKE_FORCE_SCALAR`, i.e. the SM3 /
DRNG / scalar reference paths; the AVX2, NEON and Cortex-M4 variants in the same files
are not compiled.

Agreements:
- All of Table 1 and Table 2 is reproduced exactly: (n, q, k, ℓ, d) in `parameters.h`
  match Table 2 for all three rows, **including η = 2 for ADKEX-256** — note
  `DKE_NOISE_A`/`DKE_NOISE_B` are dead legacy defines left at 3; the live constant is
  `DKE_CBD_ETA`, which `parameters.h:165-171` sets to 2 exactly when `DKE_MODE == 256`
  and 3 otherwise. Every declared size (pk, sk, st_A, st_B, total transcript, ss, passes)
  matches Table 1.
- **Sig is bit-exact with the spec's interval definition**, which is not obvious: the code
  computes the ML-KEM-style `Compress_q(x, ℓ) = round(2^ℓ·x/q) mod 2^ℓ`
  (`poly.c` `DKE_getsignal`: `d0 = (u<<ℓ) + q/2; d0 *= 80635; d0 >>= 28`), whereas the
  spec's I_w boundaries use L = (q−1)/2^ℓ. Working it out, the implementation's first x
  mapped to w+1 is ⌈(2w+1)q/2^{ℓ+1}⌉ = (2w+1)L/2 + ⌈(2w+1)/2^{ℓ+1}⌉ = (2w+1)L/2 + 1 for
  every w < 2^ℓ, i.e. **the same integer boundary as I_{w+1}'s lower end**. Likewise
  `DKE_poly_fromsignal` computes ⌊w·q/2^ℓ⌋, which equals w·L exactly for all w < 2^ℓ,
  so Rec is literally `y − wL`. The dither is applied as k + (0 or −1) per bit
  (`dke_utils.c` `DKE_rand_to_poly` + `DKE_signal`), i.e. k − b with b ∈ {0,1} ✓.
  The parity is taken on the **centred** representative (`DKE_poly_reduce_center` before
  `DKE_mod2`), which is the only reading consistent with the spec's centred Z_q — taking
  it on the least non-negative representative would flip the bit for every negative
  coefficient, since q is odd.
- `k_B ← 2·k_B` (`DKE_poly_scale2`) is present on both sides (`DKE_CPA_enc_derand` and
  `DKE_CPA_dec`), so both parties reconcile on the doubled value as Algorithm 11 line 16
  and Algorithm 12 line 5 require.
- The DKEM FO layer matches Algorithms 14/16 exactly, including the ordering subtlety:
  `K = KDF(ss)` is computed **before** `ss ^= coins` produces the tag (`dkecca.c:70-79`),
  so the KDF sees the raw DKE secret as Algorithm 14 line 6 specifies. Decapsulation
  compares the **full** ciphertext including the tag (`DKE_verify(ct, ctA, DKE_CTBYTES)`)
  and selects with a constant-time `DKE_cmov`; the rejection key is KDF(z ‖ c_2) ✓.
- All randomness comes from the seeded DRNG: `get_random_number(&drng_algorithm, …)` in
  `kex_init_b`, `kex_generate_pass1_msg_a`, `kex_generate_pass2_msg_b`, and with
  `-DDKE_RANDOM=0` the shipped `randombytes.c` compiles to nothing.
- Randomness budgets match Table 1: init_b 2N, pass-1 keygen 2N, pass-1 encaps N,
  pass-2 encaps N bits, for all three rows.

Discrepancies and notes:
1. **Not a defect: `kex_init_a` returns zero-length pk_A, sk_A and st_A**
   (`KEX_AlgorithmInstance.c:32-42`, `*pka_len_bytes = *ska_len_bytes = *sta_len_bytes = 0`).
   This is exactly what the specification prescribes — ADKEX is a *unilateral*
   (KEMTLS-PDK) AKE and the spec has **no** `ADKEX.init_a` algorithm at all; Figure 1
   states in words that A holds no long-term key, and Algorithms 18/20 take only pk_B
   plus fresh randomness. The spec's answer to "what should the initiator's long-term key
   be?" is: **the empty string ε.** The only wrinkle is a limitation of the ICCS metadata
   block, which has a single `pk_len`/`sk_len` pair: the library reports B's 800/1600
   through `kex_get_pk_len_bytes()`/`kex_get_sk_len_bytes()` while `kex_init_a` produces
   nothing, so the declared lengths describe only one of the two roles. Consumers that
   size A's key buffers from the metadata will over-allocate, not under-allocate.
2. **(non-defect, but fragile) 32-bit wraparound in `DKE_getsignal`.** With ℓ = 4,
   `d0 = ((16·u + 1665) * 80635)` exceeds 2^32 exactly when the intended quotient is 16
   (u ≥ 3225). The `uint32_t` wraps, `>> 28` then yields 0, which happens to equal
   `16 & 0xf`, so the result is correct for every u ∈ [0, q). It is well-defined C
   (unsigned), but the code relies on the overflow rather than on the mask.
3. **(b) spec ambiguity — the `SampleBinomialPoly` in Algorithm 11 line 14 carries no
   η subscript.** The implementation reuses the same η as everywhere else
   (`DKE_geterrorA` with `DKE_CBD_ETA`), which is the only sensible reading, but the spec
   should state it.
4. **(b) spec ambiguity — nonce continuation.** Algorithm 11 lines 4–5 and 13 share a
   running `nonce`; the spec does not say the k-th call leaves nonce at 2k, but the
   implementation does exactly that (`dkecpa.c`, `nonce` continues from the s_B/e_B loops
   into `DKE_geterrorA(&e, coins, nonce++)`). Any re-implementation that restarts the
   nonce would fail to interoperate.
5. **(informational) pk_B is recovered from sk_B in pass 2.** The ICCS `pass2_msg_b`
   signature has no pk_B parameter, but Algorithm 19 needs it for the transcript T. The
   code slices it out of `skb` at offset `CPA_SKABYTES` (`KEX_AlgorithmInstance.c:88-91`),
   which is valid because DKEM's dk = sk_CPA ‖ pk ‖ z. Correct, but it means a caller
   that passes a truncated or malformed `skb` gets a silently wrong transcript rather
   than an error — `skb_len_bytes` is cast to `(void)` and never validated.
6. **(informational) `kex_generate_pass3_msg_a` is a stub returning −1**
   (`KEX_AlgorithmInstance.c:106-118`) present only because the ICCS driver references
   the symbol; with 2 passes it is unreachable because `pass2_msg_b` returns 1.

Not verified: the NTT/`basemul` layer and the `GenMatrix` rejection sampler were read but
not checked constant-by-constant; the DFR figures of Table 2 were not recomputed; the
claimed wPFS proof of §5.1.2 was not reviewed. Only the ADKEX-128 tree was read line by
line; this is sufficient because the three instance directories are byte-identical apart
from `build.sh` and line endings — the parameter set is selected purely by
`-DADKEX_MODE=N -DDKE_MODE=N` on the command line.
