# kex-04 DKEX — algorithm summary

Three-pass **mutually authenticated** key exchange in the signature-authenticated
(SIGMA / Canetti–Krawczyk) style: an *unauthenticated, CPA-secure* Ding-type
reconciliation key exchange (DKE) over module lattices supplies the ephemeral secret,
and both parties hold a long-term **ML-DSA** signature key pair with which they sign a
single transcript binder T. Hardness: MLWE for confidentiality plus the signature's
EUF-CMA for authentication. The DKE core is byte-identical to the one in kex-01
(ADKEX) — the difference is that ADKEX authenticates the responder with a CCA KEM
(KEMTLS-PDK) whereas DKEX authenticates both parties with signatures.

Specification: `kex-04-spec.pdf` (45 pages). §2.2.1 Sig/Rec (Algorithms 2–3),
§2.3 DKE (Algorithms 8–12), §2.4 DKEX (Algorithms 13–19, Figure 1), §2.5 Tables 1–2.
English.

## Parameters

| parameter | DKEX-128 | DKEX-256 | DKEX-512 | meaning |
|---|---|---|---|---|
| n | 256 | 256 | 512 | ring degree, R_q = Z_q[X]/(X^n+1) |
| q | 3329 | 3329 | 7681 | modulus |
| k | 2 | 4 | 4 | module rank |
| η | 3 | 2 | 3 | CBD width for s, e |
| ℓ | 4 | 5 | 4 | signal bits per coefficient (2^ℓ subdomains) |
| d (= d_B) | 10 | 11 | 11 | ciphertext compression bits |
| d_A | 12 | 12 | 13 | pk coefficient width (uncompressed ⌈log2 q⌉) |
| N = λ = λ_K | 256 | 256 | 512 | seed / shared-key bits |
| SIG | ML-DSA-44 | ML-DSA-87 | ML-DSA-87 ⋆ | spec Table 1; ⋆ is the spec's own caveat |
| H, KDF | SM3-256 | SM3-256 | pseudoXOF-512 | spec Table 1 |
| failure prob. | 2^-132.7 | 2^-181.2 | 2^-167.0 | spec Table 2 |
| NGCC level | 1 | 2 | 3 | |

Sizes (bytes). The spec gives no size table for DKEX; the "spec" column below is derived
from the algorithm definitions (VKBITS/SIGKBITS/SIGBITS = ML-DSA, PKBITS/SKBITS/CTBITS =
DKE) and from the explicit state sizes stated in Algorithms 15/16/17/19.

| instance | pk spec | pk impl | sk spec | sk impl | st_A spec | st_A impl | st_B spec | st_B impl | total msg | ss | passes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| DKEX-128 | 1312 | 1312 | 2560 | 2560 | 2880 | 2880 | **64** | **1312** | 6408 / 6408 | 32 / 32 | 3 / 3 |
| DKEX-256 | 2592 | 2592 | 4896 | 4896 | 5696 | 5696 | **64** | **2592** | 12390 / 12390 | 32 / 32 | 3 / 3 |
| DKEX-512 | 2592 | 2592 | 4896 | 4896 | 9312 | 9312 | **128** | **2592** | 15718 / 15718 | 64 / 64 | 3 / 3 |

Everything agrees except st_B — see discrepancy 1. Derivations that check out:
st_A = |sk_e| + |M_1| + |pk_A| = k·d_A·n/8 + (k·d_A·n/8 + |seed|) + VKBITS/8;
m1 = M_1 = DKE pk; m2 = M_2 ‖ σ_B with M_2 = k·d·n/8 + ℓ·n/8; m3 = σ_A.

## The signal / reconciliation function (the security-critical part)

Identical to kex-01 (the two submissions ship the same `dke_utils.c` / `poly.c`).
With ℓ such that 2^{ℓ+1} | (q−1) and **L = (q−1)/2^ℓ**, the *centred* Z_q =
{−(q−1)/2,…,(q−1)/2} is cut into 2^ℓ intervals of length L centred on multiples of L:

```
I_0 = [−L/2, L/2],   I_w = ((2w−1)L/2, (2w+1)L/2]   for w = 1 … 2^ℓ−1  (wrapping at ±q/2)
```

**Sig (Algorithm 2).** For each coefficient, sample a fresh dither bit b ←$ {0,1} and
output the unique w with `f[i] − b[i] mod q ∈ I_w`. The dither is what removes the
statistical bias of the signal.

**Rec (Algorithm 3).** `ss[i] = (f[i] − w[i]·L mod q) mod 2` — subtract wL to rotate
I_w onto I_0, then take the parity of the centred representative.

Tolerance: Rec(x, Sig(y)) = Rec(y, Sig(y)) whenever x − y is even and
|x − y| ≤ (q/2)(1 − 2^{−ℓ}) − 2. ℓ = 1 is the original Ding Key Exchange; larger ℓ widens
the tolerance from ≈ q/4 − 2 to ≈ q/2 − 2 at the cost of leaking ℓ bits per coefficient.
Lemma 2.1: Rec(x,·) remains perfectly unbiased conditioned on the published signal w.
Both parties force the value even (`k ← 2·k`) before Sig/Rec, so the parity of the
centred representative is the key bit.

**Key-reuse exposure — this is the important part for DKEX.** Unlike ADKEX, DKEX uses
DKE *raw*, with no FO transform and no re-encryption check: `DKE.DeriveSecret` is a bare
reconciliation oracle. If the initiator's DKE key pair (M_1, sk_e) were ever reused
across sessions, the classical Ding signal-leakage / key-reuse attack would apply
directly (adaptively chosen M_2 values plus the observable success/failure of
reconciliation recover sk_e). Two things stop it here, and both must hold:
1. **(M_1, sk_e) is ephemeral** — freshly generated in every pass 1 (Algorithm 15 line 2)
   and explicitly erased in pass 3 (Algorithm 17 line 10).
2. **A verifies σ_B *before* calling DKE.DeriveSecret** (Algorithm 17 lines 4–8): an
   active attacker cannot deliver a chosen M_2 to A's reconciliation without forging B's
   ML-DSA signature over the transcript that includes M_1 and M_2.
The implementation honours both (see below), so the ordering in Algorithm 17 is
load-bearing, not cosmetic.

## Pseudocode

### DKE, the unauthenticated core (Algorithms 10, 11, 12)
```
DKE.Initiate(coins ∈ {0,1}^n):                          # A, ephemeral
    (r, ρ) ← XOF(coins; 2n);   Ā ← GenMatrix(ρ)
    (s_A, nonce) ← SampleSecret_η(r, 0);  e_A ← SampleSecret_η(r, nonce)
    ū_A ← Ā ∘ NTT(s_A) + NTT(e_A)
    pk ← ByteEncode(ū_A) ‖ ρ            sk ← ByteEncode(NTT(s_A))

DKE.Response(pk, coins ∈ {0,1}^{2n} = (r, b)):          # B
    (ū_A, ρ) ← pk;   Ā^T ← GenMatrix(ρ, 1)
    (s_B, nonce) ← SampleSecret_η(r, 0);  e_B ← SampleSecret_η(r, nonce)
    u_B  ← NTT^-1(Ā^T ∘ NTT(s_B)) + e_B;   u'_B ← Compress(u_B, d_B)
    k_B  ← NTT^-1(ū_A ∘ NTT(s_B)) + SampleBinomialPoly(XOF(r‖nonce))
    k_B  ← 2·k_B
    w    ← Sig(k_B, b)                  # ℓ bits per coefficient
    c    ← u'_B ‖ w                     ss ← Rec(k_B, w)

DKE.DeriveSecret(c = (u'_B, w), sk = s̄_A):              # A
    k_A ← 2·NTT^-1(NTT(Decompress(u'_B, d_B)) ∘ s̄_A)
    ss  ← Rec(k_A, w)
```

### DKEX — pass structure (Algorithms 13–19, Figure 1)

Spec defines **3 passes**; OBSERVED reports `passes=3`. Agreement.

```
Init_A()                                   # Algorithm 13
    ρ ←$ {0,1}^{|ρ_SIG.KeyGen|}
    (pk_A, sk_A) ← SIG.KeyGen(ρ)           # long-term ML-DSA key pair
    st_A ← ε

Init_B()                                   # Algorithm 14 — symmetric to Init_A
    (pk_B, sk_B) ← SIG.KeyGen(ρ);   st_B ← ε
    (pk_A and pk_B are assumed pre-distributed / mutually known)

pass 1  A → B   (Algorithm 15)
    ρ1 ←$ {0,1}^N
    (M_1, sk_e) ← DKE.Initiate(ρ1)         # EPHEMERAL CPA key pair
    m1   = M_1                                                (|m1| = PKBITS)
    st_A = (sk_e, M_1, pk_A)                                  (SKBITS+PKBITS+VKBITS)

pass 2  B → A   (Algorithm 16)
    M_1 ← m1;   ρ2 ←$ {0,1}^{2N}
    (M_2, ss) ← DKE.Response(M_1, ρ2)      # B's DKE secret, via Sig
    T  ← H(LABEL_A ‖ LABEL_B ‖ pk_A ‖ pk_B ‖ M_1 ‖ M_2 ; N)
    σ_B ← SIG.Sign(sk_B, T)
    m2   = (M_2, σ_B)                                         (CTBITS + SIGBITS)
    st_B = (ss, T)                                            (2N bits)

pass 3  A → B   (Algorithm 17)   # final pass
    (M_2, σ_B) ← m2;   (sk_e, M_1, pk_A) ← st_A
    T ← H(LABEL_A ‖ LABEL_B ‖ pk_A ‖ pk_B ‖ M_1 ‖ M_2 ; N)
    if SIG.Verify(pk_B, T, σ_B) ≠ 1: return ⊥           # <-- BEFORE touching sk_e
    ss  ← DKE.DeriveSecret(M_2, sk_e)      # A's DKE secret, via Rec
    σ_A ← SIG.Sign(sk_A, T)
    erase sk_e, M_1, pk_A;   st_A = (ss, T);   m3 = σ_A       (SIGBITS)

DeriveSS_A(st_A)                           # Algorithm 18
    ss ← KDF(st_A ; N)                     # st_A = (ss_raw ‖ T)

DeriveSS_B(m3, st_B, pk_A)                 # Algorithm 19
    σ_A ← m3;   (ss, T) ← st_B
    if SIG.Verify(pk_A, T, σ_A) ≠ 1: return ⊥
    ss ← KDF(st_B ; N)
```
LABEL_A = "DKEX-KSIG-ℓ-A", LABEL_B = "DKEX-KSIG-ℓ-B", ℓ ∈ {128,256,512}.

## Implementation vs specification

Checked: `ADKEX_parameters.h`, `adkex_sig.h`, `parameters.h`, `KEX_AlgorithmInstance.c`,
`adkex_derand.c` (Alg. 13–19), `adkex_sig_mldsa.c` (SIG adapter), `dkecpa.c` (Alg. 10–12),
`dke_utils.c` + `poly.c` (Sig/Rec), `random_sampling.c`, `randombytes.c`. The build uses
`-DDKE_FORCE_SCALAR -DDKE_HASH=0 -DDKE_RANDOM=0 -DADKEX_SIG_BACKEND_MLDSA`, i.e. the
scalar SM3/DRNG reference paths and the vendored pq-crystals ML-DSA under `dilithium/`.

Agreements:
- Table 2 is reproduced exactly for all three rows, including η = 2 for DKEX-256
  (`parameters.h:165-171` sets `DKE_CBD_ETA` to 2 exactly when `DKE_MODE == 256`; the
  `DKE_NOISE_A`/`DKE_NOISE_B` macros left at 3 are dead code). Table 1's primitive
  choices match: ML-DSA-44 / ML-DSA-87 / ML-DSA-87 via `ADKEX_SIG_MLDSA_LEVEL` = 2/5/5,
  and H/KDF = `sm3hash(256)` for N ≤ 256, `pseudoXOF(512)` for DKEX-512.
- **Sig and Rec are bit-exact with the spec's interval definition.** The code computes
  `Compress_q(x, ℓ) = round(2^ℓ·x/q) mod 2^ℓ` (`poly.c` `DKE_getsignal`) and
  `⌊w·q/2^ℓ⌋` (`DKE_poly_fromsignal`). Working out the boundaries: the first x mapped to
  w+1 is ⌈(2w+1)q/2^{ℓ+1}⌉ = (2w+1)L/2 + 1, which is exactly I_{w+1}'s lower end, and
  ⌊w·q/2^ℓ⌋ = w·L exactly for every w < 2^ℓ. The dither is applied as k + (0 or −1),
  i.e. k − b with b ∈ {0,1}; the parity is taken on the **centred** representative
  (`DKE_poly_reduce_center` before `DKE_mod2`), the only reading consistent with the
  spec's centred Z_q (q is odd, so using the least non-negative representative would
  flip the bit for every negative coefficient). `k ← 2·k` (`DKE_poly_scale2`) is present
  on both sides.
- **The signature checks are present, complete, and correctly ordered.**
  `adkex_derand.c` `ADKEX_pass3_msg_a_derand` recomputes T, calls
  `adkex_sig_verify(pk_B, σ_B, T)` and returns −1 *before* `DKE_CPA_dec(ss, sk_e, M_2)`
  — sk_e is never applied to an unauthenticated M_2. `ADKEX_derive_ss_b` verifies
  `σ_A` against `pk_A` and returns −1 on failure, so B's Algorithm 19 check is not
  skipped either. Neither check is inverted; `adkex_sig_verify` returns 1 only when
  `crypto_sign_verify_internal` returns 0.
- Pass 3 erases the ephemeral state exactly as Algorithm 17 line 10 requires
  (`memset(sta, 0, ADKEX_STA_MAX_BITS/8)` before writing (ss ‖ T)), and the intermediate
  `T`, `ss`, `pk_*_tmp` buffers are zeroised.
- Randomness budgets match: ρ1 = N bits (`ADKEX_PASS1_COINBITS = ADKEX_SEEDBITS`),
  ρ2 = 2N bits (`ADKEX_PASS2_DKEX_COINBITS = SEEDBITS + N`), SIG keygen = 32 bytes.
- All randomness comes from the seeded DRNG. `kex_init_a`, `kex_init_b`,
  `kex_generate_pass1_msg_a` and `kex_generate_pass2_msg_b` each call
  `get_random_number(&drng_algorithm, …)`; the candidate's own `randombytes.c` is a
  DRNG-backed replacement with no OS-entropy path, and the ML-DSA keygen seed is routed
  into it through `adkex_sig_random_hook`.

Discrepancies:
1. **(a) real deviation — st_B is |pk_SIG| bytes, not 2N.** Spec Algorithm 14 sets
   st_B = ε and Algorithm 16 sets st_B ∈ {0,1}^{2N} (64 / 64 / 128 bytes). The
   implementation stashes **pk_B in st_B at `kex_init_b`**
   (`KEX_AlgorithmInstance.c:63`, `memcpy(stb, pkb, ADKEX_SIGPKBITS/8)`) because the
   ICCS `kex_generate_pass2_msg_b` signature has no pk_B parameter but Algorithm 16 line
   4 needs pk_B for the transcript. Consequently
   `ADKEX_STB_MAX_BITS = max(SIGPKBITS, 2·SSBITS)` and `kex_get_stb_len_bytes()` reports
   1312 / 2592 / 2592 instead of 64 / 64 / 128 — a 20× over-declaration at level 1 and
   the only size in the whole candidate that does not match the specification. (The
   *post-pass-2* length returned through `*stb_len_bytes` is the correct 2N; only the
   declared maximum and the init_b state deviate.) kex-01 solved the same API problem
   differently, by slicing pk_B out of sk_B, and therefore kept st_B at 3N. The same
   trick is used for pk_A in st_A at `kex_init_a` (`:45`), but there it is invisible
   because st_A's pass-1 layout already ends with pk_A.
2. **(a) real deviation — non-canonical label encoding: the domain-separation strings
   are hashed with a trailing NUL byte.** `ADKEX_LABEL_BITS` is fixed at 128 (16 bytes)
   but `ADKEX_LABEL_A` = `"DKEX-KSIG-128-A"` and `ADKEX_LABEL_B` = `"DKEX-KSIG-128-B"`
   are **15** ASCII characters. `adkex_derand.c:22-23` does
   `memcpy(p, ADKEX_LABEL_A, ADKEX_LABEL_BITS/8)` — 16 bytes from a 16-byte string
   literal — so the byte actually absorbed into T is `"DKEX-KSIG-128-A\0"`. It is
   in-bounds and consistent on both sides, so the protocol works, but an implementation
   that follows the spec's `LABEL_A = "DKEX-KSIG-ℓ-A"` literally computes a different T
   and the handshake fails. The sibling submission kex-01 does not have this bug — its
   `"ADKEX-KEMTLS-128"` happens to be exactly 16 characters — which is what makes this
   look accidental rather than intentional. All three levels are affected (all six
   labels are 15 characters).
3. **(b) spec inconsistency — st_A length in Algorithm 18.** Algorithm 17 line 11 sets
   st_A ← (ss, T) and its Output line says st_A ∈ {0,1}^{2N}, but Algorithm 18's Input
   line says st_A ∈ {0,1}^N. The implementation uses 2N
   (`ADKEX_KDF_INBITS = 2*ADKEX_SSBITS`, and `kex_generate_pass3_msg_a` reports
   `*sta_len_bytes = ADKEX_KDF_INBITS/8`), which is the only self-consistent reading.
4. **(b) spec omission — the randomness source and the signature variant are not
   pinned.** Algorithms 13/14 write ρ ←$ {0,1}^{|ρ_SIG.KeyGen|} without fixing its
   length, and the spec never says whether SIG.Sign is deterministic. The implementation
   uses a 32-byte ML-DSA keygen seed and the **deterministic** ML-DSA variant
   (`adkex_sig_mldsa.c:72-80`, `crypto_sign_signature_internal` with `rnd` zeroed and
   the FIPS 204 empty-context prefix `{0,0}`). That is a legal FIPS 204 mode and is
   required for KAT reproducibility, but it should be stated normatively.
5. **(b) spec ambiguity inherited from the DKE core** — `SampleBinomialPoly` in
   Algorithm 11 line 14 carries no η subscript, and the spec does not say that the
   `nonce` counter continues from the s_B/e_B loops (it does in the code, leaving nonce
   at 2k). Any re-implementation that restarts the nonce will not interoperate.
6. **(informational) the spec itself flags DKEX-512 as under-authenticated.** §2.1.3 and
   Table 1's ⋆ note that ML-DSA-87 cannot support a 512-bit authentication claim; only
   confidentiality reaches that level.
7. **(informational)** `skb_len_bytes`, `pka_len_bytes`, `m1_len_bytes`, `m2_len_bytes`
   and `sta_len_bytes` are all cast to `(void)` and never validated in
   `KEX_AlgorithmInstance.c`; a caller that supplies a short buffer gets an out-of-bounds
   read rather than an error return. The ICCS harness always passes the declared lengths,
   so this is not reachable from the KAT driver.

Not verified: the vendored `dilithium/` tree was assumed to be the unmodified pq-crystals
reference and was not diffed against upstream; the NTT/`basemul` layer and the
`GenMatrix` rejection sampler were read but not checked constant-by-constant; the DFR
figures of Table 2 were not recomputed. Only the DKEX-128 tree was read line by line.
The DKE core files (`dke_utils.c`, `poly.c`, `dkecpa.c`, `parameters.h`,
`random_sampling.c`) were verified byte-identical to kex-01's, so the Sig/Rec findings
there apply unchanged here.
