# kex-03 CreTAKE — algorithm summary

A **credential-typed** AKE *suite*: four two-message (2-pass) AKE frameworks, one for each
ordered combination of long-term credential types — K = KEM credential, S = signature
credential — so that a deployment mid-migration can pick the framework matching what its
two endpoints actually hold. Every framework is primitive-agnostic: it composes a weak
(IND-CPA) ephemeral KEM `wKEM`, plus an IND-CCA `KEM` and/or an EUF-CMA `SIG` backend,
and derives the session key with one hash `H` over the identities (= public keys), the
complete transcript and **all** KEM-derived secrets. The instantiation layer plugs in
PolarLAC or ZEN for the KEM side and BiT for the signature side, at λ ∈ {128, 256, 512},
giving the 25 submitted instances.

Specification: `kex-03-spec.pdf` (39 pages). §3.1.1–3.1.4 Figures 1–4 (the four
frameworks), §3.2 instantiations, §4.3/Table 1 (instance naming), §5.2 Tables 2–4
(PolarLAC / BiT / ZEN parameters), §6 Tables 6–8 (per-party bandwidth). English.

## Parameters

Backend primitives (spec Tables 2, 3, 4), bytes:

| primitive | λ=128 | λ=256 | λ=512 | λ=512* |
|---|---|---|---|---|
| PolarLAC (k, n, q) | (2, 256, 257) | (2, 512, 257) | (2, 1024, 257) | (2, 1024, 769) |
| PolarLAC pk / sk_CCA / ct | 530 / 1570 / 640 | 1060 / 3140 / 1280 | 2116 / 6276 / 2560 | 2522 / 6682 / 2970 |
| PolarLAC DFR / core-SVP (C/Q) | 2^-146, 132.5/122.6 | 2^-265, 261.6/240.8 | 2^-324, 512.1/482.5 | 2^-545, 527.1/484.7 |
| ZEN (n, q) | (512, 769) | (1024, 769) | (2048, 769) | — |
| ZEN pk / ct / DFR | 615 / 512 / 2^-128 | 1229 / 1024 / 2^-175 | 2458 / 2048 / 2^-179 | — |
| BiT (d, q, (n,m)) | (256, 26881, (3,3)) | (512, 119297, (3,3)) | (1024, 520193, (3,3)) | — |
| BiT pk / sig | 1048 / 1504 | 2144 / 3456 | 5056 / 6695 | — |
| BiT MLWE / MSIS core-SVP (C) | 129 / 157 | 256 / 301 | 512 / 597 | — |

Suite-level: session key `K_LEN = 2·|k_KEM|` (32 / 64 / 128 bytes), seed length
`SEED_BYTES = 64` for every backend, `passes = 2` for every framework.

Sizes (bytes) — spec (Tables 2/3/4 for pk/sk, Tables 6–8 `BW_I + BW_R` for the
transcript) vs the built reference library. **All 25 rows match exactly**, so a single
`spec == impl` column is given; `st_A` is checked against the framework's own state
definition (Figures 1–4) and also matches in every row.

| # | instance (impl label) | spec name (Table 1) | fw | pk | sk | st_A | st_B | total msg | ss |
|---|---|---|---|---|---|---|---|---|---|
| 1 | K2K-PLAC128 | K2K-PolarLAC-128 | K2K | 530 | 1570 | 720 | 32 | 2450 | 32 |
| 2 | K2K-ZEN128 | K2K-ZEN-128 | K2K | 615 | 1303 | 592 | 32 | 2151 | 32 |
| 3 | K2S-PLAC128-BiT128 | K2S-PolarLAC-BiT-128 | K2S | 1048 | 1864 | 1554 | 32 | 3314 | 32 |
| 4 | K2S-ZEN128-BiT128 | K2S-ZEN-BiT-128 | K2S | 1048 | 1864 | 1271 | 32 | 3143 | 32 |
| 5 | S2K-BiT128-PLAC128 | S2K-BiT-PolarLAC-128 | S2K | 1048 | 1864 | 720 | 32 | 3314 | 32 |
| 6 | S2K-BiT128-ZEN128 | S2K-BiT-ZEN-128 | S2K | 1048 | 1864 | 592 | 32 | 3143 | 32 |
| 7 | S2S-BiT128-ePLAC128 | S2S-BiT-ePolarLAC-128 | S2S | 1048 | 1864 | 64 | 32 | 4178 | 32 |
| 8 | S2S-BiT128-eZEN128 | S2S-BiT-eZEN-128 | S2S | 1048 | 1864 | 64 | 32 | 4135 | 32 |
| 9 | K2K-PLAC256 | K2K-PolarLAC-256 | K2K | 1060 | 3140 | 1376 | 64 | 4900 | 64 |
| 10 | K2K-ZEN256 | K2K-ZEN-256 | K2K | 1229 | 2605 | 1120 | 64 | 4301 | 64 |
| 11 | K2S-PLAC256-BiT256 | K2S-PolarLAC-BiT-256 | K2S | 2144 | 4160 | 3108 | 64 | 7076 | 64 |
| 12 | K2S-ZEN256-BiT256 | K2S-ZEN-BiT-256 | K2S | 2144 | 4160 | 2541 | 64 | 6733 | 64 |
| 13 | S2K-BiT256-PLAC256 | S2K-BiT-PolarLAC-256 | S2K | 2144 | 4160 | 1376 | 64 | 7076 | 64 |
| 14 | S2K-BiT256-ZEN256 | S2K-BiT-ZEN-256 | S2K | 2144 | 4160 | 1120 | 64 | 6733 | 64 |
| 15 | S2S-BiT256-ePLAC256 | S2S-BiT-ePolarLAC-256 | S2S | 2144 | 4160 | 64 | 64 | 9252 | 64 |
| 16 | S2S-BiT256-eZEN256 | S2S-BiT-eZEN-256 | S2S | 2144 | 4160 | 64 | 64 | 9165 | 64 |
| 17 | K2K-PLAC512 | K2K-PolarLAC-512 | K2K | 2116 | 6276 | 2688 | 128 | 9284 | 128 |
| 18 | K2K-PLAC512Star | K2K-PolarLAC-512* | K2K | 2522 | 6682 | 3098 | 128 | 10920 | 128 |
| 19 | K2K-ZEN512 | K2K-ZEN-512 | K2K | 2458 | 5210 | 2176 | 128 | 8602 | 128 |
| 20 | K2S-PLAC512-BiT512 | K2S-PolarLAC-BiT-512 | K2S | 5056 | 9024 | 6212 | 128 | 13931 | 128 |
| 21 | K2S-ZEN512-BiT512 | K2S-ZEN-BiT-512 | K2S | 5056 | 9024 | 5082 | 128 | 13249 | 128 |
| 22 | S2K-BiT512-PLAC512 | S2K-BiT-PolarLAC-512 | S2K | 5056 | 9024 | 2688 | 128 | 13931 | 128 |
| 23 | S2K-BiT512-ZEN512 | S2K-BiT-ZEN-512 | S2K | 5056 | 9024 | 2176 | 128 | 13249 | 128 |
| 24 | S2S-BiT512-ePLAC512 | S2S-BiT-ePolarLAC-512 | S2S | 5056 | 9024 | 64 | 128 | 18066 | 128 |
| 25 | S2S-BiT512-eZEN512 | S2S-BiT-eZEN-512 | S2S | 5056 | 9024 | 64 | 128 | 17896 | 128 |

Cross-checks that hold for every row: `pk` = max(|pk_init|, |pk_resp|) over the two
credential types; `st_B` = `ss` = `K_LEN` = 2·|k_KEM|;
`st_A` = |p̃k|+|s̃k| (K2S), = 64+|c_j|+|k_j| (S2K, K2K), = 64 (S2S);
`total msg` equals Tables 6/7/8's `BW_I + BW_R` for all 25 instances (e.g. 530+2784 =
3314, 2340+2560 = 4900, 8811+9255 = 18066, and the three K2K-512 rows 4676+4608 = 9284,
5492+5428 = 10920, 4506+4096 = 8602).

## Pseudocode — one skeleton parameterised by the framework

All four frameworks share the interface `(KG, Init, Der_resp, Der_init)` and exactly two
messages. Write **wKEM** for the ephemeral IND-CPA KEM (used as a PKE:
`wGen / wEncaps / wDecaps`), **KEM** for the IND-CCA long-term KEM (`Gen / Encaps /
Decaps`), **2KEM** for the double-key KEM (`Gen1 / Gen2 / 2Encaps / 2Decaps`), **SIG**
for the signature (`SGen / Sign / Ver`), `G` for the seed-derivation hash and `H` for the
key-derivation hash.

```
KG(i):   i is an initiator  -> (sk_i, pk_i) ← KG_init   # Gen | Gen1 | SGen per framework
         i is a responder   -> (sk_j, pk_j) ← KG_resp   # Gen | SGen  per framework

Init(sk_i, pk_j)  ->  (M, st)                           # message 1, initiator
Der_resp(sk_j, pk_i, M)  ->  (M', K')                   # message 2, responder ACCEPTS here
Der_init(sk_i, pk_j, M', st)  ->  K  or  ⊥              # initiator ACCEPTS or aborts
```

| step | **K2S** (Fig. 1) init=K, resp=S | **S2K** (Fig. 2) init=S, resp=K | **K2K** (Fig. 3) init=K, resp=K | **S2S** (Fig. 4) init=S, resp=S |
|---|---|---|---|---|
| KG_init | Gen (KEM) | SGen (SIG) | Gen1 (2KEM) | SGen (SIG) |
| KG_resp | SGen (SIG) | Gen (KEM) | Gen (KEM) | SGen (SIG) |
| Init | `(s̃k,p̃k) ← wGen` | `r̃ ←$ R; (s̃k,p̃k) := wGen(G(sk_i,r̃));` `(c_j,k_j) = Encaps(pk_j);` `σ := Sign(sk_i, p̃k‖c_j)` | `r ←$ R; (s̃k,p̃k) := Gen2(G(r,sk_i));` `(c_j,k_j) = Encaps(pk_j)` | `r̃ ←$ R; (s̃k,p̃k) := wGen(G(sk_i,r̃));` `σ_i := Sign(sk_i, p̃k)` |
| M (msg 1) | `p̃k` | `p̃k ‖ c_j ‖ σ` | `p̃k ‖ c_j` | `p̃k ‖ σ_i` |
| st | `s̃k ‖ p̃k` | `r̃ ‖ c_j ‖ k_j` | `r ‖ k_j ‖ c_j` | `r̃` |
| Der_resp | `(c̃,k̃) = wEncaps(p̃k);` `(c_i,k_i) = Encaps(pk_i);` `σ := Sign(sk_j, p̃k‖c̃‖c_i)` | **`if Ver(pk_i, p̃k‖c_j, σ)=0: ⊥`**; `(c̃,k̃) = wEncaps(p̃k);` `k_j = Decaps(sk_j,c_j)` | `(c_i,k_i) = 2Encaps(pk_i, p̃k);` `k_j = Decaps(sk_j, c_j)` | **`if Ver(pk_i, p̃k, σ_i)=0: ⊥`**; `(c̃,k̃) = wEncaps(p̃k);` `σ_j := Sign(sk_j, p̃k‖c̃)` |
| M' (msg 2) | `c̃ ‖ c_i ‖ σ` | `c̃` | `c_i` | `c̃ ‖ σ_j` |
| K' | `H(pk_i,pk_j,p̃k,c̃,c_i,k_i,k̃)` | `H(pk_i,pk_j,p̃k,c̃,c_j,k_j,k̃)` | `H(pk_i,pk_j,p̃k,c_i,c_j,k_i,k_j)` | `H(pk_i,pk_j,p̃k,c̃,k̃)` |
| Der_init | **`if Ver(pk_j, p̃k‖c̃‖c_i, σ)=0: ⊥`**; `k̃=wDecaps(s̃k,c̃);` `k_i=Decaps(sk_i,c_i)` | `(s̃k,p̃k) := wGen(G(sk_i,r̃));` `k̃ = wDecaps(s̃k, c̃)` | `(s̃k,p̃k) ← Gen2(G(r,sk_i));` `k_i := 2Decaps(sk_i, s̃k, c_i)` | `(s̃k,p̃k) := wGen(G(sk_i,r̃));` **`if Ver(pk_j, p̃k‖c̃, σ_j)=0: ⊥`**; `k̃ = wDecaps(s̃k, c̃)` |
| K | same H as K' | same H as K' | same H as K' | same H as K' |

Authentication logic (§4.2): a signature authenticates the transcript components
produced by an S-credential holder; successful recovery of a secret encapsulated to a
long-term KEM public key authenticates the K-credential holder. Every framework keeps at
least one secret contribution hidden under each reveal pattern permitted by IND-(St)AA,
and binds it to the identities and the full transcript through `H`.

## Implementation vs specification

Checked: all 25 `src/<label>/KEX_AlgorithmInstance.c` and `cretake_params.h`,
`primitive_interfaces.h`, `twokem.c`/`twopke.c` (K2K), and the backend parameter headers
under `Common/primitives/{kem,sig}/`. The four framework bodies are separate but
near-identical files per instance, so the review is per *framework* (K2S, S2K, K2K, S2S)
with the per-instance differences being only the `cretake_params.h` typedefs and the
backend headers; that was verified by diffing the PolarLAC and ZEN variants of each
framework and by grepping every instance for the constructs discussed below.

Agreements:
- **Every size in the 25-row table above matches the specification**, including the
  per-party bandwidths of Tables 6–8, the PolarLAC/ZEN/BiT public-key and ciphertext
  sizes of Tables 2–4, the state layouts of Figures 1–4, and `passes = 2` everywhere.
  This is the cleanest size agreement in the batch.
- The message layouts, the H inputs (as *sets*), the choice of primitive per role, and
  the placement of each signature/verification match Figures 1–4 framework by framework.
- All protocol randomness is drawn from the seeded DRNG (`get_random_number(&drng_algorithm, …)`);
  there is no OS-entropy path in the protocol layer.
- Session state is zeroised after use (`secure_bzero(sta, …)` / `secure_bzero(stb, …)`).
- The ICCS metadata limitation for the heterogeneous frameworks is handled honestly:
  `kex_get_pk_len_bytes()` returns `max(PKI_LEN, PKR_LEN)` and the files export extra,
  clearly-commented non-ICCS accessors `kex_get_pk_len_bytes_initiator/responder` (and
  the sk equivalents).

Discrepancies:

1. **(a) CRITICAL — the responder's ephemeral secret has only 64 bits of entropy in 18
   of the 25 instances.** In every K2S, S2K and S2S instance the responder does:
   ```c
   unsigned char buf[SEED_BYTES];                       /* SEED_BYTES == 64 for all backends */
   get_random_number(&drng_algorithm, buf, SEED_BYTES * 8ULL);     /* 64 random bytes */
   pseudoXOF((MSG_LEN_BYTES + SEED_BYTES) * 8, buf, SEED_BYTES, buf2);   /* <-- BUG */
   memcpy(k_tilde, buf2, MSG_LEN_BYTES);
   memcpy(seed_enc, buf2 + MSG_LEN_BYTES, SEED_BYTES);
   PKE_Encrypt(ct_tilde, tpk, k_tilde, seed_enc);
   ```
   `pseudoXOF`'s third parameter is **`msg_len_bits`** (`api/auxfunc.c:482`), but
   `SEED_BYTES` is passed — a byte count where a bit count is required. The XOF therefore
   absorbs `(64+7)/8 = 8` bytes, i.e. **only `buf[0..7]` of the 64 random bytes**. Both
   the wKEM plaintext `k̃` and the encryption coins `seed_enc` are a deterministic
   function of 64 bits.
   * In **S2S** (6 instances) `K = H(pk_i, pk_j, p̃k, c̃, k̃)` — `k̃` is the *only* secret.
     A passive eavesdropper recovers the session key in ≈2^64 work: guess the 8 bytes,
     re-run the XOF, re-encrypt `PKE_Encrypt(p̃k, k̃, seed_enc)` and compare with the
     observed `c̃`; on a match compute `H`. This is a **complete break of session-key
     secrecy at 2^64** against claimed 128-, 256- and 512-bit levels.
   * In **K2S / S2K** (12 instances) `K` also mixes `k_i` (resp. `k_j`) from the long-term
     CCA KEM, so a purely passive attacker is still stopped by that KEM; but the ephemeral
     contribution — the one that is supposed to survive long-term-key exposure and give
     the weak forward secrecy claimed in §4.2 — is guessable at 2^64. Under the IND-AA
     freshness condition that permits long-term-key reveal, these instances offer 64 bits.
   The commented-out code immediately above the bug shows the original, correct version
   (`get_random_number(buf, MSG_LEN_BYTES*8)` and `get_random_number(seed_enc, SEED_BYTES*8)`
   drawn directly from the DRNG); the rewrite that introduced the XOF introduced the unit
   error. The KATs are unaffected — the values are still a deterministic function of the
   KAT seed — so no amount of KAT testing exposes this. The seven **K2K** instances do not
   contain this call and are not affected.
   Fix: pass `SEED_BYTES * 8`.
2. **(a) the same bits/bytes confusion in the initiator's seed derivation (benign for
   entropy, harmful for binding).** In K2K, S2K and S2S the initiator computes
   `pseudohash(SEED_BYTES * 8, buf, SEED_BYTES + SKI_LEN, seed_kg)` where
   `buf = r̃ (64 bytes) ‖ sk_i (SKI_LEN bytes)`. Again the third argument is a **byte**
   count used as a **bit** count, so only the first `(SEED_BYTES+SKI_LEN)/8` bytes are
   absorbed — at λ=128 that is 241 of 1928 bytes: the whole 64-byte seed plus only the
   first 177 bytes of `sk_i`. The ephemeral key therefore keeps full 512-bit seed entropy
   (no secrecy loss), but `G(sk_i, r̃)` binds only a prefix of the long-term secret,
   which is not what Figures 2–4 specify.
3. **(a) inverted check order in S2S `Der_init` — the CPA-only decryption runs before the
   signature is verified.** Figure 4's `Der_init` is: regenerate `(s̃k,p̃k)`; **line 3**
   `if Ver(pk_j, p̃k‖c̃, σ_j) = 0: return ⊥`; **line 5** `k̃ = wDecaps(s̃k, c̃)`. Both S2S
   instances do the opposite (`CreTAKE-S2S-BiT128-eZEN128`: `pke_dec(tsk, ct_tilde,
   k_tilde)` then `sig_verify(...)`; same in the ePolarLAC variant). The final result is
   the same because the function still returns −1 on a bad signature, but an unauthenticated
   ciphertext is now fed to a CPA-secure decryption before any authentication — the exact
   shape that enables reaction / decryption-failure attacks if any failure or timing signal
   escapes. K2S's `Der_init` gets this right (verify, then decrypt), which shows the
   ordering was understood elsewhere in the same codebase.
4. **(a) non-canonical H input ordering.** Figures 1–4 define
   `H(pk_i, pk_j, p̃k, …, k_i, k̃)`; `derive_session_key()` concatenates
   `p̃k ‖ pk_i ‖ pk_j ‖ c̃ ‖ c_i ‖ k̃ ‖ k_i` — the ephemeral public key is moved to the
   front and the two secrets are swapped. The field set and all lengths are fixed, so the
   encoding is still unambiguous and both parties agree; but it is not the spec's order,
   and there is no domain-separation label in front of the hash input.
5. **(b) naming mismatch.** Table 1's instance names (`K2S-PolarLAC-BiT-128`, …) do not
   match the shipped `ALGORITHM_INSTANCE` strings (`CreTAKE-K2S-PLAC128-BiT128`, …), and
   the 512* instance is `CreTAKE-K2K-PLAC512Star`. Harmless, but the KAT file names and
   the specification's tables cannot be matched up mechanically.
6. **(informational) unvalidated caller-supplied lengths.** In K2S's `kex_derive_ss_a`
   the signature length is computed as `mb_len_bytes - C_TILDE_LEN - C_I_LEN` with no
   lower-bound check (an under-length message underflows the unsigned subtraction), and
   `kex_generate_pass2_msg_b` `calloc`s a `tpk` buffer of `m1_len_bytes` but then reads
   `TPK_LEN` bytes from it in `derive_session_key`. Most other length arguments are cast
   to `(void)`. Not reachable from the ICCS driver, which always passes the declared
   lengths.
7. **(informational) K2K ignores backend return codes in `Der_resp`.** `twokem_enc` and
   `kem_dec` results are discarded in `kex_generate_pass2_msg_b`; with implicitly
   rejecting KEMs that is the intended behaviour (the responder proceeds with a
   pseudorandom `k_j` and the key simply fails to match), but it is not what Figure 3's
   `k_j := Decaps(sk_j, c_j)` implies for a failing decapsulation.
8. **(informational) public keys are recovered from secret keys by offset.** Both
   `memcpy(pkb, skb, PKR_LEN)` (BiT) and `memcpy(pkI, ska + TSK_LEN, PKI_LEN)` (PolarLAC/ZEN)
   assume a particular internal secret-key layout of the backend rather than using an
   accessor. Correct for the shipped backends; silently wrong for any other.

Not verified: the PolarLAC, ZEN and BiT primitive cores were treated as black boxes, as
the specification itself does (§3.2 "we only give their framework here and omit the
internal details"); the two compact double-key constructions of Figures 8 and 9 used by
K2K-PolarLAC-512 and 512* (`twokem.c` + `twopke.c`) were not verified against those
figures; the DFR bounds 2^-175 / 2^-328 claimed for those two instances were not
recomputed; the IND-(St)AA proofs of §5.1 were not reviewed. The line-level reading is of
the four λ=128 framework files plus targeted greps over all 25 instances for the
constructs in findings 1–4, which confirmed that finding 1 is present in all 18
non-K2K instances and absent from all 7 K2K instances.
