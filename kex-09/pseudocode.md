# kex-09 TriQ-KEX — algorithm summary

TriQ-KEX is the FSXY generic transform (Fujioka–Suzuki–Xagawa–Yoneyama, PKC 2012)
instantiated with the code-based TriQ-KEM: a **two-message** authenticated key
exchange whose session key is the XOR of three keyed-PRF outputs over the
transcript, derived from two *static* IND-CCA2 TriQ-KEM encapsulations (one per
direction) and one *ephemeral* IND-CPA `TriQ-wKEM` encapsulation. Claimed goal is
CK+ security in the standard model. No new hardness assumption is introduced: the
code-based part is entirely the companion TriQ-KEM (= candidate **kem-37**).

Specification: `kex-09-spec.pdf`, 15 pages, English (not Chinese). Protocol in
§III (Figure 1 + §III-B…§III-G); parameters/sizes in §IV (Tables 1–3).

## Number of passes

The spec defines **2 passes** everywhere ("two-message", §I, §III-A Fig. 1, §VI).
OBSERVED reports `passes=2` for all four instances — **agrees**.
`kex_generate_pass3_msg_a` exists only as a stub returning `-50`
(`KEX_AlgorithmInstance.c:423-433`), which is correct for a 2-pass protocol.

## Code-based machinery (from the companion TriQ-KEM spec; see `kem-37/pseudocode.md`)

The KEX spec **does not restate** any of this — §III-B/§IV explicitly defer to the
companion TriQ-KEM document, so everything below is cross-referenced from kem-37,
not from `kex-09-spec.pdf`.

* Family: HQC-style **2-quasi-cyclic** codes over `R = F2[X]/(X^n − 1)`, `n` a
  primitive prime. Block structure: `pk = (seed(h), s = x + h·y)`, one block of
  `n` bits each; `ct = (u = r1 + h·r2, v = Encode(m) + Truncate(s·r2 + e), salt)`,
  with `u` of `n` bits, `v` truncated to `n1·n2` bits, `salt` 32 bytes.
* Weights: `wx = wy = wr` (67/132/196/260) for `x, y, r1, r2`; `we`
  (106/234/350/475) for `e`. Unlike HQC, `wr < we` (unbalanced), and `r1, r2` are
  additionally drawn under a **bounded-density rejection rule**: no window of
  `L_bd` consecutive ring positions may contain more than `γ` support points,
  retried at most `N_max = 256` times (`vector.c:244-256`).
* Decoder: **concatenated Reed–Solomon / duplicated Reed–Muller**, *not*
  bit-flipping. Inner `[n2, 8]` = RM(1,7) `[128,8,64]` repeated `n2/128` times,
  decoded by fast Hadamard transform (`reed_muller.c`); outer `[n1, k/8, ·]_256`
  RS with correction capability `δ = PARAM_DELTA` = 13/16/30/36, decoded by
  Berlekamp–Massey + FFT root finding (`reed_solomon.c`, `fft.c`). Composition in
  `src/common/code.c:23-48`.
* DFR: kex-09 spec Table 4 gives the **natural DFR** ≤ 2^-121.90 / 2^-173.35 /
  2^-209.57 / 2^-230.00 (this is the value used for KEX correctness accounting,
  §III-H) and a post-rejection **CDFR** ≤ 2^-34.32 / 2^-85.63 / 2^-124.93 /
  2^-146.56. Session-level failure is bounded by 2·DFR(static) + 1·DFR(ephemeral).
* Shared secret from the decoded word: `m' = C.Decode(v − Truncate(u·y))`, then
  `(K', θ') = G_KEM(H_KEM(ek) ‖ m' ‖ salt)`; the KEM shared secret is `K'` (the
  first `κ/8` bytes of the `G` output), i.e. the decoded word is *hashed*, never
  used directly. The KEX session key is then `SK = ⊕_{i∈{A,B,T}} G_FSXY,K'_i(ST)`.

## Parameters

| parameter | 128 | 256 | 384 | 512 | meaning |
|---|---|---|---|---|---|
| κ | 128 | 256 | 384 | 512 | classical security, bits |
| n | 16301 | 50363 | 97651 | 157627 | quasi-cyclic ring length (spec Tab. 1) |
| n1 | 42 | 64 | 108 | 136 | outer RS length over F256 |
| n2 | 384 | 768 | 896 | 1152 | inner duplicated-RM length |
| k | 128 | 256 | 384 | 512 | PKE message length, bits |
| wx = wy = wr | 67 | 132 | 196 | 260 | fixed weights |
| we | 106 | 234 | 350 | 475 | error weight |
| \|seed\| | 16 | 32 | 48 | 64 | bytes (RS_G = {0,1}^κ) |
| \|salt\| | 32 | 32 | 32 | 32 | bytes, all instances |
| \|U_A\| = \|U_B\| | 4 | 4 | 4 | 4 | bytes (`"ID_A"` / `"ID_B"`, §VII-A) |
| claimed security | 128 | 256 | 384 | 512 | bits; min classical ISD 146.7/277.0/404.1/532.1 |

Sizes (bytes), specification Tables 2–3 vs the built reference library (OBSERVED):

| instance | pk spec | pk impl | sk spec | sk impl | msgs spec | msgs impl | ss spec | ss impl | match |
|---|---|---|---|---|---|---|---|---|---|
| TriQ-KEX-128 | 2054 | 2054 | 2134 | 2134 | 6148+8180=14328 | 14328 | 16 | 16 | yes |
| TriQ-KEX-256 | 6328 | 6328 | 6488 | 6488 | 18808+24952=43760 | 43760 | 32 | 32 | yes |
| TriQ-KEX-384 | 12255 | 12255 | 12495 | 12495 | 36598+48678=85276 | 85276 | 48 | 48 | yes |
| TriQ-KEX-512 | 19768 | 19768 | 20088 | 20088 | 59096+78648=137744 | 137744 | 64 | 64 | yes |

**All spec sizes match the built library exactly**, including the unusually large
message totals (14 KB → 137 KB). They are large because `M1` carries a full KEM
ciphertext *plus* a full ephemeral public key and `M2` carries *two* KEM
ciphertexts — inherent to FSXY over an HQC-style KEM, not an encoding error:
`|M1| = 8 + |c| + |ek|`, `|M2| = 8 + 2|c|`, with `|ek|/|c|` from Table 2
(2054/4086, 6328/12472, 12255/24335, 19768/39320). All eight arithmetic checks
reproduce Table 3.

State sizes are **not tabulated in the spec**, but follow from §III-E/§III-F:
`sta = |CT_A|+|ek_T|+|dk_T|+|K_A|` = 8258/25256/49037/79112 and
`stb = 2|CT|+3|K|` = 8220/25040/48814/78832 — both match OBSERVED exactly.

## Pseudocode (spec §III; symbols as in Figure 1)

### Init_A / Init_B  (§III-D, "Static Keys for a Party")
```
Init_i():                                   # i in {A, B}; identical for both
  (ek_i^KEM, dk_i^KEM) <- TriQ.KEM.KeyGen()          # §III-B
        seed_KEM <-$ {0,1}^k ; (seed_PKE, sigma) <- XOF(seed_KEM)
        (ek^PKE, dk^PKE) <- TriQ.PKE.KeyGen(seed_PKE)
        ek^KEM = ek^PKE ;  dk^KEM = (ek^KEM, dk^PKE, sigma, seed_KEM)
  sigma_i  <-$ FS = {0,1}^kappa
  sigma_i' <-$ {0,1}^kappa
  pk_i^KEX := ek_i^KEM
  sk_i^KEX := (dk_i^KEM, sigma_i, sigma_i')
  state_i  := empty                                   # no state produced at Init
```

### pass1 — GeneratePass1MsgA (§III-E)
```
Pass1_A(sk_A^KEX, pk_B^KEX):
  r_A <-$ {0,1}^kappa ; r_A' <-$ FS ; r_{T,A} <-$ RS_G = {0,1}^kappa
  rho_A <- F_{sigma_A}(r_A)  XOR  F'_{r_A'}(sigma_A')            # two PRFs
  (CT_A, K_A) <- TriQ.KEM.Encaps(ek_B^KEM ; rho_A)
  (ek_T^KEM, dk_T^KEM) <- TriQ.wKEM.KeyGen(r_{T,A})              # = KEM.KeyGen
  MESSAGE M1 := ( U_A , U_B , CT_A , ek_T^KEM )
  STATE  sta := ( CT_A , ek_T^KEM , dk_T^KEM , K_A )
```

### pass2 — GeneratePass2MsgB (§III-F)
```
Pass2_B(sk_B^KEX, pk_A^KEX, M1 = (U_A, U_B, CT_A, ek_T^KEM)):
  K_A <- TriQ.KEM.Decaps(dk_B^KEM, CT_A)                         # FO, implicit rej.
  r_B <-$ {0,1}^kappa ; r_B' <-$ FS ; r_{T,B} <-$ RS_E
  rho_B <- F_{sigma_B}(r_B) XOR F'_{r_B'}(sigma_B')
  (CT_B, K_B) <- TriQ.KEM.Encaps(ek_A^KEM ; rho_B)
  (CT_T, K_T) <- TriQ.wKEM.Encaps(ek_T^KEM ; r_{T,B})            # = KEM.Encaps
  MESSAGE M2 := ( U_A , U_B , CT_B , CT_T )
  STATE  stb := ( CT_B , CT_T , K_A , K_B , K_T )
```
(no pass 3: the protocol ends here)

### DeriveSS_A (§III-G)
```
Derive_A(sk_A^KEX, pk_B^KEX, M2, sta):
  K_B <- TriQ.KEM.Decaps(dk_A^KEM, CT_B)
  K_T <- TriQ.wKEM.Decaps_w(dk_T^KEM, CT_T)                      # §III-C
        m' <- PKE.Decrypt(dk^PKE, c_PKE); (K',theta') <- G_KEM(H(ek)||m'||salt)
        return K'          # NO re-encryption, NO comparison, NO implicit reject
  return FinalKey(...)
```

### DeriveSS_B (§III-G)
```
Derive_B(sk_B^KEX, pk_A^KEX, M1, stb):
  K_A, K_B, K_T already in stb; return FinalKey(...)

FinalKey():
  ST = ( U_A , U_B , ek_A^KEM , ek_B^KEM , CT_A , ek_T^KEM , CT_B , CT_T )
  K_A' = KDF(s, K_A) ;  K_B' = KDF(s, K_B) ;  K_T' = KDF(s, K_T)   # s = public salt
  SK   = G_FSXY,K_A'(ST) XOR G_FSXY,K_B'(ST) XOR G_FSXY,K_T'(ST)    # kappa bits
  erase local state
```

The spec fixes no concrete instantiation of `F, F', G_FSXY, KDF` beyond "domain-
separated calls to the API_PKC auxiliary `pseudoXOF`" (§III-H, §VII-A); the exact
labels and the value of the salt `s` are **implementation-defined**, so that part
of the specification is incomplete and I did not attempt to reconstruct it.

## Implementation vs specification

Checked (via `kex-09/Makefile` → `src/<label>` symlinks):
`KEX_AlgorithmInstance.c` (all 4 instances), `src/common/{kem.c, code.c}`,
`src/ref/{triq_pke.c, vector.c, parsing.c}`, `src/ref/triq-N/parameters.h` and
`src/common/triq-N/api.h` for all four levels. `kex-09/review-o48.md` does not
exist; `kex-09/security_findings.md` records KAT PASS=4 and no established claim
violation, with all protocol-level attacks `not_tested` — nothing there
contradicts the below. kem-37 is the same code base at KEM level.

**Agreements.**
* Parameter spot-check (6 constants × 4 instances, all from `parameters.h`):
  `PARAM_N` = 16301/50363/97651/157627, `PARAM_N1` = 42/64/108/136, `PARAM_N2` =
  384/768/896/1152, `PARAM_OMEGA` (= wx,wy) and `PARAM_OMEGA_R` (= wr) =
  67/132/196/260, `PARAM_OMEGA_E` (= we) = 106/234/350/475, `SEED_BYTES` =
  16/32/48/64, `SALT_BYTES` = 32. **All 24 agree with spec Table 1** (`k` appears
  as `PARAM_K` in bytes: 16/32/48/64 = k/8, consistent).
* `api.h` `CRYPTO_{PUBLICKEY,SECRETKEY,CIPHERTEXT}BYTES` reproduce spec Table 2
  exactly at all four levels, and `TRIQ_KEX_SK_BYTES = dk + 2·(κ/8)`,
  `M1/M2/STA/STB` (`KEX_AlgorithmInstance.c:30-38`) reproduce Table 3 and the
  §III-E/F state composition exactly.
* Transcript order in `triq_fsxy_final_key` (`:271-279`) is exactly
  `ID_A, ID_B, pk_A, pk_B, CT_A, ek_T, CT_B, CT_T` — matches spec ST.
* `Decaps_w` (`:214-240`) correctly omits re-encryption/comparison/implicit
  rejection, as §III-C prescribes, while the static path uses the full FO
  `crypto_kem_dec` with constant-time implicit rejection (`kem.c:168-175`,
  `vect_compare` returns 0/1 so the `result -= 1` mask is sound).
* Randomness hygiene is clean: every random byte comes from the official
  `get_random_number(&drng_algorithm, …)` (`:82-98`), which also seeds the
  internal `prng_init`. A grep for `rand()`, `srand`, `time(`, `getrandom`,
  `/dev/urandom`, `randombytes` over the built sources returns **nothing**.
* `kex_generate_pass2_msg_b` returns `1` (`:420`) — correct per
  `KEX_AlgorithmInstance.h:109` ("if key exchange is finished, return 1").

**Discrepancies / observations.**
1. **(a) Decoder failure return is unreachable — no DFR detection anywhere.**
   `triq_pke_decrypt` (`src/ref/triq_pke.c:135-159`) unconditionally `return 0`;
   it never reports a decoding failure. Consequently the check
   `if (result != 0) return -1;` in `triq_wkem_dec`
   (`KEX_AlgorithmInstance.c:228-230`) is dead code, and `result` in
   `kem.c:156` contributes nothing to the implicit-rejection mask. Decoding
   failures surface only as a silently wrong `K`, i.e. as an SK mismatch. Benign
   given the 2^-121…2^-230 natural DFR, but the code's own error path is a no-op.
2. **(a) Bounded-density rejection has no failure path.**
   `vect_sample_fixed_weight_bd` (`src/ref/vector.c:244-256`) loops at most
   `N_max = 256` times and, if every candidate is rejected, **writes the last
   (rejected) support anyway** with no error. The spec's
   bounded-density-conditioned 3-CW-QCSD assumption and CDFR figures presume the
   condition holds. Unreachable in practice (≈2^-1175 per kem-37), so a spec
   ambiguity about the fallback rather than an exploitable bug.
3. **(a/b) Non-constant-time rejection loop over secret randomness.** The number
   of iterations of that same loop depends on the sampled `r1, r2` (derived from
   the secret `θ`), so the running time of every encapsulation leaks the density
   of the secret error/randomness support. The inner
   `vect_check_bounded_density` (`vector.c:213-228`) also computes the cyclic
   distance with a data-dependent ternary on secret support values; only the
   max-tracking is branch-free. Same finding as kem-37, inherited here.
4. **(b) Identities are hard-wired constants, not real identities.**
   `triq_kex_id_a/b = "ID_A"/"ID_B"` (`KEX_AlgorithmInstance.c:62-63`) are fixed
   4-byte literals written into every message and into every transcript, and
   `triq_kex_has_id_pair` only checks that these literals are present. The spec
   sanctions this for KAT purposes (§VII-A) but it means `U_A, U_B` contribute
   **zero entropy and zero identity binding** to `ST`; the CK+ claim's
   identity-misbinding/UKS resistance rests entirely on `ek_A^KEM, ek_B^KEM`
   being in `ST`. Worth stating because the spec's §III-G writes `ST` as if
   `U_A, U_B` were genuine party identifiers.
5. **(b) The KDF salt `s` is a hard-wired per-level literal** in the source
   (`KEX_AlgorithmInstance.c:249-252`, a distinct `SEED_BYTES`-long constant for
   each of 128/256/384/512 — correctly full length in each, I checked all four).
   The spec says `s` is "included in the common public parameters" but never
   gives its value, so the specification is incomplete here and the constant is
   unverifiable against it.
6. **(c) Misaligned `uint8_t*` → `uint64_t*` casts** on the plaintext/coins:
   `KEX_AlgorithmInstance.c:202` `(const uint64_t *)coins` and `:228`
   `(uint64_t *)m_prime`, mirroring `kem.c:107,156,164`. Technically UB /
   unaligned access on strict-alignment targets; works on x86-64. Portability,
   not a cryptographic deviation.
7. **(c) Non-canonical encodings accepted on parse.** `triq_c_kem_from_string`
   (`src/ref/parsing.c:63-67`) and `triq_ek_pke_from_string` (`:41`) `memcpy` the
   raw `⌈n/8⌉` bytes without masking the unused high bits (3 spare bits at level
   128). For the static KEM the re-encryption comparison rejects such
   ciphertexts; for `Decaps_w` there is no comparison, but `ST` binds `CT_T`
   byte-for-byte, so a mutated `CT_T` yields an SK mismatch rather than an
   agreement. No attack found, but there is no input validation at all on
   received `CT_A`, `CT_B`, `CT_T` or `ek_T` beyond the length checks.

**Not verified.** The DFR/CDFR and ISD figures of Table 4 (no estimator rerun);
the FSXY reduction itself; whether the `pseudoXOF` domain separation in
`triq_fsxy_prf`/`triq_xof_label` gives genuinely independent `F`, `F'`, `G`, `KDF`
(the spec pins no instantiation to compare against); replay / role-swap /
reflection behaviour, which the fixed `ID_A`/`ID_B` labels make a natural target.
