# kem-32 QCTM (Quasi-Cyclic Twisted McEliece KEM) — algorithm summary

Code-based KEM with a **Niederreiter** syndrome ciphertext over a binary
**twisted Goppa code** `Γ(L, g, η)` (the `η α_j^t / g(α_j)` twist is what is
claimed to break the BIG QUAKE structural folding attack of [19]). The public
parity-check matrix is a *hybrid* systematic matrix
`H = [ I_{u−r0} T1 ; 0 T2 ]` where only `T1` is ℓ-block-circulant and compressed;
`T2` is `r0` ordinary "tail" rows. The KEM is **not** a re-encryption FO: the
session key is `H(b, e, C)` directly, with `b = 0` and `e = s` (a stored random
vector) on decoding failure — i.e. decode-and-hash with implicit rejection.

Specification: `kem-32-spec.pdf` (25 pages), §4 (Algorithms 1–7, one-way
function), §5 (Algorithms 8–11, KEM), §6 (security), §8.2 (sizes).

**Not executed.** This candidate is extremely slow (QCTM128 keygen ≈ 4 min for
10 records, QCTM512 ≈ 45 min), so the review below is source-reading plus the
already-recorded OBSERVED sizes and the KAT PASS result from RESULTS.md.

## Parameters

`q = 2^m`, ℓ an odd prime with ℓ | q−1, ℓ | n, `t = ℓ t0` (t0 odd),
`k = n − m(t−1) − 1`, error weight `w = (t−1)/2`,
`u = m(t−1)+1`, `r0 = u mod ℓ`. `F_q = F_2[z]/f(z)`, `F_{q^{t0}} = F_q[y]/F(y)`.

| parameter | QCTM128 | QCTM256 | QCTM512 | meaning |
|---|---|---|---|---|
| m | 18 | 18 | 18 | `q = 2^18` |
| n | 10070 | 19000 | 38000 | code length |
| ℓ | 19 | 19 | 19 | quasi-cyclic block size |
| t0 | 15 | 27 | 53 | odd |
| t = ℓ t0 | 285 | 513 | 1007 | Goppa degree |
| k | 4957 | 9783 | 19891 | dimension |
| w = (t−1)/2 | 142 | 256 | 503 | error weight |
| u = m(t−1)+1 | 5113 | 9217 | 18109 | syndrome length (bits) |
| r0 = u mod ℓ | 2 | 2 | 2 | tail rows |
| f(z) | z^18+z^3+1 | z^18+z^7+1 | z^18+z^3+1 | F_q modulus |
| F(y) | y^15+y^7+z^7 | y^27+z | y^53+y^6+z | F_{q^{t0}} modulus |
| λ (hash/key length, bits) | 256 | 256 | 512 | §3.1 |
| σ1 / σ2 | 18 / 36 | 18 / 36 | 18 / 36 | `≥ m` / `≥ 2m` |
| best ISD attack (final) | 150.87 (MayOzerov) | 272.90 (MayOzerov) | 530.30 (BJMM) | bits, spec §6.2 |
| claimed DFR | "no decapsulation failure" (§6.4) | same | same | see below |
| claimed security | 128 | 256 | 512 | bits |

Sizes (bytes) — the spec states them **twice, inconsistently**:

| instance | pk §3.2 | pk §8.2 | pk impl | sk §3.3 formula | sk §8.2 | sk impl | ct spec | ct impl | ss | match |
|---|---|---|---|---|---|---|---|---|---|---|
| QCTM128 | 167,919 | 167,987 | 167,987 | 23,299 | 192,545 | 192,545 | 640 | 640 | 32 | §8.2 yes, §3.2/§3.3 **no** |
| QCTM256 | 595,541 | 595,662 | 595,662 | 43,905 | 641,942 | 641,942 | 1,153 | 1,153 | 32 | §8.2 yes, §3.2/§3.3 **no** |
| QCTM512 | 2,374,489 | 2,374,727 | 2,374,727 | 87,766 | 2,467,243 | 2,467,243 | 2,264 | 2,264 | 64 | §8.2 yes, §3.2/§3.3 **no** |

The shipped `Test_Vectors/KAT_KEM_QCTM128.txt` carries `PK_Len = 167987`,
`SK_Len = 192545`, `CT_Len = 640`, agreeing with §8.2 and the library.

## Pseudocode

### Key generation (spec Algorithms 8–9, plus 1–4)
```
KeyGen():  delta <- $ {0,1}^lambda ;  return SeededKeyGen(delta)

SeededKeyGen(delta):
 1  E <- G(delta)                       # n + sigma2*(q-1) + sigma1*(t0+1) + lambda bits
 2  s      <- first n bits of E ;  delta' <- last lambda bits of E
 3  rho    <- next sigma1*(t0+1) bits
 4  (eta,g) <- GoppaPolynomial(rho) ;  if _|_ then delta <- delta'; restart
 8  rho_L  <- next sigma2*(q-1) bits
 9  L      <- DefinedSet(rho_L)        ; if _|_ then delta <- delta'; restart
14  (psi(T1), T2, Gamma') <- MatGen(Gamma = (g,L))  ; if _|_ then delta <- delta'; restart
18  pk <- (psi(T1), T2) ;  sk <- (delta, Gamma', s)

GoppaPolynomial(d):                                     # Algorithm 1
 2-4 beta_j <- first m bits of block j  (j < t0) ;  eta <- block t0
 5   if eta = 0 return _|_
 7   beta <- beta_0 + beta_1 y + ... + beta_{t0-1} y^{t0-1}  in F_q[y]/F(y)
 8   M <- minimal polynomial of beta over F_q
 9   if deg M != t0 return _|_
11   if v_l(ord(beta)) != v_l(q^{t0}-1) return _|_        # l-adic valuations must match
14   g(x) <- M( (x - 1/eta)^l )                           # monic irreducible, degree t = l*t0

MatGen(Gamma):                                            # Algorithm 4
     build the t x n twisted parity check over F_q, expand to the u x n binary Hhat_T,
     systematise: the first u-r0 rows must form [ I | T1 ] with T1 l-block-circulant,
     the remaining r0 rows are kept verbatim as T2;  return _|_ if that fails
```

### Encapsulation (spec Algorithms 5, 6, 10)
```
FixedWeight():                                            # Algorithm 5
 1  rho <- w * 2^j  where j is chosen so that q/2^j <= n < q/2^{j-1}
 2  repeat
 3     draw sigma1*rho uniform bits b
 5     d_j <- sum_{i<m} b[sigma1*j + i] * 2^i          for j < rho
 6     D <- ordered list of pairwise DISTINCT d_j lying in {0,..,n-1}
 7  until |D| >= w
 9  e <- indicator vector of the first w entries of D

Encaps(pk):
 1  e <- FixedWeight()
 2  C <- H e^T  in F_2^u                                  # Algorithm 6, Niederreiter
 3  K <- H(1, e, C)
```

### Decapsulation (spec Algorithms 7, 11) — the decoding step
```
Decode(C, Gamma' = (g, L', eta), pk):                     # Algorithm 7
 1  rebuild Hhat_T from Gamma'
 2  rebuild H from (psi(T1), T2)
 3  find Q^{-1} with Hhat_T = Q^{-1} H
 4  Hhat_T e^T = Q^{-1} C                                 # map the u-bit syndrome back
 5-7 lift to F_q coordinates -> the full t-coefficient syndrome  S = H^T e^T
 8  e <- TwistedGoppaDecode(S, g, L', eta)                # [36,37], NOT Patterson
 9  if e does not exist or wt(e) != w: return _|_

Decaps(C, sk = (delta, Gamma', s)):
 1  b <- 1
 2  e <- Decode(C, Gamma')
 3  if e = _|_ then e <- s ; b <- 0
 6  K <- H(b, e, C)
```
`TwistedGoppaDecode` as implemented: syndrome polynomial → extended-Euclidean
key-equation solve stopped at degree ≤ w (`twisted_euclidean`), giving
(σ = locator, τ = evaluator); Chien search over L for roots of σ; for each root
the Forney value `τ(α_j)/σ'(α_j)` must be 1 (binary code), otherwise reject;
finally `wt(e) == w` is required.

**Claimed DFR.** Spec §6.4 claims "QCTM has no decapsulation failure". That is a
statement about the *interface* only: the `b = 0, e = s` branch makes decaps
total. The spec gives **no probability bound** for `Decode` returning ⊥ on an
honestly generated ciphertext. The implicit argument is the §4.7 Remark —
"Repeated tests show that the minimum distance of the twisted Goppa code used in
this scheme is t+1. This decoding algorithm is optimal" — so `w = (t−1)/2 ≤ ⌊t/2⌋`
errors are always correctable. That minimum-distance claim is asserted from
experiment, not proved, and it is the whole correctness argument.

## Implementation vs specification

Built tree: `Implementations/Reference_Implementation/QCTM{128,256,512}`,
sources `keccak.c kem.c m2e.c permutation.c gf.c poly.c goppa.c seeded_keygen.c
qctm<n>_kem_api.c decode.c roots.c rng.c KEM_AlgorithmInstance.c
.api-pkc-kat/drng.c`, `-DAPI_PKC_KAT_DRNG_BRIDGE -lcrypto -fcommon`. Not linked:
the many `*_kat.c`, `*_speed.c`, `*_experiment.c`, `audit_*`, `verify_*`,
`hybrid_roundtrip.c`, `recompute_*` standalone tools also shipped in the same
directory.

### How the OpenSSL AES-CTR DRBG is seeded from the official DRNG

The scheme's core calls `randombytes()` from `rng.c` — the stock NIST-PQC
AES-256-CTR-DRBG (`DRBG_ctx.Key`/`.V`, `AES256_CTR_DRBG_Update`), with
`AES256_ECB` implemented through OpenSSL `EVP_EncryptUpdate`, which is the only
reason `-lcrypto` is needed. The NGCC adapter bridges it to the official DRNG:

```
init_local_rng_from_api_pkc_drng():                 # KEM_AlgorithmInstance.c:19-30
    unsigned char entropy_input[48];
    get_random_number(&drng_algorithm, entropy_input, 48*8);   # official DRNG
    randombytes_init(entropy_input, NULL, 256);                # seeds DRBG_ctx
    api_pkc_rng_ready = 1;

kem_keygen():  init_local_rng_from_api_pkc_drng()   # UNCONDITIONAL re-seed, every call
kem_enc():     ensure_local_rng_from_api_pkc_drng() # seeds ONLY if never seeded
kem_dec():     (no randomness needed)
```
`randombytes_init` zeroes Key and V and runs one `AES256_CTR_DRBG_Update` over
the 48-byte seed material (no personalization string is passed), exactly the
NIST KAT construction. Consequences:

- All scheme randomness is ultimately derived from `drng_algorithm`, so the
  NGCC "single seeded DRNG" requirement is met *indirectly*.
- Only **48 bytes per keygen** are drawn from the official DRNG. The key seed
  δ, the support ordering, the Goppa polynomial coins and every encapsulation
  error vector come from the AES-CTR-DRBG chain, not from `get_random_number`.
- Because `kem_enc` uses `ensure_` rather than `init_`, a caller that
  encapsulates repeatedly without ever calling `kem_keygen` runs off a DRBG
  seeded once, at the first `kem_enc`, and never reseeded. Within a KAT record
  this is exactly what makes the vectors reproducible; in an application it means
  the encapsulation stream is *not* re-derived from the platform DRNG per call.
  The harness observed exactly this: `review-o48.md` records
  `kem-enc-drng-consumption (QCTM128): encapsulation did not advance the harness
  DRNG` — i.e. after the first keygen, encapsulation consumes zero bytes of
  `drng_algorithm`.
- Spec §3.1 says the PRG `G` "may be instantiated by `get_random_number`
  provided by the algorithm solicitation platform". The implementation does not:
  `G` is the AES-CTR-DRBG.

Agreements:

- `sizes.h` derives every length from `(m, n, ℓ, t)` and carries
  `_Static_assert`s pinning QCTM128 to `PK = 167987`, `Γ' = 23299`, `s = 1259`,
  `API sk = 192545`, `CT = 640`, `SS = 32`, right-width 4959, `psi(T1)` rows 269,
  `T2` rows 2 — all of which match spec §3.3's *formulas*, §8.2's table and the
  library. Re-deriving them by hand from §3.2's parameters reproduces exactly
  these numbers.
- The session key is `SHAKE256(b ‖ e ‖ C)` truncated to `CRYPTO_BYTES`
  (`kem.c:388-410`), i.e. spec's `K = H(b, e, C)` with the `b` byte first, and
  `crypto_kem_dec` (`kem.c:657-684`) sets `b = 0` and `e = s` from
  `sk + SECRETKEY_S_OFFSET` exactly on decode failure. The branch sense is
  correct (not inverted).
- The decoder (`decode.c:goppa_decode`) is a genuine key-equation decoder:
  extended Euclid stopped at degree ≤ w, Chien search, and a Forney check
  `τ(α)/σ'(α) == 1` plus `wt(e) == w`. Both the "too many roots" and
  "zero derivative" paths fail closed. No `min`/`max` inversion found.
- `FixedWeight`'s `ρ` schedule (`sizes.h:41-42`, `PARAM_RHO_MULT`) implements
  spec Algorithm 5 line 1's halving rule, and `PARAM_SIGMA1 = m`,
  `PARAM_SIGMA2 = 2m` match the `σ1 ≥ m`, `σ2 ≥ 2m` requirement.

Discrepancies:

- **(b) The spec contradicts itself on the public-key size, and §3.2 is wrong.**
  §3.2.1/§3.2.2/§3.2.3 quote 167,919 / 595,541 / 2,374,489 bytes. Evaluating
  §3.3's own formula `pkbytes = ⌈((u−r0)/ℓ + r0)(n − u + r0)/8⌉` with the §3.2
  parameters gives 167,987 / 595,662 / 2,374,727, which is what §8.2, the library
  and the shipped KATs all say. §3.2's figures are low by 68 / 121 / 238 bytes;
  Table 1.1-style quotes elsewhere inherit them.
- **(a/b) The §3.3 private-key formula describes only part of the secret key.**
  §3.3 gives `skbytes = ⌈(n+t)m/8⌉` = 23,299 / 43,905 / 87,766, i.e. the Goppa
  data `Γ'` alone. The implementation's secret key is
  `Γ' ‖ pk ‖ s` (`sizes.h`: `SECRETKEY_PK_OFFSET = SECRETKEY_GAMMA_BYTES`,
  `SECRETKEY_S_OFFSET = … + PUBLICKEY_BYTES`), = 192,545 / 641,942 / 2,467,243
  as §8.2 correctly reports — 8× larger at QCTM128. The stored public key is
  genuinely needed (Algorithm 7 line 2 takes `(ψ(T1), T2)` as an input to Decode),
  so §3.3 is simply incomplete, but a reader sizing a key store from §3.3 would
  be wrong by a factor of eight.
- **(a) The seed δ that spec Algorithm 9 line 18 puts in `sk` is not stored.**
  `sk = (δ, Γ', s)` per the spec; the serialized key is `Γ' ‖ pk ‖ s` with no δ.
  (No algorithm uses δ after keygen, so nothing breaks — but the format differs
  from the specification and from what §3.3's formula would suggest.)
- **(a) `r0 = 2` is hard-wired.** `scheme_public_t_aligned()`
  (`kem.c:32-39`, identical in all three instances) returns false unless
  `SYSTEMATIC_TAIL_ROWS == 2`, and encapsulation, decapsulation and key
  generation all bail out with `FAIL` if it does (`kem.c:414,461,563`). The spec
  defines `r0 = (m(t−1)+1) mod ℓ` generically and §7.2 lists "r0 = u mod ℓ, and
  T2 contains r0 rows" as a *validated* condition, not a fixed constant. The
  three submitted parameter sets all happen to give r0 = 2, so this is currently
  invisible, but the implementation supports only that one value.
- **(a) A debug trace in the shipped reference code retains the secret error
  vector and leaks the decoder's failure reason.** `kem.c:18-21` defines
  `trace_dec_enabled()` = `getenv("LOCALLY_QUASI_CYCLIC_TWISTED_MCELIECE_TRACE_DEC") != NULL`.
  When that environment variable is set: `crypto_kem_enc` copies the freshly
  sampled error vector into the file-static `debug_last_error[ERROR_WEIGHT]`
  (`kem.c:640-644`) — `e` fully determines the session key — and the
  decapsulation path prints internal decoder state to stderr
  (`kem.c:512-530`, `decode.c:goppa_decode` prints `syndrome_deg`,
  `locator degree out of range`, `zero derivative at j=…`,
  `forney check failed j=… value=…`, `decoded_weight=…`), i.e. a fine-grained
  decoding-failure oracle. `getenv` is called on **every** encapsulation and
  decapsulation, and the buffer exists unconditionally. Not active by default,
  but this is debug instrumentation that should not be in a reference
  implementation.
- **(c) `FixedWeight` rejects instead of deduplicating.** Spec Algorithm 5
  line 6 builds `D` from the *pairwise distinct* in-range draws and loops until
  `|D| ≥ w`. `fixed_weight_from_bits` (`m2e.c`) takes the first `w` in-range
  draws *with* duplicates, then scans a `seen[]` table and returns `FAIL` —
  discarding the whole block and redrawing — if any duplicate occurred. Both
  yield a uniform weight-`w` support, so this is distributionally equivalent, but
  it consumes the random stream differently, so an independent implementation
  following the spec literally would not reproduce these KATs.
- **(c) `H` is SHAKE-256, not the platform hash.** §3.1 requirement 2 says H
  "may be instantiated by CryptHash provided by the algorithm solicitation
  platform"; the code uses `FIPS202_SHAKE256` from the bundled `keccak.c`
  (hence the build links no `auxfunc.c`). Permitted by the "may", but it means
  QCTM's only symmetric primitive is a non-national-standard one.
- **(c) `crypto_kem_dec` is not constant time** with respect to decoding
  success: it branches (`if (decrypt_nied(...) == SUCCESS)`) rather than using a
  conditional move, and the failure path takes a visibly different amount of work
  (`goppa_decode` aborts at the first bad root). `hash_session_key` also
  `malloc`s a buffer whose length is public, which is fine, but the secret `e`
  is copied into heap memory that is `free`d without being zeroised.

Not verified (not executed, and the matrix layer is large): `MatGen`'s
systematisation and the ℓ-block-circulant consistency check, the
`GoppaPolynomial` ℓ-adic-valuation test, the `Q^{-1}` reconstruction in
Algorithm 7 steps 1–7, the §6.2 ISD estimates, and the §4.7 minimum-distance
remark on which the "no decapsulation failure" claim rests.
