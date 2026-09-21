# kem-31 QIMEN-PIKE — algorithm summary

Isogeny-based KEM in the POKÉ/PIKE line, built on the SQIsign codebase. The
IND-CPA PKE is an ElGamal-style scheme over supersingular curves: key generation
produces a secret isogeny `φ: E_0 → E_A` of degree `q(2^{a−2} − q)` (KLPT +
ideal-to-isogeny), encryption pushes a random odd-degree isogeny `ψ` through
both `E_0` and `E_A`, and the shared pad is derived from a **Tate pairing** value
`tr(w_0^{η_D ζ_D})` in the D-torsion. Decryption recovers the pairing value by
reconstructing a **(2,2)-isogeny chain in the theta model** from the transmitted
2^a-torsion. The IND-CCA2 KEM is a Fujisaki–Okamoto transform with implicit
rejection.

Specification: `kem-31-spec.pdf` (120 pages), §3.2 (Algorithms 9–11, PKE),
§3.3 (Algorithms 12–15, KEM), Chapter 4 (compression: Algorithms 20–22),
Chapter 5 (parameters), Table 7.1 (sizes), Chapter 9 (failure analysis).

**This candidate was reviewed by reading the source only.** It is already
recorded (RESULTS.md, `security_findings.md`) that every fixed-length ciphertext
mutation and the all-zero ciphertext make it `abort()`, so no crafted input was
fed to it here.

## Parameters

`par = (λ, p, a, C1, C2, D)` with `C = C1 C2`, `p + 1 = 2^a C1 D`, `C2 | p − 1`,
`λ = 2λ_q`. `E_0: y² = x³ + x`. Only the **compressed** variant is built
(`ENABLE_COMPRESSED=ON`), which is what the submitted KATs use.

| parameter | NGCC-1 | NGCC-2 | NGCC-3 | meaning |
|---|---|---|---|---|
| λ (= 2λ_q) | 160 | 256 | 512 | internal security parameter |
| ⌈log2 p⌉ | 479 | 765 | 1534 | prime size |
| a | 162 | 260 | 514 | 2-power torsion exponent |
| C1 | 3^5·7^46 | 3·5^69 | 5·7^60 | odd "plus" torsion |
| C2 | 11^55 | 7^125 | 11^247 | odd "minus" torsion |
| D | 0xa9884…bcbcaf (≈180 bit) | 0x5239d…5ad7 (≈347 bit) | 0x7827d…3ef (≈697 bit) | pairing torsion |
| `FP_ENCODED_BYTES` | 64 | 96 | 192 | Fp slot (spec `B_p^enc`) |
| shared secret | 32 | 32 | 64 | `PIKE_COMPRESSED_SHARED_SECRET_BYTES` |
| claimed security | 128 (λ_q = 80) | 256 (λ_q = 128) | 512 (λ_q = 256) | bits |

Sizes (bytes), specification Table 7.1 ("Compressed" columns, p. 54) vs the built
reference library (OBSERVED) — ct agrees, **pk and sk do not**:

| instance | pk spec | pk impl | sk spec | sk impl | ct spec | ct impl | ss impl | match |
|---|---|---|---|---|---|---|---|---|
| NGCC-1 | 405 | **389** | 488 | **472** | 602 | 602 | 32 | **no (−16)** |
| NGCC-2 | 595 | **592** | 737 | **734** | 882 | 882 | 32 | **no (−3)** |
| NGCC-3 | 1201 | **1198** | 1500 | **1497** | 1746 | 1746 | 64 | **no (−3)** |

The submission's own `Test_Vectors/KAT_KEM_NGCC-*.txt` agree with the
*implementation* (`PK_Len = 389 / SK_Len = 472 / CT_Len = 602` and
`1198 / 1497 / 1746`), so it is spec Table 7.1 that is wrong, not the build.
Table 1.1 (p. 7) repeats the wrong figure ("QIMEN-PIKE (NGCC-2): 595 B public key").

## Pseudocode

### PKE.KeyGen (spec Algorithm 9)
```
 1  (q, E_A, (P'_A,Q'_A), (R'_A,S'_A), X'_A) <- CoreKeyGenIso(pp)
      # KLPT: an ideal of norm q(2^{a-2} - q); IdealToIsogeny gives phi: E_0 -> E_A
      # with the images of the 2^a-, C- and D-torsion bases
 2  alpha2, beta2 <- (Z/2^{a-2}Z)^x ;  gamma <- (Z/CZ)^x ;  delta_D <- (Z/DZ)^x
 3  P_A, Q_A  <- [alpha2] P'_A, [beta2] Q'_A          # mask the 2^a-torsion
 4  R_A, S_A  <- [gamma] R'_A, [gamma] S'_A           # mask the C-torsion
 5  X_A       <- [delta_D] X'_A                       # mask the D-torsion
 6  sk <- (q, alpha2, beta2, delta_D)
 7  pk <- (E_A, (P_A,Q_A), (R_A,S_A), X_A)
```

### PKE.Encrypt (spec Algorithm 10)
```
 1  r <- Z/CZ ;  omega2 <- (Z/2^a Z)^x ;  eta_D, zeta_D <- (Z/DZ)^x
 2  w'  <- w_0^{eta_D * zeta_D}                        # w_0 = t_D(X_0, Y_0)
 3  pad <- H(KDF || tr(w'))                            # trace kills the +-1 ambiguity
 4  E_B , (P'_B ,Q'_B ,Y'_B ) <- OddIsogenyChain(E_0, R_0 + [r]S_0, C, (P_0,Q_0,Y_0))
 5  E_AB, (P'_AB,Q'_AB,X'_AB) <- OddIsogenyChain(E_A, R_A + [r]S_A, C, (P_A,Q_A,X_A))
 6  P_B ,Q_B ,Y_B  <- [omega2]P'_B , [omega2^{-1} mod 2^a]Q'_B , [eta_D ]Y'_B
 7  P_AB,Q_AB,X_AB <- [omega2]P'_AB, [omega2^{-1} mod 2^a]Q'_AB, [zeta_D]X'_AB
 8  c  <- pad XOR msg
 9  ct <- (E_B, P_B, Q_B, Y_B, E_AB, P_AB, Q_AB, X_AB, c)
```

### PKE.Decrypt (spec Algorithm 11) — the "decoding" step
```
 1  P~_B  <- [-q]P_B ,             Q~_B  <- [-q]Q_B
 2  P~_AB <- [alpha2^{-1} mod 2^a]P_AB,  Q~_AB <- [beta2^{-1} mod 2^a]Q_AB
 3  E_M, _, (Y_M,_), (X_M,_)
        <- Isogeny22Chain( (P~_B,P~_AB), (Q~_B,Q~_AB), [(Y_B,0),(0,X_AB)] )
 4  t <- ( q (2^{a-2} - q) C delta_D )^{-1} mod D
 5  w <- TateOdd(E_M, D, X_M, Y_M, X_M - Y_M)
 6  w' <- w^t
 7  pad~ <- H(KDF || tr(w'))
 8  return pad~ XOR c
```

### KEM (spec Algorithms 12–15)
```
KeyGen:  z <- {0,1}^{2*lambda}
         (pk, sk0) <- PKE.KeyGen()
         hpk <- Hpk(pk)
         sk  <- (sk0 || pk || hpk || z)

Encaps:  m <- {0,1}^{2*lambda}
         hpk     <- Hpk(pk)
         (Kbar, rho) <- G(m || hpk)
         ct <- Enc.Det(pk, m, rho)          # DeriveCoins(rho) -> (r3, omega2, eta_D, zeta_D)
         K  <- KDF(Kbar || Hct(ct))

Decaps:  try   m' <- PKE.Decrypt(ct, sk0)
         catch return KDF(z || Hct(ct))                     # exception -> implicit reject
         (Kbar', rho') <- G(m' || hpk)
         ct' <- Enc.Det(pk, m', rho')
         if ct == ct' return KDF(Kbar' || Hct(ct))
         else         return KDF(z      || Hct(ct))
```
§3.1.2 requires domain separation: "key-derivation queries shall be written as
`H(KDF | ·)`", and §3.3.1 defines four separate functions `Hpk`, `Hct`, `G`, `KDF`.
`DeriveCoins` expands ρ into a byte stream and **rejection-samples** until the
values land in `Z/CZ`, `(Z/2^a Z)^×`, `(Z/DZ)^×`, `(Z/DZ)^×`.

## Implementation vs specification

Built tree: one shared CMake source tree
(`Implementations/Implementations`), NGCC adapter in `src/ngcc/common`,
level selected by `-DNGCC_PIKE_LEVEL=n` plus the per-level `precomp/`+`gf/`
directories; `PIKE_XOF_BACKEND=2` (SM3), `-lgmp`. Only the compressed variant is
built. Reviewed files: `src/ngcc/common/KEM_AlgorithmInstance.c`,
`src/pike/ref/pikex_compressed/pike_compressed.c` and its header,
`src/precomp/ref/NGCC_*/include/encoded_sizes.h`, `src/hd/ref/hdx/*`.

Agreements:

- The compressed wire formats in `pike_compressed.h:24-43` reproduce the
  implementation sizes exactly and are all derived, none hard-wired:
  `pk = 2·FP2 + TPLS + TWOPOW + 3·TMIN + 2 + 5·sizeof(int)`,
  `ct = 4·FP2 + 2·TWOPOW + 4·sizeof(int) + SS`,
  `sk_core = 3·SEC_TWOPOW + SEC_TORSION_D`. Evaluated with
  `FP_ENCODED_BYTES = 64/96/192`, `a = 162/260/514` and the C1/C2 bit lengths of
  spec §5.1 these give 389/592/1198 (pk), 602/882/1746 (ct), 83/142/299
  (sk_core) — i.e. the parameters of Chapter 5 *are* the ones compiled in.
- `encrypt()` (`pike_compressed.c`) implements the spec's `DeriveCoins` faithfully
  in structure: `pike_xof_stream_init(&state, seed, seed_len)` followed by
  `ibz_random_unit` rejection sampling of `β1 ∈ (Z/C1Z)^×`, `β2 ∈ (Z/C2Z)^×`,
  `ω`, `t1, t2 ∈ (Z/DZ)^×`, with `t1t2 = t1·t2 mod D` matching `η_D ζ_D`.
- Randomness comes only from the official DRNG: the adapter defines its own
  `randombytes()` as `get_random_number(&drng_algorithm, x, 8·xlen)`
  (`KEM_AlgorithmInstance.c:63-70`), and the build deliberately drops
  `randombytes_system.c` (getrandom / /dev/urandom) from the link.
- The re-encryption check is present and correctly oriented
  (`KEM_AlgorithmInstance.c`, `kem_dec`): decrypt → `derive_gm` → `encrypt` →
  `compare_ct_for_kdf` → shared secret from `m` if equal, from `dummy_m` if not.

Discrepancies:

- **(a) Size mismatch, spec vs implementation and vs the submission's own KATs.**
  Spec Table 7.1 (and Table 1.1) give compressed `pk` = 405 / 595 / 1201 and
  `sk` = 488 / 737 / 1500, whereas the library and the shipped
  `Test_Vectors/KAT_KEM_NGCC-*.txt` both say 389 / 592 / 1198 and
  472 / 734 / 1497. The ciphertext column of Table 7.1 is correct. The delta is
  entirely in the public key (16 bytes at NGCC-1, 3 bytes at NGCC-2 and NGCC-3),
  so it is not a single systematic formula difference; the `sk` column inherits
  it because `sk = sk_core ‖ pk` in both.
- **(a) The KEM secret key does not contain `hpk` or `z`.** Spec Algorithm 13
  line 4 is `sk ← (sk0 ‖ pk ‖ hpk ‖ z)`. The adapter defines
  `PIKE_SK_BYTES = PIKE_SK_CORE_BYTES + PIKE_PK_BYTES`
  (`KEM_AlgorithmInstance.c:38`) and `serialize_sk` writes only the four secret
  scalars followed by the encoded public key. Both components the spec puts there
  are missing.
- **(a) The public key is not bound into the FO hash.** Spec Algorithm 14 lines
  2–3 compute `hpk ← Hpk(pk)` and `(K̄, ρ) ← G(m ‖ hpk)`. The implementation's
  `derive_gm` is `pike_xof(gm, SS, m, SS)` — i.e. `ρ = XOF(m)` with **no `hpk`
  input at all** — and `kem_enc` then calls `encrypt(…, gm, …)`. The shared
  secret is `derive_ss_from_m_and_ct` = `XOF(m ‖ encode_ct(ct))`, so there is no
  separate `K̄` either. The public-key-binding / multi-target countermeasure that
  §3.3.1 introduces `Hpk` for is therefore absent; `pk` only enters `ss`
  indirectly, through the ciphertext.
- **(a) The implicit-rejection secret `z` is replaced by a hash of the whole
  secret key.** Spec Algorithm 13 line 1 samples `z ← {0,1}^{2λ}` and Algorithm 15
  lines 4/10 return `KDF(z ‖ Hct(ct))`. `derive_dummy_m`
  (`KEM_AlgorithmInstance.c`) instead computes `dummy_m = XOF(sk ‖ ct)` over the
  *entire* serialized secret key (secret scalars **and** the embedded public key)
  concatenated with the ciphertext, and the rejection key is
  `XOF(dummy_m ‖ encode_ct(ct))`. This is still a secret-keyed PRF of the
  ciphertext, so it is not obviously weaker, but it is a different construction
  from the one the IND-CCA2 proof (Theorem 8.2.3) is stated for.
- **(a) No domain separation.** §3.1.2 mandates `H(KDF | ·)` and §3.3.1 defines
  four distinct functions `Hpk`, `Hct`, `G`, `KDF`. The implementation calls the
  single unlabelled `pike_xof(out, outlen, in, inlen)` for all three roles it
  uses (`derive_gm`, `derive_dummy_m`, `derive_ss_from_m_and_ct`), with no prefix
  or label. The roles are separated only incidentally, by their differing input
  lengths (32, 32+602, 472+602 at NGCC-1). No `"KDF"` string appears anywhere in
  the adapter.
- **(a) `ω2` is drawn from a 4× smaller group than Algorithm 10 states.**
  Algorithm 10 line 1 says `ω2 ← (Z/2^a Z)^×` and lines 6–7 use
  `ω2^{-1} mod 2^a`. `encrypt()` computes `A = TORSION_PLUS_2POWER >> 2 = 2^{a−2}`
  and then `ibz_random_unit(&omega, &A, &state)` / `ibz_invmod(&omega_inv, &omega,
  &A)`, i.e. `ω2 ∈ (Z/2^{a−2}Z)^×`. Two bits of masking entropy less than
  specified. (It may be that the spec should say `2^{a−2}` here, matching
  Algorithm 9 line 2, which does use `(Z/2^{a−2}Z)^×` — but as written the two
  disagree.)
- **(a) The spec's exception/`try…catch` convention has no implementation.**
  Spec Algorithm 1 defines an exception convention and Algorithm 15 lines 1–4
  wrap `PKE.Decrypt` in `try/catch` so that a decryption error returns the
  implicit-rejection key. In C there is no such mechanism: the isogeny layer uses
  `assert()` on error conditions — `src/hd/ref/hdx/hd.c:123` and
  `src/hd/ref/hdx/theta_isogenies.c:59,84` are unconditional `assert(0)` in error
  branches, plus ~20 further `assert()` structural checks in the same file. The
  harness aborts land at two of them (`review-o48.md`):
  `src/ec/ref/ecx/biextension.c:185: point_ratio: Assertion 'is_point_equal(…)'`
  for `kem-ciphertext-flip` and the all-zero ciphertext, and
  `src/hd/ref/hdx/theta_isogenies.c:1642: theta_chain_comput_strategy` (the
  `assert(is_split)`) for `kem-wrong-secret-key`, at all three levels. The
  NGCC build does not define `NDEBUG` (see `kem-31/Makefile`, `DEFS_`), so a
  malformed ciphertext reaches `abort()` instead of the catch branch — which is
  exactly the confirmed finding recorded in `security_findings.md` (all
  fixed-length mutations and the all-zero ciphertext abort at every level). The
  candidate's own documented build uses `CMAKE_BUILD_TYPE=Release`, i.e.
  `-DNDEBUG`, which compiles those asserts *out*; the failing condition then
  proceeds with an invalid theta structure rather than being caught, so neither
  build realises Algorithm 15's catch branch. This is a denial-of-service /
  robustness defect, not a confidentiality break: the harness never observed
  retention of the original shared secret.
- **(c) The wire format depends on `sizeof(int)`.**
  `PIKE_COMPRESSED_PK_ENCODED_BYTES` contains `5 * sizeof(int)` and
  `PIKE_COMPRESSED_CT_ENCODED_BYTES` contains `4 * sizeof(int)`, and `pk_encode`
  advances `offset += sizeof(int)` per hint. The serialized key/ciphertext
  lengths are therefore platform-dependent rather than fixed by the
  specification; the spec gives no encoding for these "hint" integers at all.
- **(c)** `PIKE_COMPRESSED_SHARED_SECRET_BYTES` defaults to 32 in
  `pike_compressed.h:20` and is raised to 64 for NGCC-3 only by a
  `target_compile_definitions` line in `src/ngcc/CMakeLists.txt:50`. The
  shared-secret length is thus a build-system property, not a parameter-set
  constant; nothing in `precomp/ref/NGCC_3` encodes it.

Not verified (source-read only, no execution, no crafted inputs): the KLPT /
ideal-to-isogeny key generation, the (2,2)-theta chain, the Tate pairing
exponent bookkeeping of Algorithm 11 line 4, the Chapter 4 compression/
decompression correctness, and the Chapter 8/9 security and failure analyses.
Whether `pk_decode` / `ct_decode` validate their inputs (curve/point order,
scalar ranges) was not traced through; the observed aborts suggest they do not.
