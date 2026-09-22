# kem-29 Polar-KEM — algorithm summary

As specified: a KEM whose claimed hardness assumption is the **Lattice Isomorphism
Problem (LIP)** over a *polar lattice* — a Construction-D lattice built from a
nested chain of polar codes C0 ⊇ C1 ⊇ … ⊇ C_{L−1}. KeyGen publishes a secretly
rotated basis B_pk = O·B_red; Encaps encodes a message to a lattice point and adds
a short error; Decaps un-rotates with the secret isometry O and runs a multistage
polar successive-cancellation decoder. IND-CCA2 is claimed via an FO transform
with implicit rejection (§3.3).

**As implemented, it is a different and entirely broken scheme** — see
"Implementation vs specification". There is no lattice, no basis, no isometry and
no secret used in decapsulation.

Specification: `kem-29-spec.pdf` (35 pages, English), §4.2–§4.6 (Algorithms 1–4),
parameters §4.1 Table 1, API sizes §7.2.1 Table 9. Two further Markdown documents
ship beside it: `polar_kem_specification.md` (the polar-lattice construction and
SC / SC-List / BP decoder designs in more detail) and
`polar_kem_security_analysis.md`. Where the two disagree I cite which is which.

## Parameters

| parameter | PolarKEM-128 | PolarKEM-256 | PolarKEM-512 | meaning |
|---|---|---|---|---|
| N (dimension) — spec Table 1 | 512 | 1024 | 2048 | polar transform length, N = 2^m |
| N — impl `POLARKEM_N` | 512 | 1024 | 2048 | agrees |
| q — spec / impl | 12289 | 12289 | 18433 | modulus (impl agrees) |
| L (Construction-D levels) | 5 | 5 | 6 | **spec only — absent from impl** |
| error bound B | 1 | 1 | 1 | spec |
| decoding radius ρ | 15.0 | 31.0 | 63.0 | spec |
| δ (failure prob.) | < 2^−128 | < 2^−256 | < 2^−512 | spec's claim |
| shared secret | 128 bits | 256 bits | 512 bits | = impl `SS_BYTES` 16/32/64 |
| impl: message / info bits K | 128 | 256 | 512 | `MESSAGE_BYTES`·8; rate K/N = 1/4 |
| impl: `QUANT_BITS` | 11 | 9 | 8 | ciphertext coefficient compression |
| impl: amplitude | q/4 = 3072 | 3072 | 4608 | codeword bit → ±q/4 |
| claimed security | ~150 cl / ~134 qu | ~296 / ~269 | ~618 / ~561 | bits (spec's own claim) |

Sizes (bytes), specification (Table 8/9) vs the built reference library:

| instance | pk spec | pk impl | sk spec | sk impl | ct spec | ct impl | ss spec | ss impl | match |
|---|---|---|---|---|---|---|---|---|---|
| PolarKEM-128 | 1024 | 1024 | 2048 | 2048 | 768 | 768 | 16 | 16 | yes |
| PolarKEM-256 | 2048 | 2048 | 4096 | 4096 | 1280 | 1280 | 32 | 32 | yes |
| PolarKEM-512 | 4096 | 4096 | 8192 | 8192 | 2304 | 2304 | 64 | 64 | yes |

The numeric agreement is exact but **meaningless**: the sizes are powers of two
reached by padding. The implementation's actual key material is 32 bytes.
`pk = header(16) ‖ seed(32) ‖ XOF-pad(976)`,
`sk = header(16) ‖ z(32) ‖ pk(1024) ‖ XOF-pad(976)`,
`ct = header(16) ‖ payload(N·QUANT_BITS/8 = 704) ‖ tag(32) ‖ XOF-pad(16)`
(`polarkem_params.h`, `polarkem_ct.c:223-243`). The pad bytes are XOF output from
the seed, i.e. carry no information. The spec's own §4.2 says pk = B_pk ∈ Z^{N×N},
which for N = 512 could not be 1024 bytes under any encoding — Table 9 and §4.2
are already irreconcilable within the spec.

## Pseudocode (from the specification)

### Core.KEM.KeyGen — Algorithm 1 (§4.2)
```
m <- log2 N
Construct polar code chain C0 ⊇ C1 ⊇ ... ⊇ C_{L-1}, frozen sets F0 ⊆ F1 ⊆ ... ⊆ F_{L-1}
B     <- Construction D from the code chain:  B = [G0^T | 2 G1^T | ... | 2^{L-1} G_{L-1}^T | 2^L I_N]^T
B_red <- LLL(B)
O     <-$ O_N(R)                      // orthogonal matrix, sampled uniformly (spec's words)
B_pk  <- O · B_red
return pk = B_pk, sk = O
```

### Core.KEM.Encaps — Algorithm 2 (§4.3)
```
m <-$ {0,1}^K
v <- Embed(m, B_pk)        // m as the information bits of the code chain, then the polar transform
e <-$ D_err                // short error, bound B = 1
c <- v + e  (mod q)
K <- Extract(m)
return (c, K)
```

### Core.KEM.Decaps — Algorithm 3 (§4.4)
```
c'  <- O^{-1} · c  (mod q)          // rotate back to the secret (non-rotated) lattice
c'' <- c' mod 2^L                   // reduce to the fundamental region
m̂   <- PolarSCDecode(c'', {F_ℓ})
return Extract(m̂)
```

### The polar-code decoding step — Algorithm 4 (§4.6)
```
PolarSCDecode(y ∈ R^N, {F_ℓ}_{ℓ=0}^{L-1}):
  û <- 0 ∈ Z^N ;  m <- log2 N
  for i = 0 to N-1:
      ℓ* <- min{ ℓ : i ∈ F_ℓ }               // coarsest level freezing index i
      if ℓ* exists:  û_i <- 0                // frozen bit
      else:
          LLR_i <- log( p(y_i | u_i = 0) / p(y_i | u_i = 1) )
          û_i   <- CTSelect(0, 1, LLR_i >= 0)
  m̂ <- û · G_N  (mod 2^L)                    // G_N = B_N · F^{⊗ m}
  return m̂
```

Frozen-set design (§4.5.1): per level ℓ compute the Bhattacharyya parameters
{Z_i^{(ℓ)}} for the BMS channel matching the error distribution and freeze the
N − K_ℓ indices with the largest Z; rate progression R_ℓ = 2^{−ℓ},
K_ℓ = N/2^ℓ, with the top level a repetition code (K_L = 1). The Markdown spec
(`polar_kem_specification.md` §3.1–§3.5) additionally describes a *multistage*
decoder that decodes level 0 first and passes hard decisions to level 1, and
offers SC, SC-List (L_list = 8) and BP (I_max = 50) variants, recommending SC as
"constant-time friendly"; the PDF specifies only the SC variant.

**Algorithm 4 is not successive cancellation.** Each û_i is decided from y_i
alone; there is no recursive f/g (min-sum or tanh) butterfly, no use of the
previously decided bits û_0..û_{i−1}, and no level-to-level information flow
even though the loop is nominally over an L-level chain. What Algorithm 4
describes is a coordinate-wise hard-decision slicer followed by one application
of G_N. The spec nevertheless claims O(N log N) "successive cancellation"
complexity for it (§6.2, Table 7). This is a defect of the specification, not
only of the implementation.

## Implementation vs specification

Checked (built sources per `kem-29/Makefile`:
`Submission_Package/Implementations/Reference_Implementation/<inst>/` —
`polarkem_core.c`, `polarkem_polar.c`, `polarkem_pack.c`, `polarkem_ct.c`,
`KEM_AlgorithmInstance.c`, `auxfunc.c`, `drng.c`). I read all of
`polarkem_core.c` (120 lines), `polarkem_polar.c` (189) and `polarkem_pack.c`
(76), and the relevant parts of `polarkem_ct.c` (516). `polarkem_core.c`,
`polarkem_ct.c` are byte-identical between PolarKEM-128 and PolarKEM-512; only
`polarkem_polar.c` differs (the hard-coded information-position table).

What the implementation actually computes:

```
KeyGen:  seed, z <-$ DRNG (32 bytes each)
         pk = hdr ‖ seed ‖ XOF("PolarKEM-PKPAD-v1" ‖ seed)
         sk = hdr ‖ z ‖ pk ‖ XOF("PolarKEM-SKPAD-v1" ‖ ...)
Encaps:  mu <-$ DRNG (K bits)
         cw       = PolarEncode(mu)                        // bits at hard-coded info positions, then F^{⊗m}
         (π, s)   = SignedPermutation(seed)                // Fisher-Yates + sign bits, from the PUBLIC seed
         err      = XOF("PolarKEM-ERR-v1" ‖ mu ‖ H(pk))    // deterministic ternary error
         c_i      = s_i · (cw[π(i)] ? -q/4 : +q/4) + err_i   mod q
         ct       = hdr ‖ Compress(c) ‖ Tag(mu,H(pk),payload) ‖ pad
         ss       = XOF("PolarKEM-SS-v1" ‖ mu ‖ H(ct))
Decaps:  mu       = RecoverMessage(pk, ct)                 // <-- pk only
         re-encapsulate, constant-time compare, implicit rejection with z
```

- **CRITICAL (a) — decapsulation uses no secret; the KEM is trivially broken.**
  `polarkem_dec` recovers the message with
  `polarkem_recover_message(pk, ct, mu)` (`polarkem_core.c:95`), and that
  function's only inputs are the **public key** and the ciphertext
  (`polarkem_ct.c:401-439`). It derives the signed permutation from
  `pk + POLARKEM_PK_SEED_OFFSET` — the public seed — then takes the sign of each
  centred coefficient and applies the polar transform. The secret key's 32-byte
  `z` is used *only* to derive the implicit-rejection secret
  (`polarkem_derive_reject_secret`). Consequently **any party holding the public
  key can recover mu from any ciphertext and compute the shared secret**
  ss = XOF("PolarKEM-SS-v1" ‖ mu ‖ H(ct)). This destroys IND-CPA and IND-CCA
  completely; no cryptanalysis is required, only the public key. I did not find
  this recorded in `kem-29/security_findings.md` (which lists
  `KEM-LOW-EFFORT-KEY-RECOVERY` as `not_tested`) or in `RESULTS.md`, so it
  appears to be new. It also explains why every functional test passes: the
  scheme round-trips correctly, it simply has no secret.
- **(a) none of the specified construction is present.** There is no basis matrix,
  no Construction D, no LLL, no orthogonal matrix O, no level chain, no
  Bhattacharyya computation, no LLR and no mod-2^L reduction anywhere in the
  built sources. The spec's L parameter (5/5/6) has no counterpart in
  `polarkem_params.h`. The "isometry" is replaced by a signed permutation
  (`polarkem_signed_permutation`, `polarkem_polar.c:135-188`) generated by
  Fisher–Yates from the public seed.
- **(a) the code is a single polar code, not a chain.** `polarkem_info_positions`
  is one hard-coded table of K = 128/256/512 indices (`polarkem_polar.c:11-19`),
  selected by index Hamming weight rather than by any documented Bhattacharyya
  rule, giving a single rate-1/4 code — not the R_ℓ = 2^{−ℓ} progression of
  §4.5.1.
- **(a) the decoder is a hard-decision slicer.** `polarkem_polar_decode`
  (`polarkem_polar.c:119-132`) applies the in-place XOR butterfly
  `polarkem_polar_transform` to a bit vector and reads off the information
  positions. No LLRs, no list, no frozen-bit-aware cancellation. This is
  consistent with the spec's Algorithm 4 as written, and inconsistent with
  everything the spec and the Markdown document say *about* Algorithm 4.
- **(a) the advertised sizes are padding.** 976 of pk's 1024 bytes, 976 of sk's
  2048 (beyond the embedded pk), and 16/80/208 of ct are XOF-derived filler
  (`polarkem_ct.c:223-243` and the `*_PAD_*` macros in `polarkem_params.h`).
- **(a) encapsulation is deterministic given mu.** The error vector is
  XOF("PolarKEM-ERR-v1" ‖ mu ‖ H(pk)) (`polarkem_ct.c:89-125`), not sampled from
  D_err as Algorithm 2 line 3 requires. This is what makes the FO re-encryption
  check work, but it means the "short error" carries no entropy.
- Agreements worth stating, such as they are: N, q and the shared-secret lengths
  in `polarkem_params.h` match Table 1 exactly for all three instances; the
  implicit-rejection FO wrapper in `polarkem_dec` (`polarkem_core.c:109-114`) is
  correctly constant-time (`valid` → mask → select between valid_ss and
  reject_ss); ciphertext compression is a standard Kyber-style
  round(2^b·x/q) (`polarkem_pack.c:7-26`).

Not verified: the security analysis of §5 and `polar_kem_security_analysis.md`
(not re-derived); the `Optimized_Implementation` tree (not built, not read); the
exact provenance of the `polarkem_info_positions` tables. The library was not
executed — the critical finding above is from source reading and would be
straightforward to confirm by calling `polarkem_recover_message` with only a
public key.
