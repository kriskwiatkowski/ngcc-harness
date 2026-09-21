# kem-10 C-Multi-UR-AG — algorithm summary

Code-based KEM in the **rank metric**. An IND-CPA PKE is built from an augmented
Gabidulin (AG) code masked by two random F_{q^m}-linear codes; security reduces
(tightly, per the spec) to the **RSL** (Rank Support Learning) problem, a
multi-instance variant of RSD. The IND-CCA2 KEM is obtained by the **salted
Fujisaki–Okamoto transform** with implicit rejection.

Specification: `kem-10-spec.pdf` (33 pages), §3 "Specifications" (Algorithms
2–5 = PKE, Algorithms 6–9 = KEM), §4 "Parameters" (Tables 2 and 3).

## Parameters

Spec Table 2 (p. 13). q = 2 for all instances.

| parameter | Level-128 | Level-256 | Level-512 | meaning |
|---|---|---|---|---|
| m | 79 | 127 | 181 | extension degree of F_{q^m} |
| n | 35 | 45 | 67 | dimension of the random [2n,n] code / H is n×n |
| t | 79 | 127 | 181 | rank weight of the AG support vector g |
| k | 3 | 3 | 4 | AG code dimension = plaintext length over F_{q^m} |
| N1 | 11 | 15 | 19 | rows of the folded matrix |
| N2 | 16 | 16 | 21 | columns of the folded matrix |
| w1 | 8 | 10 | 12 | rank weight of the secret (X,Y) |
| w2 | 9 | 11 | 14 | rank weight of the encryption randomness |
| r = w1·w2 | 72 | 110 | 168 | error weight the AG decoder must correct |
| DFR (spec Table 3) | 2^-148 | 2^-268 | 2^-598 | decapsulation failure rate |
| classical security | 2^170 | 2^276 | 2^530 | bits (spec's own claim, MM attack) |
| quantum security | 2^85 | 2^138 | 2^265 | sqrt of classical (spec's model) |
| claimed level | 128 | 256 | 512 | bits |

Sizes (bytes), specification (Tables 1/3) vs the built reference library:

| instance | pk spec | pk impl | sk spec | sk impl | ct spec | ct impl | ss | match |
|---|---|---|---|---|---|---|---|---|
| CMultiURAG-128 | 3866 | 3866 | 94 | 3960 | 7332 | 7332 | 64 | sk differs |
| CMultiURAG-256 | 10780 | 10780 | 112 | 10892 | 15304 | 15304 | 64 | sk differs |
| CMultiURAG-512 | 28866 | 28866 | 155 | 29021 | 40926 | 40926 | 64 | sk differs |

The sk gap is exactly the public key: impl sk = 64 (seed) + ceil(mk/8) (sigma) +
pk, spec sks = ceil(mk/8) + 64. Classified below.

## Pseudocode

### PKE.KGen (spec Algorithm 3)
```
1. g  <- S_t^{N1 N2}            (rank-t support vector) from seed theta1
2. H  <- F_{q^m}^{n x n}                                 from seed theta1
3. (X;Y) <- S_{w1,1}^{2n x N1}  (rank w1, 1 in Supp(X))  from seed theta2
4. S = X + H·Y  in F_{q^m}^{n x N1}
   pk = (g, H, S)  [in practice: theta1 || S], sk = (X, Y) [in practice: theta2]
```
### PKE.Enc(pk, m; theta) (spec Algorithm 4)
```
1. G <- k x (N1 N2) generator matrix of the AG code defined by g
2. (R1; E; R2) <- S_{w2}^{(2n+N1) x N2}   sampled from seed theta
3. U = R1 + H^T R2                     in F_{q^m}^{n x N2}
   V = Fold(m·G) + E + S^T R2          in F_{q^m}^{N1 x N2}
   ct' = (U, V)
```
### PKE.Dec(sk, ct') (spec Algorithm 5)
```
1. W = V - Y^T U = Fold(m·G) + (X^T R2 - Y^T R1 + E)     // error rank <= w1 w2 = r
2. m = AG.Decode(UnFold(W))                              // Algorithm 1, WBL decoder
```
### AG.Decode (spec Algorithm 1, WBL reconstruction)
```
1. run the WBL linearized-polynomial reconstruction [7, Alg. 5] -> (N1, W1)
2. u(x) = N1, v(x) = W1;  f(x) = v(x) \ u(x)              // left division
3. if deg_q f <= k-1 and ||y - f(g)||_R <= r:  return f, e = y - f(g)
   else: return  _|_                                      // failure symbol
```
### KEM.KGen (spec Algorithm 7)
```
1. (pk', sk') <- PKE.KGen(par)
2. sigma <-$ F_{q^m}^k
3. pk = pk';  sk = (sk', sigma)
```
### KEM.Encaps (spec Algorithm 8)
```
1. m <-$ F_{q^m}^k ;  salt <-$ {0,1}^512
2. theta = G(pk, m, salt)
3. ct' <- PKE.Enc(pk, m; theta);  ct = (ct', salt)
4. K = H(pk, m, ct', salt)
```
### KEM.Decaps (spec Algorithm 9)
```
1. parse sk = (sk', sigma), ct = (ct', salt)
2. m <- PKE.Dec(sk', ct');  theta = G(pk, m, salt)
3. ct'' <- PKE.Enc(pk, m; theta)
4. if ct'' != ct':  K = H(pk, sigma, ct', salt)   // implicit rejection
   else:            K = H(pk, m,     ct', salt)
```
Hashes (spec §3.1): G and H are the NGCC `pseudohash` construction (SM3 +
HMAC-SM3), 64-byte output; the seed expander is the NGCC one, 64-byte seed;
salt is 512 bits.

## Implementation vs specification

Checked: `src/CMultiURAG-<n>/src/{kem.c, cmultiurag.c, augmented_gabidulin.c,
qpoly.c, parameters.h}` and `lib/random_source/random_source.c`, all three
instances for constants, level-128 in depth for the algorithm flow.

Agreements:
- All of m, n, k, t, N1, N2, w1, w2, r match Table 2 exactly in
  `src/parameters.h` of all three instances (spot-checked all 9 constants per
  instance, not just 3–6).
- `CMULTIURAG_SALT_BYTES 64` = the spec's 512-bit salt; G and H are both
  `pseudohash(512, ...)` with 64-byte output, as §3.1 requires.
- The FO transform is present and complete: `cmultiurag_decaps`
  (`src/kem.c`) re-encrypts and compares, and selects sigma vs m in
  constant time (OR-accumulator + XOR-select, no branch on the comparison).
- Hash inputs match Algorithms 8/9 byte for byte: `G_in = pk || m || salt`,
  `H_in = pk || m || U || V || salt`, with the same buffer used on the reject
  path (only `m` replaced by sigma), so pk and ct are bound as the proof needs.

Discrepancies:
- **(b) spec-table understatement, sk size.** Impl sk = `sk_seed(64) || pk ||
  sigma(ceil(mk/8))` (`src/kem.c` keygen, layout comment; `parameters.h:9`),
  i.e. 3960 / 10892 / 29021 bytes. The spec's Table 1/3 formula
  `ceil(mk/8) + 64` gives 94 / 112 / 155 and omits the public-key copy that
  its own Algorithm 9 needs (Decaps computes G(pk,...) and re-runs PKE.Enc
  with pk). The difference is exactly the pk size for every instance, so this
  is an incomplete size formula in the spec rather than a code bug — but the
  published sk numbers are wrong by a factor of 40–190x.
- **(a) the decoder has no failure path.** Spec Algorithm 1 lines 5–8 verify
  `deg_q f <= k-1` and `||y - f(g)||_R <= r` and return `_|_` otherwise.
  `rbc_augmented_gabidulin_decode()`
  (`src/CMultiURAG-128/src/augmented_gabidulin.c:94`) returns `void` and
  unconditionally writes the first k coefficients of the reconstructed f into
  m (line ~283, `rbc_vec_set(m, qtmp1->values, gc.k)`); neither the degree
  test nor the weight test is performed, and the `INVALID_PARAMETERS` codes
  that `qpoly.c` returns on degree overflow (e.g. `qpoly.c:81, 111, 409, 450`)
  are discarded by every caller. Correctness still holds for honest
  ciphertexts and CCA security still rests on the FO re-encryption check, but
  this is the most plausible source of the already-recorded malformed-
  ciphertext crashes (`security_findings.md`: stack smash on CMultiURAG-128
  zero ciphertext, SIGSEGV on CMultiURAG-256/512) — an out-of-weight error
  vector drives q-polynomial degrees past the `max_degree_N` allocation
  instead of being rejected. Not re-tested here (crafted input out of scope).
- **(a) Decaps consumes randomness.** Spec Algorithm 9 is deterministic. The
  implementation's decoder draws `n` random F_{q^m} elements per call
  (`augmented_gabidulin.c:120–126`, used as a constant-time mask at lines
  196–201) from `RANDOM_SOURCE_PRNG`, which is the global `drng_algorithm`
  (`lib/random_source/random_source.c:50`). Decapsulation therefore advances
  the shared DRNG stream. The masking use looks output-neutral, and KATs pass,
  but "Decaps draws from the KAT DRNG" is a deviation from the spec text and
  makes decapsulation order-dependent in any shared-DRNG deployment.
- **(c) equivalent optimisation.** The ciphertext comparison is done on the
  serialized byte strings rather than on matrices; sk stores the keygen seed
  rather than (X,Y) and re-expands it. Both are standard and output-neutral.

Not verified: the WBL reconstruction loop itself was not checked line-by-line
against [7, Algorithm 5], and the claimed DFR values were not recomputed.
