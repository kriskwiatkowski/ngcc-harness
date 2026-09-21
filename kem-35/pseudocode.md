# kem-35 Scloud+ — algorithm summary

Unstructured (plain, non-algebraic) LWE over Z_q with q = 2^10, in the FrodoKEM
mould: rectangular matrices, no ring or module structure. An IND-CPA PKE
(Scloud+.PKE) encodes the message into a **Barnes-Wall lattice code** (BW_32,
BW_128 or the rotated RBW_128) rather than into a single bit-per-coefficient
threshold, and the IND-CCA2 KEM is the Fujisaki-Okamoto transform with implicit
rejection. Secret and error matrices are ternary, drawn from the
Bernoulli-Difference (BD) distribution with parameter rho = 1/p.

Specification: `kem-35-spec.pdf` (33 pages), Sections 1.3-1.6 (algorithms and
parameters) and 2.1-2.2 (symmetric instantiation and byte-level sampling).

## Parameters

The 15 built instances are 5 security levels x 3 symmetric families (AES,
SHAKE, SM3). The family changes only which primitives instantiate XOF/PRF/H/G/KDF
— all structural parameters and all key/ciphertext sizes are identical within a
level, so the table has one column per level.

| parameter | 128 | 192 | 256 | 384 | 512 | meaning |
|---|---|---|---|---|---|---|
| l_m = l_ss | 128 | 192 | 256 | 384 | 512 | message / shared-secret bits |
| q = 2^t | 2^10 | 2^10 | 2^10 | 2^10 | 2^10 | modulus (t = 10 always) |
| (m, n) | (608,608) | (832,832) | (1184,1184) | (1664,1664) | (2400,2400) | big LWE matrix A is m x n |
| (mbar, nbar) | (8,8) | (12,11) | (12,11) | (16,16) | (16,16) | small dimensions |
| rho_s | 1/4 | 1/2 | 1/6 | 1/6 | 1/12 | BD parameter for S, S' |
| rho_e | 1/2 | 1/2 | 1/6 | 1/6 | 1/12 | BD parameter for E, E1, E2 |
| coding lattice | BW_32 | BW_128 | RBW_128 | BW_128 | RBW_128 | Barnes-Wall (rotated for RBW) |
| g = 2^tau | 2^3 | 2^3 | 2^4 | 2^3 | 2^4 | label modulus |
| sigma | 2 | 1 | 1 | 2 | 2 | repetition / number of code blocks |
| h | 512 | 512 | 512 | 768 | 1024 | hash-material bits |
| claimed security | 128 | 192 | 256 | 384 | 512 | bits (spec Table 2; DFR < 2^-lambda) |

Implementation constants (`Scloudplus-<L>/kem/parameters.h`): `scloudplus_m/n`,
`scloudplus_mbar/nbar`, `scloudplus_tau`, `scloudplus_secret_bd` (= p for rho_s),
`scloudplus_error_bd`, `scloudplus_code_rep` (= sigma), `scloudplus_bw_k`
(d = 2^k: 5 -> BW_32, 7 -> BW/RBW_128), `scloudplus_hash_bytes` (= h/8).
**All five levels were checked against spec Tables 2 and 3 and every value agrees.**

Sizes (bytes), specification (Table 4) vs the built reference library (OBSERVED):

| instance (all 3 families) | pk spec | pk impl | sk spec | sk impl | ct spec | ct impl | ss | match |
|---|---|---|---|---|---|---|---|---|
| Scloudplus-128 | 6096 | 6096 | (formula) 7440 | 7440 | 6160 | 6160 | 16 | yes |
| Scloudplus-192 | 11456 | 11456 | 13872 | 13872 | 12645 | 12645 | 24 | yes |
| Scloudplus-256 | 16296 | 16296 | 19680 | 19680 | 17925 | 17925 | 32 | yes |
| Scloudplus-384 | 33296 | 33296 | 40144 | 40144 | 33600 | 33600 | 48 | yes |
| Scloudplus-512 | 48016 | 48016 | 57872 | 57872 | 48320 | 48320 | 64 | yes |

Table 4 gives no secret-key column; the "sk spec" values are the spec's own
formula `sk = m*nbar*t/8 + n*nbar*2/8 + 16 + 2*h/8` (Algorithm 10) evaluated by
hand — they reproduce the observed sizes exactly at all five levels.

## Pseudocode

### Subroutines (spec §1.3)

```
gen(seedA) -> A in Z_q^{m x n}          # §1.3.2, packed10, row-at-a-time
  for row i:  raw <- XOF_family(seedA, i, L_A),  L_A = 10n/8
     AES  : AES-128-CTR under key seedA over blocks LE32(i*N_A + j) || 0^96
     SHAKE: SHAKE128(seedA || LE32(i), L_A)
     SM3  : SM3-pseudoXOF(seedA || LE32(i), L_A), output counter from 1
  parse raw as little-endian 10-bit coefficients, 4 per 5 bytes, row-major

BD(r, m, n, rho = 1/p) -> E in {-1,0,1}^{m x n}      # Algorithm 1
  b0,b1,... <- XOF_BD(r);  t <- ceil(log2 p)
  for each entry: repeat { a <- next t bits } until a < p ; x <- (a == 0)
                  repeat { b <- next t bits } until b < p ; y <- (b == 0)
                  e <- x - y
  (p = 2,4 are powers of two: rejection loop is vacuous; p = 6,12 reject)

Pack(C) = || Bit(c_ij, 10) row-major      # §1.3.4, byte aligned by construction
Packsk(S): ternary -> 2 bits (-1 -> 11, 0 -> 00, 1 -> 01), 4 per byte
```

### MsgEnc / MsgDec (spec §1.3.5, Algorithms 2-6, Appendix A for RBW)

```
MsgEnc(m):                                              # Algorithm 2
  split m into sigma blocks m_1..m_sigma, |m_j| = l_m/sigma
  for each j: w_j <- Label(BW_d, g = 2^tau, m_j) in Z[i]^{d/2}
  x <- (u_1,v_1,u_2,v_2,...) interleaving Re/Im per component
  x' <- x padded with zeros to length mbar*nbar
  M  <- (q/g) * x', laid out row-major into Z_q^{mbar x nbar}

Label(BW_d, g, m):                                      # Algorithm 3
  pad m to tau*d - (d/4)(k-1) bits; split into u_0..u_{d/2-1}, |u_j| = 2tau - wH(j)
  v_j <- f_{2tau - wH(j)}(u_j) in Z[i]
  for l = 1..k-1:  v <- (w_1, w_1 + phi*w_2, w_3, w_3 + phi*w_4, ...), phi = 1+i
  return [v] mod 2^tau
  (RBW_128: same, then multiply by phi — Appendix A)

MsgDec(D): invert the row-major layout, scale by g/q, run BDD, Delabel.
BDD(t, BW_d):                                           # Algorithm 6
  if d = 2: return round(t)
  split t = (t1,t2);  y1 <- BDD(t1), y2 <- BDD(t2)
  z1 <- BDD(phi^{-1}(t2 - y1)),  z2 <- BDD(phi^{-1}(t1 - y2))
  x <- (y1, y1 + phi*z1);  x' <- (y2 + phi*z2, y2)
  return whichever of x, x' is closer to t
  (Appendix B gives the exact integer versions; all arithmetic lives in 2^-t Z)
```

### KeyGen (Algorithms 7 and 10)

```
PKE.KeyGen():
  alpha <- {0,1}^h
  (seedA, r1, r2) <- PRF(alpha)            # |seedA| = 128, |r1| = |r2| = h
  A <- gen(seedA) in Z_q^{m x n}
  S <- BD(r1, n, nbar, rho_s);  E <- BD(r2, m, nbar, rho_e)
  B <- A*S + E  mod q
  return pk = Pack(B) || seedA,  sk' = Packsk(S)

KEM.KeyGen():
  (pk, sk') <- PKE.KeyGen();  hpk <- H(pk);  z <- U({0,1}^h)
  return pk, sk = sk' || pk || hpk || z
```

### Encaps (Algorithms 8 and 11)

```
KEM.Encaps(pk):
  m  <- U({0,1}^{l_ss})
  (r, k) <- G(m || H(pk))                  # |r| = |k| = h
  ct <- PKE.Enc(pk, m, r)
  ss <- KDF(k || ct)

PKE.Enc(pk, m, r):
  (B, seedA) <- pk;  A <- gen(seedA)
  (r1', r2') <- PRF(r)
  S'  <- BD(r1', mbar, m, rho_s)
  (E1, E2) <- BD(r2', mbar, n + nbar, rho_e)     # one continuous stream, E1 first
  M   <- MsgEnc(m)
  C1 <- S'*A + E1 mod q ;  C2 <- S'*B + E2 + M mod q
  return Pack(C1) || Pack(C2)
```

### Decaps (Algorithms 9 and 12)

```
KEM.Decaps(sk, ct):
  (sk', pk, hpk, z) <- sk
  m'  <- PKE.Dec(sk', ct)                  # D = C2 - C1*S mod q ; m' = MsgDec(D)
  (r', k') <- G(m' || hpk)
  ct' <- PKE.Enc(pk, m', r')
  if ct = ct': ss <- KDF(k' || ct)  else  ss <- KDF(z || ct)      # implicit rejection
```

### Symmetric instantiation (spec §2.1, Tables 5-6)

```
domain separation: one fixed label byte prepended,  F:0x46  G:0x47  H:0x48  K:0x4b
AES / SHAKE family : F, G, KDF = labeled SHAKE-256
                     H = labeled SHA3-512 when h = 512, else labeled SHAKE-256
SM3 family         : F, G, KDF = labeled SM3 pseudo-XOF, H = labeled SM3 pseudo-hash
A generation       : AES-128-CTR / SHAKE-128 / SM3 pseudo-XOF
BD sampling XOF    : SHAKE-128 for levels 128, 192 ; SHAKE-256 for 256, 384, 512
                     (SM3 family: bounded SM3 pseudo-XOF at every level)
```

## Implementation vs specification

What was checked. The 15 leaf directories `Scloudplus-<L>/kem/` hold only
`parameters.h` plus a forwarding API file; the code is shared and lives in
`Implementations and Test_Vectors/Implementations/_shared/`:
`scloudplus_core/common/kem.c` (FO transform), `common/pke.c` (Algorithms 7-9),
`common/sample.c` (Algorithm 1 / §2.2 BD parsing), `common/encode.c`
(MsgEnc/MsgDec, Label/Delabel, BDD), `ref/matrix_reference.c` (gen and the four
matrix products), `ref/pack_reference.c` (Pack/Unpack/Packsk),
`common/hash_aes_shake.c` and `common/hash_sm3_portable.c` +
`ref/sm3_reference.c` (F/G/H/K), `api_pkc/KEM_AlgorithmInstance.c` and
`api_pkc/kat_random.c` (ICCS API).

Agreements worth stating:

- **Every structural parameter of all five levels matches spec Tables 2 and 3**
  (not a sample — the whole of m, n, mbar, nbar, rho_s, rho_e, tau, sigma, d, h
  was compared). `scloudplus_secret_bd`/`error_bd` hold p = 1/rho directly.
- All 15 pk/sk/ct/ss sizes match the spec, including the secret-key layout
  `sk' || pk || H(pk) || z` implied by Algorithm 10.
- Randomness is drawn only through `randombytes()`, which in the harness build
  is `api_pkc/kat_random.c` -> `get_random_number(&drng_algorithm, ...)`, i.e.
  the official seeded DRNG. `alpha` (keygen coins), `z` and the FO message `m`
  are the only three calls, matching Algorithms 7, 10 and 11. `common/random.c`
  (getrandom/urandom) exists in the tree but is not linked for the KAT build.
- The FO transform in `common/kem.c` is complete and correct: `m || H(pk)` is
  hashed by G (public-key binding present), decapsulation re-encrypts with the
  *stored* pk, the ciphertext comparison is the branch-free
  `scloudplus_verify`/`scloudplus_cmov` pair, and the shared secret is
  `KDF(k'||ct)` or `KDF(z||ct)` with `ct` always the *received* ciphertext.
- The four domain-separation label bytes 0x46/0x47/0x48/0x4b are present exactly
  as spec §2.1 states (`common/hash_aes_shake.c:750-753`), and H switches from
  labeled SHA3-512 to labeled SHAKE-256 precisely when `h > 512`
  (`hash_aes_shake.c:802-816`), as the spec requires for levels 384 and 512.
- The BD sampler's XOF selection is driven by the BD parameter rather than by
  the level name (`common/sample.c:43-50`: SHAKE-256 iff p in {6,12}), which for
  these five parameter sets yields exactly the spec's "SHAKE-128 for 128/192,
  SHAKE-256 for 256/384/512". Equivalent, and it would stay correct if levels
  were re-tuned, but it is an indirect encoding of the spec's rule.
- BD byte parsing matches spec §2.2 bit for bit: p = 2 gives `b1 - b0` from each
  bit pair (`sample.c:186-191`), p = 4 tests the low then the high two bits of a
  nibble (`sample.c:236-242`), p = 6/12 use little-endian 3-/4-bit candidates
  with rejection at 6,7 / 12..15. `pke_enc` draws E1 and E2 from one continuous
  stream with all of E1 first (`common/pke.c:112`, `sample_e12`), as §2.2 states.
- `gen` matches §2.2: the AES path uses counter `row * N_A + j` with the
  zero-padded block and discards padding past L_A; the SHAKE path is
  `SHAKE128(seedA || LE32(row), L_A)`; the 10-bit little-endian unpacking in
  `unpack10_x4` (`ref/matrix_reference.c:73-79`) is exactly the spec's a0..a3
  formulas.
- Pack10 masks to the low 10 bits on write and reads 10 bits on parse
  (`ref/pack_reference.c:38-41, 62-65`), so the ciphertext and public-key
  encodings are canonical: every byte string of the right length decodes to
  exactly one matrix and there are no unused high bits to abuse.

No deviation found. Two observations, both benign, neither a deviation:

- (c, deliberate equivalent) `pke.c:26-27` disables the pre-pack `reduce_c1`/
  `reduce_c2` passes (`SCLOUDPLUS_PKE_KEEP_REDUCE_BEFORE_PACK 0`) because
  `mat_add`/`mat_sub` already reduce and Pack10 masks the low 10 bits. Since
  q = 2^10 the uint16 arithmetic is exact modulo q anyway; the serialized bytes
  are unchanged.
- (b, spec ambiguity — no security impact here) `unpack_sk_coeff`
  (`ref/pack_reference.c:146-153`) sign-extends any 2-bit value with the high
  bit set, so the codeword 10 (binary), which spec §1.3.4 never produces, decodes
  to -2 rather than being rejected. The secret key is not attacker-supplied in
  the KEM API (`kem_dec` only checks the length), so this is an
  unreachable non-canonical acceptance, not an exploitable one. Worth noting
  only because the spec describes Unpacksk as the exact inverse of a three-symbol
  alphabet.

Coverage. Verified by reading: parameters, FO transform, PKE control flow,
matrix generation, BD sampling, packing, and the symmetric instantiation table.
The Label/Delabel/BDD code in `common/encode.c` was read structurally (the
phi and phi^{-1} helpers, the k-1 butterfly layers of `apply_bw_layers`/
`undo_bw_layers`, the RBW extra phi multiply at `encode.c:481-486` and
`503-508`, the two-candidate distance comparison in `bddbwn`) and matches the
shape of Algorithms 3-6 and Appendix A, but the integer rounding conventions of
Appendix B were **not** checked term by term — that is the one step in this
candidate I did not verify in full. All 15 instances reproduce the submitted
KATs (RESULTS.md: 15/15 PASS), which is strong evidence that the coder is
self-consistent with the vectors, though not that it matches Appendix B.
