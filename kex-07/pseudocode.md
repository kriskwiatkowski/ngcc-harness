# kex-07 NEV-AKE — algorithm summary

A two-pass authenticated key exchange in the CK+ model, built by the generic
ROM/QROM construction **GC-AKE** from one OW-CPA PKE and one OW-CPA KEM, both
instantiated from the NEV family over `Rq = Zq[x]/(x^n+1)` (decisional NTRU +
sspRLWE). Each party has a long-term NTRU key `h = g/f` with `f = f' + v^{-1}`
and a long-term random string `s`; each session adds an ephemeral NTRU KEM key
pair. Authentication comes from the two static-key encryptions `c_j` (to the
responder) and `c_i` (to the initiator); forward secrecy from the ephemeral KEM.
The FO transform is *decomposed*: only derandomisation (`rho = G(m)`) and a
re-encryption check are used, with implicit rejection into `H_init`/`H_resp`.
The distinctive component is the randomised vector encoding
`Pt2noise`/`Noise2Pt`, which encodes one message bit across `k = 4` coefficients.

Specification: `kex-07-spec.pdf` (110 pages), §3 + Fig. 5 + Alg. 1-4 (GC-AKE),
§4.1 (Pt2noise/Noise2Pt, Lemma 3), §4.2 (NEV-PKE-OW, NEV-KEM-OW, Remark 7),
§5 + Table 2 (parameters), §6 (implementation details), §8 (proof).
English-language spec.

## Parameters

The spec's Table 2 gives **six** sets (C1/C2/C3 "compact" and R1/R2/R3
"recommended"), plus C1*/C2*/C3*, the compressed variants which "use the same
parameters" and differ only in `chi_r = T*_{1/3}` (rounding) instead of
`T_{1/3}`. The submission builds **nine** instances: the six plus the three
compressed ones (directory suffix `-c`, label suffix `_C`). `k = 4` and
`v = 1 - x^{n/4}` throughout.

| spec set | impl label | `n` | `q` | `chi_f` | `chi_g` | `chi_r` | `chi_e` | compressed | dec. failure | target |
|---|---|---|---|---|---|---|---|---|---|---|
| NEV-AKE-C1 | `NEV_AKE_512_769` | 512 | 769 | B1 | B2 | T_1/3 | B2 | no | 2^-160 | >=128 C / >=80 Q |
| NEV-AKE-C1* | `NEV_AKE_512_769_C` | 512 | 769 | B1 | B2 | T*_1/3 | B2 | yes | 2^-160 | >=128 |
| NEV-AKE-R1 | `NEV_AKE_512_1409` | 512 | 1409 | B3 | B3 | B3 | B3 | no | 2^-133 | >=128 |
| NEV-AKE-C2 | `NEV_AKE_1024_769` | 1024 | 769 | B1 | T_1/8 | T_1/3 | B2 | no | 2^-162 | >=256 |
| NEV-AKE-C2* | `NEV_AKE_1024_769_C` | 1024 | 769 | B1 | T_1/8 | T*_1/3 | B2 | yes | 2^-162 | >=256 |
| NEV-AKE-R2 | `NEV_AKE_1024_1409` | 1024 | 1409 | B2 | B2 | B2 | B2 | no | 2^-158 | >=256 |
| NEV-AKE-C3 | `NEV_AKE_2048_769` | 2048 | 769 | T_1/8 | T_1/8 | T_1/3 | B1 | no | 2^-163 | >=512 |
| NEV-AKE-C3* | `NEV_AKE_2048_769_C` | 2048 | 769 | T_1/8 | T_1/8 | T*_1/3 | B1 | yes | 2^-163 | >=512 |
| NEV-AKE-R3 | `NEV_AKE_2048_1409` | 2048 | 1409 | T_1/3 | T_1/3 | T_1/3 | B2 | no | 2^-147 | >=512 |

Core-SVP / MATZOV† estimates (Table 2): NTRU-primal (C,Q) and RLWE MATZOV†
respectively — C1 (132,116)/129, R1 (135,119)/134, C2 (266,234)/268,
R2 (284,250)/261, C3 (546,480)/521, R3 (583,513)/526. The spec **recommends
R1/R2/R3** and says C*/C variants carry a rounding assumption and heuristic
independence; it calls the uncompressed form "a better choice for
standardization".

Session-key / seed length: `SEED_BYTES` = 16 / 32 / 64 for `n` = 512 / 1024 /
2048, matching the plaintext space `{0,1}^{n/k}` = 128 / 256 / 512 bits.

Sizes (bytes), computed from the spec's formulas vs the built reference library
(`OBSERVED/kex-07.txt`). Here `P` = `POLY_BYTES` (packed `Rq` element) and
`S` = `SEED_BYTES`:

| instance | `P` | pk = `P` | sk = `2P+S` | `M1`/`M2` | sta = `3P+S` or `2P+S+ct` | stb = `S` | ss = `S` | impl pk/sk/msgs/sta/stb/ss | match |
|---|---|---|---|---|---|---|---|---|---|
| `NEV_AKE_512_769` | 615 | 615 | 1246 | 1230 | 1861 | 16 | 16 | 615/1246/1230/1861/16/16 | yes |
| `NEV_AKE_512_769_C` | 615 | 615 | 1246 | 1127 | 1758 | 16 | 16 | 615/1246/1127/1758/16/16 | yes |
| `NEV_AKE_512_1409` | 672 | 672 | 1360 | 1344 | 2032 | 16 | 16 | 672/1360/1344/2032/16/16 | yes |
| `NEV_AKE_1024_769` | 1229 | 1229 | 2490 | 2458 | 3719 | 32 | 32 | 1229/2490/2458/3719/32/32 | yes |
| `NEV_AKE_1024_769_C` | 1229 | 1229 | 2490 | 2253 | 3514 | 32 | 32 | 1229/2490/2253/3514/32/32 | yes |
| `NEV_AKE_1024_1409` | 1344 | 1344 | 2720 | 2688 | 4064 | 32 | 32 | 1344/2720/2688/4064/32/32 | yes |
| `NEV_AKE_2048_769` | 2458 | 2458 | 4980 | 4916 | 7438 | 64 | 64 | 2458/4980/4916/7438/64/64 | yes |
| `NEV_AKE_2048_769_C` | 2458 | 2458 | 4980 | 4506 | 7028 | 64 | 64 | 2458/4980/4506/7028/64/64 | yes |
| `NEV_AKE_2048_1409` | 2688 | 2688 | 5440 | 5376 | 8128 | 64 | 64 | 2688/5440/5376/8128/64/64 | yes |

All nine agree exactly. The compressed variants replace the PKE ciphertext size
`P` by `n` bytes (`R769 -> R256`), a 16.7% ciphertext reduction as §5 states.

## Pseudocode (pass structure)

`kex_get_passes_num() = 2` (matches OBSERVED `passes=2`). A = initiator `P_i`,
B = responder `P_j`.

### Init_A / Init_B — spec Alg. 1 `GC-AKE.KeyGen`

```
Init_X():
 1  (f', g) <- chi_f x chi_g, resampling until f = f' + v^{-1} and g are invertible
 2  pk <- h = g/f  in Rq                       # P bytes
 3  s  <- {0,1}^{8*S}                          # long-term reject string
 4  sk <- (f, pk, s)                           # P + P + S bytes
 5  st <- 0                                    # sta = 3P+S zeroed, stb = S zeroed
```

### pass1 (A -> B): `M = (c_j, pk~)` — spec Alg. 2 `GC-AKE.Init`

```
Pass1(sk_A, pk_B):
 1  m_j  <- {0,1}^{8*S}                        # note: sk_A is unused here (per spec)
 2  rho  <- G(m_j)                             # G = KDF(0x01 || m_j)
 3  c_j  <- PKE-OW.Enc(pk_B, m_j ; rho)        # derandomised
 4  (pk~, sk~) <- KEM-OW.KeyGen()              # ephemeral NTRU key pair
 5  M    <- c_j || pk~
 6  st_A <- (pk~, sk~, m_j, c_j)               # sta = 3P + S bytes
```

Message contents: `M1 = c_j || pk~` (`PKE_OW_CT_BYTES + POLY_BYTES`).
State after pass1: A holds the ephemeral key pair, `m_j` and `c_j`; B holds
nothing yet.

### pass2 (B -> A): `M' = (c_i, c~)` — spec Alg. 3 `GC-AKE.Der_resp`

```
Pass2(sk_B, pk_A, M):
 1  (c_j, pk~) <- parse(M)
 2  m_i  <- {0,1}^{8*S}
 3  c_i  <- PKE-OW.Enc(pk_A, m_i ; G(m_i))
 4  (K~, c~) <- KEM-OW.Encap(pk~)
 5  m_j' <- PKE-OW.Dec(sk_B, c_j)
 6  M'   <- c_i || c~
 7  fail <- [ c_j != PKE-OW.Enc(pk_B, m_j' ; G(m_j')) ]      # re-encryption check
 8  K_good <- H     (m_i, m_j', K~, i, j, M, M')
 9  K_bad  <- H_resp(s_B, m_i, c_j, K~, i, j, M, M')
10  K_B    <- cmov(K_good, K_bad, fail)                      # implicit rejection
11  st_B <- K_B                                              # stb = S bytes
```

Message contents: `M2 = c_i || c~`. State after pass2: B holds the finished
session key.

### DeriveSS_A — spec Alg. 4 `GC-AKE.Der_init`

```
DeriveSS_A(sk_A, st_A, M'):
 1  (pk~, sk~, m_j, c_j) <- st_A ;  M <- c_j || pk~
 2  m_i' <- PKE-OW.Dec(sk_A, c_i)
 3  K~'  <- KEM-OW.Decap(sk~, c~)                 # never outputs bottom
 4  fail <- [ c_i != PKE-OW.Enc(pk_A, m_i' ; G(m_i')) ]
 5  K_good <- H     (m_i', m_j, K~', i, j, M, M')
 6  K_bad  <- H_init(s_A, c_i, m_j, K~', i, j, M, M')
 7  return cmov(K_good, K_bad, fail)
```

### DeriveSS_B

```
DeriveSS_B(st_B): return st_B          # the key computed during pass2
```

### NEV-PKE-OW / NEV-KEM-OW — spec §4.2

```
KeyGen : f' <- chi_f ; g <- chi_g ; f = f' + v^{-1} ; require f, g invertible
         pk = h = g/f ;  sk = f
Enc(h, M; rho) : r <- chi_r ; m <- Pt2noise(M, eta) ; c = h*r + m
Dec(f, c)      : u = f*c ;  M' = Noise2Pt(u)
Encap(h)       : r <- chi_r ; m <- B_eta ; c = h*r + m ; K = Ext(v_bar * m mod 2)
Decap(f, c)    : u = f*c ; K = Noise2Pt(u)          # identical to Dec
```

Compressed variant (spec Remark 7): `pk = h^{-1}`, `sk = g`,
`c' = round( h^{-1} m * 256/769 ) in R_256`, `Dec: u = g * decompress(c')`.
The rounding error takes the place of `r`, so `chi_r` becomes `T*_{1/3}`.

### Vector encoding / decoding — spec §4.1 (the novel component)

`v = 1 - x^{n/k}`, `v^{-1} = ((q+1)/2)(1 + x^{n/k} + ... + x^{(k-1)n/k})`.

```
Pt2noise(M, eta):  sample s_0..s_{2k*eta-2} <- {0,1}^{n/k}
                   s_{2k*eta-1} <- M XOR (XOR_i s_i)       # secret-sharing of M
                   m_{i*n/k + j} <- sum_t ( s_{2i*eta+t, j} - s_{2i*eta+eta+t, j} )
Noise2Pt(w):       w~_i <- (w_i - (q+1)/2) mod+- q
                   t_j  <- sum_{i = j mod n/k} |w~_i|
                   M_j  <- 1 if t_j < k*(q-1)/4 else 0
```

Each message bit is spread over `k = 4` coefficients whose parities XOR to it,
so decoding only needs the *sum* of four absolute values to stay below
`k(q-1)/4` (Lemma 3) — a much weaker condition than per-coefficient decoding.

## Implementation vs specification

Checked: `kex-07/src/NEV_AKE_512_769/{params.h, ake.c/h, owpke.c, owkem.c,
pack.c, poly.c, verify.c, kat_test/KEX_AlgorithmInstance.c}`. `ake.c`,
`params.h` and `kat_test/KEX_AlgorithmInstance.c` are **byte-identical across
all nine instance directories** (verified by `diff`); the parameter set is
selected by `-DPARAMS=N` and `-DUSE_ICCS` from the build.

Agreements:

- **All nine parameter sets match Table 2.** `params.h` encodes the
  distributions as `ETA_*` with `9 = T_{1/3}` and `8 = T_{1/8}` (per the
  in-file comment). C1 `(1,2,9,2)`, R1 `(3,3,3,3)`, C2 `(1,8,9,2)`,
  R2 `(2,2,2,2)`, C3 `(8,8,9,1)`, R3 `(9,9,9,2)` map exactly onto Table 2's
  `(chi_f, chi_g, chi_r, chi_e)`. `COMPRESS` is 1 only in the three `-c`
  directories, i.e. the C1*/C2*/C3* rows.
- **All 54 byte lengths (9 instances x 6 quantities) match** the size formulas
  and the OBSERVED values (table above), including the compressed variants'
  `PKE_OW_CT_BYTES = n`.
- **GC-AKE flow**: `ake_init` = Alg. 2, `ake_der_response` = Alg. 3,
  `ake_der_init` = Alg. 4, step for step, with the hash arguments in exactly
  the order Fig. 5 and Alg. 3/4 prescribe (`H(m_i, m_j, K~, i, j, M, M')`,
  `H_resp(s_j, m_i, c_j, K~, ...)`, `H_init(s_i, c_i, m_j, K~', ...)`).
  `ake_init` correctly ignores `ski` and `ake_der_init` correctly ignores
  `pkj`, matching the algorithm inputs.
- **Implicit rejection is constant time.** Both `K_good` and `K_bad` are always
  computed and selected with `cmov` (`verify()` returns exactly 0/1 and `cmov`
  is the standard masked move), so no branch or timing channel depends on the
  re-encryption result. The four hashes carry distinct 1-byte domain separators
  `0x01..0x04` (an improvement over the spec, which only models them as
  independent random oracles).
- **NEV-PKE-OW** (`owpke.c`, `COMPRESS==0`): keygen computes `h = g * f^{-1}`
  with `f = f' + v^{-1}` (`poly_add_vinv` adds `(q+1)/2` at the four positions
  `0, NTT_DIM/4, NTT_DIM/2, 3*NTT_DIM/4`, i.e. `v^{-1}` in the permuted NTT
  layout), stores `sk = f`; enc computes `h*r + Pt2noise(m)`; dec computes
  `f*c` then `Noise2Pt`. Exactly §4.2.
- **Compressed variant** (`COMPRESS==1`): keygen stores `pk = f/g = h^{-1}`
  and `sk = g`; enc computes `h^{-1} * Pt2noise(m)` with **no additive `r`**,
  then `poly_compress`; dec multiplies by `g`. This is precisely Remark 7's
  `c' = round(h^{-1} m * 256/769)` with the rounding error absorbing `r`.
- **`poly_compress`** is `((a*341 + 469) >> 10) & 0xff`. I checked all 769
  inputs: it equals `floor(a*256/769 + 1/2) mod 256` exactly — the unusual
  constant 469 (rather than the naive 512) is a correct fixed-point tuning, not
  a bug. `poly_decompress` is `round(a*769/256)`.
- **`Noise2Pt` block indexing.** `poly_tomsg` groups coefficients at offsets
  `+NTT_DIM/4, +NTT_DIM/2, +3*NTT_DIM/4` inside blocks of `NTT_DIM`, not at
  `+n/4, +n/2, +3n/4` as §4.1 literally states. I worked through the partial-NTT
  layout of §6.1 (`a(x) = sum_l x^l a_l(x^{n/NTT_DIM})`, sub-polynomial `l`
  stored contiguously at offset `NTT_DIM*l`): under that permutation the spec's
  group `{j, j+n/4, j+n/2, j+3n/4}` maps exactly onto the implementation's
  offsets. **Not a bug** — but it is only correct because of the permuted
  storage, and the specification never states the storage order, so this is
  easy to get wrong when reimplementing.

Discrepancies:

- **(a) REAL DEFECT — the party identities `i` and `j` are hard-wired to
  all-zero.** `kat_test/KEX_AlgorithmInstance.c:105-106` and `:165-166`
  declare `unsigned char idi[SEED_BYTES] = {0}; unsigned char idj[SEED_BYTES]
  = {0};` and pass them to `ake_der_response` / `ake_der_init`. Every one of
  the nine instances does this. In GC-AKE (Fig. 5, Alg. 3 line 8, Alg. 4
  line 5) the session key is `H(m_i, m_j, K~, i, j, M, M')` — the identities
  are an explicit input, and the CK+ proof in §8 relies on them to bind the key
  to the intended peers. With both set to zero: (i) the key has **no identity
  binding whatsoever**, so the unknown-key-share / identity-misbinding
  protection the model requires is not present; (ii) `i == j`, so the key is
  also symmetric in the two identity slots and cannot distinguish the initiator
  role from the responder role. The NGCC KEX API does not carry identity
  strings, but the wrapper *does* receive `pka` in `kex_generate_pass2_msg_b`
  and `pkb` in `kex_derive_ss_a` and could have bound the public keys as
  identities (the usual substitute); it does not. The keys still bind to `M`
  and `M'`, which contain ciphertexts under `pk_i` and `pk_j`, so this is not
  an immediate key-recovery break, but it removes a stated input of the
  algorithm and voids the identity part of the security argument.
  **Highest-value finding for this candidate.**
- **(a) off-by-one in the `Noise2Pt` centring constant and threshold.**
  §4.1 defines `w~_i = (w_i - (q+1)/2) mod+- q` and `M_j = 1 iff t_j <
  k(q-1)/4`. `flipabs()` (`pack.c:355-363`) computes `|w_i - floor(q/2)|`,
  i.e. it centres at `(q-1)/2` (384 for `q = 769`, 704 for `q = 1409`) rather
  than `(q+1)/2`; and `poly_tomsg` decides on `t - q < 0`, i.e. threshold `q`
  rather than `k(q-1)/4 = q-1`. Both constants are one larger/smaller than the
  specification's. Algebraically the implementation's `|w~|` equals the spec's
  evaluated at `w+1`, so the decision region is shifted by one unit out of `q`.
  Given decryption-failure probabilities of `2^-133` to `2^-163` and decoding
  margins of hundreds, the effect on correctness and security is nil, but it is
  a genuine constant mismatch and would make a spec-exact independent
  implementation disagree with the reference on (astronomically rare)
  boundary inputs. Spec and code should be reconciled.
- **(b) the submission ships nine instances where the spec tables six.** The
  three `-c` instances are the C1*/C2*/C3* rows, which §5 and Remark 7
  explicitly flag as relying on a rounding-based (sspRLWR) assumption plus the
  Kyber-style coefficient-independence heuristic, and which the spec itself
  says are "intended for those who are comfortable with the aforementioned
  weaknesses" while "the non-compression version is a better choice for
  standardization". Submitting them as first-class instances alongside the
  recommended R sets is at odds with the specification's own recommendation,
  and Table 2 gives no separate security or failure numbers for them.
- **(b) the KEM ciphertext is not compressed in the compressed variants.**
  With `COMPRESS == 1`, `PKE_OW_CT_BYTES = n` but `KEM_OW_CT_BYTES =
  POLY_BYTES`. Remark 7 says the compression "property also extends to other
  schemes in the NEV family", so a reader may expect `c~` to shrink too. It
  does not; the saving is 8.4% of `M1`, not 16.7%. Not a deviation from any
  explicit statement, but the spec's 16.7% figure is about the ciphertext
  alone and could be misread as the protocol bandwidth.
- **(b) `kex_generate_pass3_msg_a` returns -1** rather than a benign
  "no such pass" value; harmless here because `kex_get_passes_num() = 2`, but
  it differs from kex-06's convention of returning 0 from the unused-pass
  stubs. Cosmetic, noted for cross-candidate consistency.
- **Not verified:** the CK+ proof of §8, the decryption-failure probabilities
  of Table 2, the core-SVP/MATZOV† estimates, the NTT/partial-NTT arithmetic
  beyond the layout argument above, the invertibility rejection loops in
  `ow_pke_keypair` (which are variable-time in the number of retries — a
  standard and accepted NTRU behaviour, since the retry count depends only on
  fresh randomness), and the AVX2 track. All nine instances pass the candidate
  KATs in the build (`kex-07/security_findings.md`).
