# sign-09 DOVE — algorithm summary

DOVE ("Double Oil and Vinegar") is a multivariate UOV-family hash-and-sign
signature over `F_256`. Its distinguishing trick (spec §3.1, §4.2) is that the
vinegar-by-vinegar public blocks are not sampled freely but factorised as
`P_{i,1} ~ A_{k1} A_{k2}` from only `l = ceil(sqrt(m))` base matrices `A_k`,
shrinking the public key. Hardness: MQ / UOV key recovery; claim is EU-CMA
(§2, p. 4). Two variants: `DOVE_pkc_skc` (seed-compressed pk, seed-only sk,
§3.2 / Figure 3) and `DOVE_classic` (fully expanded keys, §3.3 / Figure 4).

Specification: `sign-09-spec.pdf` (27 pages), §3 "Specification Description"
(Figures 2-4), parameters §3.4 (Tables 1-2), security estimates §6 (Tables 5-6).

## Parameters

Field `F_q = F_2[x]/(x^8+x^4+x^3+x+1)`, `q = 2^r = 256`, `r = 8`; multi-byte
counters fed to the hash are little-endian (§3.4).

| parameter | DOVE128 | DOVE256 | DOVE512 | meaning |
|---|---|---|---|---|
| o = m | 44 | 96 | 216 | oil vars = number of equations |
| n = v+o | 112 | 256 | 576 | total variables |
| v | 68 | 160 | 360 | vinegar variables (n−o) |
| q = 2^r | 256 | 256 | 256 | field size |
| l | 7 | 10 | 15 | base matrices `A_k`, `l = ceil(sqrt(m))` |
| salt_bytes | 24 | 40 | 72 | salt length |
| sk_seed_bytes | 24 | 40 | 72 | secret seed |
| pk_seed_bytes | 16 | 16 | 16 | public seed |
| claimed classical | 128 | 263 | 522 | bits, Table 5 min vs required 128/256/512 |
| claimed quantum | 120 | 233 | 486 | bits, Table 6 min vs required 80/128/256 |

Sizes (bytes), specification (Table 2, p. 10) vs the built reference library:

| instance | pk spec | pk impl | sk spec | sk impl | sig spec | sig impl | match |
|---|---|---|---|---|---|---|---|
| dove_classic_128 | 191,646 | 191646 | 192,990 | 192990 | 136 | 136 | yes |
| dove_classic_256 | 2,050,352 | 2050352 | 1,925,976 | 1925976 | 296 | 296 | yes |
| dove_classic_512 | 22,833,052 | 22833052 | 20,181,508 | 20181508 | 648 | 648 | yes |
| dove_pkc_skc_128 | 43,576 | 43576 | 24 | 24 | 136 | 136 | yes |
| dove_pkc_skc_256 | 446,992 | 446992 | 40 | 40 | 296 | 296 | yes |
| dove_pkc_skc_512 | 5,062,192 | 5062192 | 72 | 72 | 648 | 648 | yes |

All 12 sizes agree exactly. §3.4's formulae
`pk = pk_seed_bytes + m*o(o+1)/2`, `sk = sk_seed_bytes`, `sig = n + salt_bytes`
reproduce the pkc_skc rows.

## Pseudocode

`SM3(x, L)` is the spec's name for the submission-wide KDF-SM3 XOF; `‖ctr` is a
little-endian counter suffix. `Upper(A)` is Figure 2 (fold `A[j,i]` into
`A[i,j]` for `j>i`, zero the lower triangle). Arithmetic is in `F_256`, so
`−x = x`.

### KeyGen — DOVE_pkc_skc (Figure 3, lines 1-10)
```
1  seed_sk <- {0,1}^sk_seed_bytes
2  (seed_pk, T) := SM3(seed_sk, pk_seed_bytes + v*o)        # T in F_q^{v x o}
3  for k = 0 .. l-1:
4      A_k := SM3(seed_pk ‖ k, v(v+1)/2)                    # upper-triangular v x v
5      B_k = T^t A_k  (o x v),   C_k = A_k T  (v x o)
6  for i = 0 .. m-1:
7      P_{i,2} := SM3(seed_pk ‖ (l+i), v*o)                 # v x o
8      k1 = floor(i/l),  k2 = i - k1*l
9      P_{i,3} = Upper( -B_{k1} C_{k2} - T^t P_{i,2} )      # o x o
10 return pk = (seed_pk, {P_{i,3}}), sk = seed_sk
```
`DOVE_classic` KeyGen (Figure 4) is the same computation but returns expanded
`pk = (seed_pk, {A_k}, {P_{i,2}}, {P_{i,3}})` and
`sk = (seed_sk, seed_pk, T, {A_k}, {B_k}, {C_k}, {P_{i,2}})`.

### Sign (Figure 3 lines 1-19 = pkc_skc; Figure 4 lines 1-16 = classic)
```
1  (seed_pk, T) := SM3(seed_sk, pk_seed_bytes + v*o)        # classic: read from sk
2  t := SM3(msg ‖ seed_pk, m)                               # target in F_q^m
3  salt := SM3(seed_sk ‖ t, salt_bytes)
4  for ctr = 0 .. 255:
5      v := SM3(t ‖ seed_sk ‖ ctr, v)                       # vinegar vector
6      for k = 0 .. l-1:
7          A_k := SM3(seed_pk ‖ k, v(v+1)/2)                # classic: from sk
8          x_k = v^t A_k,   y_k = A_k v
9          B_k = T^t A_k,   C_k = A_k T                     # classic: from sk
10     for i = 0 .. m-1:
11         P_{i,2} := SM3(seed_pk ‖ (l+i), v*o)             # classic: from sk
12         k1 = floor(i/l),  k2 = i - k1*l
13         w[i]   := <x_{k1}, y_{k2}>
14         L[i,:] = v^t P_{i,2} + x_{k1} C_{k2} + y_{k2}^t B_{k1}^t
15     if L (m x o) invertible:
16         z = L^{-1} (t - w)
17         s = (v + T z) ‖ z                                # s in F_q^n
18         return sigma := (s, salt)
19 return 0                                                 # fail after 256 tries
```

### Verify (Figure 3 lines 1-11 = pkc_skc; Figure 4 lines 1-10 = classic)
```
1  t := SM3(msg ‖ seed_pk, m)
2  v = s[0 : v-1],  z = s[v : n-1]
3  for k = 0 .. l-1:
4      A_k := SM3(seed_pk ‖ k, v(v+1)/2)                    # classic: read from pk
5      x_k = v^t A_k,  y_k = A_k v
6  for i = 0 .. m-1:
7      P_{i,2} := SM3(seed_pk ‖ (l+i), v*o)                 # classic: read from pk
8      k1 = floor(i/l),  k2 = i - k1*l
9      w[i] := <x_{k1}, y_{k2}> + v^t P_{i,2} z + z^t P_{i,3} z
10 return (t == w)
```
The salt is an input to no hash in Verify, and not to `t` in Sign.

### Hash / XOF
```
SM3(x, L)       = KDF-SM3 counter mode (auxfunc.c:482 pseudoXOF):
                  sm3_bit(x ‖ BE32(1)) ‖ sm3_bit(x ‖ BE32(2)) ‖ ... trunc to L
SM3(x ‖ ctr, L) = pseudoXOF(x ‖ LE16(ctr), L)   (auxfunc.c:26)
```
The XOF's internal block counter is 32-bit big-endian while the DOVE-level index
(`k`, `l+i`, `ctr`) is 2-byte little-endian per §3.4. No domain-separation tag
exists between the five call sites; separation rests only on input shape and on
the `k` vs `l+i` index range.

## Implementation vs specification

**Checked.** Sources built per `sign-09/Makefile` (`gf256.c`, `matrix.c`,
`uov/blas_matrix_ref.c`, `auxfunc.c`, `drng.c`, `SIG_AlgorithmInstance.c`) under
`Implementations/.../Reference_Implementation/DOVE_{pkc_skc,classic}_ref/`; all
six labels build from these two directories via `-DDOVE_PARAM_SET`. KeyGen /
Sign / Verify read line-by-line in `DOVE_pkc_skc_ref/SIG_AlgorithmInstance.c`;
length functions and key-layout macros in the classic variant. Nothing built or
run; sizes taken from the observed table. KAT: 6/6 PASS
(`sign-09/security_findings.md`).

**Parameter spot-check** (sampling: all 8 constants of DOVE128, plus `o,n,v,l`
for DOVE256 and DOVE512 = 16 of 24): every value in
`DOVE_pkc_skc_ref/SIG_AlgorithmInstance.h:39-64` matches Table 1, as do
`DOVE_R 8`, `DOVE_Q 256` and `UPPER_SIZE(n) = n(n+1)/2`. Index arithmetic
`k1 = i/DOVE_L`, `k2 = i % DOVE_L` matches Figure 3 line 12; `matrix_add` (XOR)
correctly realises the spec's minus signs in characteristic 2; the three hash
inputs and the 256-iteration retry loop match Figure 3 lines 2-5 exactly.

**Discrepancy 1 — out-of-bounds read of the secret key (real deviation,
memory safety).** `DOVE_pkc_skc_ref/SIG_AlgorithmInstance.c:166-168`: `sig_sign`
does `T_data = sk + DOVE_SK_SEED_BYTES; matrix_fill(T, T_data);`, reading `v*o`
bytes (2,992 / 15,360 / 77,760) past a secret key the same file declares to be
24/40/72 bytes (`sig_get_sk_len_bytes`, line 44). `sig_keygen` writes only the
seed — the matching `matrix_dump(T, sk_ptr)` is commented out at line 141. The
garbage `T` is overwritten one line later by `derive_seedpk_T` (line 171), so
the scheme stays correct and KATs pass, but any caller allocating exactly
`sig_get_sk_len_bytes()` bytes takes a heap over-read on every signature.
Consistent with the "original backing buffer remained readable" note in
`security_findings.md`.

**Discrepancy 2 — inert salt; §6.1.1.1 contradicts §3.2/§3.3 (spec-internal
inconsistency, faithfully implemented).** Figures 3 and 4 set
`t = SM3(msg ‖ seed_pk)` with no salt, and Verify never reads the salt. But the
security analysis in §6.1.1.1 (p. 18) analyses `P(s) = Hash(µ ‖ salt)` and
derives its `q^m/(q-1)` collision bound by *searching over Y salts* — an
argument that does not apply to the algorithm as specified. The implementation
follows the algorithm boxes (`DOVE_pkc_skc_ref/SIG_AlgorithmInstance.c:174-180`
and `:318-325`), so the trailing `salt_bytes` field is unauthenticated: set it
to anything and the signature still verifies. This is the mechanism behind the
already-confirmed `signature-encoding-malleability` finding. It is not an
EUF-CMA break (only EU-CMA is claimed), but it voids the salted-collision
argument.

**Discrepancy 3 — Figure 4's Sign argument list omits `seed_pk` (spec
ambiguity, harmless).** Line 1 of that box uses `seed_pk`; Figure 4 KeyGen
line 11 does place it in `sk`, and
`DOVE_classic_ref/SIG_AlgorithmInstance.c:75-76` counts `DOVE_PK_SEED_BYTES`
into the secret key. Editorial omission only.

**Discrepancy 4 — `l` is never defined numerically (spec ambiguity).** §3.1
says `l = sqrt(m)`, but `m = 44, 96, 216` are not squares; Table 1 gives
`7, 10, 15 = ceil(sqrt(m))`, which is what the code uses. The needed condition
`l^2 >= m` (so `k1 = floor(i/l) <= l-1`) holds for all three sets
(49/100/225 >= 44/96/216) but is nowhere stated.

**Margin observation (not an implementation issue).** Spec Table 5's own minimum
classical estimate for DOVE128 is `2^128` against a required `2^128` — zero
margin; DOVE256/DOVE512 have 7 and 10 bits. No estimator was rerun here
(`parameter-selection` is `not_tested` in `security_findings.md`).

**Not verified.** The `uov/blas_matrix_ref.c` Gaussian-elimination path behind
the `L^{-1}` solve (Figure 3 line 16); the `DOVE_classic_ref` Sign/Verify bodies
below the key-layout and hash-call level; the SM3 core in `auxfunc.c`
(byte-identical to the shared `api/` copy). No constant-time or side-channel
assessment was attempted.
