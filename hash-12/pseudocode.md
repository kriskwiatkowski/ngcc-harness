# hash-12 Iphe — algorithm summary

Sponge with **capacity feed-forward** ("Sponge-F", the same family as hash-09
Eijen): the capacity part of the state is saved before each permutation call
and XORed back afterwards, and the digest is squeezed from the **capacity**
rather than the rate. That raises preimage security to ≈ d and second-preimage
security to `min{d, c - log2 L}`, so the capacity only needs
`c = d + tau` with `tau = 64` instead of `c >= 2d`. The permutation is a pure
ARX design on 32 x 64-bit words: 5 large rounds of 5 small rounds each, where
small round `ir` works with a group stride `l = 2^(ir+1)`, mixes each group
into a bit-reversal-permuted target group, rotates every word and then applies
a perfect word shuffle.

Specification: `hash-12-spec.pdf` (39 pages), §2 (parameters, endianness,
padding), §3 (Algorithm 1, Sponge-F), §4 (permutation gadgets AC/GM/WR/WP),
claims in §6.1 / Table 4. English-language spec.

## Parameters

`Iphe[w, n, d, tau, Nr]` with `b = nw`, `nr = log2 n`, `c = d + tau`,
`r = b - c`. All submitted instances use `w = 64`, `n = 32`, `tau = 64`,
`Nr = 5`, hence `b = 2048` and `nr = 5`.

| parameter | Iphe-512 | Iphe-768 | Iphe-1024 |
|---|---|---|---|
| state width b | 2048 | 2048 | 2048 |
| words n / word size w | 32 / 64 | 32 / 64 | 32 / 64 |
| capacity c = d + 64 | 576 | 832 | 1088 |
| rate r = 1984 − d | 1472 | 1216 | 960 |
| rate words / capacity words | 23 / 9 | 19 / 13 | 15 / 17 |
| large rounds Nr | 5 | 5 | 5 |
| small rounds per large round | 5 | 5 | 5 |
| total small rounds | 25 | 25 | 25 |
| rotation constants | rho_i = ((7i) mod 32) + 16 | same | same |
| digest d, spec | 512 | 768 | 1024 |
| digest_bits / _bytes in OBSERVED | 512 / 64 | 768 / 96 | 1024 / 128 |
| squeeze blocks needed | 1 (c > d) | 1 | 1 |
| claimed collision | 256 | 384 | 512 |
| claimed preimage | 512 | 768 | 1024 |
| claimed 2nd-preimage | 512 | 768 | 1024 |
| claimed quantum coll. / preimage | 128 / 256 | 192 / 384 | 256 / 512 |

All OBSERVED digest sizes match the specification (spec Table 2). `c > d` for
every instance, so a single squeeze produces the whole digest and no extra
permutation call is made.

## Pseudocode

### Endianness (spec §2.2) and padding (spec §2.3)

```
Bits are LSB-first inside a byte internally: bits x0..x7 -> byte
  x0*2^0 + ... + x7*2^7 ; eight bytes -> one little-endian 64-bit word.
The ICCS API delivers a message MSB-first within each byte, so the
implementation reverses the bit order of every input byte. Output bytes are
NOT bit-reversed.

Padding(m), |m| = l:                    # "1 0* 1", not the usual 10*
    append one 1 bit
    append k zero bits, k smallest >= 0 with l + 1 + k + 1 == 0 (mod r)
    append one more 1 bit
```

### Sponge-F (spec Algorithm 1)

```
Hash(m):
    S = 0^2048 ;  H = empty                      # no IV
    m' = Padding(m) ;  t = |m'|/r
    m' = B(0) || ... || B(t-1),  |B(i)| = r,  B(i) = B(i)_0 .. B(i)_{r/w-1}

    # absorbing
    for i = 0 .. t-1:
        for j = 0 .. r/w-1:  S_j ^= B(i)_j        # rate words only
        C = S AND Mc                              # Mc = 0^r || 1^c
        S = f(S)
        S = S XOR C                               # capacity feed-forward

    # squeezing, from the CAPACITY
    while |H| < d:
        H = H || S_{r/w} || ... || S_{n-1}        # c bits per squeeze
        if |H| >= d: return H[0 : d-1]
        C = S AND Mc ; S = f(S) ; S = S XOR C
```

### Permutation f (spec §4)

```
rnd = WP o WR o GM o AC                # i.e. AC, then GM, then WR, then WP
Rnd = rnd^nr        f = Rnd^Nr         # 5 x 5 = 25 small rounds

small round (large round Ir, small round ir):   l = 2^(ir+1), groups = n/l

AC:  for each group i:  S_{i*l} ^= alpha[i] XOR beta[ir] XOR gamma[Ir]
       alpha[0..15], beta[0..4], gamma[0..4] = 26 consecutive 64-bit words
       of frac(pi)

GM:  treeSum        TS_1(a) = S_a
                    TS_l(a) = TS_{l/2}(a)  +  TS_{l/2}(a+l/2)   if s odd   (l = 2^s)
                    TS_l(a) = TS_{l/2}(a) XOR TS_{l/2}(a+l/2)   if s even
     target group   q = log2(n/l),  D_l(i) = rev_q((rev_q(i)+1) mod 2^q)
                    ("increment the group index with carry from the MSB down")
     writeback      u_i = TS_l(i*l),  d = D_l(i)*l,  mu_j = 1 + 2^(j+1)
                    T_d     = S_d     +   mu_0 * u_i           # mu_0 = 3
                    T_{d+j} = S_{d+j} XOR mu_j * u_i,  1 <= j < l
                    (mu_j * u = u + (u << (j+1)), plain left shift)
                    all right-hand S are the pre-GM state; then S <- T

WR:  S_i = S_i <<< rho_i,  rho_i = ((7i) mod n) + (w-n)/2 mod w  = (7i mod 32) + 16

WP:  perfect shuffle:  S'_i = S_{2i} (i < n/2),  S'_i = S_{2(i-n/2)+1} (i >= n/2)
```

## Implementation vs specification

Source reviewed: `hash-12/src/Iphe-{512,768,1024}/CryptHash_AlgorithmInstance.c`
(196 lines; the three files are **byte-identical** — only
`ALGORITHM_INSTANCE` / `DIGEST_BIT_LENGTH` in the header differ). The code is
heavily condensed (a recursive one-line `S()` for treeSum, a bit-twiddling loop
for `D_l`), so each gadget was checked by expansion.

Verified agreements:

- `rate_bits = 2048 - digest_len_bits - 64` (l. 149) gives 1472 / 1216 / 960 —
  matches spec Table 2 for all three instances; `capacity_words = 32 -
  rate_words` gives 9 / 13 / 17.
- `C[26]` (ll. 12–39) matches spec Table 3 exactly: `C[0..15] = alpha`,
  `C[16..20] = beta`, `C[21..25] = gamma`, and the AC line
  `x[j] ^= C[j/g] ^ C[16+i] ^ C[21+r]` (l. 62) is exactly
  `rc[i, ir, Ir] = alpha[i] XOR beta[ir] XOR gamma[Ir]` applied to the first
  word of each group.
- `g = 2 << i` (l. 59) gives the strides 2, 4, 8, 16, 32 — matches
  `l = 2^(ir+1)`.
- The recursive treeSum `S(x, k)` (ll. 46–50) selects `+` or `^` by
  `k & 10` after halving. Expanding for l = 2,4,8,16,32 gives
  ADD, XOR, ADD, XOR, ADD, which is exactly the spec's
  `TS2 = +, TS4 = ^, TS8 = +, TS16 = ^, TS32 = +`.
- The target-group computation `for (k = 32; k > (l|g); ) { k >>= 1; l ^= k; }`
  (ll. 66–70) was expanded by hand for `l = 4` (8 groups): it maps group
  indices `0,1,2,3,4,5,6,7` to `4,5,6,7,2,3,1,0`, which is **exactly the
  example the spec gives** for `D_4` in §4.2.
- Writeback (ll. 71–76): `y[d] = x[d] + 3*s` for `j = 0` (`mu_0 = 3`) and
  `y[d+k] = x[d+k] ^ (s + (s << (k+1)))` for `k >= 1` (`mu_k = 1 + 2^(k+1)`,
  expanded as the spec suggests). All reads are from the pre-GM array `x` and
  all writes go to `y`, honouring "all `S_j` on the right-hand side refer to
  the state before entering GM".
- WR (ll. 79–80): `rotl64(y[j], (7*j % 32) + 16)` — matches `rho_i`.
- WP (ll. 82–83): `x[j/2 + (j%2)*16] = y[j]` — matches
  `T_{i/2} <- S_i` (even) and `T_{16 + (i-1)/2} <- S_i` (odd).
- Round structure (ll. 57–58): 5 large x 5 small = 25 applications of
  `AC, GM, WR, WP` in that order — matches `rnd = WP o WR o GM o AC`,
  `f = (rnd^5)^5`.
- Initial state is all zero (`word_t state[32] = {0}`, l. 139) — matches
  `S <- 0^b`; there is no IV.
- Capacity feed-forward (ll. 165–171, 183–189): the capacity words are saved
  after the message XOR and before `f`, then XORed back — exactly
  `C <- S AND Mc; S <- f(S); S <- S XOR C`.
- Padding: `padding_blocks = (remaining_bits > rate_bits - 2) ? 2 : 1`
  (l. 155) correctly reserves room for the two padding `1` bits, and
  `load_final_word()` (ll. 110–126) sets bit `remaining_bits` (the first
  padding 1), bit `final_bits - 1` (the second padding 1), message bits where
  present and zeros elsewhere — exactly `m || 1 || 0^k || 1`.
- Endianness: `load_message_word()` bit-reverses each input byte and packs
  little-endian (ll. 100–108); `store64_le()` writes the digest words
  little-endian **without** bit reversal (ll. 128–134). Both match §2.2's
  "the implementation reverses the bit order in each input byte. No additional
  bit reversal is applied to output bytes."
- Digest extraction: `out_words = d/64` capacity words starting at
  `state[rate_words]` (ll. 192–193) — the first `d` bits of the capacity, and
  since `c > d` a single squeeze suffices with no extra permutation, matching
  Algorithm 1.
- **Partial-byte input is handled correctly.** Message bits are read one at a
  time via `get_message_bit()` and only for `local_pos < remaining_bits`
  (ll. 120–122), so no bit beyond `msg_len_bits` is ever read. Full blocks are
  always whole bytes because every rate is a multiple of 64.
- `CryptHash()` rejects `digest_len_bits != DIGEST_BIT_LENGTH`, a NULL digest
  and a NULL message with non-zero length.

**No deviation from the specification was found for hash-12.** Every
parameter, constant, gadget, the padding rule, the feed-forward and the
squeeze rule agree with the document.

### Minor observations (not deviations)

- The treeSum operator selector `k & 10` happens to give the right parity only
  for `k <= 16`, i.e. `n <= 32`. For a hypothetical `n = 128` instance
  (`l = 64`, `s = 6`, spec wants XOR) `64 & 10 == 0` would select ADD. The
  rest of the file hard-codes `32` anyway, so the generic `Iphe[w,n,d,tau,Nr]`
  family is not actually parameterised in this reference code — only the three
  submitted instances are.
- `rotl64(x, n)` would be undefined behaviour for `n == 0`, but
  `rho_i = (7i mod 32) + 16` lies in `[16, 47]`, so it is unreachable.
- `word_t feed_forward[17]` is exactly large enough for the largest capacity
  (17 words for Iphe-1024); a hypothetical larger-capacity instance would
  overflow it.
- The three instances ship byte-identical `.c` files; the parameter spot-check
  therefore applies to all three at once.

### Not verified

- The 26 constants were compared against spec Table 3 but not recomputed from
  the binary expansion of pi.
- The differential / linear / algebraic-degree analyses of §6.2 and the
  Sponge-F bound of [6]; the numbers in the parameter table are the spec's own
  claims.
- The KAT files were not re-derived; conformance is reported by the harness
  (`RESULTS.md`).
