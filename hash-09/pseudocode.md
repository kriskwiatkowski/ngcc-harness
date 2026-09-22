# hash-09 Eijen — algorithm summary

Sponge with **capacity feed-forward** ("Sponge-F"): after each permutation call
the pre-permutation capacity is XORed back into the capacity, and the digest is
truncated from the **capacity** of the final state. This raises preimage
security from the classical c/2 to ≈ min{h, c − log2 l}, so the design can use
c = h + 64 instead of c ≥ 2h. The primitive is a 16-round ChaCha-style ARX
permutation on 2048 bits arranged as a 4 × 8 array of 64-bit words.

Specification: `hash-09-spec.pdf` (29 pages), §2 (Table 1, §2.3 mode,
§2.4 permutation), claims in §3 / Table 2. English-language spec.

## Parameters

All five instances share b = 2048 bits and the same 16-round permutation Π.

| parameter | Eijen-256 | Eijen-384 | Eijen-512 | Eijen-768 | Eijen-1024 |
|---|---|---|---|---|---|
| state width b | 2048 | 2048 | 2048 | 2048 | 2048 |
| rate r | 1728 | 1600 | 1472 | 1216 | 960 |
| capacity c = h + 64 | 320 | 448 | 576 | 832 | 1088 |
| rate words / bytes | 27 / 216 | 25 / 200 | 23 / 184 | 19 / 152 | 15 / 120 |
| capacity words | 5 | 7 | 9 | 13 | 17 |
| rounds | 16 | 16 | 16 | 16 | 16 |
| squeeze width r' | 256 | 384 | 512 | 768 | 1024 |
| digest h, spec | 256 | 384 | 512 | 768 | 1024 |
| digest_bits / _bytes in OBSERVED | 256 / 32 | 384 / 48 | 512 / 64 | 768 / 96 | 1024 / 128 |
| claimed collision | 128 | 192 | 256 | 384 | 512 |
| claimed preimage | 256 | 384 | 512 | 768 | 1024 |
| claimed 2nd-preimage | 256 | 384 | 512 | 768 | 1024 |

All OBSERVED sizes match the spec. The `c = h + 64` rule is what buys full
h-bit second-preimage security at the maximum message length `l_max = 2^64 - 1`
(spec §2.2), since second-preimage security is `min{h, c - log2 l}`.

## Pseudocode

### Padding (spec §2.3)

```
pad10*_r(M) = M || 1 || 0^k,   k smallest >= 0 with (|M| + 1 + k) mod r == 0
            = M[0] || M[1] || ... || M[l-1],   |M[i]| = r
```

No length field. Domain separation for the last block is the constant
`1_c = 0^(c-1) || 1` XORed into the capacity.

### Sponge-F mode (spec §2.3)

```
Eijen_h(M):
    X_0 = 0^r || IV,    IV = 0^c              # the whole state starts at zero

    for i = 1 .. l:
        if i < l:  S = X_{i-1} XOR (M[i-1] || 0^c)
        else:      S = X_{i-1} XOR (M[i-1] || 1_c)        # final-block constant
        X_i = PI(S) XOR (0^r || right_c(S))               # capacity feed-forward

    return right_h(X_l)                                   # digest from the CAPACITY
```

Note the feed-forward operand is `right_c(S)` — the capacity *after* the
message block and, on the last block, *after* `1_c` has been XORed in. (See
Discrepancy 2.)

### Permutation PI (spec §2.4)

```
state: A[0..31] of 64-bit words; column j = (A[4j], A[4j+1], A[4j+2], A[4j+3])
PI = R(15) o ... o R(0)                                   # 16 rounds

R(t):  A --MixQuad--> Z --PosPerm--> U --AMix4--> W --PosPerm--> A'

MixQuad, per column, on (a,b,c,d) with rotations pi=(p0..p5) and constant ci:
    a = a + b ; d ^= a ; d = ROTL(d, p0) ; a = ROTL(a, p4) ^ ci
    c = c + d ; b ^= c ; b = ROTL(b, p1) ; c = ROTL(c, p5)
    a = a + b ; d ^= a ; d = ROTL(d, p2)
    c = c + d ; b ^= c ; b = ROTL(b, p3)
  columns 0..3 use p0 = (36, 54, 45, 44, 18, 9) and constant ci0^(t)
  columns 4..7 use p1 = (56, 46, 54, 34, 19, 51) and constant ci1^(t)
  the 32 constants are consecutive 64-bit words of frac(pi)

PosPerm:  U[l] = Z[sigma(l)],  sigma =
    [22, 0,29,19,26, 4, 1,23,30, 8, 5,27, 2,12, 9,31,
      6,16,13, 3,10,20,17, 7,14,24,21,11,18,28,25,15]

AMix4, per column j (L = all-ones minus identity over F2):
    W[4j+t] = XOR of the other three words of column j
```

## Implementation vs specification

Source reviewed: `hash-09/src/Eijen-*/eijen_ref.c` (238 lines),
`eijen_internal.h`, `eijen.h`, `CryptHash_AlgorithmInstance.c`. All five
instance directories ship byte-identical Eijen sources; only
`CryptHash_AlgorithmInstance.h` differs. Line numbers refer to `eijen_ref.c`.

Verified agreements:

- `EIJEN_CONFIGS` (`eijen_internal.h`) lists `{h, rate_words, capacity_words,
  digest_words, rate_bytes, digest_bytes}` =
  `{256,27,5,4,216,32} {384,25,7,6,200,48} {512,23,9,8,184,64}
  {768,19,13,12,152,96} {1024,15,17,16,120,128}` — every value matches
  spec Table 1 (rate_words*64 = r, capacity_words*64 = c = h + 64).
- `EIJEN_ROUNDS 16` matches §2.4.
- `eijen_mixquad()` (ll. 28–45) is a statement-for-statement transcription of
  the spec's `MQ_{pi,ci}`, including the two added operations
  `a = ROTL(a, p4) ^ ci` and `c = ROTL(c, p5)`.
- Rotation sets `36,54,45,44,18,9` for columns 0–3 and
  `56,46,54,34,19,51` for columns 4–7 (ll. 51–58) match `p0` and `p1`.
- `EIJEN_RC0`/`EIJEN_RC1` reproduce the spec's round constants; I checked
  rounds 0, 1 and 15 against the values printed in §2.4.1
  (`0x243F6A8885A308D3`/`0x13198A2E03707344`, `0xA4093822299F31D0`/
  `0x082EFA98EC4E6C89`, `0xB4CC5C341141E8CE`/`0xA15486AF7C72E993`).
- `eijen_sigma()` (ll. 62–72) implements PosPerm as a cycle decomposition.
  I expanded all eight cycles and verified `new s[l] = old s[sigma(l)]` for
  **all 32 indices** against the spec's sigma — exact match.
- `eijen_linear_layer()` (ll. 75–85) computes `x = XOR of the column` then
  `s[b+t] ^= x`, which is exactly `W[4j+t] = XOR of the other three` — matches
  AMix4.
- Round order `MixQuad, PosPerm, AMix4, PosPerm` (ll. 90–95) matches §2.4.
- Initial state all zero (`memset` in `eijen_init`) — matches `X_0 = 0^r || 0^c`.
- Digest extraction (ll. 190–193): the last `digest_words` state words,
  i.e. `right_h(X_l)` — matches eq. (1).
- Streaming buffer logic: a message whose length is an exact multiple of the
  rate correctly triggers a separate all-padding final block (ll. 175–178),
  which is what `pad10*` with `k = r-1` requires.
- The partial-byte path masks the caller's final byte
  (`partial_byte & (0xff << (8 - partial_bits))`, l. 182–184), so bits past
  `msg_len_bits` cannot reach the state — the automated battery's
  `hash-unused-bits` check passes for all five instances.

### Discrepancy 1 (real deviation, **collision-producing**, all instances): the byte-aligned padding bit is placed at the wrong end of the byte

`eijen_final_partial()` ll. 179–185:

```c
if (partial_bits == 0U) {
    ctx->buf[ctx->buf_len] = 0x01U;                      /* <-- LSB of the byte */
} else {
    uint8_t keep = (uint8_t)(0xffU << (8U - partial_bits));
    uint8_t pad  = (uint8_t)(0x80U >> partial_bits);     /* <-- MSB-first */
    ctx->buf[ctx->buf_len] = (uint8_t)((partial_byte & keep) | pad);
}
```

The partial-byte branch uses the MSB-first bit order that the shipped ICCS
`README` mandates (`0x80 >> partial_bits`), but the byte-aligned branch writes
`0x01`, i.e. the *least* significant bit. The two branches disagree, and the
value `0x80 >> 0` that the general formula would give is `0x80`, not `0x01`.

**Consequence: a trivial collision.** Let `M` be any message whose length `L`
is a multiple of 8, and let `M' = M || 0000000` (seven appended zero bits).
Then

- for `M`: `full_bytes = L/8`, `partial_bits = 0` → pad byte = `0x01`;
- for `M'`: `full_bytes = L/8` (integer division), `partial_bits = 7`,
  `keep = 0xFE`, `pad = 0x01`, and the seven message bits are zero →
  pad byte = `(0x00 & 0xFE) | 0x01` = `0x01`.

`eijen_hash_bits()` uses `msg_len_bits` for nothing else, so the byte fed to
the sponge, the buffer length and the `is_last` flag are all identical. Hence

```
Eijen-h(M, L bits)  ==  Eijen-h(M || 0^7, L+7 bits)   for every byte-aligned M
```

for all five instances. Two distinct bit strings, one digest — a directly
constructible collision that defeats the h/2-bit collision claim of §3 and
violates the injectivity of `pad10*` that §2.3 specifies. The automated
`hash-zero-padding` check did not catch it because it extends by whole zero
*bytes*, not by seven bits.

Fix: `ctx->buf[ctx->buf_len] = 0x80U;` in the byte-aligned branch (or drop the
special case and use `0x80U >> partial_bits` uniformly).

### Discrepancy 2 (real deviation, all instances): the final-block feed-forward uses the capacity from *before* the domain constant

Spec §2.3 defines, for the last block,
`S_{l-1} = X_{l-1} XOR (M[l-1] || 1_c)` and then
`X_l = PI(S_{l-1}) XOR (0^r || right_c(S_{l-1}))`. The fed-forward value is
therefore the capacity **including** `1_c`.

`eijen_absorb_block()` (ll. 99–120) saves the capacity *first* (ll. 105–107),
then XORs the message and, when `is_last`, the constant (ll. 111–113):

```c
for (i = 0; i < cap_words; i++) saved_cap[i] = ctx->state[cap_start + i];
...
if (is_last) ctx->state[EIJEN_STATE_WORDS - 1] ^= (UINT64_C(1) << 63);
eijen_permutation(ctx->state);
for (i = 0; i < cap_words; i++) ctx->state[cap_start + i] ^= saved_cap[i];
```

For interior blocks this is equivalent (the message touches only the rate), but
for the final block the implementation feeds forward `right_c(X_{l-1})` instead
of `right_c(X_{l-1}) XOR 1_c`. The computed digest is therefore the spec's
digest **XOR the single bit of `1_c`** — and since `1_c`'s set bit lies in the
last state word, which is always inside `right_h`, *every* Eijen digest differs
from the specification in exactly one bit. Security impact is nil (an
unconditional constant XOR on the output), but the shipped KATs will not match
a spec-faithful implementation.

### Spec ambiguity (class b): the bit position of `1_c`

§2.3 says "Under little-endian byte ordering, the final 64-bit word of `1_c` is
represented as `(10000000, 00000000, ..., 00000000)`", which reads as byte 0 of
that word being `0x80`, i.e. the word value `0x0000000000000080`. The
implementation uses `1 << 63` = `0x8000000000000000`, which little-endian
serialises to `0x80` in the *last* byte. Both are a single bit in the last
capacity word, so domain separation works either way, but the spec's sentence
does not pin the position down; a second implementer could reasonably pick the
other one.

### Minor observations

- `CryptHash()` correctly rejects `digest_len_bits != DIGEST_BIT_LENGTH` and a
  NULL message with non-zero length.
- `eijen_rotl64(x, n)` is undefined behaviour for `n == 0`; no rotation
  constant used is 0, so it is unreachable in the reference path.
- The package also contains an AVX2 4-way variant (`eijen_avx2.c`) guarded by
  `__AVX2__`; the NGCC build compiles `eijen_ref.c` only (per the shipped
  `CMakeLists.txt` and `hash-09/Makefile`), and the AVX2 path was not reviewed.

### Not verified

- The remaining 26 round constants against the π expansion.
- The differential/differential-linear/integral analyses of §4; the numbers in
  the parameter table are the spec's own claims.
- The Sponge-F security bound of §3 was taken at face value.
