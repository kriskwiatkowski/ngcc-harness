# hash-10 FEILIAN — algorithm summary

HAIFA-style iterated hash: a single 1024-bit compression function
**FEILIAN-f(h, m, tw)** with a 1024-bit chaining state, a 1024-bit message
block and a 256-bit tweak `tw = (ver, flag, t0, t1)` carrying the instance
version, a final-block flag and a 128-bit counter of processed message bits.
Inside, the state is a 4 x 4 matrix of 64-bit words and the compression
function runs 5 phases x 4 rounds = 20 rounds of an ARX
SubColumn / ShiftRow / AddConstant structure, closed with a Davies–Meyer-style
feed-forward `h' = h XOR v5`. All three instances share one compression
function; they differ only in `ver` and in how much of the final 1024-bit state
is output.

Specification: `hash-10-spec.pdf` (68 pages), Chapter 2 (§2.1 constants,
§2.2 compression function, §2.3 hash function), claims in §4.1 / Table 4.1.
English-language spec.

## Parameters

| parameter | FEILIAN-512 | FEILIAN-768 | FEILIAN-1024 | meaning |
|---|---|---|---|---|
| chaining state | 1024 | 1024 | 1024 | 4 x 4 matrix of 64-bit words |
| message block ("rate") | 1024 | 1024 | 1024 | bits absorbed per compression call |
| capacity | n/a | n/a | n/a | not a sponge; HAIFA iteration |
| tweak | 256 | 256 | 256 | `(ver, flag, t0, t1)` |
| `ver` | 0x200 | 0x300 | 0x400 | = 512 / 768 / 1024 |
| phases x rounds | 5 x 4 = 20 | 5 x 4 = 20 | 5 x 4 = 20 | §2.2.4 |
| counter t | 128 bits | 128 | 128 | message bits processed |
| digest, spec | 512 (= h0..h7) | 768 (= h0..h11) | 1024 (= h0..h15) | truncation of the final state |
| digest_bits / _bytes in OBSERVED | 512 / 64 | 768 / 96 | 1024 / 128 | matches spec |
| claimed collision | 256 | 384 | 512 | Table 4.1 |
| claimed preimage | 512 | 768 | 1024 | Table 4.1 |
| claimed 2nd-preimage | 512 | 768 | 1024 | Table 4.1 |
| max message length | < 2^128 bits | | | §2.3 |

All OBSERVED digest sizes match the specification.

## Pseudocode

### Padding and iteration (spec §2.3)

```
Split M into 1024-bit blocks M_0 || M_1 || ... || M_l
If |M_l| < 1024:  M_l' = M_l || 0...0      (zero bits, up to 1024)
else:             M_l' = M_l
# NO 10* bit, NO length block: unambiguity comes from the counter t and flag

h_0  = IV ;  t = 0 ;  flag = 0x0000000000000000
for i = 0 .. l-1:
    t   = t + 1024
    tw  = (ver, flag, t0, t1)
    h_{i+1} = FEILIAN-f(h_i, M_i, tw)
t    = t + |M_l|                       # BIT length of the unpadded last block
flag = 0xFFFFFFFFFFFFFFFF
tw   = (ver, flag, t0, t1)
h_{l+1} = FEILIAN-f(h_l, M_l', tw)

digest = h0 || ... || h_{d-1},   d = 8 / 12 / 16 words for 512 / 768 / 1024
```

### Compression function (spec §2.2.4)

```
FEILIAN-f(h, m, tw):
    v0 = h
    v1 = P_0(v0, m) ; v2 = P_1(v1, m) ; v3 = P_2(v2, m)
    v4 = P_3(v3, m) ; v5 = P_4(v4, m)          # the SAME m in every phase
    return v0 XOR v5                            # feed-forward

P_i(v, m):  v = R_xor(v, m) ; v = R(v) ; v = R(v) ; v = R(v)     # 4 rounds

R_xor(v, m):                       R(v):
    v = v (+) m0..m7                   v = SC(v)
    v = SC(v) ; v = SR(v)              v = SR(v)
    v = v (+) m8..m15                  v = SC(v)
    v = SC(v) ; v = SR(v)              v = SR(v)
    v = AC(v)                          v = AC(v)

  (+) injects a half-block into rows 0 and 2 only:
      row0 ^= (m0,m1,m2,m3)   row2 ^= (m4,m5,m6,m7)     [first half]
      row0 ^= (m8..m11)       row2 ^= (m12..m15)        [second half]
```

### Layers (spec §2.2.2)

```
SubColumn SC, per column (a1, b1, a0, b0) = (v[0][c], v[1][c], v[2][c], v[3][c]):
    a1 = a1 + b1                     # + is mod 2^64
    s0 = a1
    a0 = a0 + b0
    b0 = b0 XOR s0 ;  b0 = b0 >>> 8
    a0 = a0 + Sigma0(b0)             # Sigma0(x) = x ^ (x>>>5)  ^ (x>>>48)
    s1 = a0
    b1 = b1 XOR s1 ;  b1 = b1 >>> 63
    a1 = a1 + Sigma1(b1)             # Sigma1(x) = x ^ (x>>>11) ^ (x>>>40)

ShiftRow SR: rotate row i left by i positions (row 0 unchanged)

AddConstant AC (spec §2.2.2):
    row0 ^= (0, 0, 0, 0)
    row1 ^= (ver, flag, t0, t1)                  <-- tweak in ROW 1
    row2 ^= (0, 0, 0, 0)
    row3 ^= (C0', C1', C2', C3')                 <-- constants in ROW 3
  where at phase i, (C0',C1',C2',C3') = (C_{i%4}, C_{(i+1)%4}, C_{(i+2)%4}, C_{(i+3)%4})
```

Constants: `IV` = the first sixteen 64-bit words of frac(pi);
`Const = (C0..C3)` = frac(sqrt(2)), frac(sqrt(3)), frac(sqrt(5)), frac(sqrt(7)).

## Implementation vs specification

Source reviewed: `hash-10/src/FEILIAN{512,768,1024}/CryptHash_AlgorithmInstance.c`
(367 lines; the three files are identical apart from `FEILIAN_VERSION`,
`HASH_BYTES`, `HASH_ROWS` and comments). Line numbers are from the 512 file.

Verified agreements:

- `TOTAL_ROUNDS 20`, five 4-round phases with `rnd % 4 == 0` selecting
  `round_with_msg` (ll. 281–288) — matches §2.2.4 / the Phase definition.
- Phase constants `rc_groups[5] = { RC1, RC2, RC3, RC4, RC1 }` (l. 279) with
  `RC1..RC4` the four cyclic rotations of `Const` (ll. 144–162) — matches
  `(C_{i%4}, C_{(i+1)%4}, C_{(i+2)%4}, C_{(i+3)%4})` for i = 0..4. The four
  `Const` values equal the spec's `C0..C3` exactly.
- `sbox_column()` (ll. 179–187) is a faithful transcription of the spec's
  `SubColumn`, with `Sigma0 = x ^ (x>>>5) ^ (x>>>48)` and
  `Sigma1 = x ^ (x>>>11) ^ (x>>>40)` (ll. 46–54) as specified, and the
  column mapped as `(a1,b1,a0,b0) = (row0,row1,row2,row3)`.
- `shift_rows()` (ll. 199–212) produces exactly the spec's displayed result
  `(v0,v1,v2,v3 / v5,v6,v7,v4 / v10,v11,v8,v9 / v15,v12,v13,v14)`.
- `round_with_msg()` injects `m0..m3` into row 0 and `m4..m7` into row 2, then
  after SC/SR injects `m8..m11` / `m12..m15` — matches the spec's `R_xor`
  injection matrix (rows 1 and 3 receive nothing).
- `feilian_compress()` keeps `h_initial` and finishes with
  `add_state(h_out, h_initial)` — the `h' = v0 XOR v5` feed-forward.
- `ver` = 0x200 / 0x300 / 0x400 per instance; `flag` = 0 / all-ones
  (ll. 267–269) — matches §2.2.1.
- Counter: non-final blocks add 1024, the last block adds
  `msg_bits - i*1024`, i.e. the unpadded bit length of `M_l` (ll. 316–324) —
  matches `t <- t + ||M_l||`. `t0` is the high half, `t1` the low half
  (`set_hash_bits`, ll. 133–138, plus `flag_and_bits[2]/[3]`).
- Digest truncation: `store_state()` emits the first `HASH_ROWS` rows
  (2 / 3 / 4) = `h0..h7` / `h0..h11` / `h0..h15` — matches §2.3.
- Last-block handling: a message whose length is an exact multiple of 1024
  gets no extra block (`pad_bits = 0`), matching "If the last block is full,
  M_l' = M_l"; the empty message is one all-zero block with `t = 0`.

### Discrepancy 1 (real deviation, all instances): padding does not mask the partial final byte — **the anchored `hash-unused-bits` finding**

`pad_message()` ll. 84–90:

```c
size_t msg_bytes = (msg_bits + 7) / 8;
...
*padded = (uint8_t *)calloc(*padded_len, 1);
memcpy(*padded, msg, msg_bytes);
```

The whole final byte is copied, so the `8 - (msg_bits mod 8)` bits *after* the
declared end of the message are absorbed into the compression function. Nothing
anywhere else masks them.

**The specification is at fault-free here — the implementation is wrong.**
§2.3 defines the input as a bit string `M` of bit length `< 2^128`, splits it
into 1024-bit blocks, and pads the last block with `'0'` **bits**
(`M_l' <- M_l || 0...0`); the counter update `t <- t + ||M_l||` is likewise in
bits. There is no partial-byte ambiguity to exploit: the padded block must be
`M_l` followed by zeros. The shipped ICCS `README` additionally fixes the
MSB-first convention for partial bytes, under which the correct code is

```c
if (msg_bits % 8) padded[msg_bytes-1] = msg[msg_bytes-1] & (0xFF << (8 - msg_bits % 8));
```

This is the source of the already-recorded `hash-unused-bits` finding for all
three instances (`hash-10/security_findings.md`). Unlike hash-05's padding,
there is no carry bug — the declared message bits are preserved; only the
trailing garbage leaks in. The counter `t` still separates messages of
different lengths, which is why the `hash-zero-padding` check passes.

### Discrepancy 2 (real deviation, all instances): the AddConstant layer puts the tweak and the round constants in the wrong rows

Spec §2.2.2 shows `AC` XORing

```
row 0 : 0,   0,    0,  0
row 1 : ver, flag, t0, t1
row 2 : 0,   0,    0,  0
row 3 : C0', C1',  C2', C3'
```

Both `round_without_msg()` (ll. 226–229) and `round_with_msg()` (ll. 249–252)
do the opposite:

```c
for (int c = 0; c < MATRIX_COLS; c++) {
    state[1][c] ^= rc[c];                 /* constants -> row 1 */
    state[3][c] ^= flag_and_bits[c];      /* tweak     -> row 3 */
}
```

Rows 1 and 3 are swapped with respect to the specification. The state-row
indexing elsewhere is unambiguous and matches the spec (the `FEILIAN_IV`
matrix, the message-injection rows, and the digest = rows 0..k), so this is a
genuine mismatch, not a transposed convention. A spec-faithful implementation
produces different digests from the shipped KATs. Security-wise the two
placements are probably of comparable strength (SubColumn treats rows 0/2 as
the `a` words and 1/3 as the `b` words, so swapping moves the tweak from a
`b1` position to a `b0` position), but the specification and the code define
different functions.

### Discrepancy 3 (specification typo): `IV7`

Spec §2.1 lists `IV7 = 0x3D84D5B5B5470917`. The implementation uses
`0x3f84d5b5b5470917` (l. 170). The IV is documented as "the first decimal
digits of pi"; the correct 8th 64-bit word of frac(pi) is
`0x3F84D5B5B5470917` (the same value appears in the well-known pi word table,
and the spec itself uses `0x3F84D5B5B5470917` in hash-06/hash-08's copies of
the same table). So the implementation is right and the **specification has a
one-nibble typo**. Anyone implementing from the document alone would produce
digests that disagree with the KATs.

### Minor observations

- The spec never states the byte order used to map message bytes to the
  64-bit words `m0..m15`, nor the order used to serialise the digest words.
  The implementation uses **little-endian** within each 64-bit word
  (`load_block`, `store_state`, ll. 60–68 / 115–127). This is a spec gap, not
  a deviation.
- The counter is carried in `size_t msg_bits` and two 64-bit accumulators
  where the high word can only ever be incremented by carry from a `size_t`
  value, so the effective maximum message length is 2^64 - 1 bits, not the
  `< 2^128` of §2.3. Not reachable through the ICCS API, which itself caps at
  `unsigned long long`.
- `CryptHash()` accepts any `0 < digest_len_bits <= DIGEST_BIT_LENGTH` and
  truncates (masking the last partial byte), rather than requiring equality.
  Harmless but non-standard for this API.
- `pad_message()` over-allocates by one byte when `msg_bits` is not a multiple
  of 8 (`msg_bytes + ceil(pad_bits/8)`); the block count and all reads stay in
  bounds, so this is only wasted memory.

### Not verified

- The remaining 15 `IV` words against the pi expansion (only `IV7` was
  cross-checked because it differed).
- The indifferentiability argument (§4.3) and the dedicated attacks of §4.6;
  the numbers in the parameter table are the spec's own claims.
