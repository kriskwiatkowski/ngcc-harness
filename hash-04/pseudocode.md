# hash-04 CHAMP (Cayley HAshing with Matrix Products) — algorithm summary

Cayley hash: a message bit string is mapped to a *word* in the free semigroup on
two fixed 2x2 matrices `A`, `B` over `F_p`, the product is accumulated
left-to-right, and the digest is the (entrywise inverted) product matrix. There
is **no sponge, no compression function, no padding and no length encoding** —
the whole design is one monoid homomorphism `H_M : {0,1}* -> GL(2, F_p)`
followed by an invertible encoding. Security rests on the girth / relation
problem of the Cayley graph of `<A,B> <= GL(2,F_p)` (i.e. "no short relation
u(A,B) = v(A,B)"), not on any standard-model assumption.

Specification: `hash-04-spec.pdf` (10 pages), Section 5 ("Algorithm
description"), Section 5.1 (parameters), Section 6 (Julia reference listing),
Section 7.1 (security statements). English-language spec.

## Parameters

| parameter | CHAMP-512 | CHAMP-1024 | meaning |
|---|---|---|---|
| group | `<A,B> <= GL(2,F_p)` | same | 2x2 matrices mod a prime (spec §3.1) |
| `p` | `2^128 - 15449` | `2^256 - 36113` | safe prime `p = 2q+1` (§5.1) |
| `p` bit length | 128 | 256 | |
| generator for bit 0 | `A = [[-2,1],[4,-3]]` | same | `det A = 2` (§5.1) |
| generator for bit 1 | `B = [[-5,2],[-6,2]]` | same | `det B = 2` (§5.1) |
| alternative pair (not implemented) | `A=[[-2,1],[4,-3]], B=[[6,4],[-2,-1]]` | same | §5.1; §6 says the C code uses the **first** pair |
| state | 4 field elements (2x2 matrix) | 4 field elements | 512 / 1024 bits |
| "rate" | 1 bit per matrix multiply | 1 bit | no block structure at all |
| "capacity" | n/a | n/a | not a sponge |
| "rounds" | n/a | n/a | one 2x2 modular matrix product per message bit |
| absorption order | MSB-first within each byte | same | §5 step 1 / ICCS README note 5 |
| padding | **none** | **none** | §5 has no padding rule |
| digest length | 512 | 1024 | `4 * ceil(log2 p)` bits |
| claimed collision security | qualitative only | qualitative only | see below |
| claimed preimage security | qualitative only | qualitative only | §7.1 |

The spec gives **no numeric collision/preimage bit-strength claim**. §7.1 states
only: (1) provably no collisions between inputs of *different* lengths when the
length difference is below `q ~ 2^127` (CHAMP-512) resp. `~ 2^255`
(CHAMP-1024) — this follows from `det A = det B = 2` and `p` being a safe
prime; (2) same-length collision resistance is *not* proved, only argued from
"the actual girth is huge in most cases"; (3) first/last input bit is claimed
unrecoverable with advantage over 1/2 for inputs of >= 1000 bits.

Sizes, specification vs the built reference library (`OBSERVED/hash-04.txt`):

| instance | digest spec (bits) | digest impl (bits) | digest impl (bytes) | match |
|---|---|---|---|---|
| CHAMP-512 | 512 | 512 | 64 | yes |
| CHAMP-1024 | 1024 | 1024 | 128 | yes |

## Pseudocode

### Hash(X, nbits)  — spec §5, Julia listing §6

```
Input : bit string X = x_0 x_1 ... x_{nbits-1}  (MSB-first within each byte)
Output: digest of 4*len(p) bits

 1  S <- I                                     # 2x2 identity over F_p
 2  for i = 0 .. nbits-1:                      # left to right, "as you go"
 3      b <- (X[i/8] >> (7 - i mod 8)) & 1     # i-th bit, MSB first
 4      M <- (b == 0) ? A : B                  # 0 -> A, 1 -> B
 5      S <- (S * M) mod p                     # RIGHT multiplication
 6  H_M(X) <- S                                # the homomorphic value
 7  for each entry s of S:                     # spec §3.3 / §5 step 2
 8      h <- (s == 0) ? 0 : s^{-1} mod p       # invert NONZERO entries only
 9  # spec §5 step 3: concatenate in the order h11, h21, h12, h22
10  H(X) <- BE(h11) || BE(h21) || BE(h12) || BE(h22)
```

No padding, no domain separation, no length field, no finalisation
permutation: `H_M` is exactly the semigroup homomorphism, and step 7-10 is a
public bijection (entrywise inversion is an involution on `F_p^*`, fixing 0).
Consequences the spec states as *features* (§4): `H_M(X||Y) = H_M(X)·H_M(Y)`,
so the digest of `X||Y` is computable from the digests of `X` and `Y` alone.

### Variable digest length

Not supported. Each instance is a separate parameter set with a hard-wired
prime; the digest length is `4·|p|` bits and cannot be varied. The ICCS API
passes `digest_len_bits`, and both reference instances discard it (see below).

### Absorb / squeeze loop (implementation form)

```
build_byte_table():                            # 256 entries, product of 8 gens
    for v = 0..255: T[v] <- prod_{b=7..0} ( ((v>>b)&1) ? B : A )
CryptHash(dlen, msg, nbits, out):
    S <- I
    for i = 0 .. (nbits >> 3) - 1:  S <- S * T[msg[i]]        # 8 bits at a time
    for b = 7 down to 8-(nbits mod 8):                        # partial byte
        S <- S * ( ((msg[full]>>b)&1) ? B : A )
    out <- encode( inv0(S11), inv0(S21), inv0(S12), inv0(S22) )
```

## Implementation vs specification

Checked: `hash-04/src/CHAMP-512/CryptHash_AlgorithmInstance.c` (324 lines) and
`hash-04/src/CHAMP-1024/CryptHash_AlgorithmInstance.c` (353 lines). These two
files are the entire hash (plus the ICCS `drng.c`, which is not used by
`CryptHash`). No other source implements any part of the algorithm.

Agreements:

- `p` constants match the spec exactly. CHAMP-512 `P = {0xFFFFFFFFFFFFC3A7,
  0xFFFF...FFFF}` = `2^128 - 15449`; CHAMP-1024 `P[0] = 0xFFFFFFFFFFFF72EF`
  = `2^256 - 36113`. I independently verified with a Miller-Rabin check that
  both are prime, both are safe primes (`(p-1)/2` prime), and both are the
  *largest* safe prime of their bit length, as §5.1 claims. Both are `= 7 mod 8`.
- Generators match the **first** suggested pair (§5.1/§6): `GEN_A` column-major
  `(p-2, 4, 1, p-3)` = `[[-2,1],[4,-3]]`, `GEN_B` `(p-5, p-6, 2, 2)` =
  `[[-5,2],[-6,2]]`. The alternative pair is not present, consistent with §6.
- Bit order is MSB-first within a byte, and multiplication is on the **right**
  (`mat2x2_mul(tmp, state, M)` computes `state * M`), i.e. left-to-right over
  the input as §5 step 1 requires. The 256-entry byte table is built the same
  way (`b = 7 down to 0`), so it is the deliberate optimisation described in §8.
- Entry order in the digest is `h11, h21, h12, h22` (`state[0], state[1],
  state[2], state[3]` in the column-major layout), matching §5 step 3.
- Zero entries are emitted as all-zero, not inverted (`u128_is_zero` /
  `u256_is_zero` guard), matching §5 step 2.
- Partial trailing bits are absorbed bit-by-bit, MSB-first, exactly `nbits mod
  8` of them; bits below the message length in the last byte are ignored.

Discrepancies:

- **(a) real deviation — digest byte order.** The spec's §5 step 2/3 and the
  Julia listing in §6 serialise each field entry **big-endian**
  (`digest[32*(k-1)+j+1] = (vals[k] >> (8*(31-j))) & 0xff`). Both C instances
  serialise each entry **little-endian**, limb 0 first and least-significant
  byte first inside each limb: CHAMP-512
  `CryptHash_AlgorithmInstance.c:309-321`, CHAMP-1024 `:335-348`. So the C
  digest is the byte-reversal of each 128/256-bit field entry relative to the
  spec's reference code. The KATs were generated from the C code, so the KATs
  are self-consistent, but any independent implementation written from the
  specification will not interoperate. Security-neutral (a public fixed byte
  permutation), interoperability-breaking. Already recorded in
  `hash-04/security_findings.md` as `digest byte-order conformance`.
- **(a) real deviation / API defect — `digest_len_bits` is ignored.**
  `CryptHash()` does `(void)digest_len_bits;` (CHAMP-512 line 270, CHAMP-1024
  line 299) and unconditionally writes 64 resp. 128 bytes. A caller asking for
  a shorter digest gets a buffer overrun rather than a truncated digest, and a
  caller asking for a longer one gets a silent short write. The ICCS API
  documents `digest_len_bits` as an input; the spec defines no variable-length
  mode, so this is a spec-gap the code resolves by ignoring the argument.
- **(b) spec gap — no padding / no length binding.** The specification
  deliberately defines no padding rule, so `H_M` is a homomorphism and
  `H(X||Y)` is computable from `H(X)` and `H(Y)` (§4, stated as a feature).
  The implementation faithfully reproduces this. Practical consequence: CHAMP
  is trivially length-extendable and is unusable as a secret-prefix MAC or as
  a random-oracle substitute. This is spec-intended, not an implementation bug,
  but it is the sharpest deviation from what "cryptographic hash function"
  normally implies, and the spec's §7.1 security statements do not mention it.
- **(c) note, not a deviation — algebraic structure of the image.** At a fixed
  input length `n`, `det H_M(X) = 2^n` is constant, so all digests of
  length-`n` messages lie in a single determinant coset of `SL(2,F_p)`, of size
  `p(p^2-1) ~ p^3`. The invertible encoding cannot enlarge it. The effective
  image entropy is therefore ~`3|p|` bits (384 for CHAMP-512, 768 for
  CHAMP-1024), not the nominal 512/1024, so same-length birthday collision
  search is at most `2^192` / `2^384` — still above the nominal 128/256-bit
  levels, but the spec never states a numeric level to compare against.
  Independently noted in `hash-04/security_findings.md`.
- **Not verified:** I did not check the primality/girth-related claims beyond
  the safe-prime arithmetic above, did not run any collision search, and did
  not verify the KAT files byte-for-byte against the spec (the build's KAT
  check passes, but that only shows the C code is self-consistent).
- **Thread-safety (minor, not a spec issue):** `byte_table` /
  `byte_table_ready` are non-atomic file-scope globals lazily initialised
  inside `CryptHash`; concurrent first calls race.
