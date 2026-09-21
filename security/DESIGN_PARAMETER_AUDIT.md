# Design and parameter-capacity audit

This audit looks for elementary security ceilings that are easy to validate
without trusting a candidate's lattice/MQ/isogeny estimator. It distinguishes
normative design choices from submitted-code conformance defects.

Run the reproducible inventory and registered checks with:

```sh
python3 security/design_parameter_audit.py
python3 security/design_parameter_audit.py --json > design-parameter-audit.json
```

The tool inventories all 586 currently built instances, including all 141 hash
instances and all 247 KEM/KEX shared-secret outputs. Its registered findings
then check exact specification text and source constants. A digest-size or
delivered-key-capacity row is only a ceiling; it is promoted to a finding only
when the construction makes the corresponding attack valid.

## Confirmed specification/design issues

| Finding | Candidate | Normative parameter | Elementary consequence |
|---|---|---|---|
| `kem-17-2` | HEP-QC-7 (`kem-17`) | The 512-bit set fixes `seedKEM` and `K` at 32 bytes, and derives the complete keypair from `seedKEM`. | At most `2^256` public keys; enumerate seeds and match the public key to recover the decapsulation key. Delivered-key capacity is also at most 256 bits. |
| `kem-12-1` | CTL-512 (`kem-12`) | The short-key format regenerates `f,g` from one 32-byte seed and recomputes `h=f^-1 g mod q`. | At most `2^256` public keys; seed enumeration recovers the target trapdoor data despite the nominal 512-bit lattice parameters. |
| `sign-02-1` | BiT-512 (`sign-02`) | `mu=H(tr || M)` is a 512-bit unsalted message representative. | A generic collision costs about `2^256`; ask for a signature on one colliding message and transfer it to the other. |
| `sign-06-1` | COMPASS-SIG-512 (`sign-06`) | `mu=H(pk || M)` is instantiated as a 512-bit unsalted message representative. | The same generic `2^256` collision-and-transfer forgery caps classical EUF-CMA security. |
| `sign-18-1` | Origami-512 (`sign-18`) | The PDF explicitly compresses every message with a fixed 64-byte `H_msg` before deriving `Hash(target || H_msg(M) || salt)`. | A collision in `H_msg` costs about `2^256` and survives every later salt value, transferring a signature to the other message. |
| `sign-31-1` | TSUOV-512 (`sign-31`) | The PDF defines `Expand_mu(seed_pk || M) := pseudohash(512, ...)`, then hashes `mu || salt`. | A roughly `2^256` `Expand_mu` collision transfers signatures; the later salt does not repair the colliding prehash. |

VDOO-512 (`sign-33-3`) has a separate normative proof gap. Its salt is fixed at
16 bytes while its EUF-CMA bound contains
`(q_s+q_h) q_s 2^-|salt|`. The term is already `2^-127` for one signing and one
hash query, and becomes order one around `2^64` signing queries. This prevents
the stated proof from substantiating 512-bit EUF-CMA security, but is not by
itself a concrete forgery.

The MEGASCON (`hash-18`) and MOZI (`hash-20`) cross-variant prefix relations are
also construction-level: shorter outputs are prefixes of longer variants on
the same short messages because the variants share initialization, padding,
and permutation behavior. This is a reproducible cross-function/domain-
separation weakness; it is not automatically a collision or preimage break of
an individual advertised variant.

## Confirmed implementation or specification-conformance ceilings

| Finding | Candidate | Submitted behavior | Classification |
|---|---|---|---|
| `kem-11-1` | COMPASS-KEM-512 (`kem-11`) | The IND-CPA keypair is derived from one 32-byte root and the KEM returns 32-byte keys, although the normative `n=512` algorithms use `n`-bit values. | Implementation/specification conformance break; key search and delivered-key capacity are at most 256 bits. |
| `kem-12-2` | CTL-512 (`kem-12`) | The adapter returns a 48-byte shared secret and uses a 48-byte `c2`; the PDF assigns 64 bytes to Level 5 `c2`. | Implementation/specification conformance break; delivered-key capacity is at most 384 bits. |
| `sign-06-2` | COMPASS-SIG-512 (`sign-06`) | KeyGen draws one 32-byte root, while the PDF requires an `n=512`-bit root. | Implementation/specification conformance break; at most `2^256` generated public keys. |
| `sign-08-1` | DARTS-512 (`sign-08`) | The implementation's unsalted `mu=H1(pk,M)` is 64 bytes. | Confirmed `2^256` collision ceiling; the PDF names `H1` but omits its output length. |
| `sign-22-1`, `sign-22-2` | Rhyme-512 (`sign-22`) | Both the full keypair root and unsalted message representative are fixed at 32 and 64 bytes respectively. | Two `2^256` ceilings. The PDF leaves both `rho_0` and `H_gen` output length undefined, so this is also a specification omission. |
| `kex-06-1` | MAMBA-NIKE-512 (`kex-06`) | The static CBD secret polynomial is deterministically sampled from a 32-byte noise seed. | Implementation/specification conformance break; for the public `rho`, enumerate noise seeds and match `b` in `2^256` work. |
| `sign-33-2` | VDOO-512 (`sign-33`) | The wrapper hashes arbitrary messages to 32 bytes before the specified signing transform. | About `2^128` generic collision-and-transfer work; the exact truncation is a source-level choice rather than a clear normative parameter. |
| `sign-15-3` | MORNING-ATLAS-192 (`sign-15`) | The source uses `kappa=64`, giving `log2(C(128,64) 2^64)=188.17143` challenge bits; the PDF uses 69. | Implementation-only parameter mismatch. |

## Cleared false positives and audit limits

- DARTS-512, FLIT-512, DKEM-512, DTRU-2048, WeaverKEM-512, and TSUOV-512
  use 64-byte Level-5 key seeds. Apparent 32-byte hits came from lower-level
  conditional branches.
- NTRE-512 and MAMBA-Viper-512 use two independent 32-byte secret-generating
  inputs, not a single 256-bit root. MAMBA-Frost-512 uses substantially more
  secret/error-seed material; its 32-byte value is a public-matrix seed.
- QingLuan-512 scales its key seed, salt, and multi-pipe hash output to 128
  bytes and explicitly salts collision-sensitive message binding.
- A shared-secret output length bounds deployable key capacity, but does not
  alone prove an IND-CCA distinguisher. Likewise, the registered `2^256`
  attacks are mathematical security ceilings, not computations attempted by
  this harness.
- The source review prioritizes claimed Level-5/512-bit instances. Absence
  from this report is not evidence that a candidate has no design flaw.
