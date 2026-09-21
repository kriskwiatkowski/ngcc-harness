# Reproducers

Runnable witnesses for every defect reported in the `*/report.md` files. Each
one drives a candidate's own reference implementation through the uniform ABI
described in `api/README.md`. No submission file is modified and no shipped
binary is executed; the libraries are compiled from the candidates' own sources
by the per-candidate Makefiles.

## Running everything

```sh
make -C api harness            # once
make -C tools                  # build the reproducer
make -C hash-09 && make -C kem-01 && ...   # build the candidates you want
tools/reproduce.sh             # run every reproducer
tools/reproduce.sh hash-09     # or just one candidate
```

`reproduce.sh` exits 0 when every reported defect reproduced and every control
stayed clean. A candidate whose libraries are not built is reported as `SKIP`
rather than a failure.

## Reading the output

```
ATTACK <check> <instance> CONFIRMED|NOT-CONFIRMED <detail>
```

Rows marked `[control]` run the *same* check against a candidate that does not
have the defect, and are expected to print `NOT-CONFIRMED`. They are there so a
reader can see the test distinguishes broken from sound implementations rather
than always firing.

## Checks

| check | defect | candidates |
|---|---|---|
| `hash-collide-zeropad` | `H(M) == H(M‖0000000)`; the byte-aligned padding branch writes `0x01` where MSB-first `pad10*` needs `0x80` | Eijen (hash-09) |
| `hash-collide-rate` | `pad10*1` puts both padding bits in one position when `\|M\| mod r == r-1` | MasterCube (hash-17) |
| `hash-prefix` | no domain separation, so the short digest is a byte-exact prefix of the long one | Megascon (hash-18), Mozi (hash-20) |
| `kem-ct-flip` | the FO implicit-rejection branch is dead code, so modified ciphertexts still return the original shared secret | Aigis-Enc+ (kem-01) |
| `kem-reject-mask` | the rejection mask is not normalised to all-ones, so the returned value retains the low 7 bits of every byte of the valid secret | CheetahKEM (kem-09), LoongKEM (kem-18) |
| `sig-malleable` | non-canonical trailing encoding bytes, so a distinct signature verifies for the same message (SUF-CMA) | Aigis-Sig+ (sign-01), CS (sign-07) |
| `sig-accept-all` | the verifier discards its result and accepts anything | UVW (sign-32) |
| `keygen-determinism` | key generation ignores the seeded DRNG, so two different seeds give the same key | Galas (sign-12) |
| `keygen-fresh` | the seed is ignored but an internal generator advances within a process, so the defect shows as an identical *first* key in every fresh process | HEP-QC (kem-17), VDOO (sign-33) |

VDOO needs `keygen-fresh` rather than `keygen-determinism`: its unseeded
generator carries a counter, so two keys made in one process differ and an
in-process test would wrongly clear it.

Polar-KEM has its own reproducer, `kem-29/reproduce_public_recovery.py`, because
the break is specific: the submission ships `polarkem_recover_message(pk, ct, mu)`
and `polarkem_derive_valid_secret(mu, ct, ss)`, which together recover the
session key from public data alone. `reproduce.sh` runs it.

## Crashes during a sweep

Several candidate verifiers fault on malformed input, which is a reported
defect in its own right. `ngcc_attack` traps the fault, counts it and carries
on, so one bad input cannot hide the rest of the sweep. Aigis-Sig+ reports both
its malleable bits and the flips that crash verification in the same line.
Jumping out of a fault handler is not strictly portable; it is reliable on
Linux and is confined to this test tool.

## Scope

These demonstrate the reported behaviour. They are not cryptanalysis: none of
them attacks a hardness assumption, and a `CONFIRMED` line means only that the
described defect is present in the built library. Findings that are real but
have no cheap runnable witness (for example CreTAKE's 64-bit ephemeral secret,
which needs about 2^64 offline work) are documented in the corresponding
`report.md` and `pseudocode.md` instead.
