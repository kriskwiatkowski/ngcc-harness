# NGCC Round 1 reproduction harness

Build tooling and runnable reproducers for the findings published at
<https://ngcc.dev>. Every candidate's **reference implementation** is
compiled from the submitter's own sources into one shared library per
parameter set, driven through the official ICCS API exactly as the official
`KAT_*.c` generators do, and the reported defects are demonstrated against
those libraries by `tools/ngcc_attack`.

The required candidate reference sources are included in this repository.
Nothing else shipped inside a submission is executed: no candidate Makefile,
CMake, script or prebuilt binary is run. Each `<id>/Makefile` lists the sources
explicitly and compiles them with fixed flags (see `api/README.md`, "Rules
that every candidate Makefile follows").

This repository is not affiliated with NICCS. `SOURCE_ARCHIVES.md` records the
official submission archives from which the included source files were taken.

## Quick start

```sh
make -C api harness                  # bin/ngcc_kat, the KAT harness
make -C tools                        # tools/ngcc_attack, the reproducer
make -C kem-01 && make -C sign-07    # <id>/lib/lib<instance>.so
make -C kem-01 test                  # reproduce the submitted KATs (kat.sha256)
tools/reproduce.sh                   # run every reproducer and its controls
tools/reproduce.sh kem-01            # or one candidate
make design-audit                    # static specification/parameter findings
make check-vulnerabilities           # validate all stable vulnerability IDs
```

`make -j8 all test` builds and KAT-tests every included candidate. Run
`make reproduce` after the libraries have been built. Requirements: gcc, GNU
make and python3; some candidates need `-lgmp` or `-lcrypto` (recorded in their
Makefile).

## Layout

```
api/            KAT harness (bin/ngcc_kat), link shim, generic make rules; api/README.md
tools/          ngcc_attack.c reproducer, reproduce.sh runner; tools/README.md
security/       complete vulnerability inventory, static audit and exact evidence
<id>/           included reference sources, per-candidate Makefile,
                kat.sha256 manifest, and patches/ where shipped source cannot
                compile as-is; kex-02, sign-03 and kem-29 also have
                candidate-local reproducer source
downloads.csv   candidate list with archive URLs from niccs.org.cn
download.sh     optional: fetch original archives into orig/<id>/orig.zip
extract.sh      optional: unpack an original archive for provenance checks
SOURCE_ARCHIVES.md  archive sizes and SHA-256 digests for included candidates
```

Candidate ids (`sign-NN`, `kem-NN`, `kex-NN`, `hash-NN`) follow the numbering
of the official Round 1 lists. Only candidates covered by a published report,
or used as a control by `reproduce.sh`, have sources and build files here.
Candidates used only by `security/design_parameter_audit.py` contain the exact
specification and source files cited by that audit and are not build targets.
Submitted test-vector files are not included: the compact `kat.sha256`
manifests let `make test` compare freshly generated vectors to every required
reference digest without retaining multi-gigabyte text files.

Every published issue is identified in `security/vulnerabilities.csv` by its
stable `xxx-yy-z` ID. The verification field distinguishes runtime witnesses,
static checks, findings covered by both, and review findings for which no cheap
automated witness is claimed.

`api/drng.c`, `api/auxfunc.c` and the `api/API_PKC`, `api/API_CryptHash`
trees are the official NICCS API package files, unmodified; the harness links
the official DRNG into any instance directory that ships without its own copy.
