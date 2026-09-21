# NGCC Round 1 reproduction harness

Build tooling and runnable reproducers for the findings published at
<https://ngcc.dev>. Every candidate's **reference implementation** is
compiled from the submitter's own sources into one shared library per
parameter set, driven through the official ICCS API exactly as the official
`KAT_*.c` generators do, and the reported defects are demonstrated against
those libraries by `tools/ngcc_attack`.

Nothing shipped inside a submission is ever executed: no candidate Makefile,
CMake, script or prebuilt binary is run. Each `<id>/Makefile` lists the sources
explicitly and compiles them with fixed flags (see `api/README.md`, "Rules
that every candidate Makefile follows").

This repository is not affiliated with NICCS. The submission archives are
not redistributed here; `download.sh` fetches them from niccs.org.cn.

## Quick start

```sh
IDS="kem-01 sign-07" ./download.sh   # fetch orig/<id>/orig.zip (all 119 without IDS)
./extract.sh kem-01 sign-07          # unpack into <id>/, strip execute bits
make -C api harness                  # bin/ngcc_kat, the KAT harness
make -C tools                        # tools/ngcc_attack, the reproducer
make -C kem-01 && make -C sign-07    # <id>/lib/lib<instance>.so
make -C kem-01 test                  # reproduce the submitted KATs (kat.sha256)
tools/reproduce.sh                   # run every reproducer and its controls
tools/reproduce.sh kem-01            # or one candidate
```

`make -j8 all test` builds and KAT-tests every candidate that has been
extracted; `make reproduce` runs the full reproducer suite. Requirements: gcc,
GNU make, python3, curl, bsdtar or unzip; some candidates need `-lgmp` or
`-lcrypto` (recorded in their Makefile).

## Layout

```
api/            KAT harness (bin/ngcc_kat), link shim, generic make rules; api/README.md
tools/          ngcc_attack.c reproducer, reproduce.sh runner; tools/README.md
<id>/           per-candidate Makefile, kat.sha256 manifest, patches/ where a
                shipped source cannot compile as-is; kem-29 also has its own
                reproducer script
downloads.csv   candidate list with archive URLs from niccs.org.cn
download.sh     fetches archives into orig/<id>/orig.zip (untracked)
extract.sh      unpacks orig/<id>/orig.zip into <id>/ (untracked)
```

Candidate ids (`sign-NN`, `kem-NN`, `kex-NN`, `hash-NN`) follow the numbering
of the official Round 1 lists. Only candidates covered by a published report,
or used as a control by `reproduce.sh`, have build files here.

`api/drng.c`, `api/auxfunc.c` and the `api/API_PKC`, `api/API_CryptHash`
trees are the official NICCS API package files, unmodified; the harness links
the official DRNG into any instance directory that ships without its own copy.
