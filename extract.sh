#!/bin/sh
# Unpack downloaded submission archives orig/<id>/orig.zip into <id>/, the
# layout the per-candidate Makefiles expect (paths in each Makefile are
# relative to <id>/). Execute bits are stripped from everything extracted:
# nothing shipped in a submission is run, the harness compiles from source.
#
#   ./extract.sh              every archive under orig/
#   ./extract.sh kem-01 ...   selected candidates
set -u
cd "$(dirname "$0")" || exit 2
ids=${*:-$(ls -d orig/*/ 2>/dev/null | cut -d/ -f2)}
[ -n "$ids" ] || { echo "nothing under orig/; run ./download.sh first" >&2; exit 1; }
rc=0
for id in $ids; do
    z=orig/$id/orig.zip
    [ -s "$z" ] || { echo "missing $z (run: IDS=$id ./download.sh)" >&2; rc=1; continue; }
    [ -f "$id/Makefile" ] || echo "note: no $id/Makefile here, extracting anyway" >&2
    mkdir -p "$id"
    if command -v bsdtar >/dev/null 2>&1; then
        bsdtar -xf "$z" -C "$id" || { echo "FAIL  $id" >&2; rc=1; continue; }
    else
        unzip -qo "$z" -d "$id" || { echo "FAIL  $id" >&2; rc=1; continue; }
    fi
    find "$id" -type f ! -name Makefile ! -path "$id/patches/*" -exec chmod a-x {} +
    echo "ok    $id"
done
exit $rc
