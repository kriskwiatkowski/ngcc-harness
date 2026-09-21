#!/bin/sh
# Reproduce every demonstrated defect reported in this repository.
#
#   make -C api harness          # once
#   make -C <candidate>          # build the candidate libraries you want
#   tools/reproduce.sh           # run every reproducer
#   tools/reproduce.sh hash-09   # just one candidate
#
# Each line is either
#   ATTACK <check> <instance> CONFIRMED ...      the reported defect is present
#   ATTACK <check> <instance> NOT-CONFIRMED ...  it is not
# Control rows are marked [control] and are EXPECTED to print NOT-CONFIRMED:
# they run the same check against an unaffected candidate to show the test
# itself is sound.
#
# Exit status: 0 if every selected finding reproduced, every selected control
# stayed clean, and no required library was missing.

set -u
cd "$(dirname "$0")/.." || exit 2
A=tools/ngcc_attack
[ -x "$A" ] || { echo "build first: make -C tools" >&2; exit 2; }

only="${1:-}"
fail=0
skipped=0

# run <candidate> <label> <expect CONFIRMED|NOT-CONFIRMED> <args...>
run() {
    cand=$1; label=$2; expect=$3; shift 3
    [ -n "$only" ] && [ "$only" != "$cand" ] && return 0
    # the library argument is the first remaining one after the check name
    lib=$2
    if [ ! -f "$lib" ]; then
        echo "SKIP   $cand $label (build it: make -C $cand)"
        skipped=$((skipped + 1))
        return 0
    fi
    out=$("$A" "$@" 2>&1)
    rc=$?
    case "$out" in
        *CONFIRMED*) got=CONFIRMED ;;
        *) got=ERROR ;;
    esac
    case "$out" in *NOT-CONFIRMED*) got=NOT-CONFIRMED ;; esac
    if [ "$got" = "$expect" ]; then
        printf '%s  %s\n' "$label" "$out"
    else
        printf 'UNEXPECTED (%s, wanted %s) %s\n' "$got" "$expect" "$out"
        fail=$((fail + 1))
    fi
    return 0
}

echo "== hash-09 Eijen: trivial collisions (report: Critical) =="
for l in hash-09/lib/*.so; do
    run hash-09 "        " CONFIRMED hash-collide-zeropad "$l"
done
run hash-04 "[control]" NOT-CONFIRMED hash-collide-zeropad hash-04/lib/libCHAMP-512.so
run hash-12 "[control]" NOT-CONFIRMED hash-collide-zeropad hash-12/lib/libIphe-1024.so

echo
echo "== hash-17 MasterCube: pad10*1 boundary collisions (report: Critical) =="
run hash-17 "        " CONFIRMED hash-collide-rate hash-17/lib/libMasterCube-512.so  959
run hash-17 "        " CONFIRMED hash-collide-rate hash-17/lib/libMasterCube-768.so  703
run hash-17 "        " CONFIRMED hash-collide-rate hash-17/lib/libMasterCube-1024.so 447
run hash-17 "[control]" NOT-CONFIRMED hash-collide-rate hash-17/lib/libMasterCube-512.so 955

echo
echo "== hash-18 / hash-20: no domain separation between digest lengths (report: High) =="
run hash-18 "        " CONFIRMED hash-prefix hash-18/lib/libMEGASCON-384.so hash-18/lib/libMEGASCON-512.so
run hash-20 "        " CONFIRMED hash-prefix hash-20/lib/libMOZI-384.so     hash-20/lib/libMOZI-512.so
run hash-04 "[control]" NOT-CONFIRMED hash-prefix hash-04/lib/libCHAMP-512.so hash-04/lib/libCHAMP-1024.so

echo
echo "== kem-01 Aigis-Enc+: dead implicit rejection (report: Critical) =="
for l in kem-01/lib/*.so; do
    run kem-01 "        " CONFIRMED kem-ct-flip "$l"
done

echo
echo "== kem-09 Cheetah / kem-18 Loong: rejection mask leaks the secret (report: Critical) =="
for l in kem-09/lib/*.so; do run kem-09 "        " CONFIRMED kem-reject-mask "$l"; done
for l in kem-18/lib/*.so; do run kem-18 "        " CONFIRMED kem-reject-mask "$l"; done
run kem-22 "[control]" NOT-CONFIRMED kem-reject-mask kem-22/lib/libMithril-128.so

echo
echo "== kem-29 Polar-KEM: public-key-only shared-secret recovery (report: Critical) =="
if [ -z "$only" ] || [ "$only" = kem-29 ]; then
    if [ -f kem-29/lib/libPolarKEM-128.so ]; then
        python3 kem-29/reproduce_public_recovery.py || fail=$((fail + 1))
    else
        echo "SKIP   kem-29 (build it: make -C kem-29)"; skipped=$((skipped + 1))
    fi
fi

echo
echo "== kex-02 AFS-KEX: completed-session key recovery after long-term compromise (report: Critical) =="
if [ -z "$only" ] || [ "$only" = kex-02 ]; then
    if [ -x kex-02/reproduce_pfs_break ] &&
       [ -x kex-02/reproduce_pfs_break_c256 ] &&
       [ -x kex-02/reproduce_pfs_break_c512 ]; then
        kex-02/reproduce_pfs_break || fail=$((fail + 1))
        kex-02/reproduce_pfs_break_c256 || fail=$((fail + 1))
        kex-02/reproduce_pfs_break_c512 || fail=$((fail + 1))
    else
        echo "SKIP   kex-02 (build it: make -C kex-02 exploit)"; skipped=$((skipped + 1))
    fi
fi

echo
echo "== sign-03 CEDRUS+C: adaptive FORS leaf-accumulation forgery (report: Critical) =="
if [ -z "$only" ] || [ "$only" = sign-03 ]; then
    if [ -x sign-03/reproduce_forgery ] && [ -f sign-03/lib/libCEDRUSC-160f.so ]; then
        sign-03/reproduce_forgery sign-03/lib/libCEDRUSC-160f.so || fail=$((fail + 1))
    else
        echo "SKIP   sign-03 (build it: make -C sign-03 exploit)"; skipped=$((skipped + 1))
    fi
fi

echo
echo "== sign-01 Aigis-Sig+ / sign-07 CS: SUF-CMA malleability (report: High) =="
run sign-01 "        " CONFIRMED sig-malleable sign-01/lib/libAigis-sig1.so
run sign-07 "        " CONFIRMED sig-malleable sign-07/lib/libCS-128.so

echo
echo "== sign-15 MORNING-ATLAS: ignored hint padding violates SUF-CMA (report: Critical) =="
for l in sign-15/lib/*.so; do
    run sign-15 "        " CONFIRMED sig-hint-padding "$l"
done

echo
echo "== sign-25 SQIsign2D2: verifier verdict depends on stale stack state (report: Critical) =="
run sign-25 "        " CONFIRMED sig-uninit-verdict sign-25/lib/libSQISign2Dsquare-Level2-eff_uncompressed.so
run sign-25 "[control]" NOT-CONFIRMED sig-uninit-verdict sign-25/lib/libSQISign2Dsquare-Level2-eff_compressed.so

echo
echo "== sign-32 UVW: verifier accepts anything (report: Critical) =="
run sign-32 "        " CONFIRMED sig-accept-all sign-32/lib/libUVW-128.so
run sign-32 "        " CONFIRMED sig-accept-all sign-32/lib/libUVW-256.so

echo
echo "== sign-12 Galas: key generation ignores the seed (report: Critical) =="
run sign-12 "        " CONFIRMED keygen-determinism sign-12/lib/libGalas-160S.so
run kem-01  "[control]" NOT-CONFIRMED keygen-determinism kem-01/lib/libAigis-enc1.so

echo
echo "== kem-17 HEP-QC / sign-33 VDOO: identical key in every fresh process (report: Critical) =="
if { [ -z "$only" ] || [ "$only" = kem-17 ]; } && [ -f kem-17/lib/libhep-qc-1.so ]; then
    a=$("$A" keygen-fresh kem-17/lib/libhep-qc-1.so 0x01 | awk '{print $NF}')
    b=$("$A" keygen-fresh kem-17/lib/libhep-qc-1.so 0x99 | awk '{print $NF}')
    c=$("$A" keygen-fresh kem-01/lib/libAigis-enc1.so 0x01 | awk '{print $NF}')
    d=$("$A" keygen-fresh kem-01/lib/libAigis-enc1.so 0x99 | awk '{print $NF}')
    if [ "$a" = "$b" ]; then
        echo "          ATTACK keygen-fresh         hep-qc-1 CONFIRMED identical first key across two fresh processes with different seeds ($a)"
    else
        echo "UNEXPECTED hep-qc-1 keys differ across seeds"; fail=$((fail + 1))
    fi
    if [ "$c" != "$d" ]; then
        echo "[control] ATTACK keygen-fresh         Aigis-enc1 NOT-CONFIRMED keys differ across seeds, as they should"
    else
        echo "UNEXPECTED control Aigis-enc1 keys identical"; fail=$((fail + 1))
    fi
elif [ -z "$only" ] || [ "$only" = kem-17 ]; then
    echo "SKIP   kem-17 (build it: make -C kem-17)"; skipped=$((skipped + 1))
fi

# VDOO advances an unseeded counter within a process, so successive in-process
# keys differ; the defect shows as an identical FIRST key per fresh process.
if { [ -z "$only" ] || [ "$only" = sign-33 ]; } && [ -f sign-33/lib/libvdoo_128.so ]; then
    a=$("$A" keygen-fresh sign-33/lib/libvdoo_128.so 0x01 | awk '{print $NF}')
    b=$("$A" keygen-fresh sign-33/lib/libvdoo_128.so 0x99 | awk '{print $NF}')
    if [ "$a" = "$b" ]; then
        echo "          ATTACK keygen-fresh         VDOO-128 CONFIRMED identical first key across two fresh processes with different seeds ($a)"
    else
        echo "UNEXPECTED VDOO-128 keys differ across seeds"; fail=$((fail + 1))
    fi
elif [ -z "$only" ] || [ "$only" = sign-33 ]; then
    echo "SKIP   sign-33 (build it: make -C sign-33)"; skipped=$((skipped + 1))
fi

echo
if [ "$fail" -eq 0 ] && [ "$skipped" -eq 0 ]; then
    echo "all reproducers behaved as reported"
else
    echo "$fail reproducer(s) did NOT behave as reported ($skipped skipped)"
fi
exit $((fail > 0 || skipped > 0))
