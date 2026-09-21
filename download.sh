#!/bin/bash
# Download all 119 NGCC Round 1 candidate submission zips from niccs.org.cn,
# in parallel. Each candidate has its own directory <type>-<NN>/ (type/NN match
# sign.csv, kem.csv, kex.csv, hash.csv) and the zip is saved there under its
# original name. The list of candidates is read from downloads.csv
# (ID;Category;No;Algorithm;ZipFile;DownloadURL;PageURL;ForumThread).
# Generated 2026-09-20 from https://www.niccs.org.cn/niccs/Proposal/pc/list.html
#
# Usage: [IDS="kem-01 sign-07"] ./download.sh [base-dir] [jobs]
#   base-dir  default: directory containing this script
#   jobs      parallel downloads, default 16 (or $JOBS)
# Existing zips are skipped and partial .part files are resumed (the server
# supports HTTP ranges), so it is safe to re-run. Each fetch is retried.

BASE="${1:-$(cd "$(dirname "$0")" && pwd)}"
JOBS="${2:-${JOBS:-16}}"
CSV="$BASE/downloads.csv"
LOG="$BASE/download.log"

[ -r "$CSV" ] || { echo "missing $CSV" >&2; exit 1; }

# get <id> <zipname> <url>
get() {
    local id="$1" zip="orig.zip" url="$3" dir="$BASE/orig/$1" try
    mkdir -p "$dir"
    if [ -s "$dir/$zip" ]; then
        echo "skip  $id/$zip"
        return 0
    fi
    for try in 1 2 3 4 5; do
        if curl -fsSL -A "Mozilla/5.0" --retry 3 --retry-delay 3 \
                --connect-timeout 30 --speed-time 60 --speed-limit 1024 \
                -C - -o "$dir/$zip.part" "$url"; then
            mv "$dir/$zip.part" "$dir/$zip"
            echo "ok    $id/$zip ($(stat -c %s "$dir/$zip") bytes)"
            return 0
        fi
        echo "retry $id/$zip (attempt $try failed)" >&2
        sleep $((try * 5))
    done
    echo "FAIL  $id/$zip $url" >&2
    return 1
}
export -f get
export BASE

# Rows are tab-separated <id> <zip> <url>; xargs -0 keeps '+', spaces and
# non-ASCII in zip names intact.
# IDS="kem-01 sign-07" ./download.sh fetches only those candidates.
FILTER='.'
[ -n "${IDS:-}" ] && FILTER="^($(echo "$IDS" | tr ' ' '|'));"
tail -n +2 "$CSV" | grep -E "$FILTER" | awk -F';' '{printf "%s\t%s\t%s\0", $1, $5, $6}' \
    | xargs -0 -P "$JOBS" -I{} bash -c 'IFS=$'"'"'\t'"'"' read -r id zip url <<<"{}"; get "$id" "$zip" "$url"' \
    2>&1 | tee "$LOG"

echo "done: $(find "$BASE/orig" -mindepth 2 -maxdepth 2 -name "orig.zip" | wc -l) zips, $(grep -c '^FAIL' "$LOG") failed"
