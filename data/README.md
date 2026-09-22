# Public reference data

This directory complements the runnable attack harness with data for every
Round 1 candidate, whether or not a vulnerability has been reported.

- `parameters.csv` contains one row per submitted implementation instance. The
  byte sizes are the values exposed by the official ICCS API getters and
  captured from the source-built libraries. Blank fields do not apply to that
  primitive type.
- `sign.csv`, `kem.csv`, `kex.csv`, and `hash.csv` contain the official candidate
  names and submitters.
- `specifications.csv` records each canonical PDF's byte size, SHA-256 digest,
  and path inside the original submission archive.
- `spec-sources.tsv` records the path of each canonical specification inside
  its original submission archive.

Each `<candidate>/` directory also contains `<candidate>-spec.pdf` and
`pseudocode.md`. The latter is the human-readable extraction of the algorithms,
parameter tables, and specification/implementation comparison.

Regenerate this dataset from the private analysis tree and validate the public
copy with:

```sh
make sync-reference-data NGCC1=../ngcc1
make check-reference-data
```
