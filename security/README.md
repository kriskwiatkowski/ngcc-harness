# Design and parameter audit

`design_parameter_audit.py` reproduces the static and information-theoretic
findings whose attacks are too large to execute. Run it with:

```sh
make design-audit
python3 security/design_parameter_audit.py --json
```

The candidate directories without Makefiles contain only the exact submitted
PDF and source files cited by these checks. They are evidence for the static
audit, not incomplete build targets. See `DESIGN_PARAMETER_AUDIT.md` for the
classification rules and limits.

`vulnerabilities.csv` is the complete public inventory of stable `xxx-yy-z`
issue IDs. Its verification field is one of `runtime`, `static`,
`runtime+static`, or `review`; `review` means the source/specification finding
is identified here without claiming a cheap automated witness. Validate the
inventory with:

```sh
make check-vulnerabilities
python3 security/check_vulnerability_ids.py --reports ../ngcc1
```
