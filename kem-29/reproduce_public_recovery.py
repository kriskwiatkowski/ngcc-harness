#!/usr/bin/env python3
"""Reproduce Polar-KEM shared-secret recovery using only pk and ct.

This loads the source-built libraries in kem-29/lib.  The two internal helpers
are hidden by the export map, so their ELF symbol offsets are resolved with
`nm`; no secret-key bytes are passed to either helper.
"""

import ctypes
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def symbol_offset(library: Path, symbol: str) -> int:
    symbols = subprocess.check_output(["nm", str(library)], text=True)
    match = re.search(rf"^([0-9a-f]+) [Tt] {re.escape(symbol)}$", symbols, re.M)
    if not match:
        raise RuntimeError(f"missing local symbol {symbol} in {library}")
    return int(match.group(1), 16)


def reproduce(library: Path) -> bool:
    dll = ctypes.CDLL(str(library))
    for name in ("kem_get_pk_len_bytes", "kem_get_sk_len_bytes",
                 "kem_get_ss_len_bytes", "kem_get_ct_len_bytes"):
        getattr(dll, name).restype = ctypes.c_ulonglong

    pk_len = dll.kem_get_pk_len_bytes()
    sk_len = dll.kem_get_sk_len_bytes()
    ss_len = dll.kem_get_ss_len_bytes()
    ct_len = dll.kem_get_ct_len_bytes()
    pk = (ctypes.c_ubyte * pk_len)()
    sk = (ctypes.c_ubyte * sk_len)()
    ss = (ctypes.c_ubyte * ss_len)()
    ct = (ctypes.c_ubyte * ct_len)()
    pk_out = ctypes.c_ulonglong()
    sk_out = ctypes.c_ulonglong()
    ss_out = ctypes.c_ulonglong()
    ct_out = ctypes.c_ulonglong()
    if dll.kem_keygen(pk, ctypes.byref(pk_out), sk, ctypes.byref(sk_out)) != 0:
        raise RuntimeError("kem_keygen failed")
    if dll.kem_enc(pk, pk_len, ss, ctypes.byref(ss_out), ct,
                   ctypes.byref(ct_out)) != 0:
        raise RuntimeError("kem_enc failed")

    # For an ELF ET_DYN object, runtime_address = load_base + st_value.
    exported = ctypes.cast(dll.kem_enc, ctypes.c_void_p).value
    load_base = exported - symbol_offset(library, "kem_enc")
    helper_type = ctypes.CFUNCTYPE(
        ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
    recover = helper_type(
        load_base + symbol_offset(library, "polarkem_recover_message"))
    derive = helper_type(
        load_base + symbol_offset(library, "polarkem_derive_valid_secret"))

    # mu is the same size as the shared secret in every submitted instance.
    mu = (ctypes.c_ubyte * ss_len)()
    recovered = (ctypes.c_ubyte * ss_len)()
    if recover(pk, ct, mu) != 0 or derive(mu, ct, recovered) != 0:
        raise RuntimeError("public-only recovery helpers failed")
    return bytes(recovered) == bytes(ss)


def main() -> int:
    libraries = sorted((ROOT / "lib").glob("libPolarKEM-*.so"))
    if not libraries:
        raise SystemExit("build kem-29 first: make -C kem-29")
    failed = False
    for library in libraries:
        matched = reproduce(library)
        print(f"{library.name}: public-only shared-secret recovery: "
              f"{'MATCH' if matched else 'FAIL'}")
        failed |= not matched
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
