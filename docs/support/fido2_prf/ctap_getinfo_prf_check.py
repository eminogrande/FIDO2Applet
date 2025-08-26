#!/usr/bin/env python3
"""
Small helper to query authenticatorGetInfo over PC/SC and verify that
the "prf" extension is advertised. Uses python-fido2's CtapPcscDevice.

Usage:
  python3 tools/ctap_getinfo_prf_check.py [--reader "<PCSC Reader Name>"] [--json]

Exit codes:
  0 = prf found
  1 = prf not found
  2 = no device / error
"""
import argparse
import json
import sys
from typing import Optional

try:
    from fido2.ctap2 import Ctap2
    from fido2.pcsc import CtapPcscDevice
except Exception as e:  # pragma: no cover
    print(f"python-fido2 not available: {e}", file=sys.stderr)
    sys.exit(2)


def pick_device(reader_name: Optional[str] = None) -> Optional[CtapPcscDevice]:
    # python-fido2 allows filtering by exact reader name
    try:
        devs = list(CtapPcscDevice.list_devices(reader_name))
    except TypeError:
        # older python-fido2 may not accept filter; fall back and filter locally
        devs = list(CtapPcscDevice.list_devices())
        if reader_name:
            devs = [d for d in devs if getattr(d, "reader", None) == reader_name]
    return devs[0] if devs else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reader", help="Exact PC/SC reader name to use", default=None)
    ap.add_argument("--json", action="store_true", help="Emit JSON output")
    args = ap.parse_args()

    dev = pick_device(args.reader)
    if not dev:
        # list available devices to help the user
        names = []
        try:
            for d in CtapPcscDevice.list_devices():
                names.append(getattr(d, "reader", str(d)))
        except Exception:
            pass
        msg = {
            "ok": False,
            "error": "No PC/SC FIDO2 device found",
            "readers": names,
        }
        if args.json:
            print(json.dumps(msg))
        else:
            print(msg["error"], "Available:", ", ".join(names), file=sys.stderr)
        return 2

    info = Ctap2(dev).get_info()
    # Normalize extensions to strings
    exts = []
    for x in (info.extensions or []):
        if isinstance(x, bytes):
            try:
                exts.append(x.decode("ascii", "ignore"))
            except Exception:
                exts.append(x.hex())
        else:
            exts.append(str(x))

    has_prf = any(e == "prf" for e in exts)

    result = {
        "ok": True,
        "reader": getattr(dev, "reader", None),
        "versions": list(info.versions or []),
        "extensions": exts,
        "has_prf": has_prf,
    }
    if args.json:
        print(json.dumps(result))
    else:
        print("Reader:", result["reader"]) 
        print("Versions:", ", ".join(result["versions"]))
        print("Extensions:", ", ".join(exts))
        print("prf present:", has_prf)

    return 0 if has_prf else 1


if __name__ == "__main__":
    sys.exit(main())

