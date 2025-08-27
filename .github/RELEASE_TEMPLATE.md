# PRF support + Integration Snapshot (2025-08-26)

## Overview
This release preserves and documents:
- FIDO2 PRF advertisement (via hmac-secret)
- Integration materials for Satochip MuSig2 (CLI, Web UI, Expo NFC)

## What changed
- Minimal code change to advertise `"prf"` in GetInfo extensions
- Added docs + PRF GetInfo probe under `docs/support/fido2_prf/`
- Added `integration/` with manifest, changelog, and MuSig2 support materials

## How to verify PRF
```
pip install python-fido2 pyscard
python3 docs/support/fido2_prf/ctap_getinfo_prf_check.py --reader "<PCSC Reader Name>"
```
Expect `has_prf: true`.

## Assets
Upload the following from the repo `backups/` folder:
- integration-2025-08-26.zip
- feat-prf-support-2025-08-26.bundle
- main-integration-2025-08-26.bundle

Refer to docs/releases/2025-08-26-prf-support.md for checksums and full details.
