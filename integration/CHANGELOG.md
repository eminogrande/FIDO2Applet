# Integration Changelog

Date: 2025-08-26

This changelog tracks work done in this repo that spans multiple applets and won’t necessarily be upstreamed as-is.

## Added
- FIDO2 PRF (WebAuthn "prf") advertisement:
  - Branch `feat/prf-support` (based on `nuri/main`).
  - Code: `src/main/java/us/q3q/fido2/CannedCBOR.java` (adds `PRF_EXTENSION_ID`, includes `"prf"` in GetInfo extensions).
  - Docs: `docs/support/fido2_prf/` including `README.md`, `CARD_INFO.md`, and `ctap_getinfo_prf_check.py` probe.
  - Root `CHANGELOG.md` entry for upstream PR context.
- Satochip MuSig2 tooling and docs:
  - Integration docs: `integration/satochip_musig2/README.md`.
  - CLI: `integration/satochip_musig2/tools/`.
  - Web UI: `integration/satochip_musig2/webapp/`.
  - Expo helpers: `integration/satochip_musig2/rn/`.
- Consolidated doc: `README_FIDO2_Satochip.md`.

## Notes
- Keep upstream PRs minimal; use `integration/` to collect supporting materials and demos.

