# Integration Manifest

This manifest enumerates the key files and folders for both FIDO2 (PRF) and Satochip (MuSig2) work hosted in this repo.

## FIDO2 PRF
- Code: `src/main/java/us/q3q/fido2/CannedCBOR.java` (PRF advertisement)
- Docs: `docs/support/fido2_prf/README.md` (build/install/test + merge)
- Card/Reader: `docs/support/fido2_prf/CARD_INFO.md`
- Probe: `docs/support/fido2_prf/ctap_getinfo_prf_check.py`
- Upstream branch: `feat/prf-support` (fork: eminogrande/FIDO2Applet)

## Satochip MuSig2
- Applet sources: `SatochipApplet/`
- Docs: `integration/satochip_musig2/README.md`
- CLIs: `integration/satochip_musig2/tools/`
- Web UI: `integration/satochip_musig2/webapp/`
- Expo helpers: `integration/satochip_musig2/rn/`

## Combined Docs
- `README_FIDO2_Satochip.md`
- `integration/README.md`
- `integration/CHANGELOG.md` (this repo’s integration changes)

