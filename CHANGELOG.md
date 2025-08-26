# Changelog

All notable changes to this project will be documented in this file.

The format follows Keep a Changelog, and this project adheres to Semantic Versioning where applicable.

## [Unreleased]

### Added
- Advertise WebAuthn "prf" extension in `authenticatorGetInfo` (via `CannedCBOR`).
- Documentation under `docs/support/fido2_prf/` describing build, install, testing, and card/reader notes.
- Tooling: `tools/ctap_getinfo_prf_check.py` to verify that `prf` appears in the `extensions` list returned by `authenticatorGetInfo` over PC/SC.

