# Release: PRF support + Integration Snapshot (2025-08-26)

This release documents and preserves:
- FIDO2 PRF (WebAuthn "prf") advertisement work, mapped to existing CTAP hmac-secret logic
- Integration materials for Satochip MuSig2 demos (CLI, Web UI, Expo NFC)

Use this release to track the state of both lines of work and to test PRF advertisement end-to-end.

## Highlights
- PRF advertised in  via  (minimal change)
- Docs and PRF GetInfo probe added under 
- Integration support folder with Satochip MuSig2 tools, webapp, and RN helpers
- Preservation assets uploaded (zip + git bundles)

## Tags and Branches
- Tag (integration snapshot): 
- Tag (PRF branch snapshot): 
- Branch (PR for upstream): 

Links:
- Branch: https://github.com/eminogrande/FIDO2Applet/tree/feat/prf-support
- Tags: https://github.com/eminogrande/FIDO2Applet/tags

## Changes (summary)
- : add  ("prf") and include it in GetInfo extensions
- : list PRF as supported (via hmac-secret)
- : README, CARD_INFO, and PRF GetInfo probe script
- : manifest, changelog, and separated materials for PRF and MuSig2

## Build and Install (FIDO2 PRF)
- Build: 
- Install (SCP03):


## Verify PRF Advertisement
- Dependencies: Defaulting to user installation because normal site-packages is not writeable
- Run:

- Expect  (exit code 0)

## Browser Note
WebAuthn PRF requires a platform authenticator or a roaming CTAP HID/NFC authenticator. Browsers do not use PC/SC smartcards directly.

## Assets (checksums)
- Integration zip: 
  - SHA256: c1a7a785d96ee2e0d2a4e817b9531a72596951b09aad51f4a015e742baa98c28
- Bundle (PRF branch): 
  - SHA256: 47abef2ad81836108ea60c859955e7cbf60b0f065dd94577e806172feea9e86f
- Bundle (Main/integration): 
  - SHA256: 7478f0dbe19c8e7c519a8430ad1ea213e7b1e1506ab39457c16ff5687a715aea

Direct links:
- Zip: https://github.com/eminogrande/FIDO2Applet/blob/main/backups/integration-2025-08-26.zip
- PRF bundle: https://github.com/eminogrande/FIDO2Applet/blob/main/backups/feat-prf-support-2025-08-26.bundle
- Main bundle: https://github.com/eminogrande/FIDO2Applet/blob/main/backups/main-integration-2025-08-26.bundle

## Upstream PR Plan (nuri-com/FIDO2Applet)
- Branch  adds PRF advertisement (GetInfo) and docs under 
- Open PR against upstream  with the minimal diff and link to these notes

## Appendix
- Card/Reader notes: 
- Integration manifest: 
- Integration changelog: 
