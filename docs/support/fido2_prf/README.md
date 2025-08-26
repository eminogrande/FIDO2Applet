# FIDO2 PRF Support (WebAuthn “prf”) — Notes

Date: 2025-08-26

## Summary

- Advertises WebAuthn "prf" support. The PRF output is implemented via the CTAP `hmac-secret` mechanism already present in this applet.
- Changes are intentionally minimal and self-contained in `CannedCBOR` so they are easy to review and revert if needed.

## Code Changes

- `src/main/java/us/q3q/fido2/CannedCBOR.java`:
  - Added `PRF_EXTENSION_ID` bytes (`"prf"`).
  - Included `"prf"` in the `AUTH_INFO_START` extensions array (and updated the item count from 6 to 7).
- `README.md`:
  - Added a row in Implementation Status: “Webauthn prf extension — Supported (via CTAP hmac-secret)”.

No other logic changes are required because the PRF implementation uses `hmac-secret` under the hood.

## Build

- Requires Java 8 + JavaCard SDK 3.0.4.
- Example (Gradle):

```
export JC_HOME=<path_to_your_jckit_304>
./gradlew buildJavaCard
```

The `.cap` will be under `build/javacard/`.

## Install (SCP03)

Use `gp.jar` or GlobalPlatformPro-compatible tool with SCP03 keys for your card and the correct PC/SC reader.

```
java -jar gp.jar -r "<Reader Name>" \
  --key-enc <ENC> --key-mac <MAC> --key-dek <DEK> \
  -f --install build/javacard/FIDO2Applet.cap
```

For vendor cards shipping with fixed SCP03 keys, substitute the known keys; otherwise perform GP key establishment first.

## Verifying PRF Advertisement

You can verify the extension advertisement from `authenticatorGetInfo`:

- With the project’s existing Python tests or the provided probe script, confirm the `extensions` array includes `"prf"` alongside `hmac-secret`, `credBlob`, `largeBlobKey`, `minPinLength`, `credProtect`, etc.
- Using the probe script (PC/SC):

```
python3 -m pip install python-fido2 pyscard  # if needed
python3 tools/ctap_getinfo_prf_check.py --reader "<PCSC Reader Name>"
# exit code 0 means prf found; 1 means not found
```
- Browser WebAuthn testing of PRF requires a platform authenticator or a roaming CTAP HID/NFC authenticator. PC/SC cards are not used directly by browsers.

## Merge Plan (nuri-com/FIDO2Applet)

1. Create branch: `feat/prf-support` from `main`.
2. Apply the two changes above (CannedCBOR + README row).
3. Commit with message like: “Advertise WebAuthn prf extension (maps to hmac-secret).”
4. Add this folder under `docs/support/fido2_prf/` in the upstream repo.
5. Open PR with brief rationale and testing notes; mention that there is no additional runtime logic beyond hmac-secret.

## Reader and Card Notes

See `docs/support/fido2_prf/CARD_INFO.md` for example PC/SC reader selection and troubleshooting tips.
