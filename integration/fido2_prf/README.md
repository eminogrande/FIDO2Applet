# FIDO2 Applet (PRF support)

This folder contains supporting material for integrating the PRF (WebAuthn "prf" extension) into the Java Card FIDO2 applet.

## Code location in this repo

- Applet sources: `src/main/java/us/q3q/fido2/`
- Look for extension handling in `CannedCBOR` and where `GetInfo`/`makeCredential` extension lists are assembled.

## Build

```bash
export JAVA_HOME="/Library/Java/JavaVirtualMachines/temurin-8.jdk/Contents/Home"
export PATH="$JAVA_HOME/bin:$PATH"
# JavaCard SDK 3.0.4
# ant build (ensure your ant buildfile points to JCKIT_HOME=../oracle_javacard_sdks/jc304_kit)
```

## Install (SCP03)

```bash
java -jar gp_latest.jar \
  --key-enc <ENC> --key-mac <MAC> --key-dek <DEK> \
  -r "<Reader Name>" -f --install <FIDO2.cap>
```

## Testing PRF

- Platform authenticators: Use a PRF demo web page; request PRF in PublicKeyCredentialCreationOptions and check clientExtensionResults.
- Roaming (security key): browser requires CTAP HID/NFC authenticators; a PC/SC smartcard will not be used by WebAuthn.

## Merge plan (nuri-com/FIDO2Applet)

- Create a branch in the upstream fork (e.g., `feat/prf-support`).
- Port the extension advertisement (PRF) changes from `CannedCBOR` and related GetInfo/makeCredential code.
- Drop this folder (integration/fido2_prf) under a `docs/support/` path in upstream for future devs.
- Add a short CHANGELOG entry describing PRF support and test steps.
