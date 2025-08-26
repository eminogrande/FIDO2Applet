# End‑to‑End Guide: FIDO2 (PRF) Applet + Satochip MuSig2 Applet

Last updated: 2025-08-26

This README explains how to build, install, and test:

- A Java Card FIDO2 applet with PRF support.
- The Satochip (Bitcoin) applet with MuSig2 support (including on‑card seed generation).

It covers:

- Hardware/readers and OS prerequisites
- Establishing a secure channel (SCP03), retrieving keys, and installing CAPs
- Verifying functionality via CLI, local web UI, Expo (iOS/Android NFC), and browser (WebAuthn/PRF)
- Troubleshooting and tips for OMNIKEY readers, pcsc-lite/pyscard, secure channel errors, etc.

Use this as the canonical implementation and testing guide for both applets.

---

## Prerequisites

**Hardware**

- Java Card test card (JCOP/NXP or equivalent, supports EC + SCP03)
- USB smartcard reader (tested: HID Global OMNIKEY 5422; contact slot recommended)
- Optional NFC reader (for mobile/NFC testing)

**Host OS**

- macOS (Apple Silicon): uses Apple’s built-in PC/SC; do not install pcsc-lite services
- Linux: pcscd + libpcsclite
- Windows: PCSCLite-equivalent services built-in (ensure the Smart Card service is running)

**Tools**

- JDK 8 (required for ant-javacard): Temurin 8 (`brew install --cask temurin8`)
- Apache Ant: `brew install ant` or `apt-get install ant`
- JavaCard SDK 3.0.4: https://github.com/martinpaljak/oracle_javacard_sdks (use `jc304_kit`)
- GlobalPlatformPro (gp.jar): included or https://github.com/martinpaljak/GlobalPlatformPro/releases
- Python 3.11 (recommended), `pyscard`, `flask` (for web backend)
- Node.js + Expo (for mobile NFC testing)

**Reader identification (macOS OMNIKEY 5422: shows two entries — contact + contactless)**

```bash
python - <<'PY'
from smartcard.System import readers
from smartcard.Exceptions import CardConnectionException
for r in readers():
    print("Reader:", r)
    try:
        c = r.createConnection(); c.connect()
        print("  ATR:", bytes(c.getATR()).hex())
        c.disconnect()
    except CardConnectionException as e:
        print("  No card in this reader:", e)
PY
```

Use the reader string that prints a valid ATR in subsequent commands.

---

## Secure Channel (SCP03) and Keys

Most install flows require SCP03 keys (ENC/MAC/DEK) for your card’s ISD. If you don’t have them, and your card supports vendor APDUs to dump defaults, you can use:

- Select OP (if present): `00 A4 04 00 08 A0 00 00 00 03 00 00 00` (OK if not present)
- Retrieve keys:
  - ENC: `B1 05 30 01 02 9F 45`
  - MAC: `B1 05 30 01 02 9F 46`
  - DEK: `B1 05 30 01 02 9F 47`

Using `gp.jar` over PC/SC:

```bash
java -jar gp_latest.jar -d \
  -a 00A4040008A000000003000000 \
  -a b1053001029f45 -a b1053001029f46 -a b1053001029f47
```

Responses (TLV):

- `9F45 10 <ENC>`
- `9F46 10 <MAC>`
- `9F47 10 <DEK>`

Save them (e.g., `SatochipApplet/SCP03_KEYS.md`) and treat as secrets.

**Common `gp.jar` usage**

- List content:

```bash
java -jar gp_latest.jar --key-enc <ENC> --key-mac <MAC> --key-dek <DEK> -r "<Reader Name>" -l
```

- Install CAP (force replace):

```bash
java -jar gp_latest.jar --key-enc <ENC> --key-mac <MAC> --key-dek <DEK> -r "<Reader Name>" -f --install <capfile>
```

---

## FIDO2 Applet with PRF

**Overview**

- Build and install a Java Card FIDO2 applet that advertises and supports the WebAuthn `prf` extension.
- Notes:
  - Desktop browsers do NOT speak PC/SC for WebAuthn — use a CTAP HID/NFC roaming device (e.g., YubiKey) if testing in browser.
  - Platform authenticators (Touch ID/Face ID) may implement PRF for platform passkeys.

**Build**

```bash
export JAVA_HOME="/Library/Java/JavaVirtualMachines/temurin-8.jdk/Contents/Home"
export PATH="$JAVA_HOME/bin:$PATH"
# Get JC SDK 3.0.4
git clone https://github.com/martinpaljak/oracle_javacard_sdks.git
# Run your FIDO2 applet ant build pointing to JCKIT_HOME=../oracle_javacard_sdks/jc304_kit
ant build
```

**Install**

```bash
java -jar gp_latest.jar \
  --key-enc <ENC> --key-mac <MAC> --key-dek <DEK> \
  -r "<Reader Name>" -f --install <FIDO2.cap>
```

**Testing PRF**

- Platform passkeys: Use a PRF demo page, request PRF in PublicKeyCredentialCreationOptions, check `clientExtensionResults`.
- Roaming key in browser: Requires real CTAP HID/NFC device that supports PRF; browsers will not use PC/SC smart cards as FIDO devices.

---

## Satochip MuSig2 Applet

**Overview**

- Java Card applet for Bitcoin with BIP32 and MuSig2 (BIP‑0327) support.
- Features:
  - BIP32 seed import (`0x6C`) and (if built) on‑card seed generation (`0x6B`).
  - BIP32 derive (`0x6D`) sets the current key; MuSig2 uses key number `0xFF` (last derived key).
  - MuSig2 nonce (`0x7E`) and sign (`0x7F`).

**Build + Install (with on‑card seed `0x6B`)**

```bash
export JAVA_HOME="/Library/Java/JavaVirtualMachines/temurin-8.jdk/Contents/Home"
export PATH="$JAVA_HOME/bin:$PATH"
# Get JC SDK 3.0.4
git clone https://github.com/martinpaljak/oracle_javacard_sdks.git
cd SatochipApplet
JCKIT_HOME=../oracle_javacard_sdks/jc304_kit ant build
java -jar gp_latest.jar \
  --key-enc <ENC> --key-mac <MAC> --key-dek <DEK> \
  -r "<Reader Name>" -f --install SatoChip-3.0.4.cap
```

**Secure Channel + PIN**

- Many commands require PIN and/or the applet’s secure channel (SC). CardConnector (pysatochip) establishes SC for you (INS `0x81/0x82`).

### Testing via CLI (CardConnector‑based)

Create venv & install:

```bash
python -m venv .venv && source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install pyscard flask
python -m pip install -e pysatochip
python - <<'PY'
from smartcard.System import readers
print("readers:", readers())
PY
```

Run the 2‑party demo (card + simulated counter‑signer). This imports a host RNG seed by default; add `--on-card-seed` to use `0x6B` if your applet build supports it:

```bash
python tools/musig2_demo_cli.py \
  --reader "HID Global OMNIKEY 5422 Smartcard Reader" \
  --pin 123456 \
  --seed-bytes 32 \
  --path "m/86'/0'/0'/0/0" \
  --log debug
```

At the end it prints:

- `signature: <hex>`
- `verified: True`

If using on-card seed (requires INS `0x6B` in your applet):

```bash
python tools/musig2_demo_cli.py \
  --reader "HID Global OMNIKEY 5422 Smartcard Reader" \
  --pin 123456 \
  --on-card-seed --seed-bytes 32 \
  --path "m/86'/0'/0'/0/0" \
  --log debug
```

> Tip: If one reader string fails, try the other (“…Reader 01”). Use the one that prints a valid ATR.

### Testing via Raw PC/SC CLI (explicit protocol)

A raw PC/SC CLI that sets T=1 (fallback T=0) but does not implement the applet’s secure channel:

```bash
python tools/musig2_demo_cli_pcsc.py \
  --reader "HID Global OMNIKEY 5422 Smartcard Reader 01" \
  --pin 123456 \
  --seed-bytes 32 \
  --path "m/86'/0'/0'/0/0" \
  --log debug
```

If your applet enforces SC before PIN, prefer the CardConnector‑based CLI.

### Testing via Local Web UI (Flask backend)

Start backend against PC/SC:

```bash
source .venv/bin/activate
export SATOCHIP_BACKEND=pysatochip
python tools/webapp/server.py
```

Open http://127.0.0.1:8000, then:

- Get Status → shows backend = `pysatochip` and capabilities (/health)
- Verify PIN
- Seed + BIP32: generate seed (host or on‑card), derive `m/86'/0'/0'/0/0` (MuSig2 uses key number `0xFF` after derive)
- MuSig2 (2‑party demo): One click; returns signature + `verified:true`; logs everything (L, a’s, nonces, R/e/b, partials)

### Testing via Expo (iOS/Android NFC)

- Install:

```bash
yarn add react-native-nfc-manager expo-crypto
```

- Helpers in this repo:
  - `tools/rn-musig2/apdus.ts` — APDU builders for SELECT/PIN/seed import/derive/MuSig2
  - `tools/rn-musig2/aggregator.ts` — helper to compute L, a, e, ea and format logs
  - `tools/rn-musig2/ExpoScreen.tsx` — example screen: SELECT → PIN → seed import → derive → nonce → compute b/ea → sign

- iOS: enable CoreNFC entitlement; use `NfcTech.Iso7816`.
- Android: use `NfcTech.IsoDep`.
- Flow mirrors the web UI 2‑party demo; follow the logs and values from the browser demo when implementing.

---

## FIDO2 (PRF) in Browsers

- Platform authenticators (Touch ID/Face ID): use a PRF demo site to request PRF and verify extension results.
- Roaming key in browsers: requires a CTAP HID/NFC FIDO device that supports PRF; browsers don’t use PC/SC smartcards as FIDO devices.

---

## Troubleshooting

- `gp.jar` errors:
  - Card cryptogram invalid → SCP03 keys are wrong; retrieve defaults via vendor APDUs or use correct keys.
  - Conditions of use not satisfied → card state/privileges; try `-f` (force) and ensure the correct reader `-r "…Reader"`.

- Secure channel required (SW `9C20`):
  - Use CardConnector (pysatochip) backend; it establishes SC (INS `0x81/0x82`).

- Invalid protocol in transmit (PC/SC):
  - OMNIKEY often needs explicit T=1 (fallback T=0). The CLI sets this now.

- `6D00` (INS not supported):
  - Your applet build doesn’t include that INS (e.g., `0x6B` on‑card seed). Rebuild/install the updated CAP that includes it.

- No readers found:
  - macOS: Ensure the reader is connected and visible in System Information; close other smartcard apps.
  - Linux: `sudo systemctl enable --now pcscd`; run `pcsc_scan` to confirm presence.

- pyscard on macOS:
  - Prefer Python 3.11 via pyenv. If Apple’s Python 3.9 is used, wheels may fail. Use:

```bash
brew install pyenv
pyenv install 3.11.9 && pyenv shell 3.11.9
python -m venv .venv && source .venv/bin/activate
pip install pyscard==2.0.7
```

- Reader selection:
  - Always pick the reader string that prints an ATR in the discovery snippet.

---

## Security Notes

- Seed generation:
  - On‑card (`0x6B`): seed never leaves the SE. Without a secure display, backup requires using “Export seed” (`0x6A`, PIN‑gated, dangerous). Consider host seed + immediate backup for user‑friendly flows.

- Never log secrets:
  - Web UI/CLI tools print hex for dev convenience — never share logs containing seeds/keys.

- Rotate SCP03 keys for production.

---

## File Map in This Repo

- `SatochipApplet/`
  - `build.xml` (ant-javacard)
  - `gp_latest.jar` (GlobalPlatformPro)
  - `SatoChip-3.0.4.cap` (built CAP)
  - `SCP03_KEYS.md` (if you saved them)

- `tools/`
  - `musig2_demo_cli.py` (CardConnector, full 2‑party MuSig2 demo; SC + PIN; verified signature)
  - `musig2_demo_cli_pcsc.py` (raw PC/SC; sets T=1/T=0; no SC)
  - `webapp/server.py` (Flask backend for web UI; `/health`, `/bip32`, `/musig2`)
  - `webapp/static/index.html` (Frontend; detailed logs; 2‑party demo)
  - `rn-musig2/apdus.ts`, `aggregator.ts`, `ExpoScreen.tsx` (Expo/NFC helpers)
  - `README.md` (tools usage summary)

---

If you hit any error, paste the full console output (and `/health` JSON in the web UI) and we’ll adjust quickly until you end with a “verified: True” MuSig2 or PRF result.
