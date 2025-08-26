# Satochip MuSig2 Applet — Support Docs and Scripts

This folder contains the supporting documentation and tools for the Satochip (Bitcoin) applet with MuSig2 support.

## Contents in this repo

- Applet sources: `SatochipApplet/` (build.xml, CAP build via ant-javacard)
- CLI demos:
  - `tools/musig2_demo_cli.py` (pysatochip/CardConnector — secure channel + PIN; full 2‑party demo, verified signature)
  - `tools/musig2_demo_cli_pcsc.py` (raw PC/SC — sets T=1/T=0; use only if CardConnector path unavailable)
- Web UI:
  - Backend: `tools/webapp/server.py` (Flask; `/health`, `/bip32`, `/musig2`)
  - Frontend: `tools/webapp/static/index.html` (Get Status, PIN, Seed/BIP32, MuSig2 raw + 2‑party demo; Event Log)
- Expo/NFC helpers:
  - `tools/rn-musig2/apdus.ts`, `aggregator.ts`, `ExpoScreen.tsx`

## Reader guidance (macOS OMNIKEY 5422)

Use the contact slot that shows a valid ATR:

```bash
python - <<'PY'
from smartcard.System import readers
from smartcard.Exceptions import CardConnectionException
for r in readers():
    print('Reader:', r)
    try:
        c = r.createConnection(); c.connect(); print(' ATR:', bytes(c.getATR()).hex()); c.disconnect()
    except CardConnectionException as e:
        print(' No card in this reader:', e)
PY
```

Pass that exact string to `--reader` in CLI demos.

## Build + Install (with on‑card seed 0x6B)

```bash
export JAVA_HOME="/Library/Java/JavaVirtualMachines/temurin-8.jdk/Contents/Home"
export PATH="$JAVA_HOME/bin:$PATH"
# Get JC SDK 3.0.4 if needed
git clone https://github.com/martinpaljak/oracle_javacard_sdks.git
cd SatochipApplet
JCKIT_HOME=../oracle_javacard_sdks/jc304_kit ant build

# Install (SCP03)
java -jar gp_latest.jar \
  --key-enc <ENC> --key-mac <MAC> --key-dek <DEK> \
  -r "<Reader Name>" -f --install SatoChip-3.0.4.cap
```

## CLI — full 2‑party demo (recommended)

```bash
python -m venv .venv && source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install pyscard flask
python -m pip install -e pysatochip
python tools/musig2_demo_cli.py \
  --reader "<Reader Name>" \
  --pin 123456 \
  --seed-bytes 32 \
  --path "m/86'/0'/0'/0/0" \
  --log debug
# Optional on‑card seed: add --on-card-seed
```

Expected tail: `signature: <hex>` and `verified: True`.

## Web UI — one‑click valid signature

```bash
source .venv/bin/activate
export SATOCHIP_BACKEND=pysatochip
python tools/webapp/server.py
# http://127.0.0.1:8000
```

Click through: Get Status → Verify PIN → Seed (host/on‑card) → Derive → MuSig2 (2‑party demo) → signature + verified:true.

Event Log shows every request/response.

## Expo iOS/Android (NFC)

- Install deps: `yarn add react-native-nfc-manager expo-crypto`
- Use `apdus.ts`, `aggregator.ts`, and `ExpoScreen.tsx` for a working flow.
- iOS: CoreNFC entitlement + `NfcTech.Iso7816`. Android: `NfcTech.IsoDep`.

## SCP03 & PIN notes

- Some operations require the applet’s secure channel; CardConnector handles this (`card_initiate_secure_channel`).
- If you see `9C20` (secure channel required), ensure you use the CardConnector‑based CLI or the web UI (`pysatochip` backend).

