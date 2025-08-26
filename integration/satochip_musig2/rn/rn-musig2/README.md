# RN MuSig2 APDU Helpers

Path: `tools/rn-musig2/apdus.ts`

Exports utilities to build Satochip MuSig2 APDUs from React Native with `react-native-nfc-manager`.

Example (TypeScript):

```ts
import NfcManager, {NfcTech} from 'react-native-nfc-manager';
import {apduSelectByAID, AID_APPLET, apduGetStatus, apduMusig2GenerateNonceInit, apduMusig2GenerateNonceFinalize, apduMusig2SignInit, apduMusig2SignFinalize, hexToBytes} from './apdus';

async function tx(apdu: Uint8Array): Promise<Uint8Array> {
  const resp = await NfcManager.isoDepHandler.transceive(Array.from(apdu));
  return new Uint8Array(resp);
}

export async function musig2Demo() {
  await NfcManager.start();
  await NfcManager.requestTechnology(NfcTech.IsoDep);
  try {
    await tx(apduSelectByAID(AID_APPLET));
    const st = await tx(apduGetStatus());
    console.log('status=', Buffer.from(st).toString('hex'));

    // Build your inputs according to BIP-327
    const aggpk = undefined; // or hexToBytes('...')
    const msg = undefined; // or hexToBytes('...')
    const extra = undefined; // or hexToBytes('...')

    const init = apduMusig2GenerateNonceInit(0, aggpk, msg, extra);
    const r1 = await tx(init);
    console.log('pubnonce=', Buffer.from(r1).toString('hex'));

    const fin = apduMusig2GenerateNonceFinalize(0);
    const r2 = await tx(fin);
    console.log('enc_secnonce=', Buffer.from(r2).toString('hex'));

    // Sign (example placeholders; compute b/ea/flags correctly per BIP-327)
    const secnonce = r2; // 144 bytes
    const b = new Uint8Array(32);
    const ea = new Uint8Array(32);
    const initS = apduMusig2SignInit(0, secnonce);
    await tx(initS);
    const finalS = apduMusig2SignFinalize(0, b, ea, true, true);
    const r3 = await tx(finalS);
    console.log('psig=', Buffer.from(r3).toString('hex'));
  } finally {
    NfcManager.cancelTechnologyRequest();
  }
}
```

Notes:
- Browsers cannot send ISO-DEP APDUs; use RN/Native (Android IsoDep, iOS CoreNFC).
- Compute `b`, `ea`, `r_even`, `ggacc` as per BIP-327.

