// Minimal APDU builder helpers for Satochip MuSig2 (TypeScript)
// Use with react-native-nfc-manager (IsoDep / Iso7816)

export const CLA = 0xB0;
export const INS_GET_STATUS = 0x3C;
export const INS_MUSIG2_GEN_NONCE = 0x7E;
export const INS_MUSIG2_SIGN_HASH = 0x7F;

export const OP_INIT = 0x01;
export const OP_PROCESS = 0x02;
export const OP_FINALIZE = 0x03;

export const AID_PACKAGE = hexToBytes("5361746F43686970");
export const AID_APPLET = hexToBytes("5361746F4368697000");

export function hexToBytes(h: string): Uint8Array {
  const s = h.replace(/\s+/g, "");
  if (s.length % 2 !== 0) throw new Error("hex length");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

export function concat(...chunks: Uint8Array[]): Uint8Array {
  const len = chunks.reduce((a, b) => a + b.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.length; }
  return out;
}

export function apduSelectByAID(aid: Uint8Array): Uint8Array {
  // 00 A4 04 00 Lc | AID
  return concat(U8([0x00, 0xA4, 0x04, 0x00, aid.length]), aid);
}

export function apduGetStatus(): Uint8Array {
  // B0 3C 00 00 00
  return U8([CLA, INS_GET_STATUS, 0x00, 0x00, 0x00]);
}

export function apduMusig2GenerateNonceInit(keynbr: number, aggpk?: Uint8Array, msg?: Uint8Array, extra?: Uint8Array): Uint8Array {
  const agg = aggpk ? concat(U8([aggpk.length]), aggpk) : U8([0x00]);
  const m = (msg && msg.length > 0) ? concat(U8([msg.length]), msg) : U8([0xFF]);
  const ex = extra ? concat(U8([extra.length]), extra) : U8([0x00]);
  const data = concat(agg, m, ex);
  return concat(U8([CLA, INS_MUSIG2_GEN_NONCE, keynbr & 0xFF, OP_INIT, data.length]), data);
}

export function apduMusig2GenerateNonceFinalize(keynbr: number): Uint8Array {
  return U8([CLA, INS_MUSIG2_GEN_NONCE, keynbr & 0xFF, OP_FINALIZE, 0x00]);
}

export function apduMusig2SignInit(keynbr: number, secnonce: Uint8Array): Uint8Array {
  if (secnonce.length !== 144) throw new Error("secnonce must be 144 bytes");
  return concat(U8([CLA, INS_MUSIG2_SIGN_HASH, keynbr & 0xFF, OP_INIT, secnonce.length]), secnonce);
}

export function apduMusig2SignFinalize(keynbr: number, b: Uint8Array, ea: Uint8Array, rEven: boolean, ggaccIs1: boolean): Uint8Array {
  if (b.length !== 32 || ea.length !== 32) throw new Error("b and ea must be 32 bytes");
  const flags = U8([rEven ? 0x00 : 0x01, ggaccIs1 ? 0x01 : 0x00]);
  const data = concat(b, ea, flags);
  return concat(U8([CLA, INS_MUSIG2_SIGN_HASH, keynbr & 0xFF, OP_FINALIZE, data.length]), data);
}

export function U8(arr: number[]): Uint8Array { return new Uint8Array(arr); }

// Example usage with react-native-nfc-manager:
// const sel = apduSelectByAID(AID_APPLET);
// const r1 = await NfcManager.isoDepHandler.transceive([...sel]);
// const init = apduMusig2GenerateNonceInit(0, aggpk, msg, extra);
// const r2 = await NfcManager.isoDepHandler.transceive([...init]);
// const fin = apduMusig2GenerateNonceFinalize(0);
// const r3 = await NfcManager.isoDepHandler.transceive([...fin]);

