// Minimal MuSig2 aggregator helpers (demo-oriented)
// NOTE: This is a developer aid. For production, use a vetted MuSig2 library.

// secp256k1 group order
export const SEC_N = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

export type Sha256Fn = (msg: Uint8Array) => Promise<Uint8Array>;

export function u8(...n: number[]): Uint8Array { return new Uint8Array(n); }
export function cat(...p: Uint8Array[]): Uint8Array {
  const L = p.reduce((a, b) => a + b.length, 0);
  const o = new Uint8Array(L);
  let off = 0;
  for (const c of p) { o.set(c, off); off += c.length; }
  return o;
}
export function hexToU8(h: string): Uint8Array {
  const s = h.replace(/\s+/g, "");
  if (s.length % 2) throw new Error("hex length");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}
export function u8ToHex(a: Uint8Array): string { return Array.from(a).map(b => b.toString(16).padStart(2, '0')).join(''); }

export function beBytesToBigInt(b: Uint8Array): bigint {
  let x = 0n;
  for (const v of b) x = (x << 8n) + BigInt(v);
  return x;
}
export function bigIntTo32BE(x: bigint): Uint8Array {
  let v = x % SEC_N;
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}

// L = H( pk1 || pk2 || ... || pkN ), pk compressed 33B or x-only 32B per your scheme
export async function computeL(pkList: Uint8Array[], sha256: Sha256Fn): Promise<Uint8Array> {
  return sha256(cat(...pkList));
}

// a_i (aka b) = H(L || pk_i) mod n
export async function computeCoeff(L: Uint8Array, pk: Uint8Array, sha256: Sha256Fn): Promise<Uint8Array> {
  const h = await sha256(cat(L, pk));
  const a = beBytesToBigInt(h) % SEC_N;
  return bigIntTo32BE(a);
}

// e = H( Rx || aggpk_x || msg ) mod n
export async function computeChallenge(Rx: Uint8Array, aggpkX: Uint8Array, msg: Uint8Array, sha256: Sha256Fn): Promise<Uint8Array> {
  const h = await sha256(cat(Rx, aggpkX, msg));
  const e = beBytesToBigInt(h) % SEC_N;
  return bigIntTo32BE(e);
}

// ea = (e * a) mod n
export function mulModN(e32: Uint8Array, a32: Uint8Array): Uint8Array {
  const e = beBytesToBigInt(e32); const a = beBytesToBigInt(a32);
  return bigIntTo32BE((e * a) % SEC_N);
}

// Demo wiring for 1-signer (device) placeholder:
// - Given a participants list of public keys (compressed/x-only as you choose), compute L and a (aka b)
// - If you don't have Rx/aggpkX yet, you can’t compute a valid e. Use zeros as placeholder only for transport tests.
export async function demoComputeBAndEA(
  pkList: Uint8Array[],
  myPk: Uint8Array,
  Rx?: Uint8Array,
  aggpkX?: Uint8Array,
  msg?: Uint8Array,
  sha256?: Sha256Fn,
): Promise<{ b: Uint8Array; ea: Uint8Array; hasValidE: boolean }>{
  if (!sha256) throw new Error('sha256 fn required');
  const L = await computeL(pkList, sha256);
  const b = await computeCoeff(L, myPk, sha256);
  if (Rx && aggpkX && msg) {
    const e = await computeChallenge(Rx, aggpkX, msg, sha256);
    return { b, ea: mulModN(e, b), hasValidE: true };
  }
  // placeholder only
  return { b, ea: new Uint8Array(32), hasValidE: false };
}

