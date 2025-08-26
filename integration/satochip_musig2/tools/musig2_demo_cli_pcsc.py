#!/usr/bin/env python3
import argparse, logging, secrets, hashlib, sys
from typing import Tuple

from smartcard.System import readers
from smartcard.Exceptions import CardConnectionException
from smartcard.CardConnection import CardConnection

try:
    from pysatochip.ecc import ECPubkey, CURVE_ORDER as N, generator as GEN
except Exception:
    print("pysatochip not installed. Run: pip install -e pysatochip", file=sys.stderr)
    raise

def int_to_32(i: int) -> bytes:
    return (i % N).to_bytes(32, 'big')

def tagged_hash(tag: str, *chunks: bytes) -> bytes:
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + b''.join(chunks)).digest()

def encode_bip32_path(path: str) -> bytes:
    s = path.strip()
    if s.startswith('m/'): s = s[2:]
    parts = s.split('/') if s else []
    out = bytearray()
    for seg in parts:
        hardened = seg.endswith("'")
        num = int(seg[:-1] if hardened else seg)
        val = (0x80000000 | num) if hardened else num
        out += val.to_bytes(4, 'big')
    return bytes(out)

def apdu(conn, data: bytes) -> Tuple[bytes,int,int]:
    rapdu, sw1, sw2 = conn.transmit(list(data))
    return (bytes(rapdu), sw1, sw2)

def select_applet(conn):
    sel = bytes.fromhex('00A40400095361746F4368697000')
    r, sw1, sw2 = apdu(conn, sel)
    if (sw1,sw2)!=(0x90,0x00):
        raise RuntimeError(f"SELECT failed: {sw1:02x}{sw2:02x}")

def verify_pin(conn, pin: str):
    p = pin.encode('utf-8')
    cmd = bytes([0xB0,0x42,0x00,0x00,len(p)]) + p
    r, sw1, sw2 = apdu(conn, cmd)
    if (sw1,sw2)!=(0x90,0x00):
        raise RuntimeError(f"PIN verify failed: {sw1:02x}{sw2:02x}")

def seed_on_card(conn, length: int):
    cmd = bytes([0xB0,0x6B,length&0xFF,0x00,0x00])
    r, sw1, sw2 = apdu(conn, cmd)
    if (sw1,sw2)!=(0x90,0x00):
        raise RuntimeError(f"seed generate failed: {sw1:02x}{sw2:02x}")

def derive(conn, path: str) -> bytes:
    pb = encode_bip32_path(path)
    cmd = bytes([0xB0,0x6D,len(pb)//4,0x40,len(pb)]) + pb
    r, sw1, sw2 = apdu(conn, cmd)
    if (sw1,sw2)!=(0x90,0x00):
        raise RuntimeError(f"derive failed: {sw1:02x}{sw2:02x}")
    # Parse: [chaincode(32) | coordx_size(2) | coordx | ...]
    if len(r) < 36:
        raise RuntimeError("derive response too short")
    coord_size = int.from_bytes(r[32:34],'big')
    x = r[34:34+coord_size]
    if len(x)!=32:
        raise RuntimeError("unexpected x size")
    return x

def musig2_nonce(conn, keynbr: int, Qx: bytes, msg: bytes) -> Tuple[bytes,bytes]:
    # INIT
    data = bytes([len(Qx)]) + Qx + bytes([len(msg)]) + msg + bytes([0x00])
    cmd = bytes([0xB0,0x7E,keynbr&0xFF,0x01,len(data)]) + data
    r1, sw1, sw2 = apdu(conn, cmd)
    if (sw1,sw2)!=(0x90,0x00):
        raise RuntimeError(f"nonce init failed: {sw1:02x}{sw2:02x}")
    # FINALIZE
    cmd = bytes([0xB0,0x7E,keynbr&0xFF,0x03,0x00])
    r2, sw1, sw2 = apdu(conn, cmd)
    if (sw1,sw2)!=(0x90,0x00):
        raise RuntimeError(f"nonce finalize failed: {sw1:02x}{sw2:02x}")
    return (r1, r2)

def musig2_sign(conn, keynbr: int, enc_secnonce: bytes, b: bytes, ea: bytes, r_even: bool, ggacc_is_1: bool) -> bytes:
    # INIT
    cmd = bytes([0xB0,0x7F,keynbr&0xFF,0x01,len(enc_secnonce)]) + enc_secnonce
    r, sw1, sw2 = apdu(conn, cmd)
    if (sw1,sw2)!=(0x90,0x00):
        raise RuntimeError(f"sign init failed: {sw1:02x}{sw2:02x}")
    # FINALIZE
    flags = bytes([0x00 if r_even else 0x01, 0x01 if ggacc_is_1 else 0x00])
    data = b + ea + flags
    cmd = bytes([0xB0,0x7F,keynbr&0xFF,0x03,len(data)]) + data
    psig, sw1, sw2 = apdu(conn, cmd)
    if (sw1,sw2)!=(0x90,0x00):
        raise RuntimeError(f"sign finalize failed: {sw1:02x}{sw2:02x}")
    return psig

def main():
    ap = argparse.ArgumentParser(description="Satochip MuSig2 2‑party demo (PC/SC)")
    ap.add_argument('--reader', required=True, help="PC/SC reader substring to select")
    ap.add_argument('--pin', default='123456')
    ap.add_argument('--seed-bytes', type=int, default=32)
    ap.add_argument('--path', default="m/86'/0'/0'/0/0")
    ap.add_argument('--msg-hex', help='32B hex message; omit for random')
    ap.add_argument('--log', default='info', choices=['debug','info','warning','error'])
    args = ap.parse_args()
    logging.basicConfig(level=getattr(logging, args.log.upper()))
    log = logging.getLogger('pcsc_musig2')

    # Pick reader
    r = None
    for rd in readers():
        if args.reader in str(rd):
            r = rd; break
    if not r:
        raise RuntimeError(f"Reader not found: {args.reader}")
    conn = r.createConnection()
    try:
        conn.connect(CardConnection.T1_protocol)
    except Exception:
        conn.connect(CardConnection.T0_protocol)
    # SELECT applet
    select_applet(conn)
    # Verify PIN
    verify_pin(conn, args.pin)
    # Seed on card
    seed_on_card(conn, args.seed_bytes)
    # Derive and get x-only pubkey of card
    P1x = derive(conn, args.path)
    # Build card pubkey from x-only (assume even y for demo; aggregator handles ggacc)
    P1 = ECPubkey(bytes([0x02]) + P1x)
    # Server keypair
    d2 = secrets.randbelow(N-1) + 1
    G = GEN()
    P2 = d2 * G
    x2, y2 = P2.point()
    P2x = x2.to_bytes(32, 'big')
    # L and coeffs
    L = hashlib.sha256(P1x + P2x).digest()
    a1 = int.from_bytes(hashlib.sha256(L + P1x).digest(), 'big') % N
    a2 = int.from_bytes(hashlib.sha256(L + P2x).digest(), 'big') % N
    Q = (a1 * P1) + (a2 * P2)
    Qx_int, Qy_int = Q.point()
    Qx = Qx_int.to_bytes(32, 'big')
    ggacc_is_1 = (Qy_int % 2 == 0)
    # msg
    msg = bytes.fromhex(args.msg_hex) if args.msg_hex else secrets.token_bytes(32)
    # Card pubnonces
    pubnonce, enc = musig2_nonce(conn, 0xFF, Qx, msg)
    R1c_ser = pubnonce[0:33]
    R2c_ser = pubnonce[33:66]
    R1c = ECPubkey(R1c_ser)
    R2c = ECPubkey(R2c_ser)
    # Server nonces
    k1_2 = secrets.randbelow(N-1) + 1
    k2_2 = secrets.randbelow(N-1) + 1
    R1s = k1_2 * G
    R2s = k2_2 * G
    R1s_ser = bytes.fromhex(R1s.get_public_key_hex(True))
    R2s_ser = bytes.fromhex(R2s.get_public_key_hex(True))
    # b
    b_int = int.from_bytes(tagged_hash("MuSig/nonce", Qx, msg, R1c_ser, R2c_ser, R1s_ser, R2s_ser), 'big') % N
    b = int_to_32(b_int)
    # R
    R1 = R1c + R1s
    R2 = R2c + R2s
    R = R1 + (b_int * R2)
    Rx_int, Ry_int = R.point()
    Rx = Rx_int.to_bytes(32, 'big')
    r_even = (Ry_int % 2 == 0)
    if not r_even:
        k1_2 = (N - k1_2) % N
        k2_2 = (N - k2_2) % N
    # e
    e_int = int.from_bytes(tagged_hash("BIP0340/challenge", Rx, Qx, msg), 'big') % N
    # ea for card
    ea1_int = (e_int * a1) % N
    ea1 = int_to_32(ea1_int)
    # Card partial
    psig1 = musig2_sign(conn, 0xFF, enc, b, ea1, r_even, ggacc_is_1)
    s1_int = int.from_bytes(psig1, 'big')
    # Server partial
    ea2_int = (e_int * a2) % N
    d2_eff = d2 if ggacc_is_1 else (N - d2)
    s2_int = ( (ea2_int * d2_eff) + k1_2 + (b_int * k2_2) ) % N
    s_int = (s1_int + s2_int) % N
    sig = Rx + int_to_32(s_int)
    # Verify: sG == R + eQ
    sG = s_int * G
    Rchk = sG + ((N - e_int) * Q)
    ok = (Rchk.point()[0] == Rx_int)
    print("signature:", sig.hex())
    print("verified:", ok)

if __name__ == '__main__':
    main()
