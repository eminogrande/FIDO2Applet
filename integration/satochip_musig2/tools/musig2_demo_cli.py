#!/usr/bin/env python3
"""
End-to-end MuSig2 demo CLI (2-party):
- Connects to Satochip via pysatochip (PC/SC)
- PIN verify
- Seed init (host import or on-card)
- Derive BIP32 path (default m/86'/0'/0'/0/0)
- Generate card pubnonces (R1c,R2c)
- Simulate counter-signer (server) nonces (R1s,R2s) and keypair
- Compute L, a1/a2, Q, b, R, e, ea
- Ask card for partial signature
- Compute server partial; combine to final BIP340 signature
- Verify signature

Requires: pysatochip (pyscard), ecdsa (installed via pysatochip reqs)
"""
import argparse
import logging
import secrets
import hashlib

from typing import Tuple


def int_to_32(i: int, n: int) -> bytes:
    return (i % n).to_bytes(32, 'big')


def tagged_hash(tag: str, *chunks: bytes) -> bytes:
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + b''.join(chunks)).digest()


def main():
    parser = argparse.ArgumentParser(description="Satochip MuSig2 2‑party demo CLI")
    parser.add_argument("--pin", default="123456", help="PIN (default: 123456)")
    parser.add_argument("--reader", help="PC/SC reader substring to select (e.g. 'OMNIKEY 5422 ... 01')")
    parser.add_argument("--on-card-seed", action="store_true", help="Generate seed on card (INS 0x6B)")
    parser.add_argument("--seed-bytes", type=int, default=32, help="Seed length (16,24,32,48,64)")
    parser.add_argument("--path", default="m/86'/0'/0'/0/0", help="BIP32 path to derive")
    parser.add_argument("--msg-hex", help="Message (hex32). Omit to use random")
    parser.add_argument("--log", default="info", choices=["debug","info","warning","error"])
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log.upper()), format='%(levelname)s %(message)s')
    log = logging.getLogger("musig2_demo_cli")

    # Imports from pysatochip
    from pysatochip.CardConnector import CardConnector
    from pysatochip.ecc import ECPubkey, CURVE_ORDER as N, generator as GEN

    # Connect
    cc = CardConnector(None, logging.getLogger().getEffectiveLevel())
    # Try to get ATR for logging, but don't fail the demo if not connected yet
    try:
        atr = cc.card_get_ATR()
        log.info(f"ATR: {atr}")
    except Exception as e:
        log.warning(f"Could not get ATR yet (will continue): {e}")

    # Ensure secure channel if required
    try:
        _resp, _sw1, _sw2, status = cc.card_get_status()
        if getattr(cc, 'needs_secure_channel', False):
            log.info("Initiating secure channel with applet…")
            cc.card_initiate_secure_channel()
    except Exception as e:
        log.warning(f"Could not retrieve status/secure channel: {e}")

    # Connect to specific reader if specified
    if args.reader:
        from smartcard.System import readers
        from smartcard.CardConnection import CardConnection as _PCSCConn
        
        # Find the reader
        reader_list = readers()
        target_reader = None
        for r in reader_list:
            if args.reader in str(r):
                target_reader = r
                break
        
        if target_reader:
            log.info(f"Connecting to reader: {target_reader}")
            connection = target_reader.createConnection()
            try:
                connection.connect(_PCSCConn.T1_protocol)
                log.debug("PC/SC connected with T=1 protocol")
            except Exception:
                connection.connect(_PCSCConn.T0_protocol)
                log.debug("PC/SC connected with T=0 protocol")
            cc.cardservice = target_reader
            cc.cardservice.connection = connection
            cc.card_present = True
        else:
            log.warning(f"Reader '{args.reader}' not found")
    
    # Force PC/SC protocol if needed (macOS/OMNIKEY)
    else:
        try:
            from smartcard.CardConnection import CardConnection as _PCSCConn
            try:
                cc.cardservice.connection.connect(_PCSCConn.T1_protocol)
                log.debug("PC/SC connected with T=1 protocol")
            except Exception:
                cc.cardservice.connection.connect(_PCSCConn.T0_protocol)
                log.debug("PC/SC connected with T=0 protocol")
        except Exception as e:
            log.debug(f"PC/SC protocol hint skipped: {e}")

    # Select the Satochip applet
    try:
        cc.card_select()
        log.info("Satochip applet selected")
    except Exception as e:
        log.warning(f"Could not select applet: {e}")
    
    # Get status and check if secure channel is needed
    try:
        resp, sw1, sw2, status = cc.card_get_status()
        if status.get('needs_secure_channel', False):
            log.info("Initiating secure channel...")
            cc.card_initiate_secure_channel()
        if not status.get('setup_done', False):
            log.warning("Applet not setup, attempting basic setup...")
            # Basic setup if needed
            pin0 = list(args.pin.encode('utf-8'))
            ublk0 = list("0123456789ABCDEF".encode('utf-8'))
            cc.card_setup(
                pin_tries0=5, ublk_tries0=10, pin0=pin0, ublk0=ublk0,
                pin_tries1=0, ublk_tries1=0, pin1=[], ublk1=[],
                memsize=32, memsize2=0,
                create_object_ACL=0x01, create_key_ACL=0x01, create_pin_ACL=0x01
            )
    except Exception as e:
        log.warning(f"Could not setup secure channel or applet: {e}")

    # PIN
    cc.card_verify_PIN_deprecated(0, list(args.pin.encode('utf-8')))
    log.info("PIN verified")

    # Seed
    if args.on_card_seed:
        seed_len = args.seed_bytes
        assert seed_len in (16,24,32,48,64)
        # INS 0x6B P1=len P2=0 Lc=0
        apdu = [0xB0, 0x6B, seed_len & 0xFF, 0x00, 0x00]
        resp, sw1, sw2 = cc.card_transmit(apdu)
        if (sw1,sw2)!=(0x90,0x00):
            raise RuntimeError(f"On-card seed generation failed: {hex(256*sw1+sw2)}")
        log.info("Seed generated on card")
    else:
        seed = secrets.token_bytes(args.seed_bytes)
        cc.card_bip32_import_seed(seed)
        log.info(f"Seed imported (host RNG), hex={seed.hex()}")

    # Derive
    pubkey1, chaincode = cc.card_bip32_get_extendedkey(args.path)
    P1_hex = pubkey1.get_public_key_hex(False)
    P1 = ECPubkey(bytes.fromhex(P1_hex))
    x1, y1 = P1.point()
    P1x = x1.to_bytes(32, 'big')
    log.info(f"Card pubkey: {P1_hex}")

    # Counter-signer keypair
    d2 = secrets.randbelow(N-1) + 1
    G = GEN()
    P2 = d2 * G
    P2_hex = P2.get_public_key_hex(False)
    x2, y2 = P2.point()
    P2x = x2.to_bytes(32, 'big')
    log.info(f"Server pubkey: {P2_hex}")

    # L and a1,a2
    L = hashlib.sha256(P1x + P2x).digest()
    a1 = int.from_bytes(hashlib.sha256(L + P1x).digest(), 'big') % N
    a2 = int.from_bytes(hashlib.sha256(L + P2x).digest(), 'big') % N
    # Agg Q
    Q = (a1 * P1) + (a2 * P2)
    Qx_int, Qy_int = Q.point()
    Qx = Qx_int.to_bytes(32, 'big')
    ggacc_is_1 = (Qy_int % 2 == 0)
    log.info(f"aggpk_x={Qx.hex()} ggacc_is_1={ggacc_is_1}")

    # msg
    msg = bytes.fromhex(args.msg_hex) if args.msg_hex else secrets.token_bytes(32)
    log.info(f"msg_hex={msg.hex()}")

    # Card pubnonces
    pubnonce1, enc1 = cc.card_musig2_generate_nonce(keynbr=0xFF, aggpk=Qx, msg=msg, extra=None)
    R1c_ser = pubnonce1[0:33]
    R2c_ser = pubnonce1[33:66]
    R1c = ECPubkey(R1c_ser)
    R2c = ECPubkey(R2c_ser)
    log.info(f"card R1={R1c_ser.hex()} R2={R2c_ser.hex()}")

    # Server nonces
    k1_2 = secrets.randbelow(N-1) + 1
    k2_2 = secrets.randbelow(N-1) + 1
    R1s = k1_2 * G
    R2s = k2_2 * G
    R1s_ser = bytes.fromhex(R1s.get_public_key_hex(True))
    R2s_ser = bytes.fromhex(R2s.get_public_key_hex(True))
    log.info(f"server R1={R1s_ser.hex()} R2={R2s_ser.hex()}")

    # b coefficient
    b_bytes = tagged_hash("MuSig/nonce", Qx, msg, R1c_ser, R2c_ser, R1s_ser, R2s_ser)
    b_int = int.from_bytes(b_bytes, 'big') % N
    b = int_to_32(b_int, N)
    log.info(f"b={b.hex()}")

    # R = (R1c+R1s) + b*(R2c+R2s)
    R1 = R1c + R1s
    R2 = R2c + R2s
    R = R1 + (b_int * R2)
    Rx_int, Ry_int = R.point()
    Rx = Rx_int.to_bytes(32, 'big')
    r_even = (Ry_int % 2 == 0)
    log.info(f"R_x={Rx.hex()} r_even={r_even}")

    # adjust server k’s for parity
    if not r_even:
        k1_2 = (N - k1_2) % N
        k2_2 = (N - k2_2) % N

    # e
    e_bytes = tagged_hash("BIP0340/challenge", Rx, Qx, msg)
    e_int = int.from_bytes(e_bytes, 'big') % N
    e = int_to_32(e_int, N)
    log.info(f"e={e.hex()}")

    # ea for card (signer #1)
    ea1_int = (e_int * a1) % N
    ea1 = int_to_32(ea1_int, N)

    # Card partial
    psig1 = cc.card_musig2_sign_hash(keynbr=0xFF, secnonce=enc1, b=b, ea=ea1, r_has_even_y=r_even, ggacc_is_1=ggacc_is_1)
    s1_int = int.from_bytes(psig1, 'big')
    log.info(f"card partial={psig1.hex()}")

    # Server partial s2 = (ea2*d2' + k1_2 + b*k2_2) mod n
    ea2_int = (e_int * a2) % N
    d2_eff = d2 if ggacc_is_1 else (N - d2)
    s2_int = ( (ea2_int * d2_eff) + k1_2 + (b_int * k2_2) ) % N
    s_int = (s1_int + s2_int) % N
    sig = Rx + int_to_32(s_int, N)
    log.info(f"signature={sig.hex()}")

    # Verify: sG == R + eQ
    sG = s_int * G
    eQ = e_int * Q
    Rchk = sG + ((N - e_int) * Q)
    ok = (Rchk.point()[0] == Rx_int)
    print("verified:", ok)


if __name__ == "__main__":
    main()
