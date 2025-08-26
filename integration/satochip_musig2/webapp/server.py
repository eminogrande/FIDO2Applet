#!/usr/bin/env python3
import os
import logging
from typing import Optional

from flask import Flask, jsonify, request, send_from_directory
import subprocess
import re
import os
import hashlib
import secrets


def make_app():
    app = Flask(__name__, static_folder="static", static_url_path="/static")
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    logger = logging.getLogger("satochip_webapp")

    backend_mode = os.environ.get("SATOCHIP_BACKEND", "auto").lower()

    # Lazy-init backends to allow running without reader for UI
    cc = {"conn": None, "err": None}

    def _pysatochip():
        if cc["conn"] is None and cc["err"] is None:
            try:
                from pysatochip.CardConnector import CardConnector
                conn = CardConnector(None, logging.getLogger().getEffectiveLevel())
                if getattr(conn, 'needs_secure_channel', False):
                    conn.card_initiate_secure_channel()
                cc["conn"] = conn
            except Exception as e:
                cc["err"] = f"CardConnector init failed: {e}"
        if cc["conn"] is None:
            raise RuntimeError(cc["err"] or "CardConnector not available")
        return cc["conn"]

    # gp.jar raw APDU backend (fallback)
    def _gp_path():
        p = os.environ.get("GPJAR_PATH")
        if p and os.path.exists(p):
            return p
        # relative to repo: tools/webapp/server.py -> ../../SatochipApplet/gp_latest.jar
        here = os.path.dirname(os.path.abspath(__file__))
        cand = os.path.abspath(os.path.join(here, "..", "..", "SatochipApplet", "gp_latest.jar"))
        if os.path.exists(cand):
            return cand
        raise RuntimeError("gp_latest.jar not found; set GPJAR_PATH")

    def _gp_send(apdus_hex: list[str]):
        # Use '-d' to print APDU traces and parse A<< lines
        cmd = ["java", "-jar", _gp_path(), "-d"]
        for h in apdus_hex:
            cmd += ["-a", h]
        out = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if out.returncode != 0:
            raise RuntimeError(f"gp.jar failed: {out.stdout.strip()}")
        lines = out.stdout.splitlines()
        rapdus = []
        # Capture data and SW for each A<<
        pat = re.compile(r"A<<.*? ([0-9A-Fa-f ]+)?\s*([0-9A-Fa-f]{4})$")
        for ln in lines:
            if "A<<" in ln:
                m = pat.search(ln)
                if m:
                    data_hex = (m.group(1) or "").replace(" ", "").lower()
                    sw_hex = m.group(2).lower()
                    rapdus.append({"data_hex": data_hex, "sw_hex": sw_hex})
        # Return exactly one response per sent APDU: take the last N, to skip any trailing default SELECT
        if len(apdus_hex) > 0:
            rapdus = rapdus[-len(apdus_hex):]
        return rapdus

    def _backend():
        if backend_mode == "gpjar":
            return "gpjar"
        if backend_mode == "pysatochip":
            return "pysatochip"
        # auto: try pysatochip first
        try:
            _pysatochip()
            return "pysatochip"
        except Exception:
            return "gpjar"

    @app.route("/health", methods=["GET"])
    def health():
        mode = _backend()
        caps = {
            "status": True,
            "verify_pin": (mode == "pysatochip"),
            "seed_import": (mode == "pysatochip"),
            "seed_generate_card": (mode == "pysatochip"),
            "seed_export": (mode == "pysatochip"),
            "derive_string_path": (mode == "pysatochip"),
            "derive_fallback": (mode == "gpjar"),
            "musig2_nonce": (mode == "pysatochip"),
            "musig2_sign": (mode == "pysatochip"),
            "musig2_two_party_demo": (mode == "pysatochip"),
        }
        return jsonify({"backend": mode, "capabilities": caps})

    @app.route("/")
    def index():
        return send_from_directory(app.static_folder, "index.html")

    @app.route("/status", methods=["GET"])
    def status():
        try:
            mode = _backend()
            if mode == "pysatochip":
                conn = _pysatochip()
                (_, _, _, d) = conn.card_get_status()
                return jsonify({
                    "backend": mode,
                    "protocol_major": d.get("protocol_major_version"),
                    "protocol_minor": d.get("protocol_minor_version"),
                    "applet_major": d.get("applet_major_version"),
                    "applet_minor": d.get("applet_minor_version"),
                    "protocol": d.get("protocol_version"),
                })
            else:
                # gp.jar fallback: SELECT + GET_STATUS
                select = "00A40400095361746F4368697000"
                get_status = "B03C000000"
                resps = _gp_send([select, get_status])
                st = resps[0]
                data_hex = st.get("data_hex", "")
                # Parse first 4 bytes if present
                proto = {}
                if len(data_hex) >= 8:
                    pm = int(data_hex[0:2], 16)
                    pn = int(data_hex[2:4], 16)
                    am = int(data_hex[4:6], 16)
                    an = int(data_hex[6:8], 16)
                    proto = {
                        "protocol_major": pm,
                        "protocol_minor": pn,
                        "applet_major": am,
                        "applet_minor": an,
                        "protocol": (pm << 8) + pn,
                    }
                return jsonify({"backend": mode, "rapdu_hex": data_hex, **proto})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/verify_pin", methods=["POST"])
    def verify_pin():
        try:
            pin = request.json.get("pin", "")
            mode = _backend()
            if mode == "pysatochip":
                conn = _pysatochip()
                conn.card_verify_PIN_deprecated(0, list(pin.encode("utf-8")))
                return jsonify({"backend": mode, "ok": True})
            else:
                # PIN verify via raw APDU
                # B0 42 00 00 Lc | PIN
                pin_hex = pin.encode("utf-8").hex()
                lc = f"{len(pin):02x}"
                apdu = f"B0420000{lc}{pin_hex}"
                _gp_send(["00A40400095361746F4368697000", apdu])
                return jsonify({"backend": mode, "ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    @app.route("/bip32/generate_seed", methods=["POST"])
    def bip32_generate_seed():
        try:
            length = int(request.json.get("length", 32))
            on_card = bool(request.json.get("on_card", False))
            if length not in (16, 24, 32, 48, 64):
                return jsonify({"error": "length must be one of 16,24,32,48,64"}), 400
            mode = _backend()
            if on_card:
                if mode != "pysatochip":
                    return jsonify({"error": "On-card generation requires pysatochip backend (PC/SC)."}), 400
                conn = _pysatochip()
                # Ensure PIN and secure channel
                try:
                    if getattr(conn, 'needs_secure_channel', False):
                        conn.card_initiate_secure_channel()
                except Exception:
                    pass
                pin = request.json.get("pin")
                if pin:
                    conn.card_verify_PIN_deprecated(0, list(pin.encode('utf-8')))
                # APDU: B0 6B P1=len P2=00 (no data)
                apdu = [0xB0, 0x6B, length & 0xFF, 0x00, 0x00]
                resp, sw1, sw2 = conn.card_transmit(apdu)
                if sw1 != 0x90 or sw2 != 0x00:
                    return jsonify({"error": f"on-card generation failed: {hex(256*sw1+sw2)}"}), 400
                # Then export authentikey
                ak = conn.card_bip32_get_authentikey()
                return jsonify({
                    "backend": mode,
                    "on_card": True,
                    "authentikey_hex": ak.get_public_key_hex(False)
                })
            # Host generation + import
            seed = os.urandom(length)
            if mode == "pysatochip":
                conn = _pysatochip()
                conn.card_bip32_import_seed(seed)
                ak = conn.card_export_authentikey()
                ak_hex = ak.get_public_key_hex(False)
                return jsonify({
                    "backend": mode,
                    "seed_hex": seed.hex(),
                    "authentikey_hex": ak_hex,
                    "note": "Backup this seed securely; it won’t be shown again."
                })
            else:
                # Raw import seed: B0 6C P1=len P2=00 Lc=len | seed
                p1 = f"{length:02x}"
                apdu = ("B06C" + p1 + "00" + p1 + seed.hex()).upper()
                # Then export authentikey: B0 AD 00 00
                resps = _gp_send(["00A40400095361746F4368697000", apdu, "B0AD0000"])
                ak_hex = resps[1].get("data_hex", "")
                return jsonify({
                    "backend": mode,
                    "seed_hex": seed.hex(),
                    "authentikey_hex": ak_hex,
                    "note": "Backup this seed securely; it won’t be shown again."
                })
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    @app.route("/bip32/derive", methods=["POST"])
    def bip32_derive():
        try:
            path = request.json.get("path", "m/86'/0'/0'/0/0")
            mode = _backend()
            if mode == "pysatochip":
                conn = _pysatochip()
                pubkey, chaincode = conn.card_bip32_get_extendedkey(path)
                return jsonify({
                    "backend": mode,
                    "path": path,
                    "pubkey_hex": pubkey.get_public_key_hex(False),
                    "chaincode_hex": chaincode.hex()
                })
            else:
                # Build BIP32 GET_EXTENDED_KEY APDU per pysatochip implementation
                # Convert path string to bytes using the same encoding: 4 bytes per index (big-endian)
                path_hex = request.json.get("path_hex")
                if not path_hex:
                    # auto-encode string path to bytes
                    data = _encode_bip32_path(path)
                else:
                    data = bytes.fromhex(path_hex)
                p1 = len(data) // 4
                p2 = 0x40
                apdu = bytes([0xB0, 0x6D, p1 & 0xFF, p2, len(data)]) + data
                resps = _gp_send(["00A40400095361746F4368697000", apdu.hex()])
                # Return raw payload; client can parse
                return jsonify({
                    "backend": mode,
                    "path": path,
                    "rapdu_hex": resps[0].get("data_hex", "")
                })
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    @app.route("/bip32/export_seed", methods=["POST"])
    def bip32_export_seed():
        try:
            mode = _backend()
            if mode != "pysatochip":
                return jsonify({"error": "Exporting seed requires pysatochip backend (secure channel/PIN)."}), 400
            conn = _pysatochip()
            pin = request.json.get("pin")
            if pin:
                conn.card_verify_PIN_deprecated(0, list(pin.encode('utf-8')))
            # APDU: B0 6A 00 00 00
            apdu = [0xB0, 0x6A, 0x00, 0x00, 0x00]
            resp, sw1, sw2 = conn.card_transmit(apdu)
            if sw1 != 0x90 or sw2 != 0x00:
                return jsonify({"error": f"export failed: {hex(256*sw1+sw2)}"}), 400
            return jsonify({"backend": mode, "seed_hex": bytes(resp).hex()})
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    # ---------- Helpers (BIP32 path, EC ops, tagged hash) ----------

    def _encode_bip32_path(path_str: str) -> bytes:
        s = path_str.strip()
        if s.startswith('m/'): s = s[2:]
        parts = s.split('/') if s else []
        out = bytearray()
        for seg in parts:
            hardened = seg.endswith("'")
            num = int(seg[:-1] if hardened else seg)
            val = (0x80000000 | num) if hardened else num
            out += val.to_bytes(4, 'big')
        return bytes(out)

    # secp256k1 constants
    from pysatochip.ecc import ECPubkey, CURVE_ORDER as N, generator as GEN

    def _int_from_bytes(b: bytes) -> int:
        return int.from_bytes(b, 'big')

    def _int_to_32(bi: int) -> bytes:
        return (bi % N).to_bytes(32, 'big')

    def _tagged_hash(tag: str, *chunks: bytes) -> bytes:
        t = hashlib.sha256(tag.encode()).digest()
        h = hashlib.sha256(t + t + b''.join(chunks)).digest()
        return h

    def _xonly_from_pubkey_bytes(pub_hex: str) -> bytes:
        P = ECPubkey(bytes.fromhex(pub_hex))
        x, y = P.point()
        return x.to_bytes(32, 'big')

    @app.route("/musig2/demo_two_party", methods=["POST"])
    def musig2_demo_two_party():
        try:
            mode = _backend()
            if mode != "pysatochip":
                return jsonify({"error": "Two-party demo requires pysatochip backend (PC/SC)."}), 400
            from pysatochip.CardConnector import CardConnector
            conn = _pysatochip()
            # PIN optional
            pin = request.json.get("pin")
            if pin:
                conn.card_verify_PIN_deprecated(0, list(pin.encode('utf-8')))
            # Derive (optional); else assume already set
            path = request.json.get("path")
            if path:
                conn.card_bip32_get_extendedkey(path)
            # Get card pubkey (uncompressed hex)
            pubkey1, cc = conn.card_bip32_get_extendedkey("m/86'/0'/0'/0/0") if path else conn.card_bip32_get_extendedkey("m/86'/0'/0'/0/0")
            P1_hex = pubkey1.get_public_key_hex(False)
            P1 = ECPubkey(bytes.fromhex(P1_hex))
            P1x = _xonly_from_pubkey_bytes(P1_hex)
            # Counter-signer keypair
            d2 = secrets.randbelow(N-1) + 1
            P2 = (d2 * GEN()).from_point(generator_secp256k1) if False else None  # not used; use ECPubkey API
            # Build P2 from scalar
            G = GEN()
            P2 = (d2 * G)
            P2_hex = P2.get_public_key_hex(False)
            P2x = _xonly_from_pubkey_bytes(P2_hex)
            # L and coeffs a1,a2
            L = hashlib.sha256(P1x + P2x).digest()
            a1 = _int_from_bytes(hashlib.sha256(L + P1x).digest()) % N
            a2 = _int_from_bytes(hashlib.sha256(L + P2x).digest()) % N
            # Q = a1*P1 + a2*P2
            Q = (a1 * P1) + (a2 * P2)
            Qx_int, Qy_int = Q.point()
            Qx = Qx_int.to_bytes(32, 'big')
            ggacc_is_1 = (Qy_int % 2 == 0)
            # msg
            msg_hex = request.json.get("msg_hex") or secrets.token_hex(32)
            msg = bytes.fromhex(msg_hex)
            # Card pubnonces
            pubnonce1, enc1 = conn.card_musig2_generate_nonce(keynbr=0xFF, aggpk=Qx, msg=msg, extra=None)
            # parse two 33-byte points
            R1c_ser = pubnonce1[0:33]
            R2c_ser = pubnonce1[33:66]
            R1c = ECPubkey(R1c_ser)
            R2c = ECPubkey(R2c_ser)
            # Server nonces
            k1_2 = secrets.randbelow(N-1) + 1
            k2_2 = secrets.randbelow(N-1) + 1
            R1s = k1_2 * GEN()
            R2s = k2_2 * GEN()
            R1s_ser = bytes.fromhex(R1s.get_public_key_hex(True))
            R2s_ser = bytes.fromhex(R2s.get_public_key_hex(True))
            # b (nonce coefficient)
            b_bytes = _tagged_hash("MuSig/nonce", Qx, msg, R1c_ser, R2c_ser, R1s_ser, R2s_ser)
            b_int = _int_from_bytes(b_bytes) % N
            b = _int_to_32(b_int)
            # Aggregate R = (R1c+R1s) + b*(R2c+R2s)
            R1 = R1c + R1s
            R2 = R2c + R2s
            R = R1 + (b_int * R2)
            Rx_int, Ry_int = R.point()
            Rx = Rx_int.to_bytes(32, 'big')
            r_even = (Ry_int % 2 == 0)
            # If R.y odd, adjust server nonces as per BIP-340
            if not r_even:
                k1_2 = (N - k1_2) % N
                k2_2 = (N - k2_2) % N
            # Challenge e = BIP340 tagged hash
            e_bytes = _tagged_hash("BIP0340/challenge", Rx, Qx, msg)
            e_int = _int_from_bytes(e_bytes) % N
            e = _int_to_32(e_int)
            # a1,a2 -> ea1, ea2
            ea1_int = (e_int * a1) % N
            ea2_int = (e_int * a2) % N
            ea1 = _int_to_32(ea1_int)
            # Card partial
            psig1 = conn.card_musig2_sign_hash(keynbr=0xFF, secnonce=enc1, b=b, ea=ea1, r_has_even_y=r_even, ggacc_is_1=ggacc_is_1)
            s1_int = _int_from_bytes(psig1)
            # Server partial s2 = (ea2*d2' + k1_2 + b*k2_2) mod n
            d2_eff = d2 if ggacc_is_1 else (N - d2)
            s2_int = ( (ea2_int * d2_eff) + k1_2 + (b_int * k2_2) ) % N
            s_int = (s1_int + s2_int) % N
            sig = Rx + _int_to_32(s_int)
            # Verify: s*G == R + e*Q
            sG = s_int * GEN()
            eQ = e_int * Q
            R_check = sG + ((N - e_int) * Q)
            Rx_chk, Ry_chk = R_check.point()
            verified = (Rx_chk == Rx_int and ((Ry_chk % 2) == (Ry_int % 2)))
            return jsonify({
                "backend": mode,
                "path": path,
                "msg_hex": msg_hex,
                "card_pubkey_hex": P1_hex,
                "server_pubkey_hex": P2_hex,
                "L_hex": L.hex(),
                "a1_hex": _int_to_32(a1).hex(),
                "a2_hex": _int_to_32(a2).hex(),
                "aggpk_x_hex": Qx.hex(),
                "ggacc_is_1": ggacc_is_1,
                "card_pubnonces": {"R1_hex": R1c_ser.hex(), "R2_hex": R2c_ser.hex()},
                "server_pubnonces": {"R1_hex": R1s_ser.hex(), "R2_hex": R2s_ser.hex()},
                "b_hex": b.hex(),
                "R_x_hex": Rx.hex(),
                "r_even": r_even,
                "e_hex": e.hex(),
                "partial_card_hex": psig1.hex(),
                "signature_hex": sig.hex(),
                "verified": verified
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    @app.route("/import_privkey", methods=["POST"])
    def import_privkey():
        try:
            slot = int(request.json["slot"])  # 0..15
            key_hex = request.json["privkey_hex"]
            key = bytes.fromhex(key_hex)
            if len(key) != 32:
                return jsonify({"error": "privkey must be 32B hex"}), 400
            mode = _backend()
            if mode == "pysatochip":
                conn = _pysatochip()
                conn.satochip_import_privkey(slot, key)
                return jsonify({"backend": mode, "ok": True})
            else:
                # Build raw APDU per CardConnector.satochip_import_privkey
                key_encoding = 0x00
                key_type = 0x0C
                key_size = bytes([0x01, 0x00])
                rfu = bytes(6)
                blob = bytes([0x00, 0x20]) + key
                data = bytes([key_encoding, key_type]) + key_size + rfu + blob
                apdu = bytes([0xB0, 0x32, slot & 0xFF, 0x00, len(data)]) + data
                _gp_send(["00A40400095361746F4368697000", apdu.hex()])
                return jsonify({"backend": mode, "ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    @app.route("/musig2/generate_nonce", methods=["POST"])
    def musig2_generate_nonce():
        try:
            keynbr = int(request.json.get("keynbr", 0))
            aggpk_hex = request.json.get("aggpk_hex")
            msg_hex = request.json.get("msg_hex")
            extra_hex = request.json.get("extra_hex")
            aggpk: Optional[bytes] = bytes.fromhex(aggpk_hex) if aggpk_hex else None
            msg: Optional[bytes] = bytes.fromhex(msg_hex) if msg_hex else None
            extra: Optional[bytes] = bytes.fromhex(extra_hex) if extra_hex else None
            mode = _backend()
            if mode == "pysatochip":
                conn = _pysatochip()
                pubnonce, enc = conn.card_musig2_generate_nonce(keynbr=keynbr, aggpk=aggpk, msg=msg, extra=extra)
                return jsonify({"backend": mode, "pubnonce_hex": pubnonce.hex(), "encrypted_secnonce_hex": enc.hex()})
            else:
                # Build INIT data: [aggpk_len|aggpk|msg_len|msg|extra_len|extra]
                parts = []
                if aggpk is None:
                    parts.append(bytes([0x00]))
                else:
                    parts.append(bytes([len(aggpk)]) + aggpk)
                if msg is None or len(msg) == 0:
                    parts.append(bytes([0xFF]))
                else:
                    parts.append(bytes([len(msg)]) + msg)
                if extra is None:
                    parts.append(bytes([0x00]))
                else:
                    parts.append(bytes([len(extra)]) + extra)
                data = b"".join(parts)
                apdu_init = (bytes([0xB0, 0x7E, keynbr & 0xFF, 0x01, len(data)]) + data).hex()
                apdu_fin = bytes([0xB0, 0x7E, keynbr & 0xFF, 0x03, 0x00]).hex()
                resps = _gp_send(["00A40400095361746F4368697000", apdu_init, apdu_fin])
                pubnonce_hex = resps[0]["data_hex"]
                enc_hex = resps[1]["data_hex"]
                return jsonify({"backend": mode, "pubnonce_hex": pubnonce_hex, "encrypted_secnonce_hex": enc_hex})
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    @app.route("/musig2/sign_hash", methods=["POST"])
    def musig2_sign_hash():
        try:
            keynbr = int(request.json.get("keynbr", 0))
            secnonce_hex = request.json["secnonce_hex"]
            b_hex = request.json["b_hex"]
            ea_hex = request.json["ea_hex"]
            r_even = bool(request.json.get("r_even", True))
            ggacc_is_1 = bool(request.json.get("ggacc_is_1", True))
            secnonce = bytes.fromhex(secnonce_hex)
            b = bytes.fromhex(b_hex)
            ea = bytes.fromhex(ea_hex)
            mode = _backend()
            if mode == "pysatochip":
                conn = _pysatochip()
                psig = conn.card_musig2_sign_hash(keynbr=keynbr, secnonce=secnonce, b=b, ea=ea,
                                                  r_has_even_y=r_even, ggacc_is_1=ggacc_is_1)
                return jsonify({"backend": mode, "partial_signature_hex": psig.hex()})
            else:
                init = bytes([0xB0, 0x7F, keynbr & 0xFF, 0x01, len(secnonce)]) + secnonce
                flags = bytes([0x00 if r_even else 0x01, 0x01 if ggacc_is_1 else 0x00])
                data = b + ea + flags
                fin = bytes([0xB0, 0x7F, keynbr & 0xFF, 0x03, len(data)]) + data
                resps = _gp_send(["00A40400095361746F4368697000", init.hex(), fin.hex()])
                psig_hex = resps[1]["data_hex"]
                return jsonify({"backend": mode, "partial_signature_hex": psig_hex})
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    return app


if __name__ == "__main__":
    app = make_app()
    port = int(os.environ.get("PORT", 8000))
    app.run(host="127.0.0.1", port=port, debug=True)
