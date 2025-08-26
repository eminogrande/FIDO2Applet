import React, {useState} from 'react';
import {ScrollView, View, Text, TextInput, Button} from 'react-native';
import NfcManager, {NfcTech} from 'react-native-nfc-manager';
import {apduSelectByAID, AID_APPLET, apduGetStatus, apduMusig2GenerateNonceInit, apduMusig2GenerateNonceFinalize, apduMusig2SignInit, apduMusig2SignFinalize, hexToBytes} from './apdus';
import * as Crypto from 'expo-crypto';
import {demoComputeBAndEA, u8ToHex} from './aggregator';

function hex(b: Uint8Array) { return u8ToHex(b); }

async function tx(apdu: Uint8Array): Promise<Uint8Array> {
  const resp = await NfcManager.isoDepHandler.transceive(Array.from(apdu));
  return new Uint8Array(resp);
}

export default function ExpoMuSig2Screen() {
  const [log, setLog] = useState<string>('');
  const [pin, setPin] = useState<string>('123456');
  const [seedLen, setSeedLen] = useState<string>('32');
  const [path, setPath] = useState<string>("m/86'/0'/0'/0/0");
  const [aggpk, setAggpk] = useState<string>('');
  const [msg, setMsg] = useState<string>('');
  const [extra, setExtra] = useState<string>('');
  const [pubnonce, setPubnonce] = useState<string>('');
  const [secnonce, setSecnonce] = useState<string>('');
  const [bHex, setBHex] = useState<string>('');
  const [eaHex, setEaHex] = useState<string>('');
  const [rEven, setREven] = useState<boolean>(true);
  const [ggacc, setGgacc] = useState<boolean>(true);

  const sha256: (m: Uint8Array) => Promise<Uint8Array> = async (m) => {
    const h = await Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA256, Buffer.from(m).toString('hex'), {encoding: Crypto.CryptoEncoding.HEX});
    return hexToBytes(h);
  };

  function append(s: string) { setLog(l => l + s + '\n'); }

  async function withNfc<T>(f: () => Promise<T>) {
    await NfcManager.start();
    await NfcManager.requestTechnology(NfcTech.IsoDep);
    try { return await f(); } finally { NfcManager.cancelTechnologyRequest(); }
  }

  async function doSelect() {
    await withNfc(async () => {
      append('SELECT AID');
      const sel = apduSelectByAID(AID_APPLET);
      const r = await tx(sel);
      append('SW=' + hex(r.slice(-2)));
    });
  }

  async function doStatus() {
    await withNfc(async () => {
      const r = await tx(apduGetStatus());
      append('GET_STATUS R=' + hex(r));
    });
  }

  async function doVerifyPin() {
    await withNfc(async () => {
      const p = new TextEncoder().encode(pin);
      const apdu = new Uint8Array([0xB0, 0x42, 0x00, 0x00, p.length, ...p]);
      const r = await tx(apdu);
      append('VERIFY_PIN SW=' + hex(r.slice(-2)));
    });
  }

  function encodePath(p: string): Uint8Array {
    // Very small parser for paths like m/86'/0'/0'/0/0
    const items = p.replace('m/', '').split('/');
    const out = new Uint8Array(items.length * 4);
    const dv = new DataView(out.buffer);
    items.forEach((seg, i) => {
      const hardened = seg.endsWith("'");
      const num = parseInt(hardened ? seg.slice(0, -1) : seg, 10) >>> 0;
      const val = hardened ? (0x80000000 | num) : num;
      dv.setUint32(i * 4, val, false);
    });
    return out;
  }

  async function doImportSeed() {
    await withNfc(async () => {
      const n = Math.max(16, Math.min(64, parseInt(seedLen || '32', 10)));
      const seed = Crypto.getRandomBytes(n);
      append('Generating seed ' + n + 'B...');
      const apdu = new Uint8Array([0xB0, 0x6C, n & 0xff, 0x00, n, ...seed]);
      const r = await tx(apdu);
      append('IMPORT_SEED SW=' + hex(r.slice(-2)) + ' seed_hex=' + Buffer.from(seed).toString('hex'));
    });
  }

  async function doDerive() {
    await withNfc(async () => {
      const pb = encodePath(path);
      const apdu = new Uint8Array([0xB0, 0x6D, pb.length / 4, 0x40, pb.length, ...pb]);
      const r = await tx(apdu);
      append('DERIVE R=' + hex(r));
    });
  }

  async function doNonce() {
    await withNfc(async () => {
      const keynbr = 0xff; // use derived BIP32 key
      const agg = aggpk ? hexToBytes(aggpk) : undefined;
      const m = msg ? hexToBytes(msg) : undefined;
      const ex = extra ? hexToBytes(extra) : undefined;
      const r1 = await tx(apduMusig2GenerateNonceInit(keynbr, agg, m, ex));
      const r2 = await tx(apduMusig2GenerateNonceFinalize(keynbr));
      setPubnonce(hex(r1));
      setSecnonce(hex(r2));
      append('NONCE pubnonce=' + hex(r1));
      append('NONCE enc_secnonce=' + hex(r2));
    });
  }

  async function doComputeBEA() {
    // Demo: compute b (a_i) using only device pubkey
    // NOTE: For a real signature, compute L from all participants and e from Rx/aggpkX/msg
    // This demo sets ea=0 if it cannot compute e yet
    const myPk = aggpk ? hexToBytes(aggpk) : new Uint8Array(32); // placeholder if you don’t have aggpk yet
    const {b, ea, hasValidE} = await demoComputeBAndEA([myPk], myPk, undefined, undefined, undefined, sha256);
    setBHex(u8ToHex(b));
    setEaHex(u8ToHex(ea));
    append('AGG b=' + u8ToHex(b) + ' ea=' + u8ToHex(ea) + ' validE=' + hasValidE);
  }

  async function doSign() {
    await withNfc(async () => {
      const keynbr = 0xff;
      const sec = hexToBytes(secnonce);
      const b = hexToBytes(bHex);
      const ea = hexToBytes(eaHex);
      const init = await tx(apduMusig2SignInit(keynbr, sec));
      append('SIGN INIT SW=' + hex(init.slice(-2)));
      const fin = await tx(apduMusig2SignFinalize(keynbr, b, ea, rEven, ggacc));
      append('SIGN FINAL R=' + hex(fin));
    });
  }

  return (
    <ScrollView contentContainerStyle={{padding: 16}}>
      <Text style={{fontWeight:'bold', fontSize:18}}>Satochip MuSig2 Demo (Expo)</Text>
      <View style={{height:8}}/>
      <Button title="SELECT" onPress={doSelect}/>
      <Button title="GET STATUS" onPress={doStatus}/>
      <View style={{height:8}}/>
      <Text>PIN</Text>
      <TextInput value={pin} onChangeText={setPin} autoCapitalize='none' style={{borderWidth:1,padding:6}}/>
      <Button title="VERIFY PIN" onPress={doVerifyPin}/>

      <View style={{height:12}}/>
      <Text>Generate Seed bytes (16/24/32/48/64)</Text>
      <TextInput value={seedLen} onChangeText={setSeedLen} keyboardType='numeric' style={{borderWidth:1,padding:6}}/>
      <Button title="IMPORT RANDOM SEED" onPress={doImportSeed}/>

      <View style={{height:12}}/>
      <Text>Derive Path</Text>
      <TextInput value={path} onChangeText={setPath} autoCapitalize='none' style={{borderWidth:1,padding:6}}/>
      <Button title="DERIVE BIP32 KEY" onPress={doDerive}/>
      <Text>Tip: After derive, MuSig2 key number = 0xFF</Text>

      <View style={{height:12}}/>
      <Text>aggpk (hex, x-only or compressed)</Text>
      <TextInput value={aggpk} onChangeText={setAggpk} autoCapitalize='none' style={{borderWidth:1,padding:6}}/>
      <Text>msg (hex)</Text>
      <TextInput value={msg} onChangeText={setMsg} autoCapitalize='none' style={{borderWidth:1,padding:6}}/>
      <Text>extra (hex)</Text>
      <TextInput value={extra} onChangeText={setExtra} autoCapitalize='none' style={{borderWidth:1,padding:6}}/>
      <Button title="GENERATE NONCE" onPress={doNonce}/>
      <Text>pubnonce: {pubnonce}</Text>
      <Text>enc_secnonce: {secnonce}</Text>

      <View style={{height:12}}/>
      <Button title="COMPUTE b & ea (demo)" onPress={doComputeBEA}/>
      <Text>b (hex):</Text>
      <TextInput value={bHex} onChangeText={setBHex} autoCapitalize='none' style={{borderWidth:1,padding:6}}/>
      <Text>ea (hex):</Text>
      <TextInput value={eaHex} onChangeText={setEaHex} autoCapitalize='none' style={{borderWidth:1,padding:6}}/>
      <View style={{flexDirection:'row', alignItems:'center', gap:8}}>
        <Text>R even Y?</Text>
        <Button title={rEven? 'Yes' : 'No'} onPress={()=>setREven(v=>!v)}/>
        <Text>ggacc is 1?</Text>
        <Button title={ggacc? 'Yes' : 'No'} onPress={()=>setGgacc(v=>!v)}/>
      </View>
      <Button title="SIGN HASH" onPress={doSign}/>

      <View style={{height:12}}/>
      <Text selectable style={{fontFamily:'Courier', fontSize:12}}>{log}</Text>
    </ScrollView>
  );
}

