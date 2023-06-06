import KNXSecure from './src/protocol/KNXSecure.js';
import Curve25519 from './src/Curve25519.js';

const { pbkdf2, xor, len2byte, macCBC, hash, encrypt, decrypt } = KNXSecure;

function dump(v) {
    return Buffer.from(v).toString('hex');
}

/** Calculate the payload and MAC for a secure wrapper. */
function wrap(sessionKey, payload, sessionId, sequence, serial, tag) {
    console.log('# SecureWrapper');
    const lenTotal = payload.length + sessionId.length + sequence.length + serial.length + tag.length +
        6 + // KNX/IP header
        16; // MAC
    const header = Buffer.from('06100950', 'hex');
    const additional = Buffer.concat([
        header,
        len2byte(lenTotal),
        sessionId
    ]);
    const block0 = Buffer.concat([
        sequence,
        serial,
        tag,
        len2byte(payload.length)
    ]);
    const ctr0 = Buffer.concat([
        sequence,
        serial,
        tag,
        Buffer.from('ff00', 'hex')
    ]);
    const mac = macCBC(sessionKey, block0, additional, payload);
    console.log('MAC (clear)  ', mac.toString('hex'));
    const encrypted = encrypt(sessionKey, ctr0, mac, payload);
    console.log('MAC (encrypt)', encrypted.toString('hex'));
    // 7915a4f36e6e4208d28b4a207d8f35c0d138c26a7b5e716952dba8e7e4bd80bd7d868a3ae78749de
    // d138c26a7b5e716952dba8e7e4bd80bd7d868a3ae78749de
    const decrypted = decrypt(sessionKey, ctr0, encrypted);
    if (!payload.equals(decrypted.data))
        throw new Error("Decrypted data error.");
    if (!mac.equals(decrypted.mac))
        throw new Error("Decrypted MAC error.");
    return encrypted;
}

// replicate test vectors from
// https://github.com/XKNX/xknx/blob/5f8b96871ee90f81ebdb447e0f22629c47063b75/examples/ip_secure_calculations.py#L159

console.log('# SessionRequest');
const myKey = Curve25519.generateKeyPair(Buffer.from('b8fabd62665d8b9e8a9d8b1f4bca42c8c2789a6110f50e9dd785b3ede883f378','hex'));
console.log('My public    ', dump(myKey.public));
const devKeyPub = Buffer.from('bdf099909923143ef0a5de0b3be3687bc5bd3cf5f9e6f901699cd870ec1ff824', 'hex');
console.log('Device public', dump(devKeyPub));
const pubXOR = xor(Buffer.from(myKey.public), devKeyPub);
console.log('XORed pubkeys', dump(pubXOR));
const keyShared = Curve25519.sharedKey(myKey.private, devKeyPub);
console.log('# SessionResponse');
console.log('ECDH shared  ', dump(keyShared));
const sessionKey = hash(Buffer.from(keyShared)).slice(0, 16);
console.log('Session key  ', dump(sessionKey));
const myPassword = 'secret';
const devPassword = 'trustme';
const devPasswordHash = await pbkdf2(devPassword, 'device-authentication-code.1.secure.ip.knx.org', 65536, 16, 'sha256');
console.log('Device passwd', dump(devPasswordHash));
const data = Buffer.from('0610095200380001b752be246459260f6b0c4801fbd5a67599f83b4057b3ef1e79e469ac17234e15', 'hex');
const blockEmpty = Buffer.alloc(0);
const block0 = Buffer.alloc(16); // zero-filled block for MAC
const mac = macCBC(devPasswordHash, block0,
    Buffer.concat([data.slice(0, 8), pubXOR]), blockEmpty);
console.log('MAC (cleartx)', dump(mac));
const ctrSessionResponse = Buffer.from('0000000000000000000000000000ff00', 'hex');
const macEncrypted = encrypt(devPasswordHash, ctrSessionResponse, mac, blockEmpty);
console.log('MAC (encrypt)', dump(macEncrypted));
console.log('# SessionAuthenticate');
const myPasswordHash = await pbkdf2(myPassword, 'user-password.1.secure.ip.knx.org', 65536, 16, 'sha256');
console.log('My password  ', dump(myPasswordHash));
const authWrap = Buffer.from('06100950003e000100000000000000fa12345678affe7915a4f36e6e4208d28b4a207d8f35c0d138c26a7b5e716952dba8e7e4bd80bd7d868a3ae78749de', 'hex');
const authSess = Buffer.from('06100953001800011f1d59ea9f12a152e5d9727f08462cde', 'hex');
const authCtrSession = Buffer.from('0000000000000000000000000000ff00', 'hex');
const authMAC = macCBC(myPasswordHash, block0,
    Buffer.concat([authSess.slice(0, 8), pubXOR]), blockEmpty);
console.log('MAC (clear)  ', dump(authMAC));
const authMACEncrypted = encrypt(myPasswordHash, authCtrSession, authMAC, blockEmpty);
console.log('MAC (encrypt)', dump(authMACEncrypted));
console.log('MAC (receivd)', dump(authSess.slice(8)));
if (!authMACEncrypted.equals(authSess.slice(8)))
    throw new Error('Invalid MAC.');
const encrypted = wrap(sessionKey, authSess,
    authWrap.slice(6, 8),    // secure session id
    authWrap.slice(8, 14),   // sequence number
    authWrap.slice(14, 20),  // serial number
    authWrap.slice(20, 22)); // message tag
if (!encrypted.equals(authWrap.slice(22)))
    throw new Error('Invalid encryption.');
// verify MAC
const decrypted = decrypt(myPasswordHash, authCtrSession, authSess.slice(8));
if (!authMAC.equals(decrypted.mac))
    throw new Error("Decrypted MAC error.");
console.log('# SessionStatus');
const statusWrap = Buffer.from('06100950002e000100000000000000faaaaaaaaaaffe26156db5c749888fa373c3e0b4bde4497c395e4b1c2f46a1', 'hex');
const statusSess = Buffer.from('0610095400080000', 'hex');
const statusEncr = wrap(sessionKey, statusSess,
    statusWrap.slice(6, 8),    // secure session id
    statusWrap.slice(8, 14),   // sequence number
    statusWrap.slice(14, 20),  // serial number
    statusWrap.slice(20, 22)); // message tag
if (!statusEncr.equals(statusWrap.slice(22)))
    throw new Error('Invalid encryption.');
