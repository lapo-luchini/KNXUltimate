'use strict'
const __importDefault = (this && this.__importDefault) || function (mod) {
  return (mod && mod.__esModule) ? mod : { default: mod }
}
Object.defineProperty(exports, '__esModule', { value: true })
exports.KNXSecureSessionRequest = void 0

const util = require('util')
const crypto = require('crypto')

exports.pbkdf2 = util.promisify(crypto.pbkdf2);

exports.xor = function (buf1, buf2) {
    if (buf1.length != buf2.length)
        throw new Error('Buffers must have same length.');
    const out = Buffer.allocUnsafe(buf1.length);
    for (let i = 0; i < out.length; ++i)
        out[i] = buf1[i] ^ buf2[i];
    return out;
};

function len2byte(len) {
    if ((len >>> 16) > 0)
        throw new Error('Length is excessive: ' + len);
    return Buffer.from([(len >>> 8) & 0xFF, len & 0xFF]);
};
exports.len2byte = len2byte;

exports.macCBC = function(key, block0, additional, payload) {
    const lenAddit = additional.length;
    if ((lenAddit >>> 16) > 0)
        throw new Error('Additional data is too long.');
    const lenTotal = block0.length + 2 + lenAddit + payload.length;
    const lenPadded = ((lenTotal-1)|0xF)+1; // pad to next 16 bytes block
    const blocks = Buffer.concat([
        block0,
        len2byte(lenAddit),
        additional,
        payload,
        Buffer.alloc(lenPadded - lenTotal)
    ]);
    // console.log('MAC CBC key:   ', key.toString('hex'));
    // console.log('MAC CBC blocks:', blocks.toString('hex'));
    const cipher = crypto.createCipheriv('aes-128-cbc', key, Buffer.alloc(16));
    const tmp = cipher.update(blocks);
    const tmp2 = cipher.final(); // should return nothing, but it does!??
    // console.log('MAC CBC out:   ', tmp.toString('hex'));
    // console.log('MAC CBC final: ', tmp2.toString('hex'));
    return tmp.subarray(-16);
};

exports.hash = function (data) {
    return crypto
        .createHash('sha256')
        .update(data)
        .digest();
};

exports.encrypt = function (key, ctr, mac, payload) {
    const cipher = crypto.createCipheriv('aes-128-ctr', key, ctr);
    const macEncrypted = cipher.update(mac);
    return Buffer.concat([
        cipher.update(payload),
        cipher.final(),
        macEncrypted
    ]);
};

exports.decrypt = function(key, ctr, payload) {
    const cipher = crypto.createDecipheriv('aes-128-ctr', key, ctr);
    const mac = cipher.update(payload.subarray(-16));
    const data = Buffer.concat([
        cipher.update(payload.subarray(0, -16)),
        cipher.final()
    ]);
    return { data, mac };
};

// # sourceMappingURL=KNXSecure.js.map
