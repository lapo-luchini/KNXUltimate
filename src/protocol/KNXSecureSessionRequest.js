'use strict'
const __importDefault = (this && this.__importDefault) || function (mod) {
  return (mod && mod.__esModule) ? mod : { default: mod }
}
Object.defineProperty(exports, '__esModule', { value: true })
exports.KNXSecureSessionRequest = void 0
const crypto = require('crypto')
const KNXConstants = require('./KNXConstants')
const KNXPacket = require('./KNXPacket')
const KNXSecure = require('./KNXSecure')
const HPAI = require('./HPAI')
const CRIFactory = __importDefault(require('./CRIFactory'))

class KNXSecureSessionRequest extends KNXPacket.KNXPacket {
  constructor (cri, hpaiData = HPAI.HPAI.NULLHPAI, _jKNXSecureKeyring = {}, useTestKey = null) {
    // super(KNXConstants.KNX_CONSTANTS.SECURE_SESSION_REQUEST, hpaiControl.length + hpaiData.length + cri.length + 32);
    super(KNXConstants.KNX_CONSTANTS.SECURE_SESSION_REQUEST, hpaiData.length + 32)
    this.cri = cri
    this.hpaiData = hpaiData

    const Curve25519 = require('./../Curve25519')
    try {
      if (_jKNXSecureKeyring.useTestKey)
        console.log('Warning INSECURE test key in use:', _jKNXSecureKeyring.useTestKey);
      const secret = Curve25519.generateKeyPair(_jKNXSecureKeyring.useTestKey || crypto.randomBytes(32))
      // let hexString = "f0c143e363147dc64913d736978042ef748ba448aa6ce2a1dab5ddecca919455";
      // secret.public = Uint8Array.from(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
      this.diffieHellmanClientPublicValue = Buffer.from(secret.public).toString('hex');
      // this.diffieHellmanClientPublicValue = Buffer.from(authenticationPasswordUint8Array).toString('hex')
      console.log('My public:', this.diffieHellmanClientPublicValue);
      _jKNXSecureKeyring.tunnel = {};
      _jKNXSecureKeyring.tunnel.dhSecret = secret
    } catch (error) {
      throw (error)
    }
  }

  static createFromBuffer (buffer, offset = 0) {
    if (offset >= buffer.length) {
      throw new Error('Buffer too short')
    }
    const hpaiControl = HPAI.HPAI.createFromBuffer(buffer, offset)
    offset += hpaiControl.length
    const hpaiData = HPAI.HPAI.createFromBuffer(buffer, offset)
    offset += hpaiData.length
    const cri = CRIFactory.default.createFromBuffer(buffer, offset)
    return new KNXSecureSessionRequest(cri, hpaiControl, hpaiData)
  }

  toBuffer () {
    return Buffer.concat([
      this.header.toBuffer(),
      this.hpaiData.toBuffer(),
      Buffer.from(this.diffieHellmanClientPublicValue, 'hex')
    ])
  }
}
exports.KNXSecureSessionRequest = KNXSecureSessionRequest
// # sourceMappingURL=KNXSecureSessionRequest.js.map
