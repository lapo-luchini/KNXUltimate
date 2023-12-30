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

class KNXSecureSessionAuthenticate extends KNXPacket.KNXPacket {
  constructor (cri,  _jKNXSecureKeyring = {}) {
    // super(KNXConstants.KNX_CONSTANTS.SECURE_SESSION_REQUEST, hpaiControl.length + hpaiData.length + cri.length + 32);
    // super(KNXConstants.KNX_CONSTANTS.SECURE_SESSION_AUTH, 26)
    super(KNXConstants.KNX_CONSTANTS.SECURE_WRAPPER, 62)
    this.cri = cri;
    const keyring = _jKNXSecureKeyring;
    const tunnel = keyring.tunnel;

    const myPassword = keyring.Devices[0].managementPassword;
    const myPasswordHash = KNXSecure.pbkdf2(myPassword, 'user-password.1.secure.ip.knx.org', 65536, 16, 'sha256');
    console.log('My password', myPasswordHash.toString('hex'));
    const pubXOR = KNXSecure.xor(Buffer.from(tunnel.dhSecret.public), tunnel.dhServer);
    console.log('XOR        ', pubXOR.toString('hex'));
    const authHead = Buffer.from(
      '06' +   // header size
      '10' +   // protocol version
      '0953' + // SESSION_AUTHENTICATE
      '0018' + // total length (24)
      '0001', // user id (admin)
      'hex');
    const mac = KNXSecure.macCBC(myPasswordHash, Buffer.alloc(16), Buffer.concat([ authHead, pubXOR ]), Buffer.alloc(0));
    const authCtrSession = Buffer.from('0000000000000000000000000000ff00', 'hex');
    const macEncrypted = KNXSecure.encrypt(myPasswordHash, authCtrSession, mac, Buffer.alloc(0));
    const authSess = Buffer.concat([ authHead, macEncrypted ]);
    // const authSess = pubXOR;
    const sessionId = Buffer.from('0001', 'hex');
    // const sessionId = Buffer.from('000a', 'hex');
    const sequence = Buffer.from('000000000000', 'hex');
    const serial = Buffer.from('00fa12345678', 'hex');
    const tag = Buffer.from('affe', 'hex');
    // const serial = Buffer.from('0000786b6e78', 'hex');
    // const tag = Buffer.from('0000', 'hex');
    this.head2 = Buffer.concat([ sessionId, sequence, serial, tag ]);
    this.wrap = KNXSecure.wrap(tunnel.sessionKey, authSess, sessionId, sequence, serial, tag);
  }

  static createFromBuffer (buffer, offset = 0) {
    throw new Error('TODO');
    /*
    if (offset >= buffer.length) {
      throw new Error('Buffer too short')
    }
    const hpaiControl = HPAI.HPAI.createFromBuffer(buffer, offset)
    offset += hpaiControl.length
    const hpaiData = HPAI.HPAI.createFromBuffer(buffer, offset)
    offset += hpaiData.length
    const cri = CRIFactory.default.createFromBuffer(buffer, offset)
    return new KNXSecureSessionRequest(cri, hpaiControl, hpaiData)
    */
  }

  toBuffer () {
    console.log('Auth1', this.header.toBuffer());
    console.log('Auth2', this.head2);
    console.log('Auth3', this.wrap);
    return Buffer.concat([
      this.header.toBuffer(),
      this.head2,
      this.wrap
    ])
  }
}
exports.KNXSecureSessionAuthenticate = KNXSecureSessionAuthenticate
// # sourceMappingURL=KNXSecureSessionRequest.js.map
