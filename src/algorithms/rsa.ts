import { BufferSourceConverter, Convert } from 'pvtsutils';

import {
  EncryptedKeyNotSupportedError,
  InvalidKeyDataError,
  InvalidPrivateKeyFormatError,
} from '../errors';
import type {
  AlgorithmBinding,
  DecodeSshSignatureParams,
  DecodeSshSignatureResult,
  EncodeSshSignatureParams,
  ExportPrivatePkcs8Params,
  ExportPrivateToSshParams,
  ExportPublicSpkiParams,
  ExportPublicToSshParams,
  ImportPrivateFromSshParams,
  ImportPrivatePkcs8Params,
  ImportPublicFromSshParams,
  ImportPublicSpkiParams,
  SignParams,
  VerifyParams,
} from '../registry';
import type { SshSignatureAlgo } from '../types';
import type { SshPublicKeyBlob } from '../wire/public_key';
import { SshReader } from '../wire/reader';
import { SshWriter } from '../wire/writer';

export class RsaBinding implements AlgorithmBinding {
  private hash = 'SHA-256';

  constructor(hash = 'SHA-256') {
    this.hash = hash;
  }

  async importPublicFromSsh(params: ImportPublicFromSshParams): Promise<CryptoKey> {
    const { blob, crypto } = params;
    const reader = new SshReader(blob);

    // Skip type (already verified in parsePublicKey)
    reader.readString();

    // Read e (exponent)
    const e = reader.readMpInt();

    // Read n (modulus)
    const n = reader.readMpInt();

    // Create JWK
    const jwk = {
      kty: 'RSA' as const,
      n: Convert.ToBase64Url(n),
      e: Convert.ToBase64Url(e),
    };

    return crypto.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: this.hash,
      },
      true,
      ['verify'],
    );
  }

  async exportPublicToSsh(params: ExportPublicToSshParams): Promise<Uint8Array> {
    const { publicKey, crypto } = params;
    const jwk = await crypto.subtle.exportKey('jwk', publicKey);

    if (!jwk.n || !jwk.e) {
      throw new InvalidKeyDataError('RSA JWK missing required parameters (n, e)');
    }

    // Decode base64url
    const n = Convert.FromBase64Url(jwk.n);
    const e = Convert.FromBase64Url(jwk.e);

    const writer = new SshWriter();
    writer.writeString('ssh-rsa');
    writer.writeMpInt(e);
    writer.writeMpInt(n);

    return writer.toUint8Array();
  }

  async importPublicSpki(params: ImportPublicSpkiParams): Promise<CryptoKey> {
    const { spki, crypto } = params;
    return crypto.subtle.importKey(
      'spki',
      BufferSourceConverter.toArrayBuffer(spki),
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: this.hash,
      },
      true,
      ['verify'],
    );
  }

  async exportPublicSpki(params: ExportPublicSpkiParams): Promise<ArrayBuffer> {
    const { publicKey, crypto } = params;
    return crypto.subtle.exportKey('spki', publicKey);
  }

  async importPrivatePkcs8(params: ImportPrivatePkcs8Params): Promise<CryptoKey> {
    const { pkcs8, crypto } = params;
    return crypto.subtle.importKey(
      'pkcs8',
      BufferSourceConverter.toArrayBuffer(pkcs8),
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: this.hash,
      },
      true,
      ['sign'],
    );
  }

  async exportPrivatePkcs8(params: ExportPrivatePkcs8Params): Promise<ArrayBuffer> {
    const { privateKey, crypto } = params;
    return crypto.subtle.exportKey('pkcs8', privateKey);
  }

  async importPrivateFromSsh(params: ImportPrivateFromSshParams): Promise<CryptoKey> {
    const { sshKey, crypto } = params;

    // Remove PEM headers and decode base64
    const base64Data = sshKey
      .replace(/-----BEGIN OPENSSH PRIVATE KEY-----/, '')
      .replace(/-----END OPENSSH PRIVATE KEY-----/, '')
      .replace(/\s/g, '');

    const binaryData = Convert.FromBase64(base64Data);
    const reader = new SshReader(binaryData);

    // Check magic string
    const magic = reader.readBytes(15);
    if (Convert.ToHex(magic) !== '6f70656e7373682d6b65792d763100') {
      throw new InvalidPrivateKeyFormatError('invalid magic string');
    }

    // Read cipher, kdf, and options
    const _cipherName = reader.readString();
    const _kdfName = reader.readString();
    const _kdfOptions = reader.readString();

    if (_cipherName !== 'none') {
      throw new EncryptedKeyNotSupportedError(_cipherName);
    }

    // Read number of keys
    const numKeys = reader.readUint32();
    if (numKeys !== 1) {
      throw new InvalidPrivateKeyFormatError('multiple keys not supported');
    }

    // Skip public key (we don't need it for private key import)
    const publicKeyLength = reader.readUint32();
    reader.readBytes(publicKeyLength);

    // Read encrypted private key length and data
    const privateKeyLength = reader.readUint32();
    const privateKeyData = reader.readBytes(privateKeyLength);

    // Decrypt if needed (but we already checked cipher is 'none')
    const privateReader = new SshReader(privateKeyData);

    // Read checkints
    const checkint1 = privateReader.readUint32();
    const checkint2 = privateReader.readUint32();
    if (checkint1 !== checkint2) {
      throw new InvalidPrivateKeyFormatError('invalid checkints');
    }

    // Skip key type (already known)
    privateReader.readString();

    // Read RSA parameters in SSH private key format order
    const n = privateReader.readMpInt();
    const e = privateReader.readMpInt();
    const d = privateReader.readMpInt();
    const iqmp = privateReader.readMpInt();
    const p = privateReader.readMpInt();
    const q = privateReader.readMpInt();

    // Skip comment
    privateReader.readString();

    // Create JWK with all required parameters
    // Convert Uint8Array to BigInt for calculations
    const dBig = BigInt('0x' + Convert.ToHex(d));
    const pBig = BigInt('0x' + Convert.ToHex(p));
    const qBig = BigInt('0x' + Convert.ToHex(q));

    // Calculate dp = d mod (p-1), dq = d mod (q-1)
    const dpBig = dBig % (pBig - 1n);
    const dqBig = dBig % (qBig - 1n);

    // Convert back to Uint8Array with proper padding
    const dpBytes = Convert.FromHex(dpBig.toString(16).padStart(p.length * 2, '0'));
    const dqBytes = Convert.FromHex(dqBig.toString(16).padStart(q.length * 2, '0'));

    const jwk = {
      kty: 'RSA' as const,
      n: Convert.ToBase64Url(n),
      e: Convert.ToBase64Url(e),
      d: Convert.ToBase64Url(d),
      p: Convert.ToBase64Url(p),
      q: Convert.ToBase64Url(q),
      dp: Convert.ToBase64Url(dpBytes),
      dq: Convert.ToBase64Url(dqBytes),
      qi: Convert.ToBase64Url(iqmp),
    };

    return crypto.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: this.hash,
      },
      true,
      ['sign'],
    );
  }

  async exportPrivateToSsh(params: ExportPrivateToSshParams): Promise<Uint8Array> {
    const { privateKey, crypto } = params;

    // Export private key to JWK to obtain all RSA parameters
    const jwk: any = await crypto.subtle.exportKey('jwk', privateKey);
    if (!jwk.n || !jwk.e || !jwk.d || !jwk.p || !jwk.q) {
      throw new InvalidKeyDataError('RSA JWK missing required parameters');
    }

    const n = new Uint8Array(Convert.FromBase64Url(jwk.n));
    const e = new Uint8Array(Convert.FromBase64Url(jwk.e));
    const d = new Uint8Array(Convert.FromBase64Url(jwk.d));
    const p = new Uint8Array(Convert.FromBase64Url(jwk.p));
    const q = new Uint8Array(Convert.FromBase64Url(jwk.q));
    const qi = jwk.qi ? new Uint8Array(Convert.FromBase64Url(jwk.qi)) : new Uint8Array();

    // Build the private key section as expected by importPrivateFromSsh
    // Order: ssh-rsa, n, e, d, iqmp, p, q
    const writer = new SshWriter();
    writer.writeString('ssh-rsa');
    writer.writeMpInt(n);
    writer.writeMpInt(e);
    writer.writeMpInt(d);
    writer.writeMpInt(qi);
    writer.writeMpInt(p);
    writer.writeMpInt(q);

    return writer.toUint8Array();
  }

  async sign(params: SignParams): Promise<ArrayBuffer> {
    const { privateKey, data, crypto, hash = this.hash } = params;

    // If the key's hash doesn't match the requested hash, re-import it
    let keyToUse = privateKey;
    if (hash !== this.hash) {
      const pkcs8 = await this.exportPrivatePkcs8({ privateKey, crypto });
      keyToUse = await this.importPrivatePkcs8({ pkcs8: new Uint8Array(pkcs8), crypto });
    }

    return crypto.subtle.sign(
      'RSASSA-PKCS1-v1_5',
      keyToUse,
      BufferSourceConverter.toArrayBuffer(data),
    );
  }

  async verify(params: VerifyParams): Promise<boolean> {
    const { publicKey, signature, data, crypto, hash = this.hash } = params;

    // If the key's hash doesn't match the requested hash, re-import it
    let keyToUse = publicKey;
    if (hash !== this.hash) {
      const spki = await this.exportPublicSpki({ publicKey, crypto });
      keyToUse = await this.importPublicSpki({ spki: new Uint8Array(spki), crypto });
    }

    return crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      keyToUse,
      BufferSourceConverter.toArrayBuffer(signature),
      BufferSourceConverter.toArrayBuffer(data),
    );
  }

  encodeSshSignature(params: EncodeSshSignatureParams): Uint8Array {
    const { signature, algo } = params;
    const writer = new SshWriter();
    writer.writeString(algo);
    writer.writeBytes(signature);
    return writer.toUint8Array();
  }

  decodeSshSignature(params: DecodeSshSignatureParams): DecodeSshSignatureResult {
    const { signature } = params;
    const reader = new SshReader(signature);
    const algo = reader.readString() as SshSignatureAlgo;
    const sig = reader.readBytes(reader.remaining());
    return { signature: sig, algo };
  }

  supportsCryptoKey(cryptoKey: CryptoKey): boolean {
    return cryptoKey.algorithm.name === 'RSASSA-PKCS1-v1_5';
  }

  parseCertificatePublicKey(reader: SshReader): SshPublicKeyBlob {
    // Read RSA public key components from certificate format
    const publicKeyExponent = reader.readBytes(reader.readUint32()); // e
    const publicKeyModulus = reader.readBytes(reader.readUint32()); // n

    // Reconstruct the public key blob in standard SSH format
    const writer = new SshWriter();
    writer.writeString('ssh-rsa');
    writer.writeMpInt(publicKeyExponent);
    writer.writeMpInt(publicKeyModulus);

    return {
      type: 'ssh-rsa',
      keyData: writer.toUint8Array(),
    };
  }

  getCertificateType(): string {
    return 'ssh-rsa-cert-v01@openssh.com';
  }

  getSignatureAlgo(): SshSignatureAlgo {
    return this.hash === 'SHA-256' ? 'rsa-sha2-256' : 'rsa-sha2-512';
  }
}
