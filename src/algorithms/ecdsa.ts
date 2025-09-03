import { BufferSourceConverter, Convert } from 'pvtsutils';

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
import { SshReader } from '../wire/reader';
import { SshWriter } from '../wire/writer';

export class EcdsaBinding implements AlgorithmBinding {
  private curveName: string;
  private sshType: string;
  private namedCurve: string;

  constructor(curveName: string, sshType: string, namedCurve: string) {
    this.curveName = curveName;
    this.sshType = sshType;
    this.namedCurve = namedCurve;
  }

  async importPublicFromSsh(params: ImportPublicFromSshParams): Promise<CryptoKey> {
    const { blob, crypto } = params;
    const reader = new SshReader(blob);

    // Skip type (already verified in parsePublicKey)
    reader.readString();

    // Read curve name
    const curve = reader.readString();
    if (curve !== this.curveName) {
      throw new Error(`Invalid curve name: ${curve}, expected ${this.curveName}`);
    }

    // Read Q (public key as mpint)
    const q = reader.readMpInt();

    // Convert to JWK format
    const jwk = {
      kty: 'EC' as const,
      crv: this.namedCurve,
      x: Convert.ToBase64Url(q.slice(1, 33)), // x coordinate (32 bytes)
      y: Convert.ToBase64Url(q.slice(33)), // y coordinate (32 bytes)
    };

    return crypto.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'ECDSA',
        namedCurve: this.namedCurve,
      },
      true,
      ['verify'],
    );
  }

  async exportPublicToSsh(params: ExportPublicToSshParams): Promise<Uint8Array> {
    const { publicKey, crypto } = params;
    const jwk = await crypto.subtle.exportKey('jwk', publicKey);

    if (!jwk.x || !jwk.y) {
      throw new Error('Invalid JWK');
    }

    // Decode base64url
    const x = new Uint8Array(Convert.FromBase64Url(jwk.x));
    const y = new Uint8Array(Convert.FromBase64Url(jwk.y));

    // Create uncompressed point (0x04 + x + y)
    const q = new Uint8Array(1 + x.length + y.length);
    q[0] = 0x04;
    q.set(x, 1);
    q.set(y, 1 + x.length);

    const writer = new SshWriter();
    writer.writeString(this.sshType);
    writer.writeString(this.curveName);
    writer.writeMpInt(q);

    return writer.toUint8Array();
  }

  async importPublicSpki(params: ImportPublicSpkiParams): Promise<CryptoKey> {
    const { spki, crypto } = params;
    return crypto.subtle.importKey(
      'spki',
      BufferSourceConverter.toArrayBuffer(spki),
      {
        name: 'ECDSA',
        namedCurve: this.namedCurve,
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
        name: 'ECDSA',
        namedCurve: this.namedCurve,
      },
      true,
      ['sign'],
    );
  }

  async exportPrivatePkcs8(params: ExportPrivatePkcs8Params): Promise<ArrayBuffer> {
    const { privateKey, crypto } = params;
    return crypto.subtle.exportKey('pkcs8', privateKey);
  }

  async exportPrivateToSsh(params: ExportPrivateToSshParams): Promise<Uint8Array> {
    const { privateKey, crypto } = params;

    // Export private key to JWK to get all parameters
    const jwk: any = await crypto.subtle.exportKey('jwk', privateKey);
    if (!jwk.d || !jwk.x || !jwk.y) {
      throw new Error('Invalid ECDSA JWK');
    }

    // Decode coordinates
    const x = new Uint8Array(Convert.FromBase64Url(jwk.x));
    const y = new Uint8Array(Convert.FromBase64Url(jwk.y));
    const d = new Uint8Array(Convert.FromBase64Url(jwk.d));

    // Create uncompressed public key point (0x04 + x + y)
    const publicPoint = new Uint8Array(1 + x.length + y.length);
    publicPoint[0] = 0x04;
    publicPoint.set(x, 1);
    publicPoint.set(y, 1 + x.length);

    // Build the private key section as expected by importPrivateFromSsh
    const writer = new SshWriter();
    writer.writeString(this.sshType);
    writer.writeString(this.curveName);
    writer.writeMpInt(publicPoint);
    writer.writeMpInt(d);

    return writer.toUint8Array();
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
      throw new Error('Invalid OpenSSH private key format');
    }

    // Read cipher, kdf, and options
    const _cipherName = reader.readString();
    const _kdfName = reader.readString();
    const _kdfOptions = reader.readString();

    if (_cipherName !== 'none') {
      throw new Error('Encrypted OpenSSH private keys are not supported');
    }

    // Read number of keys
    const numKeys = reader.readUint32();
    if (numKeys !== 1) {
      throw new Error('Multiple keys in OpenSSH private key are not supported');
    }

    // Skip public key
    const publicKeyLength = reader.readUint32();
    reader.readBytes(publicKeyLength);

    // Read private key
    const privateKeyLength = reader.readUint32();
    const privateKeyData = reader.readBytes(privateKeyLength);

    const privateReader = new SshReader(privateKeyData);

    // Read checkints
    const checkint1 = privateReader.readUint32();
    const checkint2 = privateReader.readUint32();
    if (checkint1 !== checkint2) {
      throw new Error('Invalid checkints in OpenSSH private key');
    }

    // Skip key type
    privateReader.readString();

    // Read curve name
    privateReader.readString();

    // Read public key point
    const publicKeyPoint = privateReader.readMpInt();

    // Read private key value
    const privateKeyValue = privateReader.readMpInt();

    // Skip comment
    privateReader.readString();

    // Extract x and y from public key point (uncompressed format: 0x04 + x + y)
    if (publicKeyPoint[0] !== 0x04) {
      throw new Error('Invalid public key point format');
    }

    // Calculate coordinate length based on curve
    const coordLength = Math.floor((publicKeyPoint.length - 1) / 2);
    const x = publicKeyPoint.slice(1, 1 + coordLength);
    const y = publicKeyPoint.slice(1 + coordLength);

    // Create JWK
    const jwk = {
      kty: 'EC' as const,
      crv: this.namedCurve,
      x: Convert.ToBase64Url(x),
      y: Convert.ToBase64Url(y),
      d: Convert.ToBase64Url(privateKeyValue),
    };

    return crypto.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'ECDSA',
        namedCurve: this.namedCurve,
      },
      true,
      ['sign'],
    );
  }

  async sign(params: SignParams): Promise<ArrayBuffer> {
    const { privateKey, data, crypto } = params;
    return crypto.subtle.sign(
      {
        name: 'ECDSA',
        hash: 'SHA-256',
      },
      privateKey,
      BufferSourceConverter.toArrayBuffer(data),
    );
  }

  async verify(params: VerifyParams): Promise<boolean> {
    const { publicKey, signature, data, crypto } = params;
    return crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: 'SHA-256',
      },
      publicKey,
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
    return (
      cryptoKey.algorithm.name === 'ECDSA' &&
      (cryptoKey.algorithm as any).namedCurve === this.namedCurve
    );
  }
}

// Create instances for each curve
export const EcdsaP256Binding = new EcdsaBinding('nistp256', 'ecdsa-sha2-nistp256', 'P-256');
export const EcdsaP384Binding = new EcdsaBinding('nistp384', 'ecdsa-sha2-nistp384', 'P-384');
export const EcdsaP521Binding = new EcdsaBinding('nistp521', 'ecdsa-sha2-nistp521', 'P-521');
