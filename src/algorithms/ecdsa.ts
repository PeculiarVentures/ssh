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

export class EcdsaBinding implements AlgorithmBinding {
  private curveName: string;
  private sshType: string;
  private namedCurve: string;

  constructor(curveName: string, sshType: string, namedCurve: string) {
    this.curveName = curveName;
    this.sshType = sshType;
    this.namedCurve = namedCurve;
  }

  /**
   * Get the hash algorithm for this ECDSA curve
   */
  private getHashAlgorithm(): 'SHA-256' | 'SHA-384' | 'SHA-512' {
    switch (this.namedCurve) {
      case 'P-256':
        return 'SHA-256';
      case 'P-384':
        return 'SHA-384';
      case 'P-521':
        return 'SHA-512';
      default:
        return 'SHA-256'; // fallback
    }
  }

  /**
   * Get the expected coordinate length for this ECDSA curve
   */
  private getExpectedLength(): number {
    switch (this.namedCurve) {
      case 'P-256':
        return 32;
      case 'P-384':
        return 48;
      case 'P-521':
        return 66;
      default:
        return 32; // fallback
    }
  }

  /**
   * Get the expected signature coordinate length (r or s) for this ECDSA curve
   */
  private getSignatureCoordLength(): number {
    return this.getExpectedLength();
  }

  async importPublicSsh(params: ImportPublicFromSshParams): Promise<CryptoKey> {
    const { blob, crypto } = params;
    const reader = new SshReader(blob);

    // Skip type (already verified in parsePublicKey)
    reader.readString();

    // Read curve name
    const curve = reader.readString();
    if (curve !== this.curveName) {
      throw new InvalidKeyDataError(`ECDSA curve name ${curve}, expected ${this.curveName}`);
    }

    // Read Q (public key as mpint)
    const q = reader.readMpInt();

    // Convert to JWK format
    // Calculate coordinate length based on curve (similar to importPrivateFromSsh)
    const coordLength = Math.floor((q.length - 1) / 2);
    const jwk = {
      kty: 'EC' as const,
      crv: this.namedCurve,
      x: Convert.ToBase64Url(q.slice(1, 1 + coordLength)), // x coordinate
      y: Convert.ToBase64Url(q.slice(1 + coordLength)), // y coordinate
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

  async exportPublicSsh(params: ExportPublicToSshParams): Promise<Uint8Array> {
    const { publicKey, crypto } = params;
    const jwk = await crypto.subtle.exportKey('jwk', publicKey);

    if (!jwk.x || !jwk.y) {
      throw new InvalidKeyDataError('ECDSA JWK missing x or y parameters');
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

  async exportPublicSpki(params: ExportPublicSpkiParams): Promise<Uint8Array> {
    const { publicKey, crypto } = params;
    const spki = await crypto.subtle.exportKey('spki', publicKey);
    return BufferSourceConverter.toUint8Array(spki);
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

  async exportPrivatePkcs8(params: ExportPrivatePkcs8Params): Promise<Uint8Array> {
    const { privateKey, crypto } = params;
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', privateKey);
    return BufferSourceConverter.toUint8Array(pkcs8);
  }

  async exportPrivateSsh(params: ExportPrivateToSshParams): Promise<Uint8Array> {
    const { privateKey, crypto, jwk: providedJwk } = params;

    // Export private key to JWK to get all parameters
    const jwk = providedJwk || (await crypto.subtle.exportKey('jwk', privateKey));
    if (!jwk.d || !jwk.x || !jwk.y) {
      throw new InvalidKeyDataError('ECDSA private key JWK missing required parameters');
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

  async importPrivateSsh(params: ImportPrivateFromSshParams): Promise<CryptoKey> {
    const { sshKey, crypto } = params;

    // Remove PEM headers and decode base64
    const base64Data = sshKey
      .replace(/-----BEGIN OPENSSH PRIVATE KEY-----/, '')
      .replace(/-----END OPENSSH PRIVATE KEY-----/, '')
      .replace(/\s/g, '');

    const binaryData = Convert.FromBase64(base64Data);
    const reader = new SshReader(BufferSourceConverter.toUint8Array(binaryData));

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
      throw new InvalidPrivateKeyFormatError('invalid checkints');
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
      throw new InvalidKeyDataError('invalid ECDSA public key point format');
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

  async sign(params: SignParams): Promise<Uint8Array> {
    const { privateKey, data, crypto, hash } = params;

    // Get the correct hash algorithm for this curve
    const expectedHash = this.getHashAlgorithm();

    // Validate hash parameter if provided
    if (hash && hash !== expectedHash) {
      throw new InvalidKeyDataError(
        `ECDSA ${this.namedCurve} requires ${expectedHash}, got ${hash}`,
      );
    }

    const signature = await crypto.subtle.sign(
      {
        name: 'ECDSA',
        hash: expectedHash,
      },
      privateKey,
      BufferSourceConverter.toArrayBuffer(data),
    );
    return BufferSourceConverter.toUint8Array(signature);
  }

  async verify(params: VerifyParams): Promise<boolean> {
    const { publicKey, signature, data, crypto, hash } = params;

    // Get the correct hash algorithm for this curve
    const expectedHash = this.getHashAlgorithm();

    // Validate hash parameter if provided
    if (hash && hash !== expectedHash) {
      throw new InvalidKeyDataError(
        `ECDSA ${this.namedCurve} requires ${expectedHash}, got ${hash}`,
      );
    }

    return crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: expectedHash,
      },
      publicKey,
      BufferSourceConverter.toArrayBuffer(signature),
      BufferSourceConverter.toArrayBuffer(data),
    );
  }

  encodeSignature(params: EncodeSshSignatureParams): Uint8Array {
    const { signature, algo } = params;

    // For ECDSA, convert from raw format to SSH format (r+s)
    if (algo.startsWith('ecdsa-sha2-')) {
      // Split concatenated r+s back into components
      const coordLength = this.getSignatureCoordLength();
      const r = signature.subarray(0, coordLength);
      const s = signature.subarray(coordLength);

      const writer = new SshWriter();
      writer.writeString(algo);

      const sigWriter = new SshWriter();
      sigWriter.writeMpInt(r, true);
      sigWriter.writeMpInt(s, true);
      const sigData = sigWriter.toUint8Array();

      writer.writeUint32(sigData.length);
      writer.writeBytes(sigData);
      return writer.toUint8Array();
    }

    // For other algorithms, use default encoding
    const writer = new SshWriter();
    writer.writeString(algo);
    writer.writeUint32(signature.byteLength);
    writer.writeBytes(signature);
    return writer.toUint8Array();
  }

  decodeSignature(params: DecodeSshSignatureParams): DecodeSshSignatureResult {
    const { signature } = params;
    const reader = new SshReader(signature);
    const algo = reader.readString() as SshSignatureAlgo;
    const sigLength = reader.readUint32();
    const sig = reader.readBytes(sigLength);

    // For ECDSA, convert from SSH format (r+s) to raw format for WebCrypto
    if (algo.startsWith('ecdsa-sha2-')) {
      const sigReader = new SshReader(sig);
      let r = sigReader.readMpInt();
      let s = sigReader.readMpInt();

      // Remove leading zero bytes if present (SSH encoding may add them)
      if (r[0] === 0x00 && r.length > 1 && (r[1] & 0x80) === 0) {
        r = r.slice(1);
      }
      if (s[0] === 0x00 && s.length > 1 && (s[1] & 0x80) === 0) {
        s = s.slice(1);
      }

      // Ensure we have the correct length for the curve
      const expectedLength = this.getExpectedLength();

      // Pad with leading zeros if needed
      const rPadded = new Uint8Array(expectedLength);
      const sPadded = new Uint8Array(expectedLength);
      if (r.length <= expectedLength) {
        rPadded.set(r, expectedLength - r.length);
      } else {
        rPadded.set(r.slice(r.length - expectedLength), 0);
      }
      if (s.length <= expectedLength) {
        sPadded.set(s, expectedLength - s.length);
      } else {
        sPadded.set(s.slice(s.length - expectedLength), 0);
      }

      // Concatenate r and s (like ssh-sig does)
      const rawSignature = new Uint8Array([...rPadded, ...sPadded]);
      return { signature: rawSignature, algo };
    }

    return { signature: sig, algo };
  }

  supportsCryptoKey(cryptoKey: CryptoKey): boolean {
    return (
      cryptoKey.algorithm.name === 'ECDSA' &&
      (cryptoKey.algorithm as any).namedCurve === this.namedCurve
    );
  }

  parsePublicKey(reader: SshReader): SshPublicKeyBlob {
    // Read ECDSA public key from certificate format
    const curveName = reader.readString();
    if (curveName !== this.curveName) {
      throw new InvalidKeyDataError(
        `ECDSA certificate curve name ${curveName}, expected ${this.curveName}`,
      );
    }
    const publicKeyPoint = reader.readBytes(reader.readUint32()); // ECDSA point

    // Reconstruct the public key blob in standard SSH format
    const writer = new SshWriter();
    writer.writeString(this.sshType);
    writer.writeString(curveName);
    writer.writeMpInt(publicKeyPoint);

    return {
      type: this.sshType as any,
      keyData: writer.toUint8Array(),
    };
  }

  writePublicKey(writer: SshWriter, publicKey: SshPublicKeyBlob): void {
    // For ECDSA, extract curve name and public point
    const publicKeyReader = new SshReader(publicKey.keyData);
    publicKeyReader.readString(); // Skip "ecdsa-sha2-nistp256" etc.
    const curveName = publicKeyReader.readString();
    const publicPoint = publicKeyReader.readMpInt();
    writer.writeString(curveName);
    writer.writeUint32(publicPoint.length);
    writer.writeBytes(publicPoint);
  }

  getCertificateType(): string {
    return `${this.sshType}-cert-v01@openssh.com`;
  }

  getSignatureAlgo(): SshSignatureAlgo {
    return this.sshType as SshSignatureAlgo;
  }
}

// Create instances for each curve
export const EcdsaP256Binding = new EcdsaBinding('nistp256', 'ecdsa-sha2-nistp256', 'P-256');
export const EcdsaP384Binding = new EcdsaBinding('nistp384', 'ecdsa-sha2-nistp384', 'P-384');
export const EcdsaP521Binding = new EcdsaBinding('nistp521', 'ecdsa-sha2-nistp521', 'P-521');
