import { BufferSourceConverter, Convert } from 'pvtsutils';

import type {
  AlgorithmBinding,
  DecodeSshSignatureParams,
  DecodeSshSignatureResult,
  EncodeSshSignatureParams,
  ExportPrivatePkcs8Params,
  ExportPublicSpkiParams,
  ExportPublicToSshParams,
  ImportPrivatePkcs8Params,
  ImportPublicFromSshParams,
  ImportPublicSpkiParams,
  SignParams,
  VerifyParams,
} from '../registry';
import type { SshSignatureAlgo } from '../types';
import { SshReader } from '../wire/reader';
import { SshWriter } from '../wire/writer';

export class RsaBinding implements AlgorithmBinding {
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
        hash: 'SHA-256',
      },
      true,
      ['verify'],
    );
  }

  async exportPublicToSsh(params: ExportPublicToSshParams): Promise<Uint8Array> {
    const { publicKey, crypto } = params;
    const jwk = await crypto.subtle.exportKey('jwk', publicKey);

    if (!jwk.n || !jwk.e) {
      throw new Error('Invalid JWK');
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
        hash: 'SHA-256',
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
        hash: 'SHA-256',
      },
      true,
      ['sign'],
    );
  }

  async exportPrivatePkcs8(params: ExportPrivatePkcs8Params): Promise<ArrayBuffer> {
    const { privateKey, crypto } = params;
    return crypto.subtle.exportKey('pkcs8', privateKey);
  }

  async sign(params: SignParams): Promise<ArrayBuffer> {
    const { privateKey, data, crypto } = params;
    return crypto.subtle.sign(
      'RSASSA-PKCS1-v1_5',
      privateKey,
      BufferSourceConverter.toArrayBuffer(data),
    );
  }

  async verify(params: VerifyParams): Promise<boolean> {
    const { publicKey, signature, data, crypto } = params;
    return crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
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
    return cryptoKey.algorithm.name === 'RSASSA-PKCS1-v1_5';
  }
}
