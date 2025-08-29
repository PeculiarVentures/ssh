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

export class Ed25519Binding implements AlgorithmBinding {
  async importPublicFromSsh(params: ImportPublicFromSshParams): Promise<CryptoKey> {
    const { blob, crypto } = params;
    const reader = new SshReader(blob);

    // Skip type (already validated at higher level)
    reader.readString();

    // Read Ed25519 public key using proper SSH format:
    // uint32 length + byte[length] key_data
    const keyLength = reader.readUint32();
    if (keyLength !== 32) {
      throw new Error(`Invalid Ed25519 key length: ${keyLength}, expected 32`);
    }
    const publicKeyBytes = reader.readBytes(keyLength);

    // Import to WebCrypto
    return crypto.subtle.importKey(
      'raw',
      publicKeyBytes as any,
      {
        name: 'Ed25519',
        namedCurve: 'Ed25519',
      },
      true,
      ['verify'],
    );
  }

  async exportPublicToSsh(params: ExportPublicToSshParams): Promise<Uint8Array> {
    const { publicKey, crypto } = params;

    // Export from WebCrypto to raw format
    const rawKey = await crypto.subtle.exportKey('raw', publicKey);

    // Create SSH format: type + length + key_data
    const writer = new SshWriter();
    writer.writeString('ssh-ed25519');
    writer.writeUint32(rawKey.byteLength);
    writer.writeBytes(new Uint8Array(rawKey));

    return writer.toUint8Array();
  }

  async importPublicSpki(params: ImportPublicSpkiParams): Promise<CryptoKey> {
    const { spki, crypto } = params;

    return crypto.subtle.importKey(
      'spki',
      spki as any,
      {
        name: 'Ed25519',
        namedCurve: 'Ed25519',
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
      pkcs8 as any,
      {
        name: 'Ed25519',
        namedCurve: 'Ed25519',
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

    return crypto.subtle.sign('Ed25519', privateKey, data as any);
  }

  async verify(params: VerifyParams): Promise<boolean> {
    const { publicKey, signature, data, crypto } = params;

    return crypto.subtle.verify('Ed25519', publicKey, signature as any, data as any);
  }

  encodeSshSignature(params: EncodeSshSignatureParams): Uint8Array {
    const { signature, algo } = params;

    const sigBytes = new Uint8Array(signature);
    const writer = new SshWriter();
    writer.writeString(algo);
    writer.writeUint32(sigBytes.length);
    writer.writeBytes(sigBytes);
    return writer.toUint8Array();
  }

  decodeSshSignature(params: DecodeSshSignatureParams): DecodeSshSignatureResult {
    const { signature } = params;

    const reader = new SshReader(signature);
    const algo = reader.readString() as SshSignatureAlgo;
    // Read the length field and then the actual signature
    const sigLength = reader.readUint32();
    const sigBytes = reader.readBytes(sigLength);

    return {
      signature: sigBytes,
      algo,
    };
  }

  supportsCryptoKey(cryptoKey: CryptoKey): boolean {
    return cryptoKey.algorithm.name === 'Ed25519';
  }
}
