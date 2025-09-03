import { Convert } from 'pvtsutils';
import type {
  AlgorithmBinding,
  DecodeSshSignatureParams,
  DecodeSshSignatureResult,
  EncodeSshSignatureParams,
  ExportPrivatePkcs8Params,
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

    // Export from WebCrypto to JWK format first, then extract the key
    const jwk = await crypto.subtle.exportKey('jwk', publicKey);
    if (!jwk.x) {
      throw new Error('Invalid Ed25519 JWK');
    }

    // Convert base64url to bytes
    const keyBytes = new Uint8Array(Convert.FromBase64Url(jwk.x));

    // Create SSH format: type + length + key_data
    const writer = new SshWriter();
    writer.writeString('ssh-ed25519');
    writer.writeUint32(keyBytes.length);
    writer.writeBytes(keyBytes);

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

    // Read public key (32 bytes) - this is a length-prefixed field
    const pubKeyLength = privateReader.readUint32();
    const _publicKeyBytes = privateReader.readBytes(pubKeyLength);

    // Read private key + public key - this is a length-prefixed field
    const privKeyLength = privateReader.readUint32();
    const privateKeyBytes = privateReader.readBytes(privKeyLength);

    // Skip comment
    privateReader.readString();

    // Use only the first 32 bytes (private key part)
    const privateKey = privateKeyBytes.slice(0, 32);

    // Create JWK format for Ed25519
    const jwk = {
      kty: 'OKP' as const,
      crv: 'Ed25519',
      d: Convert.ToBase64Url(privateKey),
      x: Convert.ToBase64Url(_publicKeyBytes),
    };

    return crypto.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'Ed25519',
        namedCurve: 'Ed25519',
      },
      true,
      ['sign'],
    );
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
