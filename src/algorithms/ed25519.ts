import { Convert } from 'pvtsutils';
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
      throw new InvalidKeyDataError(`Ed25519 key length ${keyLength}, expected 32`);
    }
    const publicKeyBytes = reader.readBytes(keyLength);

    // Import to WebCrypto
    return crypto.subtle.importKey('raw', publicKeyBytes as BufferSource, 'Ed25519', true, [
      'verify',
    ]);
  }

  async exportPublicToSsh(params: ExportPublicToSshParams): Promise<Uint8Array> {
    const { publicKey, crypto } = params;

    // Export from WebCrypto to JWK format first, then extract the key
    const jwk = await crypto.subtle.exportKey('jwk', publicKey);
    if (!jwk.x) {
      throw new InvalidKeyDataError('Ed25519 JWK missing x parameter');
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

    return crypto.subtle.importKey('spki', spki as BufferSource, 'Ed25519', true, ['verify']);
  }

  async exportPublicSpki(params: ExportPublicSpkiParams): Promise<ArrayBuffer> {
    const { publicKey, crypto } = params;

    return crypto.subtle.exportKey('spki', publicKey);
  }

  async importPrivatePkcs8(params: ImportPrivatePkcs8Params): Promise<CryptoKey> {
    const { pkcs8, crypto } = params;

    return crypto.subtle.importKey('pkcs8', pkcs8 as BufferSource, 'Ed25519', true, ['sign']);
  }

  async exportPrivatePkcs8(params: ExportPrivatePkcs8Params): Promise<ArrayBuffer> {
    const { privateKey, crypto } = params;

    return crypto.subtle.exportKey('pkcs8', privateKey);
  }

  async exportPrivateToSsh(params: ExportPrivateToSshParams): Promise<Uint8Array> {
    const { privateKey, crypto, jwk: providedJwk } = params;

    // Export private key as JWK to get private scalar
    const jwk = providedJwk || (await crypto.subtle.exportKey('jwk', privateKey));
    if (!jwk.d || !jwk.x) {
      throw new InvalidKeyDataError('Ed25519 private key JWK missing required parameters');
    }

    const privateBytes = new Uint8Array(Convert.FromBase64Url(jwk.d));
    const publicBytes = new Uint8Array(Convert.FromBase64Url(jwk.x));

    // Build the private key section as expected by importPrivateFromSsh
    const writer = new SshWriter();
    writer.writeString('ssh-ed25519');

    // Public key part (32 bytes)
    writer.writeUint32(publicBytes.length);
    writer.writeBytes(publicBytes);

    // Private key part (64 bytes: 32-byte private + 32-byte public)
    const privKeyPart = new Uint8Array(64);
    privKeyPart.set(privateBytes, 0);
    privKeyPart.set(publicBytes, 32);

    writer.writeUint32(privKeyPart.length);
    writer.writeBytes(privKeyPart);

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

    return crypto.subtle.importKey('jwk', jwk, 'Ed25519', true, ['sign']);
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

  parseCertificatePublicKey(reader: SshReader): SshPublicKeyBlob {
    // Read Ed25519 public key from certificate format
    const publicKeyData = reader.readBytes(reader.readUint32()); // 32-byte Ed25519 public key

    // Reconstruct the public key blob in standard SSH format
    const writer = new SshWriter();
    writer.writeString('ssh-ed25519');
    writer.writeUint32(publicKeyData.length);
    writer.writeBytes(publicKeyData);

    return {
      type: 'ssh-ed25519',
      keyData: writer.toUint8Array(),
    };
  }

  writeCertificatePublicKey(writer: SshWriter, publicKey: SshPublicKeyBlob): void {
    // For Ed25519, extract the raw key data (skip type string and length)
    const publicKeyReader = new SshReader(publicKey.keyData);
    publicKeyReader.readString(); // Skip "ssh-ed25519"
    const keyLength = publicKeyReader.readUint32(); // Read length of key data
    const rawKeyData = publicKeyReader.readBytes(keyLength); // Read actual key data
    writer.writeUint32(rawKeyData.length);
    writer.writeBytes(rawKeyData);
  }

  getCertificateType(): string {
    return 'ssh-ed25519-cert-v01@openssh.com';
  }

  getSignatureAlgo(): SshSignatureAlgo {
    return 'ssh-ed25519';
  }
}
