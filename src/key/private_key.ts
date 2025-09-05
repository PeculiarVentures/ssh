import { Convert } from 'pvtsutils';
import { getCrypto } from '../crypto';
import {
  EncryptedKeyNotSupportedError,
  InvalidPrivateKeyFormatError,
  UnsupportedKeyTypeError,
} from '../errors.js';
import { AlgorithmRegistry } from '../registry';
import type { ByteView, SshKeyType } from '../types';
import { SshObject } from '../types';
import { encoder } from '../utils';
import { SshReader } from '../wire/reader';
import { SshWriter } from '../wire/writer';
import { SshPublicKey } from './public_key';

export type SshPrivateKeyExportFormat = 'ssh' | 'pkcs8';

export class SshPrivateKey extends SshObject {
  public static readonly TYPE = 'private-key';
  public readonly type = SshPrivateKey.TYPE;

  private cryptoKey: CryptoKey;
  private publicKey?: SshPublicKey;
  private cachedJwk?: JsonWebKey;
  public readonly keyType: SshKeyType;

  private constructor(cryptoKey: CryptoKey, keyType: SshKeyType, publicKey?: SshPublicKey) {
    super();
    this.cryptoKey = cryptoKey;
    this.keyType = keyType;
    this.publicKey = publicKey;
  }

  /**
   * Get cached JWK
   */
  private async getJwk(crypto: Crypto): Promise<any> {
    if (!this.cachedJwk) {
      this.cachedJwk = await crypto.subtle.exportKey('jwk', this.cryptoKey);
    }
    return this.cachedJwk;
  }

  /**
   * Import from SSH private key string
   */
  static async importPrivateFromSsh(sshKey: string): Promise<SshPrivateKey> {
    // First, determine the key type from the SSH private key
    const keyType = await SshPrivateKey.detectSshKeyType(sshKey);

    // Get the appropriate binding
    const binding = AlgorithmRegistry.get(keyType);

    // Import using the specific binding
    const cryptoKey = await binding.importPrivateFromSsh({ sshKey, crypto: getCrypto() });
    return new SshPrivateKey(cryptoKey, keyType as SshKeyType);
  }

  /**
   * Detect SSH key type from OpenSSH private key format
   */
  /**
   * Detects the SSH key type from an OpenSSH private key
   * @param sshKey OpenSSH private key string
   * @returns SSH key type (e.g., 'ssh-ed25519', 'ssh-rsa', etc.)
   * @throws {InvalidPrivateKeyFormatError} When key format is invalid
   * @throws {UnexpectedEOFError} When key data is truncated
   */
  private static async detectSshKeyType(sshKey: string): Promise<string> {
    // Parse the OpenSSH private key to extract the key type
    // OpenSSH private key format:
    // - BEGIN/END markers
    // - Base64-encoded binary data containing key material

    const base64Data = sshKey
      .replace(/-----BEGIN OPENSSH PRIVATE KEY-----/, '')
      .replace(/-----END OPENSSH PRIVATE KEY-----/, '')
      .replace(/\s/g, '');

    let binaryData: Uint8Array;
    try {
      binaryData = new Uint8Array(Convert.FromBase64(base64Data));
    } catch {
      throw new InvalidPrivateKeyFormatError('Invalid base64 encoding');
    }

    const reader = new SshReader(binaryData);

    // Check magic string "openssh-key-v1\0"
    const magic = reader.readBytes(15);
    const expectedMagic = '6f70656e7373682d6b65792d763100';
    if (Convert.ToHex(magic) !== expectedMagic) {
      throw new InvalidPrivateKeyFormatError(
        `Invalid magic bytes. Expected: ${expectedMagic}, got: ${Convert.ToHex(magic)}`,
      );
    }

    // Read OpenSSH private key structure:
    const cipher = reader.readString(); // cipher name
    const _kdf = reader.readString(); // kdf name
    reader.readString(); // kdf options (skip)

    // Check if key is encrypted (not supported)
    if (cipher !== 'none') {
      throw new EncryptedKeyNotSupportedError(cipher);
    }

    // Read number of keys (should be 1)
    const keyCount = reader.readUint32();
    if (keyCount !== 1) {
      throw new InvalidPrivateKeyFormatError(`Expected 1 key, found ${keyCount}`);
    }

    // Read public key data to determine key type
    const publicKeyLength = reader.readUint32();
    const publicKeyData = reader.readBytes(publicKeyLength);
    const publicReader = new SshReader(publicKeyData);

    // First field in public key data is the key type
    return publicReader.readString();
  }

  /**
   * Import from PKCS#8 format
   */
  static async importPrivatePkcs8(
    pkcs8: ByteView,
    type: SshKeyType,
    crypto = getCrypto(),
  ): Promise<SshPrivateKey> {
    const binding = AlgorithmRegistry.get(type);

    const cryptoKey = await binding.importPrivatePkcs8({ pkcs8, crypto });
    return new SshPrivateKey(cryptoKey, type);
  }

  /**
   * Create from WebCrypto CryptoKey
   */
  static async fromWebCrypto(cryptoKey: CryptoKey, type?: SshKeyType): Promise<SshPrivateKey> {
    // Auto-detect SSH key type from CryptoKey if not provided
    const sshType = type || (AlgorithmRegistry.getSshTypeFromCryptoKey(cryptoKey) as SshKeyType);
    return new SshPrivateKey(cryptoKey, sshType);
  }

  /**
   * Export private key
   */
  async export(
    format: SshPrivateKeyExportFormat = 'ssh',
    crypto = getCrypto(),
  ): Promise<string | Uint8Array> {
    if (format === 'ssh') {
      const binding = AlgorithmRegistry.get(this.keyType);

      if (!binding.exportPrivateToSsh) {
        throw new UnsupportedKeyTypeError(`SSH export not supported for ${this.keyType}`);
      }

      // Export public key blob for the outer structure using cached public key
      const publicKey = await this.exportPublicKey(crypto);
      const publicBlob = publicKey.getBlob().keyData;

      // Get cached JWK for optimization
      const jwk = await this.getJwk(crypto);

      // Export algorithm-specific private data
      const privateData = await binding.exportPrivateToSsh({
        privateKey: this.cryptoKey,
        crypto,
        jwk,
      });

      // Build the complete OpenSSH private key structure
      const writer = new SshWriter();

      // Magic string "openssh-key-v1\0"
      writer.writeBytes(encoder.encode('openssh-key-v1\0'));

      // Cipher, KDF, KDF options (unencrypted)
      writer.writeString('none');
      writer.writeString('none');
      writer.writeString('');

      // Number of keys
      writer.writeUint32(1);

      // Public key
      writer.writeUint32(publicBlob.length);
      writer.writeBytes(publicBlob);

      // Private section
      const privateSectionWriter = new SshWriter();

      // Checkints (two identical random values)
      const checkint = Math.floor(Math.random() * 0xffffffff) >>> 0;
      privateSectionWriter.writeUint32(checkint);
      privateSectionWriter.writeUint32(checkint);

      // Algorithm-specific private data
      privateSectionWriter.writeBytes(privateData);

      // Comment (empty)
      privateSectionWriter.writeString('');

      // Padding to make total length multiple of 8
      const privData = privateSectionWriter.toUint8Array();
      const blockSize = 8;
      const padLen = blockSize - (privData.length % blockSize);
      if (padLen < blockSize) {
        for (let i = 1; i <= padLen; i++) {
          privateSectionWriter.writeUint8(i);
        }
      }

      const finalPrivData = privateSectionWriter.toUint8Array();
      writer.writeUint32(finalPrivData.length);
      writer.writeBytes(finalPrivData);

      // Encode as base64 and wrap in PEM
      const keyData = writer.toUint8Array();
      const base64 = Convert.ToBase64(keyData);

      // Split into 70-character lines
      const lines = [];
      for (let i = 0; i < base64.length; i += 70) {
        lines.push(base64.slice(i, i + 70));
      }

      return `-----BEGIN OPENSSH PRIVATE KEY-----\n${lines.join('\n')}\n-----END OPENSSH PRIVATE KEY-----`;
    } else if (format === 'pkcs8') {
      const binding = AlgorithmRegistry.get(this.keyType);
      const pkcs8 = await binding.exportPrivatePkcs8({ privateKey: this.cryptoKey, crypto });
      return new Uint8Array(pkcs8);
    }
    throw new UnsupportedKeyTypeError(`Unsupported export format: ${format}`);
  }

  /**
   * Export to SSH format (convenience method).
   * Returns a base64-encoded string in OpenSSH private key format
   * (e.g., "-----BEGIN OPENSSH PRIVATE KEY-----\n...").
   */
  async toSSH(): Promise<string> {
    const result = await this.export('ssh');
    return result as string;
  }

  /**
   * Export to PKCS#8 format (convenience method).
   * Returns binary DER-encoded PKCS#8 data as Uint8Array.
   */
  async toPKCS8(): Promise<Uint8Array> {
    const result = await this.export('pkcs8');
    return result as Uint8Array;
  }

  /**
   * Get WebCrypto key (convenience method)
   */
  toWebCrypto(): CryptoKey {
    return this.cryptoKey;
  }

  /**
   * Export to PKCS#8
   */
  async exportPrivatePkcs8(): Promise<Uint8Array> {
    return this.toPKCS8();
  }

  /**
   * Get public key (convenience method)
   */
  async getPublicKey(crypto = getCrypto()): Promise<SshPublicKey> {
    return this.exportPublicKey(crypto);
  }

  /**
   * Sign data and return raw signature
   */
  async sign(algo: string, data: ByteView, crypto = getCrypto()): Promise<Uint8Array> {
    const binding = AlgorithmRegistry.get(algo);

    const signature = await binding.sign({ privateKey: this.cryptoKey, data, crypto });
    return new Uint8Array(signature);
  }

  /**
   * Get public key
   */
  async exportPublicKey(crypto = getCrypto()): Promise<SshPublicKey> {
    if (this.publicKey) {
      return this.publicKey;
    }

    const binding = AlgorithmRegistry.get(this.keyType);

    const exported = await binding.exportPublicToSsh({ publicKey: this.cryptoKey, crypto });
    const blob = {
      type: this.keyType,
      keyData: exported,
    };

    this.publicKey = new SshPublicKey(blob);
    return this.publicKey;
  }
}
