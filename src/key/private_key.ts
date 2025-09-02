import { Convert } from 'pvtsutils';
import { getCrypto } from '../crypto';
import { AlgorithmRegistry } from '../registry';
import type { ByteView, SshKeyType } from '../types';
import { SshReader } from '../wire/reader';
import { SshPublicKey } from './public_key';

/**
 * Auto-detect SSH key type from WebCrypto CryptoKey
 */
function getSshKeyTypeFromCryptoKey(cryptoKey: CryptoKey): SshKeyType {
  const sshType = AlgorithmRegistry.getSshTypeFromCryptoKey(cryptoKey);
  if (!sshType) {
    throw new Error(`Unsupported algorithm: ${(cryptoKey.algorithm as any).name}`);
  }
  return sshType as SshKeyType;
}

export type SshPrivateKeyExportFormat = 'ssh' | 'pkcs8';

export class SshPrivateKey {
  private cryptoKey: CryptoKey;
  private type: SshKeyType;
  private publicKey?: SshPublicKey;

  private constructor(cryptoKey: CryptoKey, type: SshKeyType, publicKey?: SshPublicKey) {
    this.cryptoKey = cryptoKey;
    this.type = type;
    this.publicKey = publicKey;
  }

  /**
   * Import from SSH private key string
   */
  static async importPrivateFromSsh(sshKey: string): Promise<SshPrivateKey> {
    // First, determine the key type from the SSH private key
    const keyType = await SshPrivateKey.detectSshKeyType(sshKey);

    // Get the appropriate binding
    const binding = AlgorithmRegistry.get(keyType);
    if (!binding) {
      throw new Error(`Unsupported SSH key type: ${keyType}`);
    }

    // Import using the specific binding
    const cryptoKey = await binding.importPrivateFromSsh({ sshKey, crypto: getCrypto() });
    return new SshPrivateKey(cryptoKey, keyType as SshKeyType);
  }

  /**
   * Detect SSH key type from OpenSSH private key format
   */
  private static async detectSshKeyType(sshKey: string): Promise<string> {
    // Parse the OpenSSH private key to extract the key type
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

    // Skip cipher, kdf, options
    reader.readString(); // cipher
    reader.readString(); // kdf
    reader.readString(); // options

    // Skip number of keys
    reader.readUint32();

    // Read public key to determine type
    const publicKeyLength = reader.readUint32();
    const publicKeyData = reader.readBytes(publicKeyLength);
    const publicReader = new SshReader(publicKeyData);

    return publicReader.readString(); // This is the key type
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
    if (!binding) {
      throw new Error(`Unsupported key type: ${type}`);
    }

    const cryptoKey = await binding.importPrivatePkcs8({ pkcs8, crypto });
    return new SshPrivateKey(cryptoKey, type);
  }

  /**
   * Create from WebCrypto CryptoKey
   */
  static async fromWebCrypto(cryptoKey: CryptoKey, type?: SshKeyType): Promise<SshPrivateKey> {
    // Auto-detect SSH key type from CryptoKey if not provided
    const sshType = type || getSshKeyTypeFromCryptoKey(cryptoKey);
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
      // Placeholder: export to SSH private key format
      throw new Error('Not implemented: export to SSH format');
    } else if (format === 'pkcs8') {
      const binding = AlgorithmRegistry.get(this.type);
      if (!binding) {
        throw new Error(`Unsupported key type: ${this.type}`);
      }
      const pkcs8 = await binding.exportPrivatePkcs8({ privateKey: this.cryptoKey, crypto });
      return new Uint8Array(pkcs8);
    }
    throw new Error(`Unsupported export format: ${format}`);
  }

  /**
   * Export to PKCS#8
   */
  async exportPrivatePkcs8(): Promise<Uint8Array> {
    const result = await this.export('pkcs8');
    return result as Uint8Array;
  }

  /**
   * Sign data and return SSH signature
   */
  async sign(data: ByteView, algo?: string, crypto = getCrypto()): Promise<string> {
    const binding = AlgorithmRegistry.get(this.type);
    if (!binding) {
      throw new Error(`Unsupported key type: ${this.type}`);
    }

    const signature = await binding.sign({ privateKey: this.cryptoKey, data, crypto });
    const sshAlgo = algo || this.type; // Default to key type
    const encoded = binding.encodeSshSignature({ signature, algo: sshAlgo as any });
    return Convert.ToBase64(encoded);
  }

  /**
   * Get public key
   */
  async exportPublicKey(crypto = getCrypto()): Promise<SshPublicKey> {
    if (this.publicKey) {
      return this.publicKey;
    }

    const binding = AlgorithmRegistry.get(this.type);
    if (!binding) {
      throw new Error(`Unsupported key type: ${this.type}`);
    }

    const exported = await binding.exportPublicToSsh({ publicKey: this.cryptoKey, crypto });
    const blob = {
      type: this.type,
      keyData: exported,
    };

    this.publicKey = new SshPublicKey(blob);
    return this.publicKey;
  }

  /**
   * Get key type
   */
  get keyType(): SshKeyType {
    return this.type;
  }
}
