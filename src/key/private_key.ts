import { getCrypto } from '../crypto';
import { AlgorithmRegistry } from '../registry';
import type { ByteView, SshKeyType } from '../types';
import { SshPublicKey } from './public_key';

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
  static async importPrivateFromSsh(_sshKey: string): Promise<SshPrivateKey> {
    // Placeholder: parse SSH private key format
    throw new Error('Not implemented: importPrivateFromSsh');
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
  static async fromWebCrypto(cryptoKey: CryptoKey, type: SshKeyType): Promise<SshPrivateKey> {
    return new SshPrivateKey(cryptoKey, type);
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
    return btoa(String.fromCharCode(...encoded));
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
