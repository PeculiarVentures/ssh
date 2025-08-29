import { getCrypto } from '../crypto';
import { AlgorithmRegistry } from '../registry';
import type { ByteView, SshKeyType } from '../types';
import {
  parsePublicKey as parseWirePublicKey,
  serializePublicKey as serializeWirePublicKey,
  type SshPublicKeyBlob,
} from '../wire/public_key';

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

export type SshPublicKeyExportFormat = 'ssh' | 'spki';

export class SshPublicKey {
  private blob: SshPublicKeyBlob;

  constructor(blob: SshPublicKeyBlob) {
    this.blob = blob;
  }

  static async importPublicFromSsh(sshKey: string, crypto = getCrypto()): Promise<SshPublicKey> {
    const blob = parseWirePublicKey(sshKey);
    const binding = AlgorithmRegistry.get(blob.type);
    if (!binding) {
      throw new Error(`Unsupported key type: ${blob.type}`);
    }

    // Validate that the key can be imported (but don't store CryptoKey)
    await binding.importPublicFromSsh({ blob: blob.keyData, crypto });
    return new SshPublicKey(blob);
  }

  static async importPublicSpki(
    spki: ByteView,
    type: SshKeyType,
    crypto = getCrypto(),
  ): Promise<SshPublicKey> {
    const binding = AlgorithmRegistry.get(type);
    if (!binding) {
      throw new Error(`Unsupported key type: ${type}`);
    }

    const cryptoKey = await binding.importPublicSpki({ spki, crypto });
    const exported = await binding.exportPublicToSsh({ publicKey: cryptoKey, crypto });
    const blob: SshPublicKeyBlob = {
      type,
      keyData: exported,
    };

    return new SshPublicKey(blob);
  }

  static async fromWebCrypto(
    cryptoKey: CryptoKey,
    type?: SshKeyType,
    crypto = getCrypto(),
  ): Promise<SshPublicKey> {
    // Auto-detect SSH key type from CryptoKey if not provided
    const sshType = type || getSshKeyTypeFromCryptoKey(cryptoKey);

    const binding = AlgorithmRegistry.get(sshType);
    if (!binding) {
      throw new Error(`Unsupported key type: ${sshType}`);
    }

    const exported = await binding.exportPublicToSsh({ publicKey: cryptoKey, crypto });
    const blob: SshPublicKeyBlob = {
      type: sshType,
      keyData: exported,
    };

    return new SshPublicKey(blob);
  }

  async export(
    format: SshPublicKeyExportFormat = 'ssh',
    crypto = getCrypto(),
  ): Promise<string | Uint8Array> {
    if (format === 'ssh') {
      return serializeWirePublicKey(this.blob);
    } else if (format === 'spki') {
      const binding = AlgorithmRegistry.get(this.blob.type);
      if (!binding) {
        throw new Error(`Unsupported key type: ${this.blob.type}`);
      }
      const cryptoKey = await binding.importPublicFromSsh({ blob: this.blob.keyData, crypto });
      const spki = await binding.exportPublicSpki({ publicKey: cryptoKey, crypto });
      return new Uint8Array(spki);
    }
    throw new Error(`Unsupported export format: ${format}`);
  }

  /**
   * Export to SPKI
   */
  async exportPublicSpki(crypto = getCrypto()): Promise<Uint8Array> {
    const result = await this.export('spki', crypto);
    return result as Uint8Array;
  }

  /**
   * Convert to WebCrypto CryptoKey for cryptographic operations
   */
  async toCryptoKey(crypto = getCrypto()): Promise<CryptoKey> {
    const binding = AlgorithmRegistry.get(this.blob.type);
    if (!binding) {
      throw new Error(`Unsupported key type: ${this.blob.type}`);
    }
    return binding.importPublicFromSsh({ blob: this.blob.keyData, crypto });
  }

  /**
   * Get key type
   */
  get type(): SshKeyType {
    return this.blob.type;
  }

  /**
   * Get comment
   */
  get comment(): string | undefined {
    return this.blob.comment;
  }

  /**
   * Get blob
   */
  getBlob(): SshPublicKeyBlob {
    return { ...this.blob };
  }
}
