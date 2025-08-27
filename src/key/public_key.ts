import { getCrypto } from '../crypto';
import { AlgorithmRegistry } from '../registry';
import type { ByteView, SshKeyType } from '../types';
import {
  parsePublicKey as parseWirePublicKey,
  serializePublicKey as serializeWirePublicKey,
  type SshPublicKeyBlob,
} from '../wire/public_key';

export type SshPublicKeyExportFormat = 'ssh' | 'spki';

export class SshPublicKey {
  private blob: SshPublicKeyBlob;
  private cryptoKey?: CryptoKey;

  constructor(blob: SshPublicKeyBlob, cryptoKey?: CryptoKey) {
    this.blob = blob;
    this.cryptoKey = cryptoKey;
  }

  /**
   * Import from SSH public key string
   */
  static async importPublicFromSsh(sshKey: string, crypto = getCrypto()): Promise<SshPublicKey> {
    const blob = parseWirePublicKey(sshKey);
    const binding = AlgorithmRegistry.get(blob.type);
    if (!binding) {
      throw new Error(`Unsupported key type: ${blob.type}`);
    }

    const cryptoKey = await binding.importPublicFromSsh({ blob: blob.keyData, crypto });
    return new SshPublicKey(blob, cryptoKey);
  }

  /**
   * Import from SPKI format
   */
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

    return new SshPublicKey(blob, cryptoKey);
  }

  /**
   * Create from WebCrypto CryptoKey
   */
  static async fromWebCrypto(
    cryptoKey: CryptoKey,
    type: SshKeyType,
    crypto = getCrypto(),
  ): Promise<SshPublicKey> {
    const binding = AlgorithmRegistry.get(type);
    if (!binding) {
      throw new Error(`Unsupported key type: ${type}`);
    }

    const exported = await binding.exportPublicToSsh({ publicKey: cryptoKey, crypto });
    const blob: SshPublicKeyBlob = {
      type,
      keyData: exported,
    };

    return new SshPublicKey(blob, cryptoKey);
  }

  /**
   * Export public key
   */
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
      const cryptoKey =
        this.cryptoKey || (await binding.importPublicFromSsh({ blob: this.blob.keyData, crypto }));
      const spki = await binding.exportPublicSpki({ publicKey: cryptoKey, crypto });
      return new Uint8Array(spki);
    }
    throw new Error(`Unsupported export format: ${format}`);
  }

  /**
   * Export to SPKI
   */
  async exportPublicSpki(): Promise<Uint8Array> {
    const result = await this.export('spki');
    return result as Uint8Array;
  }

  /**
   * Verify signature in SSH format
   */
  async verify(data: ByteView, signature: string, crypto = getCrypto()): Promise<boolean> {
    const binding = AlgorithmRegistry.get(this.blob.type);
    if (!binding) {
      throw new Error(`Unsupported key type: ${this.blob.type}`);
    }
    const cryptoKey =
      this.cryptoKey || (await binding.importPublicFromSsh({ blob: this.blob.keyData, crypto }));

    const sigBytes = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
    const decoded = binding.decodeSshSignature({ signature: sigBytes });
    return await binding.verify({
      publicKey: cryptoKey,
      signature: decoded.signature,
      data,
      crypto,
    });
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
