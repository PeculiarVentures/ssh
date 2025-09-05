import { getCrypto } from '../crypto';
import { UnsupportedKeyTypeError } from '../errors';
import { AlgorithmRegistry } from '../registry';
import type { ByteView, SshKeyType } from '../types';
import { SshObject } from '../types';
import {
  parsePublicKey as parseWirePublicKey,
  serializePublicKey as serializeWirePublicKey,
  type SshPublicKeyBlob,
} from '../wire/public_key';

export type SshPublicKeyExportFormat = 'ssh' | 'spki';

export class SshPublicKey extends SshObject {
  public static readonly TYPE = 'public-key';
  public readonly type = SshPublicKey.TYPE;

  private blob: SshPublicKeyBlob;
  private cachedCryptoKey?: CryptoKey;

  constructor(blob: SshPublicKeyBlob) {
    super();
    this.blob = blob;
  }

  /**
   * Get cached CryptoKey
   */
  private async getCryptoKey(crypto = getCrypto()): Promise<CryptoKey> {
    if (!this.cachedCryptoKey) {
      const binding = AlgorithmRegistry.get(this.blob.type);

      this.cachedCryptoKey = await binding.importPublicFromSsh({ blob: this.blob.keyData, crypto });
    }
    return this.cachedCryptoKey;
  }

  static async importPublicFromSsh(sshKey: string, crypto = getCrypto()): Promise<SshPublicKey> {
    const blob = parseWirePublicKey(sshKey);
    const binding = AlgorithmRegistry.get(blob.type);

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
    const sshType = type || (AlgorithmRegistry.getSshTypeFromCryptoKey(cryptoKey) as SshKeyType);

    const binding = AlgorithmRegistry.get(sshType);

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
      const cryptoKey = await this.getCryptoKey(crypto);
      const binding = AlgorithmRegistry.get(this.blob.type);
      const spki = await binding.exportPublicSpki({ publicKey: cryptoKey, crypto });
      return new Uint8Array(spki);
    }
    throw new UnsupportedKeyTypeError(`Unsupported export format: ${format}`);
  }

  /**
   * Export to SSH format (convenience method).
   * Returns a base64-encoded string in SSH public key format
   * (e.g., "ssh-rsa AAAAB3NzaC1yc2E...").
   */
  async toSSH(): Promise<string> {
    const result = await this.export('ssh');
    return result as string;
  }

  /**
   * Export to SPKI format (convenience method).
   * Returns binary DER-encoded SPKI data as Uint8Array.
   */
  async toSPKI(): Promise<Uint8Array> {
    const result = await this.export('spki');
    return result as Uint8Array;
  }

  /**
   * Get WebCrypto key (convenience method)
   */
  async toWebCrypto(crypto = getCrypto()): Promise<CryptoKey> {
    return this.toCryptoKey(crypto);
  }

  /**
   * Export to SPKI
   */
  async exportPublicSpki(_crypto = getCrypto()): Promise<Uint8Array> {
    return this.toSPKI();
  }

  /**
   * Verify raw signature
   */
  async verify(
    algorithm: string,
    signature: Uint8Array,
    data: ByteView,
    crypto = getCrypto(),
  ): Promise<boolean> {
    // Get binding for the signature algorithm
    const binding = AlgorithmRegistry.get(algorithm);

    // Get CryptoKey and verify
    const cryptoKey = await this.toCryptoKey(crypto);
    return binding.verify({
      publicKey: cryptoKey,
      signature,
      data,
      crypto,
    });
  }

  /**
   * Convert to WebCrypto CryptoKey for cryptographic operations
   */
  async toCryptoKey(crypto = getCrypto()): Promise<CryptoKey> {
    return this.getCryptoKey(crypto);
  }

  /**
   * Get key type
   */
  get keyType(): SshKeyType {
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

  /**
   * Compute thumbprint of the public key
   */
  async thumbprint(
    algorithm: 'sha256' | 'sha512' = 'sha256',
    crypto = getCrypto(),
  ): Promise<Uint8Array> {
    const hashAlgorithm = algorithm === 'sha256' ? 'SHA-256' : 'SHA-512';
    const data = this.blob.keyData as BufferSource;
    const hash = await crypto.subtle.digest(hashAlgorithm, data);
    return new Uint8Array(hash);
  }
}
