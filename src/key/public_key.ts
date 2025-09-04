import { Convert } from 'pvtsutils';
import { getCrypto } from '../crypto';
import { UnsupportedAlgorithmError, UnsupportedKeyTypeError } from '../errors';
import { AlgorithmRegistry } from '../registry';
import type { ByteView, SshKeyType } from '../types';
import { getSshKeyTypeFromCryptoKey } from '../utils';
import {
  parsePublicKey as parseWirePublicKey,
  serializePublicKey as serializeWirePublicKey,
  type SshPublicKeyBlob,
} from '../wire/public_key';

export type SshPublicKeyExportFormat = 'ssh' | 'spki';

export class SshPublicKey {
  private blob: SshPublicKeyBlob;
  private cachedCryptoKey?: CryptoKey;

  constructor(blob: SshPublicKeyBlob) {
    this.blob = blob;
  }

  /**
   * Get cached CryptoKey
   */
  private async getCryptoKey(crypto = getCrypto()): Promise<CryptoKey> {
    if (!this.cachedCryptoKey) {
      const binding = AlgorithmRegistry.get(this.blob.type);
      if (!binding) {
        throw new UnsupportedKeyTypeError(`Unsupported key type: ${this.blob.type}`);
      }
      this.cachedCryptoKey = await binding.importPublicFromSsh({ blob: this.blob.keyData, crypto });
    }
    return this.cachedCryptoKey;
  }

  static async importPublicFromSsh(sshKey: string, crypto = getCrypto()): Promise<SshPublicKey> {
    const blob = parseWirePublicKey(sshKey);
    const binding = AlgorithmRegistry.get(blob.type);
    if (!binding) {
      throw new UnsupportedKeyTypeError(`Unsupported key type: ${blob.type}`);
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
      throw new UnsupportedKeyTypeError(`Unsupported key type: ${type}`);
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
      throw new UnsupportedKeyTypeError(`Unsupported key type: ${sshType}`);
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
      const cryptoKey = await this.getCryptoKey(crypto);
      const binding = AlgorithmRegistry.get(this.blob.type);
      if (!binding) {
        throw new UnsupportedKeyTypeError(`Unsupported key type: ${this.blob.type}`);
      }
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
   * Verify signature with convenient interface
   */
  async verifySignature(data: ByteView, signature: string, crypto = getCrypto()): Promise<boolean> {
    const binding = AlgorithmRegistry.get(this.blob.type);
    if (!binding) {
      throw new UnsupportedKeyTypeError(`Unsupported key type: ${this.blob.type}`);
    }

    // Decode base64 signature
    const signatureBytes = new Uint8Array(Convert.FromBase64(signature));
    const decodedSignature = binding.decodeSshSignature({ signature: signatureBytes });

    // Get CryptoKey and verify
    const cryptoKey = await this.toCryptoKey(crypto);
    return binding.verify({
      publicKey: cryptoKey,
      signature: decodedSignature.signature,
      data,
      crypto,
    });
  }

  /**
   * Verify signature with hash parameter (for RSA)
   */
  async verifySignatureWithHash(
    data: ByteView,
    signature: string,
    hash: 'SHA-256' | 'SHA-512' = 'SHA-256',
    crypto = getCrypto(),
  ): Promise<boolean> {
    const algo = this.getSignatureAlgorithm(hash);
    const binding = AlgorithmRegistry.get(algo);
    if (!binding) {
      throw new UnsupportedAlgorithmError(`Unsupported algorithm: ${algo}`);
    }

    // Decode base64 signature
    const signatureBytes = new Uint8Array(Convert.FromBase64(signature));
    const decodedSignature = binding.decodeSshSignature({ signature: signatureBytes });

    // Import public key with the correct binding
    const cryptoKey = await binding.importPublicFromSsh({ blob: this.blob.keyData, crypto });

    return binding.verify({
      publicKey: cryptoKey,
      signature: decodedSignature.signature,
      data,
      crypto,
      hash,
    });
  }

  /**
   * Get SSH signature algorithm based on key type and hash
   */
  private getSignatureAlgorithm(hash: 'SHA-256' | 'SHA-512'): string {
    switch (this.blob.type) {
      case 'ssh-rsa':
        return hash === 'SHA-256' ? 'rsa-sha2-256' : 'rsa-sha2-512';
      case 'ssh-ed25519':
        return 'ssh-ed25519';
      case 'ecdsa-sha2-nistp256':
        return 'ecdsa-sha2-nistp256';
      case 'ecdsa-sha2-nistp384':
        return 'ecdsa-sha2-nistp384';
      case 'ecdsa-sha2-nistp521':
        return 'ecdsa-sha2-nistp521';
      default:
        throw new UnsupportedKeyTypeError(`Unsupported key type: ${this.blob.type}`);
    }
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
