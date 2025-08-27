import { getCrypto } from '../crypto';
import { SshPublicKey } from '../key/public_key';
import {
  parseCertificateData,
  parse as parseWireCertificate,
  serialize as serializeWireCertificate,
  type SshCertificateBlob,
  type SshCertificateData,
} from '../wire/certificate';
import { SshReader } from '../wire/reader';

export type SshCertificateType = 'user' | 'host';

export class SshCertificate {
  private _blob: SshCertificateBlob;
  private data?: SshCertificateData;
  private _publicKey?: SshPublicKey;
  private _signatureKey?: SshPublicKey;

  private constructor(blob: SshCertificateBlob) {
    this._blob = blob;
  }

  /**
   * Create from certificate text (SSH format)
   */
  static async fromText(text: string): Promise<SshCertificate> {
    const blob = parseWireCertificate(text);
    return new SshCertificate(blob);
  }

  /**
   * Create from certificate blob
   */
  static async fromBlob(blob: SshCertificateBlob): Promise<SshCertificate> {
    return new SshCertificate(blob);
  }

  /**
   * Export to text (SSH format)
   */
  toText(): string {
    return serializeWireCertificate(this._blob);
  }

  /**
   * Export to blob
   */
  toBlob(): SshCertificateBlob {
    return { ...this._blob };
  }

  /**
   * Get certificate blob
   */
  get blob(): SshCertificateBlob {
    return this.toBlob();
  }

  /**
   * Get key ID
   */
  async getKeyId(): Promise<string> {
    if (!this.data) {
      await this.parseData();
    }
    if (!this.data) {
      throw new Error('Failed to parse certificate data');
    }
    return this.data.keyId;
  }

  /**
   * Get valid principals
   */
  async getPrincipals(): Promise<string[]> {
    if (!this.data) {
      await this.parseData();
    }
    if (!this.data) {
      throw new Error('Failed to parse certificate data');
    }
    return this.data.validPrincipals;
  }

  /**
   * Get certificate type
   */
  async getType(): Promise<SshCertificateType> {
    if (!this.data) {
      await this.parseData();
    }
    if (!this.data) {
      throw new Error('Failed to parse certificate data');
    }
    return this.data.type;
  }

  /**
   * Get serial number
   */
  async getSerial(): Promise<bigint> {
    if (!this.data) {
      await this.parseData();
    }
    if (!this.data) {
      throw new Error('Failed to parse certificate data');
    }
    return this.data.serial;
  }

  /**
   * Get valid after timestamp
   */
  async getValidAfter(): Promise<bigint> {
    if (!this.data) {
      await this.parseData();
    }
    if (!this.data) {
      throw new Error('Failed to parse certificate data');
    }
    return this.data.validAfter;
  }

  /**
   * Get valid before timestamp
   */
  async getValidBefore(): Promise<bigint> {
    if (!this.data) {
      await this.parseData();
    }
    if (!this.data) {
      throw new Error('Failed to parse certificate data');
    }
    return this.data.validBefore;
  }

  /**
   * Get public key
   */
  async getPublicKey(): Promise<SshPublicKey> {
    if (!this._publicKey) {
      if (!this.data) {
        await this.parseData();
      }
      if (!this.data) {
        throw new Error('Failed to parse certificate data');
      }
      const publicKeyBlob = {
        type: this.data.keyType as any,
        keyData: this.data.publicKey,
      };
      this._publicKey = new SshPublicKey(publicKeyBlob);
    }
    return this._publicKey;
  }

  /**
   * Get signature key
   */
  async getSignatureKey(): Promise<SshPublicKey> {
    if (!this._signatureKey) {
      if (!this.data) {
        await this.parseData();
      }
      if (!this.data) {
        throw new Error('Failed to parse certificate data');
      }

      // Parse the signature key blob to determine its actual type
      const reader = new SshReader(this.data.signatureKey);
      const signatureKeyType = reader.readString();

      const signatureKeyBlob = {
        type: signatureKeyType as any,
        keyData: this.data.signatureKey,
      };
      this._signatureKey = new SshPublicKey(signatureKeyBlob);
    }
    return this._signatureKey;
  }

  /**
   * Get critical options
   */
  async getCriticalOptions(): Promise<Record<string, string>> {
    if (!this.data) {
      await this.parseData();
    }
    if (!this.data) {
      throw new Error('Failed to parse certificate data');
    }
    return { ...this.data.criticalOptions };
  }

  /**
   * Get extensions
   */
  async getExtensions(): Promise<Record<string, string>> {
    if (!this.data) {
      await this.parseData();
    }
    if (!this.data) {
      throw new Error('Failed to parse certificate data');
    }
    return { ...this.data.extensions };
  }

  /**
   * Verify certificate signature
   */
  async verify(caPublicKey?: SshPublicKey, crypto = getCrypto()): Promise<boolean> {
    if (!this.data) {
      await this.parseData();
    }
    if (!this.data) {
      throw new Error('Failed to parse certificate data');
    }

    // Use provided CA key or the signature key from certificate
    const verifyKey = caPublicKey || (await this.getSignatureKey());

    // Create the data to be signed (everything except the signature)
    const signedData = this.getSignedData();

    // Verify the signature
    try {
      const signatureStr = btoa(String.fromCharCode(...this.data.signature));
      return await verifyKey.verify(signedData, signatureStr, crypto);
    } catch {
      return false;
    }
  }

  /**
   * Get the signed data portion of the certificate
   */
  private getSignedData(): Uint8Array {
    // For now, return the first part of the certificate data
    // This is a simplified implementation
    if (!this.data) {
      throw new Error('Certificate not parsed');
    }

    // Calculate signed data length by finding signature offset
    const totalLength = this._blob.keyData.length;
    const signatureLength = this.data.signature.length;
    const signedDataLength = totalLength - signatureLength - 4; // -4 for signature length field

    return this._blob.keyData.slice(0, signedDataLength);
  }

  /**
   * Parse certificate data from blob
   */
  private async parseData(): Promise<void> {
    if (this.data) {
      return;
    }

    try {
      this.data = parseCertificateData(this._blob.keyData);
    } catch {
      throw new Error('Failed to parse certificate data');
    }
  }
}
