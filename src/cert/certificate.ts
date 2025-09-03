import { getCrypto } from '../crypto';
import { SshPublicKey } from '../key/public_key';
import { AlgorithmRegistry } from '../registry';
import {
  parseCertificateData,
  parse as parseWireCertificate,
  serialize as serializeWireCertificate,
  type SshCertificateBlob,
  type SshCertificateData,
} from '../wire/certificate';
import { SshReader } from '../wire/reader';
import { SshWriter } from '../wire/writer';

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
   * Export to SSH format (convenience method)
   */
  toSSH(): string {
    return this.toText();
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
   * Get key ID (synchronous convenience method)
   */
  get keyId(): string {
    if (!this.data) {
      throw new Error('Certificate data not parsed. Call an async method first.');
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
   * Get valid principals (synchronous convenience method)
   */
  get principals(): string[] {
    if (!this.data) {
      throw new Error('Certificate data not parsed. Call an async method first.');
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
   * Get certificate type (synchronous convenience method)
   */
  get certType(): SshCertificateType {
    if (!this.data) {
      throw new Error('Certificate data not parsed. Call an async method first.');
    }
    return this.data.type;
  }

  /**
   * Check if certificate is currently valid (synchronous convenience method)
   */
  get isValid(): boolean {
    if (!this.data) {
      throw new Error('Certificate data not parsed. Call an async method first.');
    }
    const now = BigInt(Math.floor(Date.now() / 1000));
    return now >= this.data.validAfter && now <= this.data.validBefore;
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
      this._publicKey = new SshPublicKey(this.data.publicKey);
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

      this._signatureKey = new SshPublicKey(this.data.signatureKey);
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

    // Decode SSH signature to raw format
    const binding = AlgorithmRegistry.get(verifyKey.type);
    if (!binding) {
      throw new Error(`Unsupported key type: ${verifyKey.type}`);
    }

    const decodedSignature = binding.decodeSshSignature({ signature: this.data.signature });

    // Get CryptoKey and verify
    const cryptoKey = await verifyKey.toCryptoKey(crypto);
    return binding.verify({
      publicKey: cryptoKey,
      signature: decodedSignature.signature,
      data: signedData,
      crypto,
    });
  }

  /**
   * Get the signed data portion of the certificate
   */
  private getSignedData(): Uint8Array {
    if (!this.data) {
      throw new Error('Certificate not parsed');
    }

    // According to PROTOCOL.certkeys specification:
    // "signature is computed over all preceding fields from the initial string
    // up to, and including the signature key"

    // Find where the signature field starts (after signature key)
    const reader = new SshReader(this._blob.keyData);

    // Skip all fields until we reach the signature
    reader.readString(); // certificate type
    reader.readBytes(reader.readUint32()); // nonce

    // Skip public key
    if (this.data.keyType === 'ssh-ed25519') {
      reader.readBytes(reader.readUint32());
    } else if (this.data.keyType === 'ssh-rsa') {
      reader.readBytes(reader.readUint32()); // e
      reader.readBytes(reader.readUint32()); // n
    }

    reader.readUint64(); // serial
    reader.readUint32(); // type
    reader.readBytes(reader.readUint32()); // key id
    reader.readBytes(reader.readUint32()); // valid principals
    reader.readUint64(); // valid after
    reader.readUint64(); // valid before
    reader.readBytes(reader.readUint32()); // critical options
    reader.readBytes(reader.readUint32()); // extensions
    reader.readBytes(reader.readUint32()); // reserved
    reader.readBytes(reader.readUint32()); // signature key - THIS IS INCLUDED in signed data

    // Everything up to this point (INCLUDING signature key) is signed
    const signedDataEnd = reader.getOffset();

    // Return the exact bytes from the beginning INCLUDING signature key
    return this._blob.keyData.slice(0, signedDataEnd);
  }

  private getCertificateTypeFromKeyType(keyType: string): string {
    switch (keyType) {
      case 'ssh-ed25519':
        return 'ssh-ed25519-cert-v01@openssh.com';
      case 'ssh-rsa':
        return 'ssh-rsa-cert-v01@openssh.com';
      case 'ecdsa-sha2-nistp256':
        return 'ecdsa-sha2-nistp256-cert-v01@openssh.com';
      case 'ecdsa-sha2-nistp384':
        return 'ecdsa-sha2-nistp384-cert-v01@openssh.com';
      case 'ecdsa-sha2-nistp521':
        return 'ecdsa-sha2-nistp521-cert-v01@openssh.com';
      default:
        throw new Error(`Unsupported key type for certificate: ${keyType}`);
    }
  }

  private getCertificateDataWithoutSignature(): Uint8Array {
    if (!this.data) {
      throw new Error('Certificate not parsed');
    }

    const reader = new SshReader(this._blob.keyData);

    // Skip certificate type (we already have it)
    reader.readString();

    // Read nonce
    const nonceLength = reader.readUint32();
    const nonce = reader.readBytes(nonceLength);

    // Read public key based on certificate type
    let publicKeyData: Uint8Array;
    if (this.data.keyType === 'ssh-ed25519') {
      const pubKeyLength = reader.readUint32();
      publicKeyData = reader.readBytes(pubKeyLength);
    } else if (this.data.keyType === 'ssh-rsa') {
      // RSA has two components: e and n
      const eLength = reader.readUint32();
      const e = reader.readBytes(eLength);
      const nLength = reader.readUint32();
      const n = reader.readBytes(nLength);

      // Combine e and n into one data block for length calculation
      const writer = new SshWriter();
      writer.writeUint32(eLength);
      writer.writeBytes(e);
      writer.writeUint32(nLength);
      writer.writeBytes(n);
      publicKeyData = writer.toUint8Array();
    } else {
      throw new Error(`Unsupported key type: ${this.data.keyType}`);
    }

    // Read serial
    const serial = reader.readUint64();

    // Read type
    const type = reader.readUint32();

    // Read key ID
    const keyIdLength = reader.readUint32();
    const keyId = reader.readBytes(keyIdLength);

    // Read valid principals
    const principalsLength = reader.readUint32();
    const principals = reader.readBytes(principalsLength);

    // Read validity period
    const validAfter = reader.readUint64();
    const validBefore = reader.readUint64();

    // Read critical options
    const criticalOptionsLength = reader.readUint32();
    const criticalOptions = reader.readBytes(criticalOptionsLength);

    // Read extensions
    const extensionsLength = reader.readUint32();
    const extensions = reader.readBytes(extensionsLength);

    // Read reserved
    const reservedLength = reader.readUint32();
    const reserved = reader.readBytes(reservedLength);

    // Read signature key - this is PART OF the signed data
    const signatureKeyLength = reader.readUint32();
    const signatureKey = reader.readBytes(signatureKeyLength);

    // Now rebuild the data structure up to this point (but NOT including the signature)
    const writer = new SshWriter();

    // Write nonce
    writer.writeUint32(nonceLength);
    writer.writeBytes(nonce);

    // Write public key data
    if (this.data.keyType === 'ssh-ed25519') {
      writer.writeUint32(publicKeyData.length);
      writer.writeBytes(publicKeyData);
    } else if (this.data.keyType === 'ssh-rsa') {
      writer.writeBytes(publicKeyData); // Already contains the length prefixed data
    }

    // Write serial
    writer.writeUint64(serial);

    // Write type
    writer.writeUint32(type);

    // Write key ID
    writer.writeUint32(keyIdLength);
    writer.writeBytes(keyId);

    // Write valid principals
    writer.writeUint32(principalsLength);
    writer.writeBytes(principals);

    // Write validity period
    writer.writeUint64(validAfter);
    writer.writeUint64(validBefore);

    // Write critical options
    writer.writeUint32(criticalOptionsLength);
    writer.writeBytes(criticalOptions);

    // Write extensions
    writer.writeUint32(extensionsLength);
    writer.writeBytes(extensions);

    // Write reserved
    writer.writeUint32(reservedLength);
    writer.writeBytes(reserved);

    // Write signature key (this is part of signed data)
    writer.writeUint32(signatureKeyLength);
    writer.writeBytes(signatureKey);

    return writer.toUint8Array();
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
