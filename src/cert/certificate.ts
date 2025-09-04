import { getCrypto } from '../crypto';
import { SshPublicKey } from '../key/public_key';
import { AlgorithmRegistry } from '../registry';
import { SshSignature } from '../signature';
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
  private data: SshCertificateData;
  private _validAfter: bigint;
  private _validBefore: bigint;

  readonly keyId: string;
  readonly principals: string[];
  readonly certType: SshCertificateType;
  readonly serial: bigint;
  readonly validAfter: Date;
  readonly validBefore: Date;
  readonly publicKey: SshPublicKey;
  readonly signatureKey: SshPublicKey;
  readonly criticalOptions: Record<string, string>;
  readonly extensions: Record<string, string>;

  private constructor(blob: SshCertificateBlob) {
    this._blob = blob;
    this.data = parseCertificateData(blob.keyData);
    this._validAfter = this.data.validAfter;
    this._validBefore = this.data.validBefore;
    this.keyId = this.data.keyId;
    this.principals = this.data.validPrincipals;
    this.certType = this.data.type;
    this.serial = this.data.serial;
    this.validAfter = new Date(Number(this.data.validAfter) * 1000);
    this.validBefore = new Date(Number(this.data.validBefore) * 1000);
    this.publicKey = new SshPublicKey(this.data.publicKey);
    this.signatureKey = new SshPublicKey(this.data.signatureKey);
    this.criticalOptions = { ...this.data.criticalOptions };
    this.extensions = { ...this.data.extensions };
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
   * Export to SSH format (convenience method).
   * Returns a base64-encoded string in SSH certificate format.
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

  public validate(date: Date = new Date()): boolean {
    const ts = BigInt(Math.floor(date.getTime() / 1000));
    const after = this._validAfter;
    const before = this._validBefore;
    const INFINITY = 0xffffffffffffffffn;
    const upper = before === INFINITY ? ts : before;
    return ts >= after && ts <= upper;
  }

  /**
   * Verify certificate signature
   */
  async verify(caPublicKey?: SshPublicKey, crypto = getCrypto()): Promise<boolean> {
    // Use provided CA key or the signature key from certificate
    const verifyKey = caPublicKey || this.signatureKey;

    // Create the data to be signed (everything except the signature)
    const signedData = this.getSignedData();

    // Parse SSH signature
    const sshSignature = SshSignature.parse(this.data.signature);

    // Get binding for the signature algorithm
    const binding = AlgorithmRegistry.get(sshSignature.algorithm);

    // Get CryptoKey and verify
    const cryptoKey = await verifyKey.toCryptoKey(crypto);
    return binding.verify({
      publicKey: cryptoKey,
      signature: sshSignature.signature,
      data: signedData,
      crypto,
    });
  }

  /**
   * Get the signed data portion of the certificate
   */
  private getSignedData(): Uint8Array {
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
    } else if (this.data.keyType.startsWith('ecdsa-sha2-')) {
      reader.readString(); // curve name
      reader.readBytes(reader.readUint32()); // public point
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
}
