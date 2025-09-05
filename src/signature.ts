import { Convert } from 'pvtsutils';
import { getCrypto } from './crypto';
import { SshPrivateKey } from './key/private_key';
import { SshPublicKey } from './key/public_key';
import { AlgorithmRegistry } from './registry';
import type { SshKeyType, SshSignatureAlgo } from './types';
import { SshObject } from './types';
import { SshReader } from './wire/reader';
import {
  parseSignature,
  serializeSignature,
  SshSignatureBlob,
  SshSignatureFormat,
} from './wire/signature';
import { SshWriter } from './wire/writer';

export class SshSignature extends SshObject {
  public static readonly TYPE = 'signature';
  public readonly type = SshSignature.TYPE;

  private blob: SshSignatureBlob;

  readonly format: SshSignatureFormat;
  readonly algorithm: string;
  readonly signature: Uint8Array;
  readonly version?: number;
  readonly publicKey?: SshPublicKey;
  readonly namespace?: string;
  readonly reserved?: string;
  readonly hashAlgorithm?: string;

  private constructor(blob: SshSignatureBlob) {
    super();
    this.blob = blob;
    this.format = blob.format;
    this.algorithm = blob.algorithm;
    this.signature = blob.signature;
    this.version = blob.version;
    this.namespace = blob.namespace;
    this.reserved = blob.reserved;
    this.hashAlgorithm = blob.hashAlgorithm;
    if (blob.publicKey) {
      const reader = new SshReader(blob.publicKey);
      const type = reader.readString() as SshKeyType;
      this.publicKey = new SshPublicKey({ type, keyData: blob.publicKey });
    }
  }

  /**
   * Parse SSH signature from binary data
   */
  static parse(data: Uint8Array): SshSignature {
    const blob = parseSignature(data);
    return new SshSignature(blob);
  }

  /**
   * Create from signature blob
   */
  static fromBlob(blob: SshSignatureBlob): SshSignature {
    return new SshSignature(blob);
  }

  /**
   * Parse SSH signature from base64 string
   */
  static fromBase64(base64: string): SshSignature {
    const data = new Uint8Array(Convert.FromBase64(base64));
    return SshSignature.parse(data);
  }

  /**
   * Parse SSH signature from SSH SIGNATURE format file content
   */
  static fromText(text: string): SshSignature {
    const base64 = text
      .replace(/-----BEGIN SSH SIGNATURE-----/, '')
      .replace(/-----END SSH SIGNATURE-----/, '')
      .replace(/[\r\n\s]/g, '');
    return SshSignature.fromBase64(base64);
  }

  /**
   * Serialize signature to binary data
   */
  serialize(): Uint8Array {
    return serializeSignature(this.blob);
  }

  /**
   * Export to base64 string
   */
  toBase64(): string {
    return Convert.ToBase64(this.serialize());
  }

  /**
   * Export to SSH SIGNATURE format text
   */
  toText(): string {
    const base64 = this.toBase64();
    // Split base64 into 70-character lines
    const lines = [];
    for (let i = 0; i < base64.length; i += 70) {
      lines.push(base64.substring(i, i + 70));
    }

    return ['-----BEGIN SSH SIGNATURE-----', ...lines, '-----END SSH SIGNATURE-----'].join('\n');
  }

  async toSSH(): Promise<string> {
    return this.toText();
  }

  /**
   * Verify signature against data using provided public key
   */
  async verify(data: Uint8Array, publicKey: SshPublicKey): Promise<boolean> {
    const binding = AlgorithmRegistry.get(this.algorithm);
    const cryptoKey = await publicKey['getCryptoKey']();
    const crypto = getCrypto();

    let dataToVerify = data;

    // For SSH SIGNATURE format, compute the data to be signed according to spec
    if (this.format === 'ssh-signature') {
      const hashAlg = this.hashAlgorithm || 'sha512';
      const namespace = this.namespace || 'file';
      const reserved = this.reserved || '';

      // Step 1: Hash the original message with the specified hash algorithm
      const hashAlgorithm = hashAlg === 'sha256' ? 'SHA-256' : 'SHA-512';
      const messageHash = await crypto.subtle.digest(hashAlgorithm, data as BufferSource);
      const messageHashBytes = new Uint8Array(messageHash);

      // Step 2: Create the signed data structure according to Section 5 of spec:
      // SSHSIG || namespace || reserved || hash_algorithm || H(message)
      const writer = new SshWriter();

      // Magic string (6 bytes)
      writer.writeBytes(new TextEncoder().encode('SSHSIG'));

      // Namespace (as SSH string)
      writer.writeString(namespace);

      // Reserved (as SSH string)
      writer.writeString(reserved);

      // Hash algorithm (as SSH string)
      writer.writeString(hashAlg);

      // H(message) - the hash of the message (as SSH string)
      writer.writeUint32(messageHashBytes.length);
      writer.writeBytes(messageHashBytes);

      dataToVerify = writer.toUint8Array();
    }

    // For RSA algorithms, determine the correct hash algorithm
    let hashAlgorithm: 'SHA-256' | 'SHA-512' | undefined;
    if (this.algorithm === 'rsa-sha2-256') {
      hashAlgorithm = 'SHA-256';
    } else if (this.algorithm === 'rsa-sha2-512') {
      hashAlgorithm = 'SHA-512';
    }

    let signatureToVerify: Uint8Array;
    if (this.format === 'legacy' || this.format === 'ssh-signature') {
      // Decode the SSH signature to get the proper format for WebCrypto
      // Create wire format for decodeSshSignature (algorithm + length + signature bytes)
      const sigWriter = new SshWriter();
      sigWriter.writeString(this.algorithm);
      sigWriter.writeUint32(this.signature.length);
      sigWriter.writeBytes(this.signature);
      const wireFormatSignature = sigWriter.toUint8Array();

      const decodedSig = binding.decodeSshSignature({
        signature: wireFormatSignature,
      });
      signatureToVerify = decodedSig.signature;
    } else {
      // For SSH SIGNATURE format, signature is already raw
      signatureToVerify = this.signature;
    }

    return binding.verify({
      publicKey: cryptoKey,
      signature: signatureToVerify,
      data: dataToVerify,
      crypto,
      hash: hashAlgorithm,
    });
  }

  /**
   * Create signature from algorithm and raw signature bytes
   */
  static fromLegacy(algorithm: string, signature: Uint8Array): SshSignature {
    const binding = AlgorithmRegistry.get(algorithm);
    const encodedSignature = binding.encodeSshSignature({
      signature,
      algo: algorithm as SshSignatureAlgo,
    });
    // Extract the signature data part
    const sigReader = new SshReader(encodedSignature);
    sigReader.readString(); // skip algorithm
    const sigLength = sigReader.readUint32();
    const signatureData = sigReader.readBytes(sigLength);

    return new SshSignature({
      format: 'legacy',
      algorithm,
      signature: signatureData,
    });
  }

  /**
   * Create SSH SIGNATURE format signature
   */
  static fromSshSignature(
    algorithm: string,
    signature: Uint8Array,
    options: {
      version?: number;
      publicKey?: SshPublicKey;
      namespace?: string;
      reserved?: string;
      hashAlgorithm?: string;
    } = {},
  ): SshSignature {
    const blob: SshSignatureBlob = {
      format: 'ssh-signature',
      algorithm,
      signature,
      version: options.version || 1,
      publicKey: options.publicKey ? options.publicKey.getBlob().keyData : undefined,
      namespace: options.namespace || 'file',
      reserved: options.reserved || '',
      hashAlgorithm: options.hashAlgorithm || 'sha512',
    };
    return new SshSignature(blob);
  }

  /**
   * Sign data with a private key
   */
  static async sign(
    algorithm: string,
    privateKey: SshPrivateKey,
    data: Uint8Array,
    options: {
      format?: 'legacy' | 'ssh-signature';
      namespace?: string;
    } = {},
  ): Promise<SshSignature> {
    const { format = 'legacy', namespace = 'file' } = options;

    if (format === 'legacy') {
      const rawSignature = await privateKey.sign(algorithm, data);
      const algorithmUsed = algorithm || privateKey.keyType;
      return SshSignature.fromLegacy(algorithmUsed, rawSignature);
    } else {
      // Determine the signature algorithm to use
      const signatureAlgorithm = algorithm;
      const binding = AlgorithmRegistry.get(signatureAlgorithm);
      const hashAlgorithm = algorithm === 'rsa-sha2-256' ? 'sha256' : 'sha512';

      // Get the public key for SSH SIGNATURE format
      const publicKey = await privateKey.exportPublicKey();

      // For SSH SIGNATURE format, create the data to be signed according to spec
      const crypto = getCrypto();

      // Step 1: Hash the original message with the specified hash algorithm
      const webCryptoHashAlg = hashAlgorithm === 'sha256' ? 'SHA-256' : 'SHA-512';
      const messageHash = await crypto.subtle.digest(webCryptoHashAlg, data as BufferSource);
      const messageHashBytes = new Uint8Array(messageHash);

      // Step 2: Create the signed data structure according to Section 5 of spec:
      // SSHSIG || namespace || reserved || hash_algorithm || H(message)
      const writer = new SshWriter();

      // Magic string (6 bytes)
      writer.writeBytes(new TextEncoder().encode('SSHSIG'));

      // Namespace (as SSH string)
      writer.writeString(namespace);

      // Reserved (as SSH string)
      writer.writeString('');

      // Hash algorithm (as SSH string)
      writer.writeString(hashAlgorithm);

      // H(message) - the hash of the message (as SSH string)
      writer.writeUint32(messageHashBytes.length);
      writer.writeBytes(messageHashBytes);

      const dataToSign = writer.toUint8Array();

      const rawSignature = await privateKey.sign(signatureAlgorithm, dataToSign);
      const encodedSignature = binding.encodeSshSignature({
        signature: rawSignature,
        algo: signatureAlgorithm as SshSignatureAlgo,
      });

      // For SSH SIGNATURE format, we need to extract just the signature data part
      // The SSH wire format is: string(algorithm) + uint32(length) + bytes(signature_data)
      // We want just the signature_data part for storage in the SSH SIGNATURE blob
      const sigReader = new SshReader(encodedSignature);
      sigReader.readString(); // skip algorithm name
      const sigLength = sigReader.readUint32();
      const signatureData = sigReader.readBytes(sigLength);

      return SshSignature.fromSshSignature(signatureAlgorithm, signatureData, {
        namespace,
        hashAlgorithm,
        publicKey,
      });
    }
  }
}
