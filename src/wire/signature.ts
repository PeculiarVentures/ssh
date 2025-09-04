import { SshReader } from './reader';
import { SshWriter } from './writer';

export type SshSignatureFormat = 'legacy' | 'ssh-signature';

export interface SshSignatureBlob {
  format: SshSignatureFormat;
  algorithm: string;
  signature: Uint8Array;
  // SSH SIGNATURE specific fields
  version?: number;
  publicKey?: Uint8Array;
  namespace?: string;
  reserved?: string;
  hashAlgorithm?: string;
}

/**
 * Parse SSH signature from binary data
 */
export function parseSignature(data: Uint8Array): SshSignatureBlob {
  const reader = new SshReader(data);

  // Check for SSH SIGNATURE magic - direct byte comparison
  if (data.length >= 6 && new TextDecoder().decode(data.subarray(0, 6)) === 'SSHSIG') {
    return parseSshSignatureFormat(reader);
  } else {
    return parseLegacyFormat(reader);
  }
}

/**
 * Parse SSH SIGNATURE format (RFC 4253)
 */
function parseSshSignatureFormat(reader: SshReader): SshSignatureBlob {
  // Read magic bytes directly (not as SSH string)
  const magicBytes = reader.readBytes(6);
  const magic = new TextDecoder().decode(magicBytes);
  if (magic !== 'SSHSIG') {
    throw new Error('Invalid SSH SIGNATURE magic');
  }

  const version = reader.readUint32();
  const publicKeyLength = reader.readUint32();
  const publicKey = reader.readBytes(publicKeyLength);
  const namespace = reader.readString();
  const reserved = reader.readString();
  const hashAlgorithm = reader.readString();

  // Signature is in legacy format: algo + length + signature_bytes
  const signatureLength = reader.readUint32();
  const signatureData = reader.readBytes(signatureLength);
  const sigReader = new SshReader(signatureData);
  const algorithm = sigReader.readString();
  const signatureLength2 = sigReader.readUint32();
  const signature = sigReader.readBytes(signatureLength2);

  return {
    format: 'ssh-signature',
    algorithm,
    signature,
    version,
    publicKey,
    namespace,
    reserved,
    hashAlgorithm,
  };
}

/**
 * Parse legacy signature format
 */
function parseLegacyFormat(reader: SshReader): SshSignatureBlob {
  const algorithm = reader.readString();
  const signatureLength = reader.readUint32();
  const signature = reader.readBytes(signatureLength);

  return {
    format: 'legacy',
    algorithm,
    signature,
  };
}

/**
 * Serialize SSH signature to binary data
 */
export function serializeSignature(blob: SshSignatureBlob): Uint8Array {
  if (blob.format === 'ssh-signature') {
    return serializeSshSignatureFormat(blob);
  } else {
    return serializeLegacyFormat(blob);
  }
}

/**
 * Serialize to SSH SIGNATURE format
 */
function serializeSshSignatureFormat(blob: SshSignatureBlob): Uint8Array {
  const writer = new SshWriter();

  // Write magic bytes directly (not as SSH string)
  writer.writeBytes(new TextEncoder().encode('SSHSIG'));
  writer.writeUint32(blob.version || 1);

  if (blob.publicKey) {
    writer.writeUint32(blob.publicKey.length);
    writer.writeBytes(blob.publicKey);
  } else {
    writer.writeUint32(0);
  }

  writer.writeString(blob.namespace || 'file');
  writer.writeString(blob.reserved || '');
  writer.writeString(blob.hashAlgorithm || 'sha512');

  // Write signature in legacy format
  const sigWriter = new SshWriter();
  sigWriter.writeString(blob.algorithm);
  sigWriter.writeUint32(blob.signature.length);
  sigWriter.writeBytes(blob.signature);

  const sigData = sigWriter.toUint8Array();
  writer.writeUint32(sigData.length);
  writer.writeBytes(sigData);

  return writer.toUint8Array();
}

/**
 * Serialize to legacy format
 */
function serializeLegacyFormat(blob: SshSignatureBlob): Uint8Array {
  const writer = new SshWriter();
  writer.writeString(blob.algorithm);
  writer.writeUint32(blob.signature.length);
  writer.writeBytes(blob.signature);
  return writer.toUint8Array();
}
