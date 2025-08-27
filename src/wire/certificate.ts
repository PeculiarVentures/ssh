import type { ByteView, SshKeyType } from '../types';
import { SshReader } from './reader';
import { SshWriter } from './writer';

export interface SshCertificateBlob {
  type: SshKeyType;
  keyData: Uint8Array;
  comment?: string;
}

export interface SshCertificateData {
  nonce: Uint8Array;
  keyType: string;
  publicKey: Uint8Array;
  serial: bigint;
  type: 'user' | 'host';
  keyId: string;
  validPrincipals: string[];
  validAfter: bigint;
  validBefore: bigint;
  criticalOptions: Record<string, string>;
  extensions: Record<string, string>;
  reserved: Uint8Array;
  signatureKey: Uint8Array;
  signature: Uint8Array;
}

export function parse(input: ByteView | string): SshCertificateBlob {
  if (typeof input === 'string') {
    const parts = input.trim().split(/\s+/);
    if (parts.length < 2) {
      throw new Error('Invalid SSH certificate format');
    }

    const type = parts[0] as SshKeyType;
    const blob = Uint8Array.from(atob(parts[1]), c => c.charCodeAt(0));
    const comment = parts.length > 2 ? parts.slice(2).join(' ') : undefined;

    // Validate blob
    const reader = new SshReader(blob);
    const blobType = reader.readString();
    if (blobType !== type) {
      throw new Error('Certificate type mismatch');
    }

    return {
      type,
      keyData: blob,
      comment,
    };
  } else {
    let data: Uint8Array;
    if (input instanceof ArrayBuffer) {
      data = new Uint8Array(input);
    } else {
      data = input;
    }

    const reader = new SshReader(data);
    const type = reader.readString() as SshKeyType;
    const keyData = data.slice(reader.getOffset());

    return {
      type,
      keyData,
    };
  }
}

export function parseCertificateData(keyData: Uint8Array): SshCertificateData {
  const reader = new SshReader(keyData);

  // Read certificate type
  const certType = reader.readString();

  // Read nonce
  const nonce = reader.readBytes(reader.readUint32());

  // Read public key based on certificate type
  let publicKey: Uint8Array;
  let keyType: string;

  if (certType === 'ssh-rsa-cert-v01@openssh.com') {
    // For RSA certificates, read the public key components directly
    const publicKeyExponent = reader.readBytes(reader.readUint32()); // e
    const publicKeyModulus = reader.readBytes(reader.readUint32()); // n

    // Reconstruct the public key blob
    const writer = new SshWriter();
    writer.writeString('ssh-rsa');
    writer.writeBytes(publicKeyExponent);
    writer.writeBytes(publicKeyModulus);
    publicKey = writer.toUint8Array();
    keyType = 'ssh-rsa';
  } else if (certType === 'ssh-ed25519-cert-v01@openssh.com') {
    // For Ed25519 certificates, read the public key
    const publicKeyData = reader.readBytes(reader.readUint32()); // 32-byte Ed25519 public key

    // Reconstruct the public key blob
    const writer = new SshWriter();
    writer.writeString('ssh-ed25519');
    writer.writeBytes(publicKeyData);
    publicKey = writer.toUint8Array();
    keyType = 'ssh-ed25519';
  } else if (certType === 'ecdsa-sha2-nistp256-cert-v01@openssh.com') {
    // For ECDSA P-256 certificates, read the curve and public key point
    const curveName = reader.readString(); // should be "nistp256"
    const publicKeyPoint = reader.readBytes(reader.readUint32()); // ECDSA point

    // Reconstruct the public key blob
    const writer = new SshWriter();
    writer.writeString('ecdsa-sha2-nistp256');
    writer.writeString(curveName);
    writer.writeBytes(publicKeyPoint);
    publicKey = writer.toUint8Array();
    keyType = 'ecdsa-sha2-nistp256';
  } else if (certType === 'ecdsa-sha2-nistp384-cert-v01@openssh.com') {
    // For ECDSA P-384 certificates
    const curveName = reader.readString(); // should be "nistp384"
    const publicKeyPoint = reader.readBytes(reader.readUint32());

    const writer = new SshWriter();
    writer.writeString('ecdsa-sha2-nistp384');
    writer.writeString(curveName);
    writer.writeBytes(publicKeyPoint);
    publicKey = writer.toUint8Array();
    keyType = 'ecdsa-sha2-nistp384';
  } else if (certType === 'ecdsa-sha2-nistp521-cert-v01@openssh.com') {
    // For ECDSA P-521 certificates
    const curveName = reader.readString(); // should be "nistp521"
    const publicKeyPoint = reader.readBytes(reader.readUint32());

    const writer = new SshWriter();
    writer.writeString('ecdsa-sha2-nistp521');
    writer.writeString(curveName);
    writer.writeBytes(publicKeyPoint);
    publicKey = writer.toUint8Array();
    keyType = 'ecdsa-sha2-nistp521';
  } else {
    throw new Error(`Unsupported certificate type: ${certType}`);
  }

  // Read serial
  const serial = reader.readUint64();

  // Read type
  const typeValue = reader.readUint32();
  const type: 'user' | 'host' = typeValue === 1 ? 'user' : 'host';

  // Read key ID
  const keyId = reader.readString();

  // Read valid principals
  const principalsLength = reader.readUint32();
  const principalsData = reader.readBytes(principalsLength);
  const validPrincipals: string[] = [];

  if (principalsData.length > 0) {
    const principalsReader = new SshReader(principalsData);
    while (principalsReader.getOffset() < principalsData.length) {
      try {
        const principal = principalsReader.readString();
        validPrincipals.push(principal);
      } catch {
        break; // End of principals data
      }
    }
  }

  // Read validity period
  const validAfter = reader.readUint64();
  const validBefore = reader.readUint64();

  // Read critical options
  const criticalOptions: Record<string, string> = {};
  const criticalLength = reader.readUint32();
  const criticalData = reader.readBytes(criticalLength);

  if (criticalData.length > 0) {
    const optionsReader = new SshReader(criticalData);
    while (optionsReader.getOffset() < criticalData.length) {
      try {
        const name = optionsReader.readString();
        const valueData = optionsReader.readBytes(optionsReader.readUint32());
        const value = valueData.length === 0 ? '' : new TextDecoder().decode(valueData);
        criticalOptions[name] = value;
      } catch {
        break; // End of options data
      }
    }
  }

  // Read extensions
  const extensions: Record<string, string> = {};
  const extensionsLength = reader.readUint32();
  const extensionsData = reader.readBytes(extensionsLength);

  if (extensionsData.length > 0) {
    const extReader = new SshReader(extensionsData);
    while (extReader.getOffset() < extensionsData.length) {
      try {
        const name = extReader.readString();
        const valueData = extReader.readBytes(extReader.readUint32());
        const value = valueData.length === 0 ? '' : new TextDecoder().decode(valueData);
        extensions[name] = value;
      } catch {
        break; // End of extensions data
      }
    }
  }

  // Read reserved
  const reservedLength = reader.readUint32();
  const reserved = reader.readBytes(reservedLength);

  // Read signature key
  const signatureKeyLength = reader.readUint32();
  const signatureKey = reader.readBytes(signatureKeyLength);

  // Read signature
  const signatureLength = reader.readUint32();
  const signature = reader.readBytes(signatureLength);

  return {
    nonce,
    keyType,
    publicKey,
    serial,
    type,
    keyId,
    validPrincipals,
    validAfter,
    validBefore,
    criticalOptions,
    extensions,
    reserved,
    signatureKey,
    signature,
  };
}

export function serialize(cert: SshCertificateBlob): string {
  const base64 = btoa(String.fromCharCode(...cert.keyData));
  const parts = [cert.type, base64];
  if (cert.comment) {
    parts.push(cert.comment);
  }
  return parts.join(' ');
}
