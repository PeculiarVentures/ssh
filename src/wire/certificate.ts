import { Convert } from 'pvtsutils';
import { InvalidFormatError, UnsupportedAlgorithmError, UnsupportedKeyTypeError } from '../errors';
import { AlgorithmRegistry } from '../registry';
import type { ByteView, SshKeyType } from '../types';
import { decoder, encoder } from '../utils';
import type { SshPublicKeyBlob } from './public_key';
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
  publicKey: SshPublicKeyBlob;
  serial: bigint;
  type: 'user' | 'host';
  keyId: string;
  validPrincipals: string[];
  validAfter: bigint;
  validBefore: bigint;
  criticalOptions: Record<string, string>;
  extensions: Record<string, string>;
  reserved: Uint8Array;
  signatureKey: SshPublicKeyBlob;
  signature: Uint8Array;
}

export function parse(input: ByteView | string): SshCertificateBlob {
  if (typeof input === 'string') {
    const parts = input.trim().split(/\s+/);
    if (parts.length < 2) {
      throw new InvalidFormatError('SSH certificate string', 'type base64 [comment]');
    }

    const type = parts[0] as SshKeyType;
    const blob = new Uint8Array(Convert.FromBase64(parts[1]));
    const comment = parts.length > 2 ? parts.slice(2).join(' ') : undefined;

    // Validate blob
    const reader = new SshReader(blob);
    const blobType = reader.readString();
    if (blobType !== type) {
      throw new InvalidFormatError(`certificate blob type ${blobType}`, `expected ${type}`);
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
  // Map certificate type to SSH key type
  const mappedKeyType = AlgorithmRegistry.certTypeToKeyType(certType);
  if (!mappedKeyType) {
    throw new UnsupportedAlgorithmError(certType);
  }

  // Get the algorithm binding and parse the public key
  const binding = AlgorithmRegistry.get(mappedKeyType);
  const publicKey = binding.parseCertificatePublicKey(reader);
  const keyType = mappedKeyType;

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
        const value = valueData.length === 0 ? '' : decoder.decode(valueData);
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
        const value = valueData.length === 0 ? '' : decoder.decode(valueData);
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
  const signatureKeyData = reader.readBytes(signatureKeyLength);

  // Parse signature key type
  const signatureKeyReader = new SshReader(signatureKeyData);
  const signatureKeyType = signatureKeyReader.readString();
  const signatureKey: SshPublicKeyBlob = {
    type: signatureKeyType as SshKeyType,
    keyData: signatureKeyData,
  };

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
  const base64 = Convert.ToBase64(cert.keyData);
  const parts = [cert.type, base64];
  if (cert.comment) {
    parts.push(cert.comment);
  }
  return parts.join(' ');
}

export interface CreateCertificateDataParams {
  publicKey: SshPublicKeyBlob;
  keyType: string;
  serial: bigint;
  type: 'user' | 'host';
  keyId: string;
  validPrincipals: string[];
  validAfter: bigint;
  validBefore: bigint;
  criticalOptions: Record<string, string>;
  extensions: Record<string, string>;
  nonce?: Uint8Array;
  signatureKey?: SshPublicKeyBlob;
  signature?: Uint8Array;
}

export function createCertificateData(params: CreateCertificateDataParams): Uint8Array {
  const {
    publicKey,
    keyType,
    serial,
    type,
    keyId,
    validPrincipals,
    validAfter,
    validBefore,
    criticalOptions,
    extensions,
    nonce,
    signatureKey,
    signature,
  } = params;

  const writer = new SshWriter();

  // Write certificate type
  const certType = keyType + '-cert-v01@openssh.com';
  writer.writeString(certType);

  // Write nonce
  const certNonce = nonce || new Uint8Array(32); // Use zero-filled array if no nonce provided
  writer.writeUint32(certNonce.length);
  writer.writeBytes(certNonce);

  // Write public key data based on key type
  if (keyType === 'ssh-ed25519') {
    // For Ed25519, extract the raw key data (skip type string and length)
    const publicKeyReader = new SshReader(publicKey.keyData);
    publicKeyReader.readString(); // Skip "ssh-ed25519"
    const keyLength = publicKeyReader.readUint32(); // Read length of key data
    const rawKeyData = publicKeyReader.readBytes(keyLength); // Read actual key data
    writer.writeUint32(rawKeyData.length);
    writer.writeBytes(rawKeyData);
  } else if (keyType === 'ssh-rsa') {
    // For RSA, extract e and n components
    const publicKeyReader = new SshReader(publicKey.keyData);
    publicKeyReader.readString(); // Skip "ssh-rsa"
    const e = publicKeyReader.readMpInt();
    const n = publicKeyReader.readMpInt();
    writer.writeUint32(e.length);
    writer.writeBytes(e);
    writer.writeUint32(n.length);
    writer.writeBytes(n);
  } else if (keyType.startsWith('ecdsa-sha2-')) {
    // For ECDSA, extract curve name and public point
    const publicKeyReader = new SshReader(publicKey.keyData);
    publicKeyReader.readString(); // Skip "ecdsa-sha2-nistp256" etc.
    const curveName = publicKeyReader.readString();
    const publicPoint = publicKeyReader.readMpInt();
    writer.writeString(curveName);
    writer.writeUint32(publicPoint.length);
    writer.writeBytes(publicPoint);
  } else {
    throw new UnsupportedKeyTypeError(keyType, [
      'ssh-ed25519',
      'ssh-rsa',
      'ecdsa-sha2-nistp256',
      'ecdsa-sha2-nistp384',
      'ecdsa-sha2-nistp521',
    ]);
  }

  // Write serial
  writer.writeUint64(serial);

  // Write type
  writer.writeUint32(type === 'user' ? 1 : 2);

  // Write key ID
  writer.writeString(keyId);

  // Write valid principals
  const principalsWriter = new SshWriter();
  for (const principal of validPrincipals) {
    principalsWriter.writeString(principal);
  }
  writer.writeUint32(principalsWriter.getOffset());
  writer.writeBytes(principalsWriter.toUint8Array());

  // Write validity period
  writer.writeUint64(validAfter);
  writer.writeUint64(validBefore);

  // Write critical options
  const optionsWriter = new SshWriter();
  for (const [name, value] of Object.entries(criticalOptions)) {
    optionsWriter.writeString(name);
    const valueBytes = encoder.encode(value);
    optionsWriter.writeUint32(valueBytes.length);
    optionsWriter.writeBytes(valueBytes);
  }
  writer.writeUint32(optionsWriter.getOffset());
  writer.writeBytes(optionsWriter.toUint8Array());

  // Write extensions
  const extensionsWriter = new SshWriter();
  for (const [name, value] of Object.entries(extensions)) {
    extensionsWriter.writeString(name);
    const valueBytes = encoder.encode(value);
    extensionsWriter.writeUint32(valueBytes.length);
    extensionsWriter.writeBytes(valueBytes);
  }
  writer.writeUint32(extensionsWriter.getOffset());
  writer.writeBytes(extensionsWriter.toUint8Array());

  // Write reserved (empty)
  writer.writeUint32(0);
  writer.writeBytes(new Uint8Array(0));

  // Write signature key (if provided)
  if (signatureKey) {
    writer.writeUint32(signatureKey.keyData.length);
    writer.writeBytes(signatureKey.keyData);
  }

  // Write signature (if provided)
  if (signature) {
    writer.writeUint32(signature.length);
    writer.writeBytes(signature);
  }

  return writer.toUint8Array();
}
