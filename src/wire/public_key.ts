import { Convert } from 'pvtsutils';
import type { SshKeyType } from '../types';
import { SshReader } from './reader';

export interface SshPublicKeyBlob {
  type: SshKeyType;
  keyData: Uint8Array;
  comment?: string;
}

export function parsePublicKey(input: string | Uint8Array): SshPublicKeyBlob {
  const parts = typeof input === 'string' ? input.trim().split(/\s+/) : null;
  if (!parts || parts.length < 2) {
    throw new Error('Invalid SSH public key format');
  }

  const type = parts[0] as SshKeyType;
  const blob = new Uint8Array(Convert.FromBase64(parts[1]));
  const comment = parts.length > 2 ? parts.slice(2).join(' ') : undefined;

  // Validate blob
  const reader = new SshReader(blob);
  const blobType = reader.readString();
  if (blobType !== type) {
    throw new Error('Key type mismatch');
  }

  return {
    type,
    keyData: blob,
    comment,
  };
}

export function serializePublicKey(blob: SshPublicKeyBlob): string {
  const base64 = Convert.ToBase64(blob.keyData);
  const parts = [blob.type, base64];
  if (blob.comment) {
    parts.push(blob.comment);
  }
  return parts.join(' ');
}
