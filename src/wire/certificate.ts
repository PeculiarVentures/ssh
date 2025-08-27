import type { ByteView, SshKeyType } from '../types';
import { SshReader } from './reader';

export interface SshCertificateBlob {
  type: SshKeyType;
  keyData: Uint8Array;
  comment?: string;
}

export function parse(input: ByteView | string,): SshCertificateBlob {
  if (typeof input === 'string') {
    const parts = input.trim().split(/\s+/);
    if (parts.length < 2) {
      throw new Error('Invalid SSH certificate format');
    }

    const type = parts[0] as SshKeyType;
    const blob = Uint8Array.from(atob(parts[1]), (c) => c.charCodeAt(0));
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

export function serialize(cert: SshCertificateBlob): string {
  const base64 = btoa(String.fromCharCode(...cert.keyData));
  const parts = [cert.type, base64];
  if (cert.comment) {
    parts.push(cert.comment);
  }
  return parts.join(' ');
}
