import type { ByteView, SshKeyType } from '../types';
import { SshReader } from './reader';
import { SshWriter } from './writer';

export interface SshCertificateBlob {
  // Placeholder - will be expanded with certificate fields
  type: SshKeyType;
  keyData: Uint8Array;
}

export function parse(input: ByteView | string,): SshCertificateBlob {
  // Placeholder implementation
  let data: Uint8Array;
  if (typeof input === 'string') {
    data = Uint8Array.from(atob(input), (c) => c.charCodeAt(0));
  } else if (input instanceof ArrayBuffer) {
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

export function serialize(cert: SshCertificateBlob): Uint8Array {
  // Placeholder implementation
  const writer = new SshWriter();
  writer.writeString(cert.type);
  writer.writeBytes(cert.keyData);
  return writer.toUint8Array();
}
