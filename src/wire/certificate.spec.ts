import { describe, expect, it } from 'vitest';
import { parse as parseCertificate, serialize as serializeCertificate } from './certificate';
import { SshWriter } from './writer';

describe('parseCertificate', () => {
  it('should parse certificate from Uint8Array', () => {
    const writer = new SshWriter();
    writer.writeString('ssh-rsa-cert-v01@openssh.com');
    writer.writeBytes(new Uint8Array([0x01, 0x02, 0x03]));
    const fullData = writer.toUint8Array();
    const keyData = new Uint8Array([0x01, 0x02, 0x03]);

    const result = parseCertificate(fullData);
    expect(result.type).toBe('ssh-rsa-cert-v01@openssh.com');
    expect(result.keyData).toEqual(keyData);
  });

  it('should parse certificate from base64 string', () => {
    const writer = new SshWriter();
    writer.writeString('ssh-rsa-cert-v01@openssh.com');
    writer.writeBytes(new Uint8Array([0x01, 0x02, 0x03]));
    const fullData = writer.toUint8Array();
    const base64 = btoa(String.fromCharCode(...fullData));
    const keyData = new Uint8Array([0x01, 0x02, 0x03]);

    const result = parseCertificate(base64);
    expect(result.type).toBe('ssh-rsa-cert-v01@openssh.com');
    expect(result.keyData).toEqual(keyData);
  });
});

describe('serializeCertificate', () => {
  it('should serialize certificate', () => {
    const keyData = new Uint8Array([0x01, 0x02, 0x03]);
    const cert = {
      type: 'ssh-rsa-cert-v01@openssh.com' as const,
      keyData,
    };

    const result = serializeCertificate(cert);

    // Verify the result by parsing it back
    const parsed = parseCertificate(result);
    expect(parsed.type).toBe(cert.type);
    expect(parsed.keyData).toEqual(cert.keyData);
  });
});
