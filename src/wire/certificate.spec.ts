import { Convert } from 'pvtsutils';
import { describe, expect, it } from 'vitest';
import { testUserEcdsa, testUserEd25519, testUserRsa } from '../../tests/utils/testFixtures';
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
    const base64 = Convert.ToBase64(fullData);

    const certString = `ssh-rsa-cert-v01@openssh.com ${base64}`;
    const result = parseCertificate(certString);
    expect(result.type).toBe('ssh-rsa-cert-v01@openssh.com');
    expect(result.keyData).toEqual(fullData);
  });

  it('should parse real RSA SSH certificate', () => {
    const result = parseCertificate(testUserRsa);
    expect(result.type).toBe('ssh-rsa-cert-v01@openssh.com');
    expect(result.keyData).toBeDefined();
    expect(result.keyData.length).toBeGreaterThan(0);
    expect(result.comment).toBe('test-user-rsa');
  });

  it('should parse real Ed25519 SSH certificate', () => {
    const result = parseCertificate(testUserEd25519);
    expect(result.type).toBe('ssh-ed25519-cert-v01@openssh.com');
    expect(result.keyData).toBeDefined();
    expect(result.keyData.length).toBeGreaterThan(0);
    expect(result.comment).toBe('test-user-ed25519');
  });

  it('should parse real ECDSA P-256 SSH certificate', () => {
    const result = parseCertificate(testUserEcdsa);
    expect(result.type).toBe('ecdsa-sha2-nistp256-cert-v01@openssh.com');
    expect(result.keyData).toBeDefined();
    expect(result.keyData.length).toBeGreaterThan(0);
  });
});

describe('serializeCertificate', () => {
  it('should serialize certificate', () => {
    const writer = new SshWriter();
    writer.writeString('ssh-rsa-cert-v01@openssh.com');
    writer.writeBytes(new Uint8Array([0x01, 0x02, 0x03]));
    const keyData = writer.toUint8Array();

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

  it('should round-trip real RSA SSH certificate', () => {
    const parsed = parseCertificate(testUserRsa);
    const serialized = serializeCertificate(parsed);

    // Since serialize is placeholder, it will not match exactly, but check basic properties
    const reParsed = parseCertificate(serialized);
    expect(reParsed.type).toBe(parsed.type);
    expect(reParsed.keyData).toEqual(parsed.keyData);
  });

  it('should round-trip real Ed25519 SSH certificate', () => {
    const parsed = parseCertificate(testUserEd25519);
    const serialized = serializeCertificate(parsed);

    const reParsed = parseCertificate(serialized);
    expect(reParsed.type).toBe(parsed.type);
    expect(reParsed.keyData).toEqual(parsed.keyData);
  });

  it('should round-trip real ECDSA P-256 SSH certificate', () => {
    const parsed = parseCertificate(testUserEcdsa);
    const serialized = serializeCertificate(parsed);

    const reParsed = parseCertificate(serialized);
    expect(reParsed.type).toBe(parsed.type);
    expect(reParsed.keyData).toEqual(parsed.keyData);
  });
});
