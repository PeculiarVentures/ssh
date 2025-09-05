import { Convert } from 'pvtsutils';
import { describe, expect, it } from 'vitest';
import { testUserEcdsa, testUserEd25519, testUserRsa } from '../../tests/utils/testFixtures';
import { getCrypto } from '../crypto';
import { AlgorithmRegistry } from '../registry';
import {
  parse as parseCertificate,
  parseCertificateData,
  serialize as serializeCertificate,
} from './certificate';
import { SshWriter } from './writer';

describe('parseCertificate', () => {
  const crypto = getCrypto();
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

  it('should parse certificate data and allow public key import', async () => {
    // Test RSA certificate
    const rsaCert = parseCertificate(testUserRsa);
    const rsaData = parseCertificateData(rsaCert.keyData);
    const rsaBinding = AlgorithmRegistry.get(rsaData.publicKey.type);
    const rsaKey = await rsaBinding.importPublicSsh({
      blob: rsaData.publicKey.keyData,
      crypto,
    });
    expect(rsaKey).toBeDefined();

    // Test Ed25519 certificate
    const ed25519Cert = parseCertificate(testUserEd25519);
    const ed25519Data = parseCertificateData(ed25519Cert.keyData);
    const ed25519Binding = AlgorithmRegistry.get(ed25519Data.publicKey.type);
    const ed25519Key = await ed25519Binding.importPublicSsh({
      blob: ed25519Data.publicKey.keyData,
      crypto,
    });
    expect(ed25519Key).toBeDefined();

    // Test ECDSA certificate
    const ecdsaCert = parseCertificate(testUserEcdsa);
    const ecdsaData = parseCertificateData(ecdsaCert.keyData);
    const ecdsaBinding = AlgorithmRegistry.get(ecdsaData.publicKey.type);
    const ecdsaKey = await ecdsaBinding.importPublicSsh({
      blob: ecdsaData.publicKey.keyData,
      crypto,
    });
    expect(ecdsaKey).toBeDefined();
  });

  it('should use AlgorithmRegistry for certificate type mapping', () => {
    // Test that certTypeToKeyType works correctly
    expect(AlgorithmRegistry.certTypeToKeyType('ssh-rsa-cert-v01@openssh.com')).toBe('ssh-rsa');
    expect(AlgorithmRegistry.certTypeToKeyType('ssh-ed25519-cert-v01@openssh.com')).toBe(
      'ssh-ed25519',
    );
    expect(AlgorithmRegistry.certTypeToKeyType('ecdsa-sha2-nistp256-cert-v01@openssh.com')).toBe(
      'ecdsa-sha2-nistp256',
    );
    expect(AlgorithmRegistry.certTypeToKeyType('unknown-cert-type')).toBeUndefined();
  });

  it('should use AlgorithmRegistry for certificate type generation', () => {
    // Test that bindings return correct certificate types
    const rsaBinding = AlgorithmRegistry.get('ssh-rsa');
    expect(rsaBinding.getCertificateType?.()).toBe('ssh-rsa-cert-v01@openssh.com');

    const ed25519Binding = AlgorithmRegistry.get('ssh-ed25519');
    expect(ed25519Binding.getCertificateType?.()).toBe('ssh-ed25519-cert-v01@openssh.com');

    const ecdsaBinding = AlgorithmRegistry.get('ecdsa-sha2-nistp256');
    expect(ecdsaBinding.getCertificateType?.()).toBe('ecdsa-sha2-nistp256-cert-v01@openssh.com');
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
