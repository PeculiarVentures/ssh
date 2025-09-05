import { describe, expect, it } from 'vitest';
import { rsaCertificate, testEd25519Cert } from '../../tests/utils/testFixtures';
import { getCrypto } from '../crypto';
import { SshPublicKey } from '../key/public_key';
import { SshCertificateBuilder } from './builder';
import { SshCertificate } from './certificate';

describe('SshCertificate', () => {
  it('should handle invalid certificate format gracefully', async () => {
    // Test with invalid certificate text
    await expect(SshCertificate.fromSSH('invalid')).rejects.toThrow();
  });

  it('should create certificate from valid blob', async () => {
    // Use a real certificate for testing
    const cert = await SshCertificate.fromSSH(rsaCertificate);
    const blob = cert.toBlob();

    // Create from blob and verify it's the same
    const certFromBlob = await SshCertificate.fromBlob(blob);
    expect(certFromBlob.toBlob()).toEqual(blob);
  });

  it('should expose certificate properties', async () => {
    const cert = await SshCertificate.fromSSH(rsaCertificate);

    // Test that properties are accessible
    expect(cert.keyId).toBeDefined();
    expect(cert.principals).toBeDefined();
    expect(cert.certType).toBeDefined();
    expect(cert.serial).toBeDefined();
    expect(cert.validAfter).toBeDefined();
    expect(cert.validBefore).toBeDefined();
    expect(cert.publicKey).toBeDefined();
    expect(cert.signatureKey).toBeDefined();
    expect(cert.criticalOptions).toBeDefined();
    expect(cert.extensions).toBeDefined();
    expect(cert.validate(new Date('2023-01-01T00:00:00Z'))).toBe(false);
    expect(cert.validate(cert.validAfter)).toBe(true); // validAfter should be valid
    expect(cert.validate(cert.validBefore)).toBe(true); // validBefore should be valid
  });

  it('should parse real SSH certificate correctly', async () => {
    // Expected values from ssh-keygen -L output for rsa.cert
    const expectedKeyId = 'test-user-rsa';
    const expectedType = 'user';
    const expectedSerial = 0n;
    const expectedPrincipals = ['testuser'];
    const expectedExtensions = {
      'permit-X11-forwarding': '',
      'permit-agent-forwarding': '',
      'permit-port-forwarding': '',
      'permit-pty': '',
      'permit-user-rc': '',
    };

    // Parse certificate
    const cert = await SshCertificate.fromSSH(rsaCertificate);

    // Test all fields
    expect(cert.keyId).toBe(expectedKeyId);
    expect(cert.certType).toBe(expectedType);
    expect(cert.serial).toBe(expectedSerial);
    expect(cert.principals).toEqual(expectedPrincipals);

    // Test extensions (values are empty strings for these extensions)
    const extensions = cert.extensions;
    expect(extensions).toEqual(expectedExtensions);

    // Test that dates are reasonable (should be around current time)
    const validAfter = cert.validAfter;
    const validBefore = cert.validBefore;
    expect(validAfter.getTime()).toBeGreaterThan(0);
    expect(validBefore.getTime()).toBeGreaterThan(validAfter.getTime());

    // Test that we can get public key and signature key
    const publicKey = cert.publicKey;
    expect(publicKey).toBeDefined();
    expect(publicKey.keyType).toBe('ssh-rsa');

    const signatureKey = cert.signatureKey;
    expect(signatureKey).toBeDefined();
    expect(signatureKey.keyType).toBe('ssh-ed25519');

    // Test critical options (should be empty)
    const criticalOptions = cert.criticalOptions;
    expect(criticalOptions).toEqual({});
  });

  it('should parse real Ed25519 SSH certificate correctly', async () => {
    // Expected values for Ed25519 certificate
    const expectedKeyId = 'test-user-ed25519';
    const expectedType = 'user';
    const expectedSerial = 0n;
    const expectedPrincipals = ['testuser'];
    const expectedExtensions = {
      'permit-X11-forwarding': '',
      'permit-agent-forwarding': '',
      'permit-port-forwarding': '',
      'permit-pty': '',
      'permit-user-rc': '',
    };

    // Parse certificate
    const cert = await SshCertificate.fromSSH(testEd25519Cert);

    // Test all fields
    expect(cert.keyId).toBe(expectedKeyId);
    expect(cert.certType).toBe(expectedType);
    expect(cert.serial).toBe(expectedSerial);
    expect(cert.principals).toEqual(expectedPrincipals);

    // Test extensions
    const extensions = cert.extensions;
    expect(extensions).toEqual(expectedExtensions);

    // Test that we can get public key
    const publicKey = cert.publicKey;
    expect(publicKey).toBeDefined();
    expect(publicKey.keyType).toBe('ssh-ed25519');

    // Test that we can get signature key
    const signatureKey = cert.signatureKey;
    expect(signatureKey).toBeDefined();
    expect(signatureKey.keyType).toBe('ssh-ed25519');

    // Test critical options (should be empty)
    const criticalOptions = cert.criticalOptions;
    expect(criticalOptions).toEqual({});
  });

  it('should verify RSA SHA-512 certificate', async () => {
    const crypto = getCrypto();

    // Generate RSA test keys
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['sign', 'verify'],
    );

    const caKeyPair = await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['sign', 'verify'],
    );

    // Create public keys
    const publicKey = await SshPublicKey.fromWebCrypto(keyPair.publicKey);
    const caPublicKey = await SshPublicKey.fromWebCrypto(caKeyPair.publicKey);

    // Create certificate builder
    const builder = new SshCertificateBuilder({
      publicKey,
      keyId: 'test-rsa-sha512-verify',
      validPrincipals: ['user@example.com'],
    });

    // Sign certificate with RSA SHA-512
    const certificate = await builder.sign({
      signatureKey: caPublicKey,
      privateKey: caKeyPair.privateKey,
      signatureAlgorithm: 'rsa-sha2-512',
    });

    // Verify signature
    const isValid = await certificate.verify(caPublicKey);
    expect(isValid).toBe(true);

    // Test with wrong CA key (should fail)
    const wrongCaKeyPair = await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['sign', 'verify'],
    );
    const wrongCaPublicKey = await SshPublicKey.fromWebCrypto(wrongCaKeyPair.publicKey);
    const isValidWrong = await certificate.verify(wrongCaPublicKey);
    expect(isValidWrong).toBe(false);
  });
});
