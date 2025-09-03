import { describe, expect, it } from 'vitest';
import { rsaCertificate, testEcdsaCert, testEd25519Cert } from '../../tests/utils/testFixtures';
import { SshCertificate } from './certificate';

describe('SshCertificate', () => {
  it('should handle invalid certificate format gracefully', async () => {
    // Test with invalid certificate text
    await expect(SshCertificate.fromText('invalid')).rejects.toThrow();
  });

  it('should create certificate from valid blob', async () => {
    // Use a real certificate for testing
    const cert = await SshCertificate.fromText(rsaCertificate);
    const blob = cert.toBlob();

    // Create from blob and verify it's the same
    const certFromBlob = await SshCertificate.fromBlob(blob);
    expect(certFromBlob.toBlob()).toEqual(blob);
  });

  it('should expose certificate properties', async () => {
    const cert = await SshCertificate.fromText(rsaCertificate);

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
    const cert = await SshCertificate.fromText(rsaCertificate);

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
    expect(publicKey.type).toBe('ssh-rsa');

    const signatureKey = cert.signatureKey;
    expect(signatureKey).toBeDefined();
    expect(signatureKey.type).toBe('ssh-ed25519');

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
    const cert = await SshCertificate.fromText(testEd25519Cert);

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
    expect(publicKey.type).toBe('ssh-ed25519');

    // Test that we can get signature key
    const signatureKey = cert.signatureKey;
    expect(signatureKey).toBeDefined();
    expect(signatureKey.type).toBe('ssh-ed25519');

    // Test critical options (should be empty)
    const criticalOptions = cert.criticalOptions;
    expect(criticalOptions).toEqual({});
  });

  it('should parse real ECDSA P-256 SSH certificate correctly', async () => {
    // Expected values for ECDSA certificate
    const expectedKeyId = 'test-user-ecdsa';
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
    const cert = await SshCertificate.fromText(testEcdsaCert);

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
    expect(publicKey.type).toBe('ecdsa-sha2-nistp256');

    // Test that we can get signature key
    const signatureKey = cert.signatureKey;
    expect(signatureKey).toBeDefined();
    expect(signatureKey.type).toBe('ssh-ed25519');

    // Test critical options (should be empty)
    const criticalOptions = cert.criticalOptions;
    expect(criticalOptions).toEqual({});
  });
});
