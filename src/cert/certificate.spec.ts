import { describe, expect, it } from 'vitest';
import { rsaCertificate, testEcdsaCert, testEd25519Cert } from '../../tests/utils/testFixtures';
import { SshCertificate } from './certificate';

describe('SshCertificate', () => {
  it('should handle invalid certificate format gracefully', async () => {
    // Test with invalid certificate text
    await expect(SshCertificate.fromText('invalid')).rejects.toThrow();
  });

  it('should create certificate from valid blob', async () => {
    // Create a minimal valid certificate blob for testing
    // This is a simplified test that doesn't require a full real certificate
    const certType = 'ssh-rsa-cert-v01@openssh.com';

    // Create minimal certificate data structure
    // This would normally be a properly formatted certificate
    const minimalCertData = new Uint8Array([
      // Certificate type string length (4 bytes)
      0,
      0,
      0,
      certType.length,
      // Certificate type string
      ...new TextEncoder().encode(certType),
      // Minimal certificate fields would follow...
    ]);

    const certBlob = {
      type: certType as any,
      keyData: minimalCertData,
    };

    // This test will help us understand what happens with minimal data
    const cert = await SshCertificate.fromBlob(certBlob);
    expect(cert).toBeDefined();
    expect(cert.toBlob()).toEqual(certBlob);
  });

  it('should expose certificate properties', async () => {
    // This test will be expanded once we have proper certificate parsing
    const certType = 'ssh-rsa-cert-v01@openssh.com';
    const minimalCertData = new Uint8Array([
      0,
      0,
      0,
      certType.length,
      ...new TextEncoder().encode(certType),
    ]);

    const certBlob = {
      type: certType as any,
      keyData: minimalCertData,
    };

    const cert = await SshCertificate.fromBlob(certBlob);

    // Test that async getters throw the expected error message
    await expect(cert.getKeyId()).rejects.toThrow('Failed to parse certificate data');
    await expect(cert.getPrincipals()).rejects.toThrow('Failed to parse certificate data');
    await expect(cert.getType()).rejects.toThrow('Failed to parse certificate data');
    await expect(cert.getSerial()).rejects.toThrow('Failed to parse certificate data');
    await expect(cert.getValidAfter()).rejects.toThrow('Failed to parse certificate data');
    await expect(cert.getValidBefore()).rejects.toThrow('Failed to parse certificate data');
    await expect(cert.getPublicKey()).rejects.toThrow('Failed to parse certificate data');
    await expect(cert.getSignatureKey()).rejects.toThrow('Failed to parse certificate data');
    await expect(cert.getCriticalOptions()).rejects.toThrow('Failed to parse certificate data');
    await expect(cert.getExtensions()).rejects.toThrow('Failed to parse certificate data');
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
    expect(await cert.getKeyId()).toBe(expectedKeyId);
    expect(await cert.getType()).toBe(expectedType);
    expect(await cert.getSerial()).toBe(expectedSerial);
    expect(await cert.getPrincipals()).toEqual(expectedPrincipals);

    // Test extensions (values are empty strings for these extensions)
    const extensions = await cert.getExtensions();
    expect(extensions).toEqual(expectedExtensions);

    // Test that dates are reasonable (should be around current time)
    const validAfter = await cert.getValidAfter();
    const validBefore = await cert.getValidBefore();
    expect(validAfter).toBeGreaterThan(0n);
    expect(validBefore).toBeGreaterThan(validAfter);

    // Test that we can get public key and signature key
    const publicKey = await cert.getPublicKey();
    expect(publicKey).toBeDefined();
    expect(publicKey.type).toBe('ssh-rsa');

    const signatureKey = await cert.getSignatureKey();
    expect(signatureKey).toBeDefined();
    expect(signatureKey.type).toBe('ssh-ed25519');

    // Test critical options (should be empty)
    const criticalOptions = await cert.getCriticalOptions();
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
    expect(await cert.getKeyId()).toBe(expectedKeyId);
    expect(await cert.getType()).toBe(expectedType);
    expect(await cert.getSerial()).toBe(expectedSerial);
    expect(await cert.getPrincipals()).toEqual(expectedPrincipals);

    // Test extensions
    const extensions = await cert.getExtensions();
    expect(extensions).toEqual(expectedExtensions);

    // Test that we can get public key
    const publicKey = await cert.getPublicKey();
    expect(publicKey).toBeDefined();
    expect(publicKey.type).toBe('ssh-ed25519');

    // Test that we can get signature key
    const signatureKey = await cert.getSignatureKey();
    expect(signatureKey).toBeDefined();
    expect(signatureKey.type).toBe('ssh-ed25519');

    // Test critical options (should be empty)
    const criticalOptions = await cert.getCriticalOptions();
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
    expect(await cert.getKeyId()).toBe(expectedKeyId);
    expect(await cert.getType()).toBe(expectedType);
    expect(await cert.getSerial()).toBe(expectedSerial);
    expect(await cert.getPrincipals()).toEqual(expectedPrincipals);

    // Test extensions
    const extensions = await cert.getExtensions();
    expect(extensions).toEqual(expectedExtensions);

    // Test that we can get public key
    const publicKey = await cert.getPublicKey();
    expect(publicKey).toBeDefined();
    expect(publicKey.type).toBe('ecdsa-sha2-nistp256');

    // Test that we can get signature key
    const signatureKey = await cert.getSignatureKey();
    expect(signatureKey).toBeDefined();
    expect(signatureKey.type).toBe('ssh-ed25519');

    // Test critical options (should be empty)
    const criticalOptions = await cert.getCriticalOptions();
    expect(criticalOptions).toEqual({});
  });
});
