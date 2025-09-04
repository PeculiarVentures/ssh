import { describe, expect, it } from 'vitest';
import { getCrypto } from '../crypto';
import { SshPublicKey } from '../key/public_key';
import { SshCertificateBuilder } from './builder';
import { SshCertificate } from './certificate';

describe('SshCertificateBuilder', () => {
  const crypto = getCrypto();

  it('should create certificate builder', async () => {
    // Generate test key
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'Ed25519',
        namedCurve: 'Ed25519',
      },
      true,
      ['sign', 'verify'],
    );

    // Create SshPublicKey from WebCrypto key
    const publicKey = await SshPublicKey.fromWebCrypto(keyPair.publicKey);

    // Create certificate builder
    const builder = new SshCertificateBuilder({
      publicKey,
      keyId: 'test-cert',
      validPrincipals: ['user@example.com'],
    });

    expect(builder).toBeInstanceOf(SshCertificateBuilder);
  });

  it('should build certificate with Ed25519', async () => {
    // Generate test keys
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'Ed25519',
        namedCurve: 'Ed25519',
      },
      true,
      ['sign', 'verify'],
    );

    const caKeyPair = await crypto.subtle.generateKey(
      {
        name: 'Ed25519',
        namedCurve: 'Ed25519',
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
      keyId: 'test-cert',
      validPrincipals: ['user@example.com'],
      serial: 123n,
    });

    // Set validity period
    const now = BigInt(Math.floor(Date.now() / 1000));
    builder.setValidity(now, now + 86400n); // 24 hours

    // Add some extensions
    builder.addExtension('permit-X11-forwarding', '');
    builder.addExtension('permit-agent-forwarding', '');

    // Sign certificate
    const certificate = await builder.sign({
      signatureKey: caPublicKey,
      privateKey: caKeyPair.privateKey,
    });

    expect(certificate).toBeInstanceOf(SshCertificate);

    // Verify certificate properties
    expect(certificate.keyId).toBe('test-cert');

    expect(certificate.principals).toEqual(['user@example.com']);

    expect(certificate.serial).toBe(123n);

    expect(certificate.certType).toBe('user');

    // Verify signature
    const isValid = await certificate.verify(caPublicKey);
    expect(isValid).toBe(true);
  });

  it('should build certificate with ECDSA P-256', async () => {
    // Generate test keys
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      true,
      ['sign', 'verify'],
    );

    const caKeyPair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);

    // Create public keys
    const publicKey = await SshPublicKey.fromWebCrypto(keyPair.publicKey);
    const caPublicKey = await SshPublicKey.fromWebCrypto(caKeyPair.publicKey);

    // Create certificate builder
    const builder = new SshCertificateBuilder({
      publicKey,
      keyId: 'test-ecdsa-cert',
      validPrincipals: ['user@example.com'],
      serial: 456n,
    });

    // Set validity period
    const now = BigInt(Math.floor(Date.now() / 1000));
    builder.setValidity(now, now + 86400n); // 24 hours

    // Add some extensions
    builder.addExtension('permit-X11-forwarding', '');
    builder.addExtension('permit-agent-forwarding', '');

    // Sign certificate
    const certificate = await builder.sign({
      signatureKey: caPublicKey,
      privateKey: caKeyPair.privateKey,
    });

    expect(certificate).toBeInstanceOf(SshCertificate);

    // Verify certificate properties
    expect(certificate.keyId).toBe('test-ecdsa-cert');
    expect(certificate.principals).toEqual(['user@example.com']);
    expect(certificate.serial).toBe(456n);
    expect(certificate.certType).toBe('user');
    expect(certificate.publicKey.keyType).toBe('ecdsa-sha2-nistp256');

    // Verify signature
    const isValid = await certificate.verify(caPublicKey);
    expect(isValid).toBe(true);

    // Test round-trip: serialize and deserialize
    const certText = certificate.toText();
    const certFromText = await SshCertificate.fromText(certText);
    expect(certFromText.keyId).toBe('test-ecdsa-cert');
    expect(certFromText.publicKey.keyType).toBe('ecdsa-sha2-nistp256');
    const isValidRoundTrip = await certFromText.verify(caPublicKey);
    expect(isValidRoundTrip).toBe(true);
  });

  it('should build certificate with ECDSA P-384', async () => {
    // Generate test keys
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-384',
      },
      true,
      ['sign', 'verify'],
    );

    const caKeyPair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);

    // Create public keys
    const publicKey = await SshPublicKey.fromWebCrypto(keyPair.publicKey);
    const caPublicKey = await SshPublicKey.fromWebCrypto(caKeyPair.publicKey);

    // Create certificate builder
    const builder = new SshCertificateBuilder({
      publicKey,
      keyId: 'test-ecdsa-p384-cert',
      validPrincipals: ['user@example.com'],
    });

    // Sign certificate
    const certificate = await builder.sign({
      signatureKey: caPublicKey,
      privateKey: caKeyPair.privateKey,
    });

    expect(certificate.publicKey.keyType).toBe('ecdsa-sha2-nistp384');

    // Verify signature
    const isValid = await certificate.verify(caPublicKey);
    expect(isValid).toBe(true);
  });

  it('should build certificate with RSA SHA-512', async () => {
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
      keyId: 'test-rsa-sha512-cert',
      validPrincipals: ['user@example.com'],
      serial: 789n,
    });

    // Set validity period
    const now = BigInt(Math.floor(Date.now() / 1000));
    builder.setValidity(now, now + 86400n); // 24 hours

    // Sign certificate with RSA SHA-512
    const certificate = await builder.sign({
      signatureKey: caPublicKey,
      privateKey: caKeyPair.privateKey,
      signatureAlgorithm: 'rsa-sha2-512',
    });

    expect(certificate).toBeInstanceOf(SshCertificate);

    // Verify certificate properties
    expect(certificate.keyId).toBe('test-rsa-sha512-cert');
    expect(certificate.principals).toEqual(['user@example.com']);
    expect(certificate.serial).toBe(789n);
    expect(certificate.certType).toBe('user');
    expect(certificate.publicKey.keyType).toBe('ssh-rsa');

    // Verify signature
    const isValid = await certificate.verify(caPublicKey);
    expect(isValid).toBe(true);

    // Test round-trip: serialize and deserialize
    const certText = certificate.toText();
    const certFromText = await SshCertificate.fromText(certText);
    expect(certFromText.keyId).toBe('test-rsa-sha512-cert');
    expect(certFromText.publicKey.keyType).toBe('ssh-rsa');
    const isValidRoundTrip = await certFromText.verify(caPublicKey);
    expect(isValidRoundTrip).toBe(true);
  });
});
