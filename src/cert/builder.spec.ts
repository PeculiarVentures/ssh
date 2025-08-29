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
    const keyId = await certificate.getKeyId();
    expect(keyId).toBe('test-cert');

    const principals = await certificate.getPrincipals();
    expect(principals).toEqual(['user@example.com']);

    const serial = await certificate.getSerial();
    expect(serial).toBe(123n);

    const type = await certificate.getType();
    expect(type).toBe('user');

    // Verify signature
    const isValid = await certificate.verify(caPublicKey);
    expect(isValid).toBe(true);
  });

  it('should preview certificate blob', async () => {
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
      keyId: 'preview-test',
    });

    // Preview blob
    const blob = await builder.previewBlob();

    expect(blob).toBeInstanceOf(Uint8Array);
    expect(blob.length).toBeGreaterThan(0);
  });
});
