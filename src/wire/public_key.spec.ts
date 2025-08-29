import { Convert } from 'pvtsutils';
import { describe, expect, it } from 'vitest';
import {
  ecdsaP256Key,
  ecdsaP384Key,
  ecdsaP521Key,
  ed25519Key,
  rsaKey,
} from '../../tests/utils/testFixtures';
import { parsePublicKey, serializePublicKey } from './public_key';
import { SshWriter } from './writer';

describe('parsePublicKey', () => {
  it('should parse SSH public key string', () => {
    // Create a simple RSA-like key blob
    const writer = new SshWriter();
    writer.writeString('ssh-rsa');
    writer.writeMpInt(new Uint8Array([0x00, 0x01, 0x02])); // e
    writer.writeMpInt(new Uint8Array([0x03, 0x04, 0x05])); // n
    const keyData = writer.toUint8Array();
    const base64 = Convert.ToBase64(keyData);
    const keyString = `ssh-rsa ${base64} user@example.com`;

    const result = parsePublicKey(keyString);
    expect(result.type).toBe('ssh-rsa');
    expect(result.comment).toBe('user@example.com');
    expect(result.keyData).toEqual(keyData);
  });

  it('should parse SSH public key without comment', () => {
    const writer = new SshWriter();
    writer.writeString('ssh-rsa');
    writer.writeMpInt(new Uint8Array([0x00, 0x01]));
    writer.writeMpInt(new Uint8Array([0x02, 0x03]));
    const keyData = writer.toUint8Array();
    const base64 = Convert.ToBase64(keyData);
    const keyString = `ssh-rsa ${base64}`;

    const result = parsePublicKey(keyString);
    expect(result.type).toBe('ssh-rsa');
    expect(result.comment).toBeUndefined();
  });

  it('should parse real Ed25519 SSH public key', () => {
    const result = parsePublicKey(ed25519Key);
    expect(result.type).toBe('ssh-ed25519');
    expect(result.comment).toBe('test-ed25519');
    expect(result.keyData).toBeDefined();
    expect(result.keyData.length).toBeGreaterThan(0);
  });

  it('should parse real RSA SSH public key', () => {
    const result = parsePublicKey(rsaKey);
    expect(result.type).toBe('ssh-rsa');
    expect(result.comment).toBe('test-rsa');
    expect(result.keyData).toBeDefined();
    expect(result.keyData.length).toBeGreaterThan(0);
  });

  it('should parse real ECDSA P-256 SSH public key', () => {
    const result = parsePublicKey(ecdsaP256Key);
    expect(result.type).toBe('ecdsa-sha2-nistp256');
    expect(result.comment).toBe('test-ecdsa-p256');
    expect(result.keyData).toBeDefined();
    expect(result.keyData.length).toBeGreaterThan(0);
  });

  it('should parse real ECDSA P-384 SSH public key', () => {
    const result = parsePublicKey(ecdsaP384Key);
    expect(result.type).toBe('ecdsa-sha2-nistp384');
    expect(result.comment).toBe('test-ecdsa-p384');
    expect(result.keyData).toBeDefined();
    expect(result.keyData.length).toBeGreaterThan(0);
  });

  it('should parse real ECDSA P-521 SSH public key', () => {
    const result = parsePublicKey(ecdsaP521Key);
    expect(result.type).toBe('ecdsa-sha2-nistp521');
    expect(result.comment).toBe('test-ecdsa-p521');
    expect(result.keyData).toBeDefined();
    expect(result.keyData.length).toBeGreaterThan(0);
  });

  it('should throw on invalid format', () => {
    expect(() => parsePublicKey('invalid')).toThrow('Invalid SSH public key format');
  });

  it('should throw on type mismatch', () => {
    const writer = new SshWriter();
    writer.writeString('ssh-dss'); // different type in blob
    const keyData = writer.toUint8Array();
    const base64 = Convert.ToBase64(keyData);
    const keyString = `ssh-rsa ${base64}`;

    expect(() => parsePublicKey(keyString)).toThrow('Key type mismatch');
  });
});

describe('serializePublicKey', () => {
  it('should serialize public key with comment', () => {
    const writer = new SshWriter();
    writer.writeString('ssh-rsa');
    writer.writeMpInt(new Uint8Array([0x00, 0x01]));
    writer.writeMpInt(new Uint8Array([0x02, 0x03]));
    const keyData = writer.toUint8Array();

    const blob = {
      type: 'ssh-rsa' as const,
      keyData,
      comment: 'user@example.com',
    };

    const result = serializePublicKey(blob);
    const expectedBase64 = Convert.ToBase64(keyData);
    expect(result).toBe(`ssh-rsa ${expectedBase64} user@example.com`);
  });

  it('should serialize public key without comment', () => {
    const writer = new SshWriter();
    writer.writeString('ssh-rsa');
    writer.writeMpInt(new Uint8Array([0x00, 0x01]));
    writer.writeMpInt(new Uint8Array([0x02, 0x03]));
    const keyData = writer.toUint8Array();

    const blob = {
      type: 'ssh-rsa' as const,
      keyData,
    };

    const result = serializePublicKey(blob);
    const expectedBase64 = Convert.ToBase64(keyData);
    expect(result).toBe(`ssh-rsa ${expectedBase64}`);
  });

  it('should round-trip real Ed25519 SSH public key', () => {
    const parsed = parsePublicKey(ed25519Key);
    const serialized = serializePublicKey(parsed);

    expect(serialized).toBe(ed25519Key);
  });

  it('should round-trip real RSA SSH public key', () => {
    const parsed = parsePublicKey(rsaKey);
    const serialized = serializePublicKey(parsed);

    expect(serialized).toBe(rsaKey);
  });

  it('should round-trip real ECDSA P-256 SSH public key', () => {
    const parsed = parsePublicKey(ecdsaP256Key);
    const serialized = serializePublicKey(parsed);

    expect(serialized).toBe(ecdsaP256Key);
  });

  it('should round-trip real ECDSA P-384 SSH public key', () => {
    const parsed = parsePublicKey(ecdsaP384Key);
    const serialized = serializePublicKey(parsed);

    expect(serialized).toBe(ecdsaP384Key);
  });

  it('should round-trip real ECDSA P-521 SSH public key', () => {
    const parsed = parsePublicKey(ecdsaP521Key);
    const serialized = serializePublicKey(parsed);

    expect(serialized).toBe(ecdsaP521Key);
  });
});
