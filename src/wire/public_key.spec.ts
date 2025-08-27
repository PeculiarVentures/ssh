import { describe, expect, it } from 'vitest';
import { parsePublicKey, serializePublicKey } from './public_key';
import { SshWriter } from './writer';

describe('parsePublicKey', () => {
  it('should parse SSH public key string', () => {
    // Create a simple RSA-like key blob
    const writer = new SshWriter();
    writer.writeString('ssh-rsa',);
    writer.writeMpInt(new Uint8Array([0x00, 0x01, 0x02,],),); // e
    writer.writeMpInt(new Uint8Array([0x03, 0x04, 0x05,],),); // n
    const keyData = writer.toUint8Array();
    const base64 = btoa(String.fromCharCode(...keyData,),);
    const keyString = `ssh-rsa ${base64} user@example.com`;

    const result = parsePublicKey(keyString,);
    expect(result.type,).toBe('ssh-rsa',);
    expect(result.comment,).toBe('user@example.com',);
    expect(result.keyData,).toEqual(keyData,);
  },);

  it('should parse SSH public key without comment', () => {
    const writer = new SshWriter();
    writer.writeString('ssh-rsa',);
    writer.writeMpInt(new Uint8Array([0x00, 0x01,],),);
    writer.writeMpInt(new Uint8Array([0x02, 0x03,],),);
    const keyData = writer.toUint8Array();
    const base64 = btoa(String.fromCharCode(...keyData,),);
    const keyString = `ssh-rsa ${base64}`;

    const result = parsePublicKey(keyString,);
    expect(result.type,).toBe('ssh-rsa',);
    expect(result.comment,).toBeUndefined();
  },);

  it('should parse real Ed25519 SSH public key', () => {
    const realEd25519Key = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHIAzSy6yKCJDZA4Pbw/7Z4baapPp/DQeaN4dz8iFsNA test-ed25519';
    const result = parsePublicKey(realEd25519Key);
    expect(result.type).toBe('ssh-ed25519');
    expect(result.comment).toBe('test-ed25519');
    expect(result.keyData).toBeDefined();
    expect(result.keyData.length).toBeGreaterThan(0);
  });

  it('should parse real RSA SSH public key', () => {
    const realRsaKey = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCFXhvouwZBf0U7hdnx5+x1gKp881l6H3wODWuZEZvzxUbEOcR4Btuhe+ZpG7lu1CwdZXx+ViM/iD0EjRt3FMvwoo01FsU/OcQE9J1gK0v3iFMPCxc8kv71bs3twQa7oKxfkAqkL4iClg84YqR9aHJ+jYiBUMRxSPm1Yaip+FnQC3qOCF12Ks/mrnL4AA2VyxIWQz5bBX/oNSa/mjfOY883C3QxMWJKGH9WffCUuNFiyMBGI3ERNVmIyLn+kBTBNk/On5paJ49QBk97RIVCwgxUMX+8Z23kpfCx9xDOEK54Pt887dWa5QQcAvfWYBw8khtzVo+nGmUiRiqGpYVDzsmP test-rsa';
    const result = parsePublicKey(realRsaKey);
    expect(result.type).toBe('ssh-rsa');
    expect(result.comment).toBe('test-rsa');
    expect(result.keyData).toBeDefined();
    expect(result.keyData.length).toBeGreaterThan(0);
  });

  it('should parse real ECDSA P-256 SSH public key', () => {
    const realEcdsaP256Key = 'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHTUF2juGU/nt4CwHQzBDrvbjfgXFAYrAyN26etDYpKqzwU3kmdXfiCahNVwnWAGdRUc9JfTR32xqMs0Z9nAH4s= test-ecdsa-p256';
    const result = parsePublicKey(realEcdsaP256Key);
    expect(result.type).toBe('ecdsa-sha2-nistp256');
    expect(result.comment).toBe('test-ecdsa-p256');
    expect(result.keyData).toBeDefined();
    expect(result.keyData.length).toBeGreaterThan(0);
  });

  it('should parse real ECDSA P-384 SSH public key', () => {
    const realEcdsaP384Key = 'ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBC176k1WZa7m+d/2PASRpjWNXXmqM97j86PST4SGndlOWzq5VRAprvqsBAtCJ22yy7nkI1eycEH1z1MUmASENfI5TCI6At3akaUoVWih7xsy85QH2I5pyXo6UPt4U2sDuA== test-ecdsa-p384';
    const result = parsePublicKey(realEcdsaP384Key);
    expect(result.type).toBe('ecdsa-sha2-nistp384');
    expect(result.comment).toBe('test-ecdsa-p384');
    expect(result.keyData).toBeDefined();
    expect(result.keyData.length).toBeGreaterThan(0);
  });

  it('should parse real ECDSA P-521 SSH public key', () => {
    const realEcdsaP521Key = 'ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAH2XvyymGSIyDVMgqIiyeTlVZo4xKkCVt6PtMtoOUeLY6fNQXAJv5UP2/gPqWNKe2hbUQYtGGjB0nz/FIzJtbXrCADKmCwG35cEBDeJgskdptJksSCRAi46meA/NKR3hWcgcscCoY3vS92lH8gmFTTC0qoXn9ibYnCMXH8pqZ1/2k+IRw== test-ecdsa-p521';
    const result = parsePublicKey(realEcdsaP521Key);
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
    const base64 = btoa(String.fromCharCode(...keyData));
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
    const expectedBase64 = btoa(String.fromCharCode(...keyData));
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
    const expectedBase64 = btoa(String.fromCharCode(...keyData));
    expect(result).toBe(`ssh-rsa ${expectedBase64}`);
  });

  it('should round-trip real Ed25519 SSH public key', () => {
    const originalKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHIAzSy6yKCJDZA4Pbw/7Z4baapPp/DQeaN4dz8iFsNA test-ed25519';

    const parsed = parsePublicKey(originalKey);
    const serialized = serializePublicKey(parsed);

    expect(serialized).toBe(originalKey);
  });

  it('should round-trip real RSA SSH public key', () => {
    const originalKey = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCFXhvouwZBf0U7hdnx5+x1gKp881l6H3wODWuZEZvzxUbEOcR4Btuhe+ZpG7lu1CwdZXx+ViM/iD0EjRt3FMvwoo01FsU/OcQE9J1gK0v3iFMPCxc8kv71bs3twQa7oKxfkAqkL4iClg84YqR9aHJ+jYiBUMRxSPm1Yaip+FnQC3qOCF12Ks/mrnL4AA2VyxIWQz5bBX/oNSa/mjfOY883C3QxMWJKGH9WffCUuNFiyMBGI3ERNVmIyLn+kBTBNk/On5paJ49QBk97RIVCwgxUMX+8Z23kpfCx9xDOEK54Pt887dWa5QQcAvfWYBw8khtzVo+nGmUiRiqGpYVDzsmP test-rsa';

    const parsed = parsePublicKey(originalKey);
    const serialized = serializePublicKey(parsed);

    expect(serialized).toBe(originalKey);
  });

  it('should round-trip real ECDSA P-256 SSH public key', () => {
    const originalKey = 'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHTUF2juGU/nt4CwHQzBDrvbjfgXFAYrAyN26etDYpKqzwU3kmdXfiCahNVwnWAGdRUc9JfTR32xqMs0Z9nAH4s= test-ecdsa-p256';

    const parsed = parsePublicKey(originalKey);
    const serialized = serializePublicKey(parsed,);

    expect(serialized,).toBe(originalKey,);
  },);

  it('should round-trip real ECDSA P-384 SSH public key', () => {
    const originalKey = 'ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBC176k1WZa7m+d/2PASRpjWNXXmqM97j86PST4SGndlOWzq5VRAprvqsBAtCJ22yy7nkI1eycEH1z1MUmASENfI5TCI6At3akaUoVWih7xsy85QH2I5pyXo6UPt4U2sDuA== test-ecdsa-p384';

    const parsed = parsePublicKey(originalKey);
    const serialized = serializePublicKey(parsed);

    expect(serialized).toBe(originalKey);
  });

  it('should round-trip real ECDSA P-521 SSH public key', () => {
    const originalKey = 'ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAH2XvyymGSIyDVMgqIiyeTlVZo4xKkCVt6PtMtoOUeLY6fNQXAJv5UP2/gPqWNKe2hbUQYtGGjB0nz/FIzJtbXrCADKmCwG35cEBDeJgskdptJksSCRAi46meA/NKR3hWcgcscCoY3vS92lH8gmFTTC0qoXn9ibYnCMXH8pqZ1/2k+IRw== test-ecdsa-p521';

    const parsed = parsePublicKey(originalKey);
    const serialized = serializePublicKey(parsed);

    expect(serialized).toBe(originalKey);
  });
});
