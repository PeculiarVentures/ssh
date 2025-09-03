import { SshCertificateBuilder } from './cert/builder';
import { SshCertificate } from './cert/certificate';
import { getCrypto } from './crypto';
import { SshPrivateKey } from './key/private_key';
import { SshPublicKey } from './key/public_key';
import type { ByteView, SshKeyType } from './types';

export interface ImportOptions {
  format?: 'ssh' | 'pkcs8' | 'spki';
  type?: SshKeyType;
}

export interface KeyPairResult {
  privateKey: SshPrivateKey;
  publicKey: SshPublicKey;
}

export interface SshAlgorithm {
  name: string;
}

export interface RsaAlgorithm extends SshAlgorithm {
  name: 'rsa';
  modulusLength?: 2048 | 3072 | 4096;
}

export interface Ed25519Algorithm extends SshAlgorithm {
  name: 'ed25519';
}

export interface EcdsaAlgorithm extends SshAlgorithm {
  name: 'ecdsa-p256' | 'ecdsa-p384' | 'ecdsa-p521';
}

export type SshAlgorithmIdentifier = string | RsaAlgorithm | Ed25519Algorithm | EcdsaAlgorithm;

/**
 * Unified SSH API - provides convenient methods for working with SSH keys and certificates
 */
export class SSH {
  /**
   * Import SSH key or certificate with automatic format detection
   */
  static async import(
    data: string | ByteView,
    options: ImportOptions = {},
    crypto = getCrypto(),
  ): Promise<SshPrivateKey | SshPublicKey | SshCertificate> {
    const { format, type } = options;

    // If format is not specified, try to auto-detect
    if (!format) {
      const detectedFormat = SSH.detectFormat(data);
      return SSH.import(data, { ...options, format: detectedFormat }, crypto);
    }

    // Handle different formats
    switch (format) {
      case 'ssh':
        return SSH.importSshFormat(data as string, type, crypto);

      case 'pkcs8':
        if (!type) {
          throw new Error('Key type must be specified for PKCS#8 import');
        }
        return SshPrivateKey.importPrivatePkcs8(data as ByteView, type, crypto);

      case 'spki':
        if (!type) {
          throw new Error('Key type must be specified for SPKI import');
        }
        return SshPublicKey.importPublicSpki(data as ByteView, type, crypto);

      default:
        throw new Error(`Unsupported format: ${format}`);
    }
  }

  /**
   * Create a new SSH key pair
   */
  static async createKeyPair(
    algorithm: SshAlgorithmIdentifier,
    crypto = getCrypto(),
  ): Promise<KeyPairResult> {
    let keyPair: CryptoKeyPair;
    let sshType: SshKeyType;

    // Normalize algorithm to object form
    const alg = typeof algorithm === 'string' ? { name: algorithm } : algorithm;

    switch (alg.name) {
      case 'rsa': {
        const rsaAlg = alg as RsaAlgorithm;
        const modulusLength = rsaAlg.modulusLength ?? 2048;

        keyPair = await crypto.subtle.generateKey(
          {
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: 'SHA-256',
          },
          true,
          ['sign', 'verify'],
        );
        sshType = 'ssh-rsa';
        break;
      }

      case 'ed25519': {
        keyPair = await crypto.subtle.generateKey(
          {
            name: 'Ed25519',
            namedCurve: 'Ed25519',
          },
          true,
          ['sign', 'verify'],
        );
        sshType = 'ssh-ed25519';
        break;
      }

      case 'ecdsa-p256': {
        keyPair = await crypto.subtle.generateKey(
          {
            name: 'ECDSA',
            namedCurve: 'P-256',
          },
          true,
          ['sign', 'verify'],
        );
        sshType = 'ecdsa-sha2-nistp256';
        break;
      }

      case 'ecdsa-p384': {
        keyPair = await crypto.subtle.generateKey(
          {
            name: 'ECDSA',
            namedCurve: 'P-384',
          },
          true,
          ['sign', 'verify'],
        );
        sshType = 'ecdsa-sha2-nistp384';
        break;
      }

      case 'ecdsa-p521': {
        keyPair = await crypto.subtle.generateKey(
          {
            name: 'ECDSA',
            namedCurve: 'P-521',
          },
          true,
          ['sign', 'verify'],
        );
        sshType = 'ecdsa-sha2-nistp521';
        break;
      }

      default:
        throw new Error(`Unsupported algorithm: ${(alg as any).name}`);
    }

    const privateKey = await SshPrivateKey.fromWebCrypto(keyPair.privateKey, sshType);
    const publicKey = await SshPublicKey.fromWebCrypto(keyPair.publicKey, sshType, crypto);

    return { privateKey, publicKey };
  }

  /**
   * Create a certificate builder
   */
  static createCertificate(publicKey: SshPublicKey): SshCertificateBuilder {
    return new SshCertificateBuilder({ publicKey });
  }

  /**
   * Auto-detect format from data
   */
  private static detectFormat(data: string | ByteView): 'ssh' | 'pkcs8' | 'spki' {
    if (typeof data === 'string') {
      const trimmed = data.trim();

      // SSH certificate
      if (trimmed.includes('-cert-v01@openssh.com')) {
        return 'ssh';
      }

      // SSH private key
      if (trimmed.startsWith('-----BEGIN OPENSSH PRIVATE KEY-----')) {
        return 'ssh';
      }

      // SSH public key
      if (/^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp\d+)\s+/.test(trimmed)) {
        return 'ssh';
      }

      // PKCS#8 private key
      if (trimmed.startsWith('-----BEGIN PRIVATE KEY-----')) {
        return 'pkcs8';
      }

      // SPKI public key
      if (trimmed.startsWith('-----BEGIN PUBLIC KEY-----')) {
        return 'spki';
      }
    }

    // Binary data - assume PKCS#8 or SPKI based on content analysis
    // This is a simplified heuristic
    return 'pkcs8';
  }

  /**
   * Import SSH format (private key, public key, or certificate)
   */
  private static async importSshFormat(
    data: string,
    type?: SshKeyType,
    crypto = getCrypto(),
  ): Promise<SshPrivateKey | SshPublicKey | SshCertificate> {
    const trimmed = data.trim();

    // SSH certificate
    if (trimmed.includes('-cert-v01@openssh.com')) {
      return SshCertificate.fromText(data);
    }

    // SSH private key
    if (trimmed.startsWith('-----BEGIN OPENSSH PRIVATE KEY-----')) {
      return SshPrivateKey.importPrivateFromSsh(data);
    }

    // SSH public key
    if (/^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp\d+)\s+/.test(trimmed)) {
      return SshPublicKey.importPublicFromSsh(data, crypto);
    }

    throw new Error('Unable to detect SSH format type');
  }
}
