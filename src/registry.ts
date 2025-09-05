import { UnsupportedKeyTypeError } from './errors.js';
import type { SshSignatureAlgo } from './types';
import type { SshPublicKeyBlob } from './wire/public_key';
import { SshReader } from './wire/reader';
import { SshWriter } from './wire/writer';

export interface CommonAlgorithmParams {
  crypto: Crypto;
}

export interface ImportPublicFromSshParams extends CommonAlgorithmParams {
  blob: Uint8Array;
}

export interface ExportPublicToSshParams extends CommonAlgorithmParams {
  publicKey: CryptoKey;
}

export interface ImportPublicSpkiParams extends CommonAlgorithmParams {
  spki: Uint8Array;
}

export interface ExportPublicSpkiParams extends CommonAlgorithmParams {
  publicKey: CryptoKey;
}

export interface ImportPrivatePkcs8Params extends CommonAlgorithmParams {
  pkcs8: Uint8Array;
}

export interface ExportPrivatePkcs8Params extends CommonAlgorithmParams {
  privateKey: CryptoKey;
}

export interface ExportPrivateToSshParams extends CommonAlgorithmParams {
  privateKey: CryptoKey;
  publicKey?: CryptoKey;
  jwk?: JsonWebKey;
}

export interface ImportPrivateFromSshParams extends CommonAlgorithmParams {
  sshKey: string;
}

export interface SignParams extends CommonAlgorithmParams {
  privateKey: CryptoKey;
  data: Uint8Array;
  hash?: 'SHA-256' | 'SHA-512';
}

export interface VerifyParams extends CommonAlgorithmParams {
  publicKey: CryptoKey;
  signature: Uint8Array;
  data: Uint8Array;
  hash?: 'SHA-256' | 'SHA-512';
}

export interface EncodeSshSignatureParams {
  signature: Uint8Array;
  algo: SshSignatureAlgo;
}

export interface DecodeSshSignatureResult {
  signature: Uint8Array;
  algo: SshSignatureAlgo;
}

export interface DecodeSshSignatureParams {
  signature: Uint8Array;
}

export interface AlgorithmBinding {
  importPublicSsh(params: ImportPublicFromSshParams): Promise<CryptoKey>;
  exportPublicSsh(params: ExportPublicToSshParams): Promise<Uint8Array>;

  importPublicSpki(params: ImportPublicSpkiParams): Promise<CryptoKey>;
  exportPublicSpki(params: ExportPublicSpkiParams): Promise<Uint8Array>;
  importPrivatePkcs8(params: ImportPrivatePkcs8Params): Promise<CryptoKey>;
  exportPrivatePkcs8(params: ExportPrivatePkcs8Params): Promise<Uint8Array>;
  importPrivateSsh(params: ImportPrivateFromSshParams): Promise<CryptoKey>;
  exportPrivateSsh(params: ExportPrivateToSshParams): Promise<Uint8Array>;

  /**
   * Sign data using the private key
   * @param params - Parameters for signing
   * @returns Raw signature
   */
  sign(params: SignParams): Promise<Uint8Array>;
  /**
   * Verify data using the public key
   */
  verify(params: VerifyParams): Promise<boolean>;

  encodeSignature(params: EncodeSshSignatureParams): Uint8Array;
  decodeSignature(params: DecodeSshSignatureParams): DecodeSshSignatureResult;

  /**
   * Check if this binding supports the given WebCrypto CryptoKey
   */
  supportsCryptoKey(cryptoKey: CryptoKey): boolean;

  /**
   * Parse public key from certificate format
   * @param reader - SshReader positioned at public key data in certificate
   * @returns SshPublicKeyBlob in standard SSH format
   */
  parsePublicKey(reader: SshReader): SshPublicKeyBlob;

  /**
   * Write public key to certificate format
   * @param writer - SshWriter to write to
   * @param publicKey - SshPublicKeyBlob to serialize
   */
  writePublicKey(writer: SshWriter, publicKey: SshPublicKeyBlob): void;

  /**
   * Get certificate type for this algorithm
   * @returns Certificate type string (e.g., 'ssh-rsa-cert-v01@openssh.com')
   */
  getCertificateType(): string;

  /**
   * Get signature algorithm for this algorithm
   * @returns Signature algorithm string (e.g., 'ssh-ed25519', 'rsa-sha2-256')
   */
  getSignatureAlgo(): SshSignatureAlgo;
}

const registry = new Map<string, AlgorithmBinding>();

export class AlgorithmRegistry {
  static get(name: string): AlgorithmBinding {
    const binding = registry.get(name);
    if (!binding) {
      throw new UnsupportedKeyTypeError(name, Array.from(registry.keys()));
    }
    return binding;
  }

  static register(name: string, binding: AlgorithmBinding): void {
    registry.set(name, binding);
  }

  /**
   * Get SSH key type that supports the given WebCrypto CryptoKey
   * @throws {UnsupportedKeyTypeError} When no algorithm supports the key
   */
  static getSshTypeFromCryptoKey(cryptoKey: CryptoKey): string {
    for (const [sshType, binding] of registry.entries()) {
      if (binding.supportsCryptoKey(cryptoKey)) {
        return sshType;
      }
    }
    throw new UnsupportedKeyTypeError(cryptoKey.algorithm.name, Array.from(registry.keys()));
  }

  /**
   * Map certificate type to SSH key type
   * @param certType Certificate type (e.g., 'ssh-rsa-cert-v01@openssh.com')
   * @returns SSH key type (e.g., 'ssh-rsa') or undefined if not supported
   */
  static certTypeToKeyType(certType: string): string | undefined {
    const mapping: Record<string, string> = {
      'ssh-rsa-cert-v01@openssh.com': 'ssh-rsa',
      'ssh-ed25519-cert-v01@openssh.com': 'ssh-ed25519',
      'ecdsa-sha2-nistp256-cert-v01@openssh.com': 'ecdsa-sha2-nistp256',
      'ecdsa-sha2-nistp384-cert-v01@openssh.com': 'ecdsa-sha2-nistp384',
      'ecdsa-sha2-nistp521-cert-v01@openssh.com': 'ecdsa-sha2-nistp521',
    };
    return mapping[certType];
  }

  /**
   * Get supported certificate types
   * @returns Array of supported certificate types
   */
  static getSupportedCertTypes(): string[] {
    return Object.keys({
      'ssh-rsa-cert-v01@openssh.com': 'ssh-rsa',
      'ssh-ed25519-cert-v01@openssh.com': 'ssh-ed25519',
      'ecdsa-sha2-nistp256-cert-v01@openssh.com': 'ecdsa-sha2-nistp256',
      'ecdsa-sha2-nistp384-cert-v01@openssh.com': 'ecdsa-sha2-nistp384',
      'ecdsa-sha2-nistp521-cert-v01@openssh.com': 'ecdsa-sha2-nistp521',
    });
  }
}

// Import and register algorithms
import {
  EcdsaP256Binding,
  EcdsaP384Binding,
  EcdsaP521Binding,
  Ed25519Binding,
  RsaBinding,
} from './algorithms';

// Register Ed25519
AlgorithmRegistry.register('ssh-ed25519', new Ed25519Binding());

// Register RSA with different hashes
AlgorithmRegistry.register('ssh-rsa', new RsaBinding('SHA-256')); // For backward compatibility
AlgorithmRegistry.register('rsa-sha2-256', new RsaBinding('SHA-256'));
AlgorithmRegistry.register('rsa-sha2-512', new RsaBinding('SHA-512'));

// Register ECDSA
AlgorithmRegistry.register('ecdsa-sha2-nistp256', EcdsaP256Binding);
AlgorithmRegistry.register('ecdsa-sha2-nistp384', EcdsaP384Binding);
AlgorithmRegistry.register('ecdsa-sha2-nistp521', EcdsaP521Binding);
