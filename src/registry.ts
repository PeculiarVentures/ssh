import type { CryptoLike } from './crypto';
import { UnsupportedAlgorithmError } from './errors.js';
import type { ByteView, SshSignatureAlgo } from './types';
import type { SshPublicKeyBlob } from './wire/public_key';
import { SshReader } from './wire/reader';

export interface ImportPublicFromSshParams {
  blob: Uint8Array;
  crypto: CryptoLike;
}

export interface ExportPublicToSshParams {
  publicKey: CryptoKey;
  crypto: CryptoLike;
}

export interface ImportPublicSpkiParams {
  spki: ByteView;
  crypto: CryptoLike;
}

export interface ExportPublicSpkiParams {
  publicKey: CryptoKey;
  crypto: CryptoLike;
}

export interface ImportPrivatePkcs8Params {
  pkcs8: ByteView;
  crypto: CryptoLike;
}

export interface ExportPrivatePkcs8Params {
  privateKey: CryptoKey;
  crypto: CryptoLike;
}

export interface ExportPrivateToSshParams {
  privateKey: CryptoKey;
  publicKey?: CryptoKey;
  crypto: CryptoLike;
}

export interface ImportPrivateFromSshParams {
  sshKey: string;
  crypto: CryptoLike;
}

export interface SignParams {
  privateKey: CryptoKey;
  data: ByteView;
  crypto: CryptoLike;
  hash?: 'SHA-256' | 'SHA-512';
}

export interface VerifyParams {
  publicKey: CryptoKey;
  signature: ByteView;
  data: ByteView;
  crypto: CryptoLike;
  hash?: 'SHA-256' | 'SHA-512';
}

export interface EncodeSshSignatureParams {
  signature: ByteView;
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
  importPublicFromSsh(params: ImportPublicFromSshParams): Promise<CryptoKey>;
  exportPublicToSsh(params: ExportPublicToSshParams): Promise<Uint8Array>;

  importPublicSpki(params: ImportPublicSpkiParams): Promise<CryptoKey>;
  exportPublicSpki(params: ExportPublicSpkiParams): Promise<ArrayBuffer>;
  importPrivatePkcs8(params: ImportPrivatePkcs8Params): Promise<CryptoKey>;
  exportPrivatePkcs8(params: ExportPrivatePkcs8Params): Promise<ArrayBuffer>;
  importPrivateFromSsh(params: ImportPrivateFromSshParams): Promise<CryptoKey>;
  exportPrivateToSsh?(params: ExportPrivateToSshParams): Promise<Uint8Array>;

  sign(params: SignParams): Promise<ArrayBuffer>;
  verify(params: VerifyParams): Promise<boolean>;

  encodeSshSignature(params: EncodeSshSignatureParams): Uint8Array;
  decodeSshSignature(params: DecodeSshSignatureParams): DecodeSshSignatureResult;

  /**
   * Check if this binding supports the given WebCrypto CryptoKey
   */
  supportsCryptoKey(cryptoKey: CryptoKey): boolean;

  /**
   * Parse public key from certificate format
   * @param reader - SshReader positioned at public key data in certificate
   * @returns SshPublicKeyBlob in standard SSH format
   */
  parseCertificatePublicKey(reader: SshReader): SshPublicKeyBlob;

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
      throw new UnsupportedAlgorithmError(name);
    }
    return binding;
  }

  static register(name: string, binding: AlgorithmBinding): void {
    registry.set(name, binding);
  }

  /**
   * Get SSH key type that supports the given WebCrypto CryptoKey
   * @throws {UnsupportedAlgorithmError} When no algorithm supports the key
   */
  static getSshTypeFromCryptoKey(cryptoKey: CryptoKey): string {
    for (const [sshType, binding] of registry.entries()) {
      if (binding.supportsCryptoKey(cryptoKey)) {
        return sshType;
      }
    }
    throw new UnsupportedAlgorithmError(cryptoKey.algorithm.name);
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
