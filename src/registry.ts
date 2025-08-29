import type { CryptoLike } from './crypto';
import type { ByteView, SshSignatureAlgo } from './types';

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

export interface SignParams {
  privateKey: CryptoKey;
  data: ByteView;
  crypto: CryptoLike;
}

export interface VerifyParams {
  publicKey: CryptoKey;
  signature: ByteView;
  data: ByteView;
  crypto: CryptoLike;
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

  sign(params: SignParams): Promise<ArrayBuffer>;
  verify(params: VerifyParams): Promise<boolean>;

  encodeSshSignature(params: EncodeSshSignatureParams): Uint8Array;
  decodeSshSignature(params: DecodeSshSignatureParams): DecodeSshSignatureResult;

  /**
   * Check if this binding supports the given WebCrypto CryptoKey
   */
  supportsCryptoKey(cryptoKey: CryptoKey): boolean;
}

const registry = new Map<string, AlgorithmBinding>();

export class AlgorithmRegistry {
  static get(name: string): AlgorithmBinding | undefined {
    return registry.get(name);
  }

  static register(name: string, binding: AlgorithmBinding): void {
    registry.set(name, binding);
  }

  /**
   * Get SSH key type that supports the given WebCrypto CryptoKey
   */
  static getSshTypeFromCryptoKey(cryptoKey: CryptoKey): string | undefined {
    for (const [sshType, binding] of registry.entries()) {
      if (binding.supportsCryptoKey(cryptoKey)) {
        return sshType;
      }
    }
    return undefined;
  }
}

// Import and register algorithms
import { Ed25519Binding } from './algorithms/ed25519';
import { RsaBinding } from './algorithms/rsa';

// Register Ed25519
AlgorithmRegistry.register('ssh-ed25519', new Ed25519Binding());

// Register RSA
AlgorithmRegistry.register('ssh-rsa', new RsaBinding());
