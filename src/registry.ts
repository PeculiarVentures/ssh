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
}

const registry = new Map<string, AlgorithmBinding>();

export class AlgorithmRegistry {
  static get(name: string): AlgorithmBinding | undefined {
    return registry.get(name);
  }

  static register(name: string, binding: AlgorithmBinding): void {
    registry.set(name, binding);
  }
}
