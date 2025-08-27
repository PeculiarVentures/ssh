export type ByteView = ArrayBuffer | Uint8Array;

export type Dict<T = unknown> = Record<string, T>;

export type SshKeyType =
  | 'ssh-ed25519'
  | 'ssh-rsa'
  | 'ecdsa-sha2-nistp256'
  | 'ecdsa-sha2-nistp384'
  | 'ecdsa-sha2-nistp521'
  | 'ssh-ed25519-cert-v01@openssh.com'
  | 'ssh-rsa-cert-v01@openssh.com'
  | 'ecdsa-sha2-nistp256-cert-v01@openssh.com'
  | 'ecdsa-sha2-nistp384-cert-v01@openssh.com'
  | 'ecdsa-sha2-nistp521-cert-v01@openssh.com';

export type SshSignatureAlgo =
  | 'ssh-ed25519'
  | 'rsa-sha2-256'
  | 'rsa-sha2-512'
  | 'ecdsa-sha2-nistp256'
  | 'ecdsa-sha2-nistp384'
  | 'ecdsa-sha2-nistp521';
