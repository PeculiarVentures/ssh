<h1 align="center">
  @peculiar/ssh
</h1>

<div align="center">

![NPM License](https://img.shields.io/npm/l/@peculiar/ssh)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/PeculiarVentures/ssh/publish.yml?branch=main&label=publish)
[![npm version](https://img.shields.io/npm/v/@peculiar/ssh.svg)](https://www.npmjs.com/package/@peculiar/ssh)
![Coveralls](https://img.shields.io/coverallsCoverage/github/PeculiarVentures/ssh)
[![npm downloads](https://img.shields.io/npm/dm/@peculiar/ssh.svg)](https://www.npmjs.com/package/@peculiar/ssh)

</div>

A TypeScript library for working with SSH keys and certificates in both Node.js and browsers, built on top of WebCrypto. Provides parsing, serialization, conversion (SPKI/PKCS8 ↔ SSH), and certificate signing/verification with an extensible algorithm registry.

## Features

- 🔑 Generate RSA, ECDSA, and Ed25519 keys
- 🔐 Convert between SSH and WebCrypto formats (SPKI / PKCS8)
- ✍️ Create and verify SSH signatures
- 📜 Parse and build SSH certificates
- 🌐 Works in both browsers and Node.js

## Installation

```bash
npm install @peculiar/ssh
```

The package is ESM-only with TypeScript declarations, and requires Node.js `^20.19.0 || >=22.12.0`. CommonJS code can still `require()` it on those versions.

## Breaking Changes In v3

v3 ships ESM only. The CommonJS build is removed: v2 published `build/index.js` (CommonJS), `build/index.mjs` (ESM), `build/index.d.ts` and `build/index.d.mts`; v3 publishes ES modules only, with `build/index.js` and `build/index.d.ts` as the entry point behind an `exports` map. The other files under `build/` mirror `src/` and are internal.

- **Node.js `^20.19.0 || >=22.12.0` is required** (previously `>=20.0.0`). These versions support `require()` of ES modules, so CommonJS code can keep using `require("@peculiar/ssh")` without changes. **Node.js 20.0–20.18 is no longer supported**, and Node.js 22.0–22.11 is not supported either: neither can `require()` ESM.
- **TypeScript projects that compile to CommonJS** need `"module": "node20"` or `"nodenext"` (TypeScript 5.9+). With `"module": "node16"` the compiler reports TS1479.
- **ESM and bundler setups** (`"module": "preserve"`, `"moduleResolution": "bundler"`) work without changes.
- **Legacy `"moduleResolution": "node"` (node10)** resolves the package through `types`; `@peculiar/ssh` has no subpath exports, so nothing else changes.
- **Jest in CommonJS mode** can't load ESM packages. Use Jest's ESM mode, add `@peculiar/ssh` and `@peculiar/utils` to the `transformIgnorePatterns` exceptions, or switch to Vitest.
- **Deep imports stay blocked.** The `exports` map allows only `@peculiar/ssh` and `@peculiar/ssh/package.json`, as in v2.
- **`@peculiar/utils` ^4.** The runtime dependency moved from `@peculiar/utils` ^3 to ^4, which is ESM-only as well. Nothing in the `@peculiar/ssh` API changes.
- **`require()` and `import` share one algorithm registry and crypto provider.** v2 shipped separate CommonJS and ESM copies, so an application that loaded both (for example ESM code plus a CommonJS dependency) got two `AlgorithmRegistry` instances and two `setCrypto()` providers: a binding registered or a provider set through one copy was invisible to the other. v3 has a single module, so both load the same state.

The public API is unchanged; only packaging and runtime requirements changed.

## Quick Start

### Generate Keys

```ts
import { SSH } from "@peculiar/ssh";

// RSA 2048
const rsa = await SSH.createKeyPair({ name: "rsa", modulusLength: 2048 });

// Ed25519
const ed = await SSH.createKeyPair("ed25519");

// ECDSA P-256
const ec = await SSH.createKeyPair("ecdsa-p256");
```

### Export and Import

```ts
// Export to SSH format
const sshPublic = await rsa.publicKey.toSSH();

// Import from SSH format
const imported = await SSH.import(sshPublic);
```

### Signing and Verifying

```ts
const data = new Uint8Array([1, 2, 3]);

// Create SSH signature
const signature = await SSH.sign("ssh-ed25519", ed.privateKey, data, {
  format: "ssh-signature",
});

// Verify SSH signature
const isValid = await SSH.verify(ed.publicKey, signature, data);
console.log("Signature valid:", isValid);
```

### Certificates

```ts
// Create a certificate
const cert = await SSH.createCertificate(ed.publicKey)
  .setKeyId("user@example.com")
  .addPrincipal("user@example.com")
  .setType("user")
  .setValidity(Date.now(), Date.now() + 365 * 24 * 60 * 60 * 1000)
  .sign({
    signatureKey: rsa.publicKey,
    privateKey: await rsa.privateKey.toWebCrypto(),
  });

// Verify certificate
const valid = await cert.verify(rsa.publicKey);
```

## Supported Algorithms

- **RSA** - Key sizes: 2048, 3072, 4096 bits with SHA-256/SHA-512 hash selection at signing
- **Ed25519** - Modern elliptic curve signature scheme
- **ECDSA** - P-256, P-384, P-521 curves with SHA-256/SHA-384/SHA-512

## Platform Support

This library works in all modern browsers that support WebCrypto API and in Node.js `^20.19.0 || >=22.12.0`. The Node.js column shows when each WebCrypto feature first appeared in Node.js. Here's the compatibility matrix:

| Feature           | Chrome | Edge | Firefox | Safari | Opera | Chrome Android | Firefox Android | Safari iOS | Node.js |
| ----------------- | ------ | ---- | ------- | ------ | ----- | -------------- | --------------- | ---------- | ------- |
| **WebCrypto API** | 37+    | 79+  | 34+     | 7+     | 24+   | 37+            | 34+             | 7+         | 15.0+   |
| **RSA, ECDSA**    | 37+    | 79+  | 34+     | 7+     | 24+   | 37+            | 34+             | 7+         | 15.0+   |
| **Ed25519**       | 137+   | 137+ | 129+    | 17+    | 121+  | 137+           | 129+            | 17+        | 16.17+  |

For older browsers, you may need to provide a WebCrypto polyfill.

**Note:** Ed25519 support was added to major browsers relatively recently. For broader compatibility, consider using ECDSA or RSA algorithms.

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for development setup, coding standards, and contribution guidelines.

## License

MIT License - see LICENSE file for details.
