# Test Fixtures

This directory contains real SSH files used for testing the SSH library. Instead of hardcoding test data as strings in TypeScript files, we store actual SSH keys and certificates as files for better maintainability and realism.

## Usage

The fixtures are loaded by `tests/utils/testFixtures.ts` which provides:

- Individual exports for each key/certificate
- Helper functions like `getAllKeys()` and `getAllCertificates()`
- PKCS#8 encoded private keys for testing private key import

## Generating New Fixtures

1. Generate SSH keys using standard tools:

   ```bash
   # RSA key
   ssh-keygen -t rsa -b 2048 -f rsa -N ""

   # Ed25519 key
   ssh-keygen -t ed25519 -f ed25519 -N ""

   # ECDSA keys
   ssh-keygen -t ecdsa -b 256 -f ecdsa-p256 -N ""
   ssh-keygen -t ecdsa -b 384 -f ecdsa-p384 -N ""
   ssh-keygen -t ecdsa -b 521 -f ecdsa-p521 -N ""
   ```

2. Convert private keys to PKCS#8 format:

   ```bash
   ssh-keygen -p -f rsa -m pkcs8 -N ""
   ssh-keygen -p -f ed25519 -m pkcs8 -N ""
   ssh-keygen -p -f ecdsa-p256 -m pkcs8 -N ""
   ssh-keygen -p -f ecdsa-p384 -m pkcs8 -N ""
   ssh-keygen -p -f ecdsa-p521 -m pkcs8 -N ""
   ```

3. Generate certificates using `ssh-keygen` with certificate options:

   ```bash
   # Create a certificate
   ssh-keygen -s ca_key -I "test-cert" -n "testuser" -V "+52w" user_key.pub
   ```

4. Copy the generated `.pub` files and certificate files directly to `fixtures/`

5. Update `testFixtures.ts` if needed to include new fixtures

## Benefits

- **Realism**: Tests use actual SSH files as they would in production
- **Maintainability**: Easy to add new test cases by generating real keys/certificates
- **No duplication**: Single source of truth for test data
- **Flexibility**: Can easily generate edge cases or specific formats
- **Security**: Private keys are stored in PKCS#8 format for compatibility with WebCrypto
