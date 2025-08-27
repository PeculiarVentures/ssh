# Test Fixtures

This directory contains real SSH files used for testing the SSH library. Instead of hardcoding test data as strings in TypeScript files, we store actual SSH keys and certificates as files for better maintainability and realism.

## Structure

```
fixtures/
├── README.md
├── rsa.pub                    # RSA public key
├── ed25519.pub               # Ed25519 public key
├── ecdsa-p256.pub           # ECDSA P-256 public key
├── ecdsa-p384.pub           # ECDSA P-384 public key
├── ecdsa-p521.pub           # ECDSA P-521 public key
├── rsa.cert                  # RSA certificate
├── ed25519.cert             # Ed25519 certificate
├── ecdsa-p256.cert          # ECDSA P-256 certificate
├── test-cert-new.cert       # Additional test certificate
├── test-ed25519-cert.cert   # Ed25519 test certificate
└── test-ecdsa-cert.cert     # ECDSA test certificate
```

## Usage

The fixtures are loaded by `tests/utils/testFixtures.ts` which provides:

- Individual exports for each key/certificate
- Helper functions like `getAllKeys()` and `getAllCertificates()`

## Generating New Fixtures

To add new test fixtures:

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

2. Generate certificates using `ssh-keygen` with certificate options:

   ```bash
   # Create a certificate
   ssh-keygen -s ca_key -I "test-cert" -n "testuser" -V "+52w" user_key.pub
   ```

3. Copy the generated `.pub` files and certificate files directly to `fixtures/`

4. Update `testFixtures.ts` if needed to include new fixtures

## Benefits

- **Realism**: Tests use actual SSH files as they would in production
- **Maintainability**: Easy to add new test cases by generating real keys/certificates
- **No duplication**: Single source of truth for test data
- **Flexibility**: Can easily generate edge cases or specific formats
