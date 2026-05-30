
# Secure File Storage — Hybrid RSA/AES 

This small command-line project shows how hybrid encryption works by combining AES for bulk data and RSA for protecting the AES session key. The implementation is explicit and educational - the building blocks (AES rounds, key schedule, MixColumns, Miller–Rabin, modular arithmetic) are implemented by hand.

Key features
- Per-user RSA keypair generation (demo uses RSA-512 for speed - use 2048+ in production)
- AES-128 in CBC mode with PKCS#7 padding for file encryption
- Hybrid workflow: AES session key is encrypted with the recipient's RSA public key
- All binary artifacts (IV, ciphertext, encrypted key) are Base64-encoded and saved in JSON manifests

How it works (high level)
- `register_user`: creates an RSA public/private keypair under `data/users/<username>/keys`
- `encrypt_file`: generates a random 128-bit AES session key, encrypts the file with AES-CBC, encrypts the AES key with the recipient's RSA public key, and writes a JSON manifest containing the Base64 bundle
- `decrypt_file`: uses the recipient's RSA private key to recover the AES session key, then decrypts the AES-CBC ciphertext and removes PKCS#7 padding

Files and structure
- `src/main.py` - CLI entrypoint and menus (user management, file operations, info)
- `src/rsa.py` - RSA math, keygen (Miller–Rabin), encryption/decryption, integer/byte conversions
- `src/aes.py` - AES-128 primitives, key expansion, block encrypt/decrypt, CBC helpers
- `src/hybrid.py` - generate session keys, bundle AES+RSA operations, serialize/deserialize
- `data/users/` - example users, their key folders and stored encrypted file manifests

Quick start
1. Install Python 3.8+ if needed.
2. From the project root run:

```bash
cd src
python main.py
```




