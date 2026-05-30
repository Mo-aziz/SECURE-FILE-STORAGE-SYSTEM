
# Secure File Storage - Hybrid RSA/AES

This project is a small command-line demo that shows how hybrid encryption works. AES is used to encrypt the file itself, and RSA is used to protect the AES session key. The code is intentionally educational, so the main cryptographic steps are written out clearly instead of being hidden behind a library call.

## Features
- Per-user RSA keypair generation for demo accounts
- AES-128 encryption in CBC mode with PKCS#7 padding
- RSA encryption of the AES session key
- Base64 encoding for JSON storage
- Manual implementations of the core crypto helpers, including:
	- AES S-box / inverse S-box
	- key expansion
	- MixColumns and inverse MixColumns
	- Miller-Rabin primality testing
	- modular inverse and modular exponentiation

## Compilation instructions
This project does not need a separate compilation step because it is written in Python.

If you want a quick syntax check, you can run:

```bash
cd src
python -m compileall .
```

## Run instructions
1. Make sure Python 3.8+ is installed.
2. Open a terminal in the project root.
3. Run the main script:

```bash
cd src
python main.py
```

## Dependencies
The project uses only Python's standard library. No extra non-crypto utility packages are required.

## How it works
- `register_user` creates an RSA public/private keypair and stores it under `data/users/<username>/keys`.
- `encrypt_file` generates a random 128-bit AES session key, encrypts the file with AES-CBC, encrypts the AES key with the recipient's RSA public key, and saves the result as a JSON manifest.
- `decrypt_file` loads the RSA private key, decrypts the AES session key, then uses it to decrypt the file and remove padding.

## Files and structure
- `src/main.py` - CLI entrypoint and menus for users, files, and system info
- `src/rsa.py` - RSA math, prime generation, keypair generation, and encryption/decryption
- `src/aes.py` - AES-128 implementation, key schedule, block encryption/decryption, and CBC mode
- `src/hybrid.py` - combines AES and RSA into one file encryption workflow
- `src/storage.py` - saves users, keys, and encrypted file manifests
- `data/users/` - sample users, keys, and encrypted files

## Example input/output
Example 1: register a user
```text
Input:
1 -> User Management
1 -> Register New User
alice

Output:
User 'alice' created successfully!
Public exponent (e): 65537
Keys saved in: ...\data\users\alice\keys
```

Example 2: encrypt a file
```text
Input:
2 -> File Operations
1 -> Encrypt a File
sender: alice
recipient: bob
file path: C:\Docs\report.docx
output name: report_encrypted

Output:
File encrypted successfully!
Original size: ... bytes
Saved as: report_encrypted.json
Stored in: ...\data\users\bob\files
```

Example 3: decrypt a file
```text
Input:
2 -> File Operations
2 -> Decrypt a File
username: bob
file name: report_encrypted.json

Output:
File decrypted successfully!
Decrypted size: ... bytes
Saved as: ...\report.docx
```
## Done by
- Mohamed Ahmed Abdelaziz
- Abdelrahman Mesbah
- Jomana Khaled
- Shahd Mohamed




