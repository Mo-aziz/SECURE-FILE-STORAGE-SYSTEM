"""
Hybrid Encryption Module - RSA + AES Workflow

This module implements a complete hybrid cryptosystem that combines:
- RSA for encrypting the session key (confidentiality of key exchange)
- AES for encrypting the actual data (efficient bulk encryption)

Workflow:
1. Sender generates a random AES-128 session key
2. Sender encrypts the session key using recipient's RSA public key
3. Sender encrypts the actual data (message/file) using the AES session key
4. Sender transmits: encrypted session key + IV + encrypted data
5. Receiver decrypts session key using their RSA private key
6. Receiver decrypts data using the recovered session key

This approach provides:
- Confidentiality: data encrypted with AES (fast, secure)
- Key confidentiality: session key encrypted with RSA (asymmetric security)
- Each file gets a unique AES key (session isolation)

Encoding:
- AES ciphertext, IV, and encrypted session key are Base64-encoded
  for safe storage and transmission
"""

import json
import os
from typing import Tuple, Dict, Any

from . import aes
from . import rsa
from . import encoding


def generate_session_key() -> bytes:
    """
    Generate a random 128-bit AES session key.
    
    Returns:
        16 bytes of cryptographically random data
    """
    return os.urandom(16)


def encrypt_file(
    plaintext: bytes,
    recipient_public_key: Tuple[int, int]
) -> Dict[str, str]:
    """
    Encrypt data using hybrid RSA+AES encryption.
    
    Steps:
    1. Generate random AES session key
    2. Generate random IV for CBC mode
    3. Encrypt plaintext with AES-CBC using session key
    4. Encrypt session key with RSA using recipient's public key
    5. Bundle ciphertext, IV, and encrypted key
    
    Args:
        plaintext: Data to encrypt (bytes)
        recipient_public_key: (e, n) public key tuple
        
    Returns:
        Dictionary with Base64-encoded:
        - 'aes_ciphertext': AES-encrypted data
        - 'aes_iv': Initialization vector
        - 'encrypted_session_key': RSA-encrypted AES key
    """
    # Step 1: Generate session key
    session_key = generate_session_key()
    
    # Step 2: Encrypt data with AES-CBC
    ciphertext, iv = aes.aes_cbc_encrypt(plaintext, session_key)
    
    # Step 3: Encrypt session key with RSA
    # Convert session key bytes to integer for RSA encryption
    session_key_int = rsa.bytes_to_int(session_key)
    encrypted_session_key_int = rsa.encrypt(session_key_int, recipient_public_key)
    encrypted_session_key_bytes = rsa.int_to_bytes(
        encrypted_session_key_int,
        (recipient_public_key[1].bit_length() + 7) // 8  # n byte length
    )
    
    # Return as Base64-encoded strings for safe storage/transmission
    return {
        'aes_ciphertext': encoding.to_base64(ciphertext),
        'aes_iv': encoding.to_base64(iv),
        'encrypted_session_key': encoding.to_base64(encrypted_session_key_bytes)
    }


def decrypt_file(
    encrypted_bundle: Dict[str, str],
    recipient_private_key: Tuple[int, int]
) -> bytes:
    """
    Decrypt data encrypted with hybrid RSA+AES encryption.
    
    Steps:
    1. Decode Base64 values from bundle
    2. Decrypt session key using RSA private key
    3. Decrypt data using recovered AES session key
    
    Args:
        encrypted_bundle: Dictionary with Base64-encoded values
        recipient_private_key: (d, n) private key tuple
        
    Returns:
        Decrypted plaintext bytes
    """
    # Step 1: Decode Base64
    aes_ciphertext = encoding.from_base64(encrypted_bundle['aes_ciphertext'])
    aes_iv = encoding.from_base64(encrypted_bundle['aes_iv'])
    encrypted_session_key_bytes = encoding.from_base64(
        encrypted_bundle['encrypted_session_key']
    )
    
    # Step 2: Decrypt session key with RSA
    encrypted_session_key_int = rsa.bytes_to_int(encrypted_session_key_bytes)
    session_key_int = rsa.decrypt(encrypted_session_key_int, recipient_private_key)
    session_key = rsa.int_to_bytes(session_key_int, 16)  # AES keys are 16 bytes
    
    # Step 3: Decrypt data with AES
    plaintext = aes.aes_cbc_decrypt(aes_ciphertext, session_key, aes_iv)
    
    return plaintext


def create_encrypted_file_manifest(
    original_filename: str,
    plaintext_size: int,
    encrypted_bundle: Dict[str, str],
    sender_name: str,
    recipient_name: str
) -> Dict[str, Any]:
    """
    Create a manifest file describing an encrypted file.
    
    Includes metadata for the UI and storage system.
    
    Args:
        original_filename: Original plaintext filename
        plaintext_size: Original unencrypted size in bytes
        encrypted_bundle: Dictionary from encrypt_file()
        sender_name: Name of who encrypted the file
        recipient_name: Name of intended recipient
        
    Returns:
        Dictionary with manifest information
    """
    return {
        'original_filename': original_filename,
        'plaintext_size': plaintext_size,
        'ciphertext_size': len(encoding.from_base64(encrypted_bundle['aes_ciphertext'])),
        'encryption_method': 'AES-128-CBC + RSA',
        'aes_key_bits': 128,
        'sender': sender_name,
        'recipient': recipient_name,
        'encrypted_bundle': encrypted_bundle
    }


def serialize_encrypted_file(manifest: Dict[str, Any]) -> str:
    """
    Serialize encrypted file manifest to JSON.
    
    Args:
        manifest: Dictionary from create_encrypted_file_manifest()
        
    Returns:
        JSON string
    """
    return json.dumps(manifest, indent=2)


def deserialize_encrypted_file(json_str: str) -> Dict[str, Any]:
    """
    Deserialize encrypted file manifest from JSON.
    
    Args:
        json_str: JSON string
        
    Returns:
        Dictionary with manifest information
    """
    return json.loads(json_str)
