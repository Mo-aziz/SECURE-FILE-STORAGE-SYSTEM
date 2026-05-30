
import json
import os
from typing import Tuple, Dict, Any

from . import aes
from . import rsa
from . import encoding


def generate_session_key() -> bytes:
 
    return os.urandom(16)


def encrypt_file(
    plaintext: bytes,
    recipient_public_key: Tuple[int, int]
) -> Dict[str, str]:
   
    # Step 1 Generate session key
    session_key = generate_session_key()
    
    # Step 2 Encrypt data with AES-CBC
    ciphertext, iv = aes.aes_cbc_encrypt(plaintext, session_key)
    
    # Step 3 Encrypt session key with RSA
    # Convert session key bytes to integer for RSA encryption
    session_key_int = rsa.bytes_to_int(session_key)
    encrypted_session_key_int = rsa.encrypt(session_key_int, recipient_public_key)
    encrypted_session_key_bytes = rsa.int_to_bytes(
        encrypted_session_key_int,
        (recipient_public_key[1].bit_length() + 7) // 8  # n byte length
    )
    
    # Return as Base64-encoded strings for storage/transmission
    return {
        'aes_ciphertext': encoding.to_base64(ciphertext),
        'aes_iv': encoding.to_base64(iv),
        'encrypted_session_key': encoding.to_base64(encrypted_session_key_bytes)
    }


def decrypt_file(
    encrypted_bundle: Dict[str, str],
    recipient_private_key: Tuple[int, int]
) -> bytes:
   
    # Step 1 Decode Base64
    aes_ciphertext = encoding.from_base64(encrypted_bundle['aes_ciphertext'])
    aes_iv = encoding.from_base64(encrypted_bundle['aes_iv'])
    encrypted_session_key_bytes = encoding.from_base64(
        encrypted_bundle['encrypted_session_key']
    )
    
    # Step 2 Decrypt session key with RSA
    encrypted_session_key_int = rsa.bytes_to_int(encrypted_session_key_bytes)
    session_key_int = rsa.decrypt(encrypted_session_key_int, recipient_private_key)
    session_key = rsa.int_to_bytes(session_key_int, 16)  # AES keys are 16 bytes
    
    # Step 3 Decrypt data with AES
    plaintext = aes.aes_cbc_decrypt(aes_ciphertext, session_key, aes_iv)
    
    return plaintext


def create_encrypted_file_manifest(
    original_filename: str,
    plaintext_size: int,
    encrypted_bundle: Dict[str, str],
    sender_name: str,
    recipient_name: str
) -> Dict[str, Any]:
    
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
   
    return json.dumps(manifest, indent=2)


def deserialize_encrypted_file(json_str: str) -> Dict[str, Any]:
   
    return json.loads(json_str)
