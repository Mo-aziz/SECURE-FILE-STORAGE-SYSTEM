"""
Encoding module for cryptographic data representation.

This module provides UTF-8 and Base64 encoding/decoding utilities
for converting between plaintext, binary ciphertext, and portable
transferable formats.

ENCODING SCHEME USED:
- UTF-8: For plaintext messages and human-readable data
- Base64: For binary ciphertext, IVs, and encrypted session keys
  (enables safe transmission and display)

Why Base64? Binary data like ciphertext and encrypted keys contain
arbitrary byte values that may not be valid UTF-8. Base64 converts
these to ASCII-safe strings that can be displayed, stored in text
files, and transmitted over channels that expect text.
"""

import base64


def to_utf8(text: str) -> bytes:
    """
    Encode plaintext string to UTF-8 bytes.
    
    Args:
        text: Human-readable plaintext
        
    Returns:
        UTF-8 encoded bytes
    """
    return text.encode('utf-8')


def from_utf8(data: bytes) -> str:
    """
    Decode UTF-8 bytes to plaintext string.
    
    Args:
        data: UTF-8 encoded bytes
        
    Returns:
        Human-readable plaintext string
    """
    return data.decode('utf-8')


def to_base64(data: bytes) -> str:
    """
    Encode binary data to Base64 string.
    
    Used for: ciphertext, IVs, encrypted session keys, and other
    binary artifacts that need to be displayed or transmitted.
    
    Args:
        data: Binary data (ciphertext, IV, encrypted key, etc.)
        
    Returns:
        Base64-encoded ASCII string
    """
    return base64.b64encode(data).decode('ascii')


def from_base64(encoded: str) -> bytes:
    """
    Decode Base64 string to binary data.
    
    Args:
        encoded: Base64-encoded ASCII string
        
    Returns:
        Original binary data
    """
    return base64.b64decode(encoded.encode('ascii'))


def hex_encode(data: bytes) -> str:
    """
    Encode binary data to hexadecimal string (for debugging).
    
    Args:
        data: Binary data
        
    Returns:
        Hex-encoded string
    """
    return data.hex()


def hex_decode(hex_str: str) -> bytes:
    """
    Decode hexadecimal string to binary data.
    
    Args:
        hex_str: Hex-encoded string
        
    Returns:
        Original binary data
    """
    return bytes.fromhex(hex_str)
