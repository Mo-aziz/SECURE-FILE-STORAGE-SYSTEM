

import base64


def to_utf8(text: str) -> bytes:
 
    return text.encode('utf-8')


def from_utf8(data: bytes) -> str:
   
    return data.decode('utf-8')


def to_base64(data: bytes) -> str:
 
    return base64.b64encode(data).decode('ascii')


def from_base64(encoded: str) -> bytes:

    return base64.b64decode(encoded.encode('ascii'))


def hex_encode(data: bytes) -> str:

    return data.hex()


def hex_decode(hex_str: str) -> bytes:
    
    return bytes.fromhex(hex_str)
