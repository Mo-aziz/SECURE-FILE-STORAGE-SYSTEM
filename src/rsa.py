"""
RSA Encryption/Decryption Module - Implemented from Scratch

This module implements the RSA public-key cryptosystem including:
- Prime number generation using Miller-Rabin test
- GCD and Extended Euclidean Algorithm
- Modular inverse computation
- Manual modular exponentiation (repeated squaring)
- RSA keypair generation
- RSA encryption and decryption

Key Security Notes:
- Uses a 512-bit modulus for educational demo (real systems use 2048+ bits)
- No padding scheme (OAEP) is used (simplified for clarity)
- Intended for small values like session keys, not bulk data

Algorithm Reference:
RSA Encryption: C = M^e mod n
RSA Decryption: M = C^d mod n
where (e,n) is public key and (d,n) is private key
"""

import random


def gcd(a: int, b: int) -> int:
    """
    Compute greatest common divisor using Euclidean algorithm.
    
    Args:
        a, b: Two integers
        
    Returns:
        Greatest common divisor of a and b
    """
    a, b = abs(a), abs(b)
    while b != 0:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> tuple:
    """
    Extended Euclidean Algorithm: find x, y such that a*x + b*y = gcd(a,b).
    
    Used to compute modular inverse.
    
    Args:
        a, b: Two integers
        
    Returns:
        (gcd, x, y) where a*x + b*y = gcd
    """
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y


def modular_inverse(a: int, m: int) -> int:
    """
    Compute modular multiplicative inverse of a modulo m.
    
    Finds x such that a*x ≡ 1 (mod m).
    Uses extended GCD; returns -1 if inverse does not exist.
    
    Args:
        a: The value
        m: The modulus
        
    Returns:
        Modular inverse of a mod m, or -1 if not exists
    """
    gcd_val, x, _ = extended_gcd(a, m)
    if gcd_val != 1:
        return -1  # Modular inverse does not exist
    return x % m


def modular_exponentiation(base: int, exp: int, mod: int) -> int:
    """
    Compute (base^exp) mod mod efficiently using repeated squaring.
    
    This is MANUAL implementation, NOT using Python's built-in pow().
    Repeated squaring is O(log exp) instead of O(exp).
    
    Algorithm:
    1. Convert exponent to binary
    2. For each bit, square the result
    3. If bit is 1, multiply by base
    4. Reduce modulo at each step to keep numbers small
    
    Args:
        base: The base value
        exp: The exponent
        mod: The modulus
        
    Returns:
        (base^exp) mod mod
    """
    if mod == 1:
        return 0
    
    result = 1
    base = base % mod
    
    # Process exponent bit by bit (from right to left)
    while exp > 0:
        # If current bit is 1, multiply result by current base
        if exp % 2 == 1:
            result = (result * base) % mod
        
        # Move to next bit
        exp = exp >> 1
        base = (base * base) % mod
    
    return result


def is_prime(n: int, k: 40) -> bool:
    """
    Miller-Rabin primality test (probabilistic).
    
    For k=40, error probability is < 2^-80 (very strong).
    
    Args:
        n: The number to test
        k: Number of rounds (higher = more confidence)
        
    Returns:
        True if n is probably prime, False if definitely composite
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n-1 as 2^r * d where d is odd
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = modular_exponentiation(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = modular_exponentiation(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True


def generate_prime(bits: int) -> int:
    """
    Generate a random prime number of specified bit length.
    
    Args:
        bits: Desired bit length of the prime
        
    Returns:
        A prime number of approximately 'bits' bits
    """
    while True:
        num = random.getrandbits(bits)
        num |= (1 << bits - 1)  # Set MSB to ensure correct bit length
        num |= 1  # Set LSB to ensure odd number
        
        if is_prime(num, k=40):
            return num


def generate_keypair(bits: int = 512) -> tuple:
    """
    Generate RSA public and private keypair.
    
    Recommended minimum: 512 bits (for demo). Real systems: 2048+ bits.
    
    Algorithm:
    1. Generate two large distinct primes p and q
    2. Compute n = p * q (modulus)
    3. Compute φ(n) = (p-1) * (q-1) (Euler's totient)
    4. Choose e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
       (typically e = 65537 for efficiency)
    5. Compute d such that e*d ≡ 1 (mod φ(n)) (using modular inverse)
    
    Returns:
        ((e, n), (d, n)) - public key and private key pairs
    """
    while True:
        # Generate two distinct large primes
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        while p == q:
            q = generate_prime(bits // 2)
        
        # Compute modulus
        n = p * q
        
        # Ensure modulus has exactly the requested bit length
        # (product of two (bits//2)-bit primes can be bits-1 or bits bits)
        if n.bit_length() != bits:
            continue  # Try again with different primes
        
        # Compute Euler's totient: φ(n) = (p-1)(q-1)
        phi_n = (p - 1) * (q - 1)
        
        # Choose public exponent e (commonly 65537)
        e = 65537
        while gcd(e, phi_n) != 1:
            e = random.randint(2, phi_n - 1)
        
        # Compute private exponent d such that e*d ≡ 1 (mod φ(n))
        d = modular_inverse(e, phi_n)
        
        # Return (public_key, private_key)
        return (e, n), (d, n)


def encrypt(plaintext: int, public_key: tuple) -> int:
    """
    RSA encryption: C = M^e mod n
    
    Args:
        plaintext: Plaintext integer (must be < n)
        public_key: (e, n) tuple
        
    Returns:
        Ciphertext integer
    """
    e, n = public_key
    return modular_exponentiation(plaintext, e, n)


def decrypt(ciphertext: int, private_key: tuple) -> int:
    """
    RSA decryption: M = C^d mod n
    
    Args:
        ciphertext: Ciphertext integer
        private_key: (d, n) tuple
        
    Returns:
        Plaintext integer
    """
    d, n = private_key
    return modular_exponentiation(ciphertext, d, n)


def int_to_bytes(value: int, length: int) -> bytes:
    """
    Convert integer to bytes (big-endian, fixed length).
    
    Args:
        value: Integer to convert
        length: Desired byte length
        
    Returns:
        Bytes representation
    """
    return value.to_bytes(length, byteorder='big')


def bytes_to_int(data: bytes) -> int:
    """
    Convert bytes to integer (big-endian).
    
    Args:
        data: Bytes to convert
        
    Returns:
        Integer representation
    """
    return int.from_bytes(data, byteorder='big')
