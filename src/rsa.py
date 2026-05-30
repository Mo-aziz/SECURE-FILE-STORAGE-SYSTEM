
import random


def gcd(a: int, b: int) -> int:

    a, b = abs(a), abs(b)
    while b != 0:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> tuple:

    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y


def modular_inverse(a: int, m: int) -> int:

    gcd_val, x, _ = extended_gcd(a, m)
    if gcd_val != 1:
        return -1  # Modular inverse does not exist
    return x % m


def modular_exponentiation(base: int, exp: int, mod: int) -> int:
  
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
    
   # Miller-Rabin primality test (probabilistic).
    
   
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
  
    while True:
        num = random.getrandbits(bits)
        num |= (1 << bits - 1)  # Set MSB to ensure correct bit length
        num |= 1  # Set LSB to ensure odd number
        
        if is_prime(num, k=40):
            return num


def generate_keypair(bits: int = 512) -> tuple:
  
    while True:
        # Generate two distinct large primes
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        while p == q:
            q = generate_prime(bits // 2)
        
        # Compute modulus
        n = p * q
        
        # Ensure modulus has exactly the requested bit length
     
        if n.bit_length() != bits:
            continue  # Try again with different primes
        
        # Compute φ(n) = (p-1)(q-1)
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

    e, n = public_key
    return modular_exponentiation(plaintext, e, n)


def decrypt(ciphertext: int, private_key: tuple) -> int:
 
    d, n = private_key
    return modular_exponentiation(ciphertext, d, n)


def int_to_bytes(value: int, length: int) -> bytes:
  
    return value.to_bytes(length, byteorder='big')


def bytes_to_int(data: bytes) -> int:
  
    return int.from_bytes(data, byteorder='big')
