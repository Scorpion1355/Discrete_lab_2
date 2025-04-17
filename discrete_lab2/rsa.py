import random
from hashlib import sha256

def gcd(a, b):
    """
    Calculate the greatest common divisor (GCD) of two numbers.
    """
    while b != 0:
        a, b = b, a % b
    return a

def mod_inv(a, m):
    """
    Calculate the modular inverse of a with respect to m.
    """
    mod0 = m
    x = 1
    y = 0
    if m == 1:
        return 0
    while a > 1:
        div = a // m
        a, m = m, a % m
        x, y = y, x - div * y
    if x < 0:
        x += mod0
    return x

def is_prime(n):
    """
    Check if a number is prime.
    """
    if n <= 1:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True


def generate_keys():
    """
    Generate a pair of public and private keys.
    """
    primes = [i for i in range(100, 1000) if is_prime(i)]
    if len(primes) < 2:
        raise ValueError("Not enough primes in the selected range")
    p, q = random.sample(primes, 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randrange(2, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)
    d = mod_inv(e, phi)
    return ((e, n), (d, n))


def encrypt(message, public_key):
    """
    Encrypt a message using the public key.
    """
    e, n = public_key
    encrypted = [pow(ord(char), e, n) for char in message]
    return encrypted


def decrypt(cipher, private_key):
    """
    Decrypt a cipher using the private key.
    """
    d, n = private_key
    decrypted_message = []
    for encrypted_char in cipher:
        decrypted_char = chr(pow(encrypted_char, d, n))
        decrypted_message.append(decrypted_char)
    return ''.join(decrypted_message)


def hash_message(message):
    """
    Generate the SHA-256 hash of a message.
    """
    return sha256(message.encode()).hexdigest()


def verify_integrity(original_message, received_hash):
    """
    Verify the integrity of a message by comparing its hash with the received hash.
    """
    calculated_hash = hash_message(original_message)
    return calculated_hash == received_hash
