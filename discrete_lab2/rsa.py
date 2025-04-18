""" rsa """

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

def is_prime(n, k=5):
    """
    Miller Rabin prime check
    """
    if n < 2:
        return False

    small_primes = [2,3,5,7,11,13,17,19,23]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    d, s = n - 1, 0
    while d & 1 == 0:
        d >>= 1
        s += 1

    def check(a):
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            return True
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                return True
        return False

    for _ in range(k):
        a = random.randrange(2, n - 1)
        if not check(a):
            return False

    return True

def generate_prime_in_range(low, high):
    """
    Pick random odd numbers in range until one is a prime
    """
    if low % 2 == 0:
        low += 1
    while True:
        p = random.randrange(low, high, 2)
        if is_prime(p):
            return p

def generate_keys(low=10**14, high=10**15):
    """
    Generate a pair of public and private keys with large primes
    """
    p = generate_prime_in_range(low, high)
    q = generate_prime_in_range(low, high)
    while q == p:
        q = generate_prime_in_range(low, high)

    n   = p * q
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
