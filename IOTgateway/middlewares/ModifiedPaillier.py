import random
from middlewares.Conversion import bytes_to_int, int_to_bytes
from gmpy2 import *
rs = gmpy2.random_state(hash(gmpy2.random_state()))

# Encryption function
def E(pk, m):
    # Calculate n^2 where n is the public key parameter
    n2 = pk['n'] * pk['n']
    # Convert message to a GMP integer
    m = mpz(m)
    # Generate a random value 'r' modulo n
    r = mpz_random(rs, pk['n'])
    # Compute c1 = (1 + m * n) mod n^2
    c1 = t_mod(1 + m * pk['n'], n2)
    # Compute c1 = c1 * h^r mod n^2
    c1 = t_mod(c1 * powmod(pk['h'], r, n2), n2)
    # Compute c2 = g^r mod n^2
    c2 = powmod(pk['g'], r, n2)
    return {'c1': int(c1), 'c2': int(c2)}

# Encryption function for the negation of a message
def oppoE(pk, m):
    n2 = pk['n'] * pk['n']
    # Negate the message
    m = mpz(-m)
    # Generate a random value 'r' modulo n
    r = mpz_random(rs, pk['n'])
    # Compute c1 = (1 + m * n) mod n^2
    c1 = t_mod(1 + m * pk['n'], n2)
    # Compute c1 = c1 * h^r mod n^2
    c1 = t_mod(c1 * powmod(pk['h'], r, n2), n2)
    # Compute c2 = g^r mod n^2
    c2 = powmod(pk['g'], r, n2)
    return {'c1': int(c1), 'c2': int(c2)}

# Decryption function
def DE(pk, skp, c):
    n2 = pk['n'] * pk['n']
    # Compute g^(skp * c2) mod n^2
    gskp = powmod(c['c2'], skp, n2)
    # Compute c1 = c1 * gskp^(-1) mod n^2
    c1 = t_mod(c['c1'] * powmod(gskp, -1, n2), n2)
    # Extract the original message from c1
    c1 = (c1 - 1) // pk['n']
    return int(c1)

# Partial decryption function 1
def DEp1(pk, skp, c):
    n2 = pk['n'] * pk['n']
    # Compute g^(skp * c2) mod n^2
    gskp = powmod(c['c2'], skp, n2)
    # Compute c1 = c1 * gskp^(-1) mod n^2
    c1 = t_mod(c['c1'] * powmod(gskp, -1, n2), n2)
    return {'c1': int(c1), 'c2': int(c['c2'])}

# Partial decryption function 2
def DEp2(pk, skp, c):
    n2 = pk['n'] * pk['n']
    # Compute g^(skp * c2) mod n^2
    gskp = powmod(c['c2'], skp, n2)
    # Compute c1 = c1 * gskp^(-1) mod n^2
    c1 = t_mod(c['c1'] * powmod(gskp, -1, n2), n2)
    # Extract the original message from c1
    c1 = (c1 - 1) // pk['n']
    return int(c1)

# Multiplication of two ciphertexts
def _mul_(pk, E1, E2):
    n2 = pk['n'] * pk['n']
    # Compute c1 = (c11 * c21) mod n^2
    c1 = (mpz(E1['c1']) * mpz(E2['c1'])) % n2
    # Compute c2 = (c12 * c22) mod n^2
    c2 = (mpz(E1['c2']) * mpz(E2['c2'])) % n2
    return {'c1': int(c1), 'c2': int(c2)}

