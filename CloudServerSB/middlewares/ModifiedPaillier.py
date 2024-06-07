import random
from middlewares.Conversion import bytes_to_int, int_to_bytes
from gmpy2 import *
rs = gmpy2.random_state(hash(gmpy2.random_state()))


def E(pk, m):   
    n2 = pk['n'] * pk['n']
    m = mpz(m)
    r = mpz_random(rs, pk['n'])
    c1 = t_mod(1 + m * pk['n'], n2)
    c1 = t_mod(c1 * powmod(pk['h'], r, n2), n2)
    c2 = powmod(pk['g'], r, n2)
    return {'c1': int(c1), 'c2': int(c2)}


def oppoE(pk, m):
    n2 = pk['n'] * pk['n']
    m = mpz(-m)
    r = mpz_random(rs, pk['n'])
    c1 = t_mod(1 + m * pk['n'], n2)
    c1 = t_mod(c1 * powmod(pk['h'], r, n2), n2)
    c2 = powmod(pk['g'], r, n2)
    return {'c1': int(c1), 'c2': int(c2)}


def DE(pk, skp, c):
    n2 = pk['n'] * pk['n']

    gskp = powmod(c['c2'], skp, n2)
    c1 = t_mod(c['c1'] * powmod(gskp, -1, n2), n2)
    c1 = (c1 - 1) // pk['n']
    return int(c1)


def DEp1(pk, skp, c):
    n2 = pk['n'] * pk['n']
    gskp = powmod(c['c2'], skp, n2)
    c1 = t_mod(c['c1'] * powmod(gskp, -1, n2), n2)
    return {'c1': int(c1), 'c2': int(c['c2'])}


def DEp2(pk, skp, c):
    n2 = pk['n'] * pk['n']
    gskp = powmod(c['c2'], skp, n2)
    c1 = t_mod(c['c1'] * powmod(gskp, -1, n2), n2)
    c1 = (c1 - 1) // pk['n']
    return int(c1)


def _mul_(pk, E1, E2):
    n2 = pk['n'] * pk['n']
    c1 = (mpz(E1['c1']) * mpz(E2['c1'])) % n2
    c2 = (mpz(E1['c2']) * mpz(E2['c2'])) % n2
    return {'c1': int(c1), 'c2': int(c2)}