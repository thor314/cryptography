# cryptography utilities
from Crypto.Util import number
import os


def generate_n_p_q(n_bits):
    p = q = n = None  # constant time allocation
    n_len = 0
    while n_len != n_bits:
        # sample p,q until n is the right size
        p, q = get_prime_over(n_bits), get_prime_over(n_bits)
        assert(p != q)
        n = p*q
        n_len = n.bit_length()
    return n, p, q


def get_prime_over(n_bits):
    """return a random N_BITS prime number, using pycrypto"""
    return number.getPrime(n_bits, os.urandom)
