# Make use of this library as reference:
# https://github.com/data61/python-paillier
# But don't worry about the features:
# - cli
# - float encryption (assume ints less than some number)
# - a bunch of convenience methods
# - tests (lol, who needs em), just write a driver, that's safe

# we want 3 algorithms for encryption:
# - setup() -> (public_info, secret_info)
# - encrypt_{generator, modulus}(pubkey, plaintext) -> ciphertext
# - decrypt_{generator, modulus}(secretkey, ciphertext) -> plaintext
# and an addition operation over ciphertexts.

# default RSA key bit length, gives more than 128 bits of security.
from Crypto.Util import number
from crypto_utils import *
import random
import os
DEFAULT_KEYSIZE = 3072


def main():
    publickey, privatekey = generate_keypair()

    message = Plaintext(2357)
    ciphertext = publickey.encrypt(message)
    doubled_ciphertext = ciphertext.add(ciphertext)
    doubled_message = privatekey.decrypt(doubled_ciphertext)

    if doubled_message == 2357*2:
        print("SUCCESS")
    else:
        print("FAIL")


def generate_keypair(n_bits=DEFAULT_KEYSIZE):
    """Generate a pair of classes: PublicKey and PrivateKey"""

    n, p, q = generate_n_p_q(n_bits)

    public_key = PublicKey(n)
    private_key = PrivateKey(public_key, p, q)

    return public_key, private_key


def generate_n_of_length(n_bits):
    """generate an RSA modulus of N_BITS"""


class PublicKey():
    """A public key and associated encryption methods"""

    def __init__(self):
        pass

    def encrypt(message):
        """output a ciphertext using the held public key info"""
        pass

    pass


class PrivateKey():
    """A private key and associated decryption methods"""

    def __init__(self):
        pass

    def decrypt(ciphertext):
    pass


class Plaintext():
    """Some integer message, pass input validation over it"""

    def __init__(self, message):
        self.message = message


class Ciphertext():
    """The Pallier encryption of some plaintext"""

    def __init__():
        pass


if __name__ == "__main__":
    main()
