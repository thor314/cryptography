# Make use of this library as reference:
# https://github.com/data61/python-paillier

# we want 3 algorithms for encryption:
# - setup() -> (public_info, secret_info)
# - encrypt_{generator, modulus}(pubkey, plaintext) -> ciphertext
# - decrypt_{generator, modulus}(secretkey, ciphertext) -> plaintext
# and an addition operation over ciphertexts.

# default RSA key bit length, gives more than 128 bits of security.
DEFAULT_KEYSIZE = 3072


def main():
    pass


def generate_keypair():
    """Generate a pair of classes: PublicKey and PrivateKey"""
    pass


class PublicKey():
    """A public key and associated encryption methods"""
    pass


class PrivateKey():
    """A private key and associated decryption methods"""
    pass


class Ciphertext():
    """The Pallier encryption of some plaintext"""


if __name__ == "__main__":
    main()
