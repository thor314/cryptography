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
import random
from crypto_utils import powmod
from crypto_utils import generate_n_p_q
DEFAULT_KEYSIZE = 3072


def main():
    public_key, private_key = generate_keypair()
    plaintext = Plaintext(2357)
    ciphertext = public_key.encrypt(plaintext)
    doubled_ciphertext = ciphertext + ciphertext
    doubled_message = private_key.decrypt(doubled_ciphertext)

    if doubled_message == 2357*2:
        print("SUCCESS")
    else:
        print("FAIL")


def generate_keypair(n_bits=DEFAULT_KEYSIZE):
    """Generate a pair of classes: PublicKey and PrivateKey"""
    n, p, q = generate_n_p_q(n_bits)
    public_key = PublicKey(n)
    private_key = PrivateKey(public_key)
    return public_key, private_key


class PublicKey():
    """A public key and associated encryption methods"""

    def __init__(self, n):
        self.g = n+1  # the convenient generator
        self.n = n
        self.n_square = n*n  # efficiency purposes
        self.max_int = n // 3 - 1

    def encrypt(self, plaintext):
        """encrypt plaintext, output ciphertext.
        concisely: c = g**e * r**n mod n**2
        less concisely:
        ciphertext = nude_ciphertext * obfuscator mod n**2
        """
        assert(isinstance(plaintext, Plaintext))
        assert(plaintext.message < self.max_int)

        nude_ciphertext = pow(self.g, plaintext.message, self.n_square)
        r = self.get_random_lt_n()
        obfuscator = pow(r, self.n, self.n_square)
        return nude_ciphertext * obfuscator % self.n_square

    def get_random_lt_n(self):
        """Return a random number less than n"""
        # systemRandom is os independent
        return random.SystemRandom().randrange(1, self.n)

    def __repr__(self):
        public_key_hash = hex(hash(self))  # [2:]
        return "<PublicKey {}>".format(public_key_hash[:12])

class PrivateKey():
    """A private key and associated decryption methods"""

    def __init__(self, n):
        self.g = n+1  # the convenient generator
        self.n = n
        self.n_square = n*n  # efficiency purposes
        self.max_int = n // 3 - 1

    def decrypt(self, ciphertext):
        pass


class Plaintext():
    """Some integer message, pass input validation over it"""

    def __init__(self, message):
        if not isinstance(message, int):
            raise TypeError('Expected message type int\nGot message type %s'
                            % type(message))
        self.message = message


class Ciphertext():
    """The Pallier encryption of some plaintext"""

    def __init__(self, encrypted_text):
        self.encrypted_text = encrypted_text

    def __add__(self, other):
        return self.encrypted_text * other.encrypted_text


if __name__ == "__main__":
    main()
