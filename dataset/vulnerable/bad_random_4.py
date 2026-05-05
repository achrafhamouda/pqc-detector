"""
Variant: random.choices used to build key bytes from an alphabet.
Same Mersenne Twister source — output is fully predictable.
"""
import random
from kyber_py.kyber import Kyber768

ALPHABET = bytes(range(256))


def derive_seed(length: int = 32) -> bytes:
    return bytes(random.choices(ALPHABET, k=length))


def setup():
    seed_a = derive_seed(32)
    seed_b = derive_seed(32)
    return Kyber768.keygen_derand(seed_a + seed_b)


if __name__ == "__main__":
    pk, sk = setup()
    print("Insecure Kyber768 setup using random.choices")
