"""
Variant: aliased import of the standard `random` module.
Even though the alias hides the name `random`, the underlying PRNG is still
Mersenne Twister. Detector must resolve aliases.
"""
import random as rng
from kyber_py.kyber import Kyber768


def derive_seed(length: int = 64) -> bytes:
    return bytes(rng.randint(0, 255) for _ in range(length))


def keygen():
    seed = derive_seed()
    return Kyber768.keygen_derand(seed)


if __name__ == "__main__":
    pk, sk = keygen()
    print("Generated insecure keypair via aliased random module")
