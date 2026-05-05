"""
Variant: deterministic seed (current hour) feeds the PRNG before key bytes
are drawn. An attacker who knows the wall-clock time can re-derive the key.
"""
import random
import time
from dilithium_py.dilithium import Dilithium3


def derive_seed(length: int = 64) -> bytes:
    random.seed(int(time.time() // 3600))  # rotates once per hour, easily guessed
    return bytes(random.randrange(0, 256) for _ in range(length))


def keygen():
    seed = derive_seed()
    return Dilithium3.keygen()


if __name__ == "__main__":
    pk, sk = keygen()
    print("Insecure Dilithium3 keygen using time-seeded PRNG")
