"""
Vulnerable example: weak key generation using random.randint.
Post-quantum primitives require cryptographically secure randomness
(os.urandom / secrets). Using random.randint produces predictable keys.
"""
import random
from kyber_py.kyber import Kyber768


def generate_weak_seed(length: int = 32) -> bytes:
    # VULNERABILITY: random.randint is a Mersenne Twister PRNG, not CSPRNG.
    return bytes([random.randint(0, 255) for _ in range(length)])


def keygen_weak():
    seed = generate_weak_seed(64)
    # Feeding a predictable seed into a KEM destroys IND-CCA security.
    public_key, secret_key = Kyber768.keygen_derand(seed)
    return public_key, secret_key


if __name__ == "__main__":
    pk, sk = keygen_weak()
    print("Generated (insecure) Kyber768 keypair")
