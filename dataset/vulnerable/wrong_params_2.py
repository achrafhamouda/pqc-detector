"""
Variant: direct use of Kyber512 (NIST category 1).
Project policy mandates NIST level 3 = Kyber768.
"""
from kyber_py.kyber import Kyber512


def keygen():
    return Kyber512.keygen()


def session():
    pk, sk = keygen()
    shared, ct = Kyber512.encaps(pk)
    return shared, ct


if __name__ == "__main__":
    s, c = session()
    print(f"ML-KEM-512 session established (insufficient security)")
