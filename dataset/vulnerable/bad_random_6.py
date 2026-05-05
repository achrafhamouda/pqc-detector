"""
Variant: mixed CSPRNG and weak PRNG. The nonce uses os.urandom (looks safe),
but the actual long-term secret is drawn from random.getrandbits.
This is a common mistake — secure-looking surface, broken core.
"""
import os
import random
from kyber_py.kyber import Kyber768


def make_handshake():
    transport_nonce = os.urandom(16)  # secure
    long_term_secret = bytes(random.getrandbits(8) for _ in range(32))  # weak
    return transport_nonce, long_term_secret


def setup():
    nonce, secret = make_handshake()
    return Kyber768.keygen_derand(secret + b"\x00" * 32)


if __name__ == "__main__":
    pk, sk = setup()
    print("Mixed-entropy handshake (insecure long-term key)")
