"""
Variant: locally-bound constant nonce reused in the same function.
The nonce is a Name (not a literal at the call site), but its binding
is a constant bytes expression.
"""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_two_messages(key: bytes, m1: bytes, m2: bytes):
    aead = AESGCM(key)
    nonce = b"\x00" * 12  # local constant, never refreshed
    c1 = aead.encrypt(nonce, m1, None)
    c2 = aead.encrypt(nonce, m2, None)
    return c1, c2


if __name__ == "__main__":
    import os
    key = os.urandom(32)
    print(encrypt_two_messages(key, b"hello", b"world"))
