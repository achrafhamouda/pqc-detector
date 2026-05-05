"""
Variant: module-level constant nonce (NONCE) reused across multiple
top-level encrypt() calls — no loop involved.
"""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from kyber_py.kyber import Kyber768

NONCE = b"\xab" * 12  # module-level constant — never refreshed


def encrypt_pair(m1: bytes, m2: bytes):
    pk, _ = Kyber768.keygen()
    shared, _ = Kyber768.encaps(pk)
    aead = AESGCM(shared[:32])
    c1 = aead.encrypt(NONCE, m1, None)
    c2 = aead.encrypt(NONCE, m2, None)
    return c1, c2


if __name__ == "__main__":
    print(encrypt_pair(b"login=alice", b"login=alice&admin=true"))
