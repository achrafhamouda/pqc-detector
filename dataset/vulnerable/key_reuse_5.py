"""
Variant: AES-GCM encrypt() called with the nonce literal inlined directly,
no intermediate variable. Several call sites, each with a different (still
hard-coded) nonce, but the same key.
"""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from kyber_py.kyber import Kyber768


def session_dump(key: bytes, payload: bytes):
    aead = AESGCM(key)
    # VULNERABILITY: literal nonce inlined; no fresh randomness.
    return aead.encrypt(b"\x42" * 12, payload, None)


def main():
    pk, _ = Kyber768.keygen()
    shared, _ = Kyber768.encaps(pk)
    key = shared[:32]
    a = session_dump(key, b"first")
    b = session_dump(key, b"second")  # same nonce literal will be used inside
    return a, b


if __name__ == "__main__":
    print(main())
