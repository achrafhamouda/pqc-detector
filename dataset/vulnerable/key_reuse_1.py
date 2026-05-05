"""
Vulnerable example: reusing the same symmetric key (and nonce) to encrypt
multiple messages after a Kyber KEM exchange. With AES-GCM, nonce/key reuse
allows authentication-key recovery and full plaintext disclosure.
"""
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from kyber_py.kyber import Kyber768


def encrypt_messages(messages: list[bytes]) -> list[tuple[bytes, bytes]]:
    pk, _ = Kyber768.keygen()
    shared_key, _ = Kyber768.encaps(pk)
    aead = AESGCM(shared_key[:32])

    # VULNERABILITY: same key AND same nonce reused for every message.
    static_nonce = b"\x00" * 12
    ciphertexts = []
    for msg in messages:
        ct = aead.encrypt(static_nonce, msg, None)
        ciphertexts.append((static_nonce, ct))
    return ciphertexts


if __name__ == "__main__":
    msgs = [b"transfer 100 EUR", b"transfer 9999 EUR", b"login token=abcd"]
    out = encrypt_messages(msgs)
    for nonce, ct in out:
        print(nonce.hex(), ct.hex())
