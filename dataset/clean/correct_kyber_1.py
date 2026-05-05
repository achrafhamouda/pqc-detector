"""
Clean example: correct ML-KEM (Kyber768) usage.

- Cryptographically secure randomness (os.urandom) handled by the library.
- NIST category 3 parameter set (Kyber768).
- Encapsulated shared secret is used only once with AES-GCM and a fresh nonce.
- Decapsulation result is compared in constant time to the expected key.
"""
import os
from hmac import compare_digest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from kyber_py.kyber import Kyber768


def kem_handshake():
    public_key, secret_key = Kyber768.keygen()
    shared_secret_sender, ciphertext = Kyber768.encaps(public_key)
    shared_secret_receiver = Kyber768.decaps(secret_key, ciphertext)

    if not compare_digest(shared_secret_sender, shared_secret_receiver):
        raise ValueError("KEM decapsulation mismatch")
    return shared_secret_sender, ciphertext, public_key, secret_key


def encrypt_message(shared_secret: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    aead = AESGCM(shared_secret[:32])
    nonce = os.urandom(12)  # fresh nonce per message
    return nonce, aead.encrypt(nonce, plaintext, None)


if __name__ == "__main__":
    shared, ct, pk, sk = kem_handshake()
    nonce, ct_msg = encrypt_message(shared, b"hello pqc")
    print(f"Kyber768 OK | nonce={nonce.hex()} ct={ct_msg.hex()}")
