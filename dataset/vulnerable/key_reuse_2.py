"""
Variant: ChaCha20-Poly1305 with a hard-coded nonce literal passed inline.
Same key + same nonce across messages destroys confidentiality.
"""
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from kyber_py.kyber import Kyber768


def encrypt_batch(messages):
    pk, _ = Kyber768.keygen()
    shared, _ = Kyber768.encaps(pk)
    aead = ChaCha20Poly1305(shared[:32])

    out = []
    for msg in messages:
        # VULNERABILITY: literal nonce inlined per call.
        ct = aead.encrypt(b"\x01" * 12, msg, None)
        out.append(ct)
    return out


if __name__ == "__main__":
    print(encrypt_batch([b"alpha", b"beta", b"gamma"]))
