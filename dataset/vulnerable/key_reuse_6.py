"""
Variant: a single Kyber-derived shared secret cached and reused for many
encryption sessions in a loop, with a name-bound nonce that is also reused.
"""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from kyber_py.kyber import Kyber768


def cached_handshake():
    pk, _ = Kyber768.keygen()
    shared, _ = Kyber768.encaps(pk)
    return shared[:32]


def stream_messages(messages):
    key = cached_handshake()
    aead = AESGCM(key)
    static_nonce = b"\xee" * 12

    out = []
    for msg in messages:
        # VULNERABILITY: nonce never rotated across iterations.
        out.append(aead.encrypt(static_nonce, msg, None))
    return out


if __name__ == "__main__":
    print(stream_messages([b"m1", b"m2", b"m3", b"m4"]))
