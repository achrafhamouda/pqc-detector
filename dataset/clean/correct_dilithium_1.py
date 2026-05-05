"""
Clean example: correct ML-DSA (Dilithium3) signature flow.

- Library-managed CSPRNG for keygen and signing.
- NIST category 3 parameter set (Dilithium3).
- The return value of verify() gates downstream processing.
- Failures raise an exception instead of being silently ignored.
"""
from dilithium_py.dilithium import Dilithium3


class InvalidSignature(Exception):
    pass


def sign_message(secret_key: bytes, message: bytes) -> bytes:
    return Dilithium3.sign(secret_key, message)


def verify_and_process(public_key: bytes, message: bytes, signature: bytes) -> str:
    is_valid = Dilithium3.verify(public_key, message, signature)
    if not is_valid:
        raise InvalidSignature("Dilithium3 signature verification failed")
    return f"executed: {message.decode(errors='replace')}"


if __name__ == "__main__":
    pk, sk = Dilithium3.keygen()
    msg = b"transfer 1 EUR"
    sig = sign_message(sk, msg)
    print(verify_and_process(pk, msg, sig))
