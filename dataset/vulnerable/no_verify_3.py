"""
Variant: signature verification wrapped in an instance method whose return
value is itself discarded by the caller.
"""
from dilithium_py.dilithium import Dilithium3


class SignatureChecker:
    def __init__(self, public_key: bytes):
        self.public_key = public_key

    def verify(self, message: bytes, signature: bytes) -> bool:
        return Dilithium3.verify(self.public_key, message, signature)


def handle(message: bytes, signature: bytes, pk: bytes) -> str:
    checker = SignatureChecker(pk)
    # VULNERABILITY: caller throws away the bool returned by checker.verify.
    checker.verify(message, signature)
    return f"processed: {message!r}"


if __name__ == "__main__":
    print(handle(b"forged", b"bogus_sig", b"pk_bytes"))
