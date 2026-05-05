"""
Variant: Falcon signature verification result discarded.
"""
from oqs_python import Falcon512


def receive(pk: bytes, msg: bytes, sig: bytes):
    signer = Falcon512()
    # VULNERABILITY: return value of verify() is discarded.
    signer.verify(pk, msg, sig)
    return process(msg)


def process(msg: bytes) -> str:
    return f"executed: {msg.decode(errors='replace')}"


if __name__ == "__main__":
    print(receive(b"pk", b"transfer 1000000 EUR", b"sig"))
