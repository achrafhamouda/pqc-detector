"""
Variant: verify() inside a try/except whose exception path is silenced.
The bool is discarded, AND any raised error is swallowed — both failure
modes lead to processing forged messages.
"""
from dilithium_py.dilithium import Dilithium3


def receive(pk: bytes, msg: bytes, sig: bytes) -> str:
    try:
        # VULNERABILITY: result discarded; any exception is also caught silently.
        Dilithium3.verify(pk, msg, sig)
    except Exception:
        pass
    return f"processed: {msg!r}"


if __name__ == "__main__":
    print(receive(b"pk", b"forged", b"bogus_sig"))
