"""
Variant: dictionary of signers; verification is dispatched dynamically and
its return value is dropped.
"""
from dilithium_py.dilithium import Dilithium3


VERIFIERS = {"dilithium3": Dilithium3}


def dispatch(alg: str, pk: bytes, msg: bytes, sig: bytes) -> str:
    # VULNERABILITY: subscript access -> verify(...) result discarded.
    VERIFIERS[alg].verify(pk, msg, sig)
    return f"processed: {msg!r}"


if __name__ == "__main__":
    print(dispatch("dilithium3", b"pk", b"forged", b"bogus"))
