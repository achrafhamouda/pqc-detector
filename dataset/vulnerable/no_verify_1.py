"""
Vulnerable example: ignoring the boolean returned by Dilithium.verify().
A signature scheme that is never checked is equivalent to no signature.
An attacker can submit any forged message and it will be accepted.
"""
from dilithium_py.dilithium import Dilithium3


def receive_and_process(message: bytes, signature: bytes, public_key: bytes) -> str:
    # VULNERABILITY: the return value of verify() is discarded.
    Dilithium3.verify(public_key, message, signature)
    # The branch below executes regardless of signature validity.
    return process(message)


def process(message: bytes) -> str:
    return f"executed: {message.decode(errors='replace')}"


if __name__ == "__main__":
    pk, sk = Dilithium3.keygen()
    msg = b"transfer 1 EUR"
    sig = Dilithium3.sign(sk, msg)

    forged_msg = b"transfer 1000000 EUR"
    print(receive_and_process(forged_msg, sig, pk))  # accepted despite invalid sig
