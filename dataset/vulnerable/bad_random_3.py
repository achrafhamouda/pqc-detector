"""
Variant: from-import pulls a weak PRNG function into the local namespace,
so the call site has no `random.` prefix. Detector must resolve from-imports.
"""
from random import getrandbits
from dilithium_py.dilithium import Dilithium3


def derive_seed(bits: int = 256) -> bytes:
    return getrandbits(bits).to_bytes(bits // 8, "big")


def sign_payload(payload: bytes):
    seed = derive_seed(512)
    pk, sk = Dilithium3.keygen()
    return Dilithium3.sign(sk, payload), pk


if __name__ == "__main__":
    sig, pk = sign_payload(b"hello")
    print(f"Signed with weak seed; sig length = {len(sig)}")
