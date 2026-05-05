"""
Variant: Dilithium2 (ML-DSA-44, NIST level 2) where the project requires
Dilithium3 (ML-DSA-65, NIST level 3).
"""
from dilithium_py.dilithium import Dilithium2


def sign_payload(payload: bytes):
    pk, sk = Dilithium2.keygen()
    sig = Dilithium2.sign(sk, payload)
    return pk, sig


if __name__ == "__main__":
    pk, sig = sign_payload(b"transfer 100 EUR")
    print(f"Signed with Dilithium2 (insufficient): sig length = {len(sig)}")
