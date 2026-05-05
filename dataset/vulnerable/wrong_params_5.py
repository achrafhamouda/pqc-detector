"""
Variant: Falcon-512 used as the signature scheme. Falcon-512 targets NIST
category 1 (~AES-128); policy requires category 3 (Falcon-1024 or Dilithium3).
"""
from oqs_python import Falcon512


def sign(payload: bytes):
    signer = Falcon512()
    pk = signer.generate_keypair()
    sig = signer.sign(payload)
    return pk, sig


if __name__ == "__main__":
    pk, sig = sign(b"hello")
    print(f"Falcon-512 signature ({len(sig)} bytes) — insufficient security")
