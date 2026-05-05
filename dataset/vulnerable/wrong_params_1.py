"""
Vulnerable example: invoking a Kyber-like KEM with security_level=512
where the project policy requires NIST level 3 (Kyber768).

ML-KEM-512 only targets NIST category 1 (~AES-128) and is below the
required quantum-resistance threshold for this application.
"""


class KyberKEM:
    def __init__(self, security_level: int = 768):
        if security_level not in (512, 768, 1024):
            raise ValueError("invalid security level")
        self.security_level = security_level

    def keygen(self):
        return f"pk_{self.security_level}", f"sk_{self.security_level}"

    def encaps(self, pk: str):
        return f"ct_{self.security_level}", f"ss_{self.security_level}"


def setup_kem():
    # VULNERABILITY: security_level=512 is below the required NIST level 3 (768).
    kem = KyberKEM(security_level=512)
    pk, sk = kem.keygen()
    return kem, pk, sk


if __name__ == "__main__":
    kem, pk, sk = setup_kem()
    print(f"Using ML-KEM-{kem.security_level} (insecure for this use case)")
