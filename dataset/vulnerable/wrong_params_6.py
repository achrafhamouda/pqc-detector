"""
Variant: a custom KEM wrapper accepts a security_level keyword. The caller
explicitly downgrades to 512.
"""


class CustomKEM:
    def __init__(self, *, security_level: int = 768):
        self.security_level = security_level

    def keygen(self):
        return f"pk_{self.security_level}", f"sk_{self.security_level}"

    def encaps(self, pk):
        return b"ct", b"ss"


def build():
    # VULNERABILITY: explicit downgrade to category 1.
    kem = CustomKEM(security_level=512)
    return kem.keygen()


if __name__ == "__main__":
    pk, sk = build()
    print(f"Built {pk}")
