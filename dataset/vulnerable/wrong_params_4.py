"""
Variant: parameter set referenced through module attribute access
(`pqc.ML_KEM_512`) rather than direct import. Detector must walk Attribute
nodes, not only Name nodes.
"""
import pqc


def setup_kem():
    kem = pqc.ML_KEM_512()  # category-1 variant
    pk, sk = kem.keygen()
    return kem, pk, sk


if __name__ == "__main__":
    kem, pk, sk = setup_kem()
    print("KEM established at insufficient security level")
