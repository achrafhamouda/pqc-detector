"""
Variant: bare `verify(...)` after a from-import, return discarded.
The call site has no class prefix, only the function name.
"""
from dilithium_signature import verify  # hypothetical free-function API


def handle(pk: bytes, msg: bytes, sig: bytes) -> str:
    # VULNERABILITY: return value discarded.
    verify(pk, msg, sig)
    return f"executed: {msg!r}"


if __name__ == "__main__":
    print(handle(b"pk", b"forged_msg", b"bogus"))
