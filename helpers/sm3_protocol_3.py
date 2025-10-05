import os
from cryptography.hazmat.primitives import hmac, hashes

# Nonce: Number used once: prevents replay attacks
def generate_nonce(length: int = 16) -> bytes:
    return os.urandom(length)

# Generate authentication tag
def generate_auth_tag(stable_key: bytes, challenge: bytes, nonce: bytes) -> bytes:
    h = hmac.HMAC(stable_key, hashes.SM3())
    h.update(challenge)
    h.update(nonce)

    return h.finalize()

# Verify authentication tag
def verify_auth_tag(stable_key: bytes, challenge: bytes, nonce: bytes, received_tag: bytes) -> bool:
    expected_tag = generate_auth_tag(stable_key, challenge, nonce)
    return expected_tag == received_tag