"""
Unit tests for ML-KEM-1024 (NIST FIPS 203)
Layer 4 & Layer 8
"""

import pytest

# Try to import pqcrypto, skip tests if not available
try:
    from pqcrypto.kem.ml_kem_1024 import generate_keypair, encrypt, decrypt
    PQCRYPTO_AVAILABLE = True
except ImportError:
    PQCRYPTO_AVAILABLE = False
    generate_keypair = None
    encrypt = None
    decrypt = None

pytestmark = pytest.mark.skipif(
    not PQCRYPTO_AVAILABLE,
    reason="pqcrypto not installed - skipping PQC tests"
)


def test_ml_kem_keypair_generation():
    """Test ML-KEM-1024 keypair generation"""
    public_key, secret_key = generate_keypair()
    assert len(public_key) > 0
    assert len(secret_key) > 0


def test_ml_kem_encapsulation_decapsulation():
    """Test ML-KEM-1024 encaps/decaps round-trip"""
    public_key, secret_key = generate_keypair()

    # Encapsulate
    ciphertext, shared_secret_sender = encrypt(public_key)

    # Decapsulate
    shared_secret_receiver = decrypt(secret_key, ciphertext)

    # Verify shared secrets match
    assert shared_secret_sender == shared_secret_receiver
    assert len(shared_secret_sender) == 32  # 256 bits


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
