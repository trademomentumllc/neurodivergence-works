"""
Unit tests for ML-DSA-87 (NIST FIPS 204)
All layers using signatures
"""

import pytest

# Try to import pqcrypto, skip tests if not available
try:
    from pqcrypto.sign.ml_dsa_87 import generate_keypair, sign, verify
    PQCRYPTO_AVAILABLE = True
except ImportError:
    PQCRYPTO_AVAILABLE = False
    generate_keypair = None
    sign = None
    verify = None

pytestmark = pytest.mark.skipif(
    not PQCRYPTO_AVAILABLE,
    reason="pqcrypto not installed - skipping PQC tests"
)


def test_ml_dsa_keypair_generation():
    """Test ML-DSA-87 keypair generation"""
    public_key, secret_key = generate_keypair()
    assert len(public_key) > 0
    assert len(secret_key) > 0


def test_ml_dsa_sign_verify():
    """Test ML-DSA-87 sign/verify round-trip"""
    public_key, secret_key = generate_keypair()
    message = b"Eight-Layer Quantum-Hardened Architecture v2.0"

    # Sign (new API: sign(secret_key, message))
    signature = sign(secret_key, message)
    assert len(signature) > 0

    # Verify (new API: verify(public_key, message, signature) returns bool)
    result = verify(public_key, message, signature)
    assert result is True, "Signature verification failed"


def test_ml_dsa_tamper_detection():
    """Test ML-DSA-87 detects message tampering"""
    public_key, secret_key = generate_keypair()
    message = b"Original message"
    tampered = b"Tampered message"

    signature = sign(secret_key, message)

    # Should return False on tampered message (new API returns bool)
    result = verify(public_key, tampered, signature)
    assert result is False, "Verification should fail for tampered message"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
