"""
Layer 1: Identity Verification with ML-DSA-87 (Dilithium5) Signatures

This module provides FIDO2-style authentication using post-quantum digital signatures
based on the ML-DSA-87 algorithm (CRYSTALS-Dilithium level 5).

Security Guarantees:
- NIST Security Level 5 (256-bit quantum security)
- Unforgeable signatures under chosen message attack (UF-CMA)
- Resistant to quantum attacks via Grover's and Shor's algorithms
- Public key size: 2592 bytes
- Signature size: ~4627 bytes
- Private key size: 4896 bytes

Example Usage:
    >>> # Initialize identity verifier
    >>> verifier = IdentityVerifier()
    >>>
    >>> # Generate keypair
    >>> public_key, private_key = verifier.generate_keypair()
    >>>
    >>> # Create authentication challenge
    >>> challenge = verifier.create_challenge(user_id="alice@example.com")
    >>>
    >>> # Sign the challenge
    >>> signature = verifier.sign_challenge(challenge, private_key)
    >>>
    >>> # Verify the signature
    >>> is_valid = verifier.verify_signature(challenge, signature, public_key)
    >>> assert is_valid == True
"""

import hashlib
import secrets
from typing import Tuple, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta

try:
    from pqcrypto.sign.ml_dsa_87 import (
        generate_keypair as sign_keygen,
        sign,
        verify
    )
except ImportError:
    raise ImportError(
        "pqcrypto is required. Install with: pip install pqcrypto"
    )


@dataclass
class AuthenticationChallenge:
    """
    Represents a FIDO2-style authentication challenge.

    Attributes:
        user_id: Unique identifier for the user
        challenge_bytes: Random cryptographic challenge (32 bytes)
        timestamp: Challenge creation time
        relying_party: Service requesting authentication
        expires_at: Challenge expiration time
        metadata: Additional authentication metadata
    """
    user_id: str
    challenge_bytes: bytes
    timestamp: datetime
    relying_party: str = "eight-layer-pqc"
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Set default expiration if not provided."""
        if self.expires_at is None:
            self.expires_at = self.timestamp + timedelta(minutes=5)

    def to_bytes(self) -> bytes:
        """
        Serialize challenge to canonical byte representation for signing.

        Returns:
            Canonical byte representation of the challenge
        """
        components = [
            self.user_id.encode('utf-8'),
            self.challenge_bytes,
            str(int(self.timestamp.timestamp())).encode('utf-8'),
            self.relying_party.encode('utf-8')
        ]
        return b'|'.join(components)

    def is_expired(self) -> bool:
        """Check if challenge has expired."""
        return datetime.now() > self.expires_at

    def get_hash(self) -> bytes:
        """
        Get SHA3-256 hash of the challenge.

        Returns:
            32-byte hash of challenge data
        """
        return hashlib.sha3_256(self.to_bytes()).digest()


class IdentityVerifier:
    """
    Post-Quantum Identity Verification System using ML-DSA-87.

    This class provides FIDO2-style authentication with quantum-resistant
    digital signatures. It implements challenge-response authentication
    suitable for zero-trust architectures.
    """

    def __init__(self, relying_party: str = "eight-layer-pqc"):
        """
        Initialize the identity verifier.

        Args:
            relying_party: Name of the service requesting authentication
        """
        self.relying_party = relying_party
        self._challenge_cache: Dict[str, AuthenticationChallenge] = {}

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a new ML-DSA-87 keypair for identity verification.

        Returns:
            Tuple of (public_key, private_key) as bytes
            - public_key: 2592 bytes
            - private_key: 4896 bytes

        Raises:
            RuntimeError: If keypair generation fails

        Security Notes:
            - Private key must be stored securely (HSM, secure enclave, etc.)
            - Public key can be freely distributed
            - Each user should have a unique keypair
        """
        try:
            public_key, private_key = sign_keygen()
            return public_key, private_key
        except Exception as e:
            raise RuntimeError(f"Failed to generate ML-DSA-87 keypair: {e}")

    def create_challenge(
        self,
        user_id: str,
        challenge_size: int = 32,
        ttl_minutes: int = 5,
        metadata: Optional[Dict[str, Any]] = None
    ) -> AuthenticationChallenge:
        """
        Create a new authentication challenge for a user.

        Args:
            user_id: Unique identifier for the user
            challenge_size: Size of random challenge in bytes (default: 32)
            ttl_minutes: Time-to-live for challenge in minutes (default: 5)
            metadata: Optional metadata to include in challenge

        Returns:
            AuthenticationChallenge object

        Raises:
            ValueError: If challenge_size < 16 or ttl_minutes < 1

        Security Notes:
            - Challenge bytes are cryptographically random
            - Challenges expire after TTL to prevent replay attacks
            - Each challenge should be used only once
        """
        if challenge_size < 16:
            raise ValueError("Challenge size must be at least 16 bytes")
        if ttl_minutes < 1:
            raise ValueError("TTL must be at least 1 minute")

        challenge_bytes = secrets.token_bytes(challenge_size)
        timestamp = datetime.now()
        expires_at = timestamp + timedelta(minutes=ttl_minutes)

        challenge = AuthenticationChallenge(
            user_id=user_id,
            challenge_bytes=challenge_bytes,
            timestamp=timestamp,
            relying_party=self.relying_party,
            expires_at=expires_at,
            metadata=metadata or {}
        )

        # Cache challenge for verification
        challenge_id = challenge.get_hash().hex()
        self._challenge_cache[challenge_id] = challenge

        return challenge

    def sign_challenge(
        self,
        challenge: AuthenticationChallenge,
        private_key: bytes
    ) -> bytes:
        """
        Sign an authentication challenge with ML-DSA-87.

        Args:
            challenge: The authentication challenge to sign
            private_key: ML-DSA-87 private key (4896 bytes)

        Returns:
            Digital signature (~4627 bytes)

        Raises:
            ValueError: If challenge is expired or private key is invalid
            RuntimeError: If signing operation fails

        Security Notes:
            - Signature is deterministic for same message and key
            - Provides UF-CMA security (unforgeable under chosen message attack)
            - Quantum resistant to Shor's algorithm attacks
        """
        if challenge.is_expired():
            raise ValueError("Cannot sign expired challenge")

        if len(private_key) != 4896:
            raise ValueError(
                f"Invalid private key size: {len(private_key)} bytes "
                "(expected 4896 bytes for ML-DSA-87)"
            )

        try:
            message = challenge.to_bytes()
            signature = sign(private_key, message)
            return signature
        except Exception as e:
            raise RuntimeError(f"Failed to sign challenge: {e}")

    def verify_signature(
        self,
        challenge: AuthenticationChallenge,
        signature: bytes,
        public_key: bytes,
        allow_expired: bool = False
    ) -> bool:
        """
        Verify a signature on an authentication challenge.

        Args:
            challenge: The authentication challenge that was signed
            signature: Digital signature to verify (~4627 bytes)
            public_key: ML-DSA-87 public key (2592 bytes)
            allow_expired: Whether to accept expired challenges (default: False)

        Returns:
            True if signature is valid, False otherwise

        Raises:
            ValueError: If inputs are invalid

        Security Notes:
            - Verification is constant-time to prevent timing attacks
            - Returns False for any verification failure
            - Should be combined with challenge replay prevention
        """
        if not allow_expired and challenge.is_expired():
            return False

        if len(public_key) != 2592:
            raise ValueError(
                f"Invalid public key size: {len(public_key)} bytes "
                "(expected 2592 bytes for ML-DSA-87)"
            )

        try:
            message = challenge.to_bytes()
            # verify() returns True/False in the new pqcrypto API
            return verify(public_key, message, signature)
        except Exception:
            # Any exception during verification means invalid signature
            return False

    def authenticate_user(
        self,
        user_id: str,
        signature: bytes,
        public_key: bytes,
        challenge_hash: Optional[str] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Complete authentication flow by verifying user signature.

        Args:
            user_id: User identifier
            signature: User's signature on the challenge
            public_key: User's ML-DSA-87 public key
            challenge_hash: Optional hash of the challenge (for cached lookup)

        Returns:
            Tuple of (success: bool, error_message: Optional[str])

        Example:
            >>> verifier = IdentityVerifier()
            >>> pk, sk = verifier.generate_keypair()
            >>> challenge = verifier.create_challenge("alice@example.com")
            >>> sig = verifier.sign_challenge(challenge, sk)
            >>> success, error = verifier.authenticate_user(
            ...     "alice@example.com",
            ...     sig,
            ...     pk,
            ...     challenge.get_hash().hex()
            ... )
            >>> assert success == True
        """
        # Find the challenge
        challenge = None
        if challenge_hash and challenge_hash in self._challenge_cache:
            challenge = self._challenge_cache[challenge_hash]

        if challenge is None:
            return False, "Challenge not found or expired"

        if challenge.user_id != user_id:
            return False, "User ID mismatch"

        if challenge.is_expired():
            # Clean up expired challenge
            if challenge_hash:
                self._challenge_cache.pop(challenge_hash, None)
            return False, "Challenge has expired"

        # Verify the signature
        is_valid = self.verify_signature(challenge, signature, public_key)

        if is_valid:
            # Clean up used challenge to prevent replay
            if challenge_hash:
                self._challenge_cache.pop(challenge_hash, None)
            return True, None
        else:
            return False, "Invalid signature"

    def cleanup_expired_challenges(self) -> int:
        """
        Remove expired challenges from cache.

        Returns:
            Number of challenges removed
        """
        expired = [
            cid for cid, challenge in self._challenge_cache.items()
            if challenge.is_expired()
        ]
        for cid in expired:
            del self._challenge_cache[cid]
        return len(expired)

    def get_key_info(self, public_key: bytes) -> Dict[str, Any]:
        """
        Get information about a public key.

        Args:
            public_key: ML-DSA-87 public key

        Returns:
            Dictionary with key information
        """
        key_hash = hashlib.sha3_256(public_key).hexdigest()
        return {
            "algorithm": "ML-DSA-87",
            "alternative_name": "CRYSTALS-Dilithium5",
            "security_level": "NIST Level 5",
            "quantum_security_bits": 256,
            "public_key_size": len(public_key),
            "expected_signature_size": "~4627 bytes",
            "key_fingerprint": key_hash[:16],
            "key_hash_sha3_256": key_hash
        }


def demo_authentication_flow():
    """
    Demonstrate complete authentication flow.

    This example shows:
    1. Keypair generation
    2. Challenge creation
    3. Challenge signing
    4. Signature verification
    5. Complete authentication
    """
    print("=== ML-DSA-87 Identity Verification Demo ===\n")

    # Initialize verifier
    verifier = IdentityVerifier(relying_party="demo-service")

    # Generate keypair for user
    print("1. Generating ML-DSA-87 keypair...")
    public_key, private_key = verifier.generate_keypair()
    print(f"   Public key size: {len(public_key)} bytes")
    print(f"   Private key size: {len(private_key)} bytes")

    # Display key information
    key_info = verifier.get_key_info(public_key)
    print(f"\n2. Key Information:")
    for k, v in key_info.items():
        print(f"   {k}: {v}")

    # Create authentication challenge
    print("\n3. Creating authentication challenge...")
    user_id = "alice@example.com"
    challenge = verifier.create_challenge(
        user_id=user_id,
        metadata={"ip": "192.168.1.100", "user_agent": "Mozilla/5.0"}
    )
    print(f"   User ID: {challenge.user_id}")
    print(f"   Challenge hash: {challenge.get_hash().hex()[:32]}...")
    print(f"   Expires at: {challenge.expires_at}")

    # Sign the challenge
    print("\n4. Signing challenge with private key...")
    signature = verifier.sign_challenge(challenge, private_key)
    print(f"   Signature size: {len(signature)} bytes")

    # Verify the signature
    print("\n5. Verifying signature...")
    is_valid = verifier.verify_signature(challenge, signature, public_key)
    print(f"   Signature valid: {is_valid}")

    # Complete authentication
    print("\n6. Completing authentication flow...")
    success, error = verifier.authenticate_user(
        user_id=user_id,
        signature=signature,
        public_key=public_key,
        challenge_hash=challenge.get_hash().hex()
    )
    print(f"   Authentication successful: {success}")
    if error:
        print(f"   Error: {error}")

    # Test with tampered signature
    print("\n7. Testing with tampered signature...")
    tampered_sig = bytearray(signature)
    tampered_sig[0] ^= 0xFF  # Flip bits in first byte
    is_valid = verifier.verify_signature(challenge, bytes(tampered_sig), public_key)
    print(f"   Tampered signature valid: {is_valid}")

    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    demo_authentication_flow()
