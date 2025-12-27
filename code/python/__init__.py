"""
Eight-Layer Post-Quantum Cryptography (PQC) Security Framework

This package provides a comprehensive post-quantum cryptographic security framework
implementing eight layers of defense-in-depth protection using NIST-standardized
algorithms.

Layers:
    1. Identity Verification - ML-DSA-87 (Dilithium5) signatures for authentication
    2. [Not implemented in this package]
    3. [Not implemented in this package]
    4. Hybrid Encryption - ML-KEM-1024 (Kyber1024) + AES-256-GCM envelope encryption
    5. [Not implemented in this package]
    6. PHI Isolation - HIPAA-compliant PHI protection with HMAC-SHA3-384
    7. [Not implemented in this package]
    8. Orchestration - Central PQC algorithm coordination and validation

Security Guarantees:
    - NIST Security Level 5 (256-bit quantum security)
    - Quantum resistance against Shor's and Grover's algorithms
    - IND-CCA2 secure key encapsulation
    - UF-CMA secure digital signatures
    - HIPAA and FHIR R4 compliance for healthcare data

Example Usage:
    >>> from eight_layer_pqc import (
    ...     IdentityVerifier,
    ...     HybridEncryptor,
    ...     PHIManager,
    ...     PQCOrchestrator
    ... )
    >>>
    >>> # Initialize components
    >>> identity = IdentityVerifier()
    >>> encryptor = HybridEncryptor()
    >>> orchestrator = PQCOrchestrator()
    >>>
    >>> # Register layers with orchestrator
    >>> orchestrator.register_layer(
    ...     layer_id="identity",
    ...     layer_name="Identity Verification",
    ...     algorithms=["ML-DSA-87"]
    ... )
    >>>
    >>> # Generate keys
    >>> sign_pk, sign_sk = identity.generate_keypair()
    >>> enc_pk, enc_sk = encryptor.generate_keypair()
    >>>
    >>> # Authenticate user
    >>> challenge = identity.create_challenge("alice@example.com")
    >>> signature = identity.sign_challenge(challenge, sign_sk)
    >>> is_valid = identity.verify_signature(challenge, signature, sign_pk)
    >>>
    >>> # Encrypt data
    >>> plaintext = b"Sensitive data"
    >>> envelope = encryptor.encrypt(plaintext, enc_pk)
    >>> decrypted = encryptor.decrypt(envelope, enc_sk)

Dependencies:
    - pqcrypto: Post-quantum cryptography primitives
    - pycryptodome: Classical cryptography (AES-GCM)

License:
    See LICENSE file in repository root

Security Contact:
    For security issues, see SECURITY.md in repository root

Author: Jason Jarmacz (NeuroDivergent AI Evolution Strategist)
Organization: Trade Momentum LLC / Neurodivergence.Works
Version: 2.0.0
"""

__version__ = "2.0.0"
__author__ = "Jason Jarmacz"
__license__ = "See LICENSE"

# Layer 1: Identity Verification
from .layer1_identity import (
    IdentityVerifier,
    AuthenticationChallenge,
    demo_authentication_flow
)

# Layer 4: Hybrid Encryption
from .layer4_encryption import (
    HybridEncryptor,
    EncryptedEnvelope,
    demo_hybrid_encryption
)

# Layer 6: PHI Isolation
from .layer6_phi import (
    PHIManager,
    PHICompartment,
    AuditLogEntry,
    FHIRResourceType,
    AccessLevel,
    demo_phi_management
)

# Layer 8: Orchestration
from .layer8_orchestrator import (
    PQCOrchestrator,
    SecurityPolicy,
    SecurityLevel,
    AlgorithmType,
    AlgorithmMetadata,
    LayerRegistration,
    LayerStatus,
    OperationMetrics,
    demo_orchestration
)

# Public API
__all__ = [
    # Layer 1
    "IdentityVerifier",
    "AuthenticationChallenge",
    "demo_authentication_flow",

    # Layer 4
    "HybridEncryptor",
    "EncryptedEnvelope",
    "demo_hybrid_encryption",

    # Layer 6
    "PHIManager",
    "PHICompartment",
    "AuditLogEntry",
    "FHIRResourceType",
    "AccessLevel",
    "demo_phi_management",

    # Layer 8
    "PQCOrchestrator",
    "SecurityPolicy",
    "SecurityLevel",
    "AlgorithmType",
    "AlgorithmMetadata",
    "LayerRegistration",
    "LayerStatus",
    "OperationMetrics",
    "demo_orchestration",
]


def get_version() -> str:
    """Get the package version."""
    return __version__


def get_security_info() -> dict:
    """
    Get security information about the PQC framework.

    Returns:
        Dictionary containing security parameters and guarantees
    """
    return {
        "version": __version__,
        "nist_security_level": 5,
        "quantum_security_bits": 256,
        "classical_security_bits": 256,
        "algorithms": {
            "signature": {
                "name": "ML-DSA-87",
                "alternative_name": "CRYSTALS-Dilithium5",
                "standardized": True,
                "public_key_size": 2592,
                "private_key_size": 4864,
                "signature_size": 4595
            },
            "kem": {
                "name": "ML-KEM-1024",
                "alternative_name": "CRYSTALS-Kyber1024",
                "standardized": True,
                "public_key_size": 1568,
                "private_key_size": 3168,
                "ciphertext_size": 1568
            },
            "symmetric": {
                "name": "AES-256-GCM",
                "standardized": True,
                "key_size": 32,
                "nonce_size": 12,
                "tag_size": 16
            },
            "hash": {
                "name": "HMAC-SHA3-384",
                "standardized": True,
                "key_size": 48,
                "output_size": 48
            }
        },
        "compliance": [
            "NIST FIPS 203 (ML-KEM)",
            "NIST FIPS 204 (ML-DSA)",
            "NIST FIPS 202 (SHA-3)",
            "NIST FIPS 197 (AES)",
            "HIPAA (45 CFR Part 160, 164)",
            "FHIR R4 (HL7)",
            "21 CFR Part 11 (FDA)"
        ],
        "security_properties": [
            "IND-CCA2 (KEM)",
            "UF-CMA (Signatures)",
            "AEAD (Authenticated Encryption)",
            "Quantum Resistant",
            "Defense-in-Depth"
        ]
    }


def run_all_demos():
    """
    Run all demonstration functions for each layer.

    This will execute:
    - Layer 1: Identity verification demo
    - Layer 4: Hybrid encryption demo
    - Layer 6: PHI management demo
    - Layer 8: Orchestration demo
    """
    print("=" * 80)
    print("EIGHT-LAYER PQC FRAMEWORK - COMPLETE DEMONSTRATION")
    print("=" * 80)
    print()

    # Display security information
    print("Framework Security Information:")
    print("-" * 80)
    info = get_security_info()
    print(f"Version: {info['version']}")
    print(f"NIST Security Level: {info['nist_security_level']}")
    print(f"Quantum Security: {info['quantum_security_bits']} bits")
    print(f"Classical Security: {info['classical_security_bits']} bits")
    print()
    print("Algorithms:")
    for algo_type, details in info['algorithms'].items():
        print(f"  {algo_type.upper()}: {details['name']}")
    print()
    print("Compliance Standards:")
    for standard in info['compliance']:
        print(f"  - {standard}")
    print()
    print("=" * 80)
    print()

    # Run demos
    try:
        demo_authentication_flow()
        print("\n" + "=" * 80 + "\n")

        demo_hybrid_encryption()
        print("\n" + "=" * 80 + "\n")

        demo_phi_management()
        print("\n" + "=" * 80 + "\n")

        demo_orchestration()
        print("\n" + "=" * 80 + "\n")

        print("ALL DEMONSTRATIONS COMPLETED SUCCESSFULLY")
        print("=" * 80)

    except Exception as e:
        print(f"\nError during demonstration: {e}")
        raise


def validate_environment() -> tuple:
    """
    Validate that all required cryptographic libraries are available.

    Returns:
        tuple[bool, str]: (success, message)

    Example:
        >>> success, msg = validate_environment()
        >>> if not success:
        ...     print(f"Environment validation failed: {msg}")
    """
    try:
        # Test pqcrypto availability
        import pqcrypto.kem.ml_kem_1024
        import pqcrypto.sign.ml_dsa_87
    except ImportError as e:
        return False, f"PQCrypto library not available: {e}"

    try:
        # Test pycryptodome availability
        from Crypto.Cipher import AES
        from Crypto.Hash import SHA3_384, HMAC
    except ImportError as e:
        return False, f"Pycryptodome library not available: {e}"

    return True, "All cryptographic libraries validated successfully"


if __name__ == "__main__":
    # When running the package as a module, show security info
    import json
    print(json.dumps(get_security_info(), indent=2))
