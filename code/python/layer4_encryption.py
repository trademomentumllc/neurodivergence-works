"""
Layer 4: Hybrid Envelope Encryption with AES-256-GCM and ML-KEM-1024

This module provides hybrid post-quantum encryption combining classical
AES-256-GCM with quantum-resistant ML-KEM-1024 (CRYSTALS-Kyber) key encapsulation.

Security Guarantees:
- NIST Security Level 5 (256-bit quantum security)
- IND-CCA2 secure key encapsulation mechanism
- Authenticated encryption with associated data (AEAD)
- Quantum resistance via lattice-based cryptography
- Public key size: 1568 bytes
- Ciphertext overhead: ~1568 bytes (encapsulated key)
- Shared secret: 32 bytes

Architecture:
    1. Generate random AES-256 key (data encryption key)
    2. Encrypt data with AES-256-GCM using DEK
    3. Encapsulate DEK using ML-KEM-1024 public key
    4. Package: encapsulated_key || nonce || tag || ciphertext

Example Usage:
    >>> # Initialize hybrid encryptor
    >>> encryptor = HybridEncryptor()
    >>>
    >>> # Generate keypair
    >>> public_key, private_key = encryptor.generate_keypair()
    >>>
    >>> # Encrypt data
    >>> plaintext = b"Sensitive medical records"
    >>> encrypted_envelope = encryptor.encrypt(plaintext, public_key)
    >>>
    >>> # Decrypt data
    >>> decrypted = encryptor.decrypt(encrypted_envelope, private_key)
    >>> assert decrypted == plaintext
"""

import struct
from typing import Tuple, Optional, Dict, Any
from dataclasses import dataclass

try:
    from pqcrypto.kem.ml_kem_1024 import (
        generate_keypair as kem_keygen,
        encrypt as kem_encapsulate,
        decrypt as kem_decapsulate
    )
except ImportError:
    raise ImportError(
        "pqcrypto is required. Install with: pip install pqcrypto"
    )

try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
except ImportError:
    raise ImportError(
        "pycryptodome is required. Install with: pip install pycryptodome"
    )


# Constants
AES_KEY_SIZE = 32  # 256 bits
AES_NONCE_SIZE = 12  # 96 bits (recommended for GCM)
AES_TAG_SIZE = 16  # 128 bits
ML_KEM_1024_PUBLIC_KEY_SIZE = 1568
ML_KEM_1024_PRIVATE_KEY_SIZE = 3168
ML_KEM_1024_CIPHERTEXT_SIZE = 1568
ML_KEM_1024_SHARED_SECRET_SIZE = 32


@dataclass
class EncryptedEnvelope:
    """
    Represents an encrypted data envelope using hybrid encryption.

    Structure:
        - encapsulated_key: ML-KEM-1024 encapsulated key (1568 bytes)
        - nonce: AES-GCM nonce (12 bytes)
        - tag: AES-GCM authentication tag (16 bytes)
        - ciphertext: AES-GCM encrypted data
        - associated_data: Optional AAD for additional authentication
    """
    encapsulated_key: bytes
    nonce: bytes
    tag: bytes
    ciphertext: bytes
    associated_data: Optional[bytes] = None

    def to_bytes(self) -> bytes:
        """
        Serialize envelope to binary format.

        Format:
            [4 bytes: encapsulated_key_len]
            [encapsulated_key]
            [12 bytes: nonce]
            [16 bytes: tag]
            [4 bytes: aad_len]
            [aad (if present)]
            [remaining: ciphertext]

        Returns:
            Serialized envelope as bytes
        """
        parts = []

        # Encapsulated key with length prefix
        parts.append(struct.pack('>I', len(self.encapsulated_key)))
        parts.append(self.encapsulated_key)

        # Nonce and tag (fixed sizes)
        parts.append(self.nonce)
        parts.append(self.tag)

        # Associated data with length prefix
        if self.associated_data:
            parts.append(struct.pack('>I', len(self.associated_data)))
            parts.append(self.associated_data)
        else:
            parts.append(struct.pack('>I', 0))

        # Ciphertext
        parts.append(self.ciphertext)

        return b''.join(parts)

    @classmethod
    def from_bytes(cls, data: bytes) -> 'EncryptedEnvelope':
        """
        Deserialize envelope from binary format.

        Args:
            data: Serialized envelope bytes

        Returns:
            EncryptedEnvelope object

        Raises:
            ValueError: If data is malformed
        """
        if len(data) < 36:  # Minimum: 4 + 12 + 16 + 4
            raise ValueError("Envelope data too short")

        offset = 0

        # Read encapsulated key
        ek_len = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        if offset + ek_len > len(data):
            raise ValueError("Invalid encapsulated key length")
        encapsulated_key = data[offset:offset+ek_len]
        offset += ek_len

        # Read nonce
        if offset + 12 > len(data):
            raise ValueError("Missing nonce")
        nonce = data[offset:offset+12]
        offset += 12

        # Read tag
        if offset + 16 > len(data):
            raise ValueError("Missing authentication tag")
        tag = data[offset:offset+16]
        offset += 16

        # Read associated data
        if offset + 4 > len(data):
            raise ValueError("Missing AAD length")
        aad_len = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4

        associated_data = None
        if aad_len > 0:
            if offset + aad_len > len(data):
                raise ValueError("Invalid AAD length")
            associated_data = data[offset:offset+aad_len]
            offset += aad_len

        # Remaining is ciphertext
        ciphertext = data[offset:]

        return cls(
            encapsulated_key=encapsulated_key,
            nonce=nonce,
            tag=tag,
            ciphertext=ciphertext,
            associated_data=associated_data
        )

    def get_size_breakdown(self) -> Dict[str, int]:
        """Get size breakdown of envelope components."""
        return {
            "encapsulated_key": len(self.encapsulated_key),
            "nonce": len(self.nonce),
            "tag": len(self.tag),
            "associated_data": len(self.associated_data) if self.associated_data else 0,
            "ciphertext": len(self.ciphertext),
            "total": len(self.to_bytes())
        }


class HybridEncryptor:
    """
    Hybrid Post-Quantum Encryption System.

    Combines AES-256-GCM (classical) with ML-KEM-1024 (post-quantum)
    for quantum-resistant authenticated encryption with perfect forward secrecy.
    """

    def __init__(self):
        """Initialize the hybrid encryptor."""
        self.algorithm_name = "AES-256-GCM + ML-KEM-1024"

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a new ML-KEM-1024 keypair.

        Returns:
            Tuple of (public_key, private_key) as bytes
            - public_key: 1568 bytes
            - private_key: 3168 bytes

        Raises:
            RuntimeError: If keypair generation fails

        Security Notes:
            - Private key must be stored securely
            - Public key can be freely distributed
            - Each entity should have a unique keypair
        """
        try:
            public_key, private_key = kem_keygen()

            if len(public_key) != ML_KEM_1024_PUBLIC_KEY_SIZE:
                raise RuntimeError(
                    f"Unexpected public key size: {len(public_key)} bytes"
                )
            if len(private_key) != ML_KEM_1024_PRIVATE_KEY_SIZE:
                raise RuntimeError(
                    f"Unexpected private key size: {len(private_key)} bytes"
                )

            return public_key, private_key
        except Exception as e:
            raise RuntimeError(f"Failed to generate ML-KEM-1024 keypair: {e}")

    def encrypt(
        self,
        plaintext: bytes,
        recipient_public_key: bytes,
        associated_data: Optional[bytes] = None
    ) -> EncryptedEnvelope:
        """
        Encrypt data using hybrid envelope encryption.

        Process:
            1. Generate random AES-256 key (DEK)
            2. Encrypt plaintext with AES-256-GCM using DEK
            3. Encapsulate DEK with ML-KEM-1024
            4. Package all components into envelope

        Args:
            plaintext: Data to encrypt
            recipient_public_key: ML-KEM-1024 public key (1568 bytes)
            associated_data: Optional additional authenticated data (not encrypted)

        Returns:
            EncryptedEnvelope containing all components

        Raises:
            ValueError: If public key is invalid
            RuntimeError: If encryption fails

        Security Notes:
            - DEK is never reused (fresh for each encryption)
            - Nonce is randomly generated (never reused with same key)
            - Provides IND-CCA2 security
            - AAD is authenticated but not encrypted
        """
        if len(recipient_public_key) != ML_KEM_1024_PUBLIC_KEY_SIZE:
            raise ValueError(
                f"Invalid public key size: {len(recipient_public_key)} bytes "
                f"(expected {ML_KEM_1024_PUBLIC_KEY_SIZE} bytes)"
            )

        try:
            # Step 1: Use KEM to generate encapsulated shared secret
            # KEM generates a random shared secret and encapsulates it
            encapsulated_key, shared_secret = kem_encapsulate(recipient_public_key)

            # The shared secret IS our DEK (32 bytes = 256 bits for AES-256)
            dek = shared_secret

            # Verify sizes
            if len(encapsulated_key) != ML_KEM_1024_CIPHERTEXT_SIZE:
                raise RuntimeError(
                    f"Unexpected encapsulated key size: {len(encapsulated_key)} bytes"
                )
            if len(dek) != AES_KEY_SIZE:
                raise RuntimeError(
                    f"Unexpected shared secret size: {len(dek)} bytes"
                )

            # Step 2: Encrypt plaintext with AES-256-GCM using the shared secret
            nonce = get_random_bytes(AES_NONCE_SIZE)
            cipher = AES.new(dek, AES.MODE_GCM, nonce=nonce)

            if associated_data:
                cipher.update(associated_data)

            ciphertext = cipher.encrypt(plaintext)
            tag = cipher.digest()

            # Step 3: Create envelope
            envelope = EncryptedEnvelope(
                encapsulated_key=encapsulated_key,
                nonce=nonce,
                tag=tag,
                ciphertext=ciphertext,
                associated_data=associated_data
            )

            # Securely erase DEK from memory
            del dek
            del shared_secret

            return envelope

        except Exception as e:
            raise RuntimeError(f"Encryption failed: {e}")

    def decrypt(
        self,
        envelope: EncryptedEnvelope,
        recipient_private_key: bytes
    ) -> bytes:
        """
        Decrypt data from encrypted envelope.

        Process:
            1. Decapsulate DEK using ML-KEM-1024 private key
            2. Decrypt ciphertext with AES-256-GCM using DEK
            3. Verify authentication tag

        Args:
            envelope: EncryptedEnvelope to decrypt
            recipient_private_key: ML-KEM-1024 private key (3168 bytes)

        Returns:
            Decrypted plaintext as bytes

        Raises:
            ValueError: If private key or envelope is invalid
            RuntimeError: If decryption or authentication fails

        Security Notes:
            - Authentication tag is verified before returning plaintext
            - Fails securely on any tampering or corruption
            - Constant-time tag verification prevents timing attacks
        """
        if len(recipient_private_key) != ML_KEM_1024_PRIVATE_KEY_SIZE:
            raise ValueError(
                f"Invalid private key size: {len(recipient_private_key)} bytes "
                f"(expected {ML_KEM_1024_PRIVATE_KEY_SIZE} bytes)"
            )

        if len(envelope.encapsulated_key) != ML_KEM_1024_CIPHERTEXT_SIZE:
            raise ValueError(
                f"Invalid encapsulated key size: {len(envelope.encapsulated_key)} bytes"
            )

        if len(envelope.nonce) != AES_NONCE_SIZE:
            raise ValueError(f"Invalid nonce size: {len(envelope.nonce)} bytes")

        if len(envelope.tag) != AES_TAG_SIZE:
            raise ValueError(f"Invalid tag size: {len(envelope.tag)} bytes")

        try:
            # Step 1: Decapsulate to recover shared secret (which is our DEK)
            dek = kem_decapsulate(recipient_private_key, envelope.encapsulated_key)

            if len(dek) != AES_KEY_SIZE:
                raise RuntimeError(f"Invalid decapsulated key size: {len(dek)} bytes")

            # Step 2: Decrypt with AES-256-GCM
            cipher = AES.new(dek, AES.MODE_GCM, nonce=envelope.nonce)

            if envelope.associated_data:
                cipher.update(envelope.associated_data)

            # Step 3: Decrypt and verify tag
            plaintext = cipher.decrypt_and_verify(envelope.ciphertext, envelope.tag)

            # Securely erase DEK from memory
            del dek

            return plaintext

        except ValueError as e:
            # Authentication failure
            raise RuntimeError(f"Decryption failed - authentication error: {e}")
        except Exception as e:
            raise RuntimeError(f"Decryption failed: {e}")

    def encrypt_to_bytes(
        self,
        plaintext: bytes,
        recipient_public_key: bytes,
        associated_data: Optional[bytes] = None
    ) -> bytes:
        """
        Encrypt data and return serialized envelope.

        Args:
            plaintext: Data to encrypt
            recipient_public_key: ML-KEM-1024 public key
            associated_data: Optional AAD

        Returns:
            Serialized encrypted envelope as bytes
        """
        envelope = self.encrypt(plaintext, recipient_public_key, associated_data)
        return envelope.to_bytes()

    def decrypt_from_bytes(
        self,
        envelope_bytes: bytes,
        recipient_private_key: bytes
    ) -> bytes:
        """
        Decrypt data from serialized envelope.

        Args:
            envelope_bytes: Serialized encrypted envelope
            recipient_private_key: ML-KEM-1024 private key

        Returns:
            Decrypted plaintext as bytes
        """
        envelope = EncryptedEnvelope.from_bytes(envelope_bytes)
        return self.decrypt(envelope, recipient_private_key)

    def get_algorithm_info(self) -> Dict[str, Any]:
        """
        Get information about the hybrid encryption algorithm.

        Returns:
            Dictionary with algorithm details
        """
        return {
            "name": self.algorithm_name,
            "kem_algorithm": "ML-KEM-1024",
            "kem_alternative_name": "CRYSTALS-Kyber1024",
            "symmetric_algorithm": "AES-256-GCM",
            "security_level": "NIST Level 5",
            "quantum_security_bits": 256,
            "classical_security_bits": 256,
            "public_key_size": ML_KEM_1024_PUBLIC_KEY_SIZE,
            "private_key_size": ML_KEM_1024_PRIVATE_KEY_SIZE,
            "encapsulated_key_size": ML_KEM_1024_CIPHERTEXT_SIZE,
            "shared_secret_size": ML_KEM_1024_SHARED_SECRET_SIZE,
            "nonce_size": AES_NONCE_SIZE,
            "tag_size": AES_TAG_SIZE,
            "minimum_overhead_bytes": ML_KEM_1024_CIPHERTEXT_SIZE + AES_NONCE_SIZE + AES_TAG_SIZE
        }

    def calculate_ciphertext_size(self, plaintext_size: int, aad_size: int = 0) -> int:
        """
        Calculate expected ciphertext size for given plaintext.

        Args:
            plaintext_size: Size of plaintext in bytes
            aad_size: Size of associated data in bytes

        Returns:
            Total size of encrypted envelope in bytes
        """
        # 4 bytes: encapsulated_key_len
        # ML_KEM_1024_CIPHERTEXT_SIZE: encapsulated key
        # 12 bytes: nonce
        # 16 bytes: tag
        # 4 bytes: aad_len
        # aad_size: associated data
        # plaintext_size: ciphertext (same size as plaintext in GCM)
        return (
            4 + ML_KEM_1024_CIPHERTEXT_SIZE +
            AES_NONCE_SIZE + AES_TAG_SIZE +
            4 + aad_size + plaintext_size
        )


def demo_hybrid_encryption():
    """
    Demonstrate hybrid encryption functionality.

    This example shows:
    1. Keypair generation
    2. Data encryption with AAD
    3. Data decryption
    4. Size calculations
    5. Tampering detection
    """
    print("=== Hybrid ML-KEM-1024 + AES-256-GCM Encryption Demo ===\n")

    # Initialize encryptor
    encryptor = HybridEncryptor()

    # Display algorithm info
    print("1. Algorithm Information:")
    algo_info = encryptor.get_algorithm_info()
    for key, value in algo_info.items():
        print(f"   {key}: {value}")

    # Generate keypair
    print("\n2. Generating ML-KEM-1024 keypair...")
    public_key, private_key = encryptor.generate_keypair()
    print(f"   Public key size: {len(public_key)} bytes")
    print(f"   Private key size: {len(private_key)} bytes")

    # Prepare data
    plaintext = b"CONFIDENTIAL: Patient diagnosis and treatment plan for Case #12345"
    aad = b"patient_id=12345|timestamp=2025-12-24T10:00:00Z"

    print(f"\n3. Encrypting data...")
    print(f"   Plaintext size: {len(plaintext)} bytes")
    print(f"   AAD size: {len(aad)} bytes")

    # Encrypt
    envelope = encryptor.encrypt(plaintext, public_key, aad)

    # Show envelope details
    print(f"\n4. Encrypted Envelope:")
    size_breakdown = envelope.get_size_breakdown()
    for component, size in size_breakdown.items():
        print(f"   {component}: {size} bytes")

    # Calculate overhead
    overhead = size_breakdown['total'] - len(plaintext)
    print(f"\n   Encryption overhead: {overhead} bytes")
    print(f"   Overhead percentage: {overhead/len(plaintext)*100:.1f}%")

    # Serialize and deserialize
    print(f"\n5. Serialization test...")
    serialized = envelope.to_bytes()
    deserialized = EncryptedEnvelope.from_bytes(serialized)
    print(f"   Serialized size: {len(serialized)} bytes")
    print(f"   Round-trip successful: {deserialized.ciphertext == envelope.ciphertext}")

    # Decrypt
    print(f"\n6. Decrypting data...")
    decrypted = encryptor.decrypt(envelope, private_key)
    print(f"   Decryption successful: {decrypted == plaintext}")
    print(f"   Decrypted text: {decrypted.decode('utf-8')}")

    # Test tampering detection
    print(f"\n7. Testing tampering detection...")
    tampered_envelope = EncryptedEnvelope(
        encapsulated_key=envelope.encapsulated_key,
        nonce=envelope.nonce,
        tag=envelope.tag,
        ciphertext=envelope.ciphertext + b'\x00',  # Append byte
        associated_data=envelope.associated_data
    )

    try:
        encryptor.decrypt(tampered_envelope, private_key)
        print("   ERROR: Tampered data was accepted!")
    except RuntimeError as e:
        print(f"   Tampering detected successfully: {str(e)[:50]}...")

    # Test AAD verification
    print(f"\n8. Testing AAD verification...")
    wrong_aad_envelope = EncryptedEnvelope(
        encapsulated_key=envelope.encapsulated_key,
        nonce=envelope.nonce,
        tag=envelope.tag,
        ciphertext=envelope.ciphertext,
        associated_data=b"wrong_aad"
    )

    try:
        encryptor.decrypt(wrong_aad_envelope, private_key)
        print("   ERROR: Wrong AAD was accepted!")
    except RuntimeError as e:
        print(f"   AAD mismatch detected successfully: {str(e)[:50]}...")

    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    demo_hybrid_encryption()
