# Layer 4: Data Encryption Specification

## Purpose

Layer 4 provides quantum-resistant data encryption at rest and in processing through hybrid envelope encryption combining AES-256-GCM with ML-KEM-1024 (FIPS 203) key encapsulation. This layer ensures that all sensitive data stored in databases, file systems, and memory is protected with authenticated encryption, safeguarding against both classical and quantum adversaries. It implements defense-in-depth with key hierarchy, secure key derivation, and cryptographic erasure capabilities.

## Algorithms

### Primary Algorithms
- **AES-256-GCM**: Authenticated encryption for data encryption
  - Key size: 256 bits (32 bytes)
  - Nonce size: 96 bits (12 bytes)
  - Authentication tag size: 128 bits (16 bytes)
  - Encryption speed: ~5 GB/s (hardware accelerated)
  - Classical security: 256-bit

- **ML-KEM-1024** (FIPS 203): Key encapsulation for data encryption keys (DEKs)
  - Public key size: 1,568 bytes
  - Ciphertext size: 1,568 bytes
  - Shared secret size: 32 bytes
  - Quantum security: NIST Level 5 (256-bit)

### Supporting Algorithms
- **HKDF-SHA256**: Key derivation function
  - Extract and expand operations
  - Context binding for derived keys
  - Salt management for key strengthening

- **SHA3-384**:
  - Content hashing for deduplication
  - Key commitment schemes
  - Data integrity verification

- **ChaCha20-Poly1305**: Alternative AEAD cipher
  - Key size: 256 bits
  - Nonce size: 96 bits
  - Tag size: 128 bits
  - Use case: Mobile devices, embedded systems

### Envelope Encryption Structure
```
Plaintext Data
  ↓ (Encrypt with DEK)
Ciphertext + GCM Tag
  ↓ (DEK wrapped with KEK via ML-KEM-1024)
Encrypted DEK (ML-KEM-1024 ciphertext)
  ↓ (Store together)
Encrypted Blob = {
  ciphertext: bytes,
  tag: bytes,
  encrypted_dek: bytes,
  nonce: bytes,
  metadata: {
    algorithm: "AES-256-GCM",
    kem_algorithm: "ML-KEM-1024",
    kdf: "HKDF-SHA256"
  }
}
```

## Security Strength

- **Quantum Security Level**: 256-bit (via ML-KEM-1024 key protection)
- **Classical Security Level**: 256-bit (via AES-256-GCM)
- **Authentication Strength**: 128-bit (GCM tag)
- **Key Hierarchy Depth**: 3 levels (Root KEK → KEK → DEK)
- **DEK Lifetime**: Single-use or per-object (ephemeral)
- **KEK Rotation Period**: 30 days
- **Root KEK Storage**: Hardware Security Module (HSM) only

## Key Hierarchy and Envelope Encryption

### Three-Level Key Hierarchy

```
Level 0: Root Key Encryption Key (Root KEK)
├─ Stored in HSM/TPM (never leaves hardware)
├─ Used to wrap Level 1 KEKs
├─ Rotation: 1 year or on compromise
└─ Backed up in split-knowledge scheme (Shamir's Secret Sharing)

Level 1: Key Encryption Keys (KEKs)
├─ One per data classification or service
├─ Encrypted by Root KEK using ML-KEM-1024
├─ Stored in secure key management service
├─ Rotation: 30 days
└─ Used to wrap Level 2 DEKs

Level 2: Data Encryption Keys (DEKs)
├─ One per data object (file, record, message)
├─ Encrypted by KEK using ML-KEM-1024
├─ Ephemeral (generated per encryption operation)
├─ Never stored in plaintext
└─ Used to encrypt actual data with AES-256-GCM
```

### Encryption Flow

**Step 1: DEK Generation**
```
1. Generate random DEK: DEK = SecureRandom(32 bytes)
2. Validate DEK entropy (NIST SP 800-90B compliance)
3. Bind DEK to context: DEK_ctx = HKDF-Expand(DEK, context_info)
```

**Step 2: Data Encryption**
```
1. Generate unique nonce: nonce = SecureRandom(12 bytes)
2. Prepare additional authenticated data (AAD):
   AAD = {
     data_id: UUID,
     timestamp: ISO8601,
     classification: string,
     version: integer
   }
3. Encrypt data:
   (ciphertext, tag) = AES-256-GCM.Encrypt(
     key=DEK_ctx,
     nonce=nonce,
     plaintext=data,
     aad=AAD
   )
```

**Step 3: DEK Encapsulation**
```
1. Retrieve KEK public key for data classification
2. Encapsulate DEK:
   encrypted_dek = ML-KEM-1024.Encapsulate(
     public_key=KEK_public,
     plaintext=DEK
   )
3. Securely erase DEK from memory
```

**Step 4: Storage**
```
Store {
  ciphertext: ciphertext,
  tag: tag,
  nonce: nonce,
  encrypted_dek: encrypted_dek,
  aad: AAD,
  metadata: {
    kek_id: UUID,
    algorithm: "AES-256-GCM",
    kem_algorithm: "ML-KEM-1024",
    timestamp: ISO8601
  }
}
```

### Decryption Flow

**Step 1: Retrieve Encrypted Data**
```
1. Fetch encrypted blob from storage
2. Validate blob integrity (SHA3-384 hash)
3. Extract encrypted_dek and metadata
```

**Step 2: DEK Decapsulation**
```
1. Retrieve KEK secret key from KMS (authenticated with Layer 2 capability token)
2. Decapsulate DEK:
   DEK = ML-KEM-1024.Decapsulate(
     secret_key=KEK_secret,
     ciphertext=encrypted_dek
   )
3. Derive context-bound key:
   DEK_ctx = HKDF-Expand(DEK, context_info from AAD)
```

**Step 3: Data Decryption**
```
1. Decrypt data:
   plaintext = AES-256-GCM.Decrypt(
     key=DEK_ctx,
     nonce=nonce,
     ciphertext=ciphertext,
     tag=tag,
     aad=AAD
   )
2. Verify tag (authenticated decryption)
3. Securely erase DEK and DEK_ctx from memory
4. Return plaintext
```

## Key Derivation with HKDF-SHA256

### Master Key Derivation
```
// Extract phase: Create pseudorandom key
PRK = HKDF-Extract(
  salt=application_salt,  // Fixed per application
  IKM=master_secret      // From HSM or secure source
)

// Expand phase: Derive purpose-specific keys
KEK = HKDF-Expand(
  PRK=PRK,
  info="KEK" || classification || timestamp,
  length=32
)

DEK = HKDF-Expand(
  PRK=PRK,
  info="DEK" || object_id || timestamp,
  length=32
)
```

### Context Binding
```
Context information includes:
- Data object ID (UUID)
- Data classification level
- Service identifier
- Timestamp
- User/service principal
- Intended purpose

Context-bound key:
DEK_ctx = HKDF-Expand(
  PRK=DEK,
  info=context_info_hash,  // SHA3-384(context_json)
  length=32
)

This prevents key misuse across different contexts.
```

### Key Commitment
```
For each DEK, compute commitment:
commitment = SHA3-384(DEK || nonce || object_id)

Store commitment alongside encrypted data.
During decryption, verify:
recomputed_commitment == stored_commitment

Prevents key substitution attacks.
```

## API Contract

### Endpoint: `/api/v1/encryption/encrypt`

**Request:**
```json
{
  "session_token": "base64url",
  "capability_token": "base64url",
  "plaintext": "base64url",
  "data_classification": "public|internal|confidential|restricted|phi",
  "context": {
    "data_id": "uuid",
    "purpose": "string",
    "metadata": {}
  },
  "algorithm": "AES-256-GCM|ChaCha20-Poly1305 (optional)"
}
```

**Response (Success):**
```json
{
  "status": "encrypted",
  "ciphertext": "base64url",
  "tag": "base64url",
  "nonce": "base64url",
  "encrypted_dek": "base64url",
  "kek_id": "uuid",
  "aad": {
    "data_id": "uuid",
    "timestamp": "ISO8601",
    "classification": "string",
    "version": 1
  },
  "metadata": {
    "algorithm": "AES-256-GCM",
    "kem_algorithm": "ML-KEM-1024",
    "kdf": "HKDF-SHA256"
  },
  "encryption_proof": {
    "commitment": "base64url (SHA3-384)",
    "mldsa87_signature": "base64url"
  }
}
```

### Endpoint: `/api/v1/encryption/decrypt`

**Request:**
```json
{
  "session_token": "base64url",
  "capability_token": "base64url",
  "ciphertext": "base64url",
  "tag": "base64url",
  "nonce": "base64url",
  "encrypted_dek": "base64url",
  "kek_id": "uuid",
  "aad": {},
  "context": {
    "data_id": "uuid",
    "purpose": "string"
  }
}
```

**Response (Success):**
```json
{
  "status": "decrypted",
  "plaintext": "base64url",
  "decryption_proof": {
    "commitment_verified": "boolean",
    "tag_verified": "boolean",
    "mldsa87_signature": "base64url",
    "timestamp": "ISO8601"
  }
}
```

**Response (Failure):**
```json
{
  "status": "error",
  "error_code": "string",
  "error_message": "string",
  "failed_checks": ["string"]
}
```

### Endpoint: `/api/v1/encryption/keys/rotate`

**Request:**
```json
{
  "session_token": "base64url",
  "admin_capability_token": "base64url",
  "kek_id": "uuid",
  "rotation_reason": "scheduled|compromised|policy_change"
}
```

**Response (Success):**
```json
{
  "status": "rotated",
  "old_kek_id": "uuid",
  "new_kek_id": "uuid",
  "rotation_timestamp": "ISO8601",
  "affected_objects": "integer",
  "re_encryption_status": "queued|in_progress|completed",
  "rotation_proof": {
    "mldsa87_signature": "base64url",
    "audit_hash": "base64url"
  }
}
```

### Endpoint: `/api/v1/encryption/keys/generate`

**Request:**
```json
{
  "session_token": "base64url",
  "admin_capability_token": "base64url",
  "key_type": "KEK|DEK",
  "classification": "string",
  "purpose": "string"
}
```

**Response (Success):**
```json
{
  "status": "generated",
  "key_id": "uuid",
  "public_key": "base64url (for ML-KEM-1024)",
  "key_metadata": {
    "algorithm": "ML-KEM-1024",
    "purpose": "string",
    "classification": "string",
    "created_at": "ISO8601",
    "expires_at": "ISO8601"
  },
  "generation_proof": {
    "entropy_quality": "high|medium",
    "mldsa87_signature": "base64url"
  }
}
```

### Endpoint: `/api/v1/encryption/batch/encrypt`

**Request:**
```json
{
  "session_token": "base64url",
  "capability_token": "base64url",
  "objects": [
    {
      "plaintext": "base64url",
      "data_id": "uuid",
      "classification": "string"
    }
  ],
  "shared_kek": "boolean (use same KEK for all objects)"
}
```

**Response (Success):**
```json
{
  "status": "batch_encrypted",
  "results": [
    {
      "data_id": "uuid",
      "ciphertext": "base64url",
      "tag": "base64url",
      "nonce": "base64url",
      "encrypted_dek": "base64url"
    }
  ],
  "batch_proof": {
    "mldsa87_signature": "base64url",
    "batch_hash": "base64url (SHA3-384)"
  }
}
```

## Error Codes

| Code | Name | Description | Retry | Lockout |
|------|------|-------------|-------|---------|
| `ENC-4001` | `ENCRYPTION_FAILED` | AES-256-GCM encryption operation failed | Yes (1x) | N/A |
| `ENC-4002` | `DECRYPTION_FAILED` | AES-256-GCM decryption operation failed | Yes (1x) | N/A |
| `ENC-4003` | `TAG_VERIFICATION_FAILED` | GCM authentication tag invalid | No | 900s |
| `ENC-4004` | `KEY_ENCAPSULATION_FAILED` | ML-KEM-1024 encapsulation failed | Yes (2x) | N/A |
| `ENC-4005` | `KEY_DECAPSULATION_FAILED` | ML-KEM-1024 decapsulation failed | Yes (2x) | 900s |
| `ENC-4006` | `KEK_NOT_FOUND` | Key encryption key not found | No | N/A |
| `ENC-4007` | `KEK_EXPIRED` | Key encryption key expired | No | N/A |
| `ENC-4008` | `DEK_GENERATION_FAILED` | Data encryption key generation failed | Yes (3x) | N/A |
| `ENC-4009` | `INSUFFICIENT_ENTROPY` | Random number generator entropy too low | Yes (1x) | 300s |
| `ENC-4010` | `COMMITMENT_VERIFICATION_FAILED` | Key commitment hash mismatch | No | 1800s |
| `ENC-4011` | `CONTEXT_MISMATCH` | Decryption context doesn't match encryption context | No | N/A |
| `ENC-4012` | `AAD_MISMATCH` | Additional authenticated data mismatch | No | 900s |
| `ENC-4013` | `NONCE_REUSE_DETECTED` | Nonce reuse detected (catastrophic) | No | Immediate |
| `ENC-4014` | `KEY_ROTATION_FAILED` | Key rotation operation failed | Yes (2x) | N/A |
| `ENC-4015` | `UNSUPPORTED_ALGORITHM` | Requested encryption algorithm not supported | No | N/A |
| `ENC-4016` | `CLASSIFICATION_MISMATCH` | Data classification doesn't match KEK classification | No | N/A |
| `ENC-4017` | `HSM_UNAVAILABLE` | Hardware security module unavailable | Yes (5x) | N/A |
| `ENC-4018` | `BATCH_ENCRYPTION_PARTIAL_FAILURE` | Some objects in batch failed | Partial | N/A |

## Compliance Mapping

### NIST Standards
- **FIPS 203**: ML-KEM key encapsulation mechanism
- **FIPS 197**: AES encryption standard
- **SP 800-38D**: GCM mode of operation
- **SP 800-57**: Key Management Recommendations
  - Part 1: General guidance (key lifecycle)
  - Part 2: Best practices for key management
  - Part 3: Application-specific key management
- **SP 800-108**: Key Derivation Using Pseudorandom Functions
- **SP 800-132**: Password-Based Key Derivation (for user-derived keys)
- **NIST Cybersecurity Framework**:
  - PR.DS-1: Data at rest protected
  - PR.DS-5: Protections against data leaks
  - PR.IP-2: System development lifecycle manages security

### HIPAA Requirements
- **164.312(a)(2)(iv)**: Encryption and Decryption
  - AES-256-GCM for ePHI encryption at rest
  - ML-KEM-1024 provides quantum-resistant key protection
- **164.312(e)(2)(ii)**: Encryption
  - 256-bit quantum security strength
  - Authenticated encryption prevents tampering
- **164.308(b)(1)**: Business Associate Contracts
  - Encryption ensures data protection when shared

### SOC 2 Type II Controls
- **CC6.1**: Encryption Keys Protected
  - Three-level key hierarchy
  - HSM storage for root keys
- **CC6.7**: Data Encrypted at Rest
  - All sensitive data encrypted with AES-256-GCM
  - Per-object DEKs for granular protection

### GDPR Compliance
- **Article 32**: Security of Processing
  - Encryption as state-of-the-art technical measure
  - Quantum-resistant protection for long-term data
- **Article 32(1)(a)**: Pseudonymization and Encryption
  - Mandatory encryption for personal data
- **Article 17**: Right to Erasure
  - Cryptographic erasure via key destruction

### PCI DSS v4.0
- **Requirement 3.5**: Encryption for Stored PAN
  - AES-256 minimum encryption strength
  - Authenticated encryption (GCM mode)
- **Requirement 3.6**: Cryptographic Key Management
  - Key hierarchy implementation
  - KEK rotation every 30 days
  - HSM storage for key encryption keys
- **Requirement 3.7**: Encryption Key Access Restricted
  - Layer 2 authorization required for key access
  - Audit logging for all key operations

### ISO/IEC 27001:2022
- **A.8.24**: Use of Cryptography
  - AES-256-GCM and ML-KEM-1024 usage
  - Key management procedures
- **A.10.1.1**: Cryptographic Controls
  - Encryption for sensitive information
- **A.10.1.2**: Key Management
  - Key lifecycle management
  - Separation of duties for key operations

### FedRAMP
- **SC-12**: Cryptographic Key Establishment and Management
  - FIPS-validated key management
  - Key hierarchy with HSM root keys
- **SC-13**: Cryptographic Protection
  - FIPS 203 (ML-KEM-1024) compliance
  - FIPS 197 (AES) compliance
- **SC-28**: Protection of Information at Rest
  - Full disk encryption with AES-256
  - Database-level encryption

### 21 CFR Part 11 (FDA)
- **11.10(a)**: System Access Validation
  - Encrypted audit trails
- **11.30**: Open Systems Controls
  - Encryption for electronic records
- **11.50**: Signature Manifestations
  - Encrypted signature records

## Implementation Notes

### Performance Optimization
- **Hardware Acceleration**: AES-NI instruction set for AES-256-GCM
- **Batch Encryption**: Process multiple objects in parallel
- **Key Caching**: Cache decapsulated KEKs in secure memory (5-minute TTL)
- **Streaming Encryption**: Support for large files (chunked encryption)

### Performance Benchmarks
- **AES-256-GCM Encryption**: ~5 GB/s (hardware accelerated)
- **ML-KEM-1024 Encapsulation**: ~0.15ms per operation
- **ML-KEM-1024 Decapsulation**: ~0.2ms per operation
- **Total Encryption Overhead**: ~0.5ms + data_size/5GB/s
- **Batch Processing**: 10,000 objects/second (1KB each)

### Memory Security
- DEKs stored in locked memory (mlock/VirtualLock)
- Secure key erasure: 3-pass overwrite with random data
- Guard pages around key material to detect buffer overflows
- Canary values to detect memory corruption

### Cryptographic Erasure
- For right-to-be-forgotten compliance:
  1. Destroy KEK for user's data classification
  2. All data encrypted with that KEK becomes irrecoverable
  3. Log destruction event with ML-DSA-87 signature
  4. No need to locate and delete individual records

### Key Backup and Recovery
- Root KEK backed up using Shamir's Secret Sharing (5-of-7 scheme)
- Key shares stored in geographically distributed HSMs
- Recovery requires quorum of key custodians
- All recovery events logged and audited

### Integration Points
- **Layer 1 (Identity)**: Authentication required for key access
- **Layer 2 (Authorization)**: Capability tokens control encryption/decryption permissions
- **Layer 3 (Network)**: Encrypted data transmitted over TLS 1.3
- **Layer 5 (Database)**: Transparent data encryption for database records
- **Layer 6 (PHI)**: Special handling for healthcare data encryption
- **Layer 7 (Self-Healing)**: Anomaly detection for unusual encryption patterns
