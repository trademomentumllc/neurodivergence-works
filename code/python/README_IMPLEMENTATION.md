# Eight-Layer PQC Python Implementation

Complete Python implementation of post-quantum cryptographic layers with NIST-standardized algorithms.

## Files Created

### 1. `__init__.py` (304 lines)
Package initialization that exposes all layer components:
- Imports all layer classes and functions
- Provides `get_security_info()` function
- Provides `run_all_demos()` to execute all demonstrations
- Validates cryptographic environment on import

### 2. `layer1_identity.py` (454 lines)
**Identity Verification with ML-DSA-87 Signatures**

**Classes:**
- `AuthenticationChallenge`: FIDO2-style authentication challenges
- `IdentityVerifier`: Post-quantum identity verification system

**Features:**
- ML-DSA-87 (Dilithium5) digital signatures
- NIST Security Level 5 (256-bit quantum security)
- Challenge-response authentication
- Signature verification with constant-time operations
- Complete demo function

**Key Sizes:**
- Public key: 2,592 bytes
- Private key: 4,864 bytes
- Signature: ~4,595 bytes

### 3. `layer4_encryption.py` (589 lines)
**Hybrid Envelope Encryption with ML-KEM-1024 + AES-256-GCM**

**Classes:**
- `EncryptedEnvelope`: Encrypted data envelope with all components
- `HybridEncryptor`: Hybrid post-quantum encryption system

**Features:**
- ML-KEM-1024 (Kyber1024) key encapsulation
- AES-256-GCM authenticated encryption
- IND-CCA2 security guarantees
- Serialization/deserialization of envelopes
- Associated authenticated data (AAD) support
- Complete demo function

**Key Sizes:**
- Public key: 1,568 bytes
- Private key: 3,168 bytes
- Encapsulated key: 1,568 bytes

### 4. `layer6_phi.py` (815 lines)
**PHI Isolation with FHIR R4 Compliance and HMAC-SHA3-384**

**Classes:**
- `FHIRResourceType`: Enumeration of supported FHIR resources
- `AccessLevel`: Access control levels
- `AuditLogEntry`: HIPAA-compliant audit logging
- `PHICompartment`: Isolated PHI storage compartment
- `PHIManager`: HIPAA-compliant PHI management system

**Features:**
- FHIR R4 resource validation
- HMAC-SHA3-384 integrity protection (48-byte tags)
- Compartmentalized storage with access control
- HIPAA-compliant audit logging
- Support for 10 FHIR resource types
- Complete demo function

**Compliance:**
- HIPAA Privacy Rule (45 CFR Part 160, 164)
- FHIR R4 (HL7 Fast Healthcare Interoperability Resources)
- 21 CFR Part 11 (FDA Electronic Records)

### 5. `layer8_orchestrator.py` (834 lines)
**Central PQC Algorithm Orchestration and Validation**

**Classes:**
- `SecurityLevel`: NIST security level enumeration
- `AlgorithmType`: Algorithm type enumeration
- `LayerStatus`: Layer operational status
- `AlgorithmMetadata`: Algorithm information and parameters
- `LayerRegistration`: Security layer registration data
- `OperationMetrics`: Performance tracking for operations
- `SecurityPolicy`: Security policy enforcement
- `PQCOrchestrator`: Central orchestration system

**Features:**
- Algorithm lifecycle management
- Security policy enforcement
- Layer registration and health checks
- Performance monitoring and metrics
- Workflow validation
- Built-in algorithm registry for all PQC algorithms
- Complete demo function

**Supported Algorithms:**
- ML-DSA-87 / CRYSTALS-Dilithium5
- ML-KEM-1024 / CRYSTALS-Kyber1024
- AES-256-GCM
- HMAC-SHA3-384
- SHA3-256

## Usage Examples

### Quick Start
```python
from eight_layer_pqc import (
    IdentityVerifier,
    HybridEncryptor,
    PHIManager,
    PQCOrchestrator
)

# Initialize components
identity = IdentityVerifier()
encryptor = HybridEncryptor()
orchestrator = PQCOrchestrator()

# Generate keys
sign_pk, sign_sk = identity.generate_keypair()
enc_pk, enc_sk = encryptor.generate_keypair()

# Authenticate
challenge = identity.create_challenge("alice@example.com")
signature = identity.sign_challenge(challenge, sign_sk)
is_valid = identity.verify_signature(challenge, signature, sign_pk)

# Encrypt
plaintext = b"Sensitive data"
envelope = encryptor.encrypt(plaintext, enc_pk)
decrypted = encryptor.decrypt(envelope, enc_sk)
```

### Run All Demos
```python
from eight_layer_pqc import run_all_demos
run_all_demos()
```

### Get Security Information
```python
from eight_layer_pqc import get_security_info
import json

info = get_security_info()
print(json.dumps(info, indent=2))
```

## Implementation Details

### Type Hints
All functions and methods include complete type hints for better IDE support and type checking.

### Error Handling
- Comprehensive exception handling in all operations
- Meaningful error messages
- Secure failure modes (fail-safe design)

### Docstrings
- Every module, class, and function has detailed docstrings
- Security guarantees documented
- Usage examples included

### Security Features
- Constant-time operations where applicable
- Secure memory handling (explicit deletion of sensitive data)
- Domain separation in HMAC operations
- Replay attack prevention
- Challenge expiration
- Access control enforcement
- Audit logging

## Dependencies

```
pqcrypto>=0.1.0
pycryptodome>=3.18.0
```

## Testing

Each module includes a demo function that can be run independently:

```bash
python3 -m eight_layer_pqc.layer1_identity
python3 -m eight_layer_pqc.layer4_encryption
python3 -m eight_layer_pqc.layer6_phi
python3 -m eight_layer_pqc.layer8_orchestrator
```

Or run all demos:
```bash
python3 -c "from eight_layer_pqc import run_all_demos; run_all_demos()"
```

## Security Guarantees

- **NIST Security Level 5**: 256-bit quantum security
- **Quantum Resistance**: Protected against Shor's and Grover's algorithms
- **IND-CCA2**: Indistinguishability under adaptive chosen-ciphertext attack
- **UF-CMA**: Unforgeability under chosen message attack
- **AEAD**: Authenticated encryption with associated data
- **Defense-in-Depth**: Multi-layer security architecture

## Compliance Standards

- NIST FIPS 203 (ML-KEM)
- NIST FIPS 204 (ML-DSA)
- NIST FIPS 202 (SHA-3)
- NIST FIPS 197 (AES)
- HIPAA (45 CFR Part 160, 164)
- FHIR R4 (HL7)
- 21 CFR Part 11 (FDA)

## File Statistics

| File | Lines | Size | Description |
|------|-------|------|-------------|
| `__init__.py` | 304 | 8.3 KB | Package initialization |
| `layer1_identity.py` | 454 | 15 KB | Identity verification |
| `layer4_encryption.py` | 589 | 19 KB | Hybrid encryption |
| `layer6_phi.py` | 815 | 27 KB | PHI isolation |
| `layer8_orchestrator.py` | 834 | 28 KB | Orchestration |
| **Total** | **2,996** | **~97 KB** | Complete implementation |

## Author

Jason Jarmacz (NeuroDivergent AI Evolution Strategist)
Trade Momentum LLC / Neurodivergence.Works

## License

See LICENSE file in repository root
