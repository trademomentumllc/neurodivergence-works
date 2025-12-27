# Layer 5: Database Security Specification

## Purpose

Layer 5 provides comprehensive quantum-resistant database security through row-level security policies, cryptographically signed records using ML-DSA-87 (FIPS 204), and SHA3-384 audit chains. This layer ensures that database operations are authenticated, authorized, logged, and protected against both classical and quantum threats. It implements defense-in-depth for structured data storage with tamper-evident audit trails and cryptographic proof of data integrity.

## Algorithms

### Primary Algorithms
- **ML-DSA-87** (FIPS 204): Record signatures and audit chain
  - Public key size: 2,592 bytes
  - Secret key size: 4,864 bytes
  - Signature size: 4,627 bytes
  - Security category: NIST Level 5 (256-bit quantum security)

- **SHA3-384**: Audit chain hashing and record integrity
  - Output size: 384 bits (48 bytes)
  - Collision resistance: 192-bit security
  - Preimage resistance: 384-bit security

### Supporting Algorithms
- **HMAC-SHA3-384**: Row-level authentication codes
- **Blake3**: Fast content hashing for deduplication
- **AES-256-GCM**: Column-level encryption (from Layer 4)
- **Argon2id**: Password hashing for database credentials
  - Memory: 64 MB
  - Iterations: 3
  - Parallelism: 4

## Security Strength

- **Quantum Security Level**: 256-bit (via ML-DSA-87 signatures)
- **Hash Security**: 192-bit collision resistance (SHA3-384)
- **Audit Chain Integrity**: Cryptographically verifiable with ML-DSA-87
- **Row-Level Isolation**: Policy-based with cryptographic enforcement
- **Maximum Chain Length**: 1,000,000 records per chain
- **Signature Verification Time**: ~3ms per record

## Row-Level Security (RLS) Policies

### Policy Structure

```sql
CREATE POLICY policy_name
ON table_name
FOR operation  -- SELECT, INSERT, UPDATE, DELETE, ALL
TO role_name   -- From Layer 2 RBAC
USING (condition)  -- Row visibility condition
WITH CHECK (condition);  -- Row modification condition
```

### Example Policies

**1. Healthcare Provider Access (PHI Data)**
```sql
-- Doctors can only see patients assigned to them
CREATE POLICY doctor_patient_access
ON patient_records
FOR SELECT
TO role_doctor
USING (
  assigned_doctor_id = current_user_id()
  AND record_status = 'active'
  AND has_capability('patient_records', 'read')
);

-- Signature verification for data integrity
CREATE POLICY verify_record_signature
ON patient_records
FOR SELECT
TO role_doctor
USING (
  verify_ml_dsa_87_signature(
    public_key_id,
    record_hash,
    record_signature
  ) = TRUE
);
```

**2. Multi-Tenant Isolation**
```sql
-- Users can only access their organization's data
CREATE POLICY tenant_isolation
ON sensitive_data
FOR ALL
TO role_user
USING (
  tenant_id = current_tenant_id()
  AND verify_hmac_sha3_384(
    tenant_key,
    row_id || tenant_id,
    row_hmac
  ) = TRUE
)
WITH CHECK (
  tenant_id = current_tenant_id()
);
```

**3. Time-Based Access Control**
```sql
-- Auditors can only read historical data
CREATE POLICY auditor_historical_access
ON audit_log
FOR SELECT
TO role_auditor
USING (
  created_at < NOW()
  AND verify_audit_chain(
    record_id,
    previous_hash,
    record_signature
  ) = TRUE
);
```

**4. Data Classification-Based Access**
```sql
-- Restrict access based on data classification
CREATE POLICY classification_enforcement
ON classified_documents
FOR SELECT
TO role_user
USING (
  classification_level <= user_clearance_level()
  AND decrypt_permission(classification_level) = TRUE
);
```

### Policy Enforcement

**Query Rewriting**
```sql
-- Original query
SELECT * FROM patient_records WHERE patient_id = '12345';

-- Rewritten with RLS policies
SELECT * FROM patient_records
WHERE patient_id = '12345'
  AND assigned_doctor_id = current_user_id()
  AND record_status = 'active'
  AND has_capability('patient_records', 'read')
  AND verify_ml_dsa_87_signature(
    public_key_id, record_hash, record_signature
  ) = TRUE;
```

**Performance Optimization**
- RLS policies compiled to prepared statements
- Signature verification cached per transaction
- Indexes on policy condition columns
- Materialized views for complex policies

## SHA3-384 Audit Chain

### Chain Structure

```
Audit Chain: Merkle-like tamper-evident log

Block_N := {
  block_id: UUID,
  sequence_number: Integer,
  timestamp: ISO8601,
  operation: {
    type: "INSERT|UPDATE|DELETE|SELECT",
    table: String,
    user_id: UUID,
    capability_token: Base64,
    affected_rows: Integer
  },
  data_hash: SHA3-384(operation_data),
  previous_hash: SHA3-384(Block_N-1),
  chain_hash: SHA3-384(
    sequence_number ||
    timestamp ||
    operation_hash ||
    data_hash ||
    previous_hash
  ),
  ml_dsa_signature: ML-DSA-87(chain_hash),
  metadata: {}
}
```

### Chain Construction

**Genesis Block**
```json
{
  "block_id": "00000000-0000-0000-0000-000000000000",
  "sequence_number": 0,
  "timestamp": "2025-01-01T00:00:00Z",
  "operation": {
    "type": "GENESIS",
    "description": "Audit chain initialized"
  },
  "data_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "chain_hash": "SHA3-384(genesis_block)",
  "ml_dsa_signature": "ML-DSA-87(chain_hash)",
  "metadata": {
    "version": "1.0",
    "algorithm": "ML-DSA-87"
  }
}
```

**Subsequent Blocks**
```python
def create_audit_block(operation, previous_block):
    block = {
        "block_id": uuid4(),
        "sequence_number": previous_block.sequence_number + 1,
        "timestamp": datetime.now(UTC),
        "operation": operation,
        "data_hash": sha3_384(operation.data),
        "previous_hash": previous_block.chain_hash
    }

    block["chain_hash"] = sha3_384(
        str(block["sequence_number"]) +
        block["timestamp"].isoformat() +
        block["operation"].hash() +
        block["data_hash"] +
        block["previous_hash"]
    )

    block["ml_dsa_signature"] = ml_dsa_87_sign(
        private_key=audit_signing_key,
        message=block["chain_hash"]
    )

    return block
```

### Chain Verification

```python
def verify_audit_chain(chain):
    """Verify entire audit chain integrity"""

    # Verify genesis block
    if not verify_genesis_block(chain[0]):
        return False

    # Verify each subsequent block
    for i in range(1, len(chain)):
        current = chain[i]
        previous = chain[i-1]

        # 1. Verify sequence number
        if current.sequence_number != previous.sequence_number + 1:
            return False

        # 2. Verify previous hash link
        if current.previous_hash != previous.chain_hash:
            return False

        # 3. Recompute and verify chain hash
        recomputed_hash = sha3_384(
            str(current.sequence_number) +
            current.timestamp.isoformat() +
            current.operation.hash() +
            current.data_hash +
            current.previous_hash
        )
        if recomputed_hash != current.chain_hash:
            return False

        # 4. Verify ML-DSA-87 signature
        if not ml_dsa_87_verify(
            public_key=audit_public_key,
            message=current.chain_hash,
            signature=current.ml_dsa_signature
        ):
            return False

    return True
```

## ML-DSA-87 Signed Records

### Record Signature Structure

```
Signed Record := {
  record: {
    record_id: UUID,
    table_name: String,
    data: {},
    version: Integer,
    created_at: Timestamp,
    updated_at: Timestamp,
    created_by: UUID,
    updated_by: UUID
  },
  signature_metadata: {
    public_key_id: UUID,
    algorithm: "ML-DSA-87",
    signed_fields: [String],  // Which fields are signed
    timestamp: ISO8601
  },
  record_hash: SHA3-384(canonicalized_record),
  ml_dsa_signature: ML-DSA-87(record_hash)
}
```

### Signing Process

**1. Record Canonicalization**
```python
def canonicalize_record(record):
    """Ensure deterministic serialization"""
    # Sort keys alphabetically
    sorted_record = dict(sorted(record.items()))

    # Convert to JSON with consistent formatting
    canonical_json = json.dumps(
        sorted_record,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=True
    )

    return canonical_json
```

**2. Hash and Sign**
```python
def sign_record(record, private_key):
    # Canonicalize record
    canonical = canonicalize_record(record)

    # Compute hash
    record_hash = sha3_384(canonical)

    # Sign hash
    signature = ml_dsa_87_sign(
        private_key=private_key,
        message=record_hash
    )

    return {
        "record_hash": record_hash,
        "ml_dsa_signature": signature,
        "signature_metadata": {
            "public_key_id": get_key_id(private_key),
            "algorithm": "ML-DSA-87",
            "signed_fields": list(record.keys()),
            "timestamp": datetime.now(UTC)
        }
    }
```

**3. Verification**
```python
def verify_record_signature(record, signature_data, public_key):
    # Canonicalize record
    canonical = canonicalize_record(record)

    # Recompute hash
    recomputed_hash = sha3_384(canonical)

    # Verify hash matches
    if recomputed_hash != signature_data["record_hash"]:
        return False

    # Verify ML-DSA-87 signature
    return ml_dsa_87_verify(
        public_key=public_key,
        message=signature_data["record_hash"],
        signature=signature_data["ml_dsa_signature"]
    )
```

## API Contract

### Endpoint: `/api/v1/database/query`

**Request:**
```json
{
  "session_token": "base64url",
  "capability_token": "base64url",
  "query": {
    "operation": "SELECT|INSERT|UPDATE|DELETE",
    "table": "string",
    "columns": ["string"],
    "conditions": {},
    "values": {}
  },
  "options": {
    "verify_signatures": "boolean",
    "include_audit": "boolean"
  }
}
```

**Response (Success):**
```json
{
  "status": "success",
  "operation": "string",
  "rows_affected": "integer",
  "data": [
    {
      "record": {},
      "signature": {
        "record_hash": "base64url",
        "ml_dsa_signature": "base64url",
        "verified": "boolean"
      }
    }
  ],
  "audit_block": {
    "block_id": "uuid",
    "sequence_number": "integer",
    "chain_hash": "base64url",
    "ml_dsa_signature": "base64url"
  },
  "execution_proof": {
    "rls_policies_applied": ["string"],
    "signature_verifications": "integer",
    "timestamp": "ISO8601"
  }
}
```

### Endpoint: `/api/v1/database/audit/verify`

**Request:**
```json
{
  "session_token": "base64url",
  "audit_range": {
    "start_sequence": "integer",
    "end_sequence": "integer"
  },
  "table": "string (optional)"
}
```

**Response (Success):**
```json
{
  "status": "verified",
  "chain_valid": "boolean",
  "blocks_verified": "integer",
  "verification_details": {
    "hash_chain_valid": "boolean",
    "signatures_valid": "boolean",
    "sequence_continuous": "boolean",
    "timestamps_monotonic": "boolean"
  },
  "verification_proof": {
    "merkle_root": "base64url (SHA3-384)",
    "ml_dsa_signature": "base64url",
    "timestamp": "ISO8601"
  }
}
```

**Response (Invalid):**
```json
{
  "status": "invalid",
  "chain_valid": "boolean",
  "errors": [
    {
      "block_id": "uuid",
      "sequence_number": "integer",
      "error_type": "hash_mismatch|signature_invalid|sequence_gap|timestamp_error",
      "details": "string"
    }
  ]
}
```

### Endpoint: `/api/v1/database/policy/create`

**Request:**
```json
{
  "session_token": "base64url",
  "admin_capability_token": "base64url",
  "policy": {
    "name": "string",
    "table": "string",
    "operation": "SELECT|INSERT|UPDATE|DELETE|ALL",
    "role": "string",
    "using_condition": "string (SQL expression)",
    "with_check_condition": "string (SQL expression)"
  }
}
```

**Response (Success):**
```json
{
  "status": "created",
  "policy_id": "uuid",
  "policy_name": "string",
  "policy_hash": "base64url (SHA3-384)",
  "ml_dsa_signature": "base64url",
  "audit_block": {
    "block_id": "uuid",
    "chain_hash": "base64url"
  }
}
```

### Endpoint: `/api/v1/database/record/sign`

**Request:**
```json
{
  "session_token": "base64url",
  "capability_token": "base64url",
  "record": {
    "table": "string",
    "record_id": "uuid",
    "data": {}
  }
}
```

**Response (Success):**
```json
{
  "status": "signed",
  "record_hash": "base64url (SHA3-384)",
  "ml_dsa_signature": "base64url",
  "signature_metadata": {
    "public_key_id": "uuid",
    "algorithm": "ML-DSA-87",
    "signed_fields": ["string"],
    "timestamp": "ISO8601"
  }
}
```

## Error Codes

| Code | Name | Description | Retry | Lockout |
|------|------|-------------|-------|---------|
| `DB-5001` | `RLS_POLICY_VIOLATION` | Row-level security policy blocked access | No | N/A |
| `DB-5002` | `SIGNATURE_VERIFICATION_FAILED` | ML-DSA-87 record signature invalid | No | 900s |
| `DB-5003` | `AUDIT_CHAIN_BROKEN` | Audit chain integrity compromised | No | Immediate |
| `DB-5004` | `HASH_MISMATCH` | Record hash doesn't match stored hash | No | 1800s |
| `DB-5005` | `SEQUENCE_GAP_DETECTED` | Missing audit blocks in sequence | No | N/A |
| `DB-5006` | `TIMESTAMP_VIOLATION` | Audit timestamp not monotonically increasing | No | N/A |
| `DB-5007` | `POLICY_NOT_FOUND` | RLS policy does not exist | No | N/A |
| `DB-5008` | `POLICY_CONFLICT` | Multiple conflicting policies | No | N/A |
| `DB-5009` | `UNAUTHORIZED_QUERY` | Query requires higher privileges | No | N/A |
| `DB-5010` | `RECORD_NOT_FOUND` | Requested record does not exist | No | N/A |
| `DB-5011` | `SIGNATURE_EXPIRED` | Record signature timestamp too old | No | N/A |
| `DB-5012` | `PUBLIC_KEY_NOT_FOUND` | Signing public key not found | No | N/A |
| `DB-5013` | `HMAC_VERIFICATION_FAILED` | Row-level HMAC verification failed | No | 900s |
| `DB-5014` | `TENANT_ISOLATION_VIOLATED` | Cross-tenant access attempted | No | Immediate |
| `DB-5015` | `AUDIT_LOG_FULL` | Audit chain reached maximum length | No | N/A |
| `DB-5016` | `CANONICALIZATION_FAILED` | Record canonicalization failed | Yes (1x) | N/A |
| `DB-5017` | `CONCURRENT_MODIFICATION` | Record modified by another transaction | Yes (3x) | N/A |
| `DB-5018` | `CHAIN_FORK_DETECTED` | Multiple chain branches detected (tampering) | No | Immediate |

## Compliance Mapping

### NIST Standards
- **FIPS 204**: ML-DSA digital signatures for records and audit chain
- **SP 800-53 Rev. 5**:
  - **AU-9**: Protection of Audit Information
    - Cryptographic audit chain with ML-DSA-87
  - **AU-10**: Non-repudiation
    - Signed records provide proof of origin
  - **AC-3**: Access Enforcement
    - Row-level security policies
  - **SC-8**: Transmission Confidentiality
    - Encrypted database connections (Layer 3)
- **NIST Cybersecurity Framework**:
  - PR.DS-6: Integrity checking mechanisms
  - PR.AC-4: Access permissions managed
  - DE.CM-1: Network monitored for anomalies

### HIPAA Requirements
- **164.308(a)(1)(ii)(D)**: Information System Activity Review
  - Audit chain provides complete activity log
  - ML-DSA-87 signatures ensure log integrity
- **164.312(a)(1)**: Access Control
  - RLS policies enforce minimum necessary access
  - Row-level isolation for PHI
- **164.312(b)**: Audit Controls
  - Cryptographically verifiable audit trail
  - Tamper-evident logging
- **164.312(c)(1)**: Integrity Controls
  - SHA3-384 hashes and ML-DSA-87 signatures
  - Record-level integrity verification
- **164.312(c)(2)**: Mechanism to Authenticate ePHI
  - Signed records prove authenticity

### SOC 2 Type II Controls
- **CC7.2**: System Monitoring
  - Comprehensive audit logging
  - Real-time integrity verification
- **CC6.6**: Logical Access Security
  - Row-level security enforcement
  - Policy-based access control
- **CC7.1**: Change Detection
  - Audit chain detects unauthorized modifications
  - Cryptographic tamper evidence

### GDPR Compliance
- **Article 5(1)(f)**: Integrity and Confidentiality
  - Cryptographic integrity protection
  - Access control via RLS policies
- **Article 30**: Records of Processing Activities
  - Complete audit trail of data access
  - Tamper-evident logging
- **Article 32**: Security of Processing
  - State-of-the-art database security
  - Quantum-resistant signatures

### PCI DSS v4.0
- **Requirement 10.2**: Audit Logging Implemented
  - All database access logged
  - Audit chain with cryptographic integrity
- **Requirement 10.3**: Audit Records Protected
  - ML-DSA-87 signatures prevent tampering
  - SHA3-384 chain ensures completeness
- **Requirement 8.2**: User Authentication
  - Database access tied to Layer 1 identity
  - RLS policies enforce authorization

### ISO/IEC 27001:2022
- **A.8.15**: Logging
  - Comprehensive audit logging
  - Cryptographically protected logs
- **A.8.16**: Monitoring Activities
  - Real-time monitoring of database operations
- **A.9.4.1**: Information Access Restriction
  - Row-level security policies
  - Fine-grained access control
- **A.12.4.1**: Event Logging
  - Tamper-evident audit trail
- **A.12.4.3**: Administrator and Operator Logs
  - Privileged operations logged and signed

### 21 CFR Part 11 (FDA)
- **11.10(e)**: Audit Trail
  - Complete record of database operations
  - Cryptographic integrity protection
- **11.10(c)**: Sequencing of Steps and Events
  - Audit chain maintains strict ordering
- **11.10(k)(2)**: Audit Information
  - Who, what, when, why logged for each operation

## Implementation Notes

### Database Platform Support
- **PostgreSQL**: Native row-level security (RLS)
- **MySQL/MariaDB**: Views and stored procedures for RLS
- **Oracle**: Virtual Private Database (VPD) for RLS
- **SQL Server**: Row-Level Security feature
- **MongoDB**: Document-level access control

### Performance Optimization
- **Signature Caching**: Cache verified signatures per transaction
- **Batch Verification**: Verify multiple signatures in parallel
- **Materialized Views**: Pre-compute RLS policy results
- **Indexing**: Indexes on policy condition columns
- **Partitioning**: Partition audit chain by time period

### Performance Benchmarks
- **RLS Policy Evaluation**: <1ms overhead per query
- **ML-DSA-87 Signature Generation**: ~5ms per record
- **ML-DSA-87 Signature Verification**: ~3ms per record
- **Audit Chain Verification**: ~3ms per block
- **Batch Signing**: 1,000 records/second
- **Batch Verification**: 2,000 records/second

### Audit Chain Management
- **Chain Rotation**: New chain every 1,000,000 blocks
- **Archival**: Old chains archived to immutable storage
- **Compression**: ZSTD compression for archived chains
- **Pruning**: Retain 7 years of audit data (configurable)

### Integration Points
- **Layer 1 (Identity)**: User identity for audit logging
- **Layer 2 (Authorization)**: Capability tokens enforce RLS policies
- **Layer 4 (Encryption)**: Column-level encryption for sensitive fields
- **Layer 6 (PHI)**: Special RLS policies for healthcare data
- **Layer 7 (Self-Healing)**: Audit anomalies trigger healing
- **Layer 8 (Orchestration)**: Coordinated key rotation for signatures
