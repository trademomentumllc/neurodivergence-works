# Layer 2: Authorization Specification

## Purpose

Layer 2 provides quantum-resistant authorization and access control services through Role-Based Access Control (RBAC) enhanced with ML-DSA-87 signed capability tokens. This layer determines what authenticated users (from Layer 1) are permitted to do within the system, preventing unauthorized access to resources and operations while maintaining cryptographic proof of authorization decisions.

## Algorithms

### Primary Algorithms
- **ML-DSA-87** (FIPS 204): Capability token signatures
  - Public key size: 2,592 bytes
  - Secret key size: 4,864 bytes
  - Signature size: 4,627 bytes
  - Security category: NIST Level 5 (256-bit security)

### Supporting Algorithms
- **SHA3-384**: Role and permission hashing
- **HMAC-SHA3-384**: Nonce generation and validation
- **HKDF-SHA256**: Capability token key derivation
- **ChaCha20-Poly1305**: Capability token encryption (alternative to AES-256-GCM)

### Nonce Management
- **Blake3**: Fast nonce commitment hashing
- **Time-based counters**: Replay attack prevention
- **Bloom filters**: Efficient nonce tracking for high-throughput scenarios

## Security Strength

- **Quantum Security Level**: 256-bit (NIST Security Category 5)
- **Classical Security Level**: 256-bit equivalent
- **Capability Token Lifetime**: Configurable, default 900 seconds (15 minutes)
- **Nonce Window**: 300 seconds (5 minutes)
- **Maximum Nonce Reuse Detection**: 10,000,000 tracked nonces per rotation period
- **Role Cache TTL**: 60 seconds

## Role-Based Access Control (RBAC) Model

### Core Components

#### 1. Roles
```
Role := {
  role_id: UUID,
  role_name: String,
  role_description: String,
  parent_roles: [UUID],  // For inheritance
  permissions: [Permission],
  ml_dsa_signature: Base64,
  created_at: Timestamp,
  updated_at: Timestamp,
  role_hash: SHA3-384(role_id || permissions || parent_roles)
}
```

#### 2. Permissions
```
Permission := {
  permission_id: UUID,
  resource: String,  // e.g., "patient_records", "billing_data"
  action: String,    // e.g., "read", "write", "delete", "execute"
  constraints: {
    time_based: Boolean,
    location_based: Boolean,
    conditions: [Condition]
  },
  permission_hash: SHA3-384(permission_id || resource || action)
}
```

#### 3. Capability Tokens
```
CapabilityToken := {
  token_id: UUID,
  subject: UUID,  // User ID from Layer 1
  role: UUID,
  permissions: [Permission],
  nonce: Base64,  // HMAC-SHA3-384 generated
  issued_at: Timestamp,
  expires_at: Timestamp,
  scope: String,
  ml_dsa_signature: Base64,
  token_hash: SHA3-384(token_id || subject || permissions || nonce)
}
```

### Permission Inheritance Model

```
Inheritance Rules:
1. Roles can inherit from multiple parent roles (DAG structure)
2. Permissions are additive (union of all inherited permissions)
3. Explicit denies override inherited allows
4. Circular inheritance is prohibited and detected
5. Inheritance depth limited to 10 levels for performance
```

**Example Hierarchy:**
```
SuperAdmin
  ├─> Admin
  │    ├─> HealthcareAdmin
  │    │    ├─> Doctor
  │    │    └─> Nurse
  │    └─> BillingAdmin
  │         └─> Biller
  └─> Auditor (read-only, no inheritance)
```

**Inheritance Resolution Algorithm:**
```python
def resolve_permissions(role, visited=set()):
    if role.role_id in visited:
        raise CircularInheritanceError

    visited.add(role.role_id)
    permissions = set(role.permissions)

    for parent_id in role.parent_roles:
        parent_role = get_role(parent_id)
        parent_permissions = resolve_permissions(parent_role, visited.copy())
        permissions.update(parent_permissions)

    # Apply explicit denies
    permissions = apply_deny_rules(permissions, role.deny_rules)

    return permissions
```

## Nonce-Based Replay Prevention

### Nonce Generation
```
nonce = HMAC-SHA3-384(
    key=server_nonce_key,
    message=user_id || timestamp || random_bytes(32) || counter
)
```

### Nonce Validation Protocol

**Phase 1: Generation**
```
1. Server generates nonce for client request
2. Nonce includes timestamp and counter
3. Nonce signed with HMAC-SHA3-384
4. Nonce returned to client with capability token
```

**Phase 2: Validation**
```
1. Client includes nonce in authorization request
2. Server validates nonce HMAC signature
3. Server checks nonce timestamp within window (±5 minutes)
4. Server checks nonce not in replay cache (Bloom filter)
5. Server commits nonce to replay cache
6. Request processed if all checks pass
```

**Phase 3: Cleanup**
```
1. Nonces older than window automatically invalidated
2. Bloom filter rotated every 24 hours
3. Persistent nonce log maintained for audit (7 days)
```

### Replay Cache Implementation
```
ReplayCache := {
  bloom_filter: BloomFilter(
    expected_items=10000000,
    false_positive_rate=0.0001
  ),
  backup_set: Set[Nonce],  // Last 100,000 nonces
  rotation_timestamp: Timestamp,
  filter_hash: Blake3(bloom_filter_state)
}
```

## API Contract

### Endpoint: `/api/v1/authorization/evaluate`

**Request:**
```json
{
  "session_token": "base64url",
  "capability_token": "base64url",
  "nonce": "base64url",
  "resource": "string",
  "action": "string",
  "context": {
    "ip_address": "string",
    "timestamp": "ISO8601",
    "additional_claims": {}
  }
}
```

**Response (Authorized):**
```json
{
  "status": "authorized",
  "decision": "allow",
  "permission_proof": {
    "ml_dsa_signature": "base64url",
    "timestamp": "ISO8601",
    "decision_hash": "base64url (SHA3-384)"
  },
  "effective_permissions": [
    {
      "resource": "string",
      "action": "string",
      "constraints": {}
    }
  ],
  "token_expiry": "ISO8601"
}
```

**Response (Denied):**
```json
{
  "status": "denied",
  "decision": "deny",
  "reason": "string",
  "error_code": "string",
  "denial_proof": {
    "ml_dsa_signature": "base64url",
    "timestamp": "ISO8601"
  }
}
```

### Endpoint: `/api/v1/authorization/token/issue`

**Request:**
```json
{
  "session_token": "base64url",
  "user_id": "uuid",
  "requested_scope": "string",
  "ttl": "integer (seconds, optional)"
}
```

**Response (Success):**
```json
{
  "status": "issued",
  "capability_token": "base64url",
  "nonce": "base64url",
  "expires_at": "ISO8601",
  "roles": ["string"],
  "permissions": [
    {
      "resource": "string",
      "action": "string"
    }
  ],
  "ml_dsa_signature": "base64url"
}
```

### Endpoint: `/api/v1/authorization/roles/assign`

**Request:**
```json
{
  "session_token": "base64url",
  "admin_capability_token": "base64url",
  "user_id": "uuid",
  "role_id": "uuid",
  "nonce": "base64url",
  "justification": "string"
}
```

**Response (Success):**
```json
{
  "status": "assigned",
  "user_id": "uuid",
  "role_id": "uuid",
  "effective_permissions": [
    {
      "resource": "string",
      "action": "string"
    }
  ],
  "assignment_proof": {
    "ml_dsa_signature": "base64url",
    "timestamp": "ISO8601",
    "audit_hash": "base64url"
  }
}
```

### Endpoint: `/api/v1/authorization/roles/create`

**Request:**
```json
{
  "session_token": "base64url",
  "admin_capability_token": "base64url",
  "nonce": "base64url",
  "role_name": "string",
  "role_description": "string",
  "parent_roles": ["uuid"],
  "permissions": [
    {
      "resource": "string",
      "action": "string",
      "constraints": {}
    }
  ]
}
```

**Response (Success):**
```json
{
  "status": "created",
  "role_id": "uuid",
  "role_hash": "base64url",
  "ml_dsa_signature": "base64url",
  "timestamp": "ISO8601"
}
```

### Endpoint: `/api/v1/authorization/nonce/generate`

**Request:**
```json
{
  "session_token": "base64url",
  "context": "string"
}
```

**Response:**
```json
{
  "nonce": "base64url",
  "expires_at": "ISO8601",
  "nonce_hash": "base64url (Blake3)"
}
```

## Error Codes

| Code | Name | Description | Retry | Lockout |
|------|------|-------------|-------|---------|
| `AUTHZ-2001` | `PERMISSION_DENIED` | User lacks required permission | No | N/A |
| `AUTHZ-2002` | `INVALID_CAPABILITY_TOKEN` | Capability token invalid or tampered | No | Immediate |
| `AUTHZ-2003` | `CAPABILITY_TOKEN_EXPIRED` | Capability token expired | No | N/A |
| `AUTHZ-2004` | `NONCE_VALIDATION_FAILED` | Nonce signature validation failed | Yes (1x) | 600s |
| `AUTHZ-2005` | `NONCE_REPLAY_DETECTED` | Nonce already used (replay attack) | No | 1800s |
| `AUTHZ-2006` | `NONCE_EXPIRED` | Nonce outside valid time window | No | N/A |
| `AUTHZ-2007` | `ROLE_NOT_FOUND` | Requested role does not exist | No | N/A |
| `AUTHZ-2008` | `CIRCULAR_INHERITANCE_DETECTED` | Role inheritance cycle detected | No | N/A |
| `AUTHZ-2009` | `INHERITANCE_DEPTH_EXCEEDED` | Role inheritance too deep (>10 levels) | No | N/A |
| `AUTHZ-2010` | `INSUFFICIENT_PRIVILEGES` | Admin action requires higher privileges | No | N/A |
| `AUTHZ-2011` | `ML_DSA_SIGNATURE_INVALID` | Capability token signature verification failed | No | 900s |
| `AUTHZ-2012` | `ROLE_ASSIGNMENT_FAILED` | Role assignment operation failed | Yes (1x) | N/A |
| `AUTHZ-2013` | `CONSTRAINT_VIOLATION` | Permission constraint not satisfied | No | N/A |
| `AUTHZ-2014` | `SCOPE_MISMATCH` | Requested scope exceeds granted scope | No | N/A |
| `AUTHZ-2015` | `RATE_LIMIT_EXCEEDED` | Too many authorization requests | No | 300s |
| `AUTHZ-2016` | `CONTEXT_VALIDATION_FAILED` | Authorization context invalid | Yes (1x) | N/A |
| `AUTHZ-2017` | `RESOURCE_NOT_FOUND` | Requested resource does not exist | No | N/A |
| `AUTHZ-2018` | `DENY_RULE_APPLIED` | Explicit deny rule overrides allow | No | N/A |

## Compliance Mapping

### NIST Standards
- **FIPS 204**: ML-DSA digital signature standard for capability tokens
- **NIST SP 800-162**: Guide to Attribute Based Access Control (ABAC)
  - Role-based attributes for access control
  - Permission constraints and conditions
- **NIST SP 800-178**: Comparison of Attribute Based Access Control (ABAC) Standards
- **NIST Cybersecurity Framework**:
  - PR.AC-4: Access permissions managed and enforced
  - PR.AC-5: Network integrity protected with access controls
  - PR.PT-3: Access to systems and assets controlled

### HIPAA Requirements
- **164.308(a)(3)(i)**: Workforce Security - Authorization/Supervision
  - RBAC ensures proper authorization controls
  - ML-DSA-87 signed capability tokens provide cryptographic proof
- **164.308(a)(4)(i)**: Information Access Management - Authorization
  - Permission model restricts access to minimum necessary
  - Inheritance model supports separation of duties
- **164.312(a)(1)**: Access Control - Unique User Identification
  - Capability tokens bound to Layer 1 identity
- **164.312(a)(2)(ii)**: Access Control - Emergency Access Procedure
  - Role constraints support break-glass scenarios
- **164.312(c)(1)**: Integrity Controls
  - ML-DSA-87 signatures ensure authorization decision integrity

### SOC 2 Type II Controls
- **CC6.1**: Logical and Physical Access Controls
  - RBAC implementation with cryptographic enforcement
  - Nonce-based replay prevention
- **CC6.2**: System Access Restricted to Authorized Users
  - Capability tokens enforce authorization decisions
  - Permission constraints provide fine-grained control
- **CC6.3**: Authorization Changes Monitored
  - All role assignments logged with ML-DSA-87 signatures
  - Audit trail for permission modifications

### GDPR Compliance
- **Article 5(1)(f)**: Integrity and Confidentiality
  - Authorization controls prevent unauthorized access
- **Article 25**: Data Protection by Design
  - Quantum-resistant authorization for long-term protection
- **Article 32**: Security of Processing
  - Role-based access control as technical measure
  - Cryptographic authorization proofs

### PCI DSS v4.0
- **Requirement 7.1**: Access Limited to Business Need
  - RBAC enforces least privilege principle
- **Requirement 7.2**: User Access Administered
  - Role assignment and management APIs
  - Inheritance model for efficient administration
- **Requirement 7.3**: Access Control Systems
  - Capability token system with ML-DSA-87 signatures
  - Nonce-based replay prevention

### ISO/IEC 27001:2022
- **A.9.1.2**: Access to Networks and Network Services
  - Authorization required for network resource access
- **A.9.2.3**: Management of Privileged Access Rights
  - Role hierarchy supports privilege management
- **A.9.4.1**: Information Access Restriction
  - Permission model restricts information access
- **A.9.4.5**: Access Control to Program Source Code
  - Resource-based permissions for code access

### 21 CFR Part 11 (FDA)
- **11.10(d)**: Limiting System Access to Authorized Individuals
  - RBAC with cryptographic capability tokens
- **11.10(g)**: Use of Authority Checks
  - Real-time authorization evaluation
  - ML-DSA-87 signed authorization decisions

## Implementation Notes

### Performance Optimization
- **Permission Cache**: In-memory cache for resolved permissions (60s TTL)
- **Bloom Filter**: O(1) nonce lookup with 0.01% false positive rate
- **Role Resolution**: Pre-computed permission sets for common roles
- **Signature Verification**: Batch verification for multiple capability tokens

### Scalability Considerations
- ML-DSA-87 signature verification: ~3ms per token
- Permission resolution: <10ms for roles with depth ≤5
- Nonce validation: <1ms with Bloom filter
- Target throughput: 10,000 authorization decisions per second per node

### Monitoring and Auditing
- All authorization decisions logged with SHA3-384 event hash
- Denied access attempts flagged for Layer 7 anomaly detection
- Role assignment changes trigger audit events
- Capability token usage tracked for compliance reporting
- Nonce replay attempts immediately escalated to security operations

### Integration Points
- **Layer 1 (Identity)**: Validates session tokens before authorization
- **Layer 3 (Network)**: Authorization decisions enforce network access
- **Layer 4 (Encryption)**: Permissions determine encryption key access
- **Layer 5 (Database)**: RBAC integrates with row-level security
- **Layer 7 (Self-Healing)**: Authorization anomalies trigger healing actions

### Key Management
- ML-DSA-87 signing keys for capability tokens stored in HSM
- Nonce HMAC keys rotated every 30 days
- Capability token encryption keys derived per-user
- All keys tagged with purpose and lifecycle metadata
