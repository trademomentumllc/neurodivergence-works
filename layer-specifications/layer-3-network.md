# Layer 3: Network Security Specification

## Purpose

Layer 3 provides quantum-resistant network security through hybrid key exchange combining classical X25519 with post-quantum ML-KEM-1024 (FIPS 203). This layer secures all network communications with TLS 1.3 integration, ensuring perfect forward secrecy and protection against harvest-now-decrypt-later attacks. It establishes secure channels for all inter-service and client-server communications.

## Algorithms

### Primary Algorithms
- **X25519MLKEM1024**: Hybrid key exchange mechanism
  - **X25519**: Elliptic curve Diffie-Hellman (classical component)
    - Public key size: 32 bytes
    - Shared secret size: 32 bytes
    - Classical security: ~128-bit
  - **ML-KEM-1024** (FIPS 203): Key encapsulation mechanism (post-quantum component)
    - Public key size: 1,568 bytes
    - Ciphertext size: 1,568 bytes
    - Shared secret size: 32 bytes
    - Security category: NIST Level 5 (256-bit quantum security)

### Supporting Algorithms
- **AES-256-GCM**: Symmetric encryption for data in transit
- **ChaCha20-Poly1305**: Alternative AEAD cipher for mobile/IoT devices
- **SHA3-384**: Transcript hashing and session binding
- **HKDF-SHA256**: Key derivation for channel keys
- **ML-DSA-87**: Server and client certificate signatures (integration with Layer 1)

### TLS 1.3 Integration
- **Cipher Suites**:
  - `TLS_AES_256_GCM_SHA384` (primary)
  - `TLS_CHACHA20_POLY1305_SHA256` (alternative)
- **Supported Groups**: `x25519mlkem1024` (hybrid)
- **Signature Algorithms**: `mldsa87` (post-quantum)

## Security Strength

- **Quantum Security Level**: 256-bit (NIST Security Category 5 via ML-KEM-1024)
- **Classical Security Level**: 128-bit (via X25519) + 256-bit (via AES-256-GCM)
- **Perfect Forward Secrecy**: Yes (ephemeral key exchange per session)
- **Session Key Lifetime**: Rekeying every 3600 seconds or 100GB data transfer
- **Certificate Validity**: 90 days maximum
- **Minimum TLS Version**: 1.3 (TLS 1.0, 1.1, 1.2 disabled)

## Hybrid Key Exchange Protocol

### Phase 1: ClientHello
```
Client → Server:
{
  protocol_version: "TLS 1.3",
  cipher_suites: [
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256"
  ],
  supported_groups: ["x25519mlkem1024"],
  signature_algorithms: ["mldsa87"],
  key_share: {
    x25519_public_key: 32 bytes,
    mlkem1024_public_key: 1568 bytes
  },
  client_random: 32 bytes,
  session_id: optional
}
```

### Phase 2: ServerHello + Key Exchange
```
Server → Client:
{
  protocol_version: "TLS 1.3",
  cipher_suite: "TLS_AES_256_GCM_SHA384",
  key_share: {
    x25519_public_key: 32 bytes,
    mlkem1024_ciphertext: 1568 bytes  // Encapsulated shared secret
  },
  server_random: 32 bytes,
  session_id: UUID
}
```

### Phase 3: Shared Secret Derivation
```
// Classical component
x25519_shared_secret = X25519(client_private, server_public)

// Post-quantum component (client decapsulates)
mlkem1024_shared_secret = ML-KEM-1024.Decapsulate(
  ciphertext=server_mlkem_ciphertext,
  secret_key=client_mlkem_secret
)

// Hybrid combination
hybrid_shared_secret = SHA3-384(
  x25519_shared_secret ||
  mlkem1024_shared_secret ||
  client_random ||
  server_random
)
```

### Phase 4: Key Derivation
```
// Master secret
master_secret = HKDF-Extract(
  salt=server_random,
  ikm=hybrid_shared_secret
)

// Traffic keys
client_write_key = HKDF-Expand(
  prk=master_secret,
  info="client traffic key" || transcript_hash,
  length=32
)

server_write_key = HKDF-Expand(
  prk=master_secret,
  info="server traffic key" || transcript_hash,
  length=32
)

client_write_iv = HKDF-Expand(
  prk=master_secret,
  info="client traffic iv" || transcript_hash,
  length=12
)

server_write_iv = HKDF-Expand(
  prk=master_secret,
  info="server traffic iv" || transcript_hash,
  length=12
)
```

### Phase 5: Certificate Exchange (with ML-DSA-87)
```
Server → Client:
{
  certificate: {
    public_key: ML-DSA-87 public key,
    subject: "server.example.com",
    issuer: "CA",
    validity: {
      not_before: Timestamp,
      not_after: Timestamp
    }
  },
  certificate_signature: ML-DSA-87(certificate),
  certificate_verify: ML-DSA-87(transcript_hash)
}

Client validates:
1. Certificate ML-DSA-87 signature from CA
2. Certificate validity period
3. Certificate subject matches server identity
4. CertificateVerify signature on transcript
```

### Phase 6: Finished Messages
```
Client → Server:
{
  finished: HMAC-SHA3-384(
    key=client_finish_key,
    message=transcript_hash
  )
}

Server → Client:
{
  finished: HMAC-SHA3-384(
    key=server_finish_key,
    message=transcript_hash
  )
}
```

## Perfect Forward Secrecy Implementation

### Session Key Rotation
```
Trigger conditions:
1. Time-based: Every 3600 seconds (1 hour)
2. Volume-based: Every 100 GB transferred
3. Event-based: On security policy change
4. Manual: Administrative command

Rotation process:
1. Generate new ephemeral X25519 key pair
2. Generate new ephemeral ML-KEM-1024 key pair
3. Perform new hybrid key exchange
4. Derive new traffic keys
5. Securely erase old private keys
6. Transition to new keys with synchronization
```

### Key Erasure Protocol
```
When session terminates or keys rotated:
1. Overwrite private keys with random data (3 passes)
2. Zero memory containing shared secrets
3. Clear key derivation intermediate values
4. Invalidate key handles in HSM/TPM
5. Log key destruction event (without key material)
```

### Session Resumption (0-RTT)
```
Pre-shared Key (PSK) Mode:
1. Server provides session ticket (encrypted with ML-KEM-1024)
2. Client presents ticket in next connection
3. New hybrid key exchange still performed (no 0-RTT data without fresh keys)
4. Maintains forward secrecy despite resumption
```

## API Contract

### Endpoint: `/api/v1/network/tls/handshake`

**Request (ClientHello):**
```json
{
  "protocol_version": "TLS 1.3",
  "cipher_suites": ["string"],
  "supported_groups": ["x25519mlkem1024"],
  "signature_algorithms": ["mldsa87"],
  "key_share": {
    "x25519_public": "base64url",
    "mlkem1024_public": "base64url"
  },
  "client_random": "base64url",
  "extensions": {}
}
```

**Response (ServerHello):**
```json
{
  "protocol_version": "TLS 1.3",
  "cipher_suite": "TLS_AES_256_GCM_SHA384",
  "key_share": {
    "x25519_public": "base64url",
    "mlkem1024_ciphertext": "base64url"
  },
  "server_random": "base64url",
  "session_id": "uuid",
  "certificate": {
    "public_key": "base64url",
    "subject": "string",
    "issuer": "string",
    "validity": {
      "not_before": "ISO8601",
      "not_after": "ISO8601"
    },
    "mldsa87_signature": "base64url"
  },
  "certificate_verify": "base64url",
  "transcript_hash": "base64url"
}
```

### Endpoint: `/api/v1/network/session/status`

**Request:**
```json
{
  "session_id": "uuid"
}
```

**Response:**
```json
{
  "session_id": "uuid",
  "status": "active|rekeying|terminated",
  "established_at": "ISO8601",
  "last_rekey": "ISO8601",
  "bytes_transferred": "integer",
  "cipher_suite": "string",
  "pfs_confirmed": "boolean",
  "next_rekey_at": "ISO8601"
}
```

### Endpoint: `/api/v1/network/session/rekey`

**Request:**
```json
{
  "session_id": "uuid",
  "new_key_share": {
    "x25519_public": "base64url",
    "mlkem1024_public": "base64url"
  },
  "reason": "time_based|volume_based|policy_change|manual"
}
```

**Response:**
```json
{
  "status": "rekeyed",
  "session_id": "uuid",
  "new_key_share": {
    "x25519_public": "base64url",
    "mlkem1024_ciphertext": "base64url"
  },
  "rekey_timestamp": "ISO8601",
  "rekey_proof": {
    "mldsa87_signature": "base64url",
    "transcript_hash": "base64url"
  }
}
```

### Endpoint: `/api/v1/network/certificate/verify`

**Request:**
```json
{
  "certificate": "base64url (DER encoded)",
  "certificate_chain": ["base64url"],
  "expected_subject": "string"
}
```

**Response (Valid):**
```json
{
  "status": "valid",
  "subject": "string",
  "issuer": "string",
  "validity": {
    "not_before": "ISO8601",
    "not_after": "ISO8601"
  },
  "signature_valid": "boolean",
  "chain_valid": "boolean",
  "verification_proof": {
    "mldsa87_signature": "base64url",
    "timestamp": "ISO8601"
  }
}
```

**Response (Invalid):**
```json
{
  "status": "invalid",
  "error_code": "string",
  "reason": "string",
  "failed_checks": ["string"]
}
```

## Error Codes

| Code | Name | Description | Retry | Lockout |
|------|------|-------------|-------|---------|
| `NET-3001` | `UNSUPPORTED_PROTOCOL_VERSION` | TLS version not supported (<1.3) | No | N/A |
| `NET-3002` | `UNSUPPORTED_CIPHER_SUITE` | Requested cipher suite not available | No | N/A |
| `NET-3003` | `KEY_EXCHANGE_FAILED` | Hybrid key exchange operation failed | Yes (3x) | N/A |
| `NET-3004` | `MLKEM_DECAPSULATION_FAILED` | ML-KEM-1024 decapsulation error | No | 900s |
| `NET-3005` | `X25519_COMPUTATION_FAILED` | X25519 shared secret derivation failed | No | 900s |
| `NET-3006` | `CERTIFICATE_VALIDATION_FAILED` | Server certificate invalid | No | N/A |
| `NET-3007` | `CERTIFICATE_EXPIRED` | Certificate outside validity period | No | N/A |
| `NET-3008` | `CERTIFICATE_REVOKED` | Certificate has been revoked | No | Immediate |
| `NET-3009` | `MLDSA_SIGNATURE_INVALID` | ML-DSA-87 signature verification failed | No | 900s |
| `NET-3010` | `HANDSHAKE_TIMEOUT` | TLS handshake exceeded time limit | Yes (3x) | N/A |
| `NET-3011` | `SESSION_NOT_FOUND` | Session ID not found or expired | No | N/A |
| `NET-3012` | `REKEY_FAILED` | Session rekeying operation failed | Yes (2x) | N/A |
| `NET-3013` | `TRANSCRIPT_HASH_MISMATCH` | Handshake transcript hash mismatch | No | 1800s |
| `NET-3014` | `FINISHED_VERIFICATION_FAILED` | Finished message HMAC invalid | No | 1800s |
| `NET-3015` | `UNSUPPORTED_KEY_SHARE` | Key share group not supported | No | N/A |
| `NET-3016` | `ENCRYPTION_FAILURE` | AES-256-GCM encryption failed | Yes (1x) | N/A |
| `NET-3017` | `DECRYPTION_FAILURE` | AES-256-GCM decryption failed | Yes (1x) | 600s |
| `NET-3018` | `REPLAY_DETECTED` | TLS record replay detected | No | 3600s |

## Compliance Mapping

### NIST Standards
- **FIPS 203**: ML-KEM key encapsulation mechanism
- **FIPS 204**: ML-DSA for certificate signatures
- **SP 800-52 Rev. 2**: Guidelines for TLS Implementations
  - TLS 1.3 mandatory
  - Strong cipher suites only
  - Perfect forward secrecy required
- **SP 800-77**: Guide to IPsec VPNs (for VPN mode)
- **SP 800-113**: Guide to SSL VPNs
- **NIST Cybersecurity Framework**:
  - PR.DS-2: Data in transit protected
  - PR.DS-5: Protections against data leaks
  - DE.CM-7: Network monitoring for unauthorized connections

### HIPAA Requirements
- **164.312(e)(1)**: Transmission Security
  - Encryption of ePHI in transit via TLS 1.3
  - Hybrid quantum-resistant key exchange
- **164.312(e)(2)(i)**: Integrity Controls
  - AES-256-GCM authenticated encryption
  - Transcript hash validation
- **164.312(e)(2)(ii)**: Encryption
  - 256-bit quantum security strength
  - Perfect forward secrecy protection

### SOC 2 Type II Controls
- **CC6.6**: Logical Access Security Related to Transmission
  - TLS 1.3 with hybrid PQC key exchange
  - Certificate-based authentication
- **CC6.7**: Transmission of Data Protected
  - End-to-end encryption with AES-256-GCM
  - Perfect forward secrecy for all sessions

### GDPR Compliance
- **Article 32**: Security of Processing
  - State-of-the-art encryption (TLS 1.3 + PQC)
  - Cryptographic protection against quantum attacks
- **Article 32(1)(a)**: Pseudonymization and Encryption
  - Data in transit encrypted with quantum-resistant algorithms

### PCI DSS v4.0
- **Requirement 4.1**: Strong Cryptography for Transmission
  - TLS 1.3 minimum version
  - AES-256-GCM cipher suite
- **Requirement 4.2**: PAN Protection During Transmission
  - End-to-end encryption for cardholder data
  - Perfect forward secrecy mandatory

### ISO/IEC 27001:2022
- **A.8.24**: Use of Cryptography
  - TLS 1.3 with post-quantum hybrid key exchange
- **A.13.1.1**: Network Controls
  - Secure network communications via Layer 3
- **A.13.1.3**: Segregation in Networks
  - TLS sessions provide logical network segregation
- **A.14.1.2**: Securing Application Services on Public Networks
  - TLS 1.3 protects application services
- **A.14.1.3**: Protecting Application Services Transactions
  - Transaction integrity via authenticated encryption

### FedRAMP
- **SC-8**: Transmission Confidentiality and Integrity
  - Cryptographic protection for data in transit
  - FIPS-validated algorithms
- **SC-13**: Cryptographic Protection
  - FIPS 203, FIPS 204 compliance
  - NSA CNSA 2.0 alignment (when using 256-bit parameters)

## Implementation Notes

### Performance Characteristics
- **Handshake Latency**:
  - X25519 computation: ~0.1ms
  - ML-KEM-1024 encapsulation: ~0.15ms
  - ML-KEM-1024 decapsulation: ~0.2ms
  - Total handshake overhead: ~0.5ms (vs. ~0.1ms for classical TLS 1.3)
- **Throughput**:
  - AES-256-GCM: ~5 GB/s (hardware accelerated)
  - ChaCha20-Poly1305: ~1.5 GB/s (software optimized)
- **Key Size Impact**:
  - Additional 1,568 bytes per key exchange (ML-KEM-1024)
  - Certificate size increase: ~2KB (ML-DSA-87 signatures)

### TLS 1.3 Integration
- Compatible with standard TLS 1.3 libraries via extension points
- Custom cipher suite registration: `0x0400` for X25519MLKEM1024
- Backward compatibility: Graceful fallback disabled (TLS 1.3 + PQC only)
- ALPN support: `h2` (HTTP/2), `h3` (HTTP/3)

### Certificate Management
- ML-DSA-87 certificates issued by internal CA
- Certificate pinning recommended for high-security applications
- OCSP stapling for revocation checking
- Certificate transparency logging for public-facing services
- Automated certificate renewal at 75% of validity period

### Network Topology Support
- **Point-to-Point**: Direct TLS connections
- **Mesh Network**: Full mesh with mutual TLS (mTLS)
- **Gateway Mode**: TLS termination at edge gateway
- **Service Mesh**: Integration with Istio/Envoy via custom extensions

### Monitoring and Logging
- All handshakes logged with session ID and transcript hash
- Certificate validation events logged
- Rekeying operations logged with reason and timestamp
- Failed handshakes trigger Layer 7 anomaly detection
- Network traffic patterns analyzed for anomalies

### Interoperability
- **Layer 1 Integration**: Uses ML-DSA-87 certificates from identity layer
- **Layer 2 Integration**: Authorization enforced before TLS session establishment
- **Layer 4 Integration**: TLS secures transport for encrypted data
- **Layer 8 Integration**: Algorithm negotiation via orchestration layer
