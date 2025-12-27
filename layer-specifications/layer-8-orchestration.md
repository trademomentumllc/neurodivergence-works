# Layer 8: PQC Orchestration Specification

## Purpose

Layer 8 provides centralized coordination and management of post-quantum cryptographic operations across all seven underlying security layers. This orchestration layer implements FIPS 203/204/205 coordination, cryptographic algorithm negotiation, crypto-agility framework, and coordinated key lifecycle management. It ensures seamless operation of the entire eight-layer security stack, maintains cryptographic consistency, and enables graceful migration between cryptographic algorithms as standards evolve.

## Algorithms

### Primary Algorithms (Coordinated)
- **ML-KEM-1024** (FIPS 203): Key Encapsulation Mechanism
  - Coordinated across Layers 3, 4, 8
- **ML-DSA-87** (FIPS 204): Digital Signature Algorithm
  - Coordinated across Layers 1, 2, 5, 6, 7, 8
- **SLH-DSA-SHAKE-256s** (FIPS 205): Stateless Hash-Based Signatures
  - Alternative signature scheme for long-term signatures
  - Public key size: 64 bytes
  - Signature size: ~29,792 bytes
  - Security: 256-bit quantum security

### Supporting Algorithms
- **SHA3-512**: Algorithm identifier hashing and policy binding
- **HKDF-SHA256**: Cross-layer key derivation coordination
- **Blake3**: Fast integrity checking for orchestration messages
- **ChaCha20-Poly1305**: Orchestration channel encryption

## Security Strength

- **Quantum Security Level**: 256-bit (coordinated across all layers)
- **Classical Security Level**: 256-bit minimum enforced
- **Algorithm Negotiation**: Cryptographically authenticated
- **Key Rotation Coordination**: Atomic cross-layer updates
- **Policy Enforcement**: Cryptographically signed policies
- **Orchestration Channel**: AES-256-GCM or ChaCha20-Poly1305 encrypted

## FIPS 203/204/205 Coordination

### Algorithm Registry

```json
{
  "registry_version": "1.0",
  "last_updated": "2025-12-24T00:00:00Z",
  "algorithms": {
    "kem": [
      {
        "name": "ML-KEM-1024",
        "fips": "FIPS 203",
        "status": "active",
        "security_level": 5,
        "quantum_bits": 256,
        "layers": [3, 4, 8],
        "key_sizes": {
          "public_key": 1568,
          "secret_key": 3168,
          "ciphertext": 1568,
          "shared_secret": 32
        },
        "performance": {
          "keygen_ms": 0.12,
          "encaps_ms": 0.15,
          "decaps_ms": 0.20
        }
      },
      {
        "name": "ML-KEM-768",
        "fips": "FIPS 203",
        "status": "supported",
        "security_level": 3,
        "quantum_bits": 192,
        "layers": [],
        "fallback_for": "ML-KEM-1024"
      }
    ],
    "signature": [
      {
        "name": "ML-DSA-87",
        "fips": "FIPS 204",
        "status": "active",
        "security_level": 5,
        "quantum_bits": 256,
        "layers": [1, 2, 5, 6, 7, 8],
        "key_sizes": {
          "public_key": 2592,
          "secret_key": 4864,
          "signature": 4627
        },
        "performance": {
          "keygen_ms": 3.5,
          "sign_ms": 5.2,
          "verify_ms": 2.8
        }
      },
      {
        "name": "SLH-DSA-SHAKE-256s",
        "fips": "FIPS 205",
        "status": "supported",
        "security_level": 5,
        "quantum_bits": 256,
        "layers": [],
        "use_case": "long_term_signatures",
        "key_sizes": {
          "public_key": 64,
          "secret_key": 128,
          "signature": 29792
        },
        "performance": {
          "keygen_ms": 15,
          "sign_ms": 350,
          "verify_ms": 18
        }
      }
    ],
    "hybrid": [
      {
        "name": "X25519MLKEM1024",
        "components": ["X25519", "ML-KEM-1024"],
        "status": "active",
        "layers": [3],
        "combiner": "SHA3-384"
      }
    ]
  },
  "registry_signature": {
    "algorithm": "ML-DSA-87",
    "signature": "base64url",
    "public_key_id": "uuid"
  }
}
```

### Cross-Layer Algorithm Policies

```json
{
  "policy_id": "uuid",
  "policy_name": "production-pqc-policy",
  "version": "2.1",
  "effective_date": "2025-12-24T00:00:00Z",
  "policies": {
    "minimum_security_level": 5,
    "quantum_security_required": true,
    "allowed_algorithms": {
      "kem": ["ML-KEM-1024"],
      "signature": ["ML-DSA-87"],
      "hash": ["SHA3-256", "SHA3-384", "SHA3-512"],
      "symmetric": ["AES-256-GCM", "ChaCha20-Poly1305"]
    },
    "prohibited_algorithms": [
      "RSA-2048",
      "ECDSA-P256",
      "SHA-1",
      "MD5",
      "DES",
      "3DES"
    ],
    "hybrid_mode": {
      "enabled": true,
      "classical_component_required": true,
      "combiner": "SHA3-384"
    },
    "key_lifecycle": {
      "max_key_age_days": {
        "identity_keys": 90,
        "session_keys": 1,
        "kek": 30,
        "dek": 0,
        "signature_keys": 180
      },
      "rotation_schedule": "0 2 * * 0",
      "emergency_rotation_sla_minutes": 15
    },
    "layer_specific": {
      "layer_1": {
        "mfa_required": true,
        "ml_dsa_signature_required": true
      },
      "layer_3": {
        "min_tls_version": "1.3",
        "hybrid_key_exchange_required": true
      },
      "layer_4": {
        "min_aes_key_size": 256,
        "authenticated_encryption_required": true
      }
    }
  },
  "policy_signature": {
    "algorithm": "ML-DSA-87",
    "signature": "base64url",
    "signed_by": "security-team-key-id"
  }
}
```

## Algorithm Negotiation

### Negotiation Protocol

**Phase 1: Capability Advertisement**
```json
{
  "message_type": "capability_advertisement",
  "message_id": "uuid",
  "timestamp": "ISO8601",
  "sender": {
    "service_id": "uuid",
    "layer": 3,
    "endpoint": "https://service.example.com"
  },
  "capabilities": {
    "kem": [
      {
        "algorithm": "ML-KEM-1024",
        "status": "preferred",
        "performance_tier": "high"
      },
      {
        "algorithm": "ML-KEM-768",
        "status": "supported",
        "performance_tier": "medium"
      }
    ],
    "signature": [
      {
        "algorithm": "ML-DSA-87",
        "status": "required",
        "performance_tier": "high"
      }
    ],
    "symmetric": [
      {
        "algorithm": "AES-256-GCM",
        "status": "preferred",
        "hardware_accelerated": true
      },
      {
        "algorithm": "ChaCha20-Poly1305",
        "status": "supported",
        "hardware_accelerated": false
      }
    ]
  },
  "constraints": {
    "max_signature_size_bytes": 5000,
    "max_public_key_size_bytes": 3000,
    "max_handshake_latency_ms": 500
  },
  "message_signature": {
    "algorithm": "ML-DSA-87",
    "signature": "base64url"
  }
}
```

**Phase 2: Algorithm Selection**
```python
def negotiate_algorithms(client_caps, server_caps, policy):
    """Negotiate cryptographic algorithms between client and server"""

    # Filter by policy
    allowed_kems = set(policy["allowed_algorithms"]["kem"])
    allowed_sigs = set(policy["allowed_algorithms"]["signature"])

    # Find intersection of capabilities
    client_kems = {c["algorithm"] for c in client_caps["kem"]}
    server_kems = {c["algorithm"] for c in server_caps["kem"]}
    common_kems = client_kems & server_kems & allowed_kems

    client_sigs = {c["algorithm"] for c in client_caps["signature"]}
    server_sigs = {c["algorithm"] for c in server_caps["signature"]}
    common_sigs = client_sigs & server_sigs & allowed_sigs

    # Select preferred algorithms
    if not common_kems or not common_sigs:
        raise AlgorithmNegotiationError("No common algorithms")

    # Prefer algorithms with highest security level
    selected_kem = select_highest_security(common_kems)
    selected_sig = select_highest_security(common_sigs)

    # Verify policy compliance
    if not verify_policy_compliance(selected_kem, selected_sig, policy):
        raise PolicyViolationError("Selected algorithms violate policy")

    return {
        "kem": selected_kem,
        "signature": selected_sig,
        "negotiation_hash": sha3_512(
            client_caps_hash + server_caps_hash + policy_hash
        )
    }
```

**Phase 3: Negotiation Confirmation**
```json
{
  "message_type": "negotiation_confirmation",
  "message_id": "uuid",
  "timestamp": "ISO8601",
  "negotiation_id": "uuid",
  "selected_algorithms": {
    "kem": "ML-KEM-1024",
    "signature": "ML-DSA-87",
    "symmetric": "AES-256-GCM",
    "hash": "SHA3-384"
  },
  "negotiation_transcript": {
    "client_capabilities_hash": "base64url (SHA3-512)",
    "server_capabilities_hash": "base64url (SHA3-512)",
    "policy_hash": "base64url (SHA3-512)",
    "negotiation_hash": "base64url (SHA3-512)"
  },
  "confirmation_signature": {
    "algorithm": "ML-DSA-87",
    "signature": "base64url"
  }
}
```

## Crypto-Agility Framework

### Migration Scenarios

#### Scenario 1: Algorithm Upgrade (ML-DSA-87 → SLH-DSA)
```json
{
  "migration_id": "uuid",
  "migration_name": "ML-DSA-87-to-SLH-DSA-migration",
  "reason": "Long-term signature requirements",
  "start_date": "2026-01-01T00:00:00Z",
  "end_date": "2026-03-31T23:59:59Z",
  "phases": [
    {
      "phase": 1,
      "name": "Preparation",
      "duration_days": 30,
      "actions": [
        "Deploy SLH-DSA libraries to all services",
        "Train ML models on SLH-DSA performance characteristics",
        "Update algorithm registry",
        "Test backward compatibility"
      ]
    },
    {
      "phase": 2,
      "name": "Dual-Algorithm Period",
      "duration_days": 45,
      "actions": [
        "Generate SLH-DSA keys for all services",
        "Sign new data with both ML-DSA-87 and SLH-DSA",
        "Verify signatures from both algorithms",
        "Monitor performance impact"
      ]
    },
    {
      "phase": 3,
      "name": "Transition",
      "duration_days": 10,
      "actions": [
        "Make SLH-DSA primary signature algorithm",
        "ML-DSA-87 becomes fallback",
        "Re-sign critical historical records",
        "Update all policies"
      ]
    },
    {
      "phase": 4,
      "name": "Decommission",
      "duration_days": 5,
      "actions": [
        "Stop accepting ML-DSA-87 signatures",
        "Revoke ML-DSA-87 keys",
        "Remove ML-DSA-87 from algorithm registry",
        "Archive old signatures for compliance"
      ]
    }
  ],
  "rollback_plan": {
    "trigger_conditions": [
      "performance_degradation > 50%",
      "error_rate > 5%",
      "incompatibility_detected"
    ],
    "rollback_steps": [
      "Revert to ML-DSA-87 as primary",
      "Invalidate SLH-DSA signatures issued during migration",
      "Restore previous policy",
      "Conduct incident review"
    ]
  },
  "migration_signature": {
    "algorithm": "ML-DSA-87",
    "signature": "base64url"
  }
}
```

### Crypto-Agility Design Principles

**1. Algorithm Abstraction**
```python
class CryptoProvider(ABC):
    """Abstract interface for cryptographic operations"""

    @abstractmethod
    def sign(self, message: bytes, private_key: Key) -> Signature:
        pass

    @abstractmethod
    def verify(self, message: bytes, signature: Signature, public_key: Key) -> bool:
        pass

    @abstractmethod
    def encapsulate(self, public_key: Key) -> Tuple[bytes, bytes]:
        pass

    @abstractmethod
    def decapsulate(self, ciphertext: bytes, private_key: Key) -> bytes:
        pass

class MLDSAProvider(CryptoProvider):
    """ML-DSA-87 implementation"""
    def sign(self, message: bytes, private_key: Key) -> Signature:
        return ml_dsa_87_sign(private_key, message)
    # ... other methods

class SLHDSAProvider(CryptoProvider):
    """SLH-DSA implementation"""
    def sign(self, message: bytes, private_key: Key) -> Signature:
        return slh_dsa_sign(private_key, message)
    # ... other methods
```

**2. Algorithm Registry Pattern**
```python
class CryptoRegistry:
    """Centralized algorithm registry"""

    def __init__(self):
        self.providers = {}
        self.policies = {}

    def register_provider(self, algorithm_name: str, provider: CryptoProvider):
        """Register a crypto provider"""
        if not self.verify_policy_compliance(algorithm_name):
            raise PolicyViolationError(f"{algorithm_name} not allowed by policy")

        self.providers[algorithm_name] = provider

    def get_provider(self, algorithm_name: str) -> CryptoProvider:
        """Get provider for algorithm"""
        if algorithm_name not in self.providers:
            raise AlgorithmNotFoundError(f"{algorithm_name} not registered")

        return self.providers[algorithm_name]

    def negotiate(self, capabilities: dict) -> str:
        """Negotiate best algorithm"""
        allowed = self.policies["allowed_algorithms"]
        preferred = self.policies["preferred_algorithms"]

        # Try preferred algorithms first
        for alg in preferred:
            if alg in capabilities and alg in self.providers:
                return alg

        # Fallback to any allowed algorithm
        for alg in allowed:
            if alg in capabilities and alg in self.providers:
                return alg

        raise AlgorithmNegotiationError("No compatible algorithms")
```

**3. Versioned Cryptographic Objects**
```json
{
  "object_type": "signature",
  "version": "2.0",
  "algorithm": "ML-DSA-87",
  "algorithm_version": "1.0",
  "signature": "base64url",
  "metadata": {
    "created_at": "ISO8601",
    "key_id": "uuid",
    "algorithm_parameters": {
      "security_level": 5,
      "parameter_set": "ML-DSA-87"
    }
  },
  "backward_compatible": true,
  "successor_algorithm": "SLH-DSA-SHAKE-256s"
}
```

## Coordinated Key Rotation

### Cross-Layer Rotation Protocol

**Step 1: Rotation Planning**
```json
{
  "rotation_plan_id": "uuid",
  "rotation_type": "scheduled|emergency|policy_change",
  "affected_layers": [1, 2, 3, 4, 5, 6, 7],
  "affected_keys": [
    {
      "layer": 1,
      "key_type": "identity_signature_key",
      "key_id": "uuid",
      "rotation_window": {
        "start": "ISO8601",
        "end": "ISO8601"
      }
    },
    {
      "layer": 3,
      "key_type": "tls_certificate",
      "key_id": "uuid",
      "rotation_window": {
        "start": "ISO8601",
        "end": "ISO8601"
      }
    }
  ],
  "dependencies": [
    {
      "prerequisite": "layer_1_rotation",
      "dependent": "layer_2_rotation",
      "reason": "Layer 2 capability tokens signed by Layer 1 keys"
    }
  ],
  "coordination_sequence": [1, 4, 3, 2, 5, 6, 7],
  "rollback_triggers": [
    "rotation_failure_count > 3",
    "service_availability < 99%",
    "error_rate > 1%"
  ]
}
```

**Step 2: Pre-Rotation Validation**
```python
def validate_rotation_plan(plan):
    """Validate rotation plan before execution"""

    # Check all affected layers are ready
    for layer in plan["affected_layers"]:
        readiness = check_layer_readiness(layer)
        if not readiness["ready"]:
            raise LayerNotReadyError(f"Layer {layer}: {readiness['reason']}")

    # Verify rotation windows don't overlap
    if has_overlapping_windows(plan["affected_keys"]):
        raise RotationWindowConflictError("Overlapping rotation windows")

    # Check dependencies are satisfied
    for dep in plan["dependencies"]:
        if not verify_dependency(dep):
            raise DependencyNotSatisfiedError(f"Dependency not satisfied: {dep}")

    # Ensure rollback plan exists
    if not plan.get("rollback_plan"):
        raise MissingRollbackPlanError("Rollback plan required")

    return True
```

**Step 3: Coordinated Rotation Execution**
```python
def execute_coordinated_rotation(plan):
    """Execute rotation across multiple layers"""

    rotation_state = {
        "status": "in_progress",
        "completed_layers": [],
        "failed_layers": [],
        "rollback_required": False
    }

    try:
        # Execute rotations in dependency order
        for layer_id in plan["coordination_sequence"]:
            layer_rotation = get_layer_rotation_config(layer_id, plan)

            # Pre-rotation checkpoint
            create_checkpoint(layer_id)

            # Execute layer rotation
            result = execute_layer_rotation(layer_id, layer_rotation)

            if result["status"] == "success":
                rotation_state["completed_layers"].append(layer_id)

                # Notify dependent layers
                notify_dependent_layers(layer_id, result["new_keys"])
            else:
                rotation_state["failed_layers"].append(layer_id)
                rotation_state["rollback_required"] = True
                break

            # Verify rotation
            if not verify_layer_rotation(layer_id, result):
                rotation_state["failed_layers"].append(layer_id)
                rotation_state["rollback_required"] = True
                break

        # Check rollback triggers
        if evaluate_rollback_triggers(plan["rollback_triggers"]):
            rotation_state["rollback_required"] = True

    except Exception as e:
        rotation_state["status"] = "failed"
        rotation_state["error"] = str(e)
        rotation_state["rollback_required"] = True

    # Execute rollback if needed
    if rotation_state["rollback_required"]:
        rollback_rotation(rotation_state["completed_layers"])
        rotation_state["status"] = "rolled_back"
    else:
        rotation_state["status"] = "completed"

    # Sign rotation event
    rotation_event = {
        "plan_id": plan["rotation_plan_id"],
        "timestamp": datetime.now(UTC),
        "state": rotation_state
    }
    rotation_event["signature"] = ml_dsa_87_sign(
        orchestration_key,
        json.dumps(rotation_event, sort_keys=True)
    )

    # Log to audit chain
    log_rotation_event(rotation_event)

    return rotation_state
```

## API Contract

### Endpoint: `/api/v1/orchestration/registry`

**Request:**
```json
{
  "session_token": "base64url",
  "capability_token": "base64url"
}
```

**Response:**
```json
{
  "status": "success",
  "registry_version": "1.0",
  "algorithms": {
    "kem": [...],
    "signature": [...],
    "hybrid": [...]
  },
  "registry_signature": {
    "algorithm": "ML-DSA-87",
    "signature": "base64url",
    "verified": true
  }
}
```

### Endpoint: `/api/v1/orchestration/negotiate`

**Request:**
```json
{
  "session_token": "base64url",
  "client_capabilities": {
    "kem": ["ML-KEM-1024", "ML-KEM-768"],
    "signature": ["ML-DSA-87"],
    "symmetric": ["AES-256-GCM"]
  },
  "constraints": {
    "max_signature_size_bytes": 5000,
    "max_handshake_latency_ms": 500
  }
}
```

**Response:**
```json
{
  "status": "negotiated",
  "negotiation_id": "uuid",
  "selected_algorithms": {
    "kem": "ML-KEM-1024",
    "signature": "ML-DSA-87",
    "symmetric": "AES-256-GCM",
    "hash": "SHA3-384"
  },
  "negotiation_signature": {
    "algorithm": "ML-DSA-87",
    "signature": "base64url"
  }
}
```

### Endpoint: `/api/v1/orchestration/policy`

**Request (Get Policy):**
```json
{
  "session_token": "base64url",
  "capability_token": "base64url",
  "policy_id": "uuid (optional)"
}
```

**Response:**
```json
{
  "status": "success",
  "policy": {
    "policy_id": "uuid",
    "policy_name": "production-pqc-policy",
    "version": "2.1",
    "effective_date": "ISO8601",
    "policies": {...},
    "policy_signature": {
      "algorithm": "ML-DSA-87",
      "signature": "base64url",
      "verified": true
    }
  }
}
```

### Endpoint: `/api/v1/orchestration/rotation/plan`

**Request:**
```json
{
  "session_token": "base64url",
  "admin_capability_token": "base64url",
  "rotation_type": "scheduled|emergency|policy_change",
  "affected_layers": [1, 2, 3],
  "rotation_window": {
    "start": "ISO8601",
    "end": "ISO8601"
  }
}
```

**Response:**
```json
{
  "status": "planned",
  "rotation_plan_id": "uuid",
  "affected_keys": [...],
  "coordination_sequence": [1, 4, 3, 2],
  "estimated_duration_minutes": 45,
  "plan_signature": {
    "algorithm": "ML-DSA-87",
    "signature": "base64url"
  }
}
```

### Endpoint: `/api/v1/orchestration/rotation/execute`

**Request:**
```json
{
  "session_token": "base64url",
  "admin_capability_token": "base64url",
  "rotation_plan_id": "uuid",
  "dry_run": false
}
```

**Response:**
```json
{
  "status": "completed|failed|rolled_back",
  "rotation_plan_id": "uuid",
  "completed_layers": [1, 3, 4],
  "failed_layers": [],
  "rollback_executed": false,
  "duration_seconds": 2700,
  "rotation_signature": {
    "algorithm": "ML-DSA-87",
    "signature": "base64url"
  }
}
```

### Endpoint: `/api/v1/orchestration/migration/status`

**Request:**
```json
{
  "session_token": "base64url",
  "capability_token": "base64url",
  "migration_id": "uuid (optional)"
}
```

**Response:**
```json
{
  "status": "success",
  "active_migrations": [
    {
      "migration_id": "uuid",
      "migration_name": "string",
      "current_phase": 2,
      "progress_percentage": 45,
      "start_date": "ISO8601",
      "estimated_completion": "ISO8601"
    }
  ]
}
```

## Error Codes

| Code | Name | Description | Retry | Lockout |
|------|------|-------------|-------|---------|
| `ORCH-8001` | `ALGORITHM_NEGOTIATION_FAILED` | No compatible algorithms found | Yes (3x) | N/A |
| `ORCH-8002` | `POLICY_VIOLATION` | Selected algorithm violates policy | No | N/A |
| `ORCH-8003` | `UNSUPPORTED_ALGORITHM` | Algorithm not in registry | No | N/A |
| `ORCH-8004` | `ROTATION_PLAN_INVALID` | Rotation plan validation failed | Yes (1x) | N/A |
| `ORCH-8005` | `ROTATION_EXECUTION_FAILED` | Rotation execution failed | Yes (1x) | N/A |
| `ORCH-8006` | `ROLLBACK_FAILED` | Rotation rollback failed | No | Immediate |
| `ORCH-8007` | `LAYER_NOT_READY` | Layer not ready for rotation | Yes (5x) | N/A |
| `ORCH-8008` | `DEPENDENCY_NOT_SATISFIED` | Rotation dependency not met | No | N/A |
| `ORCH-8009` | `MIGRATION_CONFLICT` | Conflicting migration in progress | No | N/A |
| `ORCH-8010` | `REGISTRY_SIGNATURE_INVALID` | Algorithm registry signature invalid | No | 900s |
| `ORCH-8011` | `POLICY_SIGNATURE_INVALID` | Policy signature invalid | No | 900s |
| `ORCH-8012` | `CAPABILITY_MISMATCH` | Client/server capability mismatch | No | N/A |
| `ORCH-8013` | `ORCHESTRATION_CHANNEL_FAILURE` | Communication with layer failed | Yes (5x) | N/A |
| `ORCH-8014` | `KEY_DISTRIBUTION_FAILED` | Failed to distribute new keys | Yes (3x) | N/A |
| `ORCH-8015` | `INSUFFICIENT_PRIVILEGES` | Orchestration action requires admin | No | N/A |

## Compliance Mapping

### NIST Standards
- **FIPS 203**: ML-KEM coordination across layers
- **FIPS 204**: ML-DSA coordination and signatures
- **FIPS 205**: SLH-DSA alternative signatures
- **SP 800-57**: Key Management
  - Part 1: Cross-layer key lifecycle management
- **SP 800-131A**: Transitioning the Use of Cryptographic Algorithms
  - Algorithm migration framework
- **SP 800-133**: Cryptographic Key Generation
  - Coordinated key generation
- **NIST Cybersecurity Framework**:
  - ID.AM-5: Resources prioritized based on classification
  - PR.IP-1: Configuration management baseline established
  - PR.MA-1: Maintenance and repair performed

### HIPAA Requirements
- **164.312(e)(2)(ii)**: Encryption Mechanism
  - Coordinated encryption across all PHI touchpoints
- **Security Management Process**:
  - Centralized security policy enforcement

### SOC 2 Type II Controls
- **CC8.1**: Change Management
  - Controlled algorithm migrations
  - Coordinated key rotations

### GDPR Compliance
- **Article 32**: Security of Processing
  - State-of-the-art cryptography coordination
  - Ability to ensure ongoing security

### ISO/IEC 27001:2022
- **A.8.24**: Use of Cryptography
  - Centralized cryptographic policy
- **A.14.2.1**: Secure Development Policy
  - Crypto-agility framework

## Implementation Notes

### Performance Characteristics
- **Algorithm Negotiation**: <100ms
- **Policy Validation**: <10ms
- **Rotation Planning**: <5 seconds
- **Rotation Execution**: 15-60 minutes (depending on scope)
- **Registry Lookup**: <1ms (cached)

### Scalability
- **Distributed Registry**: Replicated across all nodes
- **Event-Driven Architecture**: Kafka for rotation coordination
- **Stateless Orchestration**: Horizontal scaling support

### Monitoring
- Algorithm usage statistics per layer
- Rotation success/failure rates
- Migration progress tracking
- Policy compliance monitoring

### Integration Points
- **All Layers**: Orchestrates cryptographic operations
- **Layer 7 (Self-Healing)**: Automated rotation on anomaly detection
- **External PKI**: Certificate authority integration
- **Compliance Systems**: Audit and reporting integration
