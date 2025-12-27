# Layer 7: Self-Healing Specification

## Purpose

Layer 7 provides autonomous security monitoring, anomaly detection, and automated remediation capabilities. This layer continuously analyzes system behavior across all other layers, identifies security anomalies using machine learning algorithms, and executes automated healing actions signed with ML-DSA-87 for accountability. It implements a closed-loop security system that detects, responds to, and recovers from security incidents without human intervention while maintaining cryptographic audit trails.

## Algorithms

### Primary Algorithms
- **ML-DSA-87** (FIPS 204): Healing action signatures
  - Public key size: 2,592 bytes
  - Secret key size: 4,864 bytes
  - Signature size: 4,627 bytes
  - Security category: NIST Level 5 (256-bit quantum security)

### Anomaly Detection Algorithms

#### Statistical Methods
- **Isolation Forest**: Unsupervised anomaly detection
  - Tree depth: 8-12
  - Number of trees: 100
  - Contamination rate: 0.01 (1% anomalies expected)

- **One-Class SVM**: Boundary-based anomaly detection
  - Kernel: RBF (Radial Basis Function)
  - Nu parameter: 0.05
  - Gamma: auto

- **DBSCAN**: Density-based clustering
  - Epsilon: Auto-tuned per feature
  - Minimum samples: 5
  - Distance metric: Euclidean

#### Time Series Analysis
- **ARIMA**: Autoregressive Integrated Moving Average
  - Order: (5, 1, 2) - tunable
  - Seasonal: Yes (24-hour period for daily patterns)

- **Prophet**: Facebook's time series forecasting
  - Trend: Linear or logistic
  - Seasonality: Additive
  - Changepoint detection: Enabled

- **LSTM**: Long Short-Term Memory neural networks
  - Architecture: 2 layers, 128 units each
  - Sequence length: 100 timesteps
  - Dropout: 0.2

#### Graph-Based Detection
- **Graph Neural Networks (GNN)**: Attack pattern detection
  - Node features: User behavior, resource access
  - Edge features: Communication patterns
  - Architecture: GraphSAGE

### Supporting Algorithms
- **SHA3-384**: Event hashing and fingerprinting
- **Blake3**: Fast log hashing for real-time analysis
- **HMAC-SHA3-384**: Anomaly signature for data integrity
- **Argon2id**: Secure storage of ML model weights

## Security Strength

- **Quantum Security Level**: 256-bit (via ML-DSA-87 healing signatures)
- **Anomaly Detection Accuracy**: >95% true positive rate, <2% false positive rate
- **Detection Latency**: <5 seconds for critical anomalies
- **Remediation Latency**: <30 seconds for automated actions
- **Model Update Frequency**: Every 24 hours (incremental learning)
- **Audit Retention**: 90 days for anomaly events, 7 years for healing actions

## Anomaly Detection Framework

### Monitored Metrics

#### Layer 1 (Identity) Metrics
```python
identity_metrics = {
    "authentication_failures": int,
    "authentication_latency_ms": float,
    "mfa_bypass_attempts": int,
    "session_duration_seconds": float,
    "concurrent_sessions_per_user": int,
    "fido2_validation_failures": int,
    "ml_dsa_signature_failures": int,
    "device_fingerprint_changes": int,
    "geographic_velocity": float,  # km/hour between logins
    "authentication_time_of_day": int  # hour (0-23)
}
```

#### Layer 2 (Authorization) Metrics
```python
authorization_metrics = {
    "permission_denials": int,
    "capability_token_expirations": int,
    "nonce_replay_attempts": int,
    "privilege_escalation_attempts": int,
    "role_assignment_changes": int,
    "authorization_latency_ms": float,
    "access_pattern_entropy": float,
    "resource_access_frequency": dict,  # {resource: count}
    "cross_tenant_access_attempts": int
}
```

#### Layer 3 (Network) Metrics
```python
network_metrics = {
    "tls_handshake_failures": int,
    "certificate_validation_failures": int,
    "connection_rate_per_ip": float,
    "bandwidth_usage_mbps": float,
    "packet_loss_rate": float,
    "connection_duration_seconds": float,
    "unusual_ports": list,
    "geographic_source_diversity": int,
    "tls_downgrade_attempts": int,
    "cipher_suite_mismatches": int
}
```

#### Layer 4 (Encryption) Metrics
```python
encryption_metrics = {
    "encryption_failures": int,
    "decryption_failures": int,
    "key_rotation_delays": int,
    "kek_access_frequency": dict,
    "dek_generation_rate": float,
    "encryption_latency_ms": float,
    "nonce_reuse_attempts": int,
    "tag_verification_failures": int,
    "hsm_availability": float  # percentage
}
```

#### Layer 5 (Database) Metrics
```python
database_metrics = {
    "rls_policy_violations": int,
    "signature_verification_failures": int,
    "audit_chain_gaps": int,
    "query_execution_time_ms": float,
    "concurrent_connections": int,
    "failed_queries": int,
    "data_export_volume_mb": float,
    "unusual_query_patterns": list,
    "bulk_data_access_events": int
}
```

#### Layer 6 (PHI) Metrics
```python
phi_metrics = {
    "consent_violations": int,
    "hmac_verification_failures": int,
    "phi_access_without_consent": int,
    "deidentification_failures": int,
    "fhir_validation_errors": int,
    "break_glass_activations": int,
    "patient_record_access_rate": float,
    "minimum_necessary_violations": int
}
```

### Anomaly Detection Pipeline

**Phase 1: Data Collection**
```python
def collect_metrics():
    """Collect metrics from all layers"""
    metrics = {
        "timestamp": datetime.now(UTC),
        "layer_1": collect_identity_metrics(),
        "layer_2": collect_authorization_metrics(),
        "layer_3": collect_network_metrics(),
        "layer_4": collect_encryption_metrics(),
        "layer_5": collect_database_metrics(),
        "layer_6": collect_phi_metrics(),
        "system": collect_system_metrics()
    }

    # Compute metric hash for integrity
    metrics["hash"] = blake3(json.dumps(metrics))

    return metrics
```

**Phase 2: Feature Engineering**
```python
def engineer_features(metrics):
    """Extract features for ML models"""
    features = []

    # Time-based features
    features.append(metrics["timestamp"].hour)
    features.append(metrics["timestamp"].weekday())

    # Aggregate features
    features.append(sum_layer_failures(metrics))
    features.append(avg_latency(metrics))

    # Ratio features
    features.append(
        metrics["layer_1"]["authentication_failures"] /
        max(metrics["layer_1"]["authentication_attempts"], 1)
    )

    # Entropy features
    features.append(compute_access_entropy(metrics["layer_2"]))

    # Rate features
    features.append(
        metrics["layer_5"]["query_execution_time_ms"] /
        max(metrics["layer_5"]["query_count"], 1)
    )

    return np.array(features)
```

**Phase 3: Anomaly Detection**
```python
def detect_anomalies(features):
    """Run ensemble of anomaly detection models"""
    anomalies = []

    # Isolation Forest
    if_score = isolation_forest.decision_function([features])[0]
    if if_score < -0.5:
        anomalies.append({
            "model": "IsolationForest",
            "score": if_score,
            "severity": compute_severity(if_score)
        })

    # One-Class SVM
    svm_score = one_class_svm.decision_function([features])[0]
    if svm_score < -0.3:
        anomalies.append({
            "model": "OneClassSVM",
            "score": svm_score,
            "severity": compute_severity(svm_score)
        })

    # LSTM prediction
    lstm_prediction = lstm_model.predict([features])
    lstm_error = mean_squared_error([features], lstm_prediction)
    if lstm_error > threshold:
        anomalies.append({
            "model": "LSTM",
            "score": lstm_error,
            "severity": compute_severity(lstm_error)
        })

    return anomalies
```

**Phase 4: Anomaly Classification**
```python
def classify_anomaly(anomaly, metrics):
    """Classify anomaly into attack categories"""

    # Rule-based classification
    if metrics["layer_1"]["authentication_failures"] > 10:
        return "brute_force_attack"

    if metrics["layer_2"]["nonce_replay_attempts"] > 0:
        return "replay_attack"

    if metrics["layer_3"]["tls_downgrade_attempts"] > 0:
        return "downgrade_attack"

    if metrics["layer_5"]["rls_policy_violations"] > 5:
        return "unauthorized_access_attempt"

    if metrics["layer_6"]["consent_violations"] > 0:
        return "privacy_violation"

    # ML-based classification
    attack_type = attack_classifier.predict([anomaly["features"]])[0]
    confidence = attack_classifier.predict_proba([anomaly["features"]])

    return {
        "type": attack_type,
        "confidence": confidence[0][attack_type]
    }
```

## Autonomous Remediation

### Remediation Actions

#### Action Catalog
```python
remediation_actions = {
    "brute_force_attack": [
        "block_ip_address",
        "increase_authentication_delay",
        "require_additional_mfa_factor",
        "notify_security_team"
    ],
    "replay_attack": [
        "invalidate_session_tokens",
        "rotate_nonce_keys",
        "block_suspicious_client",
        "alert_layer_8_for_key_rotation"
    ],
    "downgrade_attack": [
        "enforce_tls_1_3_only",
        "block_legacy_cipher_suites",
        "terminate_suspicious_connections",
        "update_security_policies"
    ],
    "unauthorized_access_attempt": [
        "revoke_capability_tokens",
        "disable_user_account",
        "audit_user_permissions",
        "notify_compliance_team"
    ],
    "privacy_violation": [
        "revoke_phi_access",
        "audit_consent_status",
        "notify_privacy_officer",
        "log_hipaa_incident"
    ],
    "key_compromise_suspected": [
        "initiate_emergency_key_rotation",
        "invalidate_all_signatures_from_key",
        "alert_layer_8_orchestration",
        "lock_down_affected_resources"
    ],
    "data_exfiltration_suspected": [
        "block_outbound_connections",
        "quarantine_affected_data",
        "snapshot_system_state",
        "engage_incident_response"
    ]
}
```

### Remediation Execution

**Step 1: Action Selection**
```python
def select_remediation_actions(anomaly_type, severity):
    """Select appropriate remediation actions"""

    # Get base actions for anomaly type
    actions = remediation_actions.get(anomaly_type, [])

    # Filter by severity
    if severity == "critical":
        # Execute all actions immediately
        return actions
    elif severity == "high":
        # Execute automated actions only
        return [a for a in actions if is_automated(a)]
    elif severity == "medium":
        # Execute low-risk actions, notify for others
        return [a for a in actions if is_low_risk(a)]
    else:
        # Log only, no automated action
        return ["log_anomaly"]

    return actions
```

**Step 2: Action Validation**
```python
def validate_remediation_action(action, context):
    """Validate action before execution"""

    # Check if action is allowed by policy
    if not is_action_allowed(action, context):
        return False, "Action not allowed by policy"

    # Check if action has necessary permissions
    if not has_action_permissions(action):
        return False, "Insufficient permissions"

    # Check for potential side effects
    side_effects = predict_side_effects(action, context)
    if side_effects["severity"] > acceptable_threshold:
        return False, f"Side effects too severe: {side_effects}"

    # Check rate limits (prevent action storms)
    if is_rate_limited(action):
        return False, "Action rate limit exceeded"

    return True, "Action validated"
```

**Step 3: Action Execution**
```python
def execute_remediation_action(action, context):
    """Execute remediation action with ML-DSA-87 signature"""

    # Prepare action details
    action_details = {
        "action_id": str(uuid4()),
        "action_type": action["type"],
        "timestamp": datetime.now(UTC),
        "anomaly_id": context["anomaly_id"],
        "severity": context["severity"],
        "parameters": action["parameters"],
        "expected_outcome": action["expected_outcome"]
    }

    # Execute action
    try:
        result = action_executors[action["type"]](action["parameters"])
        action_details["status"] = "success"
        action_details["result"] = result
    except Exception as e:
        action_details["status"] = "failed"
        action_details["error"] = str(e)

    # Sign action with ML-DSA-87
    action_hash = sha3_384(json.dumps(action_details, sort_keys=True))
    action_signature = ml_dsa_87_sign(
        private_key=healing_action_key,
        message=action_hash
    )

    action_details["action_hash"] = action_hash
    action_details["ml_dsa_signature"] = action_signature

    # Log to audit chain
    log_healing_action(action_details)

    return action_details
```

**Step 4: Outcome Verification**
```python
def verify_remediation_outcome(action_details, expected_outcome):
    """Verify remediation was successful"""

    # Wait for action to take effect
    time.sleep(5)

    # Collect new metrics
    new_metrics = collect_metrics()

    # Check if anomaly is resolved
    anomalies = detect_anomalies(engineer_features(new_metrics))

    if len(anomalies) == 0:
        return {
            "status": "resolved",
            "action_effective": True
        }
    elif len(anomalies) < previous_anomaly_count:
        return {
            "status": "partially_resolved",
            "action_effective": True,
            "remaining_anomalies": len(anomalies)
        }
    else:
        return {
            "status": "unresolved",
            "action_effective": False,
            "escalation_required": True
        }
```

### ML-DSA-87 Signed Healing Actions

**Healing Action Signature Structure**
```json
{
  "action_id": "uuid",
  "action_type": "string",
  "timestamp": "ISO8601",
  "anomaly": {
    "anomaly_id": "uuid",
    "type": "string",
    "severity": "critical|high|medium|low",
    "detection_models": ["string"],
    "confidence_scores": {}
  },
  "action": {
    "type": "string",
    "parameters": {},
    "expected_outcome": "string",
    "side_effects": []
  },
  "execution": {
    "status": "success|failed|partial",
    "result": {},
    "timestamp": "ISO8601",
    "execution_time_ms": "float"
  },
  "verification": {
    "outcome_verified": "boolean",
    "anomaly_resolved": "boolean",
    "escalation_required": "boolean"
  },
  "signature": {
    "action_hash": "base64url (SHA3-384)",
    "ml_dsa_signature": "base64url (ML-DSA-87)",
    "public_key_id": "uuid",
    "algorithm": "ML-DSA-87"
  }
}
```

## API Contract

### Endpoint: `/api/v1/selfhealing/anomalies`

**Request:**
```json
{
  "session_token": "base64url",
  "capability_token": "base64url",
  "filters": {
    "severity": ["critical", "high"],
    "time_range": {
      "start": "ISO8601",
      "end": "ISO8601"
    },
    "layers": [1, 2, 3, 4, 5, 6]
  }
}
```

**Response:**
```json
{
  "status": "success",
  "anomalies": [
    {
      "anomaly_id": "uuid",
      "detected_at": "ISO8601",
      "type": "brute_force_attack",
      "severity": "high",
      "confidence": 0.95,
      "affected_layers": [1, 2],
      "detection_models": ["IsolationForest", "LSTM"],
      "metrics": {},
      "remediation_status": "in_progress|resolved|escalated"
    }
  ],
  "total_count": "integer",
  "unresolved_count": "integer"
}
```

### Endpoint: `/api/v1/selfhealing/actions`

**Request:**
```json
{
  "session_token": "base64url",
  "capability_token": "base64url",
  "anomaly_id": "uuid (optional)",
  "status": "success|failed|in_progress"
}
```

**Response:**
```json
{
  "status": "success",
  "actions": [
    {
      "action_id": "uuid",
      "action_type": "block_ip_address",
      "timestamp": "ISO8601",
      "anomaly_id": "uuid",
      "execution_status": "success",
      "outcome_verified": true,
      "ml_dsa_signature": "base64url",
      "signature_verified": true
    }
  ],
  "total_count": "integer"
}
```

### Endpoint: `/api/v1/selfhealing/action/execute`

**Request (Manual Trigger):**
```json
{
  "session_token": "base64url",
  "admin_capability_token": "base64url",
  "action_type": "string",
  "parameters": {},
  "reason": "string"
}
```

**Response:**
```json
{
  "status": "executed",
  "action_id": "uuid",
  "action_type": "string",
  "execution_result": {},
  "ml_dsa_signature": "base64url",
  "timestamp": "ISO8601"
}
```

### Endpoint: `/api/v1/selfhealing/models/status`

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
  "models": [
    {
      "model_name": "IsolationForest",
      "version": "1.2.3",
      "last_trained": "ISO8601",
      "accuracy": 0.96,
      "false_positive_rate": 0.02,
      "samples_processed": 1000000,
      "model_hash": "base64url (SHA3-384)"
    },
    {
      "model_name": "LSTM",
      "version": "2.1.0",
      "last_trained": "ISO8601",
      "accuracy": 0.94,
      "mean_squared_error": 0.003,
      "samples_processed": 500000,
      "model_hash": "base64url (SHA3-384)"
    }
  ]
}
```

### Endpoint: `/api/v1/selfhealing/health`

**Request:**
```json
{
  "session_token": "base64url"
}
```

**Response:**
```json
{
  "status": "healthy",
  "components": {
    "metric_collection": "operational",
    "anomaly_detection": "operational",
    "remediation_engine": "operational",
    "ml_models": "operational"
  },
  "metrics": {
    "anomalies_detected_24h": 23,
    "actions_executed_24h": 18,
    "success_rate": 0.95,
    "avg_detection_latency_ms": 3200,
    "avg_remediation_latency_ms": 28000
  }
}
```

## Error Codes

| Code | Name | Description | Retry | Lockout |
|------|------|-------------|-------|---------|
| `HEAL-7001` | `ANOMALY_DETECTION_FAILED` | Anomaly detection pipeline failed | Yes (3x) | N/A |
| `HEAL-7002` | `MODEL_INFERENCE_FAILED` | ML model inference failed | Yes (2x) | N/A |
| `HEAL-7003` | `ACTION_VALIDATION_FAILED` | Remediation action validation failed | No | N/A |
| `HEAL-7004` | `ACTION_EXECUTION_FAILED` | Remediation action execution failed | Yes (1x) | N/A |
| `HEAL-7005` | `ACTION_SIGNATURE_FAILED` | ML-DSA-87 action signing failed | No | 900s |
| `HEAL-7006` | `OUTCOME_VERIFICATION_FAILED` | Could not verify remediation outcome | Yes (2x) | N/A |
| `HEAL-7007` | `ANOMALY_NOT_FOUND` | Anomaly ID not found | No | N/A |
| `HEAL-7008` | `INSUFFICIENT_PERMISSIONS` | Action requires higher privileges | No | N/A |
| `HEAL-7009` | `ACTION_RATE_LIMITED` | Too many actions in time window | No | 300s |
| `HEAL-7010` | `MODEL_NOT_TRAINED` | ML model not trained yet | No | N/A |
| `HEAL-7011` | `METRIC_COLLECTION_FAILED` | Failed to collect metrics from layer | Yes (5x) | N/A |
| `HEAL-7012` | `ESCALATION_REQUIRED` | Human intervention required | No | N/A |
| `HEAL-7013` | `SIDE_EFFECTS_TOO_SEVERE` | Action side effects unacceptable | No | N/A |
| `HEAL-7014` | `ACTION_CONFLICT` | Action conflicts with existing action | No | N/A |
| `HEAL-7015` | `ROLLBACK_FAILED` | Failed to rollback failed action | No | Immediate |

## Compliance Mapping

### NIST Standards
- **FIPS 204**: ML-DSA signatures for healing actions
- **SP 800-53 Rev. 5**:
  - **SI-4**: System Monitoring
    - Continuous monitoring across all layers
  - **IR-4**: Incident Handling
    - Automated incident response
  - **IR-5**: Incident Monitoring
    - Real-time anomaly detection
  - **SI-7**: Software, Firmware, and Information Integrity
    - ML-DSA-87 signed healing actions
- **NIST Cybersecurity Framework**:
  - DE.AE-1: Baseline of network operations established
  - DE.AE-2: Detected events analyzed
  - DE.AE-3: Event data aggregated and correlated
  - DE.CM-1: Network monitored
  - RS.AN-1: Notifications from detection systems investigated
  - RS.MI-2: Incidents mitigated
  - RS.MI-3: Newly identified vulnerabilities mitigated

### HIPAA Requirements
- **164.308(a)(1)(ii)(D)**: Information System Activity Review
  - Continuous monitoring of PHI access
  - Automated anomaly detection
- **164.308(a)(6)**: Security Incident Procedures
  - Automated incident response
  - Healing actions for security incidents
- **164.312(b)**: Audit Controls
  - ML-DSA-87 signed audit trail of healing actions

### SOC 2 Type II Controls
- **CC7.2**: System Monitoring
  - Continuous security monitoring
  - Automated threat detection
- **CC7.3**: Incident Response
  - Automated remediation
  - Escalation procedures
- **CC7.4**: Response to Anomalies
  - ML-based anomaly detection
  - Autonomous healing actions

### GDPR Compliance
- **Article 32**: Security of Processing
  - Ability to ensure ongoing confidentiality and integrity
  - Ability to restore availability after incident
- **Article 33**: Breach Notification
  - Automated breach detection
  - Incident logging and reporting

### ISO/IEC 27001:2022
- **A.12.6.1**: Management of Technical Vulnerabilities
  - Automated vulnerability remediation
- **A.16.1.4**: Assessment and Decision on Information Security Events
  - ML-based event assessment
- **A.16.1.5**: Response to Information Security Incidents
  - Automated incident response
- **A.17.2.1**: Availability of Information Processing Facilities
  - Self-healing for availability

## Implementation Notes

### Machine Learning Infrastructure
- **Training Pipeline**: Batch training every 24 hours with new data
- **Model Registry**: Versioned ML models with SHA3-384 hashes
- **A/B Testing**: Compare new models against production before deployment
- **Explainability**: SHAP values for model interpretability

### Performance Benchmarks
- **Metric Collection**: 10,000 events/second
- **Anomaly Detection**: <5 seconds end-to-end latency
- **Action Execution**: <30 seconds for automated actions
- **ML-DSA-87 Signing**: ~5ms per healing action
- **Model Inference**: <100ms per prediction

### Scalability
- **Distributed Processing**: Apache Kafka for metric streaming
- **Model Serving**: TensorFlow Serving for ML models
- **Horizontal Scaling**: Stateless detection workers
- **Data Storage**: Time-series database (InfluxDB/TimescaleDB)

### Monitoring and Alerting
- Self-healing system monitors itself (meta-monitoring)
- False positive tracking and feedback loop
- Model drift detection and retraining triggers
- Healing action effectiveness tracking

### Integration Points
- **All Layers**: Metric collection from every layer
- **Layer 8 (Orchestration)**: Coordinated healing across layers
- **SIEM Integration**: Export anomalies to external SIEM
- **Incident Response**: Escalation to human operators
- **Compliance Reporting**: Automated compliance dashboards
