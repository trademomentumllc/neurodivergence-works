# Layer 6: PHI Isolation Specification

## Purpose

Layer 6 provides specialized protection for Protected Health Information (PHI) through FHIR R4 compliance, HMAC-SHA3-384 message authentication, and strict HIPAA alignment. This layer implements healthcare-specific security controls, including clinical data isolation, patient consent management, and healthcare interoperability standards. It ensures that PHI is segregated, authenticated, and protected throughout its lifecycle with quantum-resistant cryptography.

## Algorithms

### Primary Algorithms
- **HMAC-SHA3-384**: Message authentication for FHIR resources
  - Key size: 384 bits (48 bytes)
  - Output size: 384 bits (48 bytes)
  - Security: 192-bit collision resistance, 384-bit preimage resistance

### Supporting Algorithms
- **ML-DSA-87** (FIPS 204): Digital signatures for consent forms and clinical documents
  - From Layer 1 (Identity) and Layer 5 (Database)
- **AES-256-GCM**: PHI field-level encryption (from Layer 4)
- **SHA3-512**: Patient identifier hashing and de-identification
- **PBKDF2-SHA256**: Legacy system password hashing (for interop)
  - Iterations: 100,000
  - Salt: 128 bits

## Security Strength

- **Message Authentication**: 192-bit collision resistance (HMAC-SHA3-384)
- **Quantum Resistance**: 256-bit (via ML-DSA-87 signatures)
- **PHI Encryption**: 256-bit (via AES-256-GCM from Layer 4)
- **De-identification**: 512-bit hash strength (SHA3-512)
- **Consent Validity**: Cryptographically verifiable with ML-DSA-87
- **Audit Retention**: 7 years minimum (configurable)

## FHIR R4 Compliance

### Supported FHIR Resources

#### Core Clinical Resources
```
1. Patient (demographics, identifiers)
2. Observation (vital signs, lab results)
3. Condition (diagnoses, problems)
4. Procedure (surgical procedures, treatments)
5. MedicationRequest (prescriptions)
6. MedicationStatement (medication history)
7. AllergyIntolerance (allergies, intolerances)
8. Immunization (vaccination records)
9. DiagnosticReport (lab reports, imaging)
10. DocumentReference (clinical documents, CDA)
```

#### Administrative Resources
```
11. Encounter (visits, appointments)
12. Practitioner (healthcare providers)
13. Organization (healthcare facilities)
14. Location (departments, rooms)
15. Coverage (insurance information)
16. Claim (billing claims)
```

#### Security Resources
```
17. Consent (patient consent for data sharing)
18. Provenance (data origin and transformation)
19. AuditEvent (access logs, HIPAA audit trail)
```

### FHIR Resource Security Extensions

Each FHIR resource is augmented with security metadata:

```json
{
  "resourceType": "Patient",
  "id": "patient-12345",
  "meta": {
    "versionId": "1",
    "lastUpdated": "2025-12-24T10:00:00Z",
    "security": [
      {
        "system": "http://terminology.hl7.org/CodeSystem/v3-Confidentiality",
        "code": "R",
        "display": "Restricted"
      }
    ],
    "tag": [
      {
        "system": "http://example.org/pqc-security",
        "code": "quantum-protected",
        "display": "Quantum-resistant encryption applied"
      }
    ]
  },
  "extension": [
    {
      "url": "http://example.org/fhir/StructureDefinition/hmac-authentication",
      "valueString": "HMAC-SHA3-384: base64url"
    },
    {
      "url": "http://example.org/fhir/StructureDefinition/ml-dsa-signature",
      "valueString": "ML-DSA-87: base64url"
    },
    {
      "url": "http://example.org/fhir/StructureDefinition/encryption-metadata",
      "extension": [
        {
          "url": "algorithm",
          "valueString": "AES-256-GCM"
        },
        {
          "url": "encrypted-fields",
          "valueString": "name,telecom,address,ssn"
        }
      ]
    }
  ],
  "identifier": [
    {
      "use": "official",
      "system": "http://hospital.example.org/patients",
      "value": "SHA3-512-hashed-mrn"
    }
  ],
  "name": [
    {
      "use": "official",
      "family": "AES-256-GCM-encrypted",
      "given": ["AES-256-GCM-encrypted"]
    }
  ]
}
```

### FHIR API Endpoints

**Base URL**: `/fhir/r4/`

#### Standard FHIR Operations
- `GET /fhir/r4/Patient/{id}` - Read patient resource
- `POST /fhir/r4/Patient` - Create patient resource
- `PUT /fhir/r4/Patient/{id}` - Update patient resource
- `DELETE /fhir/r4/Patient/{id}` - Delete patient resource
- `GET /fhir/r4/Patient?name=Smith` - Search patients
- `GET /fhir/r4/Patient/{id}/_history` - Get resource history
- `POST /fhir/r4/Bundle` - Batch/transaction operations

#### Custom PQC Security Operations
- `POST /fhir/r4/Patient/{id}/$sign` - Sign patient record with ML-DSA-87
- `POST /fhir/r4/Patient/{id}/$verify` - Verify record signatures
- `POST /fhir/r4/Patient/{id}/$encrypt` - Re-encrypt with new keys
- `GET /fhir/r4/Patient/{id}/$consent-status` - Check consent status
- `POST /fhir/r4/Patient/{id}/$de-identify` - Generate de-identified resource

## HMAC-SHA3-384 Message Authentication

### HMAC Key Derivation

```python
# Derive HMAC key per patient
patient_hmac_key = HKDF-Expand(
    PRK=master_hmac_key,  # From Layer 4 key hierarchy
    info="FHIR-HMAC" || patient_id || "v1",
    length=48  # 384 bits
)

# Derive HMAC key per resource type
resource_hmac_key = HKDF-Expand(
    PRK=patient_hmac_key,
    info=resource_type || resource_id,
    length=48
)
```

### FHIR Resource Authentication

**1. Canonicalization**
```python
def canonicalize_fhir_resource(resource):
    """Convert FHIR JSON to canonical form"""
    # Remove meta fields (except security labels)
    cleaned = remove_metadata(resource)

    # Sort all object keys alphabetically
    sorted_resource = sort_keys_recursive(cleaned)

    # Convert to compact JSON
    canonical = json.dumps(
        sorted_resource,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=True
    )

    return canonical
```

**2. HMAC Computation**
```python
def compute_fhir_hmac(resource, hmac_key):
    """Compute HMAC-SHA3-384 for FHIR resource"""
    # Canonicalize resource
    canonical = canonicalize_fhir_resource(resource)

    # Compute HMAC
    hmac = HMAC-SHA3-384(
        key=hmac_key,
        message=canonical.encode('utf-8')
    )

    return base64url_encode(hmac)
```

**3. HMAC Verification**
```python
def verify_fhir_hmac(resource, stored_hmac, hmac_key):
    """Verify FHIR resource HMAC"""
    # Recompute HMAC
    computed_hmac = compute_fhir_hmac(resource, hmac_key)

    # Constant-time comparison
    return constant_time_compare(computed_hmac, stored_hmac)
```

### HMAC Storage in FHIR

```json
{
  "resourceType": "Patient",
  "id": "patient-12345",
  "extension": [
    {
      "url": "http://example.org/fhir/StructureDefinition/hmac-authentication",
      "extension": [
        {
          "url": "algorithm",
          "valueString": "HMAC-SHA3-384"
        },
        {
          "url": "hmac",
          "valueString": "base64url-encoded-hmac"
        },
        {
          "url": "key-id",
          "valueString": "uuid-of-hmac-key"
        },
        {
          "url": "timestamp",
          "valueDateTime": "2025-12-24T10:00:00Z"
        }
      ]
    }
  ]
}
```

## Patient Consent Management

### Consent Resource Structure

```json
{
  "resourceType": "Consent",
  "id": "consent-12345",
  "status": "active",
  "scope": {
    "coding": [
      {
        "system": "http://terminology.hl7.org/CodeSystem/consentscope",
        "code": "patient-privacy"
      }
    ]
  },
  "category": [
    {
      "coding": [
        {
          "system": "http://loinc.org",
          "code": "59284-0",
          "display": "Patient Consent"
        }
      ]
    }
  ],
  "patient": {
    "reference": "Patient/patient-12345"
  },
  "dateTime": "2025-12-24T10:00:00Z",
  "performer": [
    {
      "reference": "Patient/patient-12345"
    }
  ],
  "policy": [
    {
      "uri": "http://example.org/privacy-policy"
    }
  ],
  "provision": {
    "type": "permit",
    "period": {
      "start": "2025-12-24T00:00:00Z",
      "end": "2026-12-24T00:00:00Z"
    },
    "actor": [
      {
        "role": {
          "coding": [
            {
              "system": "http://terminology.hl7.org/CodeSystem/v3-ParticipationType",
              "code": "PRCP",
              "display": "Primary Care Provider"
            }
          ]
        },
        "reference": {
          "reference": "Practitioner/practitioner-67890"
        }
      }
    ],
    "action": [
      {
        "coding": [
          {
            "system": "http://terminology.hl7.org/CodeSystem/consentaction",
            "code": "access"
          }
        ]
      }
    ],
    "data": [
      {
        "meaning": "related",
        "reference": {
          "reference": "Patient/patient-12345/*"
        }
      }
    ]
  },
  "extension": [
    {
      "url": "http://example.org/fhir/StructureDefinition/consent-signature",
      "extension": [
        {
          "url": "algorithm",
          "valueString": "ML-DSA-87"
        },
        {
          "url": "signature",
          "valueString": "base64url-encoded-ml-dsa-87-signature"
        },
        {
          "url": "signer-public-key",
          "valueString": "base64url-encoded-public-key"
        },
        {
          "url": "timestamp",
          "valueDateTime": "2025-12-24T10:00:00Z"
        }
      ]
    }
  ]
}
```

### Consent Enforcement

```python
def check_consent(patient_id, practitioner_id, resource_type, action):
    """Check if practitioner has consent to access patient data"""

    # Retrieve active consent resources
    consents = fetch_active_consents(patient_id)

    for consent in consents:
        # Verify ML-DSA-87 signature on consent
        if not verify_consent_signature(consent):
            continue  # Skip invalid consent

        # Check if consent covers this access
        if consent_permits_access(
            consent,
            practitioner_id,
            resource_type,
            action
        ):
            # Log consent-based access
            log_consent_access(
                patient_id,
                practitioner_id,
                resource_type,
                action,
                consent.id
            )
            return True

    # No valid consent found
    return False
```

## De-identification and Anonymization

### De-identification Levels

**Level 1: Limited Dataset (HIPAA Safe Harbor)**
- Remove 18 HIPAA identifiers
- Retain dates (year only)
- Geographic granularity: state level

**Level 2: Expert Determination**
- Statistical de-identification
- K-anonymity (k ≥ 5)
- L-diversity for sensitive attributes

**Level 3: Full Anonymization**
- No re-identification possible
- Synthetic data generation
- Differential privacy (ε ≤ 1.0)

### De-identification Process

```python
def deidentify_patient_resource(patient, level="safe-harbor"):
    """De-identify patient resource per HIPAA Safe Harbor"""

    deidentified = copy.deepcopy(patient)

    if level == "safe-harbor":
        # 1. Names: Hash with SHA3-512
        for name in deidentified.get("name", []):
            name["family"] = sha3_512_hash(name["family"])
            name["given"] = [sha3_512_hash(g) for g in name.get("given", [])]

        # 2. Geographic subdivisions smaller than state: Remove
        for address in deidentified.get("address", []):
            address.pop("line", None)
            address.pop("city", None)
            address.pop("postalCode", None)
            # Keep state only

        # 3. Dates: Year only
        if "birthDate" in deidentified:
            birth_year = deidentified["birthDate"][:4]
            deidentified["birthDate"] = f"{birth_year}-01-01"

        # 4. Telephone numbers: Remove
        deidentified.pop("telecom", None)

        # 5. Email addresses: Remove
        # (Already removed in telecom)

        # 6. SSN: Remove
        deidentified["identifier"] = [
            id for id in deidentified.get("identifier", [])
            if id.get("system") != "http://hl7.org/fhir/sid/us-ssn"
        ]

        # 7. MRN: Hash with SHA3-512
        for identifier in deidentified.get("identifier", []):
            identifier["value"] = sha3_512_hash(identifier["value"])

        # 8-18: Remove other identifiers per Safe Harbor

    # Add de-identification provenance
    deidentified["meta"]["tag"].append({
        "system": "http://terminology.hl7.org/CodeSystem/v3-ObservationValue",
        "code": "MASKED",
        "display": "De-identified per HIPAA Safe Harbor"
    })

    return deidentified
```

## API Contract

### Endpoint: `/fhir/r4/Patient/{id}`

**Request (GET with Authentication):**
```
GET /fhir/r4/Patient/patient-12345
Authorization: Bearer {session_token}
X-Capability-Token: {capability_token}
X-Consent-Check: enforce
```

**Response (Success with Security Metadata):**
```json
{
  "resourceType": "Patient",
  "id": "patient-12345",
  "meta": {
    "security": [
      {
        "system": "http://terminology.hl7.org/CodeSystem/v3-Confidentiality",
        "code": "R",
        "display": "Restricted"
      }
    ]
  },
  "extension": [
    {
      "url": "http://example.org/fhir/StructureDefinition/hmac-authentication",
      "extension": [
        {
          "url": "algorithm",
          "valueString": "HMAC-SHA3-384"
        },
        {
          "url": "hmac",
          "valueString": "base64url"
        },
        {
          "url": "verified",
          "valueBoolean": true
        }
      ]
    }
  ],
  "identifier": [
    {
      "use": "official",
      "system": "http://hospital.example.org/patients",
      "value": "MRN-12345"
    }
  ],
  "name": [
    {
      "use": "official",
      "family": "Smith",
      "given": ["John"]
    }
  ],
  "birthDate": "1980-01-01"
}
```

### Endpoint: `/fhir/r4/Patient/{id}/$consent-status`

**Request:**
```
POST /fhir/r4/Patient/patient-12345/$consent-status
Content-Type: application/fhir+json
Authorization: Bearer {session_token}

{
  "resourceType": "Parameters",
  "parameter": [
    {
      "name": "practitioner",
      "valueReference": {
        "reference": "Practitioner/practitioner-67890"
      }
    },
    {
      "name": "action",
      "valueCode": "access"
    }
  ]
}
```

**Response (Consent Granted):**
```json
{
  "resourceType": "Parameters",
  "parameter": [
    {
      "name": "consent-status",
      "valueCode": "granted"
    },
    {
      "name": "consent-reference",
      "valueReference": {
        "reference": "Consent/consent-12345"
      }
    },
    {
      "name": "consent-signature-verified",
      "valueBoolean": true
    },
    {
      "name": "expiry",
      "valueDateTime": "2026-12-24T00:00:00Z"
    }
  ]
}
```

### Endpoint: `/fhir/r4/Patient/{id}/$de-identify`

**Request:**
```
POST /fhir/r4/Patient/patient-12345/$de-identify
Content-Type: application/fhir+json
Authorization: Bearer {session_token}

{
  "resourceType": "Parameters",
  "parameter": [
    {
      "name": "level",
      "valueCode": "safe-harbor"
    }
  ]
}
```

**Response:**
```json
{
  "resourceType": "Patient",
  "id": "deidentified-abc123",
  "meta": {
    "tag": [
      {
        "system": "http://terminology.hl7.org/CodeSystem/v3-ObservationValue",
        "code": "MASKED",
        "display": "De-identified per HIPAA Safe Harbor"
      }
    ]
  },
  "identifier": [
    {
      "system": "urn:oid:deidentified",
      "value": "SHA3-512-hash"
    }
  ],
  "name": [
    {
      "family": "SHA3-512-hash",
      "given": ["SHA3-512-hash"]
    }
  ],
  "address": [
    {
      "state": "CA"
    }
  ],
  "birthDate": "1980-01-01"
}
```

## Error Codes

| Code | Name | Description | Retry | Lockout |
|------|------|-------------|-------|---------|
| `PHI-6001` | `CONSENT_REQUIRED` | Patient consent required for access | No | N/A |
| `PHI-6002` | `CONSENT_DENIED` | Patient explicitly denied consent | No | N/A |
| `PHI-6003` | `CONSENT_EXPIRED` | Patient consent has expired | No | N/A |
| `PHI-6004` | `CONSENT_SIGNATURE_INVALID` | ML-DSA-87 consent signature invalid | No | 900s |
| `PHI-6005` | `HMAC_VERIFICATION_FAILED` | FHIR resource HMAC invalid | No | 900s |
| `PHI-6006` | `PHI_ENCRYPTION_REQUIRED` | PHI fields must be encrypted | No | N/A |
| `PHI-6007` | `FHIR_VALIDATION_FAILED` | FHIR resource validation failed | Yes (1x) | N/A |
| `PHI-6008` | `DEIDENTIFICATION_FAILED` | De-identification process failed | Yes (1x) | N/A |
| `PHI-6009` | `REIDENTIFICATION_RISK_HIGH` | De-identified data has high re-id risk | No | N/A |
| `PHI-6010` | `MINIMUM_NECESSARY_VIOLATED` | Access exceeds minimum necessary | No | N/A |
| `PHI-6011` | `BREAK_GLASS_REQUIRED` | Emergency access protocol required | No | N/A |
| `PHI-6012` | `AUDIT_LOG_REQUIRED` | PHI access must be audited | No | Immediate |
| `PHI-6013` | `UNSUPPORTED_FHIR_VERSION` | FHIR version not supported (require R4) | No | N/A |
| `PHI-6014` | `RESOURCE_TYPE_NOT_ALLOWED` | FHIR resource type not permitted | No | N/A |
| `PHI-6015` | `PATIENT_NOT_FOUND` | Patient resource does not exist | No | N/A |
| `PHI-6016` | `CONSENT_CONFLICT` | Multiple conflicting consents | No | N/A |
| `PHI-6017` | `PROVIDER_NOT_AUTHORIZED` | Healthcare provider not authorized | No | N/A |
| `PHI-6018` | `TREATMENT_RELATIONSHIP_REQUIRED` | No established treatment relationship | No | N/A |

## Compliance Mapping

### HIPAA Requirements

#### Privacy Rule (45 CFR 164.500)
- **164.502(a)**: Minimum Necessary
  - Consent provisions limit access to minimum necessary
  - De-identification for secondary use
- **164.508**: Authorizations
  - ML-DSA-87 signed consent resources
  - Cryptographic proof of authorization
- **164.514(a)**: De-identification
  - Safe Harbor method implemented
  - Expert determination support
- **164.514(b)**: Safe Harbor De-identification
  - All 18 identifiers removed or hashed
- **164.514(e)**: Limited Data Set
  - Partial de-identification option

#### Security Rule (45 CFR 164.300)
- **164.308(a)(3)**: Workforce Security
  - FHIR Consent resources enforce authorization
- **164.308(a)(4)**: Information Access Management
  - Minimum necessary via consent provisions
  - Role-based access integrated with Layer 2
- **164.312(a)(1)**: Access Control
  - Unique user identification from Layer 1
  - FHIR consent-based authorization
- **164.312(c)(1)**: Integrity Controls
  - HMAC-SHA3-384 for resource authentication
  - ML-DSA-87 signatures for consent integrity
- **164.312(e)(1)**: Transmission Security
  - PHI encrypted in transit (Layer 3 TLS 1.3)
- **164.312(e)(2)(ii)**: Encryption
  - AES-256-GCM field-level encryption (Layer 4)

### FHIR Specification Compliance
- **FHIR R4 (v4.0.1)**:
  - Full support for core clinical resources
  - SMART on FHIR for authorization
  - FHIR Consent resource for patient consent
  - FHIR Provenance for data lineage
  - FHIR AuditEvent for access logging
- **FHIR Security**:
  - Meta.security labels for confidentiality
  - Extensions for PQC signatures and HMACs
  - SMART App Launch for OAuth 2.0 integration

### SOC 2 Type II Controls
- **CC6.1**: PHI Access Controls
  - Consent-based access enforcement
  - HMAC authentication for data integrity
- **CC6.7**: PHI Encryption
  - Field-level encryption for sensitive data
  - Quantum-resistant protection

### GDPR Compliance
- **Article 6**: Lawfulness of Processing
  - Consent resources provide legal basis
  - ML-DSA-87 signatures prove consent
- **Article 7**: Conditions for Consent
  - FHIR Consent resources track consent
  - Cryptographic proof of consent
- **Article 9**: Processing of Special Categories
  - Health data encryption and authentication
- **Article 17**: Right to Erasure
  - De-identification and cryptographic erasure
- **Article 20**: Right to Data Portability
  - FHIR format enables portability

### 21 CFR Part 11 (FDA)
- **11.10(a)**: System Access Validation
  - Consent verification for clinical trial data
- **11.50**: Signature Manifestations
  - ML-DSA-87 signatures on consent forms
- **11.70**: Signature/Record Linking
  - Consent signatures linked to patient records

### HL7 Da Vinci Project
- **Coverage Requirements Discovery (CRD)**
- **Prior Authorization Support (PAS)**
- **Clinical Data Exchange (CDex)**
- **Payer Data Exchange (PDex)**

## Implementation Notes

### FHIR Server Integration
- **HAPI FHIR**: Java-based FHIR server with custom interceptors
- **FHIR Works on AWS**: Cloud-native FHIR server
- **Azure API for FHIR**: Managed FHIR service
- **Google Cloud Healthcare API**: GCP FHIR implementation

### Performance Optimization
- **HMAC Caching**: Cache computed HMACs for read-heavy workloads
- **Batch Verification**: Verify multiple HMACs in parallel
- **Consent Caching**: Cache active consents per patient (60s TTL)
- **Indexing**: Index on patient ID, resource type, security labels

### Performance Benchmarks
- **HMAC-SHA3-384 Computation**: ~0.5ms per resource
- **HMAC-SHA3-384 Verification**: ~0.5ms per resource
- **ML-DSA-87 Consent Signature**: ~5ms per consent
- **ML-DSA-87 Consent Verification**: ~3ms per consent
- **De-identification**: ~10ms per patient resource
- **FHIR API Response Time**: <100ms (including crypto operations)

### Interoperability
- **HL7 CDA**: Convert to FHIR DocumentReference
- **HL7 v2**: Convert ADT messages to FHIR Patient
- **DICOM**: Link imaging studies to FHIR DiagnosticReport
- **X12**: Convert claims to FHIR Claim resources

### Monitoring and Auditing
- All PHI access logged to FHIR AuditEvent resources
- Consent checks logged with outcome
- HMAC verification failures trigger alerts
- De-identification operations audited
- Break-glass access immediately escalated

### Integration Points
- **Layer 1 (Identity)**: Healthcare provider authentication
- **Layer 2 (Authorization)**: RBAC for clinical roles
- **Layer 3 (Network)**: TLS 1.3 for FHIR API
- **Layer 4 (Encryption)**: Field-level PHI encryption
- **Layer 5 (Database)**: RLS policies for PHI isolation
- **Layer 7 (Self-Healing)**: Anomaly detection for PHI access patterns
- **Layer 8 (Orchestration)**: Coordinated consent signature key rotation
