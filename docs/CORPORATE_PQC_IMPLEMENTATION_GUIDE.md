# Corporate Post-Quantum Cryptography Implementation Framework

## Enterprise Q-Day Readiness Guide

---

## Executive Summary

### The Quantum Threat Equation

```
X + Y > Z ⟹ Immediate Migration Required

Where:
  X = Data confidentiality shelf-life (years)
  Y = System migration duration (years)
  Z = Threat horizon to Q-Day (years ≤ 10)
```

**Critical Finding:** For organizations with >5 year data retention and typical 5-7 year migration timelines, migration should have already begun. The math doesn't lie:

```
Financial Services Example:
(10 years retention + 5 years migration + 2 years HNDL exposure) / 3 years to state Q-Day
= 17 / 3 = 5.67 Urgency Score

Urgency > 1.0 = CRITICAL
```

### Regulatory Hard Deadlines (NIST IR 8547, November 2024)

| Deadline | Requirement | Impact |
|----------|-------------|--------|
| **2030** | RSA, ECDSA, EdDSA, DH, ECDH **DEPRECATED** | No new implementations allowed |
| **2035** | All quantum-vulnerable algorithms **DISALLOWED** | Complete migration required |
| **2028** | State actor quantum capability (estimated) | Harvest-now-decrypt-later threat realized |

---

## Enterprise Network Architecture: PQC Migration Zones

```
╔══════════════════════════════════════════════════════════════════════════════════════╗
║                    CORPORATE PQC MIGRATION ARCHITECTURE                               ║
╚══════════════════════════════════════════════════════════════════════════════════════╝

                                    INTERNET
                                        │
                    ┌───────────────────┴───────────────────┐
                    │         ZONE 1: PERIMETER              │
                    │    [PRIORITY 1 - 2025-2026]           │
                    │                                        │
                    │  ┌─────────────────────────────────┐  │
                    │  │    CDN/WAF (Cloudflare Edge)     │  │
                    │  │    ✓ X25519MLKEM768 enabled      │  │
                    │  │    ✓ Hybrid TLS 1.3              │  │
                    │  └─────────────────────────────────┘  │
                    │                 │                      │
                    │  ┌─────────────┴─────────────┐        │
                    │  │    Load Balancers (F5/NGINX)│        │
                    │  │    ⚠ Buffer size upgrade    │        │
                    │  │    ⚠ PQC handshake support  │        │
                    │  └─────────────┬─────────────┘        │
                    │                │                      │
                    │  ┌─────────────┴─────────────┐        │
                    │  │    VPN Concentrators       │        │
                    │  │    → WireGuard + Hybrid PSK│        │
                    │  │    → OpenVPN + ML-KEM      │        │
                    │  └───────────────────────────┘        │
                    └───────────────────┬───────────────────┘
                                        │
                    ┌───────────────────┴───────────────────┐
                    │           ZONE 2: DMZ                  │
                    │    [PRIORITY 1-2 - 2025-2028]         │
                    │                                        │
                    │  ┌─────────────┐   ┌─────────────┐    │
                    │  │ API Gateway │   │ Web Servers │    │
                    │  │ (Kong/Envoy)│   │ (NGINX)     │    │
                    │  │             │   │             │    │
                    │  │ TLS 1.3     │   │ TLS 1.3     │    │
                    │  │ Hybrid KEM  │   │ Hybrid KEM  │    │
                    │  └──────┬──────┘   └──────┬──────┘    │
                    │         │                 │            │
                    │         └────────┬────────┘            │
                    │                  │                     │
                    │  ┌───────────────┴───────────────┐    │
                    │  │   Reverse Proxy / mTLS        │    │
                    │  │   Hybrid certificates         │    │
                    │  └───────────────┬───────────────┘    │
                    └──────────────────┼────────────────────┘
                                       │
         ┌─────────────────────────────┼─────────────────────────────┐
         │                             │                             │
         │              ZONE 3: INTERNAL NETWORK                     │
         │              [PRIORITY 2-3 - 2026-2030]                   │
         │                             │                             │
         │    ┌────────────────────────┼────────────────────────┐   │
         │    │                        │                        │   │
         │    ▼                        ▼                        ▼   │
         │ ┌──────────┐         ┌──────────────┐         ┌────────┐│
         │ │App Servers│         │Message Queue │         │  IAM   ││
         │ │(.NET/Java)│         │(Kafka/RabbitMQ)        │(AD/LDAP)│
         │ │          │         │              │         │        ││
         │ │OpenSSL   │         │TLS Internal  │         │Kerberos││
         │ │3.4+ OQS  │         │Hybrid certs  │         │→ PQC   ││
         │ └────┬─────┘         └──────┬───────┘         └───┬────┘│
         │      │                      │                     │     │
         │      └──────────────────────┼─────────────────────┘     │
         │                             │                           │
         │    ┌────────────────────────┼────────────────────────┐  │
         │    │                        │                        │  │
         │    ▼                        ▼                        ▼  │
         │ ┌──────────┐         ┌──────────────┐         ┌────────┐│
         │ │Databases │         │   HSM Cluster │         │ Email  ││
         │ │(SQL/NoSQL)         │               │         │Exchange││
         │ │          │         │ Thales Luna   │         │        ││
         │ │TDE→PQC   │         │ ML-KEM/ML-DSA │         │S/MIME  ││
         │ │AES-256   │         │ FIPS 140-3    │         │PQC certs│
         │ └──────────┘         └───────────────┘         └────────┘│
         │                                                          │
         └──────────────────────────────────────────────────────────┘
                                       │
                    ┌──────────────────┴──────────────────┐
                    │     ZONE 4: CERTIFICATE AUTHORITY   │
                    │     [PRIORITY 1 - 2025]             │
                    │                                      │
                    │  ┌────────────────────────────────┐  │
                    │  │        Root CA (Offline)        │  │
                    │  │                                 │  │
                    │  │  ┌─────────────────────────┐   │  │
                    │  │  │  Classical: ECDSA P-384 │   │  │
                    │  │  │  PQC: ML-DSA-87 (2026+) │   │  │
                    │  │  │  Hybrid: Both combined  │   │  │
                    │  │  └─────────────────────────┘   │  │
                    │  │              │                  │  │
                    │  │              ▼                  │  │
                    │  │  ┌─────────────────────────┐   │  │
                    │  │  │   Issuing CA (Online)   │   │  │
                    │  │  │   HSM-backed keys       │   │  │
                    │  │  │   Hybrid certificates   │   │  │
                    │  │  └─────────────────────────┘   │  │
                    │  └────────────────────────────────┘  │
                    └──────────────────────────────────────┘
                                       │
                    ┌──────────────────┴──────────────────┐
                    │      ZONE 5: CLOUD SERVICES         │
                    │      [PRIORITY 2 - 2026-2029]       │
                    │                                      │
                    │  ┌─────────┐  ┌─────────┐  ┌─────────┐
                    │  │   AWS   │  │  Azure  │  │   GCP   │
                    │  │         │  │         │  │         │
                    │  │KMS→PQC  │  │KeyVault │  │CloudHSM │
                    │  │Transfer │  │→PQC     │  │→PQC     │
                    │  │Family   │  │         │  │         │
                    │  │hybrid SSH  │         │  │         │
                    │  └─────────┘  └─────────┘  └─────────┘
                    │                                      │
                    │  ┌────────────────────────────────┐  │
                    │  │    SaaS Dependencies           │  │
                    │  │    (Vendor PQC Roadmap Req'd)  │  │
                    │  └────────────────────────────────┘  │
                    └──────────────────────────────────────┘

╔══════════════════════════════════════════════════════════════════════════════════════╗
║  LEGEND:                                                                              ║
║  ✓ = PQC-ready now        ⚠ = Upgrade required        → = Migration path             ║
║  TLS 1.3 Hybrid = X25519MLKEM768 (Chrome 124+, Cloudflare production)                ║
║  HSM = Hardware Security Module with FIPS 140-2/3 validation                          ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
```

---

## Phase 1: Cryptographic Discovery & Inventory

### The CBOM Imperative

**Straight Talk:** You can't migrate what you can't see. The #1 failure mode for PQC migration is organizations discovering quantum-vulnerable cryptography in production systems *after* they thought migration was complete.

**Industry Jargon:** Cryptographic Bill of Materials (CBOM) extends SBOM (Software Bill of Materials) per CycloneDX 1.6 specification (OWASP/IBM collaboration). CISA mandates annual CBOM reporting for federal agencies.

### Discovery Scope (Five Pillars)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    CRYPTOGRAPHIC DISCOVERY PILLARS                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                 │
│  │  EXTERNAL   │  │  INTERNAL   │  │  IT ASSETS  │                 │
│  │  NETWORK    │  │  NETWORK    │  │             │                 │
│  │             │  │             │  │             │                 │
│  │ • TLS       │  │ • Private   │  │ • Servers   │                 │
│  │   endpoints │  │   CAs       │  │ • Workstns  │                 │
│  │ • Public    │  │ • Internal  │  │ • Network   │                 │
│  │   certs     │  │   TLS       │  │   appliances│                 │
│  │ • DNS/DNSSEC│  │ • SSH keys  │  │ • Firewalls │                 │
│  │             │  │ • VPN       │  │ • LBs       │                 │
│  └─────────────┘  └─────────────┘  └─────────────┘                 │
│                                                                     │
│  ┌─────────────────────────┐  ┌─────────────────────────┐          │
│  │       DATABASES         │  │          CODE           │          │
│  │                         │  │                         │          │
│  │ • Encrypted columns     │  │ • Embedded crypto       │          │
│  │ • TDE (Transparent      │  │ • Libraries (OpenSSL,   │          │
│  │   Data Encryption)      │  │   BouncyCastle, WolfSSL)│          │
│  │ • Backup encryption     │  │ • API crypto calls      │          │
│  │ • Connection strings    │  │ • Hardcoded keys        │          │
│  └─────────────────────────┘  └─────────────────────────┘          │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Discovery Tool Landscape

| Vendor | Tool | Capabilities | Cost Range |
|--------|------|--------------|------------|
| **IBM** | CBOMkit | Sonar plugin, container scanning, CBOM viewer | Open source |
| **ReversingLabs** | Spectra Assure | Automated CBOM, risk scoring, supply chain | $50K-200K/yr |
| **QuSecure** | QuProtect R3 | End-to-end discovery, remediation, reporting | $100K-500K/yr |
| **QryptoCyber** | Crypto Discovery | Five-pillar discovery, prioritization | $75K-300K/yr |

### Mathematical Model: Discovery Confidence

```
Discovery_Confidence = Σ(Coverage_i × Accuracy_i × Completeness_i) / n

Where:
  Coverage_i    = % of infrastructure scanned in pillar i (0.0-1.0)
  Accuracy_i    = Detection accuracy for pillar i (0.0-1.0)
  Completeness_i = Depth of metadata captured (0.0-1.0)
  n             = Number of pillars (5)

Target: Discovery_Confidence ≥ 0.85 before proceeding to Phase 2
```

---

## Phase 2: Risk Assessment & Prioritization

### Priority Tiering Framework

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        PQC MIGRATION PRIORITY MATRIX                            │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  TIER 1 (2025-2026)                    TIER 2 (2026-2028)                       │
│  ━━━━━━━━━━━━━━━━━━                    ━━━━━━━━━━━━━━━━━━                       │
│  • Internet-facing TLS                 • Internal enterprise apps              │
│  • Customer portals                    • Database encryption                   │
│  • Root CAs                            • Email S/MIME                          │
│  • Code signing                        • Authentication systems                │
│  • VPN gateways                        • IoT (where feasible)                  │
│                                                                                 │
│  TIER 3 (2028-2030)                    TIER 4 (2030-2035)                       │
│  ━━━━━━━━━━━━━━━━━━                    ━━━━━━━━━━━━━━━━━━                       │
│  • Internal services                   • Legacy systems (limited agility)      │
│  • Development environments            • Air-gapped networks                   │
│  • Short-lived data (<5yr)             • Systems scheduled for decommission    │
│                                                                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│  PRIORITY SCORE = Σ(Weight_i × Factor_i) × Exposure_Multiplier                  │
│                                                                                 │
│  Weights:                              Exposure Multipliers:                    │
│    Data Sensitivity:    0.25             Internet-facing: 2.0                   │
│    Retention Period:    0.25             DMZ:             1.7                   │
│    System Criticality:  0.20             Internal:        1.3                   │
│    Crypto-Agility:      0.15             Air-gapped:      1.0                   │
│    Vendor Dependency:   0.15                                                    │
│                                                                                 │
│  Score ≥ 80: TIER 1 | 60-79: TIER 2 | 40-59: TIER 3 | <40: TIER 4              │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Phase 3: Infrastructure Preparation

### HSM Upgrade Path

**Straight Talk:** Most modern HSMs support PQC via firmware updates—you probably don't need to replace hardware. But you DO need to verify firmware versions and plan upgrade windows.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          HSM PQC READINESS STATUS                               │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  Vendor         Model                  PQC Algorithms      FIPS      Cost      │
│  ─────────────  ─────────────────────  ──────────────────  ────────  ─────     │
│  Thales         Luna Network HSM 7     ML-KEM, ML-DSA,     140-3     $50K      │
│                                        SLH-DSA             Level 3             │
│                                                                                 │
│  Utimaco        u.trust GP Se-Series   ML-KEM, ML-DSA,     140-2     $45K      │
│                                        XMSS, LMS           Level 4             │
│                                                                                 │
│  Entrust        nShield HSM            ML-KEM, ML-DSA      140-2     $55K      │
│                                                            Level 3             │
│                                                                                 │
│  Securosys      Primus CyberVault X2   ML-KEM-768/1024,    140-2     $60K      │
│                                        ML-DSA-65/87        Level 3             │
│                                                                                 │
│  Eviden (Atos)  Trustway Proteccio     ML-KEM, ML-DSA,     ANSSI     $70K      │
│                                        SLH-DSA             Highest             │
│                                                                                 │
│  ⚠ NOTE: All vendors support HYBRID operations (classical + PQC simultaneous)  │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### TLS 1.3 Hybrid Configuration

**Industry Jargon:** X25519MLKEM768 (codepoint 0x11EC) combines classical X25519 ECDH with ML-KEM-768 post-quantum KEM. Both must be broken to compromise the session—defense in depth.

```nginx
# NGINX TLS 1.3 Hybrid PQC Configuration
# Requires: OpenSSL 3.4+ with oqs-provider

ssl_protocols TLSv1.3;

# Hybrid Key Exchange (Classical + PQC)
# X25519MLKEM768 = X25519 (classical) + ML-KEM-768 (post-quantum)
ssl_ecdh_curve X25519MLKEM768:X25519:secp384r1;

# Cipher Suites (TLS 1.3 only)
ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;

# Certificate Configuration
ssl_certificate /etc/nginx/ssl/hybrid_cert.pem;
ssl_certificate_key /etc/nginx/ssl/hybrid_key.pem;

# Buffer sizes for larger PQC handshakes (critical!)
ssl_buffer_size 16k;
proxy_buffer_size 16k;
```

### Load Balancer Considerations

**⚠ WARNING:** Many enterprise load balancers have hard limits on TLS record sizes that will DROP hybrid PQC handshakes silently. Test before production deployment.

| Component | Issue | Remediation |
|-----------|-------|-------------|
| F5 BIG-IP | Default record size limits | Increase `ssl.maxrecordsize` |
| AWS ALB | May fragment hybrid handshakes | Enable jumbo frames, use NLB for TCP passthrough |
| HAProxy | Older versions drop large ClientHello | Upgrade to 2.8+, increase `tune.ssl.maxrecord` |
| Envoy | Default buffer sizing | Configure `max_connection_pools`, increase buffers |

---

## Phase 4: Vendor & Dependency Management

### Vendor Assessment Questionnaire

**Questions every vendor must answer:**

1. **PQC Roadmap:** When will ML-KEM/ML-DSA be supported?
2. **Hybrid Support:** Can classical + PQC run simultaneously during migration?
3. **Backward Compatibility:** How are legacy clients handled?
4. **Certification Status:** FIPS 140-3 with PQC? Common Criteria?
5. **Migration Tools:** What discovery/testing tools are provided?
6. **Support Timeline:** When will classical-only be deprecated/end-of-life?

### Cloud Provider Status (December 2024)

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      CLOUD PROVIDER PQC READINESS                               │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  Provider    Service              Status            Notes                       │
│  ──────────  ─────────────────    ────────────────  ─────────────────────       │
│  AWS         Transfer Family      ✓ Hybrid SSH      ML-KEM + X25519             │
│              KMS                  ⚠ Evaluating      PQC key types TBD           │
│              CloudHSM             ⚠ Roadmap 2025    Firmware update path        │
│                                                                                 │
│  Azure       Key Vault            ⚠ Evaluating      PQC algorithms planned      │
│              TLS Endpoints        ⚠ Roadmap 2025    Hybrid support TBD          │
│                                                                                 │
│  GCP         Cloud HSM            ⚠ Roadmap 2025    Following NIST timeline     │
│              TLS                  ⚠ Evaluating      Hybrid support planned      │
│                                                                                 │
│  Cloudflare  Edge TLS             ✓ PRODUCTION      38% of traffic (Mar 2025)   │
│              Origin TLS           ✓ Available       Hybrid edge-to-origin       │
│                                                                                 │
│  ✓ = Available now    ⚠ = In development/roadmap                                │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Phase 5: Pilot Deployment & Testing

### Test Matrix

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          PQC PILOT TEST MATRIX                                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  Test Category              Metrics                        Pass Criteria        │
│  ───────────────────────    ─────────────────────────────  ─────────────────    │
│  TLS Handshake Latency      Mean, P50, P95, P99            <10% regression      │
│  Key Generation Time        ML-KEM-768 keygen/s            >1000 ops/sec        │
│  Signature Performance      ML-DSA-65 sign+verify/s        >500 ops/sec         │
│  Certificate Chain          Hybrid cert validation time    <100ms               │
│  Load Balancer Pass-through Hybrid ClientHello success     100%                 │
│  Backward Compatibility     Legacy client fallback         Graceful             │
│  Rollback Procedure         Time to revert to classical    <5 minutes           │
│  Throughput Under Load      TPS with hybrid TLS            <15% regression      │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Performance Expectations

**Mathematical Model: Handshake Overhead**

```
Hybrid_Overhead = (T_classical_keygen + T_pqc_keygen + T_encaps + T_decaps) / T_classical_only

Expected values (network-bound scenarios):
  T_classical_keygen ≈ 0.1ms
  T_pqc_keygen ≈ 0.05ms (ML-KEM-768)
  T_encaps ≈ 0.05ms
  T_decaps ≈ 0.05ms

Total additional latency: ~0.15-0.25ms per handshake
Network RTT typically dominates: 20-100ms

Effective overhead in network-bound: <1%
Effective overhead in compute-bound (batch operations): 5.8-6.4×
```

---

## Phase 6: Phased Production Rollout

### Rollout Strategy

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        PRODUCTION ROLLOUT PHASES                                │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  2025-2026: PILOT PRODUCTION                                                    │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━                                                    │
│  • Internal services (IT staff, early adopters)                                 │
│  • Single geographic region                                                     │
│  • Extensive monitoring, rapid rollback                                         │
│  • Traffic: 1-5% of total                                                       │
│                                                                                 │
│  2026-2029: SCALED DEPLOYMENT                                                   │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━                                                    │
│  • Customer-facing applications                                                 │
│  • Multi-region expansion                                                       │
│  • Gradual traffic shift: 10% → 25% → 50% → 75% → 100%                         │
│  • Hybrid mode (PQC + classical simultaneously)                                 │
│                                                                                 │
│  2029-2030: FULL MIGRATION                                                      │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━                                                      │
│  • All systems migrated to hybrid PQC                                           │
│  • Classical algorithms deprecated (NIST 2030 deadline)                         │
│  • Begin legacy system decommissioning                                          │
│                                                                                 │
│  2030-2035: CLEANUP                                                             │
│  ━━━━━━━━━━━━━━━━━━━━━                                                          │
│  • Pure PQC where feasible (remove classical)                                   │
│  • Legacy system remediation/replacement                                        │
│  • Classical algorithms disallowed (NIST 2035 deadline)                         │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Phase 7: Governance & Compliance

### Organizational Structure

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      PQC MIGRATION GOVERNANCE STRUCTURE                         │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│                        ┌─────────────────────┐                                  │
│                        │   EXECUTIVE SPONSOR  │                                  │
│                        │   (CISO or CTO)      │                                  │
│                        │   Budget authority   │                                  │
│                        │   Board reporting    │                                  │
│                        └──────────┬──────────┘                                  │
│                                   │                                             │
│                        ┌──────────▼──────────┐                                  │
│                        │   PQC PROGRAM LEAD   │                                  │
│                        │   Full-time dedicated│                                  │
│                        │   Cross-functional   │                                  │
│                        └──────────┬──────────┘                                  │
│                                   │                                             │
│    ┌──────────┬──────────┬───────┴───────┬──────────┬──────────┐               │
│    │          │          │               │          │          │               │
│    ▼          ▼          ▼               ▼          ▼          ▼               │
│ ┌──────┐  ┌──────┐  ┌──────┐       ┌──────┐  ┌──────┐  ┌──────┐              │
│ │Crypto│  │ PKI/ │  │Infra │       │AppSec│  │Vendor│  │Compli│              │
│ │Expert│  │ Cert │  │ Eng  │       │      │  │ Mgmt │  │ance  │              │
│ └──────┘  └──────┘  └──────┘       └──────┘  └──────┘  └──────┘              │
│                                                                                 │
│  EXTENDED TEAM: Business units, DevOps, DBAs, Cloud architects                  │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Compliance Tracking

| Standard | Requirement | Deadline | Status |
|----------|-------------|----------|--------|
| NIST IR 8547 | RSA/ECDSA deprecated | 2030-01-01 | Planning |
| NIST IR 8547 | All QV algorithms disallowed | 2035-01-01 | Not Started |
| CNSA 2.0 | NSS migration complete | 2035-01-01 | Not Started |
| CISA | Annual CBOM reporting | 2025-12-31 | In Progress |
| PCI DSS 4.0 | Strong cryptography | 2025-03-31 | Review |

---

## Budget & Resource Estimates

### Cost Model by Organization Size

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    PQC MIGRATION COST ESTIMATES                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  Component              Small       Medium      Large       Enterprise          │
│                         (<500 emp)  (500-5K)    (5K-25K)    (>25K)              │
│  ─────────────────────  ──────────  ──────────  ──────────  ──────────         │
│  Discovery Tools        $35K        $150K       $400K       $1M+                │
│  HSM Upgrades           $50K        $200K       $500K       $2M+                │
│  Professional Services  $100K       $500K       $2M         $5M+                │
│  Staff Training         $25K        $75K        $200K       $500K               │
│  Testing Infrastructure $25K        $100K       $300K       $1M+                │
│  Monitoring Tools       $15K        $50K        $150K       $400K               │
│  ─────────────────────  ──────────  ──────────  ──────────  ──────────         │
│  TOTAL (5-year)         $250K       $1.1M       $3.5M       $10M+               │
│                                                                                 │
│  FTE Requirements:                                                              │
│  Peak dedicated staff   2           5           15          30+                 │
│  Part-time contributors 10          50          150         400+                │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Key Success Factors

### Crypto-Agility Design Principles

```python
# ANTI-PATTERN: Hardcoded cryptography
from cryptography.hazmat.primitives.asymmetric import rsa
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # Hardcoded!

# PATTERN: Crypto-agile abstraction
class CryptoProvider:
    def __init__(self, config: dict):
        self.algorithm = config.get("key_algorithm", "ML-KEM-768")
        self.key_size = config.get("key_size", 768)
    
    def generate_keypair(self):
        if self.algorithm.startswith("ML-KEM"):
            return self._generate_mlkem()
        elif self.algorithm == "X25519":
            return self._generate_x25519()
        elif self.algorithm == "RSA":  # Legacy fallback
            return self._generate_rsa()
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")
```

### Critical Reminders

1. **Start NOW** - The math shows most organizations are already behind schedule
2. **Discover FIRST** - You can't migrate what you can't see (CBOM is foundational)
3. **Hybrid is MANDATORY** - Pure PQC certificates won't be broadly available until 2026+
4. **Test EVERYTHING** - Load balancers, middleboxes, and legacy clients will break
5. **Budget REALISTICALLY** - This is a 5-10 year program, not a one-time project
6. **Governance is CONTINUOUS** - Not just a compliance checkbox

---

## References

- NIST IR 8547: Transition to Post-Quantum Cryptography Standards (November 2024)
- NIST FIPS 203, 204, 205: Post-Quantum Cryptographic Algorithm Standards (August 2024)
- IETF draft-ietf-tls-hybrid-design-16: Hybrid Key Exchange in TLS 1.3
- OWASP CycloneDX 1.6: Cryptographic Bill of Materials Specification
- CISA Post-Quantum Cryptography Initiative
- NSM-10: National Security Memorandum on Quantum Computing
- Cloudflare Research: Post-Quantum Cryptography Deployment Statistics

---

*Framework Version 1.0 | December 2024*
*NeuroDivergent AI Evolution Strategy | Trade Momentum LLC*
''''''''''''''''''''''''''''''''

p
//'
/[p/br