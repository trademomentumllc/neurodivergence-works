#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  CORPORATE POST-QUANTUM CRYPTOGRAPHY MIGRATION FRAMEWORK                      ║
║  Enterprise Q-Day Readiness Implementation Guide                              ║
║                                                                               ║
║  Mathematical Foundation:                                                     ║
║  X + Y > Z ⟹ Immediate Migration Required                                    ║
║  Where:                                                                       ║
║    X = Data confidentiality shelf-life (years)                               ║
║    Y = System migration duration (years)                                      ║
║    Z = Threat horizon to Q-Day (years ≤ 10)                                  ║
║                                                                               ║
║  Regulatory Timeline:                                                         ║
║    2030: RSA, ECDSA, EdDSA DEPRECATED (NIST IR 8547)                         ║
║    2035: ALL quantum-vulnerable algorithms DISALLOWED                         ║
║                                                                               ║
║  Author: Jason Jarmacz | Trade Momentum LLC                                   ║
║  Framework: NeuroDivergent AI Evolution Strategy                            ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum, auto
from datetime import datetime, timedelta

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1: MATHEMATICAL RISK MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class QuantumThreatModel:
    """
    Mathematical Model for Q-Day Risk Assessment
    
    Core Equation:
    ────────────────────────────────────────────────────────────────────────────
    Migration_Urgency = (X + Y) / Z
    
    Where:
        X = Data confidentiality shelf-life (years data must remain secret)
        Y = System migration duration (years to complete PQC transition)
        Z = Threat horizon to Q-Day (estimated years until quantum threat)
    
    Interpretation:
        Urgency > 1.0  →  CRITICAL: Migration must begin immediately
        Urgency = 1.0  →  WARNING: Migration deadline equals threat horizon
        Urgency < 1.0  →  MANAGEABLE: Time buffer exists
    
    Extended Model with Harvest-Now-Decrypt-Later (HNDL):
    ────────────────────────────────────────────────────────────────────────────
    Effective_Risk = (X + Y + H) / Z
    
    Where H = HNDL exposure period (data already captured by adversaries)
    
    Note: State actors assumed to achieve quantum capability 2 years ahead of
    commercial availability. If commercial Q-Day is 2030, state Q-Day is 2028.
    """
    
    # NIST/Industry Consensus Estimates (as of December 2024)
    COMMERCIAL_QDAY_ESTIMATE = 2030  # Gartner/NIST conservative estimate
    STATE_ACTOR_QDAY_ESTIMATE = 2028  # State actors typically 2 years ahead
    ENTERPRISE_MIGRATION_AVERAGE = 7  # Average years for full PQC migration
    
    def __init__(
        self,
        data_shelf_life_years: float,
        migration_duration_years: float,
        qday_estimate_year: int = 2030,
        hndl_exposure_years: float = 0,
        is_state_actor_target: bool = False
    ):
        self.X = data_shelf_life_years
        self.Y = migration_duration_years
        self.H = hndl_exposure_years
        
        # Adjust Q-Day based on adversary sophistication
        if is_state_actor_target:
            self.qday = self.STATE_ACTOR_QDAY_ESTIMATE
        else:
            self.qday = qday_estimate_year
            
        current_year = datetime.now().year
        self.Z = max(self.qday - current_year, 0.1)  # Prevent division by zero
    
    def calculate_urgency(self) -> float:
        """
        Calculate migration urgency score
        
        Returns:
            float: Urgency score where >1.0 requires immediate action
        """
        return (self.X + self.Y + self.H) / self.Z
    
    def calculate_risk_score(self) -> Dict[str, any]:
        """
        Comprehensive risk assessment with actionable interpretation
        """
        urgency = self.calculate_urgency()
        deadline_year = datetime.now().year + self.Z - self.Y
        
        if urgency > 1.5:
            risk_level = "CRITICAL"
            recommendation = "EMERGENCY: Begin migration immediately. Already behind schedule."
        elif urgency > 1.0:
            risk_level = "HIGH"
            recommendation = "URGENT: Migration must start this quarter to meet deadline."
        elif urgency > 0.7:
            risk_level = "ELEVATED"
            recommendation = "PRIORITY: Schedule migration planning within 6 months."
        else:
            risk_level = "MODERATE"
            recommendation = "PLANNED: Include in 12-24 month roadmap."
        
        return {
            "urgency_score": round(urgency, 3),
            "risk_level": risk_level,
            "recommendation": recommendation,
            "parameters": {
                "data_shelf_life_X": self.X,
                "migration_duration_Y": self.Y,
                "hndl_exposure_H": self.H,
                "threat_horizon_Z": self.Z,
                "qday_estimate": self.qday
            },
            "critical_dates": {
                "must_start_by": deadline_year,
                "must_complete_by": self.qday,
                "nist_deprecation": 2030,
                "nist_disallowed": 2035
            },
            "equation": f"({self.X} + {self.Y} + {self.H}) / {self.Z} = {urgency:.3f}"
        }


class CryptoAssetRiskMatrix:
    """
    Risk-Based Prioritization Matrix for Cryptographic Assets
    
    Mathematical Model:
    ────────────────────────────────────────────────────────────────────────────
    Asset_Priority = Σ(Wi × Fi) × Exposure_Multiplier
    
    Where:
        Wi = Weight factor for criterion i
        Fi = Score (1-5) for criterion i
        Exposure_Multiplier = 1.0 (internal) to 2.0 (internet-facing)
    
    Criteria:
        1. Data Sensitivity (regulatory, competitive, personal)
        2. Retention Period (how long data must remain confidential)
        3. System Criticality (business impact of compromise)
        4. Crypto-Agility (ease of algorithm replacement)
        5. Vendor Dependency (ability to control migration)
    """
    
    WEIGHT_FACTORS = {
        "data_sensitivity": 0.25,
        "retention_period": 0.25,
        "system_criticality": 0.20,
        "crypto_agility": 0.15,
        "vendor_dependency": 0.15
    }
    
    EXPOSURE_MULTIPLIERS = {
        "internet_facing": 2.0,
        "dmz": 1.7,
        "internal_network": 1.3,
        "air_gapped": 1.0
    }
    
    def calculate_priority(
        self,
        asset_name: str,
        data_sensitivity: int,      # 1-5 scale
        retention_period: int,       # 1-5 scale
        system_criticality: int,     # 1-5 scale
        crypto_agility: int,         # 1-5 (5 = hard to change = higher priority)
        vendor_dependency: int,      # 1-5 scale
        exposure_type: str = "internal_network"
    ) -> Dict[str, any]:
        """
        Calculate migration priority score for a cryptographic asset
        """
        weighted_sum = (
            self.WEIGHT_FACTORS["data_sensitivity"] * data_sensitivity +
            self.WEIGHT_FACTORS["retention_period"] * retention_period +
            self.WEIGHT_FACTORS["system_criticality"] * system_criticality +
            self.WEIGHT_FACTORS["crypto_agility"] * crypto_agility +
            self.WEIGHT_FACTORS["vendor_dependency"] * vendor_dependency
        )
        
        multiplier = self.EXPOSURE_MULTIPLIERS.get(exposure_type, 1.0)
        priority_score = weighted_sum * multiplier
        
        # Normalize to 0-100 scale
        normalized_score = (priority_score / 10) * 100
        
        if normalized_score >= 80:
            tier = "TIER 1 - IMMEDIATE"
            timeline = "2025-2026"
        elif normalized_score >= 60:
            tier = "TIER 2 - HIGH PRIORITY"
            timeline = "2026-2028"
        elif normalized_score >= 40:
            tier = "TIER 3 - MEDIUM PRIORITY"
            timeline = "2028-2030"
        else:
            tier = "TIER 4 - SCHEDULED"
            timeline = "2030-2035"
        
        return {
            "asset": asset_name,
            "priority_score": round(normalized_score, 1),
            "migration_tier": tier,
            "target_timeline": timeline,
            "risk_factors": {
                "data_sensitivity": data_sensitivity,
                "retention_period": retention_period,
                "system_criticality": system_criticality,
                "crypto_agility": crypto_agility,
                "vendor_dependency": vendor_dependency,
                "exposure_type": exposure_type
            },
            "equation": f"({weighted_sum:.2f} × {multiplier}) × 10 = {normalized_score:.1f}"
        }


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2: CRYPTOGRAPHIC INVENTORY (CBOM) DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════

class AlgorithmCategory(Enum):
    """NIST Quantum Security Categories"""
    QUANTUM_VULNERABLE = auto()      # RSA, ECDSA, ECDH, DH, EdDSA
    QUANTUM_SAFE_KEM = auto()        # ML-KEM (Kyber)
    QUANTUM_SAFE_SIG = auto()        # ML-DSA, SLH-DSA, FN-DSA
    SYMMETRIC = auto()               # AES (quantum-resistant with larger keys)
    HASH = auto()                    # SHA-2, SHA-3 (quantum-resistant)
    HYBRID = auto()                  # Classical + PQC combined


@dataclass
class CryptographicAsset:
    """
    Cryptographic Bill of Materials (CBOM) Asset Record
    
    Based on CycloneDX 1.6 CBOM Specification (OWASP/IBM)
    """
    asset_id: str
    algorithm_name: str
    algorithm_category: AlgorithmCategory
    key_size_bits: int
    location: str                    # File path, service name, endpoint
    discovery_method: str            # Passive, Active, Code Analysis
    confidence_score: float          # 0.0-1.0 detection confidence
    owning_system: str
    owning_team: str
    data_classification: str         # PII, PHI, Financial, Proprietary, Public
    retention_years: int
    exposure_type: str               # internet_facing, dmz, internal, air_gapped
    dependencies: List[str] = field(default_factory=list)
    certificates: List[str] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)
    vendor: Optional[str] = None
    notes: Optional[str] = None
    discovered_at: datetime = field(default_factory=datetime.now)
    
    def is_quantum_vulnerable(self) -> bool:
        """Check if asset uses quantum-vulnerable cryptography"""
        return self.algorithm_category == AlgorithmCategory.QUANTUM_VULNERABLE
    
    def get_nist_deadline(self) -> int:
        """Return NIST compliance deadline based on algorithm"""
        if self.algorithm_category == AlgorithmCategory.QUANTUM_VULNERABLE:
            return 2030  # Deprecated
        return 2035  # All quantum-vulnerable disallowed
    
    def to_cbom_dict(self) -> Dict:
        """Export to CBOM-compatible dictionary format"""
        return {
            "bom-ref": self.asset_id,
            "type": "cryptographic-asset",
            "name": self.algorithm_name,
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": self._get_primitive(),
                    "parameterSetIdentifier": f"{self.key_size_bits}",
                    "executionEnvironment": self.exposure_type
                },
                "protocolProperties": {
                    "type": self.protocols[0] if self.protocols else "unknown",
                    "cryptoRefArray": self.dependencies
                },
                "oid": self._get_oid()
            },
            "properties": [
                {"name": "location", "value": self.location},
                {"name": "confidence", "value": str(self.confidence_score)},
                {"name": "dataClassification", "value": self.data_classification},
                {"name": "retentionYears", "value": str(self.retention_years)}
            ]
        }
    
    def _get_primitive(self) -> str:
        """Map algorithm to cryptographic primitive type"""
        primitives = {
            "RSA": "pke",
            "ECDSA": "signature",
            "ECDH": "key-agreement",
            "EdDSA": "signature",
            "AES": "block-cipher",
            "ML-KEM": "kem",
            "ML-DSA": "signature",
            "SLH-DSA": "signature"
        }
        return primitives.get(self.algorithm_name.split("-")[0], "other")
    
    def _get_oid(self) -> str:
        """Get OID for algorithm (simplified)"""
        oids = {
            "RSA": "1.2.840.113549.1.1.1",
            "ECDSA": "1.2.840.10045.2.1",
            "AES-256": "2.16.840.1.101.3.4.1.42",
            "ML-KEM-768": "2.16.840.1.101.3.4.4.2",
            "ML-DSA-65": "2.16.840.1.101.3.4.3.18"
        }
        return oids.get(self.algorithm_name, "unknown")


@dataclass
class CryptographicInventory:
    """
    Enterprise Cryptographic Inventory Manager
    
    Aggregates all discovered cryptographic assets for risk assessment
    and migration planning.
    """
    organization: str
    inventory_date: datetime = field(default_factory=datetime.now)
    assets: List[CryptographicAsset] = field(default_factory=list)
    
    def add_asset(self, asset: CryptographicAsset):
        self.assets.append(asset)
    
    def get_vulnerable_assets(self) -> List[CryptographicAsset]:
        """Return all quantum-vulnerable assets"""
        return [a for a in self.assets if a.is_quantum_vulnerable()]
    
    def get_assets_by_tier(self) -> Dict[str, List[CryptographicAsset]]:
        """Group assets by migration priority tier"""
        matrix = CryptoAssetRiskMatrix()
        tiers = {"TIER 1": [], "TIER 2": [], "TIER 3": [], "TIER 4": []}
        
        for asset in self.get_vulnerable_assets():
            # Calculate priority (simplified scoring for demo)
            data_sens = {"PII": 5, "PHI": 5, "Financial": 4, "Proprietary": 3, "Public": 1}
            priority = matrix.calculate_priority(
                asset_name=asset.asset_id,
                data_sensitivity=data_sens.get(asset.data_classification, 3),
                retention_period=min(asset.retention_years // 2, 5),
                system_criticality=3,
                crypto_agility=3,
                vendor_dependency=3 if asset.vendor else 2,
                exposure_type=asset.exposure_type
            )
            
            tier_key = priority["migration_tier"].split(" - ")[0]
            tiers[tier_key].append(asset)
        
        return tiers
    
    def generate_summary_report(self) -> Dict:
        """Generate executive summary of cryptographic posture"""
        vulnerable = self.get_vulnerable_assets()
        total = len(self.assets)
        
        by_algorithm = {}
        by_exposure = {}
        by_classification = {}
        
        for asset in vulnerable:
            by_algorithm[asset.algorithm_name] = by_algorithm.get(asset.algorithm_name, 0) + 1
            by_exposure[asset.exposure_type] = by_exposure.get(asset.exposure_type, 0) + 1
            by_classification[asset.data_classification] = by_classification.get(asset.data_classification, 0) + 1
        
        return {
            "organization": self.organization,
            "inventory_date": self.inventory_date.isoformat(),
            "total_assets_discovered": total,
            "quantum_vulnerable_assets": len(vulnerable),
            "vulnerability_rate": round(len(vulnerable) / total * 100, 1) if total > 0 else 0,
            "distribution_by_algorithm": by_algorithm,
            "distribution_by_exposure": by_exposure,
            "distribution_by_classification": by_classification,
            "critical_deadline": "2030 (NIST IR 8547 Deprecation)",
            "hard_deadline": "2035 (NIST IR 8547 Disallowed)"
        }
    
    def export_cbom(self) -> Dict:
        """Export full CBOM in CycloneDX 1.6 format"""
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": f"urn:uuid:{hashlib.md5(self.organization.encode()).hexdigest()}",
            "version": 1,
            "metadata": {
                "timestamp": self.inventory_date.isoformat(),
                "tools": [{"name": "PQC Migration Framework", "version": "1.0.0"}],
                "component": {"name": self.organization, "type": "organization"}
            },
            "components": [asset.to_cbom_dict() for asset in self.assets]
        }


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3: MIGRATION PHASE FRAMEWORK
# ═══════════════════════════════════════════════════════════════════════════════

class MigrationPhase(Enum):
    """PQC Migration Lifecycle Phases"""
    PHASE_1_DISCOVERY = "Discovery & Inventory"
    PHASE_2_ASSESSMENT = "Risk Assessment & Prioritization"
    PHASE_3_INFRASTRUCTURE = "Infrastructure Readiness"
    PHASE_4_VENDOR = "Vendor & Dependency Management"
    PHASE_5_PILOT = "Pilot Deployment & Testing"
    PHASE_6_ROLLOUT = "Phased Production Rollout"
    PHASE_7_GOVERNANCE = "Governance & Compliance"


@dataclass
class MigrationMilestone:
    """Individual migration milestone with timeline and deliverables"""
    phase: MigrationPhase
    name: str
    description: str
    target_start: datetime
    target_end: datetime
    owner: str
    deliverables: List[str]
    dependencies: List[str] = field(default_factory=list)
    budget_usd: float = 0.0
    fte_required: float = 0.0
    status: str = "NOT_STARTED"
    
    def duration_days(self) -> int:
        return (self.target_end - self.target_start).days


class CorporateMigrationPlan:
    """
    Comprehensive Corporate PQC Migration Planning Framework
    
    Based on:
    - NIST NCCoE Migration to Post-Quantum Cryptography Project
    - FS-ISAC PQC Working Group Guidelines
    - CISA Post-Quantum Cryptography Initiative
    - Gartner PQC Migration Recommendations
    """
    
    def __init__(
        self,
        organization_name: str,
        organization_size: str,  # small, medium, large, enterprise
        start_year: int = 2025
    ):
        self.organization = organization_name
        self.size = organization_size
        self.start_year = start_year
        self.milestones: List[MigrationMilestone] = []
        self._generate_default_milestones()
    
    def _generate_default_milestones(self):
        """Generate recommended milestones based on organization size"""
        
        # Timeline multipliers based on organization size
        multipliers = {
            "small": 0.7,
            "medium": 1.0,
            "large": 1.3,
            "enterprise": 1.5
        }
        mult = multipliers.get(self.size, 1.0)
        
        base_date = datetime(self.start_year, 1, 1)
        
        # Phase 1: Discovery & Inventory (3-6 months)
        self.milestones.append(MigrationMilestone(
            phase=MigrationPhase.PHASE_1_DISCOVERY,
            name="Cryptographic Asset Discovery",
            description="Comprehensive inventory of all cryptographic assets across enterprise",
            target_start=base_date,
            target_end=base_date + timedelta(days=int(180 * mult)),
            owner="CISO / Security Architecture",
            deliverables=[
                "Complete CBOM (Cryptographic Bill of Materials)",
                "Asset inventory in CMDB",
                "Network diagram with crypto annotations",
                "Discovery tool deployment report"
            ],
            budget_usd=150000 * mult,
            fte_required=3 * mult
        ))
        
        # Phase 2: Risk Assessment (2-3 months)
        phase2_start = base_date + timedelta(days=int(180 * mult))
        self.milestones.append(MigrationMilestone(
            phase=MigrationPhase.PHASE_2_ASSESSMENT,
            name="Risk Assessment & Prioritization",
            description="Evaluate quantum risk exposure and prioritize migration targets",
            target_start=phase2_start,
            target_end=phase2_start + timedelta(days=int(90 * mult)),
            owner="Risk Management / Security Architecture",
            deliverables=[
                "Risk-prioritized migration backlog",
                "Business impact analysis",
                "Data classification mapping",
                "Migration timeline proposal"
            ],
            dependencies=["Cryptographic Asset Discovery"],
            budget_usd=75000 * mult,
            fte_required=2 * mult
        ))
        
        # Phase 3: Infrastructure Readiness (6-12 months)
        phase3_start = phase2_start + timedelta(days=int(90 * mult))
        self.milestones.append(MigrationMilestone(
            phase=MigrationPhase.PHASE_3_INFRASTRUCTURE,
            name="Infrastructure Preparation",
            description="Upgrade HSMs, PKI, TLS endpoints for PQC support",
            target_start=phase3_start,
            target_end=phase3_start + timedelta(days=int(365 * mult)),
            owner="Infrastructure / Platform Engineering",
            deliverables=[
                "HSM firmware upgrades to PQC-ready",
                "Internal CA PQC certificate chain",
                "TLS 1.3 hybrid configuration",
                "Load balancer compatibility verification",
                "Crypto library upgrades (OpenSSL 3.4+)"
            ],
            dependencies=["Risk Assessment & Prioritization"],
            budget_usd=500000 * mult,
            fte_required=5 * mult
        ))
        
        # Phase 4: Vendor Management (Ongoing)
        phase4_start = phase2_start
        self.milestones.append(MigrationMilestone(
            phase=MigrationPhase.PHASE_4_VENDOR,
            name="Vendor PQC Readiness Assessment",
            description="Evaluate and coordinate with vendors on PQC timelines",
            target_start=phase4_start,
            target_end=phase4_start + timedelta(days=int(180 * mult)),
            owner="Vendor Management / Procurement",
            deliverables=[
                "Vendor PQC capability matrix",
                "Contract amendments for PQC requirements",
                "Third-party risk assessment updates",
                "SaaS/Cloud provider migration alignment"
            ],
            dependencies=["Cryptographic Asset Discovery"],
            budget_usd=50000 * mult,
            fte_required=1.5 * mult
        ))
        
        # Phase 5: Pilot Deployment (6-12 months)
        phase5_start = phase3_start + timedelta(days=int(180 * mult))
        self.milestones.append(MigrationMilestone(
            phase=MigrationPhase.PHASE_5_PILOT,
            name="PQC Pilot Deployment",
            description="Deploy hybrid PQC in controlled environments",
            target_start=phase5_start,
            target_end=phase5_start + timedelta(days=int(365 * mult)),
            owner="Security Engineering / DevSecOps",
            deliverables=[
                "Sandbox environment with PQC",
                "Performance benchmark report",
                "Interoperability test results",
                "Rollback procedure documentation",
                "Lessons learned document"
            ],
            dependencies=["Infrastructure Preparation"],
            budget_usd=200000 * mult,
            fte_required=4 * mult
        ))
        
        # Phase 6: Production Rollout (2-5 years)
        phase6_start = phase5_start + timedelta(days=int(365 * mult))
        self.milestones.append(MigrationMilestone(
            phase=MigrationPhase.PHASE_6_ROLLOUT,
            name="Phased Production Migration",
            description="Systematic migration of production systems to PQC",
            target_start=phase6_start,
            target_end=datetime(2030, 1, 1),  # NIST deadline
            owner="Engineering / Operations",
            deliverables=[
                "Tier 1 systems migrated (internet-facing)",
                "Tier 2 systems migrated (internal critical)",
                "Tier 3 systems migrated (standard)",
                "Legacy system remediation plan",
                "Zero classical-only systems by 2030"
            ],
            dependencies=["PQC Pilot Deployment"],
            budget_usd=2000000 * mult,
            fte_required=10 * mult
        ))
        
        # Phase 7: Governance (Ongoing)
        self.milestones.append(MigrationMilestone(
            phase=MigrationPhase.PHASE_7_GOVERNANCE,
            name="PQC Governance Framework",
            description="Establish policies, standards, and compliance tracking",
            target_start=base_date,
            target_end=datetime(2035, 1, 1),  # NIST hard deadline
            owner="CISO / Compliance",
            deliverables=[
                "PQC Policy and Standards",
                "Crypto-agility requirements",
                "Compliance tracking dashboard",
                "Annual CBOM reporting (CISA requirement)",
                "Audit trail documentation"
            ],
            budget_usd=100000 * mult,
            fte_required=2 * mult
        ))
    
    def get_total_budget(self) -> float:
        return sum(m.budget_usd for m in self.milestones)
    
    def get_total_fte(self) -> float:
        return max(m.fte_required for m in self.milestones)
    
    def get_timeline_summary(self) -> Dict:
        """Generate executive timeline summary"""
        return {
            "organization": self.organization,
            "organization_size": self.size,
            "migration_start": self.start_year,
            "target_completion": 2030,
            "hard_deadline": 2035,
            "total_estimated_budget_usd": self.get_total_budget(),
            "peak_fte_requirement": self.get_total_fte(),
            "phases": [
                {
                    "phase": m.phase.value,
                    "name": m.name,
                    "start": m.target_start.strftime("%Y-%m"),
                    "end": m.target_end.strftime("%Y-%m"),
                    "duration_months": m.duration_days() // 30,
                    "budget_usd": m.budget_usd,
                    "fte": m.fte_required,
                    "owner": m.owner
                }
                for m in self.milestones
            ]
        }
    
    def generate_gantt_data(self) -> List[Dict]:
        """Generate data for Gantt chart visualization"""
        return [
            {
                "task": m.name,
                "phase": m.phase.value,
                "start": m.target_start.isoformat(),
                "end": m.target_end.isoformat(),
                "owner": m.owner,
                "status": m.status
            }
            for m in self.milestones
        ]


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4: INFRASTRUCTURE SPECIFICATIONS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class HSMRequirement:
    """Hardware Security Module PQC Requirements"""
    vendor: str
    model: str
    pqc_algorithms: List[str]
    firmware_version: str
    fips_validation: str
    hybrid_support: bool
    cloud_available: bool
    estimated_cost_usd: float
    notes: str


@dataclass
class TLSConfiguration:
    """TLS 1.3 Hybrid Configuration Specification"""
    cipher_suite: str
    key_exchange: str
    signature_algorithm: str
    certificate_type: str
    backward_compatible: bool
    ietf_reference: str


class InfrastructureSpec:
    """
    Enterprise Infrastructure PQC Specifications
    
    Covers:
    - HSM Requirements
    - TLS/PKI Configuration
    - Protocol Updates
    - Library Dependencies
    """
    
    # PQC-Ready HSM Vendors (2024-2025 Status)
    PQC_HSMS = [
        HSMRequirement(
            vendor="Thales",
            model="Luna Network HSM 7",
            pqc_algorithms=["ML-KEM", "ML-DSA", "SLH-DSA"],
            firmware_version="7.8.x+",
            fips_validation="FIPS 140-3 Level 3",
            hybrid_support=True,
            cloud_available=True,
            estimated_cost_usd=50000,
            notes="PQC via firmware update, no hardware replacement"
        ),
        HSMRequirement(
            vendor="Utimaco",
            model="u.trust General Purpose HSM Se-Series",
            pqc_algorithms=["ML-KEM", "ML-DSA", "SLH-DSA", "XMSS", "LMS"],
            firmware_version="Quantum Protect update",
            fips_validation="FIPS 140-2 Level 4",
            hybrid_support=True,
            cloud_available=True,
            estimated_cost_usd=45000,
            notes="Free simulator available for testing"
        ),
        HSMRequirement(
            vendor="Entrust",
            model="nShield HSM",
            pqc_algorithms=["ML-KEM", "ML-DSA"],
            firmware_version="13.x+",
            fips_validation="FIPS 140-2 Level 3",
            hybrid_support=True,
            cloud_available=True,
            estimated_cost_usd=55000,
            notes="CodeSafe TEE for crypto-agile development"
        ),
        HSMRequirement(
            vendor="Securosys",
            model="Primus CyberVault X2",
            pqc_algorithms=["ML-KEM-768", "ML-KEM-1024", "ML-DSA-65", "ML-DSA-87"],
            firmware_version="3.x+",
            fips_validation="FIPS 140-2 Level 3",
            hybrid_support=True,
            cloud_available=True,
            estimated_cost_usd=60000,
            notes="Sandbox testing environment available"
        ),
        HSMRequirement(
            vendor="Eviden (Atos)",
            model="Trustway Proteccio",
            pqc_algorithms=["ML-KEM", "ML-DSA", "SLH-DSA"],
            firmware_version="PQC HSMaaS",
            fips_validation="ANSSI Highest Qualification",
            hybrid_support=True,
            cloud_available=True,
            estimated_cost_usd=70000,
            notes="EU sovereign, NIS2 compliant"
        )
    ]
    
    # TLS 1.3 Hybrid Configuration (IETF draft-ietf-tls-hybrid-design)
    TLS_HYBRID_SUITES = [
        TLSConfiguration(
            cipher_suite="TLS_AES_256_GCM_SHA384",
            key_exchange="X25519MLKEM768",
            signature_algorithm="ecdsa_secp384r1_sha384",
            certificate_type="Hybrid (ECDSA + pending ML-DSA)",
            backward_compatible=True,
            ietf_reference="draft-ietf-tls-hybrid-design-16"
        ),
        TLSConfiguration(
            cipher_suite="TLS_AES_256_GCM_SHA384",
            key_exchange="SecP384r1MLKEM1024",
            signature_algorithm="ml-dsa-65",
            certificate_type="PQC-only (future)",
            backward_compatible=False,
            ietf_reference="draft-connolly-tls-mlkem-key-agreement"
        )
    ]
    
    # Required Library Versions
    LIBRARY_REQUIREMENTS = {
        "OpenSSL": {
            "minimum": "3.4.0",
            "pqc_provider": "oqs-provider",
            "algorithms": ["ML-KEM-768", "ML-DSA-65", "SLH-DSA-128f"]
        },
        "BouncyCastle": {
            "minimum": "1.78",
            "platform": "Java/C#",
            "algorithms": ["ML-KEM", "ML-DSA", "SLH-DSA", "FN-DSA"]
        },
        "WolfSSL": {
            "minimum": "5.7.0",
            "pqc_integration": "liboqs",
            "algorithms": ["Kyber", "Dilithium", "SPHINCS+"]
        },
        "Microsoft CNG": {
            "minimum": "Windows Server 2025",
            "platform": "Windows",
            "algorithms": ["ML-KEM (planned)", "ML-DSA (planned)"]
        },
        "liboqs": {
            "minimum": "0.10.0",
            "platform": "Cross-platform",
            "algorithms": ["All NIST PQC finalists"]
        }
    }
    
    @classmethod
    def get_hsm_comparison(cls) -> List[Dict]:
        """Compare PQC-ready HSM options"""
        return [
            {
                "vendor": h.vendor,
                "model": h.model,
                "algorithms": h.pqc_algorithms,
                "fips": h.fips_validation,
                "cloud": h.cloud_available,
                "cost_usd": h.estimated_cost_usd
            }
            for h in cls.PQC_HSMS
        ]
    
    @classmethod
    def generate_nginx_config(cls) -> str:
        """Generate NGINX configuration for hybrid TLS"""
        return '''
# NGINX TLS 1.3 Hybrid PQC Configuration
# Requires: OpenSSL 3.4+ with oqs-provider

ssl_protocols TLSv1.3;

# Hybrid Key Exchange (Classical + PQC)
ssl_ecdh_curve X25519MLKEM768:X25519:secp384r1;

# Cipher Suites (TLS 1.3 only)
ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;

# Certificate Configuration (hybrid when available)
ssl_certificate /etc/nginx/ssl/hybrid_cert.pem;
ssl_certificate_key /etc/nginx/ssl/hybrid_key.pem;

# Session Configuration
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
ssl_session_tickets off;

# OCSP Stapling
ssl_stapling on;
ssl_stapling_verify on;

# Buffer sizes for larger PQC handshakes
ssl_buffer_size 16k;
proxy_buffer_size 16k;
'''

    @classmethod
    def generate_apache_config(cls) -> str:
        """Generate Apache configuration for hybrid TLS"""
        return '''
# Apache TLS 1.3 Hybrid PQC Configuration
# Requires: OpenSSL 3.4+ with oqs-provider

SSLProtocol TLSv1.3

# Hybrid Key Exchange
SSLOpenSSLConfCmd Groups X25519MLKEM768:X25519:secp384r1

# Cipher Configuration
SSLCipherSuite TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256

# Certificate Files
SSLCertificateFile /etc/apache2/ssl/hybrid_cert.pem
SSLCertificateKeyFile /etc/apache2/ssl/hybrid_key.pem

# Session Configuration
SSLSessionCache "shmcb:/var/cache/mod_ssl/scache(512000)"
SSLSessionCacheTimeout 300

# Enable OCSP Stapling
SSLUseStapling On
SSLStaplingCache "shmcb:/var/run/ocsp(128000)"
'''


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5: COMPLIANCE & GOVERNANCE FRAMEWORK
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ComplianceRequirement:
    """Regulatory/Standard compliance requirement"""
    standard: str
    requirement_id: str
    description: str
    deadline: datetime
    applicability: str
    status: str = "NOT_STARTED"


class GovernanceFramework:
    """
    PQC Governance and Compliance Tracking
    
    Covers:
    - NIST IR 8547 (Deprecation Schedule)
    - CNSA 2.0 (National Security Systems)
    - Industry Regulations (PCI DSS, HIPAA, etc.)
    - Organizational Policies
    """
    
    REGULATORY_REQUIREMENTS = [
        ComplianceRequirement(
            standard="NIST IR 8547",
            requirement_id="NIST-2030",
            description="RSA, ECDSA, EdDSA, DH, ECDH deprecated",
            deadline=datetime(2030, 1, 1),
            applicability="All federal systems, industry best practice"
        ),
        ComplianceRequirement(
            standard="NIST IR 8547",
            requirement_id="NIST-2035",
            description="All quantum-vulnerable algorithms disallowed",
            deadline=datetime(2035, 1, 1),
            applicability="All federal systems, industry best practice"
        ),
        ComplianceRequirement(
            standard="CNSA 2.0",
            requirement_id="NSM-10",
            description="National Security Systems PQC migration complete",
            deadline=datetime(2035, 1, 1),
            applicability="National Security Systems (NSS)"
        ),
        ComplianceRequirement(
            standard="CISA",
            requirement_id="CISA-CBOM",
            description="Annual cryptographic inventory reporting",
            deadline=datetime(2025, 12, 31),
            applicability="Federal agencies"
        ),
        ComplianceRequirement(
            standard="PCI DSS 4.0",
            requirement_id="PCI-3.6.1",
            description="Strong cryptography for cardholder data",
            deadline=datetime(2025, 3, 31),
            applicability="Payment card processors"
        )
    ]
    
    @classmethod
    def get_policy_template(cls) -> str:
        """Generate corporate PQC policy template"""
        return '''
═══════════════════════════════════════════════════════════════════════════════
                    POST-QUANTUM CRYPTOGRAPHY POLICY
                    [ORGANIZATION NAME] - VERSION 1.0
═══════════════════════════════════════════════════════════════════════════════

1. PURPOSE
   This policy establishes requirements for the migration to post-quantum
   cryptographic algorithms in response to the emerging quantum computing threat.

2. SCOPE
   This policy applies to all information systems, applications, and services
   that utilize cryptographic protections for confidentiality, integrity, or
   authentication.

3. POLICY STATEMENTS

   3.1 ALGORITHM REQUIREMENTS
       a) Effective 2025-01-01: All new systems MUST support hybrid 
          cryptography (classical + PQC) for key exchange.
       b) Effective 2030-01-01: RSA, ECDSA, EdDSA, DH, and ECDH are 
          DEPRECATED and prohibited for new implementations.
       c) Effective 2035-01-01: All quantum-vulnerable algorithms are 
          DISALLOWED for any use.

   3.2 APPROVED ALGORITHMS
       Key Encapsulation: ML-KEM-768, ML-KEM-1024 (FIPS 203)
       Digital Signatures: ML-DSA-65, ML-DSA-87 (FIPS 204)
       Stateless Signatures: SLH-DSA (FIPS 205)
       Hash-Based (limited use): LMS, XMSS (NIST SP 800-208)
       Symmetric: AES-256-GCM, ChaCha20-Poly1305

   3.3 CRYPTO-AGILITY REQUIREMENT
       All systems MUST be designed for cryptographic agility, enabling
       algorithm replacement without significant architectural changes.

   3.4 INVENTORY REQUIREMENT
       A complete Cryptographic Bill of Materials (CBOM) MUST be maintained
       and updated annually.

   3.5 HYBRID DEPLOYMENT
       Internet-facing services MUST implement hybrid key exchange
       (e.g., X25519MLKEM768) before classical-only deprecation.

4. ROLES AND RESPONSIBILITIES

   4.1 CISO: Overall accountability for PQC migration program
   4.2 Security Architecture: Technical standards and implementation guidance
   4.3 System Owners: Migration of individual systems within timeline
   4.4 Vendor Management: Third-party PQC readiness assessment
   4.5 Compliance: Tracking and reporting on migration progress

5. COMPLIANCE
   Violations of this policy may result in disciplinary action and system
   decommissioning for non-compliant systems after deadline dates.

6. EXCEPTIONS
   Exceptions require written approval from CISO with documented risk
   acceptance and remediation timeline.

7. REFERENCES
   - NIST IR 8547: Transition to Post-Quantum Cryptography Standards
   - NIST FIPS 203, 204, 205: Post-Quantum Cryptographic Standards
   - CISA Post-Quantum Cryptography Initiative
   - NSM-10: National Security Memorandum on Quantum Computing

═══════════════════════════════════════════════════════════════════════════════
'''

    @classmethod
    def get_compliance_checklist(cls) -> List[Dict]:
        """Generate compliance tracking checklist"""
        return [
            {
                "requirement": r.requirement_id,
                "standard": r.standard,
                "description": r.description,
                "deadline": r.deadline.strftime("%Y-%m-%d"),
                "status": r.status
            }
            for r in cls.REGULATORY_REQUIREMENTS
        ]


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6: DEMONSTRATION & VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════

def demonstrate_framework():
    """
    Demonstrate the complete PQC Migration Framework
    
    Simulates a medium-sized enterprise starting their Q-Day preparation
    """
    print("=" * 80)
    print("CORPORATE PQC MIGRATION FRAMEWORK DEMONSTRATION")
    print("=" * 80)
    
    # 1. Quantum Threat Assessment
    print("\n" + "─" * 80)
    print("1. QUANTUM THREAT RISK ASSESSMENT")
    print("─" * 80)
    
    # Scenario: Financial services firm with 10-year data retention
    threat_model = QuantumThreatModel(
        data_shelf_life_years=10,      # Financial records retention
        migration_duration_years=5,     # Conservative estimate
        qday_estimate_year=2030,
        hndl_exposure_years=2,          # Assume 2 years of captured traffic
        is_state_actor_target=True      # Financial sector = high-value target
    )
    
    risk_assessment = threat_model.calculate_risk_score()
    print(f"\nOrganization Profile: Financial Services (State Actor Target)")
    print(f"Risk Assessment Equation: {risk_assessment['equation']}")
    print(f"\nUrgency Score: {risk_assessment['urgency_score']}")
    print(f"Risk Level: {risk_assessment['risk_level']}")
    print(f"Recommendation: {risk_assessment['recommendation']}")
    print(f"\nCritical Dates:")
    for date_name, date_value in risk_assessment['critical_dates'].items():
        print(f"  • {date_name}: {date_value}")
    
    # 2. Asset Prioritization
    print("\n" + "─" * 80)
    print("2. CRYPTOGRAPHIC ASSET PRIORITIZATION")
    print("─" * 80)
    
    matrix = CryptoAssetRiskMatrix()
    
    # Sample assets
    assets_to_assess = [
        ("Customer Portal TLS", 5, 5, 5, 4, 2, "internet_facing"),
        ("Internal API Gateway", 4, 3, 4, 3, 2, "dmz"),
        ("Database Encryption (TDE)", 5, 5, 5, 4, 3, "internal_network"),
        ("Email S/MIME", 3, 3, 3, 3, 4, "internal_network"),
        ("Development Environment", 2, 1, 2, 2, 2, "internal_network")
    ]
    
    print("\nAsset Migration Priority Matrix:")
    print(f"{'Asset':<30} {'Score':<10} {'Tier':<25} {'Timeline':<15}")
    print("─" * 80)
    
    for asset_data in assets_to_assess:
        result = matrix.calculate_priority(
            asset_name=asset_data[0],
            data_sensitivity=asset_data[1],
            retention_period=asset_data[2],
            system_criticality=asset_data[3],
            crypto_agility=asset_data[4],
            vendor_dependency=asset_data[5],
            exposure_type=asset_data[6]
        )
        print(f"{result['asset']:<30} {result['priority_score']:<10.1f} "
              f"{result['migration_tier']:<25} {result['target_timeline']:<15}")
    
    # 3. Migration Plan
    print("\n" + "─" * 80)
    print("3. MIGRATION ROADMAP")
    print("─" * 80)
    
    plan = CorporateMigrationPlan(
        organization_name="Example Financial Corp",
        organization_size="medium",
        start_year=2025
    )
    
    summary = plan.get_timeline_summary()
    print(f"\nOrganization: {summary['organization']}")
    print(f"Total Estimated Budget: ${summary['total_estimated_budget_usd']:,.0f}")
    print(f"Peak FTE Requirement: {summary['peak_fte_requirement']:.1f}")
    
    print("\nPhase Timeline:")
    print(f"{'Phase':<40} {'Start':<12} {'End':<12} {'Duration':<10}")
    print("─" * 80)
    
    for phase in summary['phases']:
        print(f"{phase['name']:<40} {phase['start']:<12} {phase['end']:<12} "
              f"{phase['duration_months']} months")
    
    # 4. Infrastructure Specifications
    print("\n" + "─" * 80)
    print("4. HSM VENDOR COMPARISON")
    print("─" * 80)
    
    hsm_comparison = InfrastructureSpec.get_hsm_comparison()
    print(f"\n{'Vendor':<15} {'Model':<25} {'FIPS':<20} {'Cost':<12}")
    print("─" * 80)
    
    for hsm in hsm_comparison:
        print(f"{hsm['vendor']:<15} {hsm['model']:<25} "
              f"{hsm['fips']:<20} ${hsm['cost_usd']:,}")
    
    # 5. Compliance Status
    print("\n" + "─" * 80)
    print("5. COMPLIANCE REQUIREMENTS")
    print("─" * 80)
    
    compliance = GovernanceFramework.get_compliance_checklist()
    print(f"\n{'Standard':<15} {'Requirement':<15} {'Deadline':<15} {'Description':<35}")
    print("─" * 80)
    
    for req in compliance:
        desc = req['description'][:32] + "..." if len(req['description']) > 35 else req['description']
        print(f"{req['standard']:<15} {req['requirement']:<15} "
              f"{req['deadline']:<15} {desc:<35}")
    
    print("\n" + "=" * 80)
    print("FRAMEWORK DEMONSTRATION COMPLETE")
    print("=" * 80)
    
    return {
        "risk_assessment": risk_assessment,
        "migration_summary": summary,
        "hsm_options": hsm_comparison,
        "compliance_status": compliance
    }


if __name__ == "__main__":
    demonstrate_framework()
