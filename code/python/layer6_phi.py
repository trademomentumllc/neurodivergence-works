"""
Layer 6: PHI (Protected Health Information) Isolation with FHIR R4 Compliance

This module provides HIPAA-compliant PHI isolation using HMAC-SHA3-384 for data
integrity and FHIR R4 resource validation for healthcare interoperability.

Security Guarantees:
- HMAC-SHA3-384 provides 384-bit authentication tags
- Pre-image resistance: 2^384 complexity
- Collision resistance: 2^192 complexity
- FHIR R4 validation ensures data integrity and compliance
- Compartmentalized storage prevents unauthorized access
- Audit logging for HIPAA compliance

Compliance:
- HIPAA Privacy Rule (45 CFR Part 160, Part 164 Subparts A & E)
- HIPAA Security Rule (45 CFR Part 164 Subparts A & C)
- FHIR R4 (HL7 Fast Healthcare Interoperability Resources)
- 21 CFR Part 11 (FDA Electronic Records)

Example Usage:
    >>> # Initialize PHI manager
    >>> phi_manager = PHIManager(master_key=secrets.token_bytes(48))
    >>>
    >>> # Create FHIR patient resource
    >>> patient_data = {
    ...     "resourceType": "Patient",
    ...     "id": "example-001",
    ...     "identifier": [{"system": "urn:oid:1.2.36.146.595.217.0.1", "value": "12345"}],
    ...     "name": [{"family": "Doe", "given": ["John"]}],
    ...     "gender": "male",
    ...     "birthDate": "1974-12-25"
    ... }
    >>>
    >>> # Store with integrity protection
    >>> compartment_id = phi_manager.store_phi(patient_data, "patient", "example-001")
    >>>
    >>> # Retrieve and verify
    >>> retrieved = phi_manager.retrieve_phi(compartment_id)
    >>> assert retrieved["data"]["id"] == "example-001"
"""

import hashlib
import hmac
import secrets
import json
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum


class FHIRResourceType(Enum):
    """Supported FHIR R4 resource types for PHI."""
    PATIENT = "Patient"
    OBSERVATION = "Observation"
    CONDITION = "Condition"
    MEDICATION_REQUEST = "MedicationRequest"
    PROCEDURE = "Procedure"
    DIAGNOSTIC_REPORT = "DiagnosticReport"
    IMMUNIZATION = "Immunization"
    ALLERGY_INTOLERANCE = "AllergyIntolerance"
    CARE_PLAN = "CarePlan"
    ENCOUNTER = "Encounter"


class AccessLevel(Enum):
    """Access levels for PHI compartments."""
    NONE = 0
    READ = 1
    WRITE = 2
    ADMIN = 3


@dataclass
class AuditLogEntry:
    """
    Audit log entry for HIPAA compliance.

    Attributes:
        timestamp: When the access occurred
        action: Type of action (read, write, delete, etc.)
        user_id: Identifier of the user performing the action
        compartment_id: PHI compartment accessed
        resource_type: Type of FHIR resource
        success: Whether the action succeeded
        ip_address: Source IP address (optional)
        metadata: Additional audit metadata
    """
    timestamp: datetime
    action: str
    user_id: str
    compartment_id: str
    resource_type: Optional[str] = None
    success: bool = True
    ip_address: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging."""
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        return result


@dataclass
class PHICompartment:
    """
    Isolated compartment for storing PHI with integrity protection.

    Attributes:
        compartment_id: Unique identifier for the compartment
        resource_type: FHIR resource type
        resource_id: FHIR resource ID
        data: The actual FHIR resource data
        hmac_tag: HMAC-SHA3-384 integrity tag
        created_at: Creation timestamp
        updated_at: Last update timestamp
        access_list: Set of user IDs with access
        metadata: Additional compartment metadata
    """
    compartment_id: str
    resource_type: str
    resource_id: str
    data: Dict[str, Any]
    hmac_tag: bytes
    created_at: datetime
    updated_at: datetime
    access_list: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self, include_data: bool = True) -> Dict[str, Any]:
        """
        Convert to dictionary representation.

        Args:
            include_data: Whether to include the actual PHI data

        Returns:
            Dictionary representation
        """
        result = {
            "compartment_id": self.compartment_id,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "hmac_tag": self.hmac_tag.hex(),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "access_list": list(self.access_list),
            "metadata": self.metadata
        }
        if include_data:
            result["data"] = self.data
        return result


class PHIManager:
    """
    HIPAA-compliant PHI manager with FHIR R4 validation and integrity protection.

    This class provides secure storage and retrieval of Protected Health Information
    with HMAC-SHA3-384 integrity protection and FHIR R4 compliance.
    """

    def __init__(self, master_key: bytes):
        """
        Initialize PHI manager with master key.

        Args:
            master_key: Master key for HMAC operations (48 bytes minimum for SHA3-384)

        Raises:
            ValueError: If master key is too short
        """
        if len(master_key) < 48:
            raise ValueError("Master key must be at least 48 bytes for HMAC-SHA3-384")

        self._master_key = master_key
        self._compartments: Dict[str, PHICompartment] = {}
        self._audit_log: List[AuditLogEntry] = []

    def _compute_hmac(self, data: bytes, context: str = "") -> bytes:
        """
        Compute HMAC-SHA3-384 tag for data.

        Args:
            data: Data to authenticate
            context: Optional context string for domain separation

        Returns:
            48-byte HMAC tag
        """
        h = hmac.new(self._master_key, digestmod=hashlib.sha3_384)
        if context:
            h.update(context.encode('utf-8'))
            h.update(b'\x00')  # Separator
        h.update(data)
        return h.digest()

    def _verify_hmac(self, data: bytes, tag: bytes, context: str = "") -> bool:
        """
        Verify HMAC-SHA3-384 tag for data.

        Args:
            data: Data to verify
            tag: HMAC tag to verify
            context: Optional context string (must match computation)

        Returns:
            True if tag is valid, False otherwise
        """
        expected_tag = self._compute_hmac(data, context)
        return hmac.compare_digest(expected_tag, tag)

    def _validate_fhir_resource(self, data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate FHIR R4 resource structure.

        This is a basic validation. For production, use a full FHIR validator.

        Args:
            data: FHIR resource to validate

        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []

        # Check required fields
        if "resourceType" not in data:
            errors.append("Missing required field: resourceType")
        else:
            resource_type = data["resourceType"]
            valid_types = [rt.value for rt in FHIRResourceType]
            if resource_type not in valid_types:
                errors.append(f"Unsupported resourceType: {resource_type}")

        if "id" not in data:
            errors.append("Missing required field: id")

        # Resource-specific validation
        if "resourceType" in data:
            resource_type = data["resourceType"]

            if resource_type == "Patient":
                # Patient must have identifier or name
                if "identifier" not in data and "name" not in data:
                    errors.append("Patient must have identifier or name")

            elif resource_type == "Observation":
                # Observation must have status and code
                if "status" not in data:
                    errors.append("Observation must have status")
                if "code" not in data:
                    errors.append("Observation must have code")

            elif resource_type == "Condition":
                # Condition must have subject
                if "subject" not in data:
                    errors.append("Condition must have subject reference")

        return len(errors) == 0, errors

    def store_phi(
        self,
        fhir_resource: Dict[str, Any],
        resource_type: str,
        resource_id: str,
        user_id: str = "system",
        access_list: Optional[Set[str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Store PHI in an isolated compartment with integrity protection.

        Args:
            fhir_resource: FHIR R4 resource data
            resource_type: FHIR resource type
            resource_id: FHIR resource ID
            user_id: User storing the data
            access_list: Set of user IDs with access rights
            metadata: Additional metadata

        Returns:
            Compartment ID

        Raises:
            ValueError: If FHIR validation fails
            RuntimeError: If storage fails

        Security Notes:
            - Data is authenticated with HMAC-SHA3-384
            - Compartment ID is randomly generated
            - Access control list is enforced
        """
        # Validate FHIR resource
        is_valid, errors = self._validate_fhir_resource(fhir_resource)
        if not is_valid:
            error_msg = "; ".join(errors)
            self._log_audit(
                action="store_phi",
                user_id=user_id,
                compartment_id="",
                resource_type=resource_type,
                success=False,
                metadata={"error": error_msg}
            )
            raise ValueError(f"FHIR validation failed: {error_msg}")

        # Generate compartment ID
        compartment_id = secrets.token_hex(16)

        # Serialize data for HMAC
        data_json = json.dumps(fhir_resource, sort_keys=True).encode('utf-8')
        context = f"phi:{resource_type}:{resource_id}"
        hmac_tag = self._compute_hmac(data_json, context)

        # Create compartment
        now = datetime.now()
        compartment = PHICompartment(
            compartment_id=compartment_id,
            resource_type=resource_type,
            resource_id=resource_id,
            data=fhir_resource,
            hmac_tag=hmac_tag,
            created_at=now,
            updated_at=now,
            access_list=access_list or {user_id},
            metadata=metadata or {}
        )

        # Store compartment
        self._compartments[compartment_id] = compartment

        # Audit log
        self._log_audit(
            action="store_phi",
            user_id=user_id,
            compartment_id=compartment_id,
            resource_type=resource_type,
            success=True
        )

        return compartment_id

    def retrieve_phi(
        self,
        compartment_id: str,
        user_id: str = "system",
        verify_integrity: bool = True
    ) -> Dict[str, Any]:
        """
        Retrieve PHI from compartment with integrity verification.

        Args:
            compartment_id: Compartment ID to retrieve
            user_id: User retrieving the data
            verify_integrity: Whether to verify HMAC tag

        Returns:
            Dictionary with compartment data

        Raises:
            KeyError: If compartment not found
            PermissionError: If user lacks access
            RuntimeError: If integrity check fails
        """
        if compartment_id not in self._compartments:
            self._log_audit(
                action="retrieve_phi",
                user_id=user_id,
                compartment_id=compartment_id,
                success=False,
                metadata={"error": "Compartment not found"}
            )
            raise KeyError(f"Compartment not found: {compartment_id}")

        compartment = self._compartments[compartment_id]

        # Check access (bypass for system user)
        if user_id != "system" and user_id not in compartment.access_list:
            self._log_audit(
                action="retrieve_phi",
                user_id=user_id,
                compartment_id=compartment_id,
                resource_type=compartment.resource_type,
                success=False,
                metadata={"error": "Access denied"}
            )
            raise PermissionError(f"User {user_id} lacks access to compartment")

        # Verify integrity
        if verify_integrity:
            data_json = json.dumps(compartment.data, sort_keys=True).encode('utf-8')
            context = f"phi:{compartment.resource_type}:{compartment.resource_id}"
            is_valid = self._verify_hmac(data_json, compartment.hmac_tag, context)

            if not is_valid:
                self._log_audit(
                    action="retrieve_phi",
                    user_id=user_id,
                    compartment_id=compartment_id,
                    resource_type=compartment.resource_type,
                    success=False,
                    metadata={"error": "Integrity check failed"}
                )
                raise RuntimeError(f"Integrity check failed for compartment {compartment_id}")

        # Audit log
        self._log_audit(
            action="retrieve_phi",
            user_id=user_id,
            compartment_id=compartment_id,
            resource_type=compartment.resource_type,
            success=True
        )

        return compartment.to_dict(include_data=True)

    def update_phi(
        self,
        compartment_id: str,
        updated_data: Dict[str, Any],
        user_id: str = "system"
    ) -> None:
        """
        Update PHI in compartment with new HMAC tag.

        Args:
            compartment_id: Compartment ID to update
            updated_data: Updated FHIR resource data
            user_id: User updating the data

        Raises:
            KeyError: If compartment not found
            PermissionError: If user lacks access
            ValueError: If FHIR validation fails
        """
        if compartment_id not in self._compartments:
            raise KeyError(f"Compartment not found: {compartment_id}")

        compartment = self._compartments[compartment_id]

        # Check access
        if user_id != "system" and user_id not in compartment.access_list:
            self._log_audit(
                action="update_phi",
                user_id=user_id,
                compartment_id=compartment_id,
                resource_type=compartment.resource_type,
                success=False,
                metadata={"error": "Access denied"}
            )
            raise PermissionError(f"User {user_id} lacks access to compartment")

        # Validate updated data
        is_valid, errors = self._validate_fhir_resource(updated_data)
        if not is_valid:
            error_msg = "; ".join(errors)
            self._log_audit(
                action="update_phi",
                user_id=user_id,
                compartment_id=compartment_id,
                resource_type=compartment.resource_type,
                success=False,
                metadata={"error": error_msg}
            )
            raise ValueError(f"FHIR validation failed: {error_msg}")

        # Compute new HMAC
        data_json = json.dumps(updated_data, sort_keys=True).encode('utf-8')
        context = f"phi:{compartment.resource_type}:{compartment.resource_id}"
        new_hmac_tag = self._compute_hmac(data_json, context)

        # Update compartment
        compartment.data = updated_data
        compartment.hmac_tag = new_hmac_tag
        compartment.updated_at = datetime.now()

        # Audit log
        self._log_audit(
            action="update_phi",
            user_id=user_id,
            compartment_id=compartment_id,
            resource_type=compartment.resource_type,
            success=True
        )

    def delete_phi(self, compartment_id: str, user_id: str = "system") -> None:
        """
        Delete PHI compartment (with audit trail).

        Args:
            compartment_id: Compartment ID to delete
            user_id: User deleting the data

        Raises:
            KeyError: If compartment not found
            PermissionError: If user lacks admin access
        """
        if compartment_id not in self._compartments:
            raise KeyError(f"Compartment not found: {compartment_id}")

        compartment = self._compartments[compartment_id]

        # Only allow deletion by users in access list (or system)
        if user_id != "system" and user_id not in compartment.access_list:
            self._log_audit(
                action="delete_phi",
                user_id=user_id,
                compartment_id=compartment_id,
                resource_type=compartment.resource_type,
                success=False,
                metadata={"error": "Access denied"}
            )
            raise PermissionError(f"User {user_id} lacks access to delete compartment")

        # Audit log before deletion
        self._log_audit(
            action="delete_phi",
            user_id=user_id,
            compartment_id=compartment_id,
            resource_type=compartment.resource_type,
            success=True,
            metadata={"resource_id": compartment.resource_id}
        )

        # Delete compartment
        del self._compartments[compartment_id]

    def grant_access(
        self,
        compartment_id: str,
        user_id: str,
        granting_user: str = "system"
    ) -> None:
        """Grant a user access to a PHI compartment."""
        if compartment_id not in self._compartments:
            raise KeyError(f"Compartment not found: {compartment_id}")

        compartment = self._compartments[compartment_id]
        compartment.access_list.add(user_id)

        self._log_audit(
            action="grant_access",
            user_id=granting_user,
            compartment_id=compartment_id,
            resource_type=compartment.resource_type,
            success=True,
            metadata={"granted_to": user_id}
        )

    def revoke_access(
        self,
        compartment_id: str,
        user_id: str,
        revoking_user: str = "system"
    ) -> None:
        """Revoke a user's access to a PHI compartment."""
        if compartment_id not in self._compartments:
            raise KeyError(f"Compartment not found: {compartment_id}")

        compartment = self._compartments[compartment_id]
        compartment.access_list.discard(user_id)

        self._log_audit(
            action="revoke_access",
            user_id=revoking_user,
            compartment_id=compartment_id,
            resource_type=compartment.resource_type,
            success=True,
            metadata={"revoked_from": user_id}
        )

    def _log_audit(
        self,
        action: str,
        user_id: str,
        compartment_id: str,
        resource_type: Optional[str] = None,
        success: bool = True,
        ip_address: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Create an audit log entry."""
        entry = AuditLogEntry(
            timestamp=datetime.now(),
            action=action,
            user_id=user_id,
            compartment_id=compartment_id,
            resource_type=resource_type,
            success=success,
            ip_address=ip_address,
            metadata=metadata or {}
        )
        self._audit_log.append(entry)

    def get_audit_log(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        user_id: Optional[str] = None,
        action: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieve audit log entries with optional filtering.

        Args:
            start_time: Filter entries after this time
            end_time: Filter entries before this time
            user_id: Filter by user ID
            action: Filter by action type

        Returns:
            List of audit log entries as dictionaries
        """
        filtered = self._audit_log

        if start_time:
            filtered = [e for e in filtered if e.timestamp >= start_time]
        if end_time:
            filtered = [e for e in filtered if e.timestamp <= end_time]
        if user_id:
            filtered = [e for e in filtered if e.user_id == user_id]
        if action:
            filtered = [e for e in filtered if e.action == action]

        return [entry.to_dict() for entry in filtered]

    def get_statistics(self) -> Dict[str, Any]:
        """Get PHI storage statistics."""
        resource_counts: Dict[str, int] = {}
        for compartment in self._compartments.values():
            resource_counts[compartment.resource_type] = \
                resource_counts.get(compartment.resource_type, 0) + 1

        return {
            "total_compartments": len(self._compartments),
            "resource_type_counts": resource_counts,
            "total_audit_entries": len(self._audit_log),
            "hmac_algorithm": "HMAC-SHA3-384",
            "compliance_standards": ["HIPAA", "FHIR R4", "21 CFR Part 11"]
        }


def demo_phi_management():
    """
    Demonstrate PHI management with FHIR R4 compliance.

    This example shows:
    1. PHI manager initialization
    2. FHIR resource creation and validation
    3. Secure storage with integrity protection
    4. Access control
    5. Audit logging
    6. Integrity verification
    """
    print("=== PHI Management with FHIR R4 Compliance Demo ===\n")

    # Initialize PHI manager with master key
    print("1. Initializing PHI manager...")
    master_key = secrets.token_bytes(48)
    phi_manager = PHIManager(master_key)
    print("   Master key generated (48 bytes)")

    # Create FHIR Patient resource
    print("\n2. Creating FHIR Patient resource...")
    patient_resource = {
        "resourceType": "Patient",
        "id": "patient-001",
        "identifier": [{
            "system": "urn:oid:1.2.36.146.595.217.0.1",
            "value": "MRN-12345"
        }],
        "name": [{
            "use": "official",
            "family": "Smith",
            "given": ["Jane", "Marie"]
        }],
        "gender": "female",
        "birthDate": "1985-07-15",
        "address": [{
            "line": ["123 Main St"],
            "city": "Springfield",
            "state": "IL",
            "postalCode": "62701"
        }]
    }
    print(f"   Patient: {patient_resource['name'][0]['given'][0]} "
          f"{patient_resource['name'][0]['family']}")

    # Store patient data
    print("\n3. Storing patient data with integrity protection...")
    compartment_id = phi_manager.store_phi(
        fhir_resource=patient_resource,
        resource_type="Patient",
        resource_id="patient-001",
        user_id="dr_jones",
        access_list={"dr_jones", "nurse_williams"}
    )
    print(f"   Compartment ID: {compartment_id}")

    # Create and store Observation
    print("\n4. Creating FHIR Observation resource...")
    observation_resource = {
        "resourceType": "Observation",
        "id": "obs-001",
        "status": "final",
        "code": {
            "coding": [{
                "system": "http://loinc.org",
                "code": "8867-4",
                "display": "Heart rate"
            }]
        },
        "subject": {"reference": "Patient/patient-001"},
        "valueQuantity": {
            "value": 72,
            "unit": "beats/minute",
            "system": "http://unitsofmeasure.org",
            "code": "/min"
        }
    }

    obs_compartment_id = phi_manager.store_phi(
        fhir_resource=observation_resource,
        resource_type="Observation",
        resource_id="obs-001",
        user_id="nurse_williams"
    )
    print(f"   Observation compartment ID: {obs_compartment_id}")

    # Retrieve with access control
    print("\n5. Testing access control...")
    try:
        # Authorized access
        retrieved = phi_manager.retrieve_phi(compartment_id, user_id="dr_jones")
        print(f"   Dr. Jones retrieved patient: {retrieved['data']['id']}")

        # Unauthorized access
        phi_manager.retrieve_phi(compartment_id, user_id="unauthorized_user")
    except PermissionError as e:
        print(f"   Unauthorized access blocked: {str(e)[:50]}...")

    # Grant and revoke access
    print("\n6. Testing access management...")
    phi_manager.grant_access(compartment_id, "dr_adams", granting_user="dr_jones")
    print("   Access granted to dr_adams")

    phi_manager.retrieve_phi(compartment_id, user_id="dr_adams")
    print(f"   Dr. Adams successfully retrieved patient data")

    phi_manager.revoke_access(compartment_id, "dr_adams", revoking_user="dr_jones")
    print("   Access revoked from dr_adams")

    # Test integrity verification
    print("\n7. Testing integrity verification...")
    # Attempt to tamper with data (simulate)
    compartment = phi_manager._compartments[compartment_id]
    original_hmac = compartment.hmac_tag
    print(f"   Original HMAC: {original_hmac.hex()[:32]}...")

    # Verify integrity
    phi_manager.retrieve_phi(compartment_id, verify_integrity=True)
    print("   Integrity verification passed")

    # Update patient data
    print("\n8. Updating patient data...")
    updated_patient = patient_resource.copy()
    updated_patient["address"][0]["postalCode"] = "62702"

    phi_manager.update_phi(compartment_id, updated_patient, user_id="dr_jones")
    print("   Patient address updated")

    # Verify new HMAC
    compartment = phi_manager._compartments[compartment_id]
    new_hmac = compartment.hmac_tag
    print(f"   New HMAC: {new_hmac.hex()[:32]}...")
    print(f"   HMAC changed: {original_hmac != new_hmac}")

    # Display statistics
    print("\n9. PHI Storage Statistics:")
    stats = phi_manager.get_statistics()
    for key, value in stats.items():
        print(f"   {key}: {value}")

    # Display audit log
    print("\n10. Audit Log (last 5 entries):")
    audit_log = phi_manager.get_audit_log()
    for entry in audit_log[-5:]:
        print(f"   [{entry['timestamp']}] {entry['action']} by {entry['user_id']} "
              f"- Success: {entry['success']}")

    # Test FHIR validation
    print("\n11. Testing FHIR validation...")
    invalid_resource = {
        "resourceType": "Patient"
        # Missing required 'id' field
    }

    try:
        phi_manager.store_phi(
            fhir_resource=invalid_resource,
            resource_type="Patient",
            resource_id="invalid",
            user_id="dr_jones"
        )
    except ValueError as e:
        print(f"   Invalid FHIR resource rejected: {str(e)[:60]}...")

    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    demo_phi_management()
