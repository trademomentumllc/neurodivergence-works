-- Layer 5: Database Security with Quantum-Resistant Audit Chain
-- PostgreSQL Row-Level Security with ML-DSA-87 signatures

CREATE TABLE patient_records_v2 (
    record_id UUID PRIMARY KEY,
    patient_id UUID NOT NULL,
    data_encrypted BYTEA NOT NULL,
    dek_classical BYTEA NOT NULL,
    dek_pqc_ct BYTEA NOT NULL,
    dek_pqc_ss_xor BYTEA NOT NULL,
    
    -- Quantum-resistant audit chain
    audit_state_hash BYTEA NOT NULL,
    audit_state_signature BYTEA NOT NULL,
    previous_audit_hash BYTEA,
    
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID NOT NULL,
    
    CONSTRAINT valid_audit_chain CHECK (
        LENGTH(audit_state_hash) = 48 AND
        LENGTH(audit_state_signature) = 4627
    )
);

-- [CONTINUE WITH RLS POLICIES FROM ARCHITECTURE.MD]
