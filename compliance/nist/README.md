# NIST Compliance Artifacts

## FIPS Standards

- **FIPS 203**: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)
- **FIPS 204**: Module-Lattice-Based Digital Signature Algorithm (ML-DSA)
- **FIPS 205**: Stateless Hash-Based Digital Signature Algorithm (SLH-DSA)

## Special Publications

- **SP 800-208**: Recommendation for Stateful Hash-Based Signature Schemes
- **SP 800-56C**: Recommendation for Key-Derivation Methods in 
Key-Establishment Schemes

## Compliance Matrix

| Layer | NIST Standard | Implementation | Status |
|-------|---------------|----------------|--------|
| 1 | FIPS 204 | ML-DSA-87 auth | ✅ |
| 2 | FIPS 204 | ML-DSA-87 tokens | ✅ |
| 3 | FIPS 203 | ML-KEM-1024 TLS | ✅ |
| 4 | FIPS 203 | ML-KEM-1024 envelope | ✅ |
| 5 | FIPS 204 | ML-DSA-87 audit | ✅ |
| 6 | FIPS 204 | ML-DSA-87 FHIR | ✅ |
| 7 | FIPS 204 | ML-DSA-87 healing | ✅ |
| 8 | FIPS 203/204/205 | All PQC algorithms | ✅ |
