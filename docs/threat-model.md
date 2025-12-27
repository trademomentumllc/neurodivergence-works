# Threat Model - Eight-Layer Architecture

## Threat Actors

### 1. Classical Adversary
**Capabilities**: Unlimited classical computing power, network access
**Attacks**: Brute force, cryptanalysis, network interception
**Defenses**: AES-256, RSA-4096, ECDH-P384, SHA-384

### 2. Quantum Adversary (Present)
**Capabilities**: Small-scale quantum computers (50-100 qubits)
**Attacks**: Limited Shor's algorithm implementation, Grover search
**Defenses**: Hybrid cryptography maintains classical security

### 3. Quantum Adversary (Future - Post Q-Day)
**Capabilities**: Cryptographically Relevant Quantum Computer (CRQC)
**Attacks**: Shor's algorithm (breaks RSA/ECDH), Grover's algorithm 
(weakens hashes)
**Defenses**: ML-KEM-1024, ML-DSA-87, SLH-DSA-256f, SHA3-384

### 4. Harvest-Now-Decrypt-Later (HNDL)
**Capabilities**: Store encrypted data now, decrypt when quantum computers 
available
**Attacks**: Passive interception and storage
**Defenses**: Layer 8 PQC ensures future quantum adversary cannot decrypt

## Attack Vectors by Layer

[... continue with detailed attack analysis per layer ...]
