# Layer 2: Quantum-Resistant Authorization

A production-ready Go implementation of Role-Based Access Control (RBAC) with hybrid post-quantum cryptographic capability tokens.

## Overview

This package provides quantum-resistant authorization using ML-DSA-87 (FIPS 204) signatures combined with classical HMAC-SHA256 for defense-in-depth security. It implements capability-based tokens with built-in replay attack prevention and comprehensive RBAC support.

## Features

- **Hybrid Cryptography**: Combines classical HMAC-SHA256 with ML-DSA-87 post-quantum signatures
- **RBAC Support**: Full role-based access control with flexible permission management
- **Replay Attack Prevention**: Cryptographic nonces prevent token reuse
- **Token Expiration**: Time-based token lifecycle management
- **Thread-Safe**: Concurrent access protection with read-write locks
- **Memory Efficient**: Automatic cleanup of expired nonces
- **Production-Ready**: Comprehensive error handling and validation

## Security Primitives

### ML-DSA-87 (Module-Lattice-Based Digital Signature Algorithm)
- **Security Level**: NIST Level 5 (equivalent to AES-256)
- **Public Key Size**: 2,592 bytes
- **Private Key Size**: 4,896 bytes
- **Signature Size**: 4,627 bytes
- **Security Basis**: Learning With Errors (LWE) problem on lattices

### Classical MAC
- **Algorithm**: HMAC-SHA256
- **Key Size**: 256 bits
- **Output Size**: 256 bits

### Nonce Generation
- **Source**: crypto/rand (cryptographically secure PRNG)
- **Size**: 256 bits
- **Purpose**: Replay attack prevention

## Installation

```bash
go get github.com/TradeMomentumLLC/eight-layer-pqc/layer2_authz
```

## Quick Start

```go
package main

import (
    "fmt"
    "time"

    "github.com/TradeMomentumLLC/eight-layer-pqc/layer2_authz"
)

func main() {
    // Create authorization manager
    am, err := authorization.NewAuthorizationManager()
    if err != nil {
        panic(err)
    }

    // Define roles
    am.AddRole("user", "Standard User", []string{"read", "list"})
    am.AddRole("admin", "Administrator", []string{"*"})

    // Generate capability token
    token, err := am.GenerateToken("user", "arn:aws:s3:::mybucket/myobject", 1*time.Hour)
    if err != nil {
        panic(err)
    }

    // Validate and check permissions
    if err := am.CheckCapability(token, "read"); err != nil {
        fmt.Println("Access denied")
    } else {
        fmt.Println("Access granted")
    }
}
```

## Architecture

### Token Structure

```go
type HybridCapabilityToken struct {
    RoleID       string      // User's role identifier
    ResourceARN  string      // Target resource identifier
    Expiry       time.Time   // Token expiration timestamp
    Nonce        [32]byte    // Unique nonce for replay prevention
    ClassicalMAC [32]byte    // HMAC-SHA256 signature
    PQCSignature []byte      // ML-DSA-87 signature (4,627 bytes)
}
```

### Security Flow

1. **Token Generation**:
   - Generate cryptographically secure 256-bit nonce
   - Serialize token data (role, resource, expiry, nonce)
   - Compute HMAC-SHA256 over serialized data
   - Generate ML-DSA-87 signature over serialized data
   - Store nonce for replay prevention

2. **Token Validation**:
   - Check token expiration
   - Verify nonce hasn't been reused (replay check)
   - Verify HMAC-SHA256 signature (constant-time comparison)
   - Verify ML-DSA-87 signature (quantum-resistant)
   - Return validation result

3. **Capability Checking**:
   - Validate token cryptographically
   - Retrieve role from token
   - Check if role has required permission
   - Grant or deny access

## API Reference

### Creating a Manager

```go
// Create new manager with fresh keys
am, err := authorization.NewAuthorizationManager()

// Create manager with existing keys (for key persistence)
am, err := authorization.NewAuthorizationManagerWithKeys(publicKey, privateKey, hmacKey)
```

### Role Management

```go
// Add a role with permissions
am.AddRole("engineer", "Data Engineer", []string{"read", "write", "query"})

// Retrieve a role
role, err := am.GetRole("engineer")

// Wildcard permission (admin)
am.AddRole("admin", "Administrator", []string{"*"})
```

### Token Operations

```go
// Generate token (1 hour TTL)
token, err := am.GenerateToken("engineer", "arn:aws:s3:::data/raw", 1*time.Hour)

// Validate token
err := am.ValidateToken(token)

// Check specific permission
err := am.CheckCapability(token, "write")

// Revoke token (prevent reuse)
am.RevokeToken(token)
```

### Key Management

```go
// Export keys for persistence
publicKey, err := am.GetPublicKey()
privateKey, err := am.GetPrivateKey()
hmacKey := am.GetHMACKey()

// Store keys securely (e.g., AWS KMS, HashiCorp Vault)
```

### Monitoring

```go
// Get statistics
stats := am.GetStats()
fmt.Printf("Active tokens: %d\n", stats.ActiveNonces)
fmt.Printf("Expired tokens: %d\n", stats.ExpiredNonces)
fmt.Printf("Total roles: %d\n", stats.TotalRoles)
```

## Error Handling

The package defines specific error types for different failure modes:

```go
var (
    ErrInvalidToken      = errors.New("invalid token")
    ErrExpiredToken      = errors.New("token expired")
    ErrInvalidSignature  = errors.New("invalid PQC signature")
    ErrInvalidMAC        = errors.New("invalid classical MAC")
    ErrNonceReused       = errors.New("nonce reused - replay attack detected")
    ErrInsufficientPerms = errors.New("insufficient permissions")
    ErrRoleNotFound      = errors.New("role not found")
    ErrInvalidNonce      = errors.New("invalid nonce")
)
```

## Performance

Benchmarks on Intel Xeon @ 2.60GHz:

| Operation | Time/op | Memory/op | Allocs/op |
|-----------|---------|-----------|-----------|
| Token Generation | 234.6 µs | 6,437 B | 17 |
| Token Validation | 36.0 µs | 1,224 B | 15 |
| Capability Check | 36.0 µs | 1,224 B | 15 |

- **Token Generation**: ~4,270 ops/sec
- **Token Validation**: ~27,750 ops/sec
- **Capability Check**: ~27,800 ops/sec

## Security Considerations

### Threat Model

The implementation protects against:
- **Quantum Computer Attacks**: ML-DSA-87 provides post-quantum security
- **Classical Cryptanalysis**: HMAC-SHA256 provides immediate classical security
- **Replay Attacks**: Nonce tracking prevents token reuse
- **Token Forgery**: Dual signatures prevent unauthorized token creation
- **Timing Attacks**: Constant-time MAC comparison prevents timing side-channels

### Key Management

- **Key Generation**: Uses `crypto/rand` for cryptographically secure randomness
- **Key Storage**: Keys should be stored in Hardware Security Modules (HSMs) or key management services
- **Key Rotation**: Implement regular key rotation policies
- **Key Separation**: Public/private keys can be distributed across services

### Nonce Management

- **In-Memory Tracking**: Current implementation uses in-memory map
- **Distributed Systems**: For multi-instance deployments, use shared storage (Redis, DynamoDB)
- **Cleanup**: Automatic cleanup every hour removes nonces older than 24 hours
- **Collision Resistance**: 256-bit nonces provide 2^256 collision resistance

### Token Lifetime

- **Default TTL**: Configure based on use case (minutes to hours)
- **Expiration Checking**: Tokens are validated before use
- **Early Revocation**: Tokens can be revoked before expiration
- **Grace Period**: No grace period - expired tokens are immediately invalid

## Production Deployment

### Key Persistence

```go
// Export keys on startup
publicKey, _ := am.GetPublicKey()
privateKey, _ := am.GetPrivateKey()
hmacKey := am.GetHMACKey()

// Store in KMS/Vault
kms.Store("pqc-public-key", publicKey)
kms.Store("pqc-private-key", privateKey)
kms.Store("hmac-key", hmacKey)

// Load keys on subsequent startups
publicKey := kms.Retrieve("pqc-public-key")
privateKey := kms.Retrieve("pqc-private-key")
hmacKey := kms.Retrieve("hmac-key")

am, _ := authorization.NewAuthorizationManagerWithKeys(publicKey, privateKey, hmacKey)
```

### Distributed Nonce Tracking

For multi-instance deployments, replace in-memory nonce storage with distributed storage:

```go
// Pseudo-code for Redis integration
func (am *AuthorizationManager) GenerateToken(...) {
    // ... generate nonce ...

    // Store in Redis with TTL
    redis.Set(fmt.Sprintf("nonce:%x", nonce), token.Expiry, token.Expiry.Sub(time.Now()))

    // ... continue token generation ...
}

func (am *AuthorizationManager) ValidateToken(token *HybridCapabilityToken) error {
    // Check Redis for nonce
    exists := redis.Exists(fmt.Sprintf("nonce:%x", token.Nonce))
    if !exists {
        return ErrInvalidNonce
    }

    // ... continue validation ...
}
```

### Monitoring and Alerting

```go
// Periodic health checks
ticker := time.NewTicker(1 * time.Minute)
for range ticker.C {
    stats := am.GetStats()

    // Alert on excessive expired tokens (possible attack)
    if stats.ExpiredNonces > 10000 {
        alerting.Send("High expired token count: possible attack")
    }

    // Metrics export
    metrics.Gauge("authz.active_tokens", stats.ActiveNonces)
    metrics.Gauge("authz.total_roles", stats.TotalRoles)
}
```

## Testing

Run comprehensive test suite:

```bash
# Unit tests
go test -v ./layer2_authz/

# Benchmarks
go test -bench=. -benchmem ./layer2_authz/

# Coverage
go test -cover ./layer2_authz/
```

## Dependencies

- **github.com/cloudflare/circl**: Cloudflare's cryptographic library implementing FIPS 204 ML-DSA
- **crypto/**: Go standard library cryptographic primitives

## License

See repository LICENSE file.

## References

- [FIPS 204: Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Cloudflare CIRCL Library](https://github.com/cloudflare/circl)
- [RFC 2104: HMAC](https://www.rfc-editor.org/rfc/rfc2104)

## Support

For issues and questions, please open an issue on the GitHub repository.
