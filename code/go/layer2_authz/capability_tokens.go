package authorization

// Layer 2: Quantum-Resistant Authorization
// RBAC with PQC-signed capability tokens using ML-DSA-87

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// HybridCapabilityToken represents a quantum-resistant authorization token
// combining classical HMAC-SHA256 with ML-DSA-87 post-quantum signatures
type HybridCapabilityToken struct {
	RoleID       string
	ResourceARN  string
	Expiry       time.Time
	Nonce        [32]byte
	ClassicalMAC [32]byte
	PQCSignature []byte
}

// Role represents an RBAC role with associated permissions
type Role struct {
	ID          string
	Name        string
	Permissions []string
}

// AuthorizationManager manages capability tokens and RBAC
type AuthorizationManager struct {
	publicKey    mldsa87.PublicKey
	privateKey   mldsa87.PrivateKey
	hmacKey      []byte
	roles        map[string]*Role
	usedNonces   map[[32]byte]time.Time
	nonceMutex   sync.RWMutex
	nonceCleanup time.Duration
}

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

// NewAuthorizationManager creates a new authorization manager with fresh ML-DSA-87 keys
func NewAuthorizationManager() (*AuthorizationManager, error) {
	// Generate ML-DSA-87 key pair for PQC signatures
	publicKey, privateKey, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ML-DSA-87 key pair: %w", err)
	}

	// Generate 256-bit HMAC key for classical MAC
	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		return nil, fmt.Errorf("failed to generate HMAC key: %w", err)
	}

	am := &AuthorizationManager{
		publicKey:    *publicKey,
		privateKey:   *privateKey,
		hmacKey:      hmacKey,
		roles:        make(map[string]*Role),
		usedNonces:   make(map[[32]byte]time.Time),
		nonceCleanup: 24 * time.Hour, // Clean up nonces older than 24 hours
	}

	// Start nonce cleanup goroutine
	go am.cleanupExpiredNonces()

	return am, nil
}

// NewAuthorizationManagerWithKeys creates a manager with provided keys
func NewAuthorizationManagerWithKeys(publicKey []byte, privateKey []byte, hmacKey []byte) (*AuthorizationManager, error) {
	if len(hmacKey) != 32 {
		return nil, errors.New("HMAC key must be 32 bytes")
	}

	var pubKey mldsa87.PublicKey
	var privKey mldsa87.PrivateKey

	if err := pubKey.UnmarshalBinary(publicKey); err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	if privateKey != nil {
		if err := privKey.UnmarshalBinary(privateKey); err != nil {
			return nil, fmt.Errorf("invalid private key: %w", err)
		}
	}

	am := &AuthorizationManager{
		publicKey:    pubKey,
		privateKey:   privKey,
		hmacKey:      hmacKey,
		roles:        make(map[string]*Role),
		usedNonces:   make(map[[32]byte]time.Time),
		nonceCleanup: 24 * time.Hour,
	}

	go am.cleanupExpiredNonces()

	return am, nil
}

// AddRole adds a new role to the RBAC system
func (am *AuthorizationManager) AddRole(roleID, name string, permissions []string) {
	am.roles[roleID] = &Role{
		ID:          roleID,
		Name:        name,
		Permissions: permissions,
	}
}

// GetRole retrieves a role by ID
func (am *AuthorizationManager) GetRole(roleID string) (*Role, error) {
	role, exists := am.roles[roleID]
	if !exists {
		return nil, ErrRoleNotFound
	}
	return role, nil
}

// GenerateToken creates a new capability token with hybrid PQC+classical signatures
func (am *AuthorizationManager) GenerateToken(roleID, resourceARN string, ttl time.Duration) (*HybridCapabilityToken, error) {
	// Verify role exists
	if _, err := am.GetRole(roleID); err != nil {
		return nil, err
	}

	// Generate cryptographically secure nonce
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Check for nonce collision (extremely unlikely but safety first)
	am.nonceMutex.RLock()
	if _, exists := am.usedNonces[nonce]; exists {
		am.nonceMutex.RUnlock()
		return nil, ErrNonceReused
	}
	am.nonceMutex.RUnlock()

	token := &HybridCapabilityToken{
		RoleID:      roleID,
		ResourceARN: resourceARN,
		Expiry:      time.Now().Add(ttl),
		Nonce:       nonce,
	}

	// Serialize token data for signing
	tokenData := am.serializeTokenData(token)

	// Generate classical HMAC-SHA256
	mac := hmac.New(sha256.New, am.hmacKey)
	mac.Write(tokenData)
	copy(token.ClassicalMAC[:], mac.Sum(nil))

	// Generate ML-DSA-87 signature
	signature, err := am.privateKey.Sign(rand.Reader, tokenData, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("failed to generate ML-DSA-87 signature: %w", err)
	}
	token.PQCSignature = signature

	// Record nonce usage
	am.nonceMutex.Lock()
	am.usedNonces[nonce] = token.Expiry
	am.nonceMutex.Unlock()

	return token, nil
}

// ValidateToken verifies both classical and PQC signatures, checks expiry and nonce
func (am *AuthorizationManager) ValidateToken(token *HybridCapabilityToken) error {
	if token == nil {
		return ErrInvalidToken
	}

	// Check expiration
	if time.Now().After(token.Expiry) {
		return ErrExpiredToken
	}

	// Verify nonce hasn't been reused
	am.nonceMutex.RLock()
	if usedTime, exists := am.usedNonces[token.Nonce]; exists {
		am.nonceMutex.RUnlock()
		// If nonce exists but token is expired, it's a replay attack
		if time.Now().After(usedTime) {
			return ErrNonceReused
		}
	} else {
		am.nonceMutex.RUnlock()
		return ErrInvalidNonce
	}

	// Serialize token data for verification
	tokenData := am.serializeTokenData(token)

	// Verify classical HMAC-SHA256
	expectedMAC := hmac.New(sha256.New, am.hmacKey)
	expectedMAC.Write(tokenData)
	expectedMACBytes := expectedMAC.Sum(nil)

	if subtle.ConstantTimeCompare(token.ClassicalMAC[:], expectedMACBytes) != 1 {
		return ErrInvalidMAC
	}

	// Verify ML-DSA-87 signature (ctx=nil for no context)
	if !mldsa87.Verify(&am.publicKey, tokenData, nil, token.PQCSignature) {
		return ErrInvalidSignature
	}

	return nil
}

// CheckCapability verifies token and checks if role has permission for resource
func (am *AuthorizationManager) CheckCapability(token *HybridCapabilityToken, requiredPermission string) error {
	// First validate the token cryptographically
	if err := am.ValidateToken(token); err != nil {
		return err
	}

	// Get the role
	role, err := am.GetRole(token.RoleID)
	if err != nil {
		return err
	}

	// Check if role has required permission
	for _, perm := range role.Permissions {
		if perm == requiredPermission || perm == "*" {
			return nil
		}
	}

	return ErrInsufficientPerms
}

// RevokeToken removes a nonce from the valid set, effectively revoking the token
func (am *AuthorizationManager) RevokeToken(token *HybridCapabilityToken) {
	am.nonceMutex.Lock()
	delete(am.usedNonces, token.Nonce)
	am.nonceMutex.Unlock()
}

// serializeTokenData creates a canonical binary representation for signing
func (am *AuthorizationManager) serializeTokenData(token *HybridCapabilityToken) []byte {
	buf := new(bytes.Buffer)

	// Write RoleID length and data
	binary.Write(buf, binary.BigEndian, uint32(len(token.RoleID)))
	buf.WriteString(token.RoleID)

	// Write ResourceARN length and data
	binary.Write(buf, binary.BigEndian, uint32(len(token.ResourceARN)))
	buf.WriteString(token.ResourceARN)

	// Write Expiry as Unix timestamp
	binary.Write(buf, binary.BigEndian, token.Expiry.Unix())

	// Write Nonce
	buf.Write(token.Nonce[:])

	return buf.Bytes()
}

// cleanupExpiredNonces periodically removes expired nonces to prevent memory leaks
func (am *AuthorizationManager) cleanupExpiredNonces() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		am.nonceMutex.Lock()
		now := time.Now()
		for nonce, expiry := range am.usedNonces {
			if now.After(expiry.Add(am.nonceCleanup)) {
				delete(am.usedNonces, nonce)
			}
		}
		am.nonceMutex.Unlock()
	}
}

// GetPublicKey returns the ML-DSA-87 public key for distribution
func (am *AuthorizationManager) GetPublicKey() ([]byte, error) {
	return am.publicKey.MarshalBinary()
}

// GetPrivateKey returns the ML-DSA-87 private key (use with caution!)
func (am *AuthorizationManager) GetPrivateKey() ([]byte, error) {
	return am.privateKey.MarshalBinary()
}

// GetHMACKey returns the HMAC key (use with caution!)
func (am *AuthorizationManager) GetHMACKey() []byte {
	key := make([]byte, len(am.hmacKey))
	copy(key, am.hmacKey)
	return key
}

// TokenStats returns statistics about the token manager
type TokenStats struct {
	ActiveNonces  int
	ExpiredNonces int
	TotalRoles    int
}

// GetStats returns current statistics about the authorization manager
func (am *AuthorizationManager) GetStats() TokenStats {
	am.nonceMutex.RLock()
	defer am.nonceMutex.RUnlock()

	now := time.Now()
	active := 0
	expired := 0

	for _, expiry := range am.usedNonces {
		if now.Before(expiry) {
			active++
		} else {
			expired++
		}
	}

	return TokenStats{
		ActiveNonces:  active,
		ExpiredNonces: expired,
		TotalRoles:    len(am.roles),
	}
}
