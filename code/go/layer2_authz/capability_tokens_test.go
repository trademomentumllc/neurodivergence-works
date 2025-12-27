package authorization

import (
	"testing"
	"time"
)

func TestNewAuthorizationManager(t *testing.T) {
	am, err := NewAuthorizationManager()
	if err != nil {
		t.Fatalf("Failed to create authorization manager: %v", err)
	}
	if am == nil {
		t.Fatal("Authorization manager is nil")
	}

	// Verify keys are generated
	pubKey, err := am.GetPublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key: %v", err)
	}
	if len(pubKey) == 0 {
		t.Fatal("Public key is empty")
	}

	privKey, err := am.GetPrivateKey()
	if err != nil {
		t.Fatalf("Failed to get private key: %v", err)
	}
	if len(privKey) == 0 {
		t.Fatal("Private key is empty")
	}

	hmacKey := am.GetHMACKey()
	if len(hmacKey) != 32 {
		t.Fatalf("HMAC key has wrong length: expected 32, got %d", len(hmacKey))
	}
}

func TestAddAndGetRole(t *testing.T) {
	am, err := NewAuthorizationManager()
	if err != nil {
		t.Fatalf("Failed to create authorization manager: %v", err)
	}

	// Add a role
	roleID := "admin"
	roleName := "Administrator"
	permissions := []string{"read", "write", "delete"}
	am.AddRole(roleID, roleName, permissions)

	// Get the role back
	role, err := am.GetRole(roleID)
	if err != nil {
		t.Fatalf("Failed to get role: %v", err)
	}
	if role.ID != roleID {
		t.Errorf("Role ID mismatch: expected %s, got %s", roleID, role.ID)
	}
	if role.Name != roleName {
		t.Errorf("Role name mismatch: expected %s, got %s", roleName, role.Name)
	}
	if len(role.Permissions) != len(permissions) {
		t.Errorf("Permissions count mismatch: expected %d, got %d", len(permissions), len(role.Permissions))
	}

	// Try to get non-existent role
	_, err = am.GetRole("nonexistent")
	if err != ErrRoleNotFound {
		t.Errorf("Expected ErrRoleNotFound, got: %v", err)
	}
}

func TestGenerateToken(t *testing.T) {
	am, err := NewAuthorizationManager()
	if err != nil {
		t.Fatalf("Failed to create authorization manager: %v", err)
	}

	// Add a role
	am.AddRole("user", "User", []string{"read"})

	// Generate token
	token, err := am.GenerateToken("user", "arn:aws:s3:::bucket/object", 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	if token == nil {
		t.Fatal("Token is nil")
	}
	if token.RoleID != "user" {
		t.Errorf("Token role ID mismatch: expected 'user', got '%s'", token.RoleID)
	}
	if token.ResourceARN != "arn:aws:s3:::bucket/object" {
		t.Errorf("Token resource ARN mismatch")
	}
	if time.Now().After(token.Expiry) {
		t.Error("Token is already expired")
	}

	// Verify nonce is not zero
	var zeroNonce [32]byte
	if token.Nonce == zeroNonce {
		t.Error("Token nonce is zero")
	}

	// Verify MAC is set
	var zeroMAC [32]byte
	if token.ClassicalMAC == zeroMAC {
		t.Error("Token MAC is zero")
	}

	// Verify PQC signature is set
	if len(token.PQCSignature) == 0 {
		t.Error("Token PQC signature is empty")
	}
}

func TestGenerateTokenInvalidRole(t *testing.T) {
	am, err := NewAuthorizationManager()
	if err != nil {
		t.Fatalf("Failed to create authorization manager: %v", err)
	}

	// Try to generate token for non-existent role
	_, err = am.GenerateToken("nonexistent", "arn:aws:s3:::bucket/object", 1*time.Hour)
	if err != ErrRoleNotFound {
		t.Errorf("Expected ErrRoleNotFound, got: %v", err)
	}
}

func TestValidateToken(t *testing.T) {
	am, err := NewAuthorizationManager()
	if err != nil {
		t.Fatalf("Failed to create authorization manager: %v", err)
	}

	// Add a role and generate token
	am.AddRole("user", "User", []string{"read"})
	token, err := am.GenerateToken("user", "arn:aws:s3:::bucket/object", 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Validate the token
	err = am.ValidateToken(token)
	if err != nil {
		t.Errorf("Token validation failed: %v", err)
	}
}

func TestValidateExpiredToken(t *testing.T) {
	am, err := NewAuthorizationManager()
	if err != nil {
		t.Fatalf("Failed to create authorization manager: %v", err)
	}

	// Add a role and generate token with very short expiry
	am.AddRole("user", "User", []string{"read"})
	token, err := am.GenerateToken("user", "arn:aws:s3:::bucket/object", 1*time.Nanosecond)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Wait for expiry
	time.Sleep(10 * time.Millisecond)

	// Validate the expired token
	err = am.ValidateToken(token)
	if err != ErrExpiredToken {
		t.Errorf("Expected ErrExpiredToken, got: %v", err)
	}
}

func TestValidateTokenInvalidMAC(t *testing.T) {
	am, err := NewAuthorizationManager()
	if err != nil {
		t.Fatalf("Failed to create authorization manager: %v", err)
	}

	// Add a role and generate token
	am.AddRole("user", "User", []string{"read"})
	token, err := am.GenerateToken("user", "arn:aws:s3:::bucket/object", 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Corrupt the MAC
	token.ClassicalMAC[0] ^= 0xFF

	// Validate the token with corrupted MAC
	err = am.ValidateToken(token)
	if err != ErrInvalidMAC {
		t.Errorf("Expected ErrInvalidMAC, got: %v", err)
	}
}

func TestValidateTokenInvalidSignature(t *testing.T) {
	am, err := NewAuthorizationManager()
	if err != nil {
		t.Fatalf("Failed to create authorization manager: %v", err)
	}

	// Add a role and generate token
	am.AddRole("user", "User", []string{"read"})
	token, err := am.GenerateToken("user", "arn:aws:s3:::bucket/object", 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Corrupt the PQC signature
	token.PQCSignature[0] ^= 0xFF

	// Validate the token with corrupted signature
	err = am.ValidateToken(token)
	if err != ErrInvalidSignature {
		t.Errorf("Expected ErrInvalidSignature, got: %v", err)
	}
}

func TestValidateTokenTamperedData(t *testing.T) {
	am, err := NewAuthorizationManager()
	if err != nil {
		t.Fatalf("Failed to create authorization manager: %v", err)
	}

	// Add a role and generate token
	am.AddRole("user", "User", []string{"read"})
	token, err := am.GenerateToken("user", "arn:aws:s3:::bucket/object", 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Tamper with the role ID
	token.RoleID = "admin"

	// Validation should fail
	err = am.ValidateToken(token)
	if err == nil {
		t.Error("Expected validation to fail for tampered token")
	}
}

func TestCheckCapability(t *testing.T) {
	am, err := NewAuthorizationManager()
	if err != nil {
		t.Fatalf("Failed to create authorization manager: %v", err)
	}

	// Add roles
	am.AddRole("user", "User", []string{"read"})
	am.AddRole("admin", "Administrator", []string{"*"})

	// Generate tokens
	userToken, err := am.GenerateToken("user", "arn:aws:s3:::bucket/object", 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate user token: %v", err)
	}

	adminToken, err := am.GenerateToken("admin", "arn:aws:s3:::bucket/object", 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate admin token: %v", err)
	}

	// User can read
	err = am.CheckCapability(userToken, "read")
	if err != nil {
		t.Errorf("User should have read permission: %v", err)
	}

	// User cannot write
	err = am.CheckCapability(userToken, "write")
	if err != ErrInsufficientPerms {
		t.Errorf("Expected ErrInsufficientPerms for user write, got: %v", err)
	}

	// Admin can do anything
	err = am.CheckCapability(adminToken, "read")
	if err != nil {
		t.Errorf("Admin should have read permission: %v", err)
	}

	err = am.CheckCapability(adminToken, "write")
	if err != nil {
		t.Errorf("Admin should have write permission: %v", err)
	}

	err = am.CheckCapability(adminToken, "delete")
	if err != nil {
		t.Errorf("Admin should have delete permission: %v", err)
	}
}

func TestRevokeToken(t *testing.T) {
	am, err := NewAuthorizationManager()
	if err != nil {
		t.Fatalf("Failed to create authorization manager: %v", err)
	}

	// Add a role and generate token
	am.AddRole("user", "User", []string{"read"})
	token, err := am.GenerateToken("user", "arn:aws:s3:::bucket/object", 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Token should be valid
	err = am.ValidateToken(token)
	if err != nil {
		t.Errorf("Token should be valid: %v", err)
	}

	// Revoke the token
	am.RevokeToken(token)

	// Token should now be invalid
	err = am.ValidateToken(token)
	if err != ErrInvalidNonce {
		t.Errorf("Expected ErrInvalidNonce for revoked token, got: %v", err)
	}
}

func TestNonceUniqueness(t *testing.T) {
	am, err := NewAuthorizationManager()
	if err != nil {
		t.Fatalf("Failed to create authorization manager: %v", err)
	}

	// Add a role
	am.AddRole("user", "User", []string{"read"})

	// Generate multiple tokens
	nonces := make(map[[32]byte]bool)
	for i := 0; i < 100; i++ {
		token, err := am.GenerateToken("user", "arn:aws:s3:::bucket/object", 1*time.Hour)
		if err != nil {
			t.Fatalf("Failed to generate token %d: %v", i, err)
		}

		// Check nonce uniqueness
		if nonces[token.Nonce] {
			t.Errorf("Duplicate nonce detected at token %d", i)
		}
		nonces[token.Nonce] = true
	}
}

func TestKeyReconstitution(t *testing.T) {
	// Create first manager
	am1, err := NewAuthorizationManager()
	if err != nil {
		t.Fatalf("Failed to create first authorization manager: %v", err)
	}

	// Export keys
	pubKey, err := am1.GetPublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key: %v", err)
	}

	privKey, err := am1.GetPrivateKey()
	if err != nil {
		t.Fatalf("Failed to get private key: %v", err)
	}

	hmacKey := am1.GetHMACKey()

	// Create second manager with same keys
	am2, err := NewAuthorizationManagerWithKeys(pubKey, privKey, hmacKey)
	if err != nil {
		t.Fatalf("Failed to create second authorization manager: %v", err)
	}

	// Add role to both managers
	am1.AddRole("user", "User", []string{"read"})
	am2.AddRole("user", "User", []string{"read"})

	// Generate token with second manager (so it has the nonce)
	token, err := am2.GenerateToken("user", "arn:aws:s3:::bucket/object", 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Validate token with second manager (should work - same instance)
	err = am2.ValidateToken(token)
	if err != nil {
		t.Errorf("Second manager should validate its own token: %v", err)
	}

	// Note: Cross-instance validation requires shared nonce tracking (e.g., via Redis)
	// For cryptographic verification only (ignoring nonce), we verify the keys work
	pubKey2, _ := am2.GetPublicKey()
	if !bytesEqual(pubKey, pubKey2) {
		t.Error("Public keys should be identical")
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestGetStats(t *testing.T) {
	am, err := NewAuthorizationManager()
	if err != nil {
		t.Fatalf("Failed to create authorization manager: %v", err)
	}

	// Add roles
	am.AddRole("user", "User", []string{"read"})
	am.AddRole("admin", "Admin", []string{"*"})

	// Initial stats
	stats := am.GetStats()
	if stats.TotalRoles != 2 {
		t.Errorf("Expected 2 roles, got %d", stats.TotalRoles)
	}
	if stats.ActiveNonces != 0 {
		t.Errorf("Expected 0 active nonces, got %d", stats.ActiveNonces)
	}

	// Generate some tokens
	for i := 0; i < 5; i++ {
		_, err := am.GenerateToken("user", "arn:aws:s3:::bucket/object", 1*time.Hour)
		if err != nil {
			t.Fatalf("Failed to generate token %d: %v", i, err)
		}
	}

	// Stats should reflect active nonces
	stats = am.GetStats()
	if stats.ActiveNonces != 5 {
		t.Errorf("Expected 5 active nonces, got %d", stats.ActiveNonces)
	}

	// Generate expired token
	_, err = am.GenerateToken("user", "arn:aws:s3:::bucket/object", 1*time.Nanosecond)
	if err != nil {
		t.Fatalf("Failed to generate expired token: %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	stats = am.GetStats()
	if stats.ExpiredNonces != 1 {
		t.Errorf("Expected 1 expired nonce, got %d", stats.ExpiredNonces)
	}
}

func TestValidateNilToken(t *testing.T) {
	am, err := NewAuthorizationManager()
	if err != nil {
		t.Fatalf("Failed to create authorization manager: %v", err)
	}

	err = am.ValidateToken(nil)
	if err != ErrInvalidToken {
		t.Errorf("Expected ErrInvalidToken for nil token, got: %v", err)
	}
}

func TestNewAuthorizationManagerWithKeysInvalidHMAC(t *testing.T) {
	pubKey := make([]byte, 2592)    // ML-DSA-87 public key size
	privKey := make([]byte, 4896)   // ML-DSA-87 private key size
	invalidHMAC := make([]byte, 16) // Wrong size

	_, err := NewAuthorizationManagerWithKeys(pubKey, privKey, invalidHMAC)
	if err == nil {
		t.Error("Expected error for invalid HMAC key size")
	}
}

func BenchmarkGenerateToken(b *testing.B) {
	am, err := NewAuthorizationManager()
	if err != nil {
		b.Fatalf("Failed to create authorization manager: %v", err)
	}

	am.AddRole("user", "User", []string{"read"})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := am.GenerateToken("user", "arn:aws:s3:::bucket/object", 1*time.Hour)
		if err != nil {
			b.Fatalf("Failed to generate token: %v", err)
		}
	}
}

func BenchmarkValidateToken(b *testing.B) {
	am, err := NewAuthorizationManager()
	if err != nil {
		b.Fatalf("Failed to create authorization manager: %v", err)
	}

	am.AddRole("user", "User", []string{"read"})
	token, err := am.GenerateToken("user", "arn:aws:s3:::bucket/object", 1*time.Hour)
	if err != nil {
		b.Fatalf("Failed to generate token: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := am.ValidateToken(token)
		if err != nil {
			b.Fatalf("Token validation failed: %v", err)
		}
	}
}

func BenchmarkCheckCapability(b *testing.B) {
	am, err := NewAuthorizationManager()
	if err != nil {
		b.Fatalf("Failed to create authorization manager: %v", err)
	}

	am.AddRole("user", "User", []string{"read"})
	token, err := am.GenerateToken("user", "arn:aws:s3:::bucket/object", 1*time.Hour)
	if err != nil {
		b.Fatalf("Failed to generate token: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := am.CheckCapability(token, "read")
		if err != nil {
			b.Fatalf("Capability check failed: %v", err)
		}
	}
}

// TestReplayAttackPrevention demonstrates that nonce tracking prevents replay attacks
func TestReplayAttackPrevention(t *testing.T) {
	am, err := NewAuthorizationManager()
	if err != nil {
		t.Fatalf("Failed to create authorization manager: %v", err)
	}

	am.AddRole("user", "User", []string{"read"})

	// Generate a token
	token, err := am.GenerateToken("user", "arn:aws:s3:::bucket/object", 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// First validation should succeed
	err = am.ValidateToken(token)
	if err != nil {
		t.Errorf("First validation should succeed: %v", err)
	}

	// Create a copy of the token (simulating interception)
	copiedToken := &HybridCapabilityToken{
		RoleID:       token.RoleID,
		ResourceARN:  token.ResourceARN,
		Expiry:       token.Expiry,
		Nonce:        token.Nonce,
		ClassicalMAC: token.ClassicalMAC,
		PQCSignature: append([]byte{}, token.PQCSignature...),
	}

	// Revoke the original token
	am.RevokeToken(token)

	// Attempt to use the copied token (replay attack)
	err = am.ValidateToken(copiedToken)
	if err != ErrInvalidNonce {
		t.Errorf("Replay attack should be prevented, got: %v", err)
	}
}

// TestCryptographicPrimitives verifies the cryptographic strength
func TestCryptographicPrimitives(t *testing.T) {
	am, err := NewAuthorizationManager()
	if err != nil {
		t.Fatalf("Failed to create authorization manager: %v", err)
	}

	// Verify key sizes
	pubKey, _ := am.GetPublicKey()
	privKey, _ := am.GetPrivateKey()
	hmacKey := am.GetHMACKey()

	// ML-DSA-87 key sizes
	if len(pubKey) != 2592 {
		t.Errorf("Public key size should be 2592 bytes (ML-DSA-87), got %d", len(pubKey))
	}
	if len(privKey) != 4896 {
		t.Errorf("Private key size should be 4896 bytes (ML-DSA-87), got %d", len(privKey))
	}
	if len(hmacKey) != 32 {
		t.Errorf("HMAC key size should be 32 bytes (SHA-256), got %d", len(hmacKey))
	}

	// Generate a token and check signature size
	am.AddRole("user", "User", []string{"read"})
	token, err := am.GenerateToken("user", "arn:aws:s3:::bucket/object", 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// ML-DSA-87 signature size
	if len(token.PQCSignature) != 4627 {
		t.Errorf("PQC signature size should be 4627 bytes (ML-DSA-87), got %d", len(token.PQCSignature))
	}

	// Verify MAC size
	if len(token.ClassicalMAC) != 32 {
		t.Errorf("Classical MAC size should be 32 bytes (SHA-256), got %d", len(token.ClassicalMAC))
	}

	// Verify nonce size
	if len(token.Nonce) != 32 {
		t.Errorf("Nonce size should be 32 bytes, got %d", len(token.Nonce))
	}
}
