package authorization_test

import (
	"fmt"
	"log"
	"time"

	"github.com/TradeMomentumLLC/eight-layer-pqc/layer2_authz"
)

// Example demonstrates basic usage of the Layer 2 Authorization system
func ExampleAuthorizationManager_basic() {
	// Create a new authorization manager with ML-DSA-87 keys
	am, err := authorization.NewAuthorizationManager()
	if err != nil {
		log.Fatalf("Failed to create authorization manager: %v", err)
	}

	// Define roles with permissions
	am.AddRole("reader", "Read-Only User", []string{"read"})
	am.AddRole("writer", "Writer", []string{"read", "write"})
	am.AddRole("admin", "Administrator", []string{"*"})

	// Generate a capability token for a user with "reader" role
	token, err := am.GenerateToken("reader", "arn:aws:s3:::mybucket/myobject", 1*time.Hour)
	if err != nil {
		log.Fatalf("Failed to generate token: %v", err)
	}

	// Validate the token
	err = am.ValidateToken(token)
	if err != nil {
		log.Fatalf("Token validation failed: %v", err)
	}

	// Check if the token has read permission
	err = am.CheckCapability(token, "read")
	if err != nil {
		fmt.Println("Access denied: read permission")
	} else {
		fmt.Println("Access granted: read permission")
	}

	// Check if the token has write permission
	err = am.CheckCapability(token, "write")
	if err != nil {
		fmt.Println("Access denied: write permission")
	} else {
		fmt.Println("Access granted: write permission")
	}

	// Output:
	// Access granted: read permission
	// Access denied: write permission
}

// Example demonstrates token expiration handling
func ExampleAuthorizationManager_expiration() {
	am, _ := authorization.NewAuthorizationManager()
	am.AddRole("user", "User", []string{"read"})

	// Create a token that expires in 100 milliseconds
	token, _ := am.GenerateToken("user", "arn:aws:s3:::bucket/object", 100*time.Millisecond)

	// Token is valid initially
	err := am.ValidateToken(token)
	if err != nil {
		fmt.Println("Token invalid (should not happen)")
	} else {
		fmt.Println("Token valid")
	}

	// Wait for token to expire
	time.Sleep(150 * time.Millisecond)

	// Token is now expired
	err = am.ValidateToken(token)
	if err != nil {
		fmt.Println("Token expired")
	} else {
		fmt.Println("Token valid (should not happen)")
	}

	// Output:
	// Token valid
	// Token expired
}

// Example demonstrates nonce-based replay attack prevention
func ExampleAuthorizationManager_replayPrevention() {
	am, _ := authorization.NewAuthorizationManager()
	am.AddRole("user", "User", []string{"read"})

	// Generate a token
	token, _ := am.GenerateToken("user", "arn:aws:s3:::bucket/object", 1*time.Hour)

	// Token is valid on first use
	err := am.ValidateToken(token)
	if err == nil {
		fmt.Println("First validation: success")
	}

	// Revoke the token (simulate using it)
	am.RevokeToken(token)

	// Token cannot be reused (replay attack prevented)
	err = am.ValidateToken(token)
	if err != nil {
		fmt.Println("Replay attempt: blocked")
	}

	// Output:
	// First validation: success
	// Replay attempt: blocked
}

// Example demonstrates role-based access control
func ExampleAuthorizationManager_rbac() {
	am, _ := authorization.NewAuthorizationManager()

	// Define roles with different permission sets
	am.AddRole("analyst", "Data Analyst", []string{"read", "query"})
	am.AddRole("engineer", "Data Engineer", []string{"read", "write", "query"})
	am.AddRole("admin", "Administrator", []string{"*"})

	// Generate tokens for different roles
	analystToken, _ := am.GenerateToken("analyst", "arn:aws:s3:::data/analytics", 1*time.Hour)
	engineerToken, _ := am.GenerateToken("engineer", "arn:aws:s3:::data/raw", 1*time.Hour)
	adminToken, _ := am.GenerateToken("admin", "arn:aws:s3:::data/all", 1*time.Hour)

	// Test permissions
	permissions := []string{"read", "write", "delete"}

	for _, perm := range permissions {
		// Analyst permissions
		err := am.CheckCapability(analystToken, perm)
		fmt.Printf("Analyst %s: %s\n", perm, accessResult(err))

		// Engineer permissions
		err = am.CheckCapability(engineerToken, perm)
		fmt.Printf("Engineer %s: %s\n", perm, accessResult(err))

		// Admin permissions
		err = am.CheckCapability(adminToken, perm)
		fmt.Printf("Admin %s: %s\n", perm, accessResult(err))
	}

	// Output:
	// Analyst read: granted
	// Engineer read: granted
	// Admin read: granted
	// Analyst write: denied
	// Engineer write: granted
	// Admin write: granted
	// Analyst delete: denied
	// Engineer delete: denied
	// Admin delete: granted
}

func accessResult(err error) string {
	if err == nil {
		return "granted"
	}
	return "denied"
}

// Example demonstrates key persistence and reconstruction
func ExampleAuthorizationManager_keyPersistence() {
	// Create initial manager
	am1, _ := authorization.NewAuthorizationManager()

	// Export keys for storage
	publicKey, _ := am1.GetPublicKey()
	privateKey, _ := am1.GetPrivateKey()
	hmacKey := am1.GetHMACKey()

	fmt.Printf("Exported keys: pubKey=%d bytes, privKey=%d bytes, hmac=%d bytes\n",
		len(publicKey), len(privateKey), len(hmacKey))

	// Simulate application restart - create new manager with saved keys
	am2, _ := authorization.NewAuthorizationManagerWithKeys(publicKey, privateKey, hmacKey)

	// Verify keys are identical
	publicKey2, _ := am2.GetPublicKey()
	if bytesEqual(publicKey, publicKey2) {
		fmt.Println("Keys successfully restored")
	}

	// Output:
	// Exported keys: pubKey=2592 bytes, privKey=4896 bytes, hmac=32 bytes
	// Keys successfully restored
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

// Example demonstrates monitoring and statistics
func ExampleAuthorizationManager_stats() {
	am, _ := authorization.NewAuthorizationManager()
	am.AddRole("user", "User", []string{"read"})

	// Generate some tokens
	for i := 0; i < 5; i++ {
		am.GenerateToken("user", fmt.Sprintf("arn:aws:s3:::bucket/object%d", i), 1*time.Hour)
	}

	// Get statistics
	stats := am.GetStats()
	fmt.Printf("Active nonces: %d\n", stats.ActiveNonces)
	fmt.Printf("Total roles: %d\n", stats.TotalRoles)

	// Generate an expired token
	am.GenerateToken("user", "arn:aws:s3:::bucket/expired", 1*time.Nanosecond)
	time.Sleep(10 * time.Millisecond)

	stats = am.GetStats()
	fmt.Printf("Expired nonces: %d\n", stats.ExpiredNonces)

	// Output:
	// Active nonces: 5
	// Total roles: 1
	// Expired nonces: 1
}

// Example demonstrates hybrid cryptographic security
func ExampleAuthorizationManager_hybridSecurity() {
	am, _ := authorization.NewAuthorizationManager()
	am.AddRole("user", "User", []string{"read"})

	// Generate a token with both classical MAC and PQC signature
	token, _ := am.GenerateToken("user", "arn:aws:s3:::bucket/object", 1*time.Hour)

	fmt.Printf("Token security layers:\n")
	fmt.Printf("- Classical MAC (HMAC-SHA256): %d bytes\n", len(token.ClassicalMAC))
	fmt.Printf("- PQC Signature (ML-DSA-87): %d bytes\n", len(token.PQCSignature))
	fmt.Printf("- Nonce (replay prevention): %d bytes\n", len(token.Nonce))

	// Validation checks both security layers
	err := am.ValidateToken(token)
	if err == nil {
		fmt.Println("Both security layers verified successfully")
	}

	// Output:
	// Token security layers:
	// - Classical MAC (HMAC-SHA256): 32 bytes
	// - PQC Signature (ML-DSA-87): 4627 bytes
	// - Nonce (replay prevention): 32 bytes
	// Both security layers verified successfully
}
