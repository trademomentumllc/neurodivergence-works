//! Hybrid Key Exchange: X25519 + ML-KEM-1024
//!
//! This module implements a hybrid key exchange combining classical X25519
//! and post-quantum ML-KEM-1024 (formerly Kyber1024) for forward secrecy
//! and quantum resistance.

use hkdf::Hkdf;
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SharedSecret};
use sha2::Sha256;
use std::error::Error;
use std::fmt;
use x25519_dalek::{EphemeralSecret as X25519Secret, PublicKey as X25519PublicKey};

/// Size of ML-KEM-1024 public key (Kyber1024)
pub const MLKEM_PUBLIC_KEY_SIZE: usize = 1568;

/// Size of ML-KEM-1024 ciphertext (Kyber1024)
pub const MLKEM_CIPHERTEXT_SIZE: usize = 1568;

/// Size of ML-KEM-1024 shared secret
pub const MLKEM_SHARED_SECRET_SIZE: usize = 32;

/// Size of X25519 public key
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;

/// Size of X25519 shared secret
pub const X25519_SHARED_SECRET_SIZE: usize = 32;

/// Size of the hybrid shared secret (X25519 + ML-KEM-1024)
pub const HYBRID_SHARED_SECRET_SIZE: usize = X25519_SHARED_SECRET_SIZE + MLKEM_SHARED_SECRET_SIZE;

/// Size of the derived session key
pub const SESSION_KEY_SIZE: usize = 32;

/// Errors that can occur during hybrid key exchange
#[derive(Debug)]
pub enum HybridKexError {
    /// Invalid public key length
    InvalidPublicKeyLength { expected: usize, got: usize },
    /// Invalid ciphertext length
    InvalidCiphertextLength { expected: usize, got: usize },
    /// ML-KEM decapsulation failed
    DecapsulationFailed,
    /// Key derivation failed
    KeyDerivationFailed,
    /// Invalid key material
    InvalidKeyMaterial(String),
}

impl fmt::Display for HybridKexError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HybridKexError::InvalidPublicKeyLength { expected, got } => {
                write!(
                    f,
                    "Invalid public key length: expected {}, got {}",
                    expected, got
                )
            }
            HybridKexError::InvalidCiphertextLength { expected, got } => {
                write!(
                    f,
                    "Invalid ciphertext length: expected {}, got {}",
                    expected, got
                )
            }
            HybridKexError::DecapsulationFailed => {
                write!(f, "ML-KEM decapsulation failed")
            }
            HybridKexError::KeyDerivationFailed => {
                write!(f, "Key derivation failed")
            }
            HybridKexError::InvalidKeyMaterial(msg) => {
                write!(f, "Invalid key material: {}", msg)
            }
        }
    }
}

impl Error for HybridKexError {}

/// Represents the server-side static keypair for hybrid key exchange
/// Note: Only ML-KEM keys are static; X25519 keys are generated per-connection for forward secrecy
pub struct HybridServerKeypair {
    /// ML-KEM-1024 secret key (static)
    pub mlkem_secret: kyber1024::SecretKey,
    /// ML-KEM-1024 public key (static)
    pub mlkem_public: kyber1024::PublicKey,
}

/// Represents the server's ephemeral X25519 keypair for a single connection
pub struct ServerX25519Keypair {
    /// X25519 ephemeral secret
    pub x25519_secret: X25519Secret,
    /// X25519 public key
    pub x25519_public: X25519PublicKey,
}

/// Represents the client-side ephemeral keypair
pub struct HybridClientKeypair {
    /// X25519 ephemeral secret
    pub x25519_secret: X25519Secret,
    /// X25519 public key
    pub x25519_public: X25519PublicKey,
}

/// Result of client-side key exchange
#[derive(Debug)]
pub struct ClientKexResult {
    /// X25519 public key to send to server
    pub x25519_public: [u8; X25519_PUBLIC_KEY_SIZE],
    /// ML-KEM ciphertext to send to server
    pub mlkem_ciphertext: Vec<u8>,
    /// Derived session key
    pub session_key: [u8; SESSION_KEY_SIZE],
}

/// Result of server-side key exchange
#[derive(Debug)]
pub struct ServerKexResult {
    /// Derived session key
    pub session_key: [u8; SESSION_KEY_SIZE],
}

impl HybridServerKeypair {
    /// Generate a new hybrid server keypair (ML-KEM only)
    pub fn generate() -> Self {
        // Generate ML-KEM-1024 keypair (static, long-lived)
        let (mlkem_public, mlkem_secret) = kyber1024::keypair();

        HybridServerKeypair {
            mlkem_secret,
            mlkem_public,
        }
    }

    /// Get the server's ML-KEM public key for transmission to client
    pub fn get_mlkem_public_key(&self) -> Vec<u8> {
        self.mlkem_public.as_bytes().to_vec()
    }

    /// Generate ephemeral X25519 keypair for a connection
    pub fn generate_x25519_keypair() -> ServerX25519Keypair {
        let x25519_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        ServerX25519Keypair {
            x25519_secret,
            x25519_public,
        }
    }

    /// Perform server-side key exchange
    ///
    /// # Arguments
    /// * `x25519_keypair` - Ephemeral X25519 keypair for this connection
    /// * `client_x25519_public` - Client's X25519 public key
    /// * `mlkem_ciphertext` - ML-KEM ciphertext from client
    ///
    /// # Returns
    /// The derived session key
    pub fn exchange(
        &self,
        x25519_keypair: ServerX25519Keypair,
        client_x25519_public: &[u8],
        mlkem_ciphertext: &[u8],
    ) -> Result<ServerKexResult, HybridKexError> {
        // Validate input lengths
        if client_x25519_public.len() != X25519_PUBLIC_KEY_SIZE {
            return Err(HybridKexError::InvalidPublicKeyLength {
                expected: X25519_PUBLIC_KEY_SIZE,
                got: client_x25519_public.len(),
            });
        }

        if mlkem_ciphertext.len() != MLKEM_CIPHERTEXT_SIZE {
            return Err(HybridKexError::InvalidCiphertextLength {
                expected: MLKEM_CIPHERTEXT_SIZE,
                got: mlkem_ciphertext.len(),
            });
        }

        // Convert client X25519 public key
        let mut x25519_key_bytes = [0u8; 32];
        x25519_key_bytes.copy_from_slice(client_x25519_public);
        let client_public = X25519PublicKey::from(x25519_key_bytes);

        // Perform X25519 key agreement (consumes ephemeral secret)
        let x25519_shared = x25519_keypair.x25519_secret.diffie_hellman(&client_public);

        // Decapsulate ML-KEM ciphertext
        let mlkem_ct = kyber1024::Ciphertext::from_bytes(mlkem_ciphertext)
            .map_err(|_| HybridKexError::DecapsulationFailed)?;

        let mlkem_shared = kyber1024::decapsulate(&mlkem_ct, &self.mlkem_secret);

        // Combine shared secrets
        let mut combined_secret = Vec::with_capacity(HYBRID_SHARED_SECRET_SIZE);
        combined_secret.extend_from_slice(x25519_shared.as_bytes());
        combined_secret.extend_from_slice(mlkem_shared.as_bytes());

        // Derive session key using HKDF
        let session_key = derive_session_key(&combined_secret)?;

        Ok(ServerKexResult { session_key })
    }
}

impl HybridClientKeypair {
    /// Generate a new ephemeral client keypair
    pub fn generate() -> Self {
        let x25519_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        HybridClientKeypair {
            x25519_secret,
            x25519_public,
        }
    }

    /// Perform client-side key exchange
    ///
    /// # Arguments
    /// * `server_x25519_public` - Server's X25519 public key
    /// * `server_mlkem_public` - Server's ML-KEM public key
    ///
    /// # Returns
    /// The key exchange result containing public keys/ciphertext to send and the session key
    ///
    /// # Note
    /// This method consumes the ephemeral secret for the key exchange
    pub fn exchange(
        self,
        server_x25519_public: &[u8],
        server_mlkem_public: &[u8],
    ) -> Result<ClientKexResult, HybridKexError> {
        // Validate input lengths
        if server_x25519_public.len() != X25519_PUBLIC_KEY_SIZE {
            return Err(HybridKexError::InvalidPublicKeyLength {
                expected: X25519_PUBLIC_KEY_SIZE,
                got: server_x25519_public.len(),
            });
        }

        if server_mlkem_public.len() != MLKEM_PUBLIC_KEY_SIZE {
            return Err(HybridKexError::InvalidPublicKeyLength {
                expected: MLKEM_PUBLIC_KEY_SIZE,
                got: server_mlkem_public.len(),
            });
        }

        // Convert server X25519 public key
        let mut x25519_key_bytes = [0u8; 32];
        x25519_key_bytes.copy_from_slice(server_x25519_public);
        let server_public = X25519PublicKey::from(x25519_key_bytes);

        // Perform X25519 key agreement
        let x25519_shared = self.x25519_secret.diffie_hellman(&server_public);

        // Parse server ML-KEM public key and encapsulate
        let mlkem_pk = kyber1024::PublicKey::from_bytes(server_mlkem_public)
            .map_err(|_| HybridKexError::InvalidKeyMaterial("Invalid ML-KEM public key".into()))?;

        let (mlkem_shared, mlkem_ciphertext) = kyber1024::encapsulate(&mlkem_pk);

        // Combine shared secrets
        let mut combined_secret = Vec::with_capacity(HYBRID_SHARED_SECRET_SIZE);
        combined_secret.extend_from_slice(x25519_shared.as_bytes());
        combined_secret.extend_from_slice(mlkem_shared.as_bytes());

        // Derive session key using HKDF
        let session_key = derive_session_key(&combined_secret)?;

        // Prepare result
        let x25519_public = *self.x25519_public.as_bytes();
        let mlkem_ciphertext = mlkem_ciphertext.as_bytes().to_vec();

        Ok(ClientKexResult {
            x25519_public,
            mlkem_ciphertext,
            session_key,
        })
    }
}

/// Derive a session key from combined shared secrets using HKDF-SHA256
///
/// # Arguments
/// * `shared_secret` - Combined X25519 and ML-KEM shared secrets
///
/// # Returns
/// A 32-byte session key
fn derive_session_key(shared_secret: &[u8]) -> Result<[u8; SESSION_KEY_SIZE], HybridKexError> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut session_key = [0u8; SESSION_KEY_SIZE];

    hk.expand(b"hybrid-x25519-mlkem1024-session-key-v1", &mut session_key)
        .map_err(|_| HybridKexError::KeyDerivationFailed)?;

    Ok(session_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_key_exchange_full_flow() {
        // Server generates static ML-KEM keypair
        let server_keypair = HybridServerKeypair::generate();
        let server_mlkem_pub = server_keypair.get_mlkem_public_key();

        // Server generates ephemeral X25519 keypair for this connection
        let server_x25519_keypair = HybridServerKeypair::generate_x25519_keypair();
        let server_x25519_pub = server_x25519_keypair.x25519_public.as_bytes().to_vec();

        // Client generates keypair and performs exchange
        let client_keypair = HybridClientKeypair::generate();
        let client_result = client_keypair
            .exchange(&server_x25519_pub, &server_mlkem_pub)
            .expect("Client exchange failed");

        // Server performs exchange
        let server_result = server_keypair
            .exchange(
                server_x25519_keypair,
                &client_result.x25519_public,
                &client_result.mlkem_ciphertext,
            )
            .expect("Server exchange failed");

        // Verify both parties derived the same session key
        assert_eq!(
            client_result.session_key, server_result.session_key,
            "Session keys must match"
        );

        // Session key should be 32 bytes
        assert_eq!(client_result.session_key.len(), SESSION_KEY_SIZE);
    }

    #[test]
    fn test_invalid_x25519_public_key_length() {
        let server_keypair = HybridServerKeypair::generate();
        let server_mlkem_pub = server_keypair.get_mlkem_public_key();

        let client_keypair = HybridClientKeypair::generate();

        // Invalid X25519 public key (wrong length)
        let invalid_x25519_pub = vec![0u8; 16];

        let result = client_keypair.exchange(&invalid_x25519_pub, &server_mlkem_pub);
        assert!(result.is_err());

        match result.unwrap_err() {
            HybridKexError::InvalidPublicKeyLength { expected, got } => {
                assert_eq!(expected, X25519_PUBLIC_KEY_SIZE);
                assert_eq!(got, 16);
            }
            _ => panic!("Expected InvalidPublicKeyLength error"),
        }
    }

    #[test]
    fn test_invalid_mlkem_public_key_length() {
        let server_x25519_keypair = HybridServerKeypair::generate_x25519_keypair();
        let server_x25519_pub = server_x25519_keypair.x25519_public.as_bytes().to_vec();

        let client_keypair = HybridClientKeypair::generate();

        // Invalid ML-KEM public key (wrong length)
        let invalid_mlkem_pub = vec![0u8; 100];

        let result = client_keypair.exchange(&server_x25519_pub, &invalid_mlkem_pub);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_ciphertext_length() {
        let server_keypair = HybridServerKeypair::generate();
        let server_x25519_keypair = HybridServerKeypair::generate_x25519_keypair();

        // Invalid ciphertext length
        let invalid_ct = vec![0u8; 100];
        let client_x25519_pub = [0u8; 32];

        let result =
            server_keypair.exchange(server_x25519_keypair, &client_x25519_pub, &invalid_ct);
        assert!(result.is_err());

        match result.unwrap_err() {
            HybridKexError::InvalidCiphertextLength { expected, got } => {
                assert_eq!(expected, MLKEM_CIPHERTEXT_SIZE);
                assert_eq!(got, 100);
            }
            _ => panic!("Expected InvalidCiphertextLength error"),
        }
    }

    #[test]
    fn test_session_key_uniqueness() {
        let server_keypair = HybridServerKeypair::generate();
        let server_mlkem_pub = server_keypair.get_mlkem_public_key();

        // Generate two different X25519 keypairs
        let server_x25519_kp1 = HybridServerKeypair::generate_x25519_keypair();
        let server_x25519_pub1 = server_x25519_kp1.x25519_public.as_bytes().to_vec();

        let server_x25519_kp2 = HybridServerKeypair::generate_x25519_keypair();
        let server_x25519_pub2 = server_x25519_kp2.x25519_public.as_bytes().to_vec();

        // Two different clients with different server ephemeral keys should derive different session keys
        let client1 = HybridClientKeypair::generate();
        let result1 = client1
            .exchange(&server_x25519_pub1, &server_mlkem_pub)
            .expect("Client 1 exchange failed");

        let client2 = HybridClientKeypair::generate();
        let result2 = client2
            .exchange(&server_x25519_pub2, &server_mlkem_pub)
            .expect("Client 2 exchange failed");

        assert_ne!(
            result1.session_key, result2.session_key,
            "Different clients should derive different session keys"
        );
    }

    #[test]
    fn test_key_derivation() {
        let secret1 = vec![1u8; HYBRID_SHARED_SECRET_SIZE];
        let secret2 = vec![2u8; HYBRID_SHARED_SECRET_SIZE];

        let key1 = derive_session_key(&secret1).expect("Derivation failed");
        let key2 = derive_session_key(&secret2).expect("Derivation failed");

        // Different inputs should produce different keys
        assert_ne!(key1, key2);

        // Same input should produce same key
        let key1_again = derive_session_key(&secret1).expect("Derivation failed");
        assert_eq!(key1, key1_again);
    }

    #[test]
    fn test_public_key_sizes() {
        let server_keypair = HybridServerKeypair::generate();
        let mlkem_pub = server_keypair.get_mlkem_public_key();

        let server_x25519_keypair = HybridServerKeypair::generate_x25519_keypair();
        let x25519_pub = server_x25519_keypair.x25519_public.as_bytes();

        assert_eq!(x25519_pub.len(), X25519_PUBLIC_KEY_SIZE);
        assert_eq!(mlkem_pub.len(), MLKEM_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_ciphertext_size() {
        let server_keypair = HybridServerKeypair::generate();
        let server_mlkem_pub = server_keypair.get_mlkem_public_key();

        let server_x25519_keypair = HybridServerKeypair::generate_x25519_keypair();
        let server_x25519_pub = server_x25519_keypair.x25519_public.as_bytes().to_vec();

        let client_keypair = HybridClientKeypair::generate();
        let result = client_keypair
            .exchange(&server_x25519_pub, &server_mlkem_pub)
            .expect("Exchange failed");

        assert_eq!(result.mlkem_ciphertext.len(), MLKEM_CIPHERTEXT_SIZE);
    }
}
