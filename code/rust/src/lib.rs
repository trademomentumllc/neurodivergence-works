//! Eight-Layer PQC - Layer 3: Network Security
//!
//! This library provides hybrid post-quantum cryptographic network security
//! implementing the X25519 + ML-KEM-1024 hybrid key exchange protocol with
//! secure session management.
//!
//! # Overview
//!
//! Layer 3 implements network-level security through:
//! - Hybrid key exchange combining classical X25519 and post-quantum ML-KEM-1024
//! - Secure session management with key rotation
//! - Protection against quantum and classical attacks
//!
//! # Example
//!
//! ```no_run
//! use eight_layer_pqc::{establish_secure_connection, NetworkSecurityError};
//!
//! fn example() -> Result<(), NetworkSecurityError> {
//!     // Server generates static ML-KEM keypair
//!     let server_keypair = eight_layer_pqc::hybrid_kex::HybridServerKeypair::generate();
//!
//!     // Get server's ML-KEM public key
//!     let server_mlkem_pub = server_keypair.get_mlkem_public_key();
//!
//!     // Server generates ephemeral X25519 keypair for this connection
//!     let server_x25519_keypair = eight_layer_pqc::hybrid_kex::HybridServerKeypair::generate_x25519_keypair();
//!     let server_x25519_pub = server_x25519_keypair.x25519_public.as_bytes().to_vec();
//!
//!     // Client performs key exchange
//!     let client_keypair = eight_layer_pqc::hybrid_kex::HybridClientKeypair::generate();
//!     let client_result = client_keypair.exchange(&server_x25519_pub, &server_mlkem_pub)?;
//!
//!     // Server completes key exchange
//!     let server_result = server_keypair.exchange(
//!         server_x25519_keypair,
//!         &client_result.x25519_public,
//!         &client_result.mlkem_ciphertext,
//!     )?;
//!
//!     // Both parties now have the same session key
//!     assert_eq!(client_result.session_key, server_result.session_key);
//!
//!     Ok(())
//! }
//! ```

pub mod hybrid_kex;
pub mod session;

use std::error::Error;
use std::fmt;

/// Primary error type for network security operations
#[derive(Debug)]
pub enum NetworkSecurityError {
    /// Hybrid key exchange error
    KeyExchange(hybrid_kex::HybridKexError),
    /// Session management error
    Session(session::SessionError),
    /// Connection error
    ConnectionError(String),
    /// Protocol error
    ProtocolError(String),
}

impl fmt::Display for NetworkSecurityError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NetworkSecurityError::KeyExchange(e) => write!(f, "Key exchange error: {}", e),
            NetworkSecurityError::Session(e) => write!(f, "Session error: {}", e),
            NetworkSecurityError::ConnectionError(msg) => write!(f, "Connection error: {}", msg),
            NetworkSecurityError::ProtocolError(msg) => write!(f, "Protocol error: {}", msg),
        }
    }
}

impl Error for NetworkSecurityError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            NetworkSecurityError::KeyExchange(e) => Some(e),
            NetworkSecurityError::Session(e) => Some(e),
            _ => None,
        }
    }
}

impl From<hybrid_kex::HybridKexError> for NetworkSecurityError {
    fn from(err: hybrid_kex::HybridKexError) -> Self {
        NetworkSecurityError::KeyExchange(err)
    }
}

impl From<session::SessionError> for NetworkSecurityError {
    fn from(err: session::SessionError) -> Self {
        NetworkSecurityError::Session(err)
    }
}

/// Represents a secure network connection
pub struct SecureConnection {
    /// Session identifier
    pub session_id: [u8; session::SESSION_ID_SIZE],
    /// Session key
    session_key: [u8; session::SESSION_KEY_SIZE],
    /// Client identifier
    pub client_id: Vec<u8>,
}

impl SecureConnection {
    /// Create a new secure connection from session parameters
    pub fn new(
        session_id: [u8; session::SESSION_ID_SIZE],
        session_key: [u8; session::SESSION_KEY_SIZE],
        client_id: Vec<u8>,
    ) -> Self {
        SecureConnection {
            session_id,
            session_key,
            client_id,
        }
    }

    /// Get the session key (for internal use only)
    pub fn session_key(&self) -> &[u8; session::SESSION_KEY_SIZE] {
        &self.session_key
    }

    /// Verify the connection with a session manager
    pub fn verify(
        &self,
        manager: &mut session::SessionManager,
    ) -> Result<(), NetworkSecurityError> {
        let session = manager.get_session(&self.session_id)?;

        if !session.verify_key(&self.session_key) {
            return Err(NetworkSecurityError::Session(
                session::SessionError::KeyMismatch,
            ));
        }

        manager.validate_session(&self.session_id)?;
        Ok(())
    }
}

/// Server context for managing secure connections
pub struct SecureServer {
    /// Server's hybrid keypair
    keypair: hybrid_kex::HybridServerKeypair,
    /// Session manager
    session_manager: session::SessionManager,
}

impl SecureServer {
    /// Create a new secure server
    ///
    /// # Arguments
    /// * `max_sessions` - Maximum number of concurrent sessions
    /// * `session_timeout` - Session timeout in seconds
    pub fn new(max_sessions: usize, session_timeout: u64) -> Self {
        SecureServer {
            keypair: hybrid_kex::HybridServerKeypair::generate(),
            session_manager: session::SessionManager::new(max_sessions, session_timeout),
        }
    }

    /// Get server's ML-KEM public key for distribution to clients
    pub fn get_mlkem_public_key(&self) -> Vec<u8> {
        self.keypair.get_mlkem_public_key()
    }

    /// Generate ephemeral X25519 keypair for a new connection
    pub fn generate_x25519_keypair() -> (Vec<u8>, hybrid_kex::ServerX25519Keypair) {
        let keypair = hybrid_kex::HybridServerKeypair::generate_x25519_keypair();
        let public_key = keypair.x25519_public.as_bytes().to_vec();
        (public_key, keypair)
    }

    /// Accept a client connection and establish a secure session
    ///
    /// # Arguments
    /// * `x25519_keypair` - Ephemeral X25519 keypair for this connection
    /// * `client_x25519_public` - Client's X25519 public key
    /// * `client_mlkem_ciphertext` - Client's ML-KEM ciphertext
    /// * `client_id` - Client identifier (e.g., IP address hash)
    ///
    /// # Returns
    /// A secure connection handle
    pub fn accept_connection(
        &mut self,
        x25519_keypair: hybrid_kex::ServerX25519Keypair,
        client_x25519_public: &[u8],
        client_mlkem_ciphertext: &[u8],
        client_id: Vec<u8>,
    ) -> Result<SecureConnection, NetworkSecurityError> {
        // Perform key exchange
        let kex_result = self.keypair.exchange(
            x25519_keypair,
            client_x25519_public,
            client_mlkem_ciphertext,
        )?;

        // Create session
        let session_id = self
            .session_manager
            .create_session(kex_result.session_key, client_id.clone())?;

        Ok(SecureConnection::new(
            session_id,
            kex_result.session_key,
            client_id,
        ))
    }

    /// Verify an existing connection
    pub fn verify_connection(
        &mut self,
        connection: &SecureConnection,
    ) -> Result<(), NetworkSecurityError> {
        connection.verify(&mut self.session_manager)
    }

    /// Terminate a connection
    pub fn terminate_connection(
        &mut self,
        session_id: &[u8; session::SESSION_ID_SIZE],
    ) -> Result<(), NetworkSecurityError> {
        self.session_manager.terminate_session(session_id)?;
        Ok(())
    }

    /// Get the number of active sessions
    pub fn active_sessions(&self) -> usize {
        self.session_manager.active_session_count()
    }

    /// Clean up expired sessions
    pub fn cleanup(&mut self) -> usize {
        self.session_manager.cleanup_expired()
    }

    /// Rotate server keypair (for long-lived servers)
    pub fn rotate_keypair(&mut self) {
        self.keypair = hybrid_kex::HybridServerKeypair::generate();
    }

    /// Get a reference to the session manager
    pub fn session_manager(&self) -> &session::SessionManager {
        &self.session_manager
    }

    /// Get a mutable reference to the session manager
    pub fn session_manager_mut(&mut self) -> &mut session::SessionManager {
        &mut self.session_manager
    }
}

impl Default for SecureServer {
    fn default() -> Self {
        Self::new(1000, session::DEFAULT_SESSION_TIMEOUT)
    }
}

/// Client context for establishing secure connections
pub struct SecureClient {
    /// Client's ephemeral keypair
    keypair: hybrid_kex::HybridClientKeypair,
    /// Client identifier
    client_id: Vec<u8>,
}

impl SecureClient {
    /// Create a new secure client
    ///
    /// # Arguments
    /// * `client_id` - Client identifier (e.g., hash of IP address)
    pub fn new(client_id: Vec<u8>) -> Self {
        SecureClient {
            keypair: hybrid_kex::HybridClientKeypair::generate(),
            client_id,
        }
    }

    /// Connect to a secure server
    ///
    /// # Arguments
    /// * `server_x25519_public` - Server's X25519 public key
    /// * `server_mlkem_public` - Server's ML-KEM public key
    ///
    /// # Returns
    /// Connection result containing session key and data to send to server
    ///
    /// # Note
    /// This method consumes the client since the ephemeral keypair should only be used once
    pub fn connect(
        self,
        server_x25519_public: &[u8],
        server_mlkem_public: &[u8],
    ) -> Result<ClientConnectionResult, NetworkSecurityError> {
        let kex_result = self
            .keypair
            .exchange(server_x25519_public, server_mlkem_public)?;

        Ok(ClientConnectionResult {
            x25519_public: kex_result.x25519_public,
            mlkem_ciphertext: kex_result.mlkem_ciphertext,
            session_key: kex_result.session_key,
            client_id: self.client_id.clone(),
        })
    }

    /// Get client identifier
    pub fn client_id(&self) -> &[u8] {
        &self.client_id
    }
}

/// Result of client connection attempt
pub struct ClientConnectionResult {
    /// Client's X25519 public key (send to server)
    pub x25519_public: [u8; hybrid_kex::X25519_PUBLIC_KEY_SIZE],
    /// Client's ML-KEM ciphertext (send to server)
    pub mlkem_ciphertext: Vec<u8>,
    /// Derived session key
    pub session_key: [u8; session::SESSION_KEY_SIZE],
    /// Client identifier
    pub client_id: Vec<u8>,
}

/// Establish a secure connection (convenience function)
///
/// This is a high-level function that demonstrates the complete flow
/// of establishing a secure connection between client and server.
///
/// # Returns
/// A tuple of (client session key, server session key) which should be equal
pub fn establish_secure_connection() -> Result<([u8; 32], [u8; 32]), NetworkSecurityError> {
    // Server setup
    let mut server = SecureServer::default();
    let server_mlkem_pub = server.get_mlkem_public_key();

    // Server generates ephemeral X25519 keypair
    let (server_x25519_pub, server_x25519_keypair) = SecureServer::generate_x25519_keypair();

    // Client setup and connection
    let client = SecureClient::new(b"client-id-12345".to_vec());
    let client_result = client.connect(&server_x25519_pub, &server_mlkem_pub)?;

    // Server accepts connection
    let server_conn = server.accept_connection(
        server_x25519_keypair,
        &client_result.x25519_public,
        &client_result.mlkem_ciphertext,
        client_result.client_id,
    )?;

    Ok((client_result.session_key, *server_conn.session_key()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_server_creation() {
        let server = SecureServer::default();
        assert_eq!(server.active_sessions(), 0);
    }

    #[test]
    fn test_secure_client_creation() {
        let client = SecureClient::new(b"test-client".to_vec());
        assert_eq!(client.client_id(), b"test-client");
    }

    #[test]
    fn test_full_connection_flow() {
        // Create server
        let mut server = SecureServer::default();
        let server_mlkem_pub = server.get_mlkem_public_key();

        // Generate ephemeral X25519 keypair
        let (server_x25519_pub, server_x25519_keypair) = SecureServer::generate_x25519_keypair();

        // Create client
        let client = SecureClient::new(b"client-001".to_vec());

        // Client connects
        let client_result = client
            .connect(&server_x25519_pub, &server_mlkem_pub)
            .expect("Client connection failed");

        // Server accepts
        let server_conn = server
            .accept_connection(
                server_x25519_keypair,
                &client_result.x25519_public,
                &client_result.mlkem_ciphertext,
                client_result.client_id.clone(),
            )
            .expect("Server accept failed");

        // Verify keys match
        assert_eq!(client_result.session_key, *server_conn.session_key());

        // Verify session is active
        assert_eq!(server.active_sessions(), 1);

        // Verify connection
        server
            .verify_connection(&server_conn)
            .expect("Connection verification failed");
    }

    #[test]
    fn test_multiple_connections() {
        let mut server = SecureServer::default();
        let server_mlkem_pub = server.get_mlkem_public_key();

        // Connect multiple clients
        for i in 0..5 {
            let client_id = format!("client-{:03}", i).into_bytes();
            let client = SecureClient::new(client_id.clone());

            // Generate fresh X25519 keypair for each connection
            let (server_x25519_pub, server_x25519_keypair) =
                SecureServer::generate_x25519_keypair();

            let client_result = client
                .connect(&server_x25519_pub, &server_mlkem_pub)
                .expect("Client connection failed");

            server
                .accept_connection(
                    server_x25519_keypair,
                    &client_result.x25519_public,
                    &client_result.mlkem_ciphertext,
                    client_id,
                )
                .expect("Server accept failed");
        }

        assert_eq!(server.active_sessions(), 5);
    }

    #[test]
    fn test_connection_termination() {
        let mut server = SecureServer::default();
        let server_mlkem_pub = server.get_mlkem_public_key();

        let (server_x25519_pub, server_x25519_keypair) = SecureServer::generate_x25519_keypair();

        let client = SecureClient::new(b"client-001".to_vec());
        let client_result = client
            .connect(&server_x25519_pub, &server_mlkem_pub)
            .expect("Client connection failed");

        let server_conn = server
            .accept_connection(
                server_x25519_keypair,
                &client_result.x25519_public,
                &client_result.mlkem_ciphertext,
                client_result.client_id,
            )
            .expect("Server accept failed");

        assert_eq!(server.active_sessions(), 1);

        server
            .terminate_connection(&server_conn.session_id)
            .expect("Termination failed");

        assert_eq!(server.active_sessions(), 0);
    }

    #[test]
    fn test_establish_secure_connection() {
        let result = establish_secure_connection().expect("Connection establishment failed");
        let (client_key, server_key) = result;

        // Keys should match
        assert_eq!(client_key, server_key);
    }

    #[test]
    fn test_keypair_rotation() {
        let mut server = SecureServer::default();
        let old_mlkem = server.get_mlkem_public_key();

        server.rotate_keypair();

        let new_mlkem = server.get_mlkem_public_key();

        // ML-KEM key should be different after rotation
        assert_ne!(old_mlkem, new_mlkem);
    }

    #[test]
    fn test_session_cleanup() {
        let mut server = SecureServer::new(10, 1); // 1 second timeout
        let server_mlkem_pub = server.get_mlkem_public_key();

        let (server_x25519_pub, server_x25519_keypair) = SecureServer::generate_x25519_keypair();

        let client = SecureClient::new(b"client-001".to_vec());
        let client_result = client
            .connect(&server_x25519_pub, &server_mlkem_pub)
            .expect("Client connection failed");

        server
            .accept_connection(
                server_x25519_keypair,
                &client_result.x25519_public,
                &client_result.mlkem_ciphertext,
                client_result.client_id,
            )
            .expect("Server accept failed");

        assert_eq!(server.active_sessions(), 1);

        // Wait for session to expire
        std::thread::sleep(std::time::Duration::from_secs(2));

        let cleaned = server.cleanup();
        assert_eq!(cleaned, 1);
        assert_eq!(server.active_sessions(), 0);
    }

    #[test]
    fn test_max_sessions_limit() {
        let mut server = SecureServer::new(2, session::DEFAULT_SESSION_TIMEOUT);
        let server_mlkem_pub = server.get_mlkem_public_key();

        // Add two sessions (should succeed)
        for i in 0..2 {
            let client_id = format!("client-{}", i).into_bytes();
            let client = SecureClient::new(client_id.clone());

            let (server_x25519_pub, server_x25519_keypair) =
                SecureServer::generate_x25519_keypair();
            let client_result = client
                .connect(&server_x25519_pub, &server_mlkem_pub)
                .unwrap();

            server
                .accept_connection(
                    server_x25519_keypair,
                    &client_result.x25519_public,
                    &client_result.mlkem_ciphertext,
                    client_id,
                )
                .unwrap();
        }

        // Third session should fail
        let client = SecureClient::new(b"client-3".to_vec());
        let (server_x25519_pub, server_x25519_keypair) = SecureServer::generate_x25519_keypair();
        let client_result = client
            .connect(&server_x25519_pub, &server_mlkem_pub)
            .unwrap();

        let result = server.accept_connection(
            server_x25519_keypair,
            &client_result.x25519_public,
            &client_result.mlkem_ciphertext,
            b"client-3".to_vec(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_error_conversion() {
        let kex_error = hybrid_kex::HybridKexError::DecapsulationFailed;
        let net_error: NetworkSecurityError = kex_error.into();

        match net_error {
            NetworkSecurityError::KeyExchange(_) => (),
            _ => panic!("Expected KeyExchange error"),
        }
    }

    #[test]
    fn test_secure_connection_verification() {
        let mut server = SecureServer::default();
        let server_mlkem_pub = server.get_mlkem_public_key();

        let (server_x25519_pub, server_x25519_keypair) = SecureServer::generate_x25519_keypair();

        let client = SecureClient::new(b"client-001".to_vec());
        let client_result = client
            .connect(&server_x25519_pub, &server_mlkem_pub)
            .unwrap();

        let conn = server
            .accept_connection(
                server_x25519_keypair,
                &client_result.x25519_public,
                &client_result.mlkem_ciphertext,
                client_result.client_id,
            )
            .unwrap();

        // Verify should succeed
        assert!(server.verify_connection(&conn).is_ok());

        // Create connection with wrong key
        let mut wrong_key = *conn.session_key();
        wrong_key[0] ^= 0xFF; // Flip some bits

        let bad_conn = SecureConnection::new(conn.session_id, wrong_key, conn.client_id.clone());

        // Verification should fail
        assert!(server.verify_connection(&bad_conn).is_err());
    }
}
