//! Secure Session Management
//!
//! This module provides secure session management with key rotation,
//! session state tracking, and cryptographic session binding.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Default session timeout in seconds (1 hour)
pub const DEFAULT_SESSION_TIMEOUT: u64 = 3600;

/// Maximum session lifetime in seconds (24 hours)
pub const MAX_SESSION_LIFETIME: u64 = 86400;

/// Session key size in bytes
pub const SESSION_KEY_SIZE: usize = 32;

/// Session ID size in bytes
pub const SESSION_ID_SIZE: usize = 32;

/// Errors that can occur during session management
#[derive(Debug, Clone, PartialEq)]
pub enum SessionError {
    /// Session not found
    SessionNotFound,
    /// Session has expired
    SessionExpired,
    /// Session is invalid
    InvalidSession,
    /// Session key mismatch
    KeyMismatch,
    /// Session limit reached
    SessionLimitReached,
    /// Invalid session ID
    InvalidSessionId,
    /// Session already exists
    SessionAlreadyExists,
    /// Time error
    TimeError,
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SessionError::SessionNotFound => write!(f, "Session not found"),
            SessionError::SessionExpired => write!(f, "Session has expired"),
            SessionError::InvalidSession => write!(f, "Session is invalid"),
            SessionError::KeyMismatch => write!(f, "Session key mismatch"),
            SessionError::SessionLimitReached => write!(f, "Session limit reached"),
            SessionError::InvalidSessionId => write!(f, "Invalid session ID"),
            SessionError::SessionAlreadyExists => write!(f, "Session already exists"),
            SessionError::TimeError => write!(f, "System time error"),
        }
    }
}

impl Error for SessionError {}

/// Represents the state of a session
#[derive(Debug, Clone, PartialEq)]
pub enum SessionState {
    /// Session is active and valid
    Active,
    /// Session is suspended (temporarily inactive)
    Suspended,
    /// Session has expired
    Expired,
    /// Session has been terminated
    Terminated,
}

/// Session metadata and cryptographic material
#[derive(Debug, Clone)]
pub struct Session {
    /// Unique session identifier
    pub id: [u8; SESSION_ID_SIZE],
    /// Session key derived from key exchange
    pub key: [u8; SESSION_KEY_SIZE],
    /// Session state
    pub state: SessionState,
    /// Session creation timestamp (seconds since UNIX epoch)
    pub created_at: u64,
    /// Last activity timestamp
    pub last_activity: u64,
    /// Session expiration timestamp
    pub expires_at: u64,
    /// Client identifier (e.g., IP address hash)
    pub client_id: Vec<u8>,
    /// Number of key rotations performed
    pub rotation_count: u32,
    /// Session-specific metadata
    pub metadata: HashMap<String, String>,
}

impl Session {
    /// Create a new session
    ///
    /// # Arguments
    /// * `key` - Session key from hybrid key exchange
    /// * `client_id` - Client identifier
    /// * `timeout` - Session timeout in seconds
    ///
    /// # Returns
    /// A new Session instance
    pub fn new(
        key: [u8; SESSION_KEY_SIZE],
        client_id: Vec<u8>,
        timeout: u64,
    ) -> Result<Self, SessionError> {
        let now = get_current_timestamp()?;
        let timeout = timeout.min(MAX_SESSION_LIFETIME);

        // Generate session ID from key and client ID
        let id = generate_session_id(&key, &client_id, now);

        Ok(Session {
            id,
            key,
            state: SessionState::Active,
            created_at: now,
            last_activity: now,
            expires_at: now + timeout,
            client_id,
            rotation_count: 0,
            metadata: HashMap::new(),
        })
    }

    /// Check if the session is valid (active and not expired)
    pub fn is_valid(&self) -> Result<bool, SessionError> {
        if self.state != SessionState::Active {
            return Ok(false);
        }

        let now = get_current_timestamp()?;
        Ok(now < self.expires_at)
    }

    /// Update last activity timestamp and extend session if needed
    pub fn touch(&mut self) -> Result<(), SessionError> {
        let now = get_current_timestamp()?;

        if now >= self.expires_at {
            self.state = SessionState::Expired;
            return Err(SessionError::SessionExpired);
        }

        self.last_activity = now;
        Ok(())
    }

    /// Rotate the session key
    ///
    /// # Arguments
    /// * `new_key` - New session key from re-key exchange
    pub fn rotate_key(&mut self, new_key: [u8; SESSION_KEY_SIZE]) -> Result<(), SessionError> {
        if self.state != SessionState::Active {
            return Err(SessionError::InvalidSession);
        }

        self.key = new_key;
        self.rotation_count += 1;
        self.touch()?;

        Ok(())
    }

    /// Suspend the session (temporarily deactivate)
    pub fn suspend(&mut self) {
        if self.state == SessionState::Active {
            self.state = SessionState::Suspended;
        }
    }

    /// Resume a suspended session
    pub fn resume(&mut self) -> Result<(), SessionError> {
        if self.state == SessionState::Suspended {
            // Check if session has expired while suspended
            let now = get_current_timestamp()?;
            if now >= self.expires_at {
                self.state = SessionState::Expired;
                return Err(SessionError::SessionExpired);
            }

            self.state = SessionState::Active;
            self.last_activity = now;
            Ok(())
        } else {
            Err(SessionError::InvalidSession)
        }
    }

    /// Terminate the session
    pub fn terminate(&mut self) {
        self.state = SessionState::Terminated;
        // Zero out the session key for security
        self.key.iter_mut().for_each(|b| *b = 0);
    }

    /// Verify the session key matches the expected key
    pub fn verify_key(&self, key: &[u8; SESSION_KEY_SIZE]) -> bool {
        // Constant-time comparison
        constant_time_eq(&self.key, key)
    }

    /// Get session age in seconds
    pub fn age(&self) -> Result<u64, SessionError> {
        let now = get_current_timestamp()?;
        Ok(now.saturating_sub(self.created_at))
    }

    /// Get time until expiration in seconds
    pub fn time_to_expiry(&self) -> Result<u64, SessionError> {
        let now = get_current_timestamp()?;
        Ok(self.expires_at.saturating_sub(now))
    }

    /// Set custom metadata
    pub fn set_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }

    /// Get custom metadata
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }
}

/// Session manager for handling multiple concurrent sessions
pub struct SessionManager {
    /// Active sessions indexed by session ID
    sessions: HashMap<[u8; SESSION_ID_SIZE], Session>,
    /// Maximum number of concurrent sessions
    max_sessions: usize,
    /// Default session timeout
    default_timeout: u64,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new(1000, DEFAULT_SESSION_TIMEOUT)
    }
}

impl SessionManager {
    /// Create a new session manager
    ///
    /// # Arguments
    /// * `max_sessions` - Maximum number of concurrent sessions
    /// * `default_timeout` - Default session timeout in seconds
    pub fn new(max_sessions: usize, default_timeout: u64) -> Self {
        SessionManager {
            sessions: HashMap::new(),
            max_sessions,
            default_timeout: default_timeout.min(MAX_SESSION_LIFETIME),
        }
    }

    /// Create a new session
    pub fn create_session(
        &mut self,
        key: [u8; SESSION_KEY_SIZE],
        client_id: Vec<u8>,
    ) -> Result<[u8; SESSION_ID_SIZE], SessionError> {
        self.cleanup_expired();

        if self.sessions.len() >= self.max_sessions {
            return Err(SessionError::SessionLimitReached);
        }

        let session = Session::new(key, client_id, self.default_timeout)?;
        let session_id = session.id;

        if self.sessions.contains_key(&session_id) {
            return Err(SessionError::SessionAlreadyExists);
        }

        self.sessions.insert(session_id, session);
        Ok(session_id)
    }

    /// Get a session by ID
    pub fn get_session(
        &self,
        session_id: &[u8; SESSION_ID_SIZE],
    ) -> Result<&Session, SessionError> {
        self.sessions
            .get(session_id)
            .ok_or(SessionError::SessionNotFound)
    }

    /// Get a mutable session by ID
    pub fn get_session_mut(
        &mut self,
        session_id: &[u8; SESSION_ID_SIZE],
    ) -> Result<&mut Session, SessionError> {
        self.sessions
            .get_mut(session_id)
            .ok_or(SessionError::SessionNotFound)
    }

    /// Validate and touch a session
    pub fn validate_session(
        &mut self,
        session_id: &[u8; SESSION_ID_SIZE],
    ) -> Result<(), SessionError> {
        let session = self.get_session_mut(session_id)?;

        if !session.is_valid()? {
            session.state = SessionState::Expired;
            return Err(SessionError::SessionExpired);
        }

        session.touch()?;
        Ok(())
    }

    /// Terminate a session
    pub fn terminate_session(
        &mut self,
        session_id: &[u8; SESSION_ID_SIZE],
    ) -> Result<(), SessionError> {
        if let Some(mut session) = self.sessions.remove(session_id) {
            session.terminate();
            Ok(())
        } else {
            Err(SessionError::SessionNotFound)
        }
    }

    /// Clean up expired sessions
    pub fn cleanup_expired(&mut self) -> usize {
        let now = get_current_timestamp().unwrap_or(0);
        let initial_count = self.sessions.len();

        self.sessions.retain(|_, session| {
            !(session.state == SessionState::Expired || now >= session.expires_at)
        });

        initial_count - self.sessions.len()
    }

    /// Get the number of active sessions
    pub fn active_session_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|s| s.state == SessionState::Active)
            .count()
    }

    /// Get all session IDs
    pub fn get_all_session_ids(&self) -> Vec<[u8; SESSION_ID_SIZE]> {
        self.sessions.keys().copied().collect()
    }

    /// Terminate all sessions (e.g., for shutdown)
    pub fn terminate_all(&mut self) {
        let session_ids: Vec<_> = self.sessions.keys().copied().collect();
        for session_id in session_ids {
            let _ = self.terminate_session(&session_id);
        }
    }
}

/// Generate a session ID from key material
fn generate_session_id(
    key: &[u8; SESSION_KEY_SIZE],
    client_id: &[u8],
    timestamp: u64,
) -> [u8; SESSION_ID_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(client_id);
    hasher.update(timestamp.to_le_bytes());
    hasher.update(b"session-id-v1");

    let result = hasher.finalize();
    let mut session_id = [0u8; SESSION_ID_SIZE];
    session_id.copy_from_slice(&result);
    session_id
}

/// Get current timestamp in seconds since UNIX epoch
fn get_current_timestamp() -> Result<u64, SessionError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| SessionError::TimeError)
}

/// Constant-time equality comparison to prevent timing attacks
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn create_test_session() -> Session {
        let key = [1u8; SESSION_KEY_SIZE];
        let client_id = b"test-client".to_vec();
        Session::new(key, client_id, DEFAULT_SESSION_TIMEOUT).unwrap()
    }

    #[test]
    fn test_session_creation() {
        let session = create_test_session();
        assert_eq!(session.state, SessionState::Active);
        assert_eq!(session.rotation_count, 0);
        assert!(session.is_valid().unwrap());
    }

    #[test]
    fn test_session_touch() {
        let mut session = create_test_session();
        let initial_activity = session.last_activity;

        std::thread::sleep(Duration::from_millis(10));

        session.touch().unwrap();
        assert!(session.last_activity >= initial_activity);
    }

    #[test]
    fn test_session_key_rotation() {
        let mut session = create_test_session();
        let new_key = [2u8; SESSION_KEY_SIZE];

        session.rotate_key(new_key).unwrap();

        assert_eq!(session.key, new_key);
        assert_eq!(session.rotation_count, 1);
    }

    #[test]
    fn test_session_key_verification() {
        let session = create_test_session();
        let correct_key = [1u8; SESSION_KEY_SIZE];
        let wrong_key = [2u8; SESSION_KEY_SIZE];

        assert!(session.verify_key(&correct_key));
        assert!(!session.verify_key(&wrong_key));
    }

    #[test]
    fn test_session_suspend_resume() {
        let mut session = create_test_session();

        session.suspend();
        assert_eq!(session.state, SessionState::Suspended);

        session.resume().unwrap();
        assert_eq!(session.state, SessionState::Active);
    }

    #[test]
    fn test_session_termination() {
        let mut session = create_test_session();

        session.terminate();
        assert_eq!(session.state, SessionState::Terminated);
        assert_eq!(session.key, [0u8; SESSION_KEY_SIZE]);
    }

    #[test]
    fn test_session_metadata() {
        let mut session = create_test_session();

        session.set_metadata("user".to_string(), "alice".to_string());
        session.set_metadata("role".to_string(), "admin".to_string());

        assert_eq!(session.get_metadata("user"), Some(&"alice".to_string()));
        assert_eq!(session.get_metadata("role"), Some(&"admin".to_string()));
        assert_eq!(session.get_metadata("nonexistent"), None);
    }

    #[test]
    fn test_session_manager_creation() {
        let manager = SessionManager::default();
        assert_eq!(manager.active_session_count(), 0);
    }

    #[test]
    fn test_session_manager_create_session() {
        let mut manager = SessionManager::default();
        let key = [1u8; SESSION_KEY_SIZE];
        let client_id = b"client1".to_vec();

        let session_id = manager.create_session(key, client_id).unwrap();
        assert_eq!(manager.active_session_count(), 1);

        let session = manager.get_session(&session_id).unwrap();
        assert_eq!(session.state, SessionState::Active);
    }

    #[test]
    fn test_session_manager_validate_session() {
        let mut manager = SessionManager::default();
        let key = [1u8; SESSION_KEY_SIZE];
        let client_id = b"client1".to_vec();

        let session_id = manager.create_session(key, client_id).unwrap();
        assert!(manager.validate_session(&session_id).is_ok());
    }

    #[test]
    fn test_session_manager_terminate_session() {
        let mut manager = SessionManager::default();
        let key = [1u8; SESSION_KEY_SIZE];
        let client_id = b"client1".to_vec();

        let session_id = manager.create_session(key, client_id).unwrap();
        assert_eq!(manager.active_session_count(), 1);

        manager.terminate_session(&session_id).unwrap();
        assert_eq!(manager.active_session_count(), 0);
    }

    #[test]
    fn test_session_manager_max_sessions() {
        let mut manager = SessionManager::new(2, DEFAULT_SESSION_TIMEOUT);

        let key1 = [1u8; SESSION_KEY_SIZE];
        let key2 = [2u8; SESSION_KEY_SIZE];
        let key3 = [3u8; SESSION_KEY_SIZE];

        manager.create_session(key1, b"client1".to_vec()).unwrap();
        manager.create_session(key2, b"client2".to_vec()).unwrap();

        let result = manager.create_session(key3, b"client3".to_vec());
        assert_eq!(result, Err(SessionError::SessionLimitReached));
    }

    #[test]
    fn test_session_manager_get_all_session_ids() {
        let mut manager = SessionManager::default();

        let key1 = [1u8; SESSION_KEY_SIZE];
        let key2 = [2u8; SESSION_KEY_SIZE];

        let id1 = manager.create_session(key1, b"client1".to_vec()).unwrap();
        let id2 = manager.create_session(key2, b"client2".to_vec()).unwrap();

        let all_ids = manager.get_all_session_ids();
        assert_eq!(all_ids.len(), 2);
        assert!(all_ids.contains(&id1));
        assert!(all_ids.contains(&id2));
    }

    #[test]
    fn test_session_manager_terminate_all() {
        let mut manager = SessionManager::default();

        let key1 = [1u8; SESSION_KEY_SIZE];
        let key2 = [2u8; SESSION_KEY_SIZE];

        manager.create_session(key1, b"client1".to_vec()).unwrap();
        manager.create_session(key2, b"client2".to_vec()).unwrap();

        assert_eq!(manager.active_session_count(), 2);

        manager.terminate_all();
        assert_eq!(manager.active_session_count(), 0);
    }

    #[test]
    fn test_constant_time_eq() {
        let a = [1u8; 32];
        let b = [1u8; 32];
        let c = [2u8; 32];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }

    #[test]
    fn test_session_age() {
        let session = create_test_session();
        std::thread::sleep(Duration::from_millis(100));

        let age = session.age().unwrap();
        // Age should be a small positive number (at least 0, likely > 0 after sleep)
        assert!(age < 10); // Should be less than 10 seconds
    }

    #[test]
    fn test_session_time_to_expiry() {
        let session = create_test_session();
        let time_left = session.time_to_expiry().unwrap();

        assert!(time_left > 0);
        assert!(time_left <= DEFAULT_SESSION_TIMEOUT);
    }

    #[test]
    fn test_session_id_generation() {
        let key1 = [1u8; SESSION_KEY_SIZE];
        let key2 = [2u8; SESSION_KEY_SIZE];
        let client_id = b"test-client".to_vec();
        let timestamp = 1234567890;

        let id1 = generate_session_id(&key1, &client_id, timestamp);
        let id2 = generate_session_id(&key2, &client_id, timestamp);
        let id3 = generate_session_id(&key1, &client_id, timestamp);

        // Different keys should produce different IDs
        assert_ne!(id1, id2);

        // Same inputs should produce same ID
        assert_eq!(id1, id3);
    }

    #[test]
    fn test_max_session_lifetime() {
        let key = [1u8; SESSION_KEY_SIZE];
        let client_id = b"test-client".to_vec();

        // Request a timeout longer than the maximum
        let session = Session::new(key, client_id, MAX_SESSION_LIFETIME + 1000).unwrap();

        let timeout = session.expires_at - session.created_at;
        assert!(timeout <= MAX_SESSION_LIFETIME);
    }
}
