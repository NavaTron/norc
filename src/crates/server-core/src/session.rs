//! Client session management

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

use navatron_protocol::{
    messages::NorcMessage,
    types::{DeviceId, SessionId, UserId},
};
use navatron_transport::connection::ConnectionHandle;

use crate::error::{ServerError, Result};

/// Client session state
#[derive(Debug, Clone, PartialEq)]
pub enum SessionState {
    /// Session is connecting
    Connecting,
    /// Session is connected but not authenticated
    Connected,
    /// Session is authenticated and active
    Authenticated,
    /// Session is inactive but not disconnected
    Inactive,
    /// Session is disconnecting
    Disconnecting,
    /// Session is terminated
    Terminated,
}

/// Client session information
pub struct ClientSession {
    /// Session identifier
    session_id: SessionId,
    /// Device identifier (set after authentication)
    device_id: Option<DeviceId>,
    /// User identifier (set after authentication)
    user_id: Option<UserId>,
    /// Session state
    state: SessionState,
    /// Client remote address
    remote_addr: SocketAddr,
    /// Connection handle
    connection: ConnectionHandle,
    /// Session creation time
    created_at: Instant,
    /// Last activity time
    last_activity: Instant,
    /// Message sender for this session
    message_sender: mpsc::UnboundedSender<NorcMessage>,
    /// Session metadata
    metadata: HashMap<String, String>,
}

impl ClientSession {
    /// Create a new client session
    pub fn new(
        session_id: SessionId,
        remote_addr: SocketAddr,
        connection: ConnectionHandle,
        message_sender: mpsc::UnboundedSender<NorcMessage>,
    ) -> Self {
        let now = Instant::now();
        
        Self {
            session_id,
            device_id: None,
            user_id: None,
            state: SessionState::Connecting,
            remote_addr,
            connection,
            created_at: now,
            last_activity: now,
            message_sender,
            metadata: HashMap::new(),
        }
    }
    
    /// Get session ID
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }
    
    /// Get device ID (if authenticated)
    pub fn device_id(&self) -> Option<DeviceId> {
        self.device_id
    }
    
    /// Get user ID (if authenticated)
    pub fn user_id(&self) -> Option<UserId> {
        self.user_id.clone()
    }
    
    /// Get session state
    pub fn state(&self) -> &SessionState {
        &self.state
    }
    
    /// Get remote address
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
    
    /// Get session age
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }
    
    /// Get time since last activity
    pub fn idle_time(&self) -> Duration {
        self.last_activity.elapsed()
    }
    
    /// Update session state
    pub fn set_state(&mut self, state: SessionState) {
        debug!(
            session_id = %self.session_id,
            old_state = ?self.state,
            new_state = ?state,
            "Session state transition"
        );
        self.state = state;
        self.update_activity();
    }
    
    /// Authenticate the session with device and user information
    pub fn authenticate(&mut self, device_id: DeviceId, user_id: UserId) -> Result<()> {
        if self.state != SessionState::Connected {
            return Err(ServerError::session(format!(
                "Cannot authenticate session in state {:?}",
                self.state
            )));
        }
        
        self.device_id = Some(device_id);
        self.user_id = Some(user_id.clone());
        self.state = SessionState::Authenticated;
        self.update_activity();
        
        info!(
            session_id = %self.session_id,
            device_id = %device_id,
            user_id = %user_id,
            "Session authenticated"
        );
        
        Ok(())
    }
    
    /// Send a message to this session
    pub async fn send_message(&self, message: NorcMessage) -> Result<()> {
        self.message_sender
            .send(message)
            .map_err(|_| ServerError::session("Failed to send message to session"))?;
        Ok(())
    }
    
    /// Update last activity timestamp
    pub fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }
    
    /// Set session metadata
    pub fn set_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }
    
    /// Get session metadata
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }
    
    /// Check if session is authenticated
    pub fn is_authenticated(&self) -> bool {
        matches!(self.state, SessionState::Authenticated)
    }
    
    /// Check if session is active
    pub fn is_active(&self) -> bool {
        matches!(
            self.state,
            SessionState::Connected | SessionState::Authenticated
        )
    }
    
    /// Check if session is expired based on idle time
    pub fn is_expired(&self, max_idle: Duration) -> bool {
        self.idle_time() > max_idle
    }
}

/// Session manager handles all active client sessions
pub struct SessionManager {
    /// Active sessions by session ID
    sessions: Arc<RwLock<HashMap<SessionId, ClientSession>>>,
    /// Session lookup by device ID
    device_sessions: Arc<RwLock<HashMap<DeviceId, SessionId>>>,
    /// Session lookup by user ID
    user_sessions: Arc<RwLock<HashMap<UserId, Vec<SessionId>>>>,
    /// Maximum number of concurrent sessions
    max_sessions: usize,
    /// Session timeout duration
    session_timeout: Duration,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new(max_sessions: usize, session_timeout: Duration) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            device_sessions: Arc::new(RwLock::new(HashMap::new())),
            user_sessions: Arc::new(RwLock::new(HashMap::new())),
            max_sessions,
            session_timeout,
        }
    }
    
    /// Add a new session
    pub async fn add_session(&self, session: ClientSession) -> Result<()> {
        let session_id = session.session_id();
        
        let mut sessions = self.sessions.write().await;
        
        // Check session limit
        if sessions.len() >= self.max_sessions {
            return Err(ServerError::resource_limit("sessions", self.max_sessions as u64));
        }
        
        sessions.insert(session_id, session);
        
        info!(
            session_id = %session_id,
            total_sessions = sessions.len(),
            "Session added"
        );
        
        Ok(())
    }
    
    /// Remove a session
    pub async fn remove_session(&self, session_id: SessionId) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        
        if let Some(session) = sessions.remove(&session_id) {
            // Clean up lookup tables
            if let Some(device_id) = session.device_id() {
                self.device_sessions.write().await.remove(&device_id);
            }
            
            if let Some(user_id) = session.user_id() {
                let mut user_sessions = self.user_sessions.write().await;
                if let Some(session_list) = user_sessions.get_mut(&user_id) {
                    session_list.retain(|&id| id != session_id);
                    if session_list.is_empty() {
                        user_sessions.remove(&user_id);
                    }
                }
            }
            
            info!(
                session_id = %session_id,
                total_sessions = sessions.len(),
                "Session removed"
            );
        }
        
        Ok(())
    }
    
    /// Get a session by ID
    pub async fn get_session(&self, session_id: SessionId) -> Option<SessionId> {
        if self.sessions.read().await.contains_key(&session_id) {
            Some(session_id)
        } else {
            None
        }
    }
    
    /// Authenticate a session
    pub async fn authenticate_session(
        &self,
        session_id: SessionId,
        device_id: DeviceId,
        user_id: UserId,
    ) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        
        let session = sessions
            .get_mut(&session_id)
            .ok_or_else(|| ServerError::session("Session not found"))?;
        
        session.authenticate(device_id, user_id.clone())?;
        
        // Update lookup tables
        self.device_sessions.write().await.insert(device_id, session_id);
        
        let mut user_sessions = self.user_sessions.write().await;
        user_sessions
            .entry(user_id)
            .or_insert_with(Vec::new)
            .push(session_id);
        
        Ok(())
    }
    
    /// Get session by device ID
    pub async fn get_session_by_device(&self, device_id: DeviceId) -> Option<SessionId> {
        let device_sessions = self.device_sessions.read().await;
        device_sessions.get(&device_id).copied()
    }
    
    /// Get all sessions for a user
    pub async fn get_user_sessions(&self, user_id: &UserId) -> Vec<SessionId> {
        let user_sessions = self.user_sessions.read().await;
        user_sessions.get(user_id).cloned().unwrap_or_default()
    }
    
    /// Get total number of active sessions
    pub async fn session_count(&self) -> usize {
        self.sessions.read().await.len()
    }
    
    /// Get total number of authenticated sessions
    pub async fn authenticated_session_count(&self) -> usize {
        self.sessions
            .read()
            .await
            .values()
            .filter(|session| session.is_authenticated())
            .count()
    }
    
    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) -> Result<usize> {
        let expired_sessions: Vec<SessionId> = {
            let sessions = self.sessions.read().await;
            sessions
                .values()
                .filter(|session| session.is_expired(self.session_timeout))
                .map(|session| session.session_id())
                .collect()
        };
        
        let cleanup_count = expired_sessions.len();
        
        for session_id in expired_sessions {
            self.remove_session(session_id).await?;
            warn!(session_id = %session_id, "Removed expired session");
        }
        
        if cleanup_count > 0 {
            info!(expired_count = cleanup_count, "Cleaned up expired sessions");
        }
        
        Ok(cleanup_count)
    }
    
    /// Send a message to a specific session
    pub async fn send_to_session(&self, session_id: SessionId, message: NorcMessage) -> Result<()> {
        let sessions = self.sessions.read().await;
        let session = sessions
            .get(&session_id)
            .ok_or_else(|| ServerError::session("Session not found"))?;
        
        session.send_message(message).await?;
        Ok(())
    }
    
    /// Send a message to a device (if online)
    pub async fn send_to_device(&self, device_id: DeviceId, message: NorcMessage) -> Result<bool> {
        if let Some(session_id) = self.get_session_by_device(device_id).await {
            let sessions = self.sessions.read().await;
            if let Some(session) = sessions.get(&session_id) {
                session.send_message(message).await?;
                Ok(true)
            } else {
                Ok(false) // Session no longer exists
            }
        } else {
            Ok(false) // Device not online
        }
    }
    
    /// Send a message to all sessions for a user
    pub async fn send_to_user(&self, user_id: &UserId, message: NorcMessage) -> Result<usize> {
        let session_ids = self.get_user_sessions(user_id).await;
        let mut sent_count = 0;
        
        let sessions = self.sessions.read().await;
        for session_id in session_ids {
            if let Some(session) = sessions.get(&session_id) {
                if session.send_message(message.clone()).await.is_ok() {
                    sent_count += 1;
                }
            }
        }
        
        Ok(sent_count)
    }
}