//! Federation engine per SERVER_REQUIREMENTS E-05

use norc_config::ServerConfig;
use norc_protocol::{messages::EncryptedMessage, TrustLevel, ProtocolVersion};
use norc_transport::tls::{TlsClientTransport, TlsServerTransport};
use norc_transport::Transport;
use rustls::ClientConfig;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};
use tracing::{info, error, warn};

/// Federation partner connection state
#[derive(Debug, Clone)]
pub enum PartnerState {
    /// Disconnected
    Disconnected,
    /// Connecting
    Connecting,
    /// Connected and authenticated
    Connected,
    /// Connection failed
    Failed(String),
}

/// Active federation connection
pub struct FederationConnection {
    /// Transport for this connection
    pub transport: Arc<Mutex<TlsClientTransport>>,
    /// Organization ID
    pub org_id: String,
    /// Connected timestamp
    pub connected_at: std::time::Instant,
    /// Last activity timestamp
    pub last_activity: std::time::Instant,
}

/// Federation partner information
#[derive(Debug, Clone)]
pub struct FederationPartner {
    /// Organization ID
    pub org_id: String,
    /// Partner address
    pub address: String,
    /// Trust level
    pub trust_level: TrustLevel,
    /// Connection state
    pub state: PartnerState,
    /// Number of connection attempts
    pub connection_attempts: u32,
}

/// Federation handshake request
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct FederationHandshake {
    /// Organization ID
    pub org_id: String,
    /// Protocol version
    pub protocol_version: ProtocolVersion,
    /// Server certificate fingerprint
    pub cert_fingerprint: String,
    /// Trust level requested
    pub trust_level: TrustLevel,
}

/// Federation handshake response
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct FederationHandshakeResponse {
    /// Accepted
    pub accepted: bool,
    /// Server organization ID
    pub org_id: String,
    /// Protocol version
    pub protocol_version: ProtocolVersion,
    /// Error message if rejected
    pub error: Option<String>,
}

/// Federation engine manages inter-server communication
pub struct FederationEngine {
    config: Arc<ServerConfig>,
    /// Active federation partners
    partners: Arc<RwLock<HashMap<String, FederationPartner>>>,
    /// Active connections (org_id -> connection)
    connections: Arc<RwLock<HashMap<String, Arc<FederationConnection>>>>,
    /// Protocol version for federation
    protocol_version: ProtocolVersion,
}

impl FederationEngine {
    /// Create a new federation engine
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self {
            config,
            partners: Arc::new(RwLock::new(HashMap::new())),
            connections: Arc::new(RwLock::new(HashMap::new())),
            protocol_version: ProtocolVersion::CURRENT,
        }
    }

    /// Initialize federation with configured partners
    pub async fn initialize(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Initializing federation engine...");

        let mut partners = self.partners.write().await;

        for partner_config in &self.config.federation.partners {
            let trust_level = TrustLevel::parse(&partner_config.trust_level)
                .unwrap_or(TrustLevel::Basic);

            let partner = FederationPartner {
                org_id: partner_config.organization_id.clone(),
                address: partner_config.address.clone(),
                trust_level,
                state: PartnerState::Disconnected,
                connection_attempts: 0,
            };

            partners.insert(partner.org_id.clone(), partner);
            info!("Registered federation partner: {}", partner_config.organization_id);
        }

        // Start connection management background task
        self.start_connection_manager();

        Ok(())
    }

    /// Start background task for connection management
    fn start_connection_manager(&self) {
        let partners = Arc::clone(&self.partners);
        let connections = Arc::clone(&self.connections);
        let engine = self.clone_engine();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                
                // Check and reconnect disconnected partners
                let partner_list = {
                    let p = partners.read().await;
                    p.values().cloned().collect::<Vec<_>>()
                };

                for partner in partner_list {
                    if matches!(partner.state, PartnerState::Disconnected | PartnerState::Failed(_)) {
                        info!("Attempting to reconnect to partner: {}", partner.org_id);
                        if let Err(e) = engine.connect_partner(&partner.org_id).await {
                            warn!("Failed to reconnect to {}: {}", partner.org_id, e);
                        }
                    }
                }

                // Clean up stale connections
                let conns = connections.read().await;
                for (org_id, conn) in conns.iter() {
                    let idle_time = conn.last_activity.elapsed().as_secs();
                    if idle_time > 300 {  // 5 minutes
                        info!("Connection to {} idle for {}s, will reconnect if needed", org_id, idle_time);
                    }
                }
            }
        });
    }

    /// Clone engine for background tasks
    fn clone_engine(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            partners: Arc::clone(&self.partners),
            connections: Arc::clone(&self.connections),
            protocol_version: self.protocol_version,
        }
    }

    /// Connect to a federation partner
    pub async fn connect_partner(&self, org_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut partners = self.partners.write().await;

        let partner = partners.get_mut(org_id)
            .ok_or_else(|| format!("Unknown partner: {}", org_id))?;

        partner.state = PartnerState::Connecting;
        partner.connection_attempts += 1;
        info!("Connecting to federation partner: {} (attempt {})", org_id, partner.connection_attempts);

        // Create TLS client config with mutual TLS
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned()
        );
        
        let tls_config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()  // TODO: Add client certificate auth
        );
        
        match TlsClientTransport::connect(&partner.address, tls_config).await {
            Ok(transport) => {
                // Perform federation handshake
                match self.perform_handshake(&transport, &partner.org_id).await {
                    Ok(_) => {
                        let connection = Arc::new(FederationConnection {
                            transport: Arc::new(Mutex::new(transport)),
                            org_id: org_id.to_string(),
                            connected_at: std::time::Instant::now(),
                            last_activity: std::time::Instant::now(),
                        });

                        self.connections.write().await.insert(org_id.to_string(), connection);
                        partner.state = PartnerState::Connected;
                        partner.connection_attempts = 0;
                        info!("Successfully connected to partner: {}", org_id);
                        Ok(())
                    }
                    Err(e) => {
                        let error_msg = format!("Handshake failed: {}", e);
                        partner.state = PartnerState::Failed(error_msg.clone());
                        error!("Federation handshake failed for {}: {}", org_id, error_msg);
                        Err(error_msg.into())
                    }
                }
            }
            Err(e) => {
                let error_msg = format!("Connection failed: {}", e);
                partner.state = PartnerState::Failed(error_msg.clone());
                error!("Failed to connect to partner {}: {}", org_id, error_msg);
                Err(error_msg.into())
            }
        }
    }

    /// Perform federation handshake
    async fn perform_handshake(
        &self,
        transport: &TlsClientTransport,
        org_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let handshake = FederationHandshake {
            org_id: self.config.organization_id.clone(),
            protocol_version: self.protocol_version,
            cert_fingerprint: "".to_string(),  // TODO: Get actual cert fingerprint
            trust_level: TrustLevel::Basic,
        };

        let handshake_data = bincode::serialize(&handshake)?;
        transport.send(&handshake_data).await?;

        // Receive handshake response
        let response_data = transport.receive().await?;
        let response: FederationHandshakeResponse = bincode::deserialize(&response_data)?;

        if !response.accepted {
            return Err(format!("Handshake rejected: {:?}", response.error).into());
        }

        info!("Federation handshake successful with {}", org_id);
        Ok(())
    }

    /// Handle incoming federation handshake
    pub async fn handle_handshake(
        &self,
        transport: Arc<Mutex<TlsServerTransport>>,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let mut transport_guard = transport.lock().await;
        
        // Receive handshake request
        let handshake_data = transport_guard.receive().await?;
        let handshake: FederationHandshake = bincode::deserialize(&handshake_data)?;

        info!("Received federation handshake from {}", handshake.org_id);

        // Validate handshake
        let partners = self.partners.read().await;
        let partner = partners.get(&handshake.org_id);

        let response = if let Some(partner) = partner {
            // Simple protocol version check (for now, just check major version)
            let version_compatible = handshake.protocol_version.major == self.protocol_version.major;
            
            if version_compatible {
                FederationHandshakeResponse {
                    accepted: true,
                    org_id: self.config.organization_id.clone(),
                    protocol_version: self.protocol_version,
                    error: None,
                }
            } else {
                FederationHandshakeResponse {
                    accepted: false,
                    org_id: self.config.organization_id.clone(),
                    protocol_version: self.protocol_version,
                    error: Some("Incompatible protocol version".to_string()),
                }
            }
        } else {
            FederationHandshakeResponse {
                accepted: false,
                org_id: self.config.organization_id.clone(),
                protocol_version: self.protocol_version,
                error: Some("Unknown organization".to_string()),
            }
        };

        let response_data = bincode::serialize(&response)?;
        transport_guard.send(&response_data).await?;

        if response.accepted {
            Ok(handshake.org_id)
        } else {
            Err(format!("Handshake rejected: {:?}", response.error).into())
        }
    }

    /// Route a message to the appropriate federation partner
    pub async fn route_message(
        &self,
        target_org: &str,
        message: &EncryptedMessage,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connections = self.connections.read().await;

        let connection = connections.get(target_org)
            .ok_or_else(|| format!("No active connection to: {}", target_org))?;

        // Serialize and send message
        let message_data = bincode::serialize(message)?;
        let mut transport = connection.transport.lock().await;
        transport.send(&message_data).await?;

        info!("Routed message to {} ({} bytes)", target_org, message_data.len());
        Ok(())
    }

    /// Get federation partner status
    pub async fn get_partner_status(&self, org_id: &str) -> Option<PartnerState> {
        let partners = self.partners.read().await;
        partners.get(org_id).map(|p| p.state.clone())
    }

    /// List all federation partners
    pub async fn list_partners(&self) -> Vec<FederationPartner> {
        let partners = self.partners.read().await;
        partners.values().cloned().collect()
    }

    /// Disconnect from a partner
    pub async fn disconnect_partner(&self, org_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut connections = self.connections.write().await;
        
        if let Some(conn) = connections.remove(org_id) {
            let mut transport = conn.transport.lock().await;
            transport.close().await?;
            info!("Disconnected from federation partner: {}", org_id);
        }

        let mut partners = self.partners.write().await;
        if let Some(partner) = partners.get_mut(org_id) {
            partner.state = PartnerState::Disconnected;
        }

        Ok(())
    }
}
