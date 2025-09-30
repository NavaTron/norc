//! Federation engine per SERVER_REQUIREMENTS E-01

use norc_config::ServerConfig;
use norc_protocol::{TrustLevel, ProtocolVersion};
use norc_transport::tls::TlsClientTransport;
use rustls::ClientConfig;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error};

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
}

/// Federation engine manages inter-server communication
pub struct FederationEngine {
    config: Arc<ServerConfig>,
    /// Active federation partners
    partners: Arc<RwLock<HashMap<String, FederationPartner>>>,
    /// Protocol version for federation
    protocol_version: ProtocolVersion,
}

impl FederationEngine {
    /// Create a new federation engine
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self {
            config,
            partners: Arc::new(RwLock::new(HashMap::new())),
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
            };

            partners.insert(partner.org_id.clone(), partner);
            info!("Registered federation partner: {}", partner_config.organization_id);
        }

        Ok(())
    }

    /// Connect to a federation partner
    pub async fn connect_partner(&self, org_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut partners = self.partners.write().await;

        let partner = partners.get_mut(org_id)
            .ok_or_else(|| format!("Unknown partner: {}", org_id))?;

        partner.state = PartnerState::Connecting;
        info!("Connecting to federation partner: {}", org_id);

        // Create TLS client config
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned()
        );
        
        let tls_config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        );
        
        match TlsClientTransport::connect(&partner.address, tls_config).await {
            Ok(_transport) => {
                partner.state = PartnerState::Connected;
                info!("Successfully connected to partner: {}", org_id);
                Ok(())
            }
            Err(e) => {
                let error_msg = format!("Connection failed: {}", e);
                partner.state = PartnerState::Failed(error_msg.clone());
                error!("Failed to connect to partner {}: {}", org_id, error_msg);
                Err(error_msg.into())
            }
        }
    }

    /// Route a message to the appropriate federation partner
    pub async fn route_message(
        &self,
        target_org: &str,
        message: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let partners = self.partners.read().await;

        let partner = partners.get(target_org)
            .ok_or_else(|| format!("Unknown target organization: {}", target_org))?;

        if !matches!(partner.state, PartnerState::Connected) {
            return Err(format!("Partner {} not connected", target_org).into());
        }

        // TODO: Implement actual message routing
        info!("Routing message to {} ({} bytes)", target_org, message.len());

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
}
