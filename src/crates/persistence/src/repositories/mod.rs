//! Repository traits and implementations

pub mod user;
pub mod device;
pub mod session;
pub mod message;
pub mod federation;
pub mod presence;
pub mod audit;

pub use user::UserRepository;
pub use device::DeviceRepository;
pub use session::SessionRepository;
pub use message::MessageRepository;
pub use federation::FederationRepository;
pub use presence::PresenceRepository;
pub use audit::AuditRepository;
