//! Repository traits and implementations

pub mod audit;
pub mod device;
pub mod federation;
pub mod message;
pub mod presence;
pub mod session;
pub mod user;

pub use audit::AuditRepository;
pub use device::DeviceRepository;
pub use federation::FederationRepository;
pub use message::MessageRepository;
pub use presence::PresenceRepository;
pub use session::SessionRepository;
pub use user::UserRepository;
