//! Request handlers for Admin API

pub mod api_keys;
pub mod audit;
pub mod certificates;
pub mod config;
pub mod connections;
pub mod devices;
pub mod federation;
pub mod health;
pub mod monitoring;
pub mod sessions;
pub mod users;

pub use api_keys::*;
pub use audit::*;
pub use certificates::*;
pub use config::*;
pub use connections::*;
pub use devices::*;
pub use federation::*;
pub use health::*;
pub use monitoring::*;
pub use sessions::*;
pub use users::*;
