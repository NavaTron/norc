//! Request handlers for Admin API

pub mod health;
pub mod users;
pub mod devices;
pub mod config;
pub mod monitoring;
pub mod federation;
pub mod audit;
pub mod api_keys;

pub use health::*;
pub use users::*;
pub use devices::*;
pub use config::*;
pub use monitoring::*;
pub use federation::*;
pub use audit::*;
pub use api_keys::*;
