//! NavaTron NORC Server Binary
#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![deny(trivial_casts, trivial_numeric_casts, unused_import_braces, unused_qualifications)]
#![warn(missing_docs)]

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    println!("NavaTron NORC Server");
    println!("TODO: Implement server application");
    Ok(())
}