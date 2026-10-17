//! # libiDRAC — Rust port
//!
//! Educational port of the Python [`libiDRAC`](https://github.com/rawnullbyte/libiDRAC)
//! library (`libiDRAC/idrac.py`). It talks to Dell iDRAC management interfaces
//! and reproduces the upstream logic: fingerprinting, firmware/LD_DEBUG
//! vulnerability probing, the raw `RACPKSSHAUTHKEY1` packet upload channel, and
//! a `racadm`-driven BIOS inventory over SSH.
//!
//! ```no_run
//! use libidrac::IDrac;
//!
//! # async fn demo() -> anyhow::Result<()> {
//! let mut idrac = IDrac::new("10.0.0.10", 443)?;
//! idrac.set_credentials("root", "calvin");
//!
//! let info = idrac.get_info().await?;
//! println!("{}", serde_json::to_string_pretty(&info)?);
//!
//! let vuln = idrac.check_if_vulnerable().await?;
//! println!("{}", serde_json::to_string_pretty(&vuln)?);
//!
//! let inventory = idrac.get_inventory(Some("root"), Some("calvin")).await;
//! println!("{}", serde_json::to_string_pretty(&inventory)?);
//! # Ok(())
//! # }
//! ```
//!
//! Everything here is for education / lab use only — don't point it at
//! anything you are not authorized to touch.

pub mod compile_cache;
pub mod idrac;
pub mod payloads;

pub use idrac::{
    ExploitCredentials, ExploitParams, ExploitResult, ExploitReverseShell, IDrac, InventoryResult,
    InfoResult, Options, VulnerabilityResult,
};

/// Library version (`__version__` in `libiDRAC/__init__.py`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Author tag (`__author__` in `libiDRAC/__init__.py`).
pub const AUTHOR: &str = "Nulla Baytu :3";
