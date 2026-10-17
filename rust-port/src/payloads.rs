//! Payload sources. The Python package shipped `payloads/*.c` as package data
//! and discovered them with `os.listdir`; the Rust port embeds them into the
//! binary with `include_str!` so there is no runtime file layout (and the
//! `exploit()` "payload file not found" branch can no longer occur).

use std::path::PathBuf;

const ADDUSER_NAME: &str = "adduser";
const ADDUSER_ENTERPRISE_NAME: &str = "adduser_enterprise";
const QUICKPAYLOAD_NAME: &str = "quickpayload";
const REVERSESHELL_NAME: &str = "reverseshell";

/// Embedded copy of `payloads/adduser.c`.
pub const ADDUSER: &str = include_str!("payloads/adduser.c");
/// Embedded copy of `payloads/adduser_enterprise.c`.
pub const ADDUSER_ENTERPRISE: &str = include_str!("payloads/adduser_enterprise.c");
/// Embedded copy of `payloads/quickpayload.c`.
pub const QUICKPAYLOAD: &str = include_str!("payloads/quickpayload.c");
/// Embedded copy of `payloads/reverseshell.c`.
pub const REVERSESHELL: &str = include_str!("payloads/reverseshell.c");

/// One registered payload (`<name>.c` in the Python payloads directory).
#[derive(Debug, Clone, Copy)]
pub struct Payload {
    pub name: &'static str,
    pub source: &'static str,
}

/// All payloads shipped with the crate.
pub const PAYLOADS: [Payload; 4] = [
    Payload { name: ADDUSER_NAME, source: ADDUSER },
    Payload { name: ADDUSER_ENTERPRISE_NAME, source: ADDUSER_ENTERPRISE },
    Payload { name: QUICKPAYLOAD_NAME, source: QUICKPAYLOAD },
    Payload { name: REVERSESHELL_NAME, source: REVERSESHELL },
];

/// The Rust-port copy of the original C payload directory (kept verbatim in
/// `src/payloads/*.c` so the sources remain inspectable next to the binary).
pub fn payload_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src").join("payloads")
}

/// `payload_type` -> C source (`{name}.c`).
pub fn source_for(name: &str) -> Option<&'static str> {
    PAYLOADS.iter().find(|p| p.name == name).map(|p| p.source)
}

/// Available payload types (python's `availableTypes` probe result).
pub fn names() -> Vec<&'static str> {
    PAYLOADS.iter().map(|p| p.name).collect()
}
