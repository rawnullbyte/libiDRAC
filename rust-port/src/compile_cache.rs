//! Content-addressed cache for compiled SH4 payload artifacts.
//!
//! Cross-compiling each payload with `sh4-linux-gnu-gcc` is by far the
//! slowest step of an exploit run, and the compiled `.so` depends only on
//! the rendered C source — identical runs (same payload, same credentials)
//! can therefore skip the compiler entirely and reuse a cached artifact.
//!
//! Artifacts live under the OS temp directory, keyed by a 64-bit FNV-1a
//! hash of the rendered source plus its byte length (the length is in the
//! filename so truncated/partial files fail the size sanity check on load).
//! Set `LIBIDRAC_NO_CACHE=1` to opt out entirely.

use std::fs;
use std::path::PathBuf;

use rand::RngCore;

/// Whether caching is enabled (env-var opt-out; checked every call so
/// flipping the variable affects subsequently spawned runs too).
pub fn is_enabled() -> bool {
    std::env::var_os("LIBIDRAC_NO_CACHE")
        .map(|v| v != "1")
        .unwrap_or(true)
}

/// 64-bit FNV-1a. Not a security primitive — just stable across runs,
/// collision-resistant enough for short C sources, and dependency-free.
pub fn fnv1a(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Where cached artifacts live (`<tempdir>/libidrac-payload-cache`).
pub fn cache_dir() -> PathBuf {
    std::env::temp_dir().join("libidrac-payload-cache")
}

/// Cache entry path for a *rendered* payload source.
pub fn entry_path(rendered: &str) -> PathBuf {
    let hash = fnv1a(rendered.as_bytes());
    cache_dir().join(format!("{hash:016x}-{}.so", rendered.len()))
}

/// Returns the cached artifact for `rendered`, if it exists and passes the
/// sanity gates (ELF magic + minimum shared-object size). Anything else is
/// treated as corruption and recompiled.
pub fn lookup(rendered: &str) -> Option<Vec<u8>> {
    if !is_enabled() {
        return None;
    }
    let bytes = fs::read(entry_path(rendered)).ok()?;
    if bytes.len() < 16 || bytes[..4] != [0x7f, b'E', b'L', b'F'] {
        return None;
    }
    Some(bytes)
}

/// Stores a successful compile result in the cache. Best effort — cache
/// failures must never fail an exploit run, so every error is swallowed.
///
/// The write is publish-atomically: a uniquely named temp file is written
/// first, then renamed into place, so concurrent exploit runs cannot observe
/// a half-written artifact.
pub fn store(rendered: &str, so: &[u8]) {
    if !is_enabled() || so.len() < 16 {
        return;
    }
    let dir = cache_dir();
    if fs::create_dir_all(&dir).is_err() {
        return;
    }
    let final_path = entry_path(rendered);
    let mut suffix = [0u8; 4];
    rand::rng().fill_bytes(&mut suffix);
    let name = final_path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("payload.so");
    let tmp_path = dir.join(format!("{name}.{}.tmp", hex::encode(suffix)));
    if fs::write(&tmp_path, so).is_ok() {
        let _ = fs::rename(&tmp_path, &final_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a_matches_reference_vectors() {
        // Published FNV-1a test vectors.
        assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a(b"foobar"), 0x8594_4171_f739_67e8);
    }

    #[test]
    fn entry_path_embeds_hash_and_length() {
        let rendered = "int main() { return 0; }";
        let path = entry_path(rendered);
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        assert!(name.ends_with(&format!("-{}.so", rendered.len())));
        let hash_part = name.split('-').next().unwrap();
        assert_eq!(hash_part.len(), 16); // 64-bit hash as zero-padded hex
    }

    #[test]
    fn store_and_lookup_roundtrip() {
        let uniq_suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        let rendered = format!("roundtrip-test-{uniq_suffix}");
        let fake_so: Vec<u8> = [vec![0x7f, b'E', b'L', b'F'], vec![0; 12]].concat();
        store(&rendered, &fake_so);
        assert_eq!(lookup(&rendered).as_deref(), Some(&fake_so[..]));
        // Clean up so repeated test runs stay tidy.
        let _ = fs::remove_file(entry_path(&rendered));
    }

    #[test]
    fn lookup_rejects_non_elf_garbage() {
        let uniq_suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        let rendered = format!("garbage-test-{uniq_suffix}");
        store(&rendered, &[b'x'; 40]); // right size, wrong magic
        assert!(lookup(&rendered).is_none());
        let _ = fs::remove_file(entry_path(&rendered));
    }
}
