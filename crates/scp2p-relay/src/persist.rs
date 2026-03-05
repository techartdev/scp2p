// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0

//! `--persist` sub-command: install `scp2p-relay` as a system service.
//!
//! Platform support:
//! - **Linux**: writes a systemd unit to `/etc/systemd/system/scp2p-relay.service`
//!   then runs `systemctl daemon-reload && systemctl enable --now scp2p-relay`.
//! - **macOS**: writes a launchd plist to
//!   `/Library/LaunchDaemons/com.scp2p.relay.plist` then runs `launchctl bootstrap`.
//! - **Windows**: registers a Windows SCM service via `sc.exe`.
//!
//! The `ExecStart` / service command is reconstructed automatically from the
//! current binary path plus every CLI argument passed *except* `--persist`.

use std::{
    env,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};

use anyhow::{Context, bail};

/// Install `scp2p-relay` as a persistent system service.
///
/// `original_args` should be `std::env::args().skip(1).collect()` *before*
/// clap parses them — that way we can faithfully reconstruct the full command
/// line the operator typed, minus the `--persist` flag itself.
pub fn install_service(original_args: &[String]) -> anyhow::Result<()> {
    let bin = current_exe_path()?;

    // Strip --persist (and the bare form in case people type "-p") from args.
    let relay_args: Vec<&str> = original_args
        .iter()
        .filter(|a| *a != "--persist")
        .map(String::as_str)
        .collect();

    #[cfg(target_os = "linux")]
    return install_systemd(&bin, &relay_args);

    #[cfg(target_os = "macos")]
    return install_launchd(&bin, &relay_args);

    #[cfg(target_os = "windows")]
    return install_windows_service(&bin, &relay_args);

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    bail!("--persist is not supported on this platform");
}

// ── helpers ────────────────────────────────────────────────────────

fn current_exe_path() -> anyhow::Result<PathBuf> {
    let exe = env::current_exe().context("cannot determine current binary path")?;
    // Canonicalize resolves symlinks so the service always points to the real file.
    exe.canonicalize().or(Ok(exe)) // ignore errors on platforms where canonicalize is fragile
}

fn run_cmd(program: &str, args: &[&str]) -> anyhow::Result<ExitStatus> {
    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("failed to run `{program}`"))?;
    Ok(status)
}

fn check_cmd(program: &str, args: &[&str]) -> anyhow::Result<()> {
    let status = run_cmd(program, args)?;
    if !status.success() {
        bail!("`{} {}` exited with {}", program, args.join(" "), status);
    }
    Ok(())
}

/// RA-05: Quote a single argument for a systemd `ExecStart=` line.
///
/// systemd uses C-style quoting: if an argument contains whitespace,
/// quotes, or backslashes it is wrapped in double quotes with internal
/// `"` and `\` escaped.  See `systemd.syntax(7)`.
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
fn systemd_quote(arg: &str) -> String {
    if arg.is_empty() {
        return r#""""#.to_string();
    }
    // If there's nothing that needs escaping we can emit bare.
    let needs_quoting = arg.bytes().any(|b| {
        b == b' '
            || b == b'\t'
            || b == b'"'
            || b == b'\\'
            || b == b'\''
            || b == b'\n'
            || b == b';'
    });
    if !needs_quoting {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 4);
    out.push('"');
    for ch in arg.chars() {
        match ch {
            '"' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

/// RA-05: Escape an argument for a macOS launchd XML `<string>` element.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
fn xml_escape(arg: &str) -> String {
    arg.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// RA-05: Quote a single argument for Windows `sc.exe binPath=`.
///
/// If the argument contains spaces, wrap it in `\"...\"`  (the outer
/// quote is for `sc.exe` parsing; the backslash-quote is for the Windows
/// command line parser).
#[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
fn windows_arg_quote(arg: &str) -> String {
    if arg.is_empty() {
        return r#"\"\""#.to_string();
    }
    if arg.contains(' ') || arg.contains('"') {
        let escaped = arg.replace('"', r#"\""#);
        format!("\\\"{}\\\"", escaped)
    } else {
        arg.to_string()
    }
}

// ── Linux / systemd ────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn install_systemd(bin: &Path, relay_args: &[&str]) -> anyhow::Result<()> {
    use std::{fs, io::Write};

    let bin_str = bin.to_string_lossy();
    let exec_start = if relay_args.is_empty() {
        systemd_quote(&bin_str)
    } else {
        let quoted_args: Vec<String> = relay_args.iter().map(|a| systemd_quote(a)).collect();
        format!("{} {}", systemd_quote(&bin_str), quoted_args.join(" "))
    };

    let unit = format!(
        r#"[Unit]
Description=SCP2P Relay Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exec_start}
Restart=on-failure
RestartSec=5s
Environment=SCP2P_LOG_FORMAT=json

[Install]
WantedBy=multi-user.target
"#
    );

    const UNIT_PATH: &str = "/etc/systemd/system/scp2p-relay.service";

    {
        let mut f = fs::File::create(UNIT_PATH)
            .with_context(|| format!("cannot write {UNIT_PATH} — are you running as root?"))?;
        f.write_all(unit.as_bytes())?;
    }

    println!("Wrote {UNIT_PATH}");
    println!("ExecStart: {exec_start}");

    check_cmd("systemctl", &["daemon-reload"])?;
    println!("systemctl daemon-reload — OK");

    check_cmd("systemctl", &["enable", "--now", "scp2p-relay"])?;
    println!("systemctl enable --now scp2p-relay — OK");

    println!();
    println!("Service is running.  View logs with:");
    println!("  journalctl -u scp2p-relay -f");

    Ok(())
}

// ── macOS / launchd ────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn install_launchd(bin: &Path, relay_args: &[&str]) -> anyhow::Result<()> {
    use std::{fs, io::Write};

    let bin_str = bin.to_string_lossy();

    // Build the <array> of <string> entries for ProgramArguments.
    let mut prog_args = format!("        <string>{}</string>\n", xml_escape(&bin_str));
    for arg in relay_args {
        prog_args.push_str(&format!("        <string>{}</string>\n", xml_escape(arg)));
    }

    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.scp2p.relay</string>
    <key>ProgramArguments</key>
    <array>
{prog_args}    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>EnvironmentVariables</key>
    <dict>
        <key>SCP2P_LOG_FORMAT</key>
        <string>json</string>
    </dict>
    <key>StandardOutPath</key>
    <string>/var/log/scp2p-relay.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/scp2p-relay.log</string>
</dict>
</plist>
"#
    );

    const PLIST_PATH: &str = "/Library/LaunchDaemons/com.scp2p.relay.plist";

    {
        let mut f = std::fs::File::create(PLIST_PATH)
            .with_context(|| format!("cannot write {PLIST_PATH} — are you running as root?"))?;
        f.write_all(plist.as_bytes())?;
    }

    println!("Wrote {PLIST_PATH}");

    // If already loaded, unload first to apply new config.
    let _ = run_cmd("launchctl", &["bootout", "system", PLIST_PATH]);

    check_cmd("launchctl", &["bootstrap", "system", PLIST_PATH])?;
    println!("launchctl bootstrap — OK");

    println!();
    println!("Service is running.  View logs with:");
    println!("  tail -f /var/log/scp2p-relay.log");

    Ok(())
}

// ── Windows / SCM ──────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn install_windows_service(bin: &Path, relay_args: &[&str]) -> anyhow::Result<()> {
    let bin_str = bin.to_string_lossy();

    // Build binPath — quote the exe, append properly escaped args.
    let bin_path = if relay_args.is_empty() {
        format!("\"{}\"", bin_str)
    } else {
        let quoted_args: Vec<String> =
            relay_args.iter().map(|a| windows_arg_quote(a)).collect();
        format!("\"{}\" {}", bin_str, quoted_args.join(" "))
    };

    // Delete old service if present (ignore errors).
    let _ = run_cmd("sc.exe", &["delete", "scp2p-relay"]);

    check_cmd(
        "sc.exe",
        &[
            "create",
            "scp2p-relay",
            "binPath=",
            &bin_path,
            "start=",
            "auto",
            "DisplayName=",
            "SCP2P Relay Node",
        ],
    )?;

    check_cmd(
        "sc.exe",
        &[
            "description",
            "scp2p-relay",
            "SCP2P relay node — bridges peers behind NAT",
        ],
    )?;
    check_cmd("sc.exe", &["start", "scp2p-relay"])?;

    println!("Windows service 'scp2p-relay' installed and started.");
    println!();
    println!("Manage with:");
    println!("  sc.exe stop  scp2p-relay");
    println!("  sc.exe start scp2p-relay");
    println!("  sc.exe delete scp2p-relay");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_quote_bare() {
        assert_eq!(systemd_quote("--bind-tcp=0.0.0.0:7001"), "--bind-tcp=0.0.0.0:7001");
    }

    #[test]
    fn systemd_quote_with_spaces() {
        assert_eq!(systemd_quote("--data-dir=/my path"), r#""--data-dir=/my path""#);
    }

    #[test]
    fn systemd_quote_with_double_quotes() {
        assert_eq!(systemd_quote(r#"say "hello""#), r#""say \"hello\"""#);
    }

    #[test]
    fn systemd_quote_empty() {
        assert_eq!(systemd_quote(""), r#""""#);
    }

    #[test]
    fn xml_escape_special_chars() {
        assert_eq!(xml_escape("a&b<c>d\"e'f"), "a&amp;b&lt;c&gt;d&quot;e&apos;f");
    }

    #[test]
    fn xml_escape_plain() {
        assert_eq!(xml_escape("--bind-tcp=0.0.0.0:7001"), "--bind-tcp=0.0.0.0:7001");
    }

    #[test]
    fn windows_arg_quote_bare() {
        assert_eq!(windows_arg_quote("--bind-tcp=0.0.0.0:7001"), "--bind-tcp=0.0.0.0:7001");
    }

    #[test]
    fn windows_arg_quote_with_spaces() {
        assert_eq!(
            windows_arg_quote("--data-dir=C:\\My Dir"),
            "\\\"--data-dir=C:\\My Dir\\\""
        );
    }

    #[test]
    fn windows_arg_quote_empty() {
        assert_eq!(windows_arg_quote(""), r#"\"\""#);
    }
}