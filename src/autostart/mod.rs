//! "Start with the system" for the daemon, one backend per operating system.
//!
//! * Linux/Android: a FreeDesktop autostart entry, `$XDG_CONFIG_HOME/autostart/vrtfido.desktop`
//! * macOS: a per-user LaunchAgent, `~/Library/LaunchAgents/dev.vrtfido.daemon.plist`
//! * Windows: the `VrtFido` value under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
//!
//! Each backend owns its own format, so only "is it on?" and "turn it on/off" are shared,
//! together with the decision of which command-line arguments survive into the startup
//! command.

use std::path::PathBuf;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;
#[cfg(any(target_os = "linux", target_os = "android"))]
use linux as backend;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as backend;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as backend;

/// Check if autostart is currently enabled for vrtfido.
pub fn is_autostart_enabled() -> bool {
    backend::is_enabled()
}

/// Enable or disable autostart for the current user.
pub fn set_autostart_enabled(enabled: bool) -> std::io::Result<()> {
    backend::set_enabled(enabled)
}

/// The executable to register. Every backend needs an absolute path: the startup entry runs
/// outside a shell, so a bare `vrtfido` would depend on a login `PATH` that may not hold the
/// directory the running binary came from (a `mise` shim, for instance).
pub(crate) fn startup_exe() -> std::io::Result<PathBuf> {
    let current = std::env::current_exe()?;
    Ok(std::fs::canonicalize(&current).unwrap_or(current))
}

/// Quotes one command-line word for the backends that keep the whole command in a single
/// string (`Exec=` line, Run value). The LaunchAgent stores one array element per word and
/// needs no quoting there.
#[cfg(any(target_os = "linux", windows))]
pub(crate) fn quote_arg(arg: &str) -> String {
    if arg.contains(' ') {
        format!("\"{}\"", arg)
    } else {
        arg.to_string()
    }
}

/// Filter command-line arguments to preserve configuration options for autostart,
/// excluding one-off commands like `--quit`, `--export`, `--import`, or `--help`.
pub fn get_retained_startup_args() -> Vec<String> {
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    let mut retained = Vec::new();
    let mut i = 0;

    while i < raw_args.len() {
        let arg = &raw_args[i];

        // Skip transient / one-off commands
        if matches!(
            arg.as_str(),
            "--daemon"
                | "-b"
                | "--quit"
                | "-q"
                | "--stop"
                | "--help"
                | "-h"
                | "--exit-after-import"
                | "clean-logs"
                | "--clean-logs"
                | "--clear-logs"
        ) || arg.starts_with("--clean-logs=")
            || arg.starts_with("--clear-logs=")
        {
            i += 1;
            continue;
        }

        // Skip export / import commands and their file targets
        if matches!(arg.as_str(), "--export" | "--import") {
            i += 1;
            if i < raw_args.len() && !raw_args[i].starts_with('-') {
                i += 1;
            }
            continue;
        }
        if arg.starts_with("--export=") || arg.starts_with("--import=") {
            i += 1;
            continue;
        }

        retained.push(arg.clone());
        i += 1;
    }

    retained
}
