//! "Start with the system" for the daemon, one backend per operating system.
//!
//! * Linux/Android: a FreeDesktop autostart entry, `$XDG_CONFIG_HOME/autostart/vrtfido.desktop`
//! * macOS: a per-user LaunchAgent, `~/Library/LaunchAgents/dev.vrtfido.daemon.plist`
//! * Windows: the `VrtFido` value under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
//!
//! Each backend owns its own format, so only "is it on?" and "turn it on/off" are shared,
//! together with the decision of which command-line arguments survive into the startup
//! command.

use std::path::{Path, PathBuf};

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
    set_autostart_enabled_with_args(enabled, None)
}

/// Enable or disable autostart for the current user with optional custom retained arguments.
pub fn set_autostart_enabled_with_args(enabled: bool, custom_args: Option<&[String]>) -> std::io::Result<()> {
    backend::set_enabled_with_args(enabled, custom_args)
}

/// The executable to register. Every backend needs an absolute path: the startup entry runs
/// outside a shell, so a bare `vrtfido` would depend on a login `PATH` that may not hold the
/// directory the running binary came from (a `mise` shim, for instance).
///
/// A `mise` install is the one case that needs more than the running binary's own path: mise
/// keeps the version in that path, so recording it would pin the entry to the release that was
/// current when the toggle was flipped. The shim is recorded instead.
///
/// The prompt window is mapped to the daemon it belongs to first: on macOS and Windows the tray
/// menu that flips the toggle runs in that client, not in the daemon.
pub(crate) fn startup_exe() -> std::io::Result<PathBuf> {
    let current = daemon_binary(std::env::current_exe()?);
    if let Some(data_dir) = mise_data_dir() {
        // Both sides resolved: `$HOME` is itself a symlink on some setups, and the running
        // binary's path comes from `/proc/self/exe`, which is already canonical.
        let data_dir = std::fs::canonicalize(&data_dir).unwrap_or(data_dir);
        if let Some(shim) = mise_shim(&current, &data_dir) {
            return Ok(shim);
        }
    }
    Ok(std::fs::canonicalize(&current).unwrap_or(current))
}

/// The binary a startup entry has to launch, given the one that is running.
///
/// `vrtfido-gui` is a client of the daemon - it talks to it over the local API and gives up when
/// no daemon answers, never starting one itself. On macOS and Windows the tray icon that owns
/// the toggle lives in that process, so without this mapping the entry would name the prompt
/// window, and the login that ran it would start nothing. The reverse of the sibling lookup
/// `spawn_gui_client` does in the daemon.
fn daemon_binary(exe: PathBuf) -> PathBuf {
    let Some(stem) = exe.file_stem().and_then(|stem| stem.to_str()) else {
        return exe;
    };
    let Some(daemon_stem) = stem.strip_suffix("-gui") else {
        return exe;
    };

    // Keep the extension: `vrtfido-gui.exe` and `vrtfido.exe` are the two names on Windows.
    let mut name = daemon_stem.to_string();
    if let Some(extension) = exe.extension().and_then(|extension| extension.to_str()) {
        name.push('.');
        name.push_str(extension);
    }

    let daemon = exe.with_file_name(name);
    // A client shipped on its own keeps its own path rather than gaining one that is not there.
    if daemon.is_file() {
        daemon
    } else {
        exe
    }
}

/// The `mise` shim that would launch this executable again, when it came out of a mise install.
///
/// mise stores a tool under `installs/<tool>/<version>/<binary>` and puts a symlink to the mise
/// binary itself at `shims/<binary>`. That shim - unlike the version directory - names the same
/// file across upgrades: it resolves the configured version again on every launch, so a new
/// release is picked up without touching the entry, and `mise prune` cannot leave it dangling.
/// `None` for anything that is not an installed copy of the tool.
fn mise_shim(exe: &Path, data_dir: &Path) -> Option<PathBuf> {
    let canon_exe = std::fs::canonicalize(exe).unwrap_or_else(|_| exe.to_path_buf());
    let canon_data_dir = std::fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf());
    let relative = canon_exe.strip_prefix(canon_data_dir.join("installs")).ok()?;
    // `installs/<tool>/<version>/<binary>`: one level less and this is not an install path, so a
    // shim of that name would be a guess rather than the shim that launched this binary.
    if relative.components().count() < 3 {
        return None;
    }
    let shim = data_dir.join("shims").join(exe.file_name()?);
    shim.is_file().then_some(shim)
}

/// Where mise keeps its data, following the order mise itself uses: the environment override,
/// then the platform data directory. A wrong guess is harmless - the install path it is compared
/// against simply does not match, and the running binary's own path is recorded as before.
fn mise_data_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("MISE_DATA_DIR").filter(|dir| !dir.is_empty()) {
        return Some(PathBuf::from(dir));
    }

    #[cfg(target_os = "macos")]
    let fallback = std::env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("mise")
    });

    // Windows has neither `HOME` nor `XDG_DATA_HOME` pointing where mise keeps its data.
    #[cfg(windows)]
    let fallback = std::env::var_os("LOCALAPPDATA").map(|dir| PathBuf::from(dir).join("mise"));

    #[cfg(not(any(target_os = "macos", windows)))]
    let fallback = std::env::var_os("XDG_DATA_HOME")
        .filter(|dir| !dir.is_empty())
        .map(|dir| PathBuf::from(dir).join("mise"))
        .or_else(|| {
            std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share/mise"))
        });

    fallback
}

/// Rewrite an enabled startup entry that names a different executable than the one running now.
///
/// Every backend records the absolute path of the binary at the moment the toggle is flipped, and
/// an upgrade can move that binary - a mise version directory, a Homebrew Cellar, an install into
/// a new prefix. The entry would then start the superseded copy, or nothing at all once the old
/// path is pruned. Running this at daemon start keeps the entry in step, and only the executable
/// is replaced: the arguments the entry carries are the ones the user configured, never the ones
/// this process happened to be started with.
pub fn refresh_entry_path() -> std::io::Result<()> {
    backend::refresh()
}

/// Quotes one command-line word for the backends that keep their whole command in a single
/// string: the FreeDesktop `Exec=` line and the Windows `Run` value. The LaunchAgent stores one
/// array element per word and needs no quoting.
#[allow(dead_code)]
pub(crate) fn quote_arg(arg: &str) -> String {
    if arg.contains(' ') {
        format!("\"{}\"", arg)
    } else {
        arg.to_string()
    }
}

/// The inverse of `quote_arg` for the first word of a command: the executable and everything
/// after it, which is the part a rewrite has to leave alone. Used by the two backends that keep
/// their command in one string.
#[allow(dead_code)]
pub(crate) fn split_exec(command: &str) -> (String, String) {
    if let Some(rest) = command.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            return (rest[..end].to_string(), rest[end + 1..].to_string());
        }
    }

    match command.find(' ') {
        Some(space) => (command[..space].to_string(), command[space..].to_string()),
        None => (command.to_string(), String::new()),
    }
}

/// Filter command-line arguments to preserve configuration options for autostart,
/// excluding one-off commands like `--quit`, `--export`, `--import`, or `--help`.
pub fn get_retained_startup_args() -> Vec<String> {
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    filter_retained_args(&raw_args)
}

/// Filter command-line arguments to preserve configuration options for autostart,
/// excluding one-off commands like `--quit`, `--export`, `--import`, `--help`, or `--autostart`.
pub fn filter_retained_args(raw_args: &[String]) -> Vec<String> {
    let mut retained = Vec::new();
    let mut i = 0;

    while i < raw_args.len() {
        let arg = &raw_args[i];

        // Skip transient / one-off commands and autostart toggle flags
        if matches!(
            arg.as_str(),
            "--daemon"
                | "-b"
                | "--quit"
                | "-q"
                | "--stop"
                | "--help"
                | "-h"
                | "--autostart"
                | "--enable-autostart"
                | "--no-autostart"
                | "--disable-autostart"
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A `mise` data directory shaped like the real one: an installed copy of the binary and the
    /// shim that `mise use`/`mise install` leaves next to it.
    fn mise_tree(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("vrtfido_mise_{}_{}", std::process::id(), name));
        let install = root.join("installs").join("github-manhavn-vrtfido").join("0.3.7");
        std::fs::create_dir_all(&install).expect("create install dir");
        std::fs::write(install.join("vrtfido"), b"").expect("write install");
        let shims = root.join("shims");
        std::fs::create_dir_all(&shims).expect("create shim dir");
        std::fs::write(shims.join("vrtfido"), b"").expect("write shim");
        root
    }

    #[test]
    fn test_mise_shim_is_used_for_an_installed_copy() {
        let root = mise_tree("installed");
        let exe = root
            .join("installs/github-manhavn-vrtfido/0.3.7/vrtfido");

        assert_eq!(mise_shim(&exe, &root), Some(root.join("shims/vrtfido")));

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_mise_shim_ignores_foreign_paths_and_missing_shims() {
        let root = mise_tree("foreign");

        // A binary somewhere else is left exactly as it is: only an install path can be mapped to
        // a shim.
        assert_eq!(mise_shim(Path::new("/usr/local/bin/vrtfido"), &root), None);

        // A version directory with no shim next to it keeps its own path rather than gaining one
        // that cannot launch anything.
        std::fs::remove_file(root.join("shims/vrtfido")).expect("remove shim");
        let exe = root.join("installs/github-manhavn-vrtfido/0.3.7/vrtfido");
        assert_eq!(mise_shim(&exe, &root), None);

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_daemon_binary_maps_the_prompt_window_to_the_daemon() {
        let root = std::env::temp_dir().join(format!("vrtfido_bin_pair_{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("create dir");
        std::fs::write(root.join("vrtfido"), b"").expect("write daemon");
        std::fs::write(root.join("vrtfido-gui"), b"").expect("write client");

        assert_eq!(daemon_binary(root.join("vrtfido-gui")), root.join("vrtfido"));
        // The daemon's own path is not rewritten, and neither is a name that only looks similar.
        assert_eq!(daemon_binary(root.join("vrtfido")), root.join("vrtfido"));
        assert_eq!(
            daemon_binary(root.join("vrtfido-gui-helper")),
            root.join("vrtfido-gui-helper")
        );

        // A client shipped without its daemon keeps its own path instead of guessing one.
        std::fs::remove_file(root.join("vrtfido")).expect("remove daemon");
        assert_eq!(
            daemon_binary(root.join("vrtfido-gui")),
            root.join("vrtfido-gui")
        );

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn test_split_exec_separates_the_executable_from_its_arguments() {
        assert_eq!(
            split_exec("/usr/bin/vrtfido --port 10209 --daemon"),
            (
                "/usr/bin/vrtfido".to_string(),
                " --port 10209 --daemon".to_string()
            )
        );
        assert_eq!(
            split_exec("\"/opt/my tools/vrtfido\" --uhid"),
            ("/opt/my tools/vrtfido".to_string(), " --uhid".to_string())
        );
        assert_eq!(
            split_exec("/usr/bin/vrtfido"),
            ("/usr/bin/vrtfido".to_string(), String::new())
        );
    }

    #[test]
    fn test_filter_retained_args_preserves_db_and_feature_flags() {
        let args = vec![
            "--db-type".to_string(),
            "mongodb".to_string(),
            "--database".to_string(),
            "mongodb://localhost:27017/test".to_string(),
            "--daemon".to_string(),
            "--unlimited-fps".to_string(),
            "--google-aaguid".to_string(),
            "--autostart".to_string(),
            "--quit".to_string(),
        ];
        let retained = filter_retained_args(&args);
        assert_eq!(
            retained,
            vec![
                "--db-type".to_string(),
                "mongodb".to_string(),
                "--database".to_string(),
                "mongodb://localhost:27017/test".to_string(),
                "--unlimited-fps".to_string(),
                "--google-aaguid".to_string(),
            ]
        );
    }
}
