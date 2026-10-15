use super::{quote_arg, startup_exe};
use std::path::{Path, PathBuf};

pub const AUTOSTART_DESKTOP_FILENAME: &str = "vrtfido.desktop";

/// Returns the path to the autostart directory according to XDG specifications:
/// `$XDG_CONFIG_HOME/autostart` or `$HOME/.config/autostart`.
pub fn get_autostart_dir() -> Option<PathBuf> {
    if let Ok(config_home) = std::env::var("XDG_CONFIG_HOME") {
        if !config_home.trim().is_empty() {
            return Some(PathBuf::from(config_home).join("autostart"));
        }
    }

    if let Ok(home) = std::env::var("HOME") {
        if !home.trim().is_empty() {
            return Some(PathBuf::from(home).join(".config").join("autostart"));
        }
    }

    None
}

/// Returns the path to the autostart desktop entry file:
/// e.g. `~/.config/autostart/vrtfido.desktop`
pub fn get_autostart_desktop_path() -> Option<PathBuf> {
    get_autostart_dir().map(|dir| dir.join(AUTOSTART_DESKTOP_FILENAME))
}

/// Check if autostart is currently enabled for vrtfido.
pub(crate) fn is_enabled() -> bool {
    let path = match get_autostart_desktop_path() {
        Some(p) => p,
        None => return false,
    };

    is_desktop_file_enabled(&path)
}

/// Checks whether a given .desktop file exists and has autostart enabled.
pub fn is_desktop_file_enabled(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return false,
    };

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Hidden=") {
            if trimmed
                .split_once('=')
                .map(|(_, v)| v.trim().eq_ignore_ascii_case("true"))
                .unwrap_or(false)
            {
                return false;
            }
        } else if trimmed.starts_with("X-GNOME-Autostart-enabled=") {
            if trimmed
                .split_once('=')
                .map(|(_, v)| v.trim().eq_ignore_ascii_case("false"))
                .unwrap_or(false)
            {
                return false;
            }
        }
    }

    true
}

/// Generate the content of the .desktop autostart entry.
pub fn generate_desktop_entry(exe_path: &Path, extra_args: &[String]) -> String {
    let quoted_exe = quote_arg(&exe_path.display().to_string());
    let args_str: String = extra_args
        .iter()
        .map(|arg| format!(" {}", quote_arg(arg)))
        .collect();

    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Version=1.0\n\
         Name=VrtFido\n\
         GenericName=Virtual FIDO2 / WebAuthn Authenticator\n\
         Comment=Virtual FIDO2 / WebAuthn Authenticator CMS\n\
         Exec={quoted_exe}{args_str} --daemon\n\
         Icon=security-high\n\
         Terminal=false\n\
         Categories=Utility;Security;\n\
         StartupNotify=false\n\
         X-GNOME-Autostart-enabled=true\n"
    )
}

/// Enable or disable autostart by writing or removing the desktop file.
pub(crate) fn set_enabled(enabled: bool) -> std::io::Result<()> {
    set_enabled_with_args(enabled, None)
}

pub(crate) fn set_enabled_with_args(enabled: bool, custom_args: Option<&[String]>) -> std::io::Result<()> {
    let desktop_path = get_autostart_desktop_path().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Could not determine user autostart directory ($HOME or $XDG_CONFIG_HOME is not set)",
        )
    })?;

    let retained_args = match custom_args {
        Some(args) => args.to_vec(),
        None => super::get_retained_startup_args(),
    };
    set_autostart_at_path(&desktop_path, enabled, None, &retained_args)
}

/// Helper to enable/disable autostart at a specific desktop file path.
pub fn set_autostart_at_path(
    desktop_path: &Path,
    enabled: bool,
    custom_exe: Option<&Path>,
    extra_args: &[String],
) -> std::io::Result<()> {
    if enabled {
        if let Some(parent) = desktop_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let exe_path = match custom_exe {
            Some(p) => p.to_path_buf(),
            None => startup_exe()?,
        };

        let content = generate_desktop_entry(&exe_path, extra_args);
        std::fs::write(desktop_path, content)?;
    } else if desktop_path.exists() {
        std::fs::remove_file(desktop_path)?;
    }

    Ok(())
}

/// Rewrite the entry when its `Exec=` names a different executable than the one running now.
/// Nothing to do - and nothing created - when autostart is off or the entry cannot be read.
pub(crate) fn refresh() -> std::io::Result<()> {
    let path = match get_autostart_desktop_path() {
        Some(path) => path,
        None => return Ok(()),
    };
    if !path.exists() {
        return Ok(());
    }
    let retained = super::get_retained_startup_args();
    if !retained.is_empty() {
        return set_enabled(true);
    }
    let content = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(_) => return Ok(()),
    };

    match rewrite_exec(&content, &startup_exe()?) {
        Some(updated) => std::fs::write(&path, updated),
        None => Ok(()),
    }
}

/// Put `exe` at the front of the `Exec=` line, keeping its arguments and every other line byte
/// for byte. `None` when the line already names `exe`, which is the normal case at every start
/// between upgrades.
fn rewrite_exec(content: &str, exe: &Path) -> Option<String> {
    let current = exe.display().to_string();
    let mut lines: Vec<String> = Vec::new();
    let mut rewritten = false;

    for line in content.lines() {
        match line.strip_prefix("Exec=") {
            Some(value) if !rewritten => {
                let (recorded, args) = super::split_exec(value);
                if recorded == current {
                    return None;
                }
                lines.push(format!("Exec={}{}", quote_arg(&current), args));
                rewritten = true;
            }
            _ => lines.push(line.to_string()),
        }
    }

    if !rewritten {
        return None;
    }

    let mut updated = lines.join("\n");
    // `lines()` drops the newline `generate_desktop_entry` ends the file with.
    if content.ends_with('\n') {
        updated.push('\n');
    }
    Some(updated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_desktop_entry() {
        let exe = Path::new("/usr/local/bin/vrtfido");
        let args = vec!["--port".to_string(), "10209".to_string()];
        let entry = generate_desktop_entry(exe, &args);

        assert!(entry.contains("Exec=/usr/local/bin/vrtfido --port 10209 --daemon"));
        assert!(entry.contains("Name=VrtFido"));
        assert!(entry.contains("X-GNOME-Autostart-enabled=true"));
    }

    #[test]
    fn test_generate_desktop_entry_with_spaces() {
        let exe = Path::new("/opt/my tools/vrtfido");
        let args = vec![];
        let entry = generate_desktop_entry(exe, &args);

        assert!(entry.contains("Exec=\"/opt/my tools/vrtfido\" --daemon"));
    }

    #[test]
    fn test_enable_disable_autostart_lifecycle() {
        let temp_dir =
            std::env::temp_dir().join(format!("vrtfido_autostart_test_{}", std::process::id()));
        let desktop_file = temp_dir.join(AUTOSTART_DESKTOP_FILENAME);

        // Ensure clean state
        let _ = std::fs::remove_file(&desktop_file);

        // Initially not enabled
        assert!(!is_desktop_file_enabled(&desktop_file));

        // Enable autostart
        let dummy_exe = Path::new("/usr/bin/vrtfido");
        set_autostart_at_path(&desktop_file, true, Some(dummy_exe), &[]).expect("enable failed");

        assert!(desktop_file.exists());
        assert!(is_desktop_file_enabled(&desktop_file));

        let content = std::fs::read_to_string(&desktop_file).expect("read failed");
        assert!(content.contains("Exec=/usr/bin/vrtfido --daemon"));

        // Disable autostart
        set_autostart_at_path(&desktop_file, false, None, &[]).expect("disable failed");
        assert!(!desktop_file.exists());
        assert!(!is_desktop_file_enabled(&desktop_file));

        // Clean up test dir
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_rewrite_exec_replaces_only_the_executable() {
        let old_exe =
            Path::new("/home/dev/.local/share/mise/installs/github-manhavn-vrtfido/0.3.7/vrtfido");
        let entry = generate_desktop_entry(
            old_exe,
            &["--db-type".to_string(), "mongodb".to_string()],
        );

        let shim = Path::new("/home/dev/.local/share/mise/shims/vrtfido");
        let updated = rewrite_exec(&entry, shim).expect("the entry names the superseded install");

        assert!(updated.contains("Exec=/home/dev/.local/share/mise/shims/vrtfido --db-type mongodb --daemon"));
        assert!(!updated.contains("0.3.7"));
        assert_eq!(updated.matches("Exec=").count(), 1);

        // The arguments and every other line survive the rewrite, byte for byte.
        let unchanged = |content: &str| {
            content
                .lines()
                .filter(|line| !line.starts_with("Exec="))
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert_eq!(unchanged(&updated), unchanged(&entry));

        // A path with spaces keeps the quoting the FreeDesktop spec (and `split_exec`) expects.
        let spaced = rewrite_exec(&entry, Path::new("/opt/my tools/vrtfido")).expect("rewrite");
        assert!(spaced.contains("Exec=\"/opt/my tools/vrtfido\" --db-type mongodb --daemon"));

        // A second pass changes nothing: the entry already names the running binary.
        assert!(rewrite_exec(&updated, shim).is_none());
    }
}
