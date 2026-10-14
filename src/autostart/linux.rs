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
    let desktop_path = get_autostart_desktop_path().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Could not determine user autostart directory ($HOME or $XDG_CONFIG_HOME is not set)",
        )
    })?;

    let retained_args = super::get_retained_startup_args();
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
}
