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

/// The name the desktop entry gives as its icon. A shared theme name such as
/// the previous `security-high` draws a generic shield; naming our own icon
/// makes the menu entry show the same logo as the tray, the dashboard and the
/// extension.
const ICON_NAME: &str = "vrtfido";

/// The sizes written into the user's hicolor theme, the PNGs every other icon
/// consumer already ships. Two entries cover the panels and menu lists that
/// scale between them.
const ICON_FILES: [(u32, &[u8]); 2] = [
    (128, include_bytes!("../../extension/icons/icon-128.png")),
    (192, include_bytes!("../../assets/icon-192.png")),
];

/// `$XDG_DATA_HOME` or `~/.local/share`: the per-user data directory whose
/// `icons/hicolor` tree the desktop reads without any cache refresh.
fn get_data_dir() -> Option<PathBuf> {
    if let Ok(data_home) = std::env::var("XDG_DATA_HOME") {
        if !data_home.trim().is_empty() {
            return Some(PathBuf::from(data_home));
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.trim().is_empty() {
            return Some(PathBuf::from(home).join(".local").join("share"));
        }
    }
    None
}

/// Write the logo into the user's icon theme so `Icon=vrtfido` resolves. An up
/// to date file is left untouched, so calling this on every start costs two
/// reads and no write at all in the steady state.
pub fn install_icon_at(data_dir: &Path) -> std::io::Result<()> {
    for (size, png) in ICON_FILES {
        let dir = data_dir
            .join("icons")
            .join("hicolor")
            .join(format!("{size}x{size}"))
            .join("apps");
        let path = dir.join(format!("{ICON_NAME}.png"));
        if std::fs::read(&path).is_ok_and(|installed| installed == png) {
            continue;
        }
        std::fs::create_dir_all(&dir)?;
        std::fs::write(&path, png)?;
    }
    Ok(())
}

/// `install_icon_at` in the user's own data directory. Called wherever the
/// desktop entry names our icon; the icon stays behind when autostart is
/// switched off, because a menu entry that still resolves beats a broken one
/// and the theme is a shared cache rather than a copy of our state.
pub(crate) fn install_icon() -> std::io::Result<()> {
    let data_dir = get_data_dir().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Could not determine the user data directory ($HOME or $XDG_DATA_HOME is not set)",
        )
    })?;
    install_icon_at(&data_dir)
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
         Icon={ICON_NAME}\n\
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
    // The entry names `Icon=vrtfido`, so the file has to exist for the menu to
    // draw it. A theme that cannot be written must not fail the toggle.
    if enabled {
        if let Err(e) = install_icon() {
            eprintln!("[AUTOSTART] Could not install the menu icon: {e}");
        }
    }
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

/// Bring the entry up to date: `Exec=` must name the executable that is running now, and the
/// icon must be the one this build ships. Nothing to do - and nothing created - when autostart
/// is off or the entry cannot be read.
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

    // The entry names our icon, so the file has to be there. This is also the
    // repair path for an entry that is already up to date but whose icon went
    // missing - a cleaned data directory, a failed earlier write - which the
    // entry rewrite alone would never notice. Best effort either way: the
    // autostart line is what matters, and it is already exactly right.
    if let Err(e) = install_icon() {
        eprintln!("[AUTOSTART] Could not install the menu icon: {e}");
    }

    match refresh_entry(&content, &startup_exe()?) {
        Some(updated) => std::fs::write(&path, updated),
        None => Ok(()),
    }
}

/// Put the current executable at the front of the `Exec=` line and the current icon on the
/// `Icon=` line, keeping every other line byte for byte. `None` when both are already what
/// this build writes, which is the normal case at every start between upgrades.
fn refresh_entry(content: &str, exe: &Path) -> Option<String> {
    let current = exe.display().to_string();
    let mut lines: Vec<String> = Vec::new();
    let mut seen_exec = false;
    let mut seen_icon = false;
    let mut changed = false;

    for line in content.lines() {
        if let Some(value) = line.strip_prefix("Exec=") {
            if !seen_exec {
                seen_exec = true;
                let (recorded, args) = super::split_exec(value);
                if recorded != current {
                    lines.push(format!("Exec={}{}", quote_arg(&current), args));
                    changed = true;
                    continue;
                }
            }
        } else if let Some(value) = line.strip_prefix("Icon=") {
            if !seen_icon {
                seen_icon = true;
                if value != ICON_NAME {
                    lines.push(format!("Icon={ICON_NAME}"));
                    changed = true;
                    continue;
                }
            }
        }
        lines.push(line.to_string());
    }

    if !changed {
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
        // Our own icon name, not a theme icon that would draw a generic shield.
        assert!(entry.contains("Icon=vrtfido"));
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
    fn test_refresh_entry_replaces_only_what_the_build_owns() {
        let old_exe =
            Path::new("/home/dev/.local/share/mise/installs/github-manhavn-vrtfido/0.3.7/vrtfido");
        let entry = generate_desktop_entry(
            old_exe,
            &["--db-type".to_string(), "mongodb".to_string()],
        );

        let shim = Path::new("/home/dev/.local/share/mise/shims/vrtfido");
        let updated = refresh_entry(&entry, shim).expect("the entry names the superseded install");

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
        let spaced = refresh_entry(&entry, Path::new("/opt/my tools/vrtfido")).expect("rewrite");
        assert!(spaced.contains("Exec=\"/opt/my tools/vrtfido\" --db-type mongodb --daemon"));

        // A second pass changes nothing: the entry already names the running binary.
        assert!(refresh_entry(&updated, shim).is_none());

        // An entry written by an older build still points at the theme's shield icon, which
        // would leave the menu entry looking like something else.
        let legacy = entry.replace("Icon=vrtfido", "Icon=security-high");
        let migrated = refresh_entry(&legacy, old_exe).expect("the entry names the old icon");
        assert!(migrated.contains("Icon=vrtfido"));
        assert!(!migrated.contains("security-high"));
        assert_eq!(migrated.matches("Icon=").count(), 1);
        assert_eq!(migrated.matches("Exec=").count(), 1);
        assert!(refresh_entry(&migrated, old_exe).is_none());
    }

    #[test]
    fn test_install_icon_writes_the_sizes_the_theme_looks_for() {
        let base = std::env::temp_dir().join(format!("vrtfido_icon_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);

        install_icon_at(&base).expect("icon install failed");

        for (size, png) in ICON_FILES {
            let path = base
                .join("icons/hicolor")
                .join(format!("{size}x{size}/apps/vrtfido.png"));
            let written = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            assert_eq!(written, png);
        }

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn test_install_icon_repairs_a_stale_file_without_touching_a_current_one() {
        let base = std::env::temp_dir().join(format!("vrtfido_icon_repair_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let installed = base.join("icons/hicolor/128x128/apps/vrtfido.png");

        // An icon left behind by another build, or a half-written one, is replaced.
        std::fs::create_dir_all(installed.parent().unwrap()).unwrap();
        std::fs::write(&installed, b"stale").unwrap();
        install_icon_at(&base).expect("icon install failed");
        assert_eq!(std::fs::read(&installed).unwrap(), ICON_FILES[0].1);

        // And a file that is already current is left alone, so the daemon's
        // start-up refresh costs the theme directory no write at all.
        let epoch = std::time::SystemTime::UNIX_EPOCH;
        std::fs::File::options()
            .write(true)
            .open(&installed)
            .unwrap()
            .set_modified(epoch)
            .unwrap();
        install_icon_at(&base).expect("icon install failed");
        assert_eq!(std::fs::metadata(&installed).unwrap().modified().unwrap(), epoch);

        let _ = std::fs::remove_dir_all(&base);
    }
}
