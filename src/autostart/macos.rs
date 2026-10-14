use std::io;
use std::path::PathBuf;

/// The launchd label: it doubles as the property-list file name and as the identifier the
/// `launchctl` commands use.
const LABEL: &str = "dev.vrtfido.daemon";

/// `~/Library/LaunchAgents/dev.vrtfido.daemon.plist` - per user, so no `sudo` is involved.
fn plist_path() -> io::Result<PathBuf> {
    let home = std::env::var("HOME").map_err(|_| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "Could not determine the user's home directory ($HOME is not set)",
        )
    })?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{LABEL}.plist")))
}

pub(crate) fn is_enabled() -> bool {
    matches!(plist_path(), Ok(path) if path.exists())
}

pub(crate) fn set_enabled(enabled: bool) -> io::Result<()> {
    let path = plist_path()?;

    if enabled {
        let exe = super::startup_exe()?;
        let mut program = vec![exe.display().to_string()];
        program.extend(super::get_retained_startup_args());
        program.push("--daemon".to_string());

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, render_plist(&program))?;

        // Loading it right away is best effort: what matters is that launchd reads the agent
        // at the next login. A GUI session is not always present (ssh, CI), and an agent that
        // is already loaded makes `launchctl load` fail, neither of which is an error here.
        let _ = std::process::Command::new("launchctl")
            .arg("load")
            .arg("-w")
            .arg(&path)
            .status();
    } else if path.exists() {
        let _ = std::process::Command::new("launchctl")
            .arg("unload")
            .arg("-w")
            .arg(&path)
            .status();
        std::fs::remove_file(&path)?;
    }

    Ok(())
}

/// `RunAtLoad` starts the daemon at login; `ProgramArguments` keeps every word separate, so a
/// path with spaces needs no quoting, only XML escaping.
fn render_plist(program: &[String]) -> String {
    let arguments = program
        .iter()
        .map(|argument| format!("    <string>{}</string>", xml_escape(argument)))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \x20 <key>Label</key>\n\
         \x20 <string>{LABEL}</string>\n\
         \x20 <key>ProgramArguments</key>\n\
         \x20 <array>\n\
         {arguments}\n\
         \x20 </array>\n\
         \x20 <key>RunAtLoad</key>\n\
         \x20 <true/>\n\
         </dict>\n\
         </plist>\n"
    )
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
