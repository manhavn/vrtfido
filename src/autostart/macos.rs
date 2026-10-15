use std::io;
use std::path::{Path, PathBuf};

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

/// Rewrite the agent so it launches the daemon that is running now, keeping the arguments the
/// property list already carries. Everything is rebuilt from those arguments, which is also what
/// repairs an agent written before the executable was resolved correctly (it named
/// `vrtfido-gui`) and one without `AbandonProcessGroup`. Nothing to do - and nothing created -
/// when autostart is off or the plist cannot be read.
pub(crate) fn refresh() -> io::Result<()> {
    let path = plist_path()?;
    let content = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(_) => return Ok(()),
    };

    match rewrite_plist(&content, &super::startup_exe()?) {
        Some(updated) => std::fs::write(&path, updated),
        None => Ok(()),
    }
}

/// The property list this backend renders for `exe`, given the one on disk. `None` when the file
/// already is what a toggle would write.
fn rewrite_plist(content: &str, exe: &Path) -> Option<String> {
    let arguments = program_arguments(content)?;
    let program = std::iter::once(exe.display().to_string())
        .chain(arguments.into_iter().skip(1))
        .collect::<Vec<_>>();

    let updated = render_plist(&program);
    (updated != content).then_some(updated)
}

/// The words of `ProgramArguments`, in order.
fn program_arguments(content: &str) -> Option<Vec<String>> {
    let key = content.find("<key>ProgramArguments</key>")?;
    let array = &content[key..];
    let mut rest = &array[..array.find("</array>")?];

    let mut arguments = Vec::new();
    while let Some(start) = rest.find("<string>") {
        let after = &rest[start + "<string>".len()..];
        let end = after.find("</string>")?;
        arguments.push(xml_unescape(&after[..end]));
        rest = &after[end + "</string>".len()..];
    }

    (!arguments.is_empty()).then_some(arguments)
}

/// `RunAtLoad` starts the daemon at login; `ProgramArguments` keeps every word separate, so a
/// path with spaces needs no quoting, only XML escaping.
///
/// `AbandonProcessGroup` is what makes the entry work at all: the daemon is asked for `--daemon`,
/// so the process launchd starts forks the real one and exits at once, and launchd kills every
/// remaining process in a job's process group when that job dies - the fork included.
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
         \x20 <key>AbandonProcessGroup</key>\n\
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

fn xml_unescape(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        // Last, so an escaped ampersand cannot turn into the start of another entity.
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The agent as the toggle writes it: the prompt window's own path, which is what macOS did
    /// before the executable was resolved to the daemon.
    fn agent_written_by_the_client() -> (String, String) {
        let client = "/Users/dev/.local/share/mise/installs/github-manhavn-vrtfido/0.3.7/vrtfido-gui";
        let program = [
            client.to_string(),
            "--host".to_string(),
            "127.0.0.1".to_string(),
            "--port".to_string(),
            "10209".to_string(),
            "--daemon".to_string(),
        ];
        (render_plist(&program), client.to_string())
    }

    #[test]
    fn test_refresh_replaces_the_prompt_window_with_the_daemon() {
        let (content, client) = agent_written_by_the_client();
        let daemon = Path::new("/Applications/VrtFido.app/Contents/MacOS/vrtfido");

        let updated = rewrite_plist(&content, daemon).expect("the agent names the client");

        assert!(!updated.contains(client.as_str()));
        assert_eq!(
            program_arguments(&updated),
            Some(vec![
                daemon.display().to_string(),
                "--host".to_string(),
                "127.0.0.1".to_string(),
                "--port".to_string(),
                "10209".to_string(),
                "--daemon".to_string(),
            ])
        );

        // A second pass changes nothing: the agent already names the running daemon.
        assert!(rewrite_plist(&updated, daemon).is_none());
    }

    #[test]
    fn test_refresh_adds_the_process_group_key_to_an_older_agent() {
        let daemon = "/usr/local/bin/vrtfido";
        let older = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                     <plist version=\"1.0\">\n\
                     <dict>\n\
                     \x20 <key>Label</key>\n\
                     \x20 <string>dev.vrtfido.daemon</string>\n\
                     \x20 <key>ProgramArguments</key>\n\
                     \x20 <array>\n\
                     \x20   <string>/usr/local/bin/vrtfido</string>\n\
                     \x20   <string>--daemon</string>\n\
                     \x20 </array>\n\
                     \x20 <key>RunAtLoad</key>\n\
                     \x20 <true/>\n\
                     </dict>\n\
                     </plist>\n";

        let updated = rewrite_plist(older, Path::new(daemon)).expect("the key is missing");

        assert!(updated.contains("  <key>AbandonProcessGroup</key>"));
        assert_eq!(
            program_arguments(&updated),
            Some(vec![daemon.to_string(), "--daemon".to_string()])
        );
    }

    #[test]
    fn test_program_arguments_round_trip_escaped_words() {
        let program = vec![
            "/opt/A&B <tools>/vrtfido".to_string(),
            "--pin".to_string(),
            "<42>".to_string(),
        ];

        let parsed = program_arguments(&render_plist(&program)).expect("the array is there");

        assert_eq!(parsed, program);
    }
}
