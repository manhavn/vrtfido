use std::io;
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
use winreg::RegKey;

/// Per-user startup lives in the registry: the `Run` key is read at every logon and needs no
/// administrator rights, unlike a Task Scheduler entry or a service.
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const VALUE_NAME: &str = "VrtFido";

fn run_key(access: u32) -> io::Result<RegKey> {
    RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(RUN_KEY, access)
}

pub(crate) fn is_enabled() -> bool {
    run_key(KEY_READ)
        .and_then(|key| key.get_value::<String, _>(VALUE_NAME))
        .is_ok()
}

pub(crate) fn set_enabled(enabled: bool) -> io::Result<()> {
    let key = run_key(KEY_READ | KEY_WRITE)?;

    if enabled {
        let exe = super::startup_exe()?;
        // The value is one command line, so every word is quoted on its own before it is
        // joined: a path like `C:\Program Files\...` would otherwise split into two arguments.
        let mut command = vec![super::quote_arg(&exe.display().to_string())];
        command.extend(
            super::get_retained_startup_args()
                .iter()
                .map(|argument| super::quote_arg(argument)),
        );
        command.push("--daemon".to_string());
        key.set_value(VALUE_NAME, &command.join(" "))
    } else {
        match key.delete_value(VALUE_NAME) {
            // Nothing to remove is exactly the state the caller asked for.
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }
}
