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
    set_enabled_with_args(enabled, None)
}

pub(crate) fn set_enabled_with_args(enabled: bool, custom_args: Option<&[String]>) -> io::Result<()> {
    let key = run_key(KEY_READ | KEY_WRITE)?;

    if enabled {
        let exe = super::startup_exe()?;
        // The value is one command line, so every word is quoted on its own before it is
        // joined: a path like `C:\Program Files\...` would otherwise split into two arguments.
        let mut command = vec![super::quote_arg(&exe.display().to_string())];
        let retained = match custom_args {
            Some(args) => args.to_vec(),
            None => super::get_retained_startup_args(),
        };
        command.extend(
            retained
                .iter()
                .map(|argument| super::quote_arg(argument)),
        );
        if !command.iter().any(|a| a == "--daemon") {
            command.push("--daemon".to_string());
        }
        key.set_value(VALUE_NAME, &command.join(" "))
    } else {
        match key.delete_value(VALUE_NAME) {
            // Nothing to remove is exactly the state the caller asked for.
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }
}

/// Rewrite the value when its command names a different executable than the one running now.
/// Nothing to do - and nothing created - when autostart is off.
pub(crate) fn refresh() -> io::Result<()> {
    let key = match run_key(KEY_READ | KEY_WRITE) {
        Ok(key) => key,
        Err(_) => return Ok(()),
    };
    let command = match key.get_value::<String, _>(VALUE_NAME) {
        Ok(command) => command,
        Err(_) => return Ok(()),
    };

    let retained = super::get_retained_startup_args();
    if !retained.is_empty() {
        return set_enabled(true);
    }

    let exe = super::startup_exe()?;
    let (recorded, args) = super::split_exec(&command);
    if recorded == exe.display().to_string() {
        return Ok(());
    }

    // Same shape as `set_enabled`: one quoted word per argument, the stored arguments kept as
    // they are.
    key.set_value(
        VALUE_NAME,
        &format!("{}{}", super::quote_arg(&exe.display().to_string()), args),
    )
}
