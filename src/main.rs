mod db;
mod platform;
mod retention;
mod security;
mod sensor;
mod autostart;
// The kernel virtual device and its StatusNotifier tray item are Linux/Android features: a
// desktop tray on macOS and Windows belongs to the prompt window, which owns the menu-bar /
// notification-area APIs together with its event loop (see `src/gui.rs`).
#[cfg(any(target_os = "linux", target_os = "android"))]
mod tray;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod uhid;
mod web;
mod passkey;
use db::Db;
use security::SecurityEngine;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use web::AppState;

// `tray.rs` is compiled into both this binary and the library (`vrtfido_core::tray`) and reaches the
// udev helpers through the crate root, so the root has to offer the same two names here.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use uhid::{ensure_permanent_uhid_permission, has_permanent_uhid_rule};

/// `true` on the hosts that can carry a kernel virtual-HID device. Windows and macOS have no
/// user-space equivalent of `/dev/uhid`, so `--uhid` is refused there instead of silently
/// starting a daemon that pretends to be a security key.
const UHID_SUPPORTED: bool = cfg!(any(target_os = "linux", target_os = "android"));

/// Default offline files share a private per-user runtime directory, but not a queue:
/// different primary databases get different filenames.
fn default_resilient_paths(spec: &str, db_type: Option<&str>) -> (String, String) {
    let spec = spec.trim();
    let local = match db_type.map(|kind| kind.to_ascii_lowercase()) {
        Some(kind) if kind == "sqlite" => true,
        Some(kind) if kind == "libsql" || kind == "turso" => {
            !spec.starts_with("libsql://")
                && !spec.starts_with("http://")
                && !spec.starts_with("https://")
        }
        Some(_) => false,
        None => !spec.contains("://") && !spec.starts_with("file:"),
    };
    let identity_spec = if local {
        let path = spec.strip_prefix("sqlite:")
            .or_else(|| spec.strip_prefix("libsql:"))
            .unwrap_or(spec);
        let path = if path.is_empty() { "authenticator.db" } else { path };
        if Path::new(path).is_absolute() {
            path.to_string()
        } else {
            std::env::current_dir().unwrap_or_default().join(path).to_string_lossy().into_owned()
        }
    } else {
        spec.to_string()
    };
    let hash = hex::encode(Sha256::digest(format!("{}\n{}", db_type.unwrap_or("").to_ascii_lowercase(), identity_spec).as_bytes()));
    let dir = platform::runtime_dir();
    let dir = dir.display();
    (
        format!("{dir}/{}.shadow.db", &hash[..24]),
        format!("{dir}/{}.queue.db", &hash[..24]),
    )
}

/// IPv6 literals need brackets before a port can be appended (`[::]:10209`).
fn bind_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{}]", host)
    } else {
        host.to_string()
    }
}

/// Host to print in the dashboard URLs: a wildcard bind is opened as `localhost`, while a
/// concrete configured address is worth showing exactly as it was set.
fn display_host(host: &str) -> &str {
    match host {
        "0.0.0.0" | "::" | "[::]" | "*" => "localhost",
        other => other,
    }
}

/// Host the GUI client connects to. It runs on the same machine, so a wildcard bind is
/// reached over the loopback interface rather than at the wildcard address itself.
fn gui_client_host(host: &str) -> &str {
    match host {
        "0.0.0.0" | "*" => "127.0.0.1",
        "::" | "[::]" => "::1",
        other => other,
    }
}

/// Starts the prompt window from the sibling `vrtfido-gui` binary.
///
/// The window is a separate process so the daemon links no windowing stack: a host without a
/// display or OpenGL driver cannot run the client, which is what lets one package serve both a
/// desktop and a headless server. `tray` travels to the client because on macOS and Windows the
/// tray icon lives in that process - it owns the menu-bar / notification-area APIs together with
/// the event loop they need. Returns the running child, `None` when it cannot run.
fn spawn_gui_client(host: &str, port: u16, tray: bool) -> Option<std::process::Child> {
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(configured) = std::env::var("VRTFIDO_GUI_BIN") {
        candidates.push(std::path::PathBuf::from(configured));
    }
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|parent| parent.to_path_buf()))
    {
        candidates.push(dir.join("vrtfido-gui"));
    }
    // Last resort: whatever the package manager put on PATH.
    candidates.push(std::path::PathBuf::from("vrtfido-gui"));

    for candidate in candidates {
        let mut command = Command::new(&candidate);
        command
            .arg("--host")
            .arg(host)
            .arg("--port")
            .arg(port.to_string());
        if !tray {
            command.arg("--no-tray");
        }
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    eprintln!("[GUI] Could not start {}: {}", candidate.display(), e);
                }
                continue;
            }
        };

        // A client that finds no display (or no usable OpenGL surface) exits immediately: report
        // that once instead of holding a dead handle for the rest of the run.
        std::thread::sleep(std::time::Duration::from_millis(500));
        match child.try_wait() {
            Ok(Some(status)) => {
                println!(
                    "[GUI] Prompt window unavailable ({} exited with {}); continuing headless.",
                    candidate.display(),
                    status
                );
                println!(
                    "[GUI] The window needs a display, a GL driver and libxkbcommon (libxkbcommon-x11 on X11); the daemon and the Web CMS on port {} keep working without it.",
                    port
                );
                return None;
            }
            _ => {
                println!("[GUI] Native GUI prompt window started (pid {}).", child.id());
                return Some(child);
            }
        }
    }

    println!("[GUI] vrtfido-gui not found; continuing headless.");
    None
}

/// Bring an enabled startup entry in step with the binary that is running now.
///
/// An upgrade can move that binary - a mise version directory, a Homebrew Cellar, a reinstall into
/// another prefix - and the entry would otherwise start the release the user has already replaced,
/// or nothing at all once the old path is pruned. Only the executable is replaced: the arguments
/// the entry carries are the ones the user configured, never the ones this process was started
/// with.
///
/// The daemon links its own copy of the module on Linux, where `tray.rs` and `uhid.rs` reach it
/// through the crate root, and the library's copy elsewhere, where the prompt window's tray menu
/// already links it.
fn refresh_autostart_entry() {
    if let Err(e) = autostart::refresh_entry_path() {
        eprintln!("[AUTOSTART] Could not bring the startup entry up to date: {}", e);
    }
}

/// Asks the prompt window to quit, then reaps it. A window that ignores the stop signal is killed
/// after a short grace period: shutting the daemon down must never hang on an optional UI.
fn stop_gui_client(child: &mut std::process::Child) {
    platform::terminate(child.id());
    for _ in 0..30 {
        match child.try_wait() {
            Ok(Some(status)) => {
                println!("[GUI] Prompt window exited ({})", status);
                return;
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(100)),
            Err(e) => {
                eprintln!("[GUI] Could not check the prompt window: {}", e);
                return;
            }
        }
    }
    println!("[GUI] Prompt window ignored the stop signal; terminating it.");
    let _ = child.kill();
    let _ = child.wait();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Parse CLI arguments & environment variables
    let args: Vec<String> = std::env::args().collect();
    let show_help = args.iter().any(|a| a == "--help" || a == "-h");
    let check_quit = args.iter().any(|a| a == "--quit" || a == "-q" || a == "--stop");
    let check_daemon = args.iter().any(|a| a == "--daemon" || a == "-b");
    let debug_mode = args.iter().any(|a| a == "--debug" || a == "-d");
    let unlimited_fps = args.iter().any(|a| a == "--unlimited-fps" || a == "--unlimited-fingerprints" || a == "-u");
    let google_aaguid = args.iter().any(|a| a == "--google-aaguid");
    let uhid_enabled = args.iter().any(|a| a == "--uhid");
    let exit_after_import = args.iter().any(|a| a == "--exit-after-import");
    let no_tray = args.iter().any(|a| a == "--no-tray");
    let enable_autostart = args.iter().any(|a| a == "--autostart" || a == "--enable-autostart");
    let disable_autostart = args.iter().any(|a| a == "--no-autostart" || a == "--disable-autostart");
    // The identity is process-wide and a credential records it at creation time, so fix it before
    // anything can serve a WebAuthn request - including the daemon child, which inherits the flags.
    passkey::set_google_aaguid(google_aaguid);
    let check_clean_logs: Option<String> = {
        let mut target = None;
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            if a == "--clean-logs" || a == "clean-logs" || a == "--clear-logs" || a == "clear-logs" {
                let next_val = args.get(i + 1).and_then(|s| {
                    if s.starts_with('-') {
                        None
                    } else {
                        Some(s.clone())
                    }
                });
                target = Some(next_val.unwrap_or_else(|| "all".to_string()));
                break;
            } else if a.starts_with("--clean-logs=") || a.starts_with("--clear-logs=") {
                let val = a.split_once('=').map(|(_, v)| v.to_string()).unwrap_or_default();
                target = Some(if val.is_empty() { "all".to_string() } else { val });
                break;
            }
            i += 1;
        }
        target
    };
    let pid_file = std::env::temp_dir().join("vrtfido.pid");

    // /dev/uhid is a Linux kernel interface: Windows and macOS have no user-space API that
    // could publish a virtual USB HID authenticator, so the flag is refused up front rather
    // than starting a daemon that advertises a security key no browser would ever see.
    if uhid_enabled && !UHID_SUPPORTED {
        eprintln!("[UHID] [!] --uhid is not available on {}.", std::env::consts::OS);
        eprintln!("[UHID]     The virtual FIDO2 device is built on /dev/uhid, which exists in the Linux");
        eprintln!("[UHID]     kernel only; publishing a virtual USB HID authenticator elsewhere needs a");
        eprintln!("[UHID]     signed kernel driver and is not part of this build.");
        eprintln!("[UHID]     Everything else works without the flag: run 'vrtfido --daemon' and manage");
        eprintln!("[UHID]     passkeys from the Web CMS on http://localhost:10209 or the browser extension.");
        std::process::exit(1);
    }

    // Handle --quit: Stop running vrtfido process
    if check_quit {
        let running_pid: Option<u32> = if pid_file.exists() {
            std::fs::read_to_string(&pid_file)
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok())
                .filter(|&pid| platform::process_alive(pid))
        } else {
            None
        };

        let target_pid = running_pid.or_else(|| platform::find_process_by_name("vrtfido"));

        if let Some(pid) = target_pid {
            println!("[DAEMON] Sending stop signal to VrtFido process (PID: {})...", pid);
            platform::terminate(pid);

            let mut stopped = false;
            for _ in 0..50 {
                std::thread::sleep(std::time::Duration::from_millis(100));
                if !platform::process_alive(pid) {
                    stopped = true;
                    break;
                }
            }

            if !stopped {
                println!("[DAEMON] Process not responding, forcing stop...");
                platform::hard_terminate(pid);
                std::thread::sleep(std::time::Duration::from_millis(200));
            }

            let _ = std::fs::remove_file(&pid_file);
            println!("[DAEMON] [+] Stopped VrtFido process (PID: {}) successfully.", pid);
            return Ok(());
        } else {
            let _ = std::fs::remove_file(&pid_file);
            println!("[DAEMON] [-] No running VrtFido process found.");
            return Ok(());
        }
    }

    // Handle --daemon: Run in background
    if check_daemon {
        if let Ok(content) = std::fs::read_to_string(&pid_file) {
            if let Ok(existing_pid) = content.trim().parse::<u32>() {
                if platform::process_alive(existing_pid) {
                    eprintln!("[DAEMON] [!] VrtFido is already running with PID: {}. Use 'vrtfido --quit' to stop first.", existing_pid);
                    std::process::exit(1);
                }
            }
        }

        let child_args: Vec<String> = args
            .iter()
            .skip(1)
            .filter(|a| *a != "--daemon" && *a != "-b")
            .cloned()
            .collect();
        if uhid_enabled {
            println!("[UHID] Checking /dev/uhid access permission...");
            #[cfg(any(target_os = "linux", target_os = "android"))]
            uhid::ensure_uhid_permission();
        } else {
            println!("[UHID] Virtual FIDO2 device disabled: pass --uhid to create it on /dev/uhid.");
        }

        let current_exe = std::env::current_exe()?;
        let log_file_path = std::env::temp_dir().join("vrtfido.log");
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file_path)?;

        let err_file = log_file.try_clone()?;

        let mut command = std::process::Command::new(current_exe);
        command
            .args(&child_args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::from(log_file))
            .stderr(std::process::Stdio::from(err_file));
        // Windows: a child that keeps the parent's console is torn down with it, so closing the
        // terminal would stop the daemon. `DETACHED_PROCESS` gives it no console at all (the
        // output already goes to the log file) and `CREATE_NEW_PROCESS_GROUP` keeps Ctrl+C in the
        // shell from reaching it. `--quit` still stops it through `TerminateProcess`.
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const DETACHED_PROCESS: u32 = 0x0000_0008;
            const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
            command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
        }
        let child = command.spawn()?;

        let child_pid = child.id();
        let _ = std::fs::write(&pid_file, child_pid.to_string());

        std::thread::sleep(std::time::Duration::from_millis(300));
        if !platform::process_alive(child_pid) {
            let _ = std::fs::remove_file(&pid_file);
            eprintln!("[DAEMON] [!] Background daemon failed to start. Check log file at: {}", log_file_path.display());
            std::process::exit(1);
        }

        println!("============================================================");
        println!("             VrtFido - Virtual FIDO2 / WebAuthn CMS         ");
        println!("============================================================");
        println!("[DAEMON] [+] Started VrtFido daemon successfully!");
        println!("[DAEMON]     - Process (PID): {}", child_pid);
        println!("[DAEMON]     - Log file: {}", log_file_path.display());
        println!("[DAEMON]     - Web CMS: http://localhost:10209");
        println!("[DAEMON] Use 'vrtfido --quit' to stop the process.\n");
        return Ok(());
    }

    if show_help {
        println!("============================================================");
        println!("             VrtFido - Virtual FIDO2 / WebAuthn CMS         ");
        println!("============================================================");
        println!("Usage: vrtfido [OPTIONS]\n");
        println!("Options:");
        println!("      --daemon, -b              Run application in background (daemon mode)");
        println!("  -q, --quit, --stop            Stop running vrtfido process (foreground or daemon)");
        println!("  -d, --debug                   Enable packet debug mode");
        println!("  -u, --unlimited-fps           Unlimited fingerprint slots (default: 10)");
        println!("      --google-aaguid           Report Google Password Manager's AAGUID instead of the project's");
        if UHID_SUPPORTED {
            println!("      --uhid                    Create the virtual FIDO2 device on /dev/uhid and request elevated access (default: off)");
        } else {
            println!("      --uhid                    Unsupported on {}: the virtual FIDO2 device needs the Linux /dev/uhid interface", std::env::consts::OS);
        }
        println!("      --no-tray                 Disable the tray icon (on macOS/Windows it is shown by the prompt window)");
        println!("      --autostart               Enable start with system (runs daemon at login with current configuration)");
        println!("      --no-autostart            Disable start with system");
        println!("  -H, --host <HOST>             Bind address for the Web CMS and API (default: 0.0.0.0, every interface)");
        println!("  -p, --port <PORT>             Port for the Web CMS and API (default: 10209)");
        println!("  -D, --database, --db <SPEC>   Database path or connection URL (default: authenticator.db)");
        println!("                                Supported:");
        println!("                                  - SQLite:     authenticator.db or sqlite:my.db");
        println!("                                  - PostgreSQL: postgresql://user:pass@host:port/dbname");
        println!("                                  - LibSQL:     libsql://... or https://... (Turso) or file");
        println!("                                  - MySQL:      mysql://user:pass@host:port/dbname");
        println!("                                  - MariaDB:    mariadb://user:pass@host:port/dbname");
        println!("                                  - MongoDB:    mongodb://user:pass@host:port/dbname (or mongodb+srv://...)");
        println!("      --db-type <TYPE>          Specify DB type (sqlite, postgres, libsql, mysql, mariadb, mongodb)");
        println!("      --auth-token <TOKEN>      Authentication token (used by LibSQL / Turso; embed MongoDB creds in the URL)");
        println!("      --shadow-db <FILE>        Override SQLite read fallback (default: <runtime dir>/...)");
        println!("      --queue-db <FILE>         Override separate pending-write queue (default: <runtime dir>/...)");
        println!("      --export <FILE.json>      Export 100% database data to JSON file and exit");
        println!("      --import <FILE.json>      Import data from JSON file into current database");
        println!("      --exit-after-import       Exit immediately after import (do not start server)");
        println!("      --clean-logs, clean-logs [TYPE]");
        println!("                                Clear logs (all, auth, debug) and exit");
        println!("  -h, --help                    Show this help message\n");
        println!("Environment variables:");
        println!("  DATABASE_URL / DB_URL         Connection string or database file path");
        println!("  HOST / PORT                   Bind address and port for the Web CMS and API");
        println!("  DB_TYPE                       Database type");
        println!("  LIBSQL_AUTH_TOKEN             LibSQL authentication token");
        println!("  SHADOW_DB / QUEUE_DB          Override shadow and queue file paths (flags take precedence)");
        println!("Offline startup uses the local shadow; writes queue in order until the primary reconnects.");
        println!("Default runtime directory: {}", platform::runtime_dir().display());
        println!("A temporary directory can be cleared at reboot: use --shadow-db/--queue-db for durable storage.");
        println!("One-off --export, --import and --clean-logs require the primary database online.");
        println!("Logs older than {} days are deleted automatically: 30 seconds after the daemon starts, then once a day.", retention::RETENTION_DAYS);
        return Ok(());
    }

    let get_opt = |name: &str, short: Option<&str>| -> Option<String> {
        let prefix = format!("{}=", name);
        for (i, a) in args.iter().enumerate() {
            if a == name || short.map_or(false, |s| a == s) {
                if i + 1 < args.len() {
                    return Some(args[i + 1].clone());
                }
            } else if a.starts_with(&prefix) {
                return Some(a[prefix.len()..].to_string());
            }
        }
        None
    };

    let db_spec = get_opt("--database", Some("-D"))
        .or_else(|| get_opt("--db", None))
        .or_else(|| std::env::var("DATABASE_URL").ok())
        .or_else(|| std::env::var("DB_URL").ok())
        .unwrap_or_else(|| "authenticator.db".to_string());

    let db_type = get_opt("--db-type", None)
        .or_else(|| std::env::var("DB_TYPE").ok())
        .or_else(|| std::env::var("DATABASE_TYPE").ok());

    let auth_token = get_opt("--auth-token", None)
        .or_else(|| get_opt("--db-token", None))
        .or_else(|| std::env::var("LIBSQL_AUTH_TOKEN").ok())
        .or_else(|| std::env::var("DATABASE_AUTH_TOKEN").ok());

    let (default_shadow, default_queue) = default_resilient_paths(&db_spec, db_type.as_deref());
    let shadow_override = get_opt("--shadow-db", None).or_else(|| std::env::var("SHADOW_DB").ok());
    let queue_override = get_opt("--queue-db", None).or_else(|| std::env::var("QUEUE_DB").ok());
    let uses_default_sidecars = shadow_override.is_none() || queue_override.is_none();
    let shadow_path = shadow_override.unwrap_or(default_shadow);
    let queue_path = queue_override.unwrap_or(default_queue);

    let export_file = get_opt("--export", None);
    let import_file = get_opt("--import", None);

    let mask_db_url = |url: &str| -> String {
        if let Ok(mut parsed) = url::Url::parse(url) {
            if parsed.password().is_some() {
                let _ = parsed.set_password(Some("***"));
            }
            parsed.to_string()
        } else {
            url.to_string()
        }
    };

    println!("============================================================");
    println!("             VrtFido - Virtual FIDO2 / WebAuthn CMS         ");
    println!("============================================================");
    if debug_mode {
        println!("[CLI] DEBUG mode: ON (--debug)");
    } else {
        println!("[CLI] DEBUG mode: OFF (Use '--debug' to view raw packets)");
    }
    if unlimited_fps {
        println!("[CLI] FINGERPRINT mode: UNLIMITED (--unlimited-fps)");
    } else {
        println!("[CLI] FINGERPRINT mode: LIMITED TO 10 (Use '--unlimited-fps' to remove limit)");
    }
    if google_aaguid {
        println!("[CLI] AAGUID: GOOGLE {} (--google-aaguid)", passkey::aaguid_string());
    } else {
        println!(
            "[CLI] AAGUID: PROJECT {} (Use '--google-aaguid' to impersonate Google Password Manager)",
            passkey::aaguid_string()
        );
    }
    if uhid_enabled {
        println!("[CLI] UHID device: ENABLED (--uhid)");
    } else if UHID_SUPPORTED {
        println!("[CLI] UHID device: DISABLED (Use '--uhid' to create the virtual FIDO2 device on /dev/uhid)");
    } else {
        println!("[CLI] UHID device: NOT AVAILABLE on {} (Linux kernel /dev/uhid only)", std::env::consts::OS);
    }


    // One-off migration/maintenance must operate directly on the primary, never on stale data
    // or on a pending queue. Normal serving is resilient even if the primary is offline.
    println!("[DB] Connecting to database: {}", mask_db_url(&db_spec));
    let direct_operation = check_clean_logs.is_some() || export_file.is_some() || import_file.is_some();
    let continue_after_import = import_file.is_some();
    if uses_default_sidecars && (!direct_operation || (continue_after_import && !exit_after_import)) {
        platform::ensure_runtime_dir()?;
    }
    let db = if direct_operation {
        Db::open_with_options(&db_spec, db_type.as_deref(), auth_token.as_deref())?
    } else {
        Db::open_resilient(&db_spec, db_type.as_deref(), auth_token.as_deref(), &shadow_path, &queue_path)?
    };
    println!("[DB] [+] Database backend: {}", db.backend_name());
    if check_clean_logs.is_none() && export_file.is_none() {
        db.log_debug("INFO", "SYSTEM", &format!("Virtual FIDO2 Manager started with {} backend", db.backend_name()));
    }

    // Handle Clean Logs if requested
    if let Some(target) = check_clean_logs {
        let target_norm = target.trim().to_lowercase();
        println!("[CLEAN] Starting log cleanup (mode: {})...", target_norm);

        let clean_auth = target_norm == "all" || target_norm == "auth" || target_norm == "audit";
        let clean_debug = target_norm == "all" || target_norm == "debug";

        if !clean_auth && !clean_debug {
            eprintln!("[CLEAN] [!] Invalid log type: '{}'. Supported: all, auth, debug", target);
            std::process::exit(1);
        }

        let mut auth_deleted = 0;
        let mut debug_deleted = 0;

        if clean_auth {
            match db.clear_auth_logs() {
                Ok(count) => {
                    auth_deleted = count;
                    println!("[CLEAN] [+] Deleted {} authentication log records (auth_logs).", count);
                }
                Err(e) => {
                    eprintln!("[CLEAN] [!] Error deleting auth_logs: {}", e);
                    return Err(e.into());
                }
            }
        }

        if clean_debug {
            match db.clear_debug_logs() {
                Ok(count) => {
                    debug_deleted = count;
                    println!("[CLEAN] [+] Deleted {} debug log records (debug_logs).", count);
                }
                Err(e) => {
                    eprintln!("[CLEAN] [!] Error deleting debug_logs: {}", e);
                    return Err(e.into());
                }
            }

            // Clean daemon log file if exists
            let daemon_log_path = std::env::temp_dir().join("vrtfido.log");
            if daemon_log_path.exists() {
                match std::fs::write(&daemon_log_path, "") {
                    Ok(_) => println!("[CLEAN] [+] Cleaned daemon log file: {}", daemon_log_path.display()),
                    Err(e) => eprintln!("[CLEAN] [!] Could not clean daemon log file: {}", e),
                }
            }
        }

        println!("============================================================");
        println!("[CLEAN] [+] Log cleanup complete! Deleted: {} auth logs, {} debug logs.", auth_deleted, debug_deleted);
        return Ok(());
    }

    // Handle data import if requested
    if let Some(import_path) = import_file {
        println!("[MIGRATION] Importing data from file: {}", import_path);
        match db.import_from_file(&import_path) {
            Ok(stats) => {
                println!("[MIGRATION] [+] Data imported successfully!");
                println!("            - Credentials: {}", stats.credentials_imported);
                println!("            - Fingerprints: {}", stats.fingerprints_imported);
                println!("            - Auth logs: {}", stats.auth_logs_imported);
                println!("            - Debug logs: {}", stats.debug_logs_imported);
                println!("            - Security settings: {}", if stats.security_settings_updated { "Updated (PIN, UV)" } else { "Unchanged" });
            }
            Err(e) => {
                eprintln!("[MIGRATION] [!] Import error: {}", e);
                return Err(e.into());
            }
        }
        if exit_after_import {
            println!("[MIGRATION] Completed import and exiting (--exit-after-import).");
            return Ok(());
        }
    }

    // Handle data export if requested
    if let Some(export_path) = export_file {
        println!("[MIGRATION] Exporting 100% database data to file: {}", export_path);
        match db.export_to_file(&export_path) {
            Ok(_) => {
                let creds = db.get_credentials().map(|c| c.len()).unwrap_or(0);
                println!("[MIGRATION] [+] Successfully exported data to: {}", export_path);
                println!("            - Total credentials saved: {}", creds);
                return Ok(());
            }
            Err(e) => {
                eprintln!("[MIGRATION] [!] Export error: {}", e);
                return Err(e.into());
            }
        }
    }

    // --import without --exit-after-import proceeds as a daemon, with a fresh resilient handle.
    let db = if continue_after_import {
        drop(db);
        Db::open_resilient(&db_spec, db_type.as_deref(), auth_token.as_deref(), &shadow_path, &queue_path)?
    } else {
        db
    };

    // Handle startup entry registration or refresh
    if enable_autostart {
        match autostart::set_autostart_enabled(true) {
            Ok(()) => println!("[AUTOSTART] Autostart with system enabled."),
            Err(e) => eprintln!("[AUTOSTART] Failed to enable autostart: {}", e),
        }
    } else if disable_autostart {
        match autostart::set_autostart_enabled(false) {
            Ok(()) => println!("[AUTOSTART] Autostart with system disabled."),
            Err(e) => eprintln!("[AUTOSTART] Failed to disable autostart: {}", e),
        }
    } else {
        refresh_autostart_entry();
    }

    // 3. Check and grant /dev/uhid access via sudo if needed - only when the virtual device is
    // requested, so a Web-CMS-only run never prompts for a password. The unsupported platforms
    // have already exited above, so there is nothing to check off Linux.
    if uhid_enabled {
        println!("[UHID] Checking /dev/uhid access permission...");
        #[cfg(any(target_os = "linux", target_os = "android"))]
        uhid::ensure_uhid_permission();
    }
    // 4. Initialize SecurityEngine & AppState
    let sensor = sensor::UsbSensor::new();
    let security = SecurityEngine::new(db.clone(), sensor.clone(), unlimited_fps);
    let debug_mode_arc = Arc::new(AtomicBool::new(debug_mode));
    let uhid_connected = Arc::new(AtomicBool::new(false));

    // The bind address is the operator's choice: the default exposes the CMS on every
    // interface, `--host 127.0.0.1` keeps it on loopback. No authentication is imposed
    // either way, so publishing the service stays a deliberate deployment decision.
    let port = get_opt("--port", Some("-p"))
        .or_else(|| std::env::var("PORT").ok())
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(10209);
    let host = get_opt("--host", Some("-H"))
        .or_else(|| std::env::var("HOST").ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "0.0.0.0".to_string());
    let app_state = AppState {
        db: db.clone(),
        security: security.clone(),
        debug_mode: debug_mode_arc.clone(),
        uhid_connected: uhid_connected.clone(),
        unlimited_fps,
        port,
    };

    // Keep the log tables bounded: entries older than seven days are removed 30 seconds after
    // the daemon starts, then once a day. The handle lives as long as this process, so the worker
    // stops when the daemon does.
    let _log_retention = retention::LogRetention::start(db.clone());

    // 5. Start Web CMS Server on the configured address
    let app = web::create_router(app_state);
    let addr = format!("{}:{}", bind_host(&host), port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!(
        "[CMS] Web Management CMS is running at: http://{}:{}",
        display_host(&host),
        port
    );
    println!(
        "[CMS] Open browser at http://{}:{} to manage and approve verification requests\n",
        display_host(&host),
        port
    );

    // Run Web Server in background task
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            eprintln!("[CMS] Web Server error: {}", e);
        }
    });

    // 6. Start the virtual FIDO2 device on its own thread (Linux kernel UHID only).
    #[cfg(any(target_os = "linux", target_os = "android"))]
    uhid::spawn_device_thread(
        db.clone(),
        security.clone(),
        tokio::runtime::Handle::current(),
        uhid_enabled,
        debug_mode,
        uhid_connected.clone(),
    );

    // 7. Start the prompt window: a sibling process that talks to this daemon over the local
    // API. It is started unconditionally, because a host that cannot run it (no display, no
    // OpenGL) simply gets the headless daemon instead of a failed startup. On macOS and
    // Windows the client also owns the tray icon, so --no-tray travels with it.
    let mut gui_client = spawn_gui_client(gui_client_host(&host), port, !no_tray);

    // 8. Start the StatusNotifier tray item on Linux, where it needs no window at all.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let _tray_handle = if !no_tray {
        tray::spawn_tray(port, uhid_enabled).await
    } else {
        println!("[TRAY] System tray disabled (--no-tray)");
        None
    };

    // Write PID file for --quit command
    let _ = std::fs::write(&pid_file, std::process::id().to_string());
    wait_for_stop_signal().await?;

    if let Some(mut child) = gui_client.take() {
        stop_gui_client(&mut child);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some(handle) = _tray_handle {
        println!("[TRAY] Shutting down system tray service...");
        handle.shutdown().await;
    }

    let _ = std::fs::remove_file(&pid_file);
    Ok(())
}

/// Blocks until the operator stops the daemon: Ctrl+C everywhere, plus SIGTERM on Unix,
/// which is what `--quit` and the tray's Quit item send.
async fn wait_for_stop_signal() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("\n[!] Received stop signal (Ctrl+C). Shutting down...");
            }
            _ = sigterm.recv() => {
                println!("\n[!] Received stop signal (SIGTERM). Shutting down...");
            }
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        println!("\n[!] Received stop signal (Ctrl+C). Shutting down...");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_and_display_hosts_handle_wildcards_and_ipv6() {
        // An IPv6 literal needs brackets before the port can be appended.
        assert_eq!(bind_host("0.0.0.0"), "0.0.0.0");
        assert_eq!(bind_host("::"), "[::]");
        assert_eq!(bind_host("[::1]"), "[::1]");
        assert_eq!(bind_host("192.168.1.5"), "192.168.1.5");
        // Wildcards are shown as localhost, explicit addresses as configured.
        assert_eq!(display_host("0.0.0.0"), "localhost");
        assert_eq!(display_host("::"), "localhost");
        assert_eq!(display_host("192.168.1.5"), "192.168.1.5");
        // The GUI client runs on the same machine, so it dials the loopback address.
        assert_eq!(gui_client_host("0.0.0.0"), "127.0.0.1");
        assert_eq!(gui_client_host("::"), "::1");
        assert_eq!(gui_client_host("192.168.1.5"), "192.168.1.5");
    }
}
