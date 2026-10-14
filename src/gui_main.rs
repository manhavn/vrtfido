//! Entry point for `vrtfido-gui`, the VrtFido prompt window.
//!
//! The window is a separate process on purpose: the daemon binary then links no windowing stack
//! at all, so one package runs on a desktop (the window appears) and on a headless server (this
//! client exits at once and the daemon logs that the window is unavailable). It talks to the
//! daemon over its local HTTP API, the same one the Web CMS uses.

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("Usage: vrtfido-gui [--host <HOST>] [--port <PORT>] [--no-tray]");
        println!();
        println!("Renders the VrtFido verification window and drives it through the daemon's");
        println!("local API (default 127.0.0.1:10209). The daemon starts this client itself,");
        println!("so running it by hand is only useful for debugging.");
        println!();
        println!("  --no-tray   Do not add the menu-bar / notification-area icon (macOS and");
        println!("              Windows; the daemon passes this on when it runs with --no-tray).");
        return;
    }

    let host = value_of(&args, "--host").unwrap_or_else(|| "127.0.0.1".to_string());
    let port = value_of(&args, "--port")
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(10209);
    // The daemon owns the system tray on Linux, so the flag only reaches this process on the
    // platforms whose tray icon lives in the window (see `src/gui.rs`).
    let tray = !args.iter().any(|a| a == "--no-tray");

    std::process::exit(vrtfido_core::gui::run(&host, port, tray));
}

fn value_of(args: &[String], flag: &str) -> Option<String> {
    let with_equals = format!("{}=", flag);
    for (index, arg) in args.iter().enumerate() {
        if arg == flag {
            return args.get(index + 1).cloned();
        }
        if let Some(value) = arg.strip_prefix(&with_equals) {
            return Some(value.to_string());
        }
    }
    None
}
