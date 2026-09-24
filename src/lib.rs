pub mod autostart;
pub mod db;
pub mod passkey;
pub mod security;
pub mod sensor;
pub mod tray;
pub mod web;

// Re-export common types
pub use db::Db;
pub use security::SecurityEngine;
pub use web::AppState;

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

/// Run standalone embedded HTTP Web CMS server (headless mode).
pub async fn run_server(
    db_path: &str,
    port: u16,
    unlimited_fps: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let db = Db::open(db_path)?;
    let sensor = sensor::UsbSensor::new();
    let security = security::SecurityEngine::new(db.clone(), sensor, unlimited_fps);

    let state = AppState {
        db,
        security,
        debug_mode: Arc::new(AtomicBool::new(false)),
        uhid_connected: Arc::new(AtomicBool::new(false)),
        unlimited_fps,
    };

    let router = web::create_router(state);
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("[HTTP] vrtfido daemon running on http://{}", addr);
    axum::serve(listener, router).await?;
    Ok(())
}

#[cfg(feature = "jni-bridge")]
pub mod jni_bridge {
    use super::*;
    use jni::objects::{JClass, JString};
    use jni::JNIEnv;

    #[no_mangle]
    pub extern "C" fn Java_com_vrtfido_VrtfidoService_startVrtfidoDaemon(
        mut env: JNIEnv,
        _class: JClass,
        db_path: JString,
        port: jni::sys::jint,
    ) {
        let path: String = env
            .get_string(&db_path)
            .map(|s| s.into())
            .unwrap_or_else(|_| "authenticator.db".into());
        let p = port as u16;
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("Failed to build Tokio runtime for vrtfido daemon");
            rt.block_on(async {
                if let Err(e) = run_server(&path, p, false).await {
                    eprintln!("[JNI] Error running vrtfido server: {}", e);
                }
            });
        });
    }
}

use std::fs::OpenOptions;
use std::path::Path;
use std::process::Command;

/// Checks whether permanent udev and module-load configurations exist for /dev/uhid.
pub fn has_permanent_uhid_rule() -> bool {
    Path::new("/etc/udev/rules.d/99-uhid.rules").exists()
        && Path::new("/etc/modules-load.d/uhid.conf").exists()
}

/// Execute elevated commands to permanently configure /dev/uhid udev rule,
/// load kernel module at boot, and set permissions for the current session.
pub fn ensure_permanent_uhid_permission() -> bool {
    println!("[UHID] [*] Requesting permission to configure permanent /dev/uhid udev rule...");

    let cmd_str = "mkdir -p /etc/modules-load.d /etc/udev/rules.d && \
                   echo 'uhid' > /etc/modules-load.d/uhid.conf && \
                   echo 'KERNEL==\"uhid\", MODE=\"0666\"' > /etc/udev/rules.d/99-uhid.rules && \
                   modprobe uhid 2>/dev/null || true; \
                   chmod 666 /dev/uhid 2>/dev/null || true; \
                   udevadm control --reload-rules 2>/dev/null || true; \
                   udevadm trigger 2>/dev/null || true";

    // 1. Try sudo (works well in terminal)
    let sudo_status = Command::new("sudo")
        .args(["sh", "-c", cmd_str])
        .status();

    let mut success = match sudo_status {
        Ok(s) if s.success() => true,
        _ => false,
    };

    // 2. If sudo fails or running in GUI environment (no TTY), try graphical elevation
    if !success && (std::env::var("DISPLAY").is_ok() || std::env::var("WAYLAND_DISPLAY").is_ok()) {
        if let Ok(pk_status) = Command::new("pkexec")
            .args(["sh", "-c", cmd_str])
            .status()
        {
            if pk_status.success() {
                success = true;
            }
        }

        if !success && Command::new("which").arg("zenity").output().map(|o| o.status.success()).unwrap_or(false) {
            let zenity_cmd = format!(
                "zenity --password --title=\"vrtfido - Cấp quyền /dev/uhid vĩnh viễn\" | sudo -S sh -c '{}'",
                cmd_str
            );
            if let Ok(z_status) = Command::new("sh").args(["-c", &zenity_cmd]).status() {
                if z_status.success() {
                    success = true;
                }
            }
        }
    }

    if success {
        if OpenOptions::new().read(true).write(true).open("/dev/uhid").is_ok() {
            println!("[UHID] [+] Granted permanent /dev/uhid access permission successfully!");
            return true;
        }
    }

    eprintln!("[UHID] [-] Failed to automatically acquire permanent /dev/uhid permission.");
    false
}
