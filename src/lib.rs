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

fn server_router(db_path: &str, port: u16) -> Result<axum::Router, db::DbError> {
    let db = Db::open(db_path)?;
    let sensor = sensor::UsbSensor::new();
    let security = SecurityEngine::new(db.clone(), sensor, false);
    Ok(web::create_router(AppState {
        db,
        security,
        debug_mode: Arc::new(AtomicBool::new(false)),
        uhid_connected: Arc::new(AtomicBool::new(false)),
        unlimited_fps: false,
        port,
    }))
}

#[cfg(feature = "jni-bridge")]
pub mod jni_bridge {
    use super::*;
    use jni::objects::{JClass, JString};
    use jni::sys::jstring;
    use jni::JNIEnv;
    use parking_lot::Mutex;
    use std::sync::{mpsc, LazyLock};
    use std::time::Duration;
    use tokio::sync::oneshot;

    struct Daemon {
        stop: oneshot::Sender<()>,
        thread: std::thread::JoinHandle<()>,
    }

    static DAEMON: LazyLock<Mutex<Option<Daemon>>> = LazyLock::new(|| Mutex::new(None));

    fn start(db_path: String, host: String, port: u16) -> Result<(), String> {
        let ip: std::net::Ipv4Addr = host.parse().map_err(|_| "Host must be an IPv4 address".to_string())?;
        if port == 0 {
            return Err("Port must be between 1 and 65535".into());
        }
        let mut current = DAEMON.lock();
        if let Some(old) = current.take() {
            if !old.thread.is_finished() {
                *current = Some(old);
                return Err("vrtfido is already running".into());
            }
            let _ = old.thread.join();
        }

        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (stop_tx, stop_rx) = oneshot::channel();
        let panic_report = ready_tx.clone();
        let thread = std::thread::spawn(move || {
            let running = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
                    Ok(rt) => rt,
                    Err(err) => {
                        let _ = ready_tx.send(Err(format!("Tokio runtime: {err}")));
                        return;
                    }
                };
                runtime.block_on(async move {
                    let result = async {
                        let router = server_router(&db_path, port).map_err(|e| e.to_string())?;
                        let listener = tokio::net::TcpListener::bind((ip, port))
                            .await
                            .map_err(|e| format!("Cannot listen on {ip}:{port}: {e}"))?;
                        Ok::<_, String>((router, listener))
                    }
                    .await;
                    match result {
                        Ok((router, listener)) => {
                            let _ = ready_tx.send(Ok(()));
                            tokio::select! {
                                result = axum::serve(listener, router) => {
                                    if let Err(err) = result {
                                        eprintln!("[HTTP] vrtfido server stopped: {err}");
                                    }
                                }
                                _ = stop_rx => {}
                            }
                        }
                        Err(err) => {
                            let _ = ready_tx.send(Err(err));
                        }
                    }
                });
            }));
            if let Err(panic) = running {
                let message = panic.downcast_ref::<String>().cloned()
                    .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_else(|| "unknown panic".into());
                let _ = panic_report.send(Err(format!("Native server panicked: {message}")));
            }
        });
        match ready_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(())) => {
                *current = Some(Daemon { stop: stop_tx, thread });
                Ok(())
            }
            other => {
                let _ = stop_tx.send(());
                Err(match other {
                    Ok(Err(err)) => err,
                    Err(err) => format!("Server startup failed: {err}"),
                    Ok(Ok(())) => unreachable!(),
                })
            }
        }
    }

    fn stop() {
        if let Some(daemon) = DAEMON.lock().take() {
            let _ = daemon.stop.send(());
            let _ = daemon.thread.join();
        }
    }

    #[no_mangle]
    pub extern "C" fn Java_com_vrtfido_VrtfidoService_startVrtfidoDaemon(
        mut env: JNIEnv,
        _class: JClass,
        db_path: JString,
        host: JString,
        port: jni::sys::jint,
    ) -> jstring {
        let result = (|| {
            let path: String = env.get_string(&db_path)
                .map_err(|e| format!("Invalid database path: {e}"))?.into();
            let host: String = env.get_string(&host)
                .map_err(|e| format!("Invalid host: {e}"))?.into();
            if !(1..=65535).contains(&port) {
                return Err("Port must be between 1 and 65535".into());
            }
            start(path, host, port as u16)
        })();
        match result {
            Ok(()) => std::ptr::null_mut(),
            Err(err) => env.new_string(err).map_or(std::ptr::null_mut(), |s| s.into_raw()),
        }
    }

    #[no_mangle]
    pub extern "C" fn Java_com_vrtfido_VrtfidoService_stopVrtfidoDaemon(
        _env: JNIEnv,
        _class: JClass,
    ) {
        stop();
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::{Read, Write};

        #[test]
        fn serves_status_then_releases_port() {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = probe.local_addr().unwrap().port();
            drop(probe);
            let path = std::env::temp_dir().join(format!("vrtfido-{}-{port}.db", std::process::id()));
            start(path.to_str().unwrap().into(), "0.0.0.0".into(), port).unwrap();
            let mut socket = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            socket.write_all(b"GET /api/status HTTP/1.0\r\nHost: localhost\r\n\r\n").unwrap();
            let mut response = String::new();
            socket.read_to_string(&mut response).unwrap();
            assert!(response.starts_with("HTTP/1.0 200") || response.starts_with("HTTP/1.1 200"), "{response}");
            assert!(response.contains("\"app_name\":\"vrtfido\""), "{response}");
            assert!(response.contains(&format!("\"port\":{port}")), "{response}");
            drop(socket);
            stop();
            let listener = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
            assert!(start(path.to_str().unwrap().into(), "0.0.0.0".into(), port).is_err());
            drop(listener);
            start(path.to_str().unwrap().into(), "127.0.0.1".into(), port).unwrap();
            assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok());
            stop();
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(path.with_extension("db-wal"));
            let _ = std::fs::remove_file(path.with_extension("db-shm"));
        }
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
