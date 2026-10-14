use std::path::PathBuf;

/// Private per-user runtime directory. `/tmp` is world-writable, so the name carries the
/// effective uid and `ensure_runtime_dir()` refuses anything that is not a 0700 directory
/// owned by that uid - a directory another user could have pre-created would otherwise let
/// them read the shadow database or replace the queue file.
pub fn runtime_dir() -> PathBuf {
    PathBuf::from(format!("/tmp/vrtfido-{}", unsafe { libc::geteuid() }))
}

/// Creates `runtime_dir()` with mode 0700 and re-validates an existing one.
pub fn ensure_runtime_dir() -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let path = runtime_dir();
    match std::fs::DirBuilder::new().mode(0o700).create(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let metadata = std::fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{} must be a private directory owned by the current user (mode 0700)",
                path.display()
            ),
        ));
    }
    Ok(())
}

/// Signal 0 performs the permission and existence checks of `kill(2)` without delivering
/// anything, which is the only portable liveness probe available to a non-parent.
pub fn process_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

pub fn terminate(pid: u32) {
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
}

pub fn hard_terminate(pid: u32) {
    unsafe {
        libc::kill(pid as i32, libc::SIGKILL);
    }
}

/// Last-resort lookup for `--quit` when the pid file is missing or stale: the process
/// table names the daemon directly. Linux and Android read `/proc`; macOS has no `/proc`,
/// so there the pid file the daemon writes is the only handle and a stale file leaves
/// nothing to find.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn find_process_by_name(name: &str) -> Option<u32> {
    find_process_by_name_via_proc(name)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn find_process_by_name(name: &str) -> Option<u32> {
    let _ = name;
    None
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn find_process_by_name_via_proc(name: &str) -> Option<u32> {
    let my_pid = std::process::id();
    let entries = std::fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if pid == my_pid {
            continue;
        }
        let comm_path = entry.path().join("comm");
        if let Ok(comm) = std::fs::read_to_string(comm_path) {
            if comm.trim() == name {
                return Some(pid);
            }
        }
    }
    None
}
