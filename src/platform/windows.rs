use std::path::PathBuf;
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE, STILL_ACTIVE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, OpenProcess, TerminateProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_TERMINATE,
};

/// `PROCESSENTRY32W::szExeFile` is a fixed `MAX_PATH` wide-character array.
const MAX_PATH: usize = 260;

/// Windows has no per-uid `/tmp`: `%TEMP%` already belongs to the logged-in account, so
/// the runtime files live in a fixed subdirectory of it instead of a uid-named one.
pub fn runtime_dir() -> PathBuf {
    std::env::temp_dir().join("vrtfido")
}

pub fn ensure_runtime_dir() -> std::io::Result<()> {
    let path = runtime_dir();
    match std::fs::create_dir(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let metadata = std::fs::symlink_metadata(&path)?;
    if !metadata.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("{} must be a directory", path.display()),
        ));
    }
    Ok(())
}

/// `OpenProcess` fails for a pid that no longer exists, and a process that has exited but
/// is still held by a handle reports an exit code other than `STILL_ACTIVE`.
pub fn process_alive(pid: u32) -> bool {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return false;
        }
        let mut exit_code: u32 = 0;
        let ok = GetExitCodeProcess(handle, &mut exit_code) != 0;
        CloseHandle(handle);
        ok && exit_code == STILL_ACTIVE as u32
    }
}

/// A directed, catchable stop signal does not exist on Windows, so the graceful and the
/// forced path both terminate the process; see the module note in `platform/mod.rs`.
pub fn terminate(pid: u32) {
    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if handle.is_null() {
            return;
        }
        TerminateProcess(handle, 1);
        CloseHandle(handle);
    }
}

pub fn hard_terminate(pid: u32) {
    terminate(pid);
}

/// Process-table walk used by `--quit` when the pid file is missing or stale, the Windows
/// counterpart of the `/proc` scan on Linux.
pub fn find_process_by_name(name: &str) -> Option<u32> {
    let my_pid = std::process::id();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE || snapshot.is_null() {
            return None;
        }

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        let mut found = None;
        let mut has_entry = Process32FirstW(snapshot, &mut entry) != 0;
        while has_entry {
            if entry.th32ProcessID != my_pid {
                let len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(MAX_PATH);
                let exe = String::from_utf16_lossy(&entry.szExeFile[..len]);
                let stem = exe
                    .strip_suffix(".exe")
                    .or_else(|| exe.strip_suffix(".EXE"))
                    .unwrap_or(&exe);
                if stem.eq_ignore_ascii_case(name) {
                    found = Some(entry.th32ProcessID);
                    break;
                }
            }
            has_entry = Process32NextW(snapshot, &mut entry) != 0;
        }

        CloseHandle(snapshot);
        found
    }
}
