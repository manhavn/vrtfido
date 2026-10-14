//! The daemon's whole host-OS seam: where the private runtime directory lives, and how a
//! running instance is found, probed and stopped.
//!
//! Everything else in this crate is either portable Rust or already gated per target, so
//! this module exists to keep three questions in one place instead of scattering
//! `#[cfg]` blocks across `main.rs` and `tray.rs`:
//!
//! * `runtime_dir()` / `ensure_runtime_dir()` - the per-user directory that holds the
//!   default shadow and queue databases. Unix derives it from the effective uid and
//!   enforces mode 0700 (`/tmp` is world-writable); Windows uses the per-user `%TEMP%`,
//!   which is already private to the account.
//! * `process_alive()`, `find_process_by_name()` - the two ways `--quit` and daemon
//!   startup detect an instance that is still running.
//! * `terminate()`, `hard_terminate()` - the stop signal. Unix sends
//!   `SIGTERM`, which lets the daemon run its shutdown path, then `SIGKILL` if it
//!   ignores it. Windows has no equivalent of a catchable, directed signal, so both
//!   levels map to `TerminateProcess`; the daemon cannot run cleanup there, and `--quit`
//!   removes the pid file itself.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;
