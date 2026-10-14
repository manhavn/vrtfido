//! `vrtfido-gui`: the VrtFido prompt window, drawn with egui/eframe.
//!
//! The window is a *client* of the daemon's local HTTP API, exactly like the Web CMS: it polls
//! `/api/verify/pending` and settles the request it finds through `/api/verify/approve`,
//! `/api/verify/reject`, `/api/verify/remember` and `/api/verify/select`. That is what lets the
//! daemon binary link no windowing stack at all - a host without a display or an OpenGL driver
//! simply never gets a window, and one rewrite of this file serves Linux, macOS and Windows.
//!
//! Three things are worth knowing before touching this file:
//!
//! * **Process split.** `main.rs` starts this process itself and waits 500 ms to decide between
//!   "prompt window" and "headless daemon", so [`run`] has to fail fast and non-zero when there is
//!   no daemon API and no usable window. A window that loses the daemon *later* closes instead of
//!   lingering ([`UNREACHABLE_POLL_LIMIT`]).
//! * **The card.** One card, drawn from the request on screen: it opens at [`WINDOW_SIZE`] and is
//!   resizable, so the same dialog works on a 1024x600 netbook and on a 4K desktop. The content is
//!   responsive - rows are laid out from the width they are given and `centered_row` wraps a row
//!   that cannot fit - and it scrolls when the card is shorter than the request needs. The card
//!   gives up [`SCROLL_BAR_RESERVE`] so the bar never crosses a button.
//! * **Window lifetime.** macOS and Windows keep one window for the whole run and hide it between
//!   requests, because the tray icon built in this process needs that event loop (`sync_window`).
//!   Linux holds no window at all while nothing is pending: winit cannot unmap
//!   a window on Wayland - `Window::set_visible` is a no-op there, and so is the `visible` field
//!   of a [`egui::ViewportBuilder`] - so a window that exists is a window the user sees. `run_ephemeral`
//!   therefore polls the daemon without any window and opens the card per request. The poll that
//!   keeps the card in sync with the daemon lives in [`eframe::App::logic`], which eframe calls
//!   for an invisible window too, and every pass asks for the next one through
//!   `request_repaint_after`.
//! * **Tray.** On macOS and Windows the menu-bar / notification-area icon is built in this very
//!   process (see [`TrayState`]), because those APIs need the thread that runs the event loop.
//!   Linux has no tray here: the daemon owns a `ksni` item that needs no window.

use crate::security::PendingPrompt;
use crate::web::{
    ApiResponse, ApproveVerifyRequest, RememberRequest, RejectVerifyRequest, SelectAccountRequest,
};
use eframe::egui;
use egui::{
    Align, Color32, CornerRadius, FontId, Margin, RichText, Stroke, Vec2, ViewportCommand,
};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// How often the window ticks: 200 ms between checks, with [`IDLE_TICKS`] of them skipped while
/// nothing is on screen.
const POLL_TICK: Duration = Duration::from_millis(200);
/// Idle ticks to skip before polling again while the window is hidden. 5 x 200 ms means one
/// request per second (`pending()` plus its answer) for a window that shows nothing - a hidden
/// prompt must not cost 5 wakeups and 5 round trips per second for the whole day.
///
/// The same 200 ms x 5 is the interval the Linux client polls at while it holds no window at all
/// (`wait_for_prompt`), so an idle client costs the daemon the same once per second on every
/// platform.
const IDLE_TICKS: u32 = 5;
/// Consecutive unreachable polls after which the daemon counts as gone. 10 of them are about ten
/// seconds at the idle cadence, which covers a daemon that is restarting.
const UNREACHABLE_POLL_LIMIT: u32 = 10;
/// A fingerprint enrollment nobody answers must not hold the chip busy forever. The daemon gives
/// up after 180 s and its lift watchdog already fires after 60 s; the window abandons the panel
/// after the same 60 s without *any* progress, which is the case where the user walked away.
const ENROLL_ABANDON: Duration = Duration::from_secs(60);
/// How long the enrollment panel keeps a final "captured" / "failed" message on screen before it
/// closes itself - the same delay the CMS modal uses.
const ENROLL_NOTICE_HOLD: Duration = Duration::from_secs(2);
/// Hide commands sent after a transition to hidden.
///
/// eframe shows the window itself once it has painted its first frame, so the hiding command of
/// that same pass is undone before the frame is over; the second one lands after it.
///
/// Only macOS and Windows hide this window: the Linux client closes it instead, because Wayland
/// cannot unmap one (see the module documentation).
const HIDE_ASSERTIONS: u8 = 2;
/// The window is a dialog, not an app: a narrow, always-on-top card that opens at this size. It is
/// resizable, because the card is the only surface for a verification request on this host and the
/// space it gets differs from desktop to desktop; the content follows the size (the rows wrap, the
/// account picker and the fields take the width they are given) and scrolls when the card is
/// shorter than the request needs.
const WINDOW_SIZE: [f32; 2] = [480.0, 440.0];
/// Smallest the card may be dragged to: below this a wrapped row and the account picker stop being
/// readable. There is no upper bound - the card fills whatever space the desktop gives it.
const MIN_WINDOW_WIDTH: f32 = 380.0;
const MIN_WINDOW_HEIGHT: f32 = 320.0;
/// Padding around the card, inside the window.
const CARD_OUTER_MARGIN: i8 = 8;
/// Padding inside the card, between its border and the content.
const CARD_INNER_MARGIN: i8 = 10;
/// Strip of the card's content the scroll bar takes: egui draws the bar *over* the content, so the
/// card gives up that width instead of letting the bar cross the last button.
const SCROLL_BAR_RESERVE: f32 = 10.0;

/// Width the card's content has at [`WINDOW_SIZE`]: the window minus both paddings, the two 2 pt
/// border halves and [`SCROLL_BAR_RESERVE`]. Every row of the card has to fit in it, which is what
/// `the_verify_action_row_fits_the_card_and_is_centred` holds the widest row to.
#[cfg(test)]
fn card_content_width() -> f32 {
    WINDOW_SIZE[0] - 2.0 * f32::from(CARD_OUTER_MARGIN + 2 + CARD_INNER_MARGIN) - SCROLL_BAR_RESERVE
}

const ESCAPE_REASON: &str = "Dismissed via Escape";
const CLOSE_REASON: &str = "Window closed by the user";
const REJECT_REASON: &str = "Rejected in the VrtFido prompt window";

/// The Web CMS dark palette, so the window and the dashboard look like one product: slate
/// surfaces with a sky-blue accent (the CSS variables of `index_html`).
struct Palette;

impl Palette {
    /// #0f172a - window background.
    const BG: Color32 = Color32::from_rgb(0x0f, 0x17, 0x2a);
    /// #182234 - the modal card.
    const CARD: Color32 = Color32::from_rgb(0x18, 0x22, 0x34);
    /// #38bdf8 - accent: card border, primary buttons, account labels.
    const ACCENT: Color32 = Color32::from_rgb(0x38, 0xbd, 0xf8);
    /// #0ea5e9 - hovered accent.
    const ACCENT_HOVER: Color32 = Color32::from_rgb(0x0e, 0xa5, 0xe9);
    /// #020617 - text on an accent surface.
    const ON_ACCENT: Color32 = Color32::from_rgb(0x02, 0x06, 0x17);
    /// #f8fafc - primary text.
    const TEXT: Color32 = Color32::from_rgb(0xf8, 0xfa, 0xfc);
    /// #94a3b8 - secondary text.
    const MUTED: Color32 = Color32::from_rgb(0x94, 0xa3, 0xb8);
    /// #1e293b - inset surfaces: RP badge, account box, input background.
    const PANEL: Color32 = Color32::from_rgb(0x1e, 0x29, 0x3b);
    /// #334155 - hairline borders and the secondary button background.
    const BORDER: Color32 = Color32::from_rgb(0x33, 0x41, 0x55);
    /// #475569 - secondary button border and hover background.
    const SECONDARY_BORDER: Color32 = Color32::from_rgb(0x47, 0x55, 0x69);
    /// #ef4444 - rejection, failures and the danger button.
    const DANGER: Color32 = Color32::from_rgb(0xef, 0x44, 0x44);
    /// rgba(239, 68, 68, 0.18) - resting danger button background.
    const DANGER_BG: Color32 = Color32::from_rgba_unmultiplied_const(0xef, 0x44, 0x44, 46);
    /// rgba(239, 68, 68, 0.4) - resting danger button border.
    const DANGER_BORDER: Color32 = Color32::from_rgba_unmultiplied_const(0xef, 0x44, 0x44, 102);
    /// #f59e0b - warnings ("security is not configured yet").
    const WARNING: Color32 = Color32::from_rgb(0xf5, 0x9e, 0x0b);
    /// #10b981 - the "this app run is already verified" notice.
    const SUCCESS: Color32 = Color32::from_rgb(0x10, 0xb9, 0x81);
    /// #ffffff - danger button text once it inverts to solid red.
    const WHITE: Color32 = Color32::WHITE;
}

/// Blocking client for the daemon's local verification API.
///
/// Method names and signatures mirror the engine's, which keeps the window code below the same
/// shape as the in-process modal it replaced. Every call runs on a worker thread (see
/// [`PromptApp::spawn`]): the fingerprint approval alone waits up to 60 s for a finger, and a
/// frozen window is exactly what this process exists to avoid.
#[derive(Clone)]
struct PromptApi {
    host: String,
    port: u16,
    /// One agent for the whole client: it keeps the loopback connection alive, so a poll does not
    /// open and tear down a TCP connection every tick.
    agent: ureq::Agent,
}

impl PromptApi {
    fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port,
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(60))
                .build(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}:{}{}", self.host, self.port, path)
    }

    /// The Web CMS address, used for the tray's "Dashboard" item.
    fn dashboard_url(&self) -> String {
        format!("http://{}:{}", self.host, self.port)
    }

    /// Startup probe. `/api/health` answers as soon as the daemon's listener is bound - which it
    /// is before `main.rs` spawns this client - so a stale `--port` is detected before a window
    /// is opened instead of after ten failed polls.
    fn probe(&self) -> Result<(), String> {
        self.agent
            .get(&self.url("/api/health"))
            .timeout(Duration::from_secs(2))
            .call()
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// The request the daemon is waiting for, `None` when none is pending. An error means the
    /// daemon could not be reached at all.
    fn pending(&self) -> Result<Option<PendingPrompt>, String> {
        let response = self
            .agent
            .get(&self.url("/api/verify/pending"))
            .timeout(Duration::from_secs(2))
            .call()
            .map_err(|e| e.to_string())?;
        let body: ApiResponse<Option<PendingPrompt>> = response
            .into_json()
            .map_err(|e| format!("invalid daemon response: {}", e))?;
        if body.success {
            Ok(body.data.unwrap_or(None))
        } else {
            Err(body.error.unwrap_or_else(|| "daemon rejected the request".into()))
        }
    }

    /// The fingerprint path waits for the USB sensor inside the daemon, so this call needs a
    /// timeout well beyond that scan window.
    fn approve_pending(
        &self,
        request_id: u64,
        method: &str,
        pin: Option<&str>,
        credential_id: Option<String>,
        remember: Option<bool>,
    ) -> Result<(), String> {
        self.post(
            "/api/verify/approve",
            &ApproveVerifyRequest {
                request_id,
                method: method.to_string(),
                pin: pin.map(|value| value.to_string()),
                credential_id,
                remember,
            },
            Duration::from_secs(60),
        )
    }

    fn reject_pending(&self, request_id: u64, reason: &str) -> Result<(), String> {
        self.post(
            "/api/verify/reject",
            &RejectVerifyRequest {
                request_id,
                reason: Some(reason.to_string()),
            },
            Duration::from_secs(5),
        )
    }

    fn set_remember_requested(&self, enabled: bool) -> Result<(), String> {
        self.post(
            "/api/verify/remember",
            &RememberRequest { enabled },
            Duration::from_secs(5),
        )
    }

    fn select_account(&self, request_id: u64, credential_id: &str) -> Result<(), String> {
        self.post(
            "/api/verify/select",
            &SelectAccountRequest {
                request_id,
                credential_id: credential_id.to_string(),
            },
            Duration::from_secs(5),
        )
    }

    /// Starts the daemon's 6-stage enrollment; the stages themselves are followed through
    /// [`PromptApi::enrollment_status`].
    fn start_enrollment(&self, name: &str) -> Result<(), String> {
        // The daemon's own `AddFingerprintRequest` is `Deserialize` only (it is the server side
        // of the route), so the client sends its own view of the same body.
        self.post(
            "/api/security/fingerprints/enroll/start",
            &EnrollRequest { name },
            Duration::from_secs(5),
        )
    }

    fn enrollment_status(&self) -> Result<EnrollProgress, String> {
        let response = self
            .agent
            .get(&self.url("/api/security/fingerprints/enroll/status"))
            .timeout(Duration::from_secs(2))
            .call()
            .map_err(|e| e.to_string())?;
        let body: ApiResponse<EnrollProgress> = response
            .into_json()
            .map_err(|e| format!("invalid daemon response: {}", e))?;
        if body.success {
            body.data.ok_or_else(|| "daemon sent no progress".to_string())
        } else {
            Err(body.error.unwrap_or_else(|| "daemon rejected the request".into()))
        }
    }

    fn cancel_enrollment(&self) -> Result<(), String> {
        self.post_empty("/api/security/fingerprints/enroll/cancel", Duration::from_secs(5))
    }

    fn post<B: serde::Serialize>(
        &self,
        path: &str,
        payload: &B,
        timeout: Duration,
    ) -> Result<(), String> {
        match self.agent.post(&self.url(path)).timeout(timeout).send_json(payload) {
            Ok(response) => Self::read_result(response),
            // A 4xx/5xx answer still carries the daemon's explanation, so read that body instead
            // of reporting a bare status code.
            Err(ureq::Error::Status(_, response)) => Self::read_result(response),
            Err(other) => Err(other.to_string()),
        }
    }

    /// `POST` without a body, for the endpoints that take none.
    fn post_empty(&self, path: &str, timeout: Duration) -> Result<(), String> {
        match self.agent.post(&self.url(path)).timeout(timeout).call() {
            Ok(response) => Self::read_result(response),
            Err(ureq::Error::Status(_, response)) => Self::read_result(response),
            Err(other) => Err(other.to_string()),
        }
    }

    fn read_result(response: ureq::Response) -> Result<(), String> {
        let body: ApiResponse<bool> = response
            .into_json()
            .map_err(|e| format!("invalid daemon response: {}", e))?;
        if body.success {
            Ok(())
        } else {
            Err(body.error.unwrap_or_else(|| "request failed".into()))
        }
    }
}

/// The enrollment label, as `POST /api/security/fingerprints/enroll/start` expects it.
#[derive(serde::Serialize)]
struct EnrollRequest<'a> {
    name: &'a str,
}

/// The enrollment progress of `sensor::EnrollProgress`, read back from the API.
///
/// The daemon type is `Serialize` only, and this window has no business in the sensor module, so
/// the client keeps its own view of the same JSON.
#[derive(serde::Deserialize, Clone, Debug)]
struct EnrollProgress {
    active: bool,
    stage: u32,
    total_stages: u32,
    status: String,
    message: String,
    error: Option<String>,
}

/// Which approval button was pressed. The string is the `method` of `/api/verify/approve`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ApprovalKind {
    Pin,
    Setup,
    Remembered,
    Fingerprint,
}

impl ApprovalKind {
    fn method(self) -> &'static str {
        match self {
            Self::Pin => "PIN",
            Self::Setup => "SETUP",
            Self::Remembered => "REMEMBERED",
            Self::Fingerprint => "FINGERPRINT",
        }
    }
}

/// Everything a worker thread hands back to the ui thread. Owning the data keeps the worker out
/// of `PromptApp`: only `logic()` touches the window state.
enum WorkerResult {
    /// Answer of the `/api/verify/pending` poll.
    Pending(Result<Option<PendingPrompt>, String>),
    /// One of the approve calls came back.
    Approval {
        kind: ApprovalKind,
        result: Result<(), String>,
    },
    /// A `reject` call came back. The window is already hidden by then: a refused rejection only
    /// means the request was settled elsewhere (the CMS, the sensor, the timeout).
    Rejected(Result<(), String>),
    /// The "Remember" checkbox of this window was pushed to the daemon.
    Remember(Result<(), String>),
    /// An account choice was pushed to the daemon.
    Select(Result<(), String>),
    /// `/api/security/fingerprints/enroll/start` came back.
    EnrollmentStarted(Result<(), String>),
    /// Answer of the `/api/security/fingerprints/enroll/status` poll.
    EnrollmentStatus(Result<EnrollProgress, String>),
    /// `/api/security/fingerprints/enroll/cancel` came back.
    EnrollmentCancelled(Result<(), String>),
}

/// How a status line is coloured: `.status-error` / `.status-info` / `.status-warning` /
/// `.status-success` of the CMS.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StatusKind {
    Info,
    Error,
    Warning,
    Success,
}

impl StatusKind {
    fn color(self) -> Color32 {
        match self {
            Self::Info => Palette::ACCENT,
            Self::Error => Palette::DANGER,
            Self::Warning => Palette::WARNING,
            Self::Success => Palette::SUCCESS,
        }
    }
}

/// The one status line under the buttons, empty when nothing has to be reported.
struct Status {
    text: String,
    kind: StatusKind,
}

impl Default for Status {
    fn default() -> Self {
        Self {
            text: String::new(),
            kind: StatusKind::Info,
        }
    }
}

/// A client-side message of the enrollment panel (the daemon's own text travels in the progress),
/// coloured like the status line it replaces.
struct EnrollmentNotice {
    text: String,
    kind: StatusKind,
}

/// State of the 6-stage fingerprint enrollment panel.
struct EnrollmentState {
    /// Label typed by the user ("Right Index", ...); the daemon stores it with the template.
    name: String,
    /// A scan is running on the daemon: follow it through `/enroll/status`.
    running: bool,
    /// The `start` call itself is in flight.
    starting: bool,
    /// A status poll is in flight (one at a time).
    status_in_flight: bool,
    /// The last progress the daemon reported.
    progress: Option<EnrollProgress>,
    /// When the progress last changed, so a scan nobody answers can be abandoned.
    last_change: Instant,
    /// Client-side message shown under the daemon's own text (errors, abandonment).
    notice: Option<EnrollmentNotice>,
    /// A final state was reached: the daemon is done, only closing is left.
    finished: bool,
    /// When the panel closes itself after a final state.
    close_at: Option<Instant>,
}

impl EnrollmentState {
    fn new() -> Self {
        Self {
            name: String::new(),
            running: false,
            starting: false,
            status_in_flight: false,
            progress: None,
            last_change: Instant::now(),
            notice: None,
            finished: false,
            close_at: None,
        }
    }
}

/// What a click in the window asked for, applied after the ui pass so the drawing code never
/// needs a mutable borrow of the whole app.
enum UiAction {
    Approve(ApprovalKind),
    Reject(&'static str),
    Remember(bool),
    SelectAccount(String),
    OpenEnrollment,
    StartEnrollment,
    CancelEnrollment,
}

struct PromptApp {
    api: PromptApi,
    /// Worker threads report here; `logic()` drains it on the ui thread.
    tx: Sender<WorkerResult>,
    rx: Receiver<WorkerResult>,

    /// The request on screen, `None` while the window is hidden.
    prompt: Option<PendingPrompt>,
    /// The two PIN fields, kept out of `prompt` because the daemon never learns about typing.
    pin: String,
    setup_pin: String,
    /// "Remember for this app run" checkbox, mirrored to the daemon on every change.
    remember: bool,
    /// Credential id of the account chosen in the multi-account list.
    account: Option<String>,
    status: Status,
    /// An approval (PIN / setup / remembered) is in flight: one action at a time.
    busy: bool,
    /// The sensor button owns the chip until its call returns.
    sensor_scan: bool,
    /// Set while the enrollment panel is open.
    enroll: Option<EnrollmentState>,

    /// Poll bookkeeping for the 200 ms tick.
    last_tick: Instant,
    idle_ticks: u32,
    poll_in_flight: bool,
    unreachable_polls: u32,
    /// The daemon is gone: close the viewport on the next pass.
    quit: bool,
    /// This window asked to close itself: a settled request on Linux, or a daemon that is gone.
    /// The close request that follows is then ours and must not be answered with `CancelClose`,
    /// which is what the window manager's "X" gets.
    closing: bool,
    /// The last visibility this window asked for, to send the command only on a change.
    window_shown: bool,
    /// Hide commands still owed to the window manager after a transition to hidden.
    hidden_assertions: u8,
    /// A newly arrived request wants the PIN field focused.
    focus_pin: bool,

    /// Menu-bar (macOS) / notification-area (Windows) icon; always `None` elsewhere.
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    tray: Option<TrayState>,
}

/// Runs the prompt window until the daemon disappears or the user quits it.
///
/// Returns the exit status of this process. A non-zero status is the "no prompt window on this
/// host" signal `main.rs` reacts to: it either comes from the startup probe (no daemon API), from
/// the display pre-flight, or from eframe (no usable OpenGL surface).
pub fn run(host: &str, port: u16, tray: bool) -> i32 {
    let api = PromptApi::new(host, port);

    // Fail fast: the daemon waits 500 ms for this process to die before it calls itself headless,
    // and a window pointed at a dead port has nothing to show anyway.
    if let Err(reason) = api.probe() {
        eprintln!("[GUI] Cannot reach the VrtFido daemon API: {}", reason);
        eprintln!(
            "[GUI] The prompt window needs the daemon at {}; continuing without a window.",
            api.dashboard_url()
        );
        return 1;
    }

    // Linux keeps no window while nothing is pending, so a host whose window could never open is
    // detected here, in the same breath as the API probe `main.rs` already waits for.
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = tray; // the tray icon lives in the daemon on these platforms
        if !has_display() {
            eprintln!(
                "[GUI] No display found (neither WAYLAND_DISPLAY nor DISPLAY is set); continuing without a window."
            );
            return 1;
        }
        return run_ephemeral(&api);
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        let api_for_app = api.clone();
        return match eframe::run_native(
            "VrtFido",
            native_options(),
            Box::new(move |cc| Ok(Box::new(PromptApp::new(cc, api_for_app, tray, None)))),
        ) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("[GUI] Could not open the prompt window: {}", e);
                eprintln!(
                    "[GUI] A display and an OpenGL 3.3 / GLES 3.0 driver are required; the daemon and its Web CMS keep working without them."
                );
                1
            }
        };
    }
}

/// The native window this client asks eframe for, wherever one is created.
fn native_options() -> eframe::NativeOptions {
    #[allow(unused_mut)]
    let mut native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("WebAuthn Verification Request - VrtFido")
            .with_inner_size(WINDOW_SIZE)
            .with_min_inner_size([MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT])
            .with_resizable(true)
            // The browser sits on the WebAuthn call while this card is up: it has to be readable.
            .with_always_on_top()
            // Wayland/X11 use this as the app id, which is what the window list shows.
            .with_app_id("dev.vrtfido.prompt"),
        centered: true,
        ..Default::default()
    };

    // macOS: `Accessory` keeps the prompt out of the Dock and out of the app switcher, which is
    // what a dialog spawned by a daemon should be. The activation policy is a property of the
    // process, so winit has to be told before its event loop is built.
    #[cfg(target_os = "macos")]
    {
        use winit::platform::macos::{ActivationPolicy, EventLoopBuilderExtMacOS};
        native_options.event_loop_builder = Some(Box::new(|builder| {
            builder.with_activation_policy(ActivationPolicy::Accessory);
        }));
    }

    native_options
}

/// `true` when this host has a display a window could be opened on.
///
/// A one-line pre-flight, not a guarantee: it filters out the headless case (a VPS, a container,
/// a service without a session) early enough for `main.rs` to fall back to the Web CMS prompt. A
/// session that has a socket but no usable GL driver is only discovered when the first request
/// wants a window.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn has_display() -> bool {
    ["WAYLAND_DISPLAY", "DISPLAY"]
        .iter()
        .any(|key| std::env::var_os(key).is_some_and(|value| !value.is_empty()))
}

/// Runs one window per verification request.
///
/// The Linux half of `run`. winit cannot unmap a window on Wayland (and "unminimizing is ignored"
/// there too), so *no* prompt on screen means *no* window: the daemon is polled over plain HTTP
/// while nothing is pending (`wait_for_prompt`), the card is opened for the request that arrives
/// and closed again as soon as the request is settled. Nothing survives a request - no window
/// state to reset, nothing left on the desktop.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn run_ephemeral(api: &PromptApi) -> i32 {
    loop {
        let Some(prompt) = wait_for_prompt(api) else {
            // The daemon is gone: there is nothing left to prompt for.
            return 0;
        };
        println!(
            "[GUI] Verification request #{}: opening the prompt window.",
            prompt.request_id
        );

        let api_for_app = api.clone();
        match eframe::run_native(
            "VrtFido",
            native_options(),
            Box::new(move |cc| Ok(Box::new(PromptApp::new(cc, api_for_app, false, Some(prompt))))),
        ) {
            // The window was closed again (the request is settled): poll for the next one.
            Ok(()) => {}
            Err(e) => {
                eprintln!("[GUI] Could not open the prompt window: {}", e);
                eprintln!(
                    "[GUI] A display and an OpenGL 3.3 / GLES 3.0 driver are required; the daemon and its Web CMS keep working without them."
                );
                return 1;
            }
        }
    }
}

/// Asks the daemon for a request while no window exists; `None` once the daemon counts as gone.
///
/// The same poll the window runs, at the same one-second cadence a hidden window uses
/// (`POLL_TICK` x `IDLE_TICKS`), and the same `UNREACHABLE_POLL_LIMIT` before the daemon is
/// declared gone - so a daemon restart is awaited here exactly like there.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn wait_for_prompt(api: &PromptApi) -> Option<PendingPrompt> {
    let mut unreachable_polls = 0;
    loop {
        match api.pending() {
            Ok(Some(prompt)) => return Some(prompt),
            Ok(None) => unreachable_polls = 0,
            Err(reason) => {
                unreachable_polls += 1;
                if unreachable_polls >= UNREACHABLE_POLL_LIMIT {
                    eprintln!(
                        "[GUI] Daemon unreachable ({}); closing the prompt client.",
                        reason
                    );
                    return None;
                }
            }
        }
        std::thread::sleep(POLL_TICK * IDLE_TICKS);
    }
}

impl PromptApp {
    /// `initial` is the request the Linux client opened this window for; macOS and Windows always
    /// pass `None` and let the poll in `logic()` find the first request.
    fn new(
        cc: &eframe::CreationContext<'_>,
        api: PromptApi,
        tray: bool,
        initial: Option<PendingPrompt>,
    ) -> Self {
        apply_theme(&cc.egui_ctx);
        // `logic()` polls for the next request, so at least one pass has to run while the window
        // is still hidden - without this first request eframe would sleep until someone typed.
        cc.egui_ctx.request_repaint();

        // Built here, in the app creator, because this closure already runs on the main thread
        // inside the event loop that the menu-bar / notification-area APIs require.
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        let tray = if tray {
            match TrayState::build(&api) {
                Some(state) => Some(state),
                None => {
                    eprintln!("[GUI] Could not create the tray icon; the prompt window keeps working.");
                    None
                }
            }
        } else {
            None
        };
        // Linux has no tray in this process (`--no-tray` travels here from the daemon, which owns
        // the ksni item), so there is nothing to build.
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        let _ = tray;

        let (tx, rx) = channel();
        // The daemon's log (this process inherits its stdout) then shows where the prompt window
        // is pointed, which is the first thing to check when no prompt ever appears.
        println!("[GUI] VrtFido prompt window ready on {}.", api.dashboard_url());
        let mut app = Self {
            api,
            tx,
            rx,
            prompt: None,
            pin: String::new(),
            setup_pin: String::new(),
            remember: false,
            account: None,
            status: Status::default(),
            busy: false,
            sensor_scan: false,
            enroll: None,
            last_tick: Instant::now() - POLL_TICK,
            idle_ticks: IDLE_TICKS,
            poll_in_flight: false,
            unreachable_polls: 0,
            quit: false,
            closing: false,
            // Nothing is on screen yet, and eframe shows every window after its first painted
            // frame: on macOS and Windows the first pass takes it off screen again (see
            // `sync_window`). On Linux the request this window was opened for is on the card.
            window_shown: false,
            hidden_assertions: HIDE_ASSERTIONS,
            focus_pin: false,
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            tray,
        };
        // The Linux client opens this window *because* a request is pending, so that request is on
        // the card from the first frame instead of one poll round trip later.
        if let Some(prompt) = initial {
            app.display_prompt(prompt);
        }
        app
    }

    /// Runs one daemon call on a worker thread.
    ///
    /// Every request is independent (the client holds no session state), so a thread per call
    /// keeps a 60 s sensor wait from blocking the polls, the tray menu and the repaints.
    fn spawn<F>(&self, call: F)
    where
        F: FnOnce(PromptApi) -> WorkerResult + Send + 'static,
    {
        let api = self.api.clone();
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(call(api));
        });
    }

    /// Applies everything the worker threads finished since the last pass.
    fn drain_results(&mut self) {
        while let Ok(result) = self.rx.try_recv() {
            match result {
                WorkerResult::Pending(answer) => {
                    self.poll_in_flight = false;
                    match answer {
                        Ok(Some(prompt)) => {
                            self.unreachable_polls = 0;
                            self.display_prompt(prompt);
                        }
                        Ok(None) => {
                            self.unreachable_polls = 0;
                            // Nothing pending: the window goes away again, and a hidden window
                            // only polls once per second from here on.
                            if self.prompt.is_some() || self.enroll.is_some() {
                                self.hide();
                            }
                        }
                        Err(reason) => {
                            self.unreachable_polls += 1;
                            if self.unreachable_polls >= UNREACHABLE_POLL_LIMIT {
                                eprintln!(
                                    "[GUI] Daemon unreachable ({}); closing the prompt window.",
                                    reason
                                );
                                self.quit = true;
                            }
                        }
                    }
                }
                WorkerResult::Approval { kind, result } => {
                    match kind {
                        ApprovalKind::Fingerprint => self.sensor_scan = false,
                        _ => self.busy = false,
                    }
                    match result {
                        // The daemon settled the request, so the card has done its job.
                        Ok(()) => self.settle(),
                        Err(e) => {
                            let message = match kind {
                                ApprovalKind::Pin => {
                                    // A rejected PIN is worth less than nothing when it is left
                                    // in the field, so the failed attempt is cleared with it.
                                    self.pin.clear();
                                    format!("❌ Authentication failed: {}", e)
                                }
                                ApprovalKind::Setup => format!("❌ Setup failed: {}", e),
                                ApprovalKind::Remembered => format!("❌ Approval error: {}", e),
                                ApprovalKind::Fingerprint => {
                                    format!("❌ Fingerprint scan: {}", e)
                                }
                            };
                            self.set_status(message, StatusKind::Error);
                        }
                    }
                }
                WorkerResult::Rejected(Err(e)) => {
                    // The window is hidden at this point, so this only belongs in the log.
                    eprintln!("[GUI] Reject request refused: {}", e);
                }
                WorkerResult::Rejected(Ok(())) => {}
                WorkerResult::Remember(Err(e)) => {
                    eprintln!("[GUI] Could not update the remember checkbox: {}", e);
                }
                WorkerResult::Remember(Ok(())) => {}
                WorkerResult::Select(Err(e)) => {
                    eprintln!("[GUI] Could not tell the daemon which account was picked: {}", e);
                }
                WorkerResult::Select(Ok(())) => {}
                WorkerResult::EnrollmentStarted(result) => {
                    if let Some(state) = self.enroll.as_mut() {
                        state.starting = false;
                        match result {
                            Ok(()) => {
                                state.running = true;
                                state.progress = None;
                                state.notice = None;
                                state.last_change = Instant::now();
                            }
                            Err(e) => {
                                state.notice = Some(EnrollmentNotice {
                                    text: format!("❌ {}", e),
                                    kind: StatusKind::Error,
                                })
                            }
                        }
                    }
                }
                WorkerResult::EnrollmentStatus(result) => {
                    self.apply_enrollment_status(result);
                }
                WorkerResult::EnrollmentCancelled(Err(e)) => {
                    eprintln!("[GUI] Could not cancel the fingerprint enrollment: {}", e);
                }
                WorkerResult::EnrollmentCancelled(Ok(())) => {}
            }
        }
    }

    /// Folds one `/enroll/status` answer into the panel.
    fn apply_enrollment_status(&mut self, result: Result<EnrollProgress, String>) {
        let Some(state) = self.enroll.as_mut() else {
            return;
        };
        state.status_in_flight = false;
        match result {
            Ok(progress) => {
                let changed = state
                    .progress
                    .as_ref()
                    .map(|old| {
                        old.stage != progress.stage
                            || old.status != progress.status
                            || old.message != progress.message
                    })
                    .unwrap_or(true);
                if changed {
                    state.last_change = Instant::now();
                }
                if !progress.active {
                    // The daemon reports "completed" or "error" and stops; the panel keeps that
                    // message visible for a moment instead of vanishing under the user's eyes.
                    state.running = false;
                    state.finished = true;
                    state.close_at = Some(Instant::now() + ENROLL_NOTICE_HOLD);
                }
                state.progress = Some(progress);
            }
            Err(e) => {
                // The sensor goes away mid-scan by being unplugged, which also kills the USB
                // link the daemon answers over: say so instead of polling into the void.
                state.notice = Some(EnrollmentNotice {
                    text: format!("⚠️ Lost contact with the sensor or the daemon: {}", e),
                    kind: StatusKind::Warning,
                });
            }
        }
    }

    /// The 200 ms tick: enrollment watchdog, enrollment poll, then the pending-request poll.
    fn tick(&mut self, ctx: &egui::Context) {
        if self.last_tick.elapsed() < POLL_TICK {
            return;
        }
        self.last_tick = Instant::now();

        self.watch_enrollment();
        self.poll_enrollment();

        // A hidden window polls at the idle cadence, a visible one every tick. Only macOS and
        // Windows own a hidden window; on Linux this window is up because a request is, and the
        // idle half runs in `run_ephemeral` without any window at all.
        if !self.window_shown {
            self.idle_ticks += 1;
            if self.idle_ticks < IDLE_TICKS {
                return;
            }
        }
        self.idle_ticks = 0;

        if !self.poll_in_flight {
            self.poll_in_flight = true;
            self.spawn(|api| WorkerResult::Pending(api.pending()));
        }
        let _ = ctx;
    }

    /// Gives up on an enrollment nobody continues, and closes a finished panel after its notice.
    fn watch_enrollment(&mut self) {
        let mut abandon = false;
        let mut close_panel = false;
        if let Some(state) = self.enroll.as_mut() {
            if state.running && !state.finished && state.last_change.elapsed() >= ENROLL_ABANDON {
                state.running = false;
                state.finished = true;
                state.notice = Some(EnrollmentNotice {
                    text: format!(
                        "✋ No touch for {}s — enrollment abandoned; the sensor may be away. Lift your finger and start again.",
                        ENROLL_ABANDON.as_secs()
                    ),
                    kind: StatusKind::Warning,
                });
                state.close_at = Some(Instant::now() + ENROLL_NOTICE_HOLD);
                abandon = true;
            }
            close_panel = state.close_at.map(|at| Instant::now() >= at).unwrap_or(false);
        }
        if close_panel {
            self.close_enrollment_panel();
            return;
        }
        if abandon {
            // Free the chip: the daemon would otherwise wait for its own 180 s deadline.
            self.spawn(|api| WorkerResult::EnrollmentCancelled(api.cancel_enrollment()));
        }
    }

    /// Follows a running enrollment every tick (the CMS polls at 250 ms).
    fn poll_enrollment(&mut self) {
        let follow = self
            .enroll
            .as_ref()
            .map(|state| state.running && !state.finished && !state.status_in_flight)
            .unwrap_or(false);
        if !follow {
            return;
        }
        if let Some(state) = self.enroll.as_mut() {
            state.status_in_flight = true;
        }
        self.spawn(|api| WorkerResult::EnrollmentStatus(api.enrollment_status()));
    }

    /// Shows a (new or updated) request.
    fn display_prompt(&mut self, prompt: PendingPrompt) {
        let is_new = self
            .prompt
            .as_ref()
            .map(|current| current.request_id != prompt.request_id)
            .unwrap_or(true);

        if is_new {
            // A new request starts from a clean card: no leftover PIN, no leftover status, and
            // the enrollment panel belongs to the request that opened it.
            self.pin.clear();
            self.setup_pin.clear();
            self.status = Status::default();
            self.enroll = None;
            self.focus_pin = true;
            self.remember = prompt.remember_requested;
            self.account = prompt
                .selected_credential_id
                .clone()
                .or_else(|| prompt.accounts.first().map(|account| account.id.clone()));
        } else {
            // Same request, newer answer: only the two fields the daemon owns are re-synced, so a
            // reloaded or second client shows the same tick and the same account.
            if self.remember != prompt.remember_requested {
                self.remember = prompt.remember_requested;
            }
            if let Some(selected) = &prompt.selected_credential_id {
                if self.account.as_deref() != Some(selected.as_str()) {
                    self.account = Some(selected.clone());
                }
            }
        }

        self.prompt = Some(prompt);
    }

    /// Drops the request on screen. Nothing is sent to the daemon here: the callers either
    /// settled the request already or deliberately leave it pending. The window itself leaves the
    /// screen in [`PromptApp::sync_window`] on the same pass - hidden on macOS and Windows, closed
    /// on Linux, where a window cannot be hidden.
    fn hide(&mut self) {
        self.prompt = None;
        self.pin.clear();
        self.setup_pin.clear();
        self.status = Status::default();
        self.enroll = None;
        // A transition to hidden, so the hide has to be asserted again (see `sync_window`).
        self.hidden_assertions = HIDE_ASSERTIONS;
    }

    /// Hides the window after a successful approval. The fields are cleared first, so the next
    /// prompt cannot show a stale PIN.
    fn settle(&mut self) {
        self.pin.clear();
        self.setup_pin.clear();
        self.status = Status::default();
        self.hide();
    }

    /// Puts the window on screen exactly while a request (or its enrollment panel) is displayed.
    ///
    /// This is not a plain show/hide, because eframe shows every window itself once it painted
    /// its first frame (`EpiIntegration::post_rendering`), whatever the `ViewportBuilder` asked
    /// for - so a hidden window has to be hidden *again* after that paint. `hidden_assertions`
    /// counts how many hide commands are still owed after a transition to hidden, and the pass
    /// that still owes one asks for an immediate repaint, which makes the wrong frame too short
    /// to be seen.
    ///
    /// On Linux the same pass closes the window instead: Wayland ignores the hiding command, so
    /// the card leaves the screen by ceasing to exist, and `run_ephemeral` opens the next one.
    fn sync_window(&mut self, ctx: &egui::Context) {
        if self.prompt.is_some() || self.enroll.is_some() {
            self.hidden_assertions = 0;
            if !self.window_shown {
                self.window_shown = true;
                ctx.send_viewport_cmd(ViewportCommand::Visible(true));
                // The prompt has to be in front of the browser the user is staring at.
                ctx.send_viewport_cmd(ViewportCommand::Minimized(false));
                ctx.send_viewport_cmd(ViewportCommand::Focus);
                ctx.send_viewport_cmd(ViewportCommand::WindowLevel(egui::WindowLevel::AlwaysOnTop));
            }
            return;
        }

        self.window_shown = false;
        if self.hidden_assertions > 0 {
            self.hidden_assertions -= 1;
            ctx.send_viewport_cmd(ViewportCommand::Visible(false));
            // Wayland ignores that command, so the card leaves the screen by ceasing to exist
            // here: `closing` marks the close as ours, which `logic()` needs to let it through.
            #[cfg(not(any(target_os = "macos", target_os = "windows")))]
            {
                self.closing = true;
                ctx.send_viewport_cmd(ViewportCommand::Close);
            }
            if self.hidden_assertions > 0 {
                ctx.request_repaint();
            }
        }
    }

    fn set_status(&mut self, text: impl Into<String>, kind: StatusKind) {
        self.status = Status {
            text: text.into(),
            kind,
        };
    }

    /// Rejects the request on screen (when there is one) and hides the window.
    fn dismiss(&mut self, reason: &'static str) {
        if let Some(prompt) = &self.prompt {
            let request_id = prompt.request_id;
            self.spawn(move |api| WorkerResult::Rejected(api.reject_pending(request_id, reason)));
        }
        self.hide();
    }

    /// Approves the request on screen. The PIN variants validate the field first, so a half-typed
    /// code never reaches the daemon (which answers an invalid one with a hard error).
    fn approve(&mut self, kind: ApprovalKind) {
        let Some(prompt) = &self.prompt else {
            return;
        };
        let request_id = prompt.request_id;
        let credential_id = self.account.clone();
        let remember = self.remember;

        let pin = match kind {
            ApprovalKind::Pin => match checked_pin(&self.pin) {
                Some(pin) => Some(pin),
                None => {
                    self.set_status("⚠️ PIN must be exactly 6 digits!", StatusKind::Error);
                    return;
                }
            },
            ApprovalKind::Setup => match checked_pin(&self.setup_pin) {
                Some(pin) => Some(pin),
                None => {
                    self.set_status(
                        "⚠️ Activation PIN must be exactly 6 digits!",
                        StatusKind::Error,
                    );
                    return;
                }
            },
            ApprovalKind::Remembered | ApprovalKind::Fingerprint => None,
        };

        match kind {
            ApprovalKind::Fingerprint => {
                if self.sensor_scan {
                    return;
                }
                self.sensor_scan = true;
                self.set_status(
                    "🖐️ Scanning sensor... Please touch USB fingerprint sensor now!",
                    StatusKind::Info,
                );
            }
            _ => {
                if self.busy {
                    return;
                }
                self.busy = true;
            }
        }

        let method = kind.method();
        self.spawn(move |api| WorkerResult::Approval {
            kind,
            result: api.approve_pending(request_id, method, pin.as_deref(), credential_id, Some(remember)),
        });
    }

    /// Tells the daemon which of the offered accounts is being verified.
    fn select_account(&mut self, credential_id: String) {
        let Some(prompt) = &self.prompt else {
            return;
        };
        let request_id = prompt.request_id;
        self.account = Some(credential_id.clone());
        self.spawn(move |api| WorkerResult::Select(api.select_account(request_id, &credential_id)));
    }

    fn open_enrollment(&mut self) {
        self.enroll = Some(EnrollmentState::new());
    }

    fn start_enrollment(&mut self) {
        let Some(state) = self.enroll.as_mut() else {
            return;
        };
        if state.starting || state.running {
            return;
        }
        let name = state.name.trim().to_string();
        if name.is_empty() {
            state.notice = Some(EnrollmentNotice {
                text: "⚠️ Please enter a name for the fingerprint!".into(),
                kind: StatusKind::Warning,
            });
            return;
        }
        state.starting = true;
        state.notice = None;
        self.spawn(move |api| WorkerResult::EnrollmentStarted(api.start_enrollment(&name)));
    }

    /// Closes the enrollment panel without touching the request on screen.
    fn close_enrollment_panel(&mut self) {
        self.enroll = None;
        // The panel may have been the last thing on screen, so the hide has to be asserted again.
        self.hidden_assertions = HIDE_ASSERTIONS;
    }

    /// Closes the enrollment panel, stopping the scan on the daemon when one is running.
    fn cancel_enrollment(&mut self) {
        let running = self
            .enroll
            .as_ref()
            .map(|state| state.running || state.starting)
            .unwrap_or(false);
        self.close_enrollment_panel();
        if running {
            self.spawn(|api| WorkerResult::EnrollmentCancelled(api.cancel_enrollment()));
        }
    }

    fn apply_action(&mut self, action: UiAction) {
        match action {
            UiAction::Approve(kind) => self.approve(kind),
            UiAction::Reject(reason) => self.dismiss(reason),
            UiAction::Remember(enabled) => {
                self.remember = enabled;
                self.spawn(move |api| WorkerResult::Remember(api.set_remember_requested(enabled)));
            }
            UiAction::SelectAccount(credential_id) => self.select_account(credential_id),
            UiAction::OpenEnrollment => self.open_enrollment(),
            UiAction::StartEnrollment => self.start_enrollment(),
            UiAction::CancelEnrollment => self.cancel_enrollment(),
        }
    }

    /// The three views of the card: setup (no PIN yet), verify, and "already verified in this app
    /// run" - the same split the CMS modal uses.
    fn draw_prompt(
        &mut self,
        ui: &mut egui::Ui,
        prompt: &PendingPrompt,
        action: &mut Option<UiAction>,
    ) {
        ui.vertical_centered(|ui| {
            ui.label(RichText::new("🛡️").size(34.0));
            ui.label(
                RichText::new("WebAuthn Verification Request")
                    .size(17.0)
                    .strong()
                    .color(Palette::ACCENT),
            );
            // The operation is the CMS modal's title; here it sits under the fixed heading.
            ui.label(
                RichText::new(operation_label(&prompt.operation))
                    .size(14.0)
                    .strong()
                    .color(Palette::TEXT),
            );
            ui.label(
                RichText::new("A website is requesting your security key:")
                    .size(12.0)
                    .color(Palette::MUTED),
            );
            rp_badge(ui, &prompt.rp_id);

            let left = seconds_left(prompt);
            ui.label(
                RichText::new(format!("⏳ Expires in {}s", left))
                    .size(11.0)
                    .color(if left <= 10 { Palette::WARNING } else { Palette::MUTED }),
            );
        });

        ui.add_space(2.0);

        // Several accounts from the same RP: the user has to say which one this login is for,
        // and the daemon forwards the choice to the WebAuthn response.
        if prompt.accounts.len() > 1 {
            egui::Frame::new()
                .fill(Palette::PANEL)
                .stroke(Stroke::new(1.0, Palette::BORDER))
                .corner_radius(CornerRadius::same(8))
                .inner_margin(Margin::symmetric(12, 8))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(
                        RichText::new("👤 Select Account to Authenticate:")
                            .size(11.0)
                            .strong()
                            .color(Palette::ACCENT),
                    );
                    let selected = prompt
                        .accounts
                        .iter()
                        .find(|account| self.account.as_deref() == Some(account.id.as_str()))
                        .map(account_label)
                        .unwrap_or_default();
                    egui::ComboBox::from_id_salt("prompt-account")
                        .width(ui.available_width())
                        .selected_text(RichText::new(selected).color(Palette::TEXT))
                        .show_ui(ui, |ui| {
                            for account in &prompt.accounts {
                                let picked = self.account.as_deref() == Some(account.id.as_str());
                                if ui
                                    .selectable_label(picked, account_label(account))
                                    .clicked()
                                {
                                    *action = Some(UiAction::SelectAccount(account.id.clone()));
                                }
                            }
                        });
                    ui.label(
                        RichText::new("Defaulted to latest used/added account.")
                            .size(10.0)
                            .color(Palette::MUTED),
                    );
                });
        } else if !prompt.user_name.is_empty() {
            ui.vertical_centered(|ui| {
                ui.label(
                    RichText::new(format!("Account: {}", prompt.user_name))
                        .size(12.0)
                        .color(Palette::MUTED),
                );
            });
        }

        // The remembered view needs no checkbox: the run is verified already.
        if !prompt.session_remembered {
            let before = self.remember;
            ui.checkbox(
                &mut self.remember,
                RichText::new("🔓 Remember for this app run — later requests skip PIN / fingerprint")
                    .size(11.0)
                    .color(Palette::MUTED),
            );
            if self.remember != before {
                *action = Some(UiAction::Remember(self.remember));
            }
        }

        ui.add_space(2.0);

        if prompt.session_remembered {
            ui.label(
                RichText::new(
                    "🔓 This app run is already verified — click Approve to confirm (no PIN or sensor needed).",
                )
                .size(12.0)
                .color(Palette::SUCCESS),
            );
            centered_row(ui, &[BTN_APPROVE, BTN_REJECT], |ui| {
                if css_button(ui, BTN_APPROVE, ButtonKind::Primary).clicked() {
                    *action = Some(UiAction::Approve(ApprovalKind::Remembered));
                }
                if css_button(ui, BTN_REJECT, ButtonKind::Danger).clicked() {
                    *action = Some(UiAction::Reject(REJECT_REASON));
                }
            });
        } else if !prompt.is_security_setup {
            // First run: the daemon has neither PIN nor fingerprint, so this request is also the
            // moment to create the 6-digit PIN that will guard the next ones.
            ui.label(
                RichText::new(
                    "⚠️ Security is not configured. Please create a 6-digit PIN to activate:",
                )
                .size(12.0)
                .color(Palette::WARNING),
            );
            let entered = pin_field(ui, "setup-pin", &mut self.setup_pin, "Enter 6 digits");
            if entered && !self.busy {
                *action = Some(UiAction::Approve(ApprovalKind::Setup));
            }
            centered_row(ui, &[BTN_ACTIVATE, BTN_REJECT_SHORT], |ui| {
                if css_button(ui, BTN_ACTIVATE, ButtonKind::Primary).clicked() {
                    *action = Some(UiAction::Approve(ApprovalKind::Setup));
                }
                if css_button(ui, BTN_REJECT_SHORT, ButtonKind::Danger).clicked() {
                    *action = Some(UiAction::Reject(REJECT_REASON));
                }
            });
        } else {
            ui.label(
                RichText::new("💡 Touch the USB fingerprint sensor now or enter your PIN:")
                    .size(12.0)
                    .color(Palette::ACCENT),
            );
            let entered = pin_field(ui, "verify-pin", &mut self.pin, "Enter 6-digit PIN");
            if entered && !self.busy {
                *action = Some(UiAction::Approve(ApprovalKind::Pin));
            }
            centered_row(ui, &[BTN_VERIFY_PIN, BTN_SENSOR, BTN_REJECT], |ui| {
                if css_button(ui, BTN_VERIFY_PIN, ButtonKind::Primary).clicked() {
                    *action = Some(UiAction::Approve(ApprovalKind::Pin));
                }
                // The sensor button owns the chip until the daemon answers, so it is the one
                // control that goes insensitive during its own scan.
                let sensor = ui.add_enabled_ui(!self.sensor_scan, |ui| {
                    css_button(ui, BTN_SENSOR, ButtonKind::Secondary)
                });
                if sensor.inner.clicked() {
                    *action = Some(UiAction::Approve(ApprovalKind::Fingerprint));
                }
                if css_button(ui, BTN_REJECT, ButtonKind::Danger).clicked() {
                    *action = Some(UiAction::Reject(REJECT_REASON));
                }
            });

            // Enrolling a new finger is part of keeping this key usable, and the daemon drives
            // the six stages itself; the panel below only shows them.
            ui.add_space(2.0);
            let sensor_ready = prompt.hardware_sensor_available;
            centered_row(ui, &[BTN_ADD_FINGERPRINT], |ui| {
                let button = ui.add_enabled_ui(sensor_ready, |ui| {
                    css_button(ui, BTN_ADD_FINGERPRINT, ButtonKind::Secondary)
                });
                if button.inner.clicked() {
                    *action = Some(UiAction::OpenEnrollment);
                }
            });
            if !sensor_ready {
                ui.vertical_centered(|ui| {
                    ui.label(
                        RichText::new(
                            "⚠️ USB fingerprint sensor (3274:8012) is not connected — plug it in and retry",
                        )
                        .size(10.0)
                        .color(Palette::WARNING),
                    );
                });
            }
        }

        if !self.status.text.is_empty() {
            ui.add_space(2.0);
            ui.label(
                RichText::new(&self.status.text)
                    .size(11.0)
                    .strong()
                    .color(self.status.kind.color()),
            );
        }
    }

    /// The 6-stage enrollment panel, the local twin of the CMS's `enrollModal`.
    fn draw_enrollment(&mut self, ui: &mut egui::Ui, action: &mut Option<UiAction>) {
        // The icon reflects the daemon's stage: a finger has to be lifted between two presses,
        // and the chip cannot sample the same press twice.
        let icon = match self.enroll.as_ref().and_then(|state| state.progress.as_ref()) {
            Some(progress) if progress.status == "finger_lift" => "👆",
            Some(progress) if progress.status == "completed" => "✅",
            Some(progress) if progress.status == "error" => "❌",
            _ => "🖐️",
        };

        ui.vertical_centered(|ui| {
            ui.label(RichText::new(icon).size(34.0));
            ui.label(
                RichText::new("Scanning USB Fingerprint")
                    .size(17.0)
                    .strong()
                    .color(Palette::ACCENT),
            );
        });

        // Before the scan starts the label has to be typed; the daemon refuses an empty one.
        let idle = self
            .enroll
            .as_ref()
            .map(|state| !state.running && !state.starting)
            .unwrap_or(false);
        if idle {
            let state = self.enroll.as_mut().expect("checked above");
            let response = ui.add(
                egui::TextEdit::singleline(&mut state.name)
                    .id(egui::Id::new("enroll-name"))
                    .hint_text("Label (e.g. Right Index, Left Thumb...)")
                    .text_color(Palette::TEXT)
                    .desired_width(f32::INFINITY)
                    .frame(input_frame())
                    .margin(Margin::symmetric(10, 6)),
            );
            let entered = response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            centered_row(ui, &[BTN_ADD_FINGERPRINT, BTN_CANCEL], |ui| {
                if css_button(ui, BTN_ADD_FINGERPRINT, ButtonKind::Primary).clicked() || entered {
                    *action = Some(UiAction::StartEnrollment);
                }
                if css_button(ui, BTN_CANCEL, ButtonKind::Danger).clicked() {
                    *action = Some(UiAction::CancelEnrollment);
                }
            });
        } else {
            // A running scan: stage counter, bar and whatever the daemon is asking for - "place
            // finger", "lift finger", "image unclear, press again".
            let (stage, total, message, message_kind) = {
                let state = self.enroll.as_ref().expect("checked above");
                match state.progress.as_ref() {
                    Some(progress) => (
                        progress.stage,
                        progress.total_stages,
                        progress.message.clone(),
                        match progress.status.as_str() {
                            "completed" => StatusKind::Success,
                            "error" => StatusKind::Error,
                            _ => StatusKind::Info,
                        },
                    ),
                    None => (
                        0,
                        6,
                        "Connecting to the USB sensor...".to_string(),
                        StatusKind::Info,
                    ),
                }
            };
            ui.vertical_centered(|ui| {
                ui.label(
                    RichText::new(format!("Stage {} / {}", stage, total))
                        .size(14.0)
                        .strong()
                        .color(Palette::ACCENT),
                );
            });
            let fraction = if total == 0 {
                0.0
            } else {
                (stage as f32 / total as f32).clamp(0.0, 1.0)
            };
            ui.add(
                egui::ProgressBar::new(fraction)
                    .desired_width(ui.available_width())
                    .fill(Palette::ACCENT),
            );
            ui.label(
                RichText::new(message)
                    .size(12.0)
                    .color(message_kind.color()),
            );

            let done = self
                .enroll
                .as_ref()
                .map(|state| state.finished)
                .unwrap_or(false);
            if !done {
                ui.label(
                    RichText::new(
                        "Every one of the 6 stages needs its own press — lift your finger between them.",
                    )
                    .size(10.0)
                    .color(Palette::MUTED),
                );
            }
            centered_row(ui, &[BTN_CANCEL], |ui| {
                if css_button(ui, BTN_CANCEL, ButtonKind::Danger).clicked() {
                    *action = Some(UiAction::CancelEnrollment);
                }
            });
        }

        if let Some(notice) = self.enroll.as_ref().and_then(|state| state.notice.as_ref()) {
            ui.label(
                RichText::new(&notice.text)
                    .size(11.0)
                    .strong()
                    .color(notice.kind.color()),
            );
        }
        if let Some(error) = self
            .enroll
            .as_ref()
            .and_then(|state| state.progress.as_ref())
            .and_then(|progress| progress.error.as_deref())
        {
            ui.label(RichText::new(error).size(11.0).strong().color(Palette::DANGER));
        }
    }
}

impl eframe::App for PromptApp {
    /// Runs for a visible *and* a hidden window, which is what keeps the daemon polled for the
    /// next request while the card is away.
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Keep the tick coming: eframe may run no ui pass at all for an invisible window, so the
        // next poll has to be scheduled from here.
        ctx.request_repaint_after(POLL_TICK);

        // Menu clicks arrive on the muda channel; draining them here (rather than in `ui`) means
        // the tray stays responsive while the window is hidden, which is its normal state. The
        // repaint timer above is what makes that drain happen at all.
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            if let Some(tray) = self.tray.as_mut() {
                tray.drain_menu();
            }
        }

        self.drain_results();
        self.sync_window(ctx);
        self.tick(ctx);

        // The window manager's "X" has to dismiss the request, not stop the client: the daemon
        // keeps this process for the next prompt, and on macOS and Windows the tray item lives
        // here. A close this client asked for itself (`closing`) goes through untouched.
        if ctx.input(|i| i.viewport().close_requested()) && !self.closing {
            ctx.send_viewport_cmd(ViewportCommand::CancelClose);
            // An enrollment in progress owns the sensor, so it is stopped before the card goes.
            self.cancel_enrollment();
            self.dismiss(CLOSE_REASON);
        }

        if self.quit {
            self.closing = true;
            ctx.send_viewport_cmd(ViewportCommand::Close);
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let mut action: Option<UiAction> = None;

        egui::Frame::central_panel(&ui.style())
            .fill(Palette::BG)
            .inner_margin(Margin::same(CARD_OUTER_MARGIN))
            .show(ui, |ui| {
                egui::Frame::new()
                    .fill(Palette::CARD)
                    .stroke(Stroke::new(2.0, Palette::ACCENT))
                    .corner_radius(CornerRadius::same(14))
                    .inner_margin(Margin::same(CARD_INNER_MARGIN))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.spacing_mut().item_spacing = Vec2::new(8.0, 8.0);
                        egui::ScrollArea::vertical()
                            .auto_shrink([false; 2])
                            .show(ui, |ui| {
                                ui.set_width(
                                    (ui.available_width() - SCROLL_BAR_RESERVE).max(0.0),
                                );
                                // Taken out of the app so the drawing code holds no borrow of
                                // `self.prompt` while the fields beside it are edited.
                                if self.enroll.is_some() {
                                    self.draw_enrollment(ui, &mut action);
                                } else if let Some(prompt) = self.prompt.take() {
                                    self.draw_prompt(ui, &prompt, &mut action);
                                    self.prompt = Some(prompt);
                                }
                            });
                    });
            });

        // Focus the PIN field of a freshly arrived request, like `grab_focus` did.
        if self.focus_pin && self.enroll.is_none() && self.prompt.is_some() {
            let id = egui::Id::new("verify-pin");
            let wanted = if self.prompt.as_ref().map(|prompt| prompt.is_security_setup).unwrap_or(false) {
                id
            } else {
                egui::Id::new("setup-pin")
            };
            ui.memory_mut(|memory| memory.request_focus(wanted));
            self.focus_pin = false;
        }

        if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
            // Escape closes the enrollment panel first; rejecting the WebAuthn request from
            // inside it would be a surprise.
            if self.enroll.is_some() {
                action = Some(UiAction::CancelEnrollment);
            } else if self.prompt.is_some() {
                action = Some(UiAction::Reject(ESCAPE_REASON));
            }
        }

        if let Some(action) = action {
            self.apply_action(action);
        }
    }
}

/// The palette as egui visuals, so widgets that are not drawn by hand (checkbox, combo box, text
/// fields, scroll bar) look like the rest of the card.
fn apply_theme(ctx: &egui::Context) {
    // The card is dark whatever the desktop theme prefers: the palette is the CMS one, and the
    // mode is pinned so a light system theme cannot repaint half the widgets.
    ctx.set_theme(egui::ThemePreference::Dark);

    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = Palette::BG;
    visuals.window_fill = Palette::CARD;
    visuals.window_stroke = Stroke::new(1.0, Palette::BORDER);
    visuals.extreme_bg_color = Palette::PANEL;
    visuals.selection.bg_fill = Palette::ACCENT;
    visuals.selection.stroke = Stroke::new(1.0, Palette::ON_ACCENT);
    // Widget text takes its colour from the per-state `fg_stroke`; every label that needs one of
    // the muted/warning/success colours sets it explicitly instead.
    visuals.widgets.noninteractive.fg_stroke.color = Palette::TEXT;
    visuals.widgets.inactive.fg_stroke.color = Palette::TEXT;
    visuals.widgets.hovered.fg_stroke.color = Palette::TEXT;
    visuals.widgets.active.fg_stroke.color = Palette::TEXT;
    visuals.widgets.inactive.corner_radius = CornerRadius::same(8);
    visuals.widgets.hovered.corner_radius = CornerRadius::same(8);
    visuals.widgets.active.corner_radius = CornerRadius::same(8);
    ctx.set_visuals_of(egui::Theme::Dark, visuals);

    ctx.all_styles_mut(|style| {
        style.spacing.item_spacing = Vec2::new(8.0, 8.0);
        style.spacing.button_padding = Vec2::new(14.0, 8.0);
        style.spacing.interact_size.y = 30.0;
    });
}

/// The three button flavours of the CMS stylesheet.
#[derive(Clone, Copy)]
enum ButtonKind {
    Primary,
    Secondary,
    Danger,
}

impl ButtonKind {
    /// (fill, hover fill, text, hover text, border, hover border), straight from `.btn-*`.
    fn colors(self) -> (Color32, Color32, Color32, Color32, Color32, Color32) {
        match self {
            Self::Primary => (
                Palette::ACCENT,
                Palette::ACCENT_HOVER,
                Palette::ON_ACCENT,
                Palette::ON_ACCENT,
                Palette::ACCENT,
                Palette::ACCENT_HOVER,
            ),
            Self::Secondary => (
                Palette::BORDER,
                Palette::SECONDARY_BORDER,
                Palette::TEXT,
                Palette::TEXT,
                Palette::SECONDARY_BORDER,
                Palette::SECONDARY_BORDER,
            ),
            // `.btn-danger` is a translucent red plate that inverts to solid red on hover.
            Self::Danger => (
                Palette::DANGER_BG,
                Palette::DANGER,
                Palette::DANGER,
                Palette::WHITE,
                Palette::DANGER_BORDER,
                Palette::DANGER,
            ),
        }
    }
}

/// Draws one styled button.
///
/// egui takes a button's fill and text colour from the widget visuals of its *state*, so the
/// colours are pushed into a scoped style instead of being baked into the widget - that is what
/// gives the CSS `:hover` behaviour without hand-painting the button.
fn css_button(ui: &mut egui::Ui, text: &str, kind: ButtonKind) -> egui::Response {
    let (fill, hover_fill, text_color, hover_text, border, hover_border) = kind.colors();
    let response = ui.scope(|ui| {
        let widgets = &mut ui.style_mut().visuals.widgets;
        widgets.inactive.weak_bg_fill = fill;
        widgets.hovered.weak_bg_fill = hover_fill;
        widgets.active.weak_bg_fill = hover_fill;
        widgets.inactive.bg_stroke = Stroke::new(1.0, border);
        widgets.hovered.bg_stroke = Stroke::new(1.0, hover_border);
        widgets.active.bg_stroke = Stroke::new(1.0, hover_border);
        widgets.inactive.fg_stroke.color = text_color;
        widgets.hovered.fg_stroke.color = hover_text;
        widgets.active.fg_stroke.color = hover_text;
        ui.add(
            egui::Button::new(RichText::new(text).size(BUTTON_TEXT_SIZE).strong())
                .corner_radius(CornerRadius::same(8))
                .min_size(Vec2::new(0.0, 30.0)),
        )
    });
    response.inner
}

/// The label size of every button, in points: [`button_width`] and [`css_button`] must agree on it.
const BUTTON_TEXT_SIZE: f32 = 13.0;

/// Width one of the card's buttons takes: its label plus the horizontal padding [`css_button`]
/// leaves on both sides, measured with the fonts the button itself is drawn with.
fn button_width(ui: &egui::Ui, label: &str) -> f32 {
    let text = ui
        .painter()
        .layout_no_wrap(
            label.to_owned(),
            FontId::proportional(BUTTON_TEXT_SIZE),
            Palette::TEXT,
        )
        .size()
        .x;
    text.ceil() + 2.0 * ui.spacing().button_padding.x
}

/// Places a row of buttons on the card's centre line; `labels` are what the buttons added by `add`
/// will say, and they are measured with [`button_width`] to shift the row into place.
///
/// egui lays a horizontal row out from its left edge and ignores the main alignment (a row is
/// aligned by its parent only), so the shift is computed here. A row that cannot fit the card
/// wraps onto a second line instead of being cut off by the `ScrollArea`.
fn centered_row(ui: &mut egui::Ui, labels: &[&str], add: impl FnOnce(&mut egui::Ui)) {
    let spacing = ui.spacing().item_spacing.x;
    let content: f32 = labels.iter().map(|label| button_width(ui, label)).sum::<f32>()
        + spacing * labels.len().saturating_sub(1) as f32;

    if content > ui.available_width() {
        ui.with_layout(
            egui::Layout::left_to_right(Align::Center).with_main_wrap(true),
            add,
        );
        return;
    }

    let shift = ((ui.available_width() - content) * 0.5).max(0.0);
    ui.horizontal(|ui| {
        ui.add_space(shift);
        add(ui);
    });
}

/// The card's button labels: the drawing code and the row centring that measures them share these,
/// so a row can never be measured for a label it does not draw.
const BTN_APPROVE: &str = "✔️ Approve";
const BTN_VERIFY_PIN: &str = "🔑 Verify with PIN";
const BTN_SENSOR: &str = "🖐️ Touch USB Sensor";
const BTN_REJECT: &str = "❌ Reject Request";
const BTN_REJECT_SHORT: &str = "Reject";
const BTN_ACTIVATE: &str = "Activate & Approve";
const BTN_ADD_FINGERPRINT: &str = "➕ Add Fingerprint";
const BTN_CANCEL: &str = "❌ Cancel";

/// The framed box an input sits in: `.pin-entry` / the account box of the CMS.
fn input_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(Palette::PANEL)
        .stroke(Stroke::new(1.0, Palette::BORDER))
        .corner_radius(CornerRadius::same(8))
}

/// The 6-digit PIN field: masked, limited to six characters, centred.
///
/// Returns `true` when the user pressed Enter: the field submits, just like the button next to it.
fn pin_field(ui: &mut egui::Ui, id_salt: &str, value: &mut String, hint: &str) -> bool {
    let response = ui.add(
        egui::TextEdit::singleline(value)
            .id(egui::Id::new(id_salt))
            .password(true)
            .char_limit(6)
            .horizontal_align(Align::Center)
            .hint_text(hint)
            .font(FontId::proportional(18.0))
            .text_color(Palette::TEXT)
            .desired_width(160.0)
            .frame(input_frame())
            .margin(Margin::symmetric(10, 6)),
    );
    response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
}

/// The RP id plate under the heading (`.modal-rp-badge`).
fn rp_badge(ui: &mut egui::Ui, rp_id: &str) {
    ui.vertical_centered(|ui| {
        egui::Frame::new()
            .fill(Palette::PANEL)
            .stroke(Stroke::new(1.0, Palette::BORDER))
            .corner_radius(CornerRadius::same(8))
            .inner_margin(Margin::symmetric(14, 6))
            .show(ui, |ui| {
                ui.label(
                    RichText::new(rp_id)
                        .size(14.0)
                        .strong()
                        .color(Palette::TEXT),
                );
            });
    });
}

/// One account line: `Display Name (user)` when the RP sent both, else the bare user name.
fn account_label(account: &crate::security::PendingAccountOption) -> String {
    if !account.user_display_name.is_empty() && account.user_display_name != account.user_name {
        format!("{} ({})", account.user_display_name, account.user_name)
    } else {
        account.user_name.clone()
    }
}

/// The operation shown to the user, worded like the CMS modal.
fn operation_label(operation: &str) -> &'static str {
    if operation == "MakeCredential" {
        "Register New Passkey"
    } else {
        "Authenticate Sign-in"
    }
}

/// Seconds left before the daemon gives up on the request.
///
/// `created_at_secs` is the daemon's Unix timestamp, and this window runs on the same host, so
/// the two clocks cannot disagree.
fn seconds_left(prompt: &PendingPrompt) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0);
    let elapsed = now.saturating_sub(prompt.created_at_secs);
    prompt.timeout_seconds.saturating_sub(elapsed)
}

/// `Some(pin)` when the field holds exactly six digits, `None` otherwise.
fn checked_pin(pin: &str) -> Option<String> {
    let trimmed = pin.trim();
    if trimmed.len() == 6 && trimmed.chars().all(|c| c.is_ascii_digit()) {
        Some(trimmed.to_string())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------------------------
// Tray icon: macOS menu bar / Windows notification area
// ---------------------------------------------------------------------------------------------

/// The tray item and its menu.
///
/// Both platforms need the main thread and the event loop that the window already owns, which is
/// exactly why the icon lives in this process instead of the daemon. Linux has no tray here: the
/// daemon registers its own `ksni` item, so this type is not even compiled there.
#[cfg(any(target_os = "macos", target_os = "windows"))]
struct TrayState {
    /// Dropping this removes the icon, so it has to stay alive for the whole run.
    _icon: tray_icon::TrayIcon,
    /// Menu ids to match incoming clicks against.
    dashboard: tray_icon::menu::MenuId,
    autostart: tray_icon::menu::MenuId,
    quit: tray_icon::menu::MenuId,
    /// Kept to update the checkmark after a toggle.
    autostart_item: tray_icon::menu::CheckMenuItem,
    /// Where the Web CMS answers, for the "Dashboard" item.
    host: String,
    port: u16,
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl TrayState {
    /// The icon shipped next to the binaries in every release archive.
    const ICON_PNG: &'static [u8] = include_bytes!("../extension/icons/icon-32.png");

    /// Builds the tray item. Returns `None` (with the caller logging it) when the platform
    /// refuses the icon - a missing tray must not take the prompt window down with it.
    fn build(api: &PromptApi) -> Option<Self> {
        use tray_icon::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};

        let menu = Menu::new();
        let dashboard = MenuItem::new("Dashboard", true, None);
        // The checkmark reports the real state of the startup entry, so the menu never lies
        // after the entry was changed elsewhere.
        let autostart = CheckMenuItem::new(
            "Start with the system",
            true,
            crate::autostart::is_autostart_enabled(),
            None,
        );
        let quit = MenuItem::new("Quit", true, None);
        let separator = PredefinedMenuItem::separator();
        let items: [&dyn tray_icon::menu::IsMenuItem; 4] = [&dashboard, &autostart, &separator, &quit];
        if let Err(e) = menu.append_items(&items) {
            eprintln!("[GUI] Could not build the tray menu: {}", e);
            return None;
        }

        // `tray_icon::Icon` wants raw RGBA, so the PNG is decoded once here.
        let image = image::load_from_memory(Self::ICON_PNG).ok()?.into_rgba8();
        let (width, height) = image.dimensions();
        let icon = tray_icon::Icon::from_rgba(image.into_raw(), width, height).ok()?;

        let tray = tray_icon::TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_icon(icon)
            .with_tooltip("VrtFido")
            // On Windows the window is hidden most of the time, so the menu is the only way to
            // reach the daemon; macOS shows it on a left click by default.
            .with_menu_on_left_click(true)
            .build()
            .ok()?;

        let dashboard_id = dashboard.id().clone();
        let autostart_id = autostart.id().clone();
        let quit_id = quit.id().clone();
        Some(Self {
            _icon: tray,
            dashboard: dashboard_id,
            autostart: autostart_id,
            quit: quit_id,
            autostart_item: autostart,
            host: api.host.clone(),
            port: api.port,
        })
    }

    /// Handles every menu click queued since the last pass.
    fn drain_menu(&mut self) {
        while let Ok(event) = tray_icon::menu::MenuEvent::receiver().try_recv() {
            if event.id == self.dashboard {
                let url = format!("http://{}:{}", self.host, self.port);
                if let Err(e) = open::that(&url) {
                    eprintln!("[GUI] Could not open {} in a browser: {}", url, e);
                }
            } else if event.id == self.autostart {
                let enable = !crate::autostart::is_autostart_enabled();
                match crate::autostart::set_autostart_enabled(enable) {
                    Ok(()) => self.autostart_item.set_checked(enable),
                    Err(e) => {
                        eprintln!(
                            "[GUI] Could not {} start with the system: {}",
                            if enable { "enable" } else { "disable" },
                            e
                        );
                        // Re-read the real state so the checkmark never drifts from the entry.
                        self.autostart_item.set_checked(crate::autostart::is_autostart_enabled());
                    }
                }
            } else if event.id == self.quit {
                quit_vrtfido();
            }
        }
    }
}

/// Stops the daemon through its pid file and ends this client.
///
/// The window is a child of the daemon: once the daemon is gone there is nothing left to prompt
/// for, so the client exits too (`main.rs` reaps it either way).
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn quit_vrtfido() -> ! {
    let pid_file = std::env::temp_dir().join("vrtfido.pid");
    if let Ok(text) = std::fs::read_to_string(&pid_file) {
        if let Ok(pid) = text.trim().parse::<u32>() {
            if crate::platform::process_alive(pid) {
                crate::platform::terminate(pid);
            }
        }
    }
    // The daemon removes the file on its own shutdown path; this covers a daemon that was killed
    // before it could.
    let _ = std::fs::remove_file(&pid_file);
    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::PendingAccountOption;

    fn account(user_name: &str, display_name: &str) -> PendingAccountOption {
        PendingAccountOption {
            id: format!("cred-{}", user_name),
            user_name: user_name.to_string(),
            user_display_name: display_name.to_string(),
            last_used_at: String::new(),
            created_at: String::new(),
        }
    }

    #[test]
    fn account_labels_prefer_the_display_name() {
        assert_eq!(account_label(&account("alice", "Alice A.")), "Alice A. (alice)");
        // A display name equal to the user name would only repeat itself.
        assert_eq!(account_label(&account("alice", "alice")), "alice");
        assert_eq!(account_label(&account("alice", "")), "alice");
    }

    #[test]
    fn pins_are_exactly_six_digits() {
        assert_eq!(checked_pin(" 123456 "), Some("123456".to_string()));
        assert_eq!(checked_pin("12345"), None);
        assert_eq!(checked_pin("1234567"), None);
        assert_eq!(checked_pin("12345a"), None);
        assert_eq!(checked_pin(""), None);
    }

    #[test]
    fn operations_are_worded_like_the_cms() {
        assert_eq!(operation_label("MakeCredential"), "Register New Passkey");
        assert_eq!(operation_label("GetAssertion"), "Authenticate Sign-in");
    }

    /// The three buttons of the verify view are the widest row on the card. They have to stay
    /// inside the card's content width - the row used to be cut off at the right edge, because the
    /// card's padding left it less room than the buttons need - and sit on the card's centre line.
    #[test]
    fn the_verify_action_row_fits_the_card_and_is_centred() {
        let ctx = egui::Context::default();
        let width = card_content_width();
        let mut rects: Vec<egui::Rect> = Vec::new();

        let _ = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(width, 400.0),
                )),
                ..Default::default()
            },
            |ui| {
                ui.set_max_width(width);
                centered_row(ui, &[BTN_VERIFY_PIN, BTN_SENSOR, BTN_REJECT], |ui| {
                    rects.push(css_button(ui, BTN_VERIFY_PIN, ButtonKind::Primary).rect);
                    rects.push(css_button(ui, BTN_SENSOR, ButtonKind::Secondary).rect);
                    rects.push(css_button(ui, BTN_REJECT, ButtonKind::Danger).rect);
                });
            },
        );

        assert_eq!(rects.len(), 3);
        // One line: a row that wrapped would mean the buttons no longer fit side by side.
        assert!(
            rects.windows(2).all(|pair| pair[0].min.y == pair[1].min.y),
            "the row wrapped: {rects:?}"
        );
        let left = rects.iter().map(|r| r.min.x).fold(f32::INFINITY, f32::min);
        let right = width - rects.iter().map(|r| r.max.x).fold(0.0, f32::max);
        assert!(left >= -0.5 && right >= -0.5, "the row is cut off: {rects:?}");
        // Centred: the slack is split evenly instead of landing all on the right.
        assert!((left - right).abs() <= 1.5, "left={left} right={right}");
    }

    /// The window is resizable, so the row has to survive a card much narrower than the default:
    /// wrapped onto two lines, still inside the width it was given.
    #[test]
    fn a_narrow_card_wraps_the_verify_row() {
        let ctx = egui::Context::default();
        let width = MIN_WINDOW_WIDTH - 2.0 * f32::from(CARD_OUTER_MARGIN + 2 + CARD_INNER_MARGIN)
            - SCROLL_BAR_RESERVE;
        let mut rects: Vec<egui::Rect> = Vec::new();

        let _ = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(width, 400.0),
                )),
                ..Default::default()
            },
            |ui| {
                ui.set_max_width(width);
                centered_row(ui, &[BTN_VERIFY_PIN, BTN_SENSOR, BTN_REJECT], |ui| {
                    rects.push(css_button(ui, BTN_VERIFY_PIN, ButtonKind::Primary).rect);
                    rects.push(css_button(ui, BTN_SENSOR, ButtonKind::Secondary).rect);
                    rects.push(css_button(ui, BTN_REJECT, ButtonKind::Danger).rect);
                });
            },
        );

        assert_eq!(rects.len(), 3);
        assert!(
            rects.iter().all(|r| r.min.x >= -0.5 && r.max.x <= width + 0.5),
            "a button sticks out of the card: {rects:?}"
        );
        assert!(
            rects.windows(2).any(|pair| pair[0].min.y != pair[1].min.y),
            "the row did not wrap in a narrow card: {rects:?}"
        );
    }

    #[test]
    fn the_palette_carries_the_cms_colors() {
        assert_eq!(Palette::ACCENT, Color32::from_rgb(0x38, 0xbd, 0xf8));
        assert_eq!(Palette::BG, Color32::from_rgb(0x0f, 0x17, 0x2a));
        assert_eq!(Palette::DANGER, Color32::from_rgb(0xef, 0x44, 0x44));
    }
}
