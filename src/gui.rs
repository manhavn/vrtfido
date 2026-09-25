use crate::security::{PendingPrompt, PromptEvent, SecurityEngine};
use gtk::prelude::*;
use gtk::{gdk, glib};
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const GUI_CSS: &str = r#"
window.vrtfido-modal {
    background-color: #0f172a;
    color: #f8fafc;
}

.modal-card {
    background-color: #182234;
    border: 2px solid #38bdf8;
    border-radius: 14px;
    padding: 22px;
}

.modal-icon {
    font-size: 36px;
}

.modal-title {
    font-size: 17px;
    font-weight: 800;
    color: #38bdf8;
}

.modal-subtitle {
    font-size: 12px;
    color: #94a3b8;
}

.modal-rp-badge {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 6px 14px;
    font-size: 14px;
    font-weight: 700;
    color: #f8fafc;
}

.account-box {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 8px 12px;
}

.account-label {
    font-size: 11px;
    font-weight: 700;
    color: #38bdf8;
}

.account-note {
    font-size: 10px;
    color: #94a3b8;
}

.pin-entry {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 8px;
    color: #f8fafc;
    font-size: 18px;
    letter-spacing: 6px;
    padding: 6px 10px;
}

.pin-entry:focus {
    border-color: #38bdf8;
}

.btn-primary {
    background-color: #38bdf8;
    color: #020617;
    font-weight: 700;
    font-size: 12px;
    border-radius: 8px;
    padding: 8px 14px;
    border: 1px solid #38bdf8;
}

.btn-primary:hover {
    background-color: #0ea5e9;
    border-color: #0ea5e9;
}

.btn-secondary {
    background-color: #334155;
    color: #f8fafc;
    font-weight: 600;
    font-size: 12px;
    border-radius: 8px;
    padding: 8px 14px;
    border: 1px solid #475569;
}

.btn-secondary:hover {
    background-color: #475569;
}

.btn-danger {
    background-color: rgba(239, 68, 68, 0.18);
    color: #ef4444;
    font-weight: 600;
    font-size: 12px;
    border-radius: 8px;
    padding: 8px 14px;
    border: 1px solid rgba(239, 68, 68, 0.4);
}

.btn-danger:hover {
    background-color: #ef4444;
    color: #ffffff;
    border-color: #ef4444;
}

.remember-check {
    font-size: 11px;
    color: #94a3b8;
}

.remember-check:hover {
    color: #f8fafc;
}

.status-label {
    font-size: 11px;
    font-weight: 600;
    padding-top: 4px;
}

.status-error {
    color: #ef4444;
}

.status-info {
    color: #38bdf8;
}

.status-warning {
    color: #f59e0b;
}

.status-success {
    color: #10b981;
}
"#;

thread_local! {
    static MODAL_HOLDER: RefCell<Option<PromptModalUi>> = RefCell::new(None);
}

pub struct GuiHandle {
    join_handle: Option<std::thread::JoinHandle<()>>,
}

impl GuiHandle {
    pub fn shutdown(mut self) {
        glib::idle_add_once(|| {
            gtk::main_quit();
        });
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.join();
        }
    }
}

/// Spawns the Linux desktop native GUI prompt service in a dedicated thread.
/// Automatically detects headless environments (missing DISPLAY or WAYLAND_DISPLAY)
/// and handles errors gracefully without interrupting daemon / CLI mode.
pub fn spawn_gui(security: SecurityEngine) -> Option<GuiHandle> {
    if std::env::var("DISPLAY").is_err() && std::env::var("WAYLAND_DISPLAY").is_err() {
        println!("[GUI] No X11 or Wayland display detected. Native GUI prompt modal disabled.");
        return None;
    }

    let (init_tx, init_rx) = std::sync::mpsc::channel::<Result<(), String>>();

    let sec_for_thread = security.clone();
    let join_handle = std::thread::spawn(move || {
        if let Err(e) = gtk::init() {
            let err_msg = format!("GTK initialization failed: {}", e);
            eprintln!("[GUI] {}. Native GUI prompt disabled.", err_msg);
            let _ = init_tx.send(Err(err_msg));
            return;
        }

        // Apply custom modern theme CSS
        let css_provider = gtk::CssProvider::new();
        if let Err(e) = css_provider.load_from_data(GUI_CSS.as_bytes()) {
            eprintln!("[GUI] Warning: Failed to parse GTK CSS: {}", e);
        } else if let Some(screen) = gdk::Screen::default() {
            gtk::StyleContext::add_provider_for_screen(
                &screen,
                &css_provider,
                gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
            );
        }

        println!("[GUI] [+] Linux desktop WebAuthn verification prompt modal initialized.");

        // Construct modal UI on GTK thread and store in thread_local
        let modal = PromptModalUi::new(sec_for_thread.clone());
        MODAL_HOLDER.with(|holder| {
            *holder.borrow_mut() = Some(modal);
        });

        let _ = init_tx.send(Ok(()));

        // 200ms periodic timer to reconcile active prompt with backend
        // (Ensures auto-close if settled via Web UI, USB touch, or 60s timeout)
        let sec_heartbeat = sec_for_thread.clone();
        glib::timeout_add_local(Duration::from_millis(200), move || {
            let pending_opt = sec_heartbeat.get_pending_prompt();
            MODAL_HOLDER.with(|holder| {
                if let Some(ui) = holder.borrow().as_ref() {
                    if ui.is_visible() {
                        match pending_opt {
                            Some(p) => {
                                if Some(p.request_id) != ui.current_request_id() {
                                    ui.display_prompt(p);
                                } else {
                                    ui.sync_fields_if_changed(&p);
                                }
                            }
                            None => {
                                ui.hide();
                            }
                        }
                    } else if let Some(p) = pending_opt {
                        ui.display_prompt(p);
                    }
                }
            });
            glib::ControlFlow::Continue
        });

        gtk::main();

        MODAL_HOLDER.with(|holder| {
            *holder.borrow_mut() = None;
        });
    });

    // Await GTK initialization result
    match init_rx.recv() {
        Ok(Ok(())) => {}
        Ok(Err(_)) | Err(_) => {
            return None;
        }
    }

    // Forward Tokio prompt broadcast events to the GTK main context via idle_add
    let sec_listener = security.clone();
    tokio::spawn(async move {
        let mut rx = sec_listener.subscribe_prompts();
        while let Ok(event) = rx.recv().await {
            glib::idle_add_once(move || {
                MODAL_HOLDER.with(|holder| {
                    if let Some(ui) = holder.borrow().as_ref() {
                        match event {
                            PromptEvent::NewPrompt(p) => {
                                ui.display_prompt(p);
                            }
                            PromptEvent::PromptUpdated(p) => {
                                ui.update_prompt(p);
                            }
                            PromptEvent::PromptClosed(id) => {
                                ui.close_if_matching(id);
                            }
                        }
                    }
                });
            });
        }
    });

    Some(GuiHandle {
        join_handle: Some(join_handle),
    })
}

struct PromptModalUi {
    _security: SecurityEngine,
    window: gtk::Window,
    rp_badge: gtk::Label,
    user_label: gtk::Label,
    account_box: gtk::Box,
    account_combo: gtk::ComboBoxText,
    remember_check: gtk::CheckButton,
    // Dynamic Views
    setup_view: gtk::Box,
    setup_pin_entry: gtk::Entry,
    verify_view: gtk::Box,
    verify_pin_entry: gtk::Entry,
    btn_verify_sensor: gtk::Button,
    remembered_view: gtk::Box,
    // Status message
    status_label: gtk::Label,
    // State tracking
    current_req_id: Arc<parking_lot::Mutex<Option<u64>>>,
    suppress_callbacks: Arc<AtomicBool>,
    _fp_scanning: Arc<AtomicBool>,
}

impl PromptModalUi {
    fn new(security: SecurityEngine) -> Self {
        let window = gtk::Window::new(gtk::WindowType::Toplevel);
        window.set_title("WebAuthn Verification Request - VrtFido");
        window.set_position(gtk::WindowPosition::Center);
        window.set_default_size(480, 420);
        window.set_resizable(false);
        window.set_keep_above(true);
        window.set_urgency_hint(true);
        window.set_type_hint(gdk::WindowTypeHint::Dialog);
        window.style_context().add_class("vrtfido-modal");

        let current_req_id = Arc::new(parking_lot::Mutex::new(None));
        let suppress_callbacks = Arc::new(AtomicBool::new(false));
        let fp_scanning = Arc::new(AtomicBool::new(false));

        // Outer margin Box
        let outer_box = gtk::Box::new(gtk::Orientation::Vertical, 0);
        outer_box.set_margin_start(16);
        outer_box.set_margin_end(16);
        outer_box.set_margin_top(16);
        outer_box.set_margin_bottom(16);

        // Card Container Box
        let card_box = gtk::Box::new(gtk::Orientation::Vertical, 10);
        card_box.style_context().add_class("modal-card");

        // Icon
        let icon_label = gtk::Label::new(Some("🛡️"));
        icon_label.style_context().add_class("modal-icon");
        card_box.pack_start(&icon_label, false, false, 0);

        // Title
        let title_label = gtk::Label::new(Some("WebAuthn Verification Request"));
        title_label.style_context().add_class("modal-title");
        card_box.pack_start(&title_label, false, false, 0);

        // Subtitle
        let subtitle_label = gtk::Label::new(Some("A website is requesting your security key:"));
        subtitle_label.style_context().add_class("modal-subtitle");
        card_box.pack_start(&subtitle_label, false, false, 0);

        // RP ID Badge Box
        let rp_box = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        rp_box.set_halign(gtk::Align::Center);
        let rp_badge = gtk::Label::new(Some("webauthn.io"));
        rp_badge.style_context().add_class("modal-rp-badge");
        rp_box.pack_start(&rp_badge, false, false, 0);
        card_box.pack_start(&rp_box, false, false, 2);

        // User / Account single label
        let user_label = gtk::Label::new(None);
        user_label.style_context().add_class("modal-subtitle");
        card_box.pack_start(&user_label, false, false, 0);

        // Multi-Account Selection Area
        let account_box = gtk::Box::new(gtk::Orientation::Vertical, 4);
        account_box.style_context().add_class("account-box");
        let account_title = gtk::Label::new(Some("👤 Select Account to Authenticate:"));
        account_title.set_halign(gtk::Align::Start);
        account_title.style_context().add_class("account-label");
        account_box.pack_start(&account_title, false, false, 0);

        let account_combo = gtk::ComboBoxText::new();
        account_box.pack_start(&account_combo, false, false, 0);

        let account_note = gtk::Label::new(Some("Defaulted to latest used/added account."));
        account_note.set_halign(gtk::Align::Start);
        account_note.style_context().add_class("account-note");
        account_box.pack_start(&account_note, false, false, 0);
        card_box.pack_start(&account_box, false, false, 2);

        // Remember Checkbox
        let remember_check = gtk::CheckButton::with_label(
            "🔓 Remember for this app run — later requests skip PIN / fingerprint",
        );
        remember_check.style_context().add_class("remember-check");
        card_box.pack_start(&remember_check, false, false, 4);

        // --- 1. SETUP VIEW (when security not setup) ---
        let setup_view = gtk::Box::new(gtk::Orientation::Vertical, 8);
        let setup_warn = gtk::Label::new(Some(
            "⚠️ Security is not configured. Please create a 6-digit PIN to activate:",
        ));
        setup_warn.style_context().add_class("status-warning");
        setup_view.pack_start(&setup_warn, false, false, 0);

        let setup_pin_entry = gtk::Entry::new();
        setup_pin_entry.set_visibility(false);
        setup_pin_entry.set_max_length(6);
        setup_pin_entry.set_alignment(0.5);
        setup_pin_entry.set_placeholder_text(Some("Enter 6 digits"));
        setup_pin_entry.style_context().add_class("pin-entry");
        setup_view.pack_start(&setup_pin_entry, false, false, 0);

        let setup_actions = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        setup_actions.set_halign(gtk::Align::Center);
        let btn_setup_approve = gtk::Button::with_label("Activate & Approve");
        btn_setup_approve.style_context().add_class("btn-primary");
        let btn_setup_reject = gtk::Button::with_label("Reject");
        btn_setup_reject.style_context().add_class("btn-danger");
        setup_actions.pack_start(&btn_setup_approve, false, false, 0);
        setup_actions.pack_start(&btn_setup_reject, false, false, 0);
        setup_view.pack_start(&setup_actions, false, false, 4);
        card_box.pack_start(&setup_view, false, false, 0);

        // --- 2. VERIFY VIEW (PIN or sensor) ---
        let verify_view = gtk::Box::new(gtk::Orientation::Vertical, 8);
        let verify_prompt = gtk::Label::new(Some(
            "💡 Touch the USB fingerprint sensor now or enter your PIN:",
        ));
        verify_prompt.style_context().add_class("status-info");
        verify_view.pack_start(&verify_prompt, false, false, 0);

        let verify_pin_entry = gtk::Entry::new();
        verify_pin_entry.set_visibility(false);
        verify_pin_entry.set_max_length(6);
        verify_pin_entry.set_alignment(0.5);
        verify_pin_entry.set_placeholder_text(Some("Enter 6-digit PIN"));
        verify_pin_entry.style_context().add_class("pin-entry");
        verify_view.pack_start(&verify_pin_entry, false, false, 0);

        let verify_actions = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        verify_actions.set_halign(gtk::Align::Center);
        let btn_verify_pin = gtk::Button::with_label("🔑 Verify with PIN");
        btn_verify_pin.style_context().add_class("btn-primary");
        let btn_verify_sensor = gtk::Button::with_label("🖐️ Touch USB Sensor");
        btn_verify_sensor.style_context().add_class("btn-secondary");
        let btn_verify_reject = gtk::Button::with_label("❌ Reject Request");
        btn_verify_reject.style_context().add_class("btn-danger");
        verify_actions.pack_start(&btn_verify_pin, false, false, 0);
        verify_actions.pack_start(&btn_verify_sensor, false, false, 0);
        verify_actions.pack_start(&btn_verify_reject, false, false, 0);
        verify_view.pack_start(&verify_actions, false, false, 4);
        card_box.pack_start(&verify_view, false, false, 0);

        // --- 3. REMEMBERED VIEW (already verified) ---
        let remembered_view = gtk::Box::new(gtk::Orientation::Vertical, 8);
        let remembered_label = gtk::Label::new(Some(
            "🔓 This app run is already verified — click Approve to confirm (no PIN or sensor needed).",
        ));
        remembered_label.style_context().add_class("status-success");
        remembered_view.pack_start(&remembered_label, false, false, 0);

        let rem_actions = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        rem_actions.set_halign(gtk::Align::Center);
        let btn_rem_approve = gtk::Button::with_label("✔️ Approve");
        btn_rem_approve.style_context().add_class("btn-primary");
        let btn_rem_reject = gtk::Button::with_label("❌ Reject Request");
        btn_rem_reject.style_context().add_class("btn-danger");
        rem_actions.pack_start(&btn_rem_approve, false, false, 0);
        rem_actions.pack_start(&btn_rem_reject, false, false, 0);
        remembered_view.pack_start(&rem_actions, false, false, 4);
        card_box.pack_start(&remembered_view, false, false, 0);

        // Status Label for errors and notices
        let status_label = gtk::Label::new(None);
        status_label.style_context().add_class("status-label");
        card_box.pack_start(&status_label, false, false, 2);

        outer_box.pack_start(&card_box, true, true, 0);
        window.add(&outer_box);

        // Setup Event Connectors
        let sec = security.clone();
        let cur_id = current_req_id.clone();
        let win_clone = window.clone();
        let status_clone = status_label.clone();
        let check_clone = remember_check.clone();
        let combo_clone = account_combo.clone();
        let pin_entry_clone = verify_pin_entry.clone();

        // 1. PIN Approval Helper
        let approve_pin_action = {
            let sec = sec.clone();
            let cur_id = cur_id.clone();
            let win = win_clone.clone();
            let status = status_clone.clone();
            let check = check_clone.clone();
            let combo = combo_clone.clone();
            let pin_entry = pin_entry_clone.clone();
            move || {
                let req_id = match *cur_id.lock() {
                    Some(id) => id,
                    None => return,
                };
                let pin = pin_entry.text().to_string();
                let pin_trimmed = pin.trim();
                if pin_trimmed.len() != 6 || !pin_trimmed.chars().all(|c| c.is_ascii_digit()) {
                    status.set_text("⚠️ PIN must be exactly 6 digits!");
                    status.style_context().remove_class("status-info");
                    status.style_context().add_class("status-error");
                    return;
                }
                let sel_cred = combo.active_id().map(|s| s.to_string());
                let rem = check.is_active();
                match sec.approve_pending(req_id, "PIN", Some(pin_trimmed), sel_cred, Some(rem)) {
                    Ok(()) => {
                        *cur_id.lock() = None;
                        pin_entry.set_text("");
                        status.set_text("");
                        win.hide();
                    }
                    Err(e) => {
                        status.set_text(&format!("❌ Authentication failed: {}", e));
                        status.style_context().remove_class("status-info");
                        status.style_context().add_class("status-error");
                        pin_entry.set_text("");
                    }
                }
            }
        };

        // Connect Verify with PIN button & Enter key
        let approve_pin_fn = approve_pin_action.clone();
        btn_verify_pin.connect_clicked(move |_| {
            approve_pin_fn();
        });
        let approve_pin_fn2 = approve_pin_action.clone();
        verify_pin_entry.connect_activate(move |_| {
            approve_pin_fn2();
        });

        // 2. Setup Activation Action
        let approve_setup_action = {
            let sec = sec.clone();
            let cur_id = cur_id.clone();
            let win = win_clone.clone();
            let status = status_clone.clone();
            let check = check_clone.clone();
            let combo = combo_clone.clone();
            let setup_entry = setup_pin_entry.clone();
            move || {
                let req_id = match *cur_id.lock() {
                    Some(id) => id,
                    None => return,
                };
                let pin = setup_entry.text().to_string();
                let pin_trimmed = pin.trim();
                if pin_trimmed.len() != 6 || !pin_trimmed.chars().all(|c| c.is_ascii_digit()) {
                    status.set_text("⚠️ Activation PIN must be exactly 6 digits!");
                    status.style_context().remove_class("status-info");
                    status.style_context().add_class("status-error");
                    return;
                }
                let sel_cred = combo.active_id().map(|s| s.to_string());
                let rem = check.is_active();
                match sec.approve_pending(req_id, "SETUP", Some(pin_trimmed), sel_cred, Some(rem)) {
                    Ok(()) => {
                        *cur_id.lock() = None;
                        setup_entry.set_text("");
                        status.set_text("");
                        win.hide();
                    }
                    Err(e) => {
                        status.set_text(&format!("❌ Setup failed: {}", e));
                        status.style_context().remove_class("status-info");
                        status.style_context().add_class("status-error");
                    }
                }
            }
        };

        let approve_setup_fn = approve_setup_action.clone();
        btn_setup_approve.connect_clicked(move |_| {
            approve_setup_fn();
        });
        let approve_setup_fn2 = approve_setup_action.clone();
        setup_pin_entry.connect_activate(move |_| {
            approve_setup_fn2();
        });

        // 3. Remembered Approve Action
        let approve_rem_action = {
            let sec = sec.clone();
            let cur_id = cur_id.clone();
            let win = win_clone.clone();
            let status = status_clone.clone();
            let combo = combo_clone.clone();
            move || {
                let req_id = match *cur_id.lock() {
                    Some(id) => id,
                    None => return,
                };
                let sel_cred = combo.active_id().map(|s| s.to_string());
                match sec.approve_pending(req_id, "REMEMBERED", None, sel_cred, Some(true)) {
                    Ok(()) => {
                        *cur_id.lock() = None;
                        status.set_text("");
                        win.hide();
                    }
                    Err(e) => {
                        status.set_text(&format!("❌ Approval error: {}", e));
                        status.style_context().remove_class("status-info");
                        status.style_context().add_class("status-error");
                    }
                }
            }
        };
        btn_rem_approve.connect_clicked(move |_| {
            approve_rem_action();
        });

        // 4. Touch USB Sensor Action
        let sensor_action = {
            let sec = sec.clone();
            let cur_id = cur_id.clone();
            let status = status_clone.clone();
            let check = check_clone.clone();
            let combo = combo_clone.clone();
            let fp_active = fp_scanning.clone();
            let btn_sensor = btn_verify_sensor.clone();
            move || {
                let req_id = match *cur_id.lock() {
                    Some(id) => id,
                    None => return,
                };
                if fp_active.swap(true, Ordering::SeqCst) {
                    return;
                }
                btn_sensor.set_sensitive(false);
                status.set_text("🖐️ Scanning sensor... Please touch USB fingerprint sensor now!");
                status.style_context().remove_class("status-error");
                status.style_context().add_class("status-info");

                let sel_cred = combo.active_id().map(|s| s.to_string());
                let rem = check.is_active();
                let sec_bg = sec.clone();
                let fp_flag = fp_active.clone();

                std::thread::spawn(move || {
                    let res = sec_bg.approve_pending(
                        req_id,
                        "FINGERPRINT",
                        None,
                        sel_cred,
                        Some(rem),
                    );
                    fp_flag.store(false, Ordering::SeqCst);
                    glib::idle_add_once(move || {
                        MODAL_HOLDER.with(|holder| {
                            if let Some(ui) = holder.borrow().as_ref() {
                                ui.handle_fingerprint_result(res);
                            }
                        });
                    });
                });
            }
        };
        btn_verify_sensor.connect_clicked(move |_| {
            sensor_action();
        });

        // 5. Reject Action Helper
        let reject_action = {
            let sec = sec.clone();
            let cur_id = cur_id.clone();
            let win = win_clone.clone();
            let status = status_clone.clone();
            let pin1 = pin_entry_clone.clone();
            let pin2 = setup_pin_entry.clone();
            move |reason: &str| {
                if let Some(req_id) = cur_id.lock().take() {
                    let _ = sec.reject_pending(req_id, reason);
                }
                pin1.set_text("");
                pin2.set_text("");
                status.set_text("");
                win.hide();
            }
        };

        let reject_fn1 = reject_action.clone();
        btn_setup_reject.connect_clicked(move |_| {
            reject_fn1("Rejected on Linux Desktop GUI");
        });
        let reject_fn2 = reject_action.clone();
        btn_verify_reject.connect_clicked(move |_| {
            reject_fn2("Rejected on Linux Desktop GUI");
        });
        let reject_fn3 = reject_action.clone();
        btn_rem_reject.connect_clicked(move |_| {
            reject_fn3("Rejected on Linux Desktop GUI");
        });

        // Window Delete ('X') event
        let reject_fn_win = reject_action.clone();
        window.connect_delete_event(move |_, _| {
            reject_fn_win("Window closed by user on Linux Desktop");
            glib::Propagation::Stop
        });

        // Escape key rejection
        let reject_fn_esc = reject_action.clone();
        window.connect_key_press_event(move |_, ev| {
            if ev.keyval() == gdk::keys::constants::Escape {
                reject_fn_esc("Dismissed via Escape on Linux Desktop");
                return glib::Propagation::Stop;
            }
            glib::Propagation::Proceed
        });

        // Remember Checkbox onchange
        let sec_check = security.clone();
        let suppress_check = suppress_callbacks.clone();
        remember_check.connect_toggled(move |btn| {
            if suppress_check.load(Ordering::SeqCst) {
                return;
            }
            sec_check.set_remember_requested(btn.is_active());
        });

        // Multi-Account ComboBox onchange
        let sec_combo = security.clone();
        let cur_id_combo = current_req_id.clone();
        let suppress_combo = suppress_callbacks.clone();
        account_combo.connect_changed(move |combo| {
            if suppress_combo.load(Ordering::SeqCst) {
                return;
            }
            if let Some(req_id) = *cur_id_combo.lock() {
                if let Some(cred_id) = combo.active_id() {
                    let _ = sec_combo.select_account(req_id, cred_id.as_str());
                }
            }
        });

        Self {
            _security: security,
            window,
            rp_badge,
            user_label,
            account_box,
            account_combo,
            remember_check,
            setup_view,
            setup_pin_entry,
            verify_view,
            verify_pin_entry,
            btn_verify_sensor,
            remembered_view,
            status_label,
            current_req_id,
            suppress_callbacks,
            _fp_scanning: fp_scanning,
        }
    }

    fn is_visible(&self) -> bool {
        self.window.is_visible()
    }

    fn current_request_id(&self) -> Option<u64> {
        *self.current_req_id.lock()
    }

    fn hide(&self) {
        *self.current_req_id.lock() = None;
        self.verify_pin_entry.set_text("");
        self.setup_pin_entry.set_text("");
        self.status_label.set_text("");
        self.window.hide();
    }

    fn close_if_matching(&self, req_id: u64) {
        let mut guard = self.current_req_id.lock();
        if *guard == Some(req_id) {
            *guard = None;
            self.verify_pin_entry.set_text("");
            self.setup_pin_entry.set_text("");
            self.status_label.set_text("");
            self.window.hide();
        }
    }

    fn display_prompt(&self, p: PendingPrompt) {
        *self.current_req_id.lock() = Some(p.request_id);

        self.suppress_callbacks.store(true, Ordering::SeqCst);

        // RP ID
        self.rp_badge.set_text(&p.rp_id);

        // Accounts selection / User name
        if p.accounts.len() > 1 {
            self.account_box.show();
            self.user_label.hide();
            self.account_combo.remove_all();

            for acc in &p.accounts {
                let label = if !acc.user_display_name.is_empty() && acc.user_display_name != acc.user_name {
                    format!("{} ({})", acc.user_display_name, acc.user_name)
                } else {
                    acc.user_name.clone()
                };
                self.account_combo.append(Some(&acc.id), &label);
            }

            if let Some(sel) = &p.selected_credential_id {
                self.account_combo.set_active_id(Some(sel));
            } else if let Some(first) = p.accounts.first() {
                self.account_combo.set_active_id(Some(&first.id));
            }
        } else {
            self.account_box.hide();
            if !p.user_name.is_empty() {
                self.user_label.set_text(&format!("Account: {}", p.user_name));
                self.user_label.show();
            } else {
                self.user_label.hide();
            }
        }

        // Remember checkbox
        let remembered = p.session_remembered;
        self.remember_check.set_active(p.remember_requested);
        if remembered {
            self.remember_check.hide();
        } else {
            self.remember_check.show();
        }

        // Reset inputs & status
        self.verify_pin_entry.set_text("");
        self.setup_pin_entry.set_text("");
        self.status_label.set_text("");

        // Switch View
        if remembered {
            self.remembered_view.show_all();
            self.setup_view.hide();
            self.verify_view.hide();
        } else if !p.is_security_setup {
            self.setup_view.show_all();
            self.verify_view.hide();
            self.remembered_view.hide();
            self.setup_pin_entry.grab_focus();
        } else {
            self.verify_view.show_all();
            self.setup_view.hide();
            self.remembered_view.hide();
            self.btn_verify_sensor.set_sensitive(p.hardware_sensor_available);
            self.verify_pin_entry.grab_focus();
        }

        self.suppress_callbacks.store(false, Ordering::SeqCst);

        // Bring window to front
        self.window.show_all();
        // Keep correct visibility for hidden view subcontainers
        if remembered {
            self.setup_view.hide();
            self.verify_view.hide();
            self.remember_check.hide();
        } else if !p.is_security_setup {
            self.verify_view.hide();
            self.remembered_view.hide();
        } else {
            self.setup_view.hide();
            self.remembered_view.hide();
        }
        if p.accounts.len() <= 1 {
            self.account_box.hide();
        }

        self.window.present();
    }

    fn update_prompt(&self, p: PendingPrompt) {
        if *self.current_req_id.lock() != Some(p.request_id) {
            return;
        }

        self.suppress_callbacks.store(true, Ordering::SeqCst);
        if self.remember_check.is_active() != p.remember_requested {
            self.remember_check.set_active(p.remember_requested);
        }

        if let Some(sel) = &p.selected_credential_id {
            if self.account_combo.active_id().as_deref() != Some(sel.as_str()) {
                self.account_combo.set_active_id(Some(sel));
            }
        }
        self.suppress_callbacks.store(false, Ordering::SeqCst);
    }

    fn sync_fields_if_changed(&self, p: &PendingPrompt) {
        if self.suppress_callbacks.load(Ordering::SeqCst) {
            return;
        }
        if self.remember_check.is_active() != p.remember_requested {
            self.suppress_callbacks.store(true, Ordering::SeqCst);
            self.remember_check.set_active(p.remember_requested);
            self.suppress_callbacks.store(false, Ordering::SeqCst);
        }
        if let Some(sel) = &p.selected_credential_id {
            if self.account_combo.active_id().as_deref() != Some(sel.as_str()) {
                self.suppress_callbacks.store(true, Ordering::SeqCst);
                self.account_combo.set_active_id(Some(sel));
                self.suppress_callbacks.store(false, Ordering::SeqCst);
            }
        }
    }

    fn handle_fingerprint_result(&self, res: Result<(), String>) {
        self.btn_verify_sensor.set_sensitive(true);
        match res {
            Ok(()) => {
                self.hide();
            }
            Err(e) => {
                self.status_label.set_text(&format!("❌ Fingerprint scan: {}", e));
                self.status_label.style_context().remove_class("status-info");
                self.status_label.style_context().add_class("status-error");
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use crate::security::PendingAccountOption;
    use crate::sensor::UsbSensor;

    fn setup_test_engine() -> SecurityEngine {
        let db = Db::open(":memory:").expect("In-memory SQLite DB failed");
        let sensor = UsbSensor::new();
        SecurityEngine::new(db, sensor, false)
    }

    #[tokio::test]
    async fn test_prompt_broadcast_lifecycle() {
        let security = setup_test_engine();
        let mut rx = security.subscribe_prompts();

        let sec_clone = security.clone();
        let handle = tokio::spawn(async move {
            let accounts = vec![
                PendingAccountOption {
                    id: "acc_1".into(),
                    user_name: "alice".into(),
                    user_display_name: "Alice A".into(),
                    last_used_at: "2026-09-25".into(),
                    created_at: "2026-09-01".into(),
                },
                PendingAccountOption {
                    id: "acc_2".into(),
                    user_name: "bob".into(),
                    user_display_name: "Bob B".into(),
                    last_used_at: "2026-09-24".into(),
                    created_at: "2026-09-02".into(),
                },
            ];
            sec_clone
                .request_user_verification_with_accounts(
                    "webauthn.io",
                    "GetAssertion",
                    "alice",
                    accounts,
                    Some("acc_1".into()),
                )
                .await
        });

        // 1. Should receive NewPrompt
        let event1 = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .expect("Timeout waiting for NewPrompt")
            .expect("Recv error");

        let req_id = match event1 {
            PromptEvent::NewPrompt(p) => {
                assert_eq!(p.rp_id, "webauthn.io");
                assert_eq!(p.operation, "GetAssertion");
                assert_eq!(p.user_name, "alice");
                assert_eq!(p.accounts.len(), 2);
                assert_eq!(p.selected_credential_id, Some("acc_1".into()));
                p.request_id
            }
            other => panic!("Expected NewPrompt, got {:?}", other),
        };

        // 2. Select different account -> PromptUpdated
        security
            .select_account(req_id, "acc_2")
            .expect("select_account failed");

        let event2 = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .expect("Timeout waiting for PromptUpdated (account)")
            .expect("Recv error");

        match event2 {
            PromptEvent::PromptUpdated(p) => {
                assert_eq!(p.request_id, req_id);
                assert_eq!(p.selected_credential_id, Some("acc_2".into()));
            }
            other => panic!("Expected PromptUpdated, got {:?}", other),
        }

        // 3. Toggle remember -> PromptUpdated
        security.set_remember_requested(true);

        let event3 = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .expect("Timeout waiting for PromptUpdated (remember)")
            .expect("Recv error");

        match event3 {
            PromptEvent::PromptUpdated(p) => {
                assert_eq!(p.request_id, req_id);
                assert!(p.remember_requested);
            }
            other => panic!("Expected PromptUpdated, got {:?}", other),
        }

        // 4. Approve prompt -> PromptClosed
        security
            .approve_pending(req_id, "SETUP", Some("123456"), None, None)
            .expect("approve_pending failed");

        let event4 = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .expect("Timeout waiting for PromptClosed")
            .expect("Recv error");

        match event4 {
            PromptEvent::PromptClosed(closed_id) => {
                assert_eq!(closed_id, req_id);
            }
            other => panic!("Expected PromptClosed, got {:?}", other),
        }

        let result = handle.await.unwrap();
        assert!(result.is_ok());
        let success = result.unwrap();
        assert_eq!(success.method, "SETUP");
    }

    #[tokio::test]
    async fn test_prompt_rejection_broadcast() {
        let security = setup_test_engine();
        let mut rx = security.subscribe_prompts();

        let sec_clone = security.clone();
        let handle = tokio::spawn(async move {
            sec_clone
                .request_user_verification("example.com", "GetAssertion", "charlie")
                .await
        });

        let event = rx.recv().await.unwrap();
        let req_id = match event {
            PromptEvent::NewPrompt(p) => p.request_id,
            other => panic!("Expected NewPrompt, got {:?}", other),
        };

        security
            .reject_pending(req_id, "Dismissed by user")
            .expect("reject_pending failed");

        let event_close = rx.recv().await.unwrap();
        match event_close {
            PromptEvent::PromptClosed(id) => assert_eq!(id, req_id),
            other => panic!("Expected PromptClosed, got {:?}", other),
        }

        let res = handle.await.unwrap();
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Dismissed by user"));
    }

    #[tokio::test]
    async fn test_parallel_web_and_gui_sync() {
        let security = setup_test_engine();
        let mut rx = security.subscribe_prompts();

        // Initially no prompt
        assert!(security.get_pending_prompt().is_none());

        let sec_clone = security.clone();
        let handle = tokio::spawn(async move {
            sec_clone
                .request_user_verification("login.github.com", "GetAssertion", "dev")
                .await
        });

        // Event for GUI
        let event = rx.recv().await.unwrap();
        let req_id = match event {
            PromptEvent::NewPrompt(p) => p.request_id,
            other => panic!("Expected NewPrompt, got {:?}", other),
        };

        // Query used by Web UI (/api/verify/pending)
        let web_prompt = security.get_pending_prompt().expect("Web UI should see pending prompt");
        assert_eq!(web_prompt.request_id, req_id);
        assert_eq!(web_prompt.rp_id, "login.github.com");

        // Web UI toggles remember preference
        security.set_remember_requested(true);
        let event_up = rx.recv().await.unwrap();
        match event_up {
            PromptEvent::PromptUpdated(p) => assert!(p.remember_requested),
            other => panic!("Expected PromptUpdated, got {:?}", other),
        }

        // Web UI approves
        security
            .approve_pending(req_id, "SETUP", Some("654321"), None, Some(true))
            .expect("Approval failed");

        // GUI receives closed event
        let event_closed = rx.recv().await.unwrap();
        match event_closed {
            PromptEvent::PromptClosed(id) => assert_eq!(id, req_id),
            other => panic!("Expected PromptClosed, got {:?}", other),
        }

        // Web UI now sees prompt is gone
        assert!(security.get_pending_prompt().is_none());

        let res = handle.await.unwrap();
        assert!(res.is_ok());
    }

    #[test]
    fn test_gui_css_validity() {
        if std::env::var("DISPLAY").is_ok() || std::env::var("WAYLAND_DISPLAY").is_ok() {
            if gtk::init().is_ok() {
                let css_provider = gtk::CssProvider::new();
                let parse_res = css_provider.load_from_data(GUI_CSS.as_bytes());
                assert!(parse_res.is_ok(), "GUI_CSS must parse without syntax errors: {:?}", parse_res.err());
            }
        }
    }
}
