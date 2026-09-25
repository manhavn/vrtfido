use crate::db::Db;
use crate::sensor::{SensorBusyMode, UsbSensor};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

#[derive(serde::Serialize, serde::Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum BiometricModality {
    Fingerprint,
    Face,
    Iris,
    Voice,
    Palm,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct PendingAccountOption {
    pub id: String,
    pub user_name: String,
    pub user_display_name: String,
    pub last_used_at: String,
    pub created_at: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct PendingPrompt {
    pub request_id: u64,
    pub rp_id: String,
    pub operation: String,
    pub user_name: String,
    pub is_security_setup: bool,
    pub pin_configured: bool,
    pub fp_count: usize,
    pub hardware_sensor_available: bool,
    pub available_modalities: Vec<BiometricModality>,
    pub created_at_secs: u64,
    pub timeout_seconds: u64,
    pub accounts: Vec<PendingAccountOption>,
    pub selected_credential_id: Option<String>,
    /// True when this run already verified the user (checkbox "Remember" + one successful approval).
    /// Only requests that still need an account choice reach this point, so the modal shows the
    /// chooser plus a single Approve button instead of asking for the PIN / fingerprint again.
    pub session_remembered: bool,
    /// Current checkbox state, so a reloaded / second tab renders the same tick.
    pub remember_requested: bool,
}

#[derive(Clone, Debug)]
pub struct VerificationSuccess {
    pub method: String,
    pub selected_credential_id: Option<String>,
}

pub struct ActiveVerification {
    pub prompt: PendingPrompt,
    pub start_time: Instant,
    pub responder: Option<oneshot::Sender<Result<VerificationSuccess, String>>>,
}


#[derive(Clone)]
pub struct SecurityEngine {
    db: Db,
    sensor: UsbSensor,
    pending: Arc<Mutex<Option<ActiveVerification>>>,
    req_counter: Arc<AtomicU64>,
    unlimited_fps: bool,
    /// State of the "Remember" checkbox in the Web CMS modal, pushed by the browser. Only read when
    /// an approval succeeds, so it never influences whether a request needs confirmation.
    remember_requested: Arc<AtomicBool>,
    /// Set once an approval succeeds while `remember_requested` was on: later requests in the *same
    /// process run* are approved without touching the PIN or the sensor again. Never persisted, so
    /// restarting the app always falls back to a full verification.
    session_verified: Arc<AtomicBool>,
    /// Set while an on-screen "Touch USB Sensor" approval owns the chip. The background touch
    /// listener has to stop scanning then: both paths drive the same single USB device, and letting
    /// them overlap made every manual attempt fail with "Fingerprint sensor error: USB sensor busy".
    fp_listener_paused: Arc<AtomicBool>,
    /// One manual scan per request: a double click must not start a second scan on the same chip.
    fp_manual_active: Arc<AtomicBool>,
}

impl SecurityEngine {
    pub fn new(db: Db, sensor: UsbSensor, unlimited_fps: bool) -> Self {
        Self {
            db,
            sensor,
            pending: Arc::new(Mutex::new(None)),
            req_counter: Arc::new(AtomicU64::new(1)),
            unlimited_fps,
            remember_requested: Arc::new(AtomicBool::new(false)),
            session_verified: Arc::new(AtomicBool::new(false)),
            fp_listener_paused: Arc::new(AtomicBool::new(false)),
            fp_manual_active: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn sensor(&self) -> &UsbSensor {
        &self.sensor
    }

    /// Live state of the modal checkbox. Kept on the server so the USB sensor's background listener
    /// can honour the same choice as the on-screen buttons.
    pub fn set_remember_requested(&self, enabled: bool) {
        self.remember_requested.store(enabled, Ordering::SeqCst);
    }

    /// Extend the verification to the rest of this run - only ever on top of a verification that
    /// just succeeded, and only when the checkbox asked for it.
    fn remember_session(&self) {
        if self.remember_requested.load(Ordering::SeqCst) {
            self.session_verified.store(true, Ordering::SeqCst);
        }
    }

    pub fn is_pin_configured(&self) -> bool {
        self.db
            .get_security_settings(self.unlimited_fps)
            .map(|s| s.pin_enabled)
            .unwrap_or(false)
    }

    pub fn validate_pin_format(pin: &str) -> Result<(), &'static str> {
        if pin.len() != 6 {
            return Err("Passkey PIN must be exactly 6 digits");
        }
        if !pin.chars().all(|c| c.is_ascii_digit()) {
            return Err("Passkey PIN may only contain numeric digits (0-9)");
        }
        Ok(())
    }

    pub fn hash_pin(pin: &str, salt: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(salt.as_bytes());
        hasher.update(pin.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn set_pin(&self, pin: &str) -> Result<(), &'static str> {
        Self::validate_pin_format(pin)?;
        let salt: String = (0..16).map(|_| format!("{:02x}", rand::random::<u8>())).collect();
        let hash = Self::hash_pin(pin, &salt);
        self.db.set_pin(&hash, &salt).map_err(|_| "Failed to save PIN to database")?;
        self.db.log_auth(None, "SYSTEM", "PinSet", "SUCCESS", "PIN", Some("Configured 6-digit PIN"));
        Ok(())
    }

    pub fn change_pin(&self, old_pin: &str, new_pin: &str) -> Result<(), &'static str> {
        Self::validate_pin_format(new_pin)?;
        self.verify_pin(old_pin)?;
        let salt: String = (0..16).map(|_| format!("{:02x}", rand::random::<u8>())).collect();
        let hash = Self::hash_pin(new_pin, &salt);
        self.db.set_pin(&hash, &salt).map_err(|_| "Failed to update PIN in database")?;
        self.db.log_auth(None, "SYSTEM", "PinChanged", "SUCCESS", "PIN", Some("Changed 6-digit PIN successfully"));
        Ok(())
    }

    pub fn remove_pin(&self, current_pin: &str) -> Result<(), &'static str> {
        self.verify_pin(current_pin)?;
        self.db.remove_pin().map_err(|_| "Failed to delete PIN from database")?;
        self.db.log_auth(None, "SYSTEM", "PinRemoved", "SUCCESS", "PIN", Some("Removed 6-digit PIN"));
        Ok(())
    }

    pub fn verify_pin(&self, pin: &str) -> Result<bool, &'static str> {
        let (stored_hash, stored_salt) = self.db.get_pin_hash_and_salt().map_err(|_| "Failed to read security settings")?;
        match (stored_hash, stored_salt) {
            (Some(hash), Some(salt)) => {
                let computed = Self::hash_pin(pin, &salt);
                if computed == hash {
                    Ok(true)
                } else {
                    Err("Incorrect PIN")
                }
            }
            _ => Err("Security PIN not configured"),
        }
    }

    /// Pre-flight check for the Web CMS: rejects the request up front instead of showing a
    /// modal that can only wait, so the dashboard reports why enrollment cannot start.
    pub fn can_enroll_fingerprint(&self) -> Result<(), String> {
        let fps = self.db.get_fingerprints().map_err(|e| e.to_string())?;
        if !self.unlimited_fps && fps.len() >= 10 {
            return Err("Maximum 10 fingerprints reached (Use --unlimited-fps to remove limit)".into());
        }
        if !UsbSensor::is_hardware_plugged() {
            return Err("USB fingerprint sensor (3274:8012) is not connected — plug it in and retry".into());
        }
        // Only another *enrollment* is a real conflict: verify windows of the background touch
        // listener are seconds long and `enroll_fingerprint_pipeline` queues behind them, so
        // rejecting them here made the dashboard refuse to enroll while any prompt was up.
        if self.sensor.busy_mode() == SensorBusyMode::Enrolling {
            return Err("USB fingerprint sensor is busy with another operation".into());
        }
        Ok(())
    }

    /// Enroll fingerprint: Scan 6 times via USB Microarray MAFP sensor
    pub fn enroll_fingerprint(&self, name: &str) -> Result<crate::db::FingerprintRow, String> {
        let fps = self.db.get_fingerprints().map_err(|e| e.to_string())?;
        if !self.unlimited_fps && fps.len() >= 10 {
            return Err("Maximum 10 fingerprints reached (Use --unlimited-fps to remove limit)".into());
        }

        let existing_slots: Vec<u32> = fps.iter().map(|f| f.slot_index).collect();
        let max_slots = if self.unlimited_fps { 30 } else { 10 };
        let mut target_slot = 0u32;
        for s in 0..max_slots {
            if !existing_slots.contains(&s) {
                target_slot = s;
                break;
            }
        }

        // Scan 6 stages on physical hardware. Without the sensor there is no template to store,
        // and recording a slot anyway used to produce a fingerprint that never matched.
        if !UsbSensor::is_hardware_plugged() {
            return Err(
                "USB fingerprint sensor (3274:8012) is not connected — plug it in and retry".into(),
            );
        }
        println!("[SECURITY] Starting 6-stage USB fingerprint enrollment...");
        let actual_fid = self.sensor.enroll_fingerprint_pipeline(target_slot)?;

        let row = self.db.add_fingerprint(actual_fid as u32, name).map_err(|e| e.to_string())?;
        self.db.log_auth(
            None,
            "SYSTEM",
            "FingerprintEnrolled",
            "SUCCESS",
            "FINGERPRINT",
            Some(&format!("Enrolled 6 stages for fingerprint '{}' saved to USB & DB slot {}", row.name, actual_fid)),
        );
        Ok(row)
    }

    pub fn delete_fingerprint(&self, id: i64) -> Result<bool, String> {
        if let Ok(Some(fp)) = self.db.get_fingerprint_by_id(id) {
            let slot = fp.slot_index;
            if UsbSensor::is_hardware_plugged() {
                println!("[SECURITY] Deleting template slot {} from USB chip...", slot);
                let _ = self.sensor.delete_slot(slot);
            }
        }

        let ok = self.db.delete_fingerprint(id).map_err(|e| e.to_string())?;
        if ok {
            self.db.log_auth(
                None,
                "SYSTEM",
                "FingerprintDeleted",
                "SUCCESS",
                "FINGERPRINT",
                Some(&format!("Deleted fingerprint id {} and template from USB chip", id)),
            );

            let remaining = self.db.get_fingerprints().map_err(|e| e.to_string())?;
            if remaining.is_empty() && UsbSensor::is_hardware_plugged() {
                let _ = self.sensor.clear_chip_templates();
            }
        }
        Ok(ok)
    }

    /// ID of the request the CMS is currently showing, or `None` when nothing waits for approval.
    /// Used by the manual sensor path to detect that another path already settled the request.
    fn pending_request_id(&self) -> Option<u64> {
        self.pending.lock().as_ref().map(|a| a.prompt.request_id)
    }

    pub fn get_pending_prompt(&self) -> Option<PendingPrompt> {
        let mut guard = self.pending.lock();
        if let Some(active) = guard.as_mut() {
            if active.start_time.elapsed() > Duration::from_secs(active.prompt.timeout_seconds) {
                *guard = None;
                None
            } else {
                // The flags are live state, not a snapshot: the checkbox is pushed by the browser and
                // the session can be extended while the prompt is up, so a reload or a second tab
                // must see the current values instead of the ones captured at creation time.
                let mut prompt = active.prompt.clone();
                prompt.session_remembered = self.session_verified.load(Ordering::SeqCst);
                prompt.remember_requested = self.remember_requested.load(Ordering::SeqCst);
                Some(prompt)
            }
        } else {
            None
        }
    }

    pub async fn request_user_verification(
        &self,
        rp_id: &str,
        operation: &str,
        user_name: &str,
    ) -> Result<String, String> {
        let res = self
            .request_user_verification_with_accounts(rp_id, operation, user_name, Vec::new(), None)
            .await?;
        Ok(res.method)
    }

    pub async fn request_user_verification_with_accounts(
        &self,
        rp_id: &str,
        operation: &str,
        user_name: &str,
        accounts: Vec<PendingAccountOption>,
        default_selected_cred_id: Option<String>,
    ) -> Result<VerificationSuccess, String> {
        // A remembered session skips the prompt entirely, but only while there is nothing left to
        // decide. With several candidate accounts the user still picks one in the CMS and presses
        // Approve, so the request has to be raised as a normal prompt.
        if self.session_verified.load(Ordering::SeqCst) && accounts.len() <= 1 {
            println!(
                "\n[SECURITY] >>> AUTO-APPROVED by the remembered session (RP: '{}', Operation: '{}', candidates: {}) <<<",
                rp_id,
                operation,
                accounts.len()
            );
            self.db.log_auth(
                default_selected_cred_id.as_deref(),
                rp_id,
                operation,
                "SUCCESS",
                "REMEMBERED",
                Some("Auto-approved with the remembered session of this app run (no PIN / fingerprint, no prompt)"),
            );
            return Ok(VerificationSuccess {
                method: "REMEMBERED".to_string(),
                selected_credential_id: default_selected_cred_id,
            });
        }

        let settings = self.db.get_security_settings(self.unlimited_fps).map_err(|e| e.to_string())?;
        let is_security_setup = settings.pin_enabled || settings.fp_count > 0;
        let sensor_ok = UsbSensor::is_hardware_plugged();

        let req_id = self.req_counter.fetch_add(1, Ordering::SeqCst);
        let prompt = PendingPrompt {
            request_id: req_id,
            rp_id: rp_id.to_string(),
            operation: operation.to_string(),
            user_name: user_name.to_string(),
            is_security_setup,
            pin_configured: settings.pin_enabled,
            fp_count: settings.fp_count,
            hardware_sensor_available: sensor_ok,
            available_modalities: vec![
                BiometricModality::Fingerprint,
                BiometricModality::Face,
            ],
            created_at_secs: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            timeout_seconds: 60,
            accounts,
            selected_credential_id: default_selected_cred_id,
            session_remembered: self.session_verified.load(Ordering::SeqCst),
            remember_requested: self.remember_requested.load(Ordering::SeqCst),
        };

        let (tx, rx) = oneshot::channel();
        {
            let mut guard = self.pending.lock();
            *guard = Some(ActiveVerification {
                prompt,
                start_time: Instant::now(),
                responder: Some(tx),
            });
        }

        println!(
            "\n[SECURITY] >>> NEW VERIFICATION REQUEST (Request #{} - RP: '{}', Operation: '{}') <<<",
            req_id, rp_id, operation
        );

        // Retrieve list of enrolled fingerprint slots
        let fps = self.db.get_fingerprints().unwrap_or_default();
        let enrolled_slots: Vec<u32> = fps.iter().map(|f| f.slot_index).collect();

        // Listen for finger touch on USB if fingerprints are enrolled
        let sensor_clone = self.sensor.clone();
        let pending_ref = self.pending.clone();
        let db_clone = self.db.clone();
        let rp_id_owned = rp_id.to_string();
        let op_owned = operation.to_string();
        // A finger pressed on the sensor is an approval too, so it must extend the session exactly
        // like the on-screen buttons when the checkbox is ticked.
        let remember_pref_clone = self.remember_requested.clone();
        let session_verified_clone = self.session_verified.clone();
        let fp_listener_paused_clone = self.fp_listener_paused.clone();

        let fp_listener = tokio::task::spawn_blocking(move || {
            if !UsbSensor::is_hardware_plugged() || enrolled_slots.is_empty() {
                return;
            }
            let start = Instant::now();
            while start.elapsed() < Duration::from_secs(55) {
                // The request was settled by another path (PIN, reject, the 60s timeout, or a
                // manual scan): stop scanning, otherwise the chip stays occupied by a listener that
                // has nothing left to approve.
                if pending_ref.lock().is_none() {
                    println!("[SECURITY] USB touch listener: request #{} already settled, stopping.", req_id);
                    return;
                }
                // A manual approval (click on "Touch USB Sensor") took the chip over: stay off it,
                // otherwise both scans fight for the single USB device.
                if fp_listener_paused_clone.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
                if sensor_clone.busy_mode() == SensorBusyMode::Idle {
                    // Wait and verify real fingerprint
                    match sensor_clone.verify_fingerprint(&enrolled_slots, 2) {
                        Ok(true) => {
                            // MATCH FOUND
                            let mut guard = pending_ref.lock();
                            if let Some(mut active) = guard.take() {
                                if active.prompt.request_id == req_id {
                                    let chosen_id = active.prompt.selected_credential_id.clone();
                                    if let Some(responder) = active.responder.take() {
                                        let _ = responder.send(Ok(VerificationSuccess {
                                            method: "USB_FINGERPRINT_HARDWARE".to_string(),
                                            selected_credential_id: chosen_id,
                                        }));
                                    }
                                    if remember_pref_clone.load(Ordering::SeqCst) {
                                        session_verified_clone.store(true, Ordering::SeqCst);
                                    }
                                    db_clone.log_auth(
                                        None,
                                        &rp_id_owned,
                                        &op_owned,
                                        "SUCCESS",
                                        "FINGERPRINT_USB",
                                        Some("Authenticated successfully via USB fingerprint sensor (Template match)"),
                                    );
                                    return;
                                } else {
                                    *guard = Some(active);
                                }
                            }
                        }
                        Ok(false) => {
                            // MISMATCH
                            println!("[SECURITY] [REJECT] Fingerprint does not match any enrolled template! REJECTED!");
                            db_clone.log_auth(
                                None,
                                &rp_id_owned,
                                &op_owned,
                                "REJECTED",
                                "FINGERPRINT_USB",
                                Some("Fingerprint verification mismatch (Rejected)"),
                            );
                            std::thread::sleep(Duration::from_millis(500));
                        }
                        Err(_) => {
                            std::thread::sleep(Duration::from_millis(100));
                        }
                    }
                } else {
                    std::thread::sleep(Duration::from_millis(300));
                }
            }
        });

        let result = match tokio::time::timeout(Duration::from_secs(60), rx).await {
            Ok(Ok(res)) => {
                let mut guard = self.pending.lock();
                *guard = None;
                res
            }
            Ok(Err(_)) => {
                let mut guard = self.pending.lock();
                *guard = None;
                Err("Verification session cancelled".to_string())
            }
            Err(_) => {
                let mut guard = self.pending.lock();
                *guard = None;
                Err("Verification timed out (Timeout 60s)".to_string())
            }
        };

        fp_listener.abort();
        result
    }

    pub fn approve_pending(
        &self,
        req_id: u64,
        method: &str,
        input_pin: Option<&str>,
        selected_credential_id: Option<String>,
        remember: Option<bool>,
    ) -> Result<(), String> {
        // The checkbox travels with the approval as well as through /api/verify/remember, so a click
        // that races the toggle still records the user's intent.
        if let Some(enabled) = remember {
            self.remember_requested.store(enabled, Ordering::SeqCst);
        }

        let mut guard = self.pending.lock();
        if let Some(mut active) = guard.take() {
            if active.prompt.request_id != req_id {
                *guard = Some(active);
                return Err("Request ID mismatch".to_string());
            }

            let chosen_cred_id = selected_credential_id.or_else(|| active.prompt.selected_credential_id.clone());

            match method {
                "PIN" => {
                    let pin = input_pin.ok_or_else(|| "PIN not provided".to_string())?;
                    self.verify_pin(pin)?;
                    if let Some(responder) = active.responder.take() {
                        let _ = responder.send(Ok(VerificationSuccess {
                            method: "PIN".to_string(),
                            selected_credential_id: chosen_cred_id,
                        }));
                    }
                    self.remember_session();
                    self.db.log_auth(
                        None,
                        &active.prompt.rp_id,
                        &active.prompt.operation,
                        "SUCCESS",
                        "PIN",
                        Some("Verified 6-digit PIN successfully via Web CMS"),
                    );
                    Ok(())
                }
                "FINGERPRINT" => {
                    let fps = self.db.get_fingerprints().map_err(|e| e.to_string())?;
                    let enrolled_slots: Vec<u32> = fps.iter().map(|f| f.slot_index).collect();
                    if enrolled_slots.is_empty() {
                        *guard = Some(active);
                        return Err("No fingerprints enrolled in the system".into());
                    }

                    if !UsbSensor::is_hardware_plugged() {
                        *guard = Some(active);
                        return Err(
                            "USB fingerprint sensor (3274:8012) is not connected — use the PIN or plug the sensor in".into(),
                        );
                    }

                    if self.fp_manual_active.swap(true, Ordering::SeqCst) {
                        *guard = Some(active);
                        return Err("A fingerprint scan is already running on the USB sensor".into());
                    }

                    // The request stays visible to the CMS while the chip is scanned: the PIN
                    // fallback and `/api/verify/pending` must not sit behind a 15s USB wait.
                    *guard = Some(active);
                    drop(guard);

                    // Stop the background touch listener before touching the chip — it runs its own
                    // scan windows on the same device, and overlapping the two is exactly what made
                    // the on-screen sensor button answer "USB sensor busy" every single time.
                    self.fp_listener_paused.store(true, Ordering::SeqCst);
                    let scan = match self
                        .sensor
                        .wait_until_idle(crate::sensor::OPERATION_TAKEOVER_WAIT)
                    {
                        // The listener's last window may have matched the finger while we waited;
                        // then the request is already answered and there is nothing left to scan.
                        Ok(()) if self.pending_request_id() != Some(req_id) => Ok(true),
                        Ok(()) => {
                            println!("[SECURITY] Waiting for finger press on USB sensor...");
                            self.sensor.verify_fingerprint(&enrolled_slots, 15)
                        }
                        Err(e) => Err(e),
                    };
                    self.fp_listener_paused.store(false, Ordering::SeqCst);
                    self.fp_manual_active.store(false, Ordering::SeqCst);

                    // Another path may have settled the request meanwhile (listener match, PIN,
                    // reject, or the 60s timeout); the WebAuthn result is already decided then.
                    let mut guard = self.pending.lock();
                    let mut active = match guard.take() {
                        Some(a) if a.prompt.request_id == req_id => a,
                        Some(a) => {
                            *guard = Some(a);
                            return Err("Request ID mismatch".to_string());
                        }
                        None => {
                            println!(
                                "[SECURITY] Manual fingerprint approval: request #{} was already settled while the sensor was busy.",
                                req_id
                            );
                            return Ok(());
                        }
                    };

                    match scan {
                        Ok(true) => {
                            println!("[SECURITY] Fingerprint verified successfully!");
                        }
                        Ok(false) => {
                            *guard = Some(active);
                            return Err("Fingerprint DOES NOT MATCH any enrolled template! Request rejected.".into());
                        }
                        Err(e) => {
                            *guard = Some(active);
                            return Err(format!("Fingerprint sensor error: {}", e));
                        }
                    }

                    if let Some(responder) = active.responder.take() {
                        let _ = responder.send(Ok(VerificationSuccess {
                            method: "FINGERPRINT".to_string(),
                            selected_credential_id: chosen_cred_id,
                        }));
                    }
                    self.remember_session();
                    self.db.log_auth(
                        None,
                        &active.prompt.rp_id,
                        &active.prompt.operation,
                        "SUCCESS",
                        "FINGERPRINT",
                        Some("Fingerprint sensor verified successfully (Template match)"),
                    );
                    Ok(())
                }
                "SETUP" => {
                    if let Some(pin) = input_pin {
                        self.set_pin(pin)?;
                    }
                    if let Some(responder) = active.responder.take() {
                        let _ = responder.send(Ok(VerificationSuccess {
                            method: "SETUP".to_string(),
                            selected_credential_id: chosen_cred_id,
                        }));
                    }
                    self.remember_session();
                    self.db.log_auth(
                        None,
                        &active.prompt.rp_id,
                        &active.prompt.operation,
                        "SUCCESS",
                        "SETUP",
                        Some("Initialized new security settings successfully"),
                    );
                    Ok(())
                }

                // Only usable on top of a verification that already happened in this run: pressing
                // Approve in the "remembered" modal sends no PIN and no fingerprint.
                "REMEMBERED" => {
                    if !self.session_verified.load(Ordering::SeqCst) {
                        *guard = Some(active);
                        return Err(
                            "No verified session in this app run — verify with the PIN or the sensor first".into(),
                        );
                    }

                    if let Some(responder) = active.responder.take() {
                        let _ = responder.send(Ok(VerificationSuccess {
                            method: "REMEMBERED".to_string(),
                            selected_credential_id: chosen_cred_id,
                        }));
                    }
                    self.db.log_auth(
                        None,
                        &active.prompt.rp_id,
                        &active.prompt.operation,
                        "SUCCESS",
                        "REMEMBERED",
                        Some("Approved with the remembered session of this app run (no PIN / fingerprint)"),
                    );
                    Ok(())
                }

                _ => {
                    *guard = Some(active);
                    Err("Invalid verification method".to_string())
                }
            }
        } else {
            Err("No pending verification request".to_string())
        }
    }

    pub fn select_account(&self, req_id: u64, credential_id: &str) -> Result<(), String> {
        let mut guard = self.pending.lock();
        if let Some(mut active) = guard.take() {
            if active.prompt.request_id != req_id {
                *guard = Some(active);
                return Err("Request ID mismatch".to_string());
            }

            active.prompt.selected_credential_id = Some(credential_id.to_string());
            *guard = Some(active);
            Ok(())
        } else {
            Err("No pending verification request".to_string())
        }
    }

    pub fn reject_pending(&self, req_id: u64, reason: &str) -> Result<(), String> {
        let mut guard = self.pending.lock();
        if let Some(mut active) = guard.take() {
            if active.prompt.request_id != req_id {
                *guard = Some(active);
                return Err("Request ID mismatch".to_string());
            }

            if let Some(responder) = active.responder.take() {
                let _ = responder.send(Err(format!("Rejected by user: {}", reason)));
            }
            self.db.log_auth(
                None,
                &active.prompt.rp_id,
                &active.prompt.operation,
                "REJECTED",
                "NONE",
                Some(reason),
            );
            Ok(())
        } else {
            Err("No pending verification request".to_string())
        }
    }
}
