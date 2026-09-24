use parking_lot::Mutex;
use rusb::{DeviceHandle, GlobalContext};
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, Instant};

pub const VENDOR_ID: u16 = 0x3274;
pub const PRODUCT_ID: u16 = 0x8012;

const EP_OUT: u8 = 0x03;
const EP_IN: u8 = 0x83;

const CMD_GET_IMAGE: u8 = 0x01;
const CMD_GEN_CHAR: u8 = 0x02;
const CMD_REG_MODEL: u8 = 0x05;
const CMD_STORE_CHAR: u8 = 0x06;
const CMD_EMPTY: u8 = 0x0D;
const CMD_DELETE_CHAR: u8 = 0x0C;
const CMD_READ_INDEX: u8 = 0x1F;
const CMD_SEARCH: u8 = 0x66;

pub const ENROLL_TOTAL_STAGES: u32 = 6;
pub const MAX_STAGE_RETRIES: u32 = 10;
/// A stage only counts once the finger is off the sensor again: the chip builds its model
/// from six independent presses, so sampling the same press twice corrupts the template.
const ENROLL_LIFT_TIMEOUT_SECS: u64 = 60;
/// The timeout of one touch wait. A wait that only ever saw transport errors reports
/// `Unavailable` instead of a plain timeout, so the caller can tell "no finger" apart from
/// "the dongle re-enumerated under us".
const TOUCH_POLL_INTERVAL: Duration = Duration::from_millis(100);
const TOUCH_LIFT_POLL_INTERVAL: Duration = Duration::from_millis(80);
const TOUCH_RETRY_INTERVAL: Duration = Duration::from_millis(500);

/// Result of waiting for the finger to arrive or leave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TouchOutcome {
    /// Finger is on the sensor.
    Touched,
    /// Sensor is clear again.
    Lifted,
    /// The wait expired with the USB link healthy, i.e. nobody touched the sensor.
    TimedOut,
    /// Every poll in the window failed on the USB link (device unplugged / re-enumerating).
    Unavailable(String),
    /// `cancel_current_op` was called.
    Cancelled,
}

static HANDSHAKE_PKT: &[u8] = &[
    0xEF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF,
    0x01, 0x00, 0x02, 0x23, 0xA2,
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SensorBusyMode {
    Idle,
    Enrolling,
    Verifying,
}

#[derive(Serialize, Clone, Debug)]
pub struct EnrollProgress {
    pub active: bool,
    pub stage: u32,
    pub total_stages: u32,
    pub status: String,
    pub message: String,
    pub error: Option<String>,
}

impl Default for EnrollProgress {
    fn default() -> Self {
        Self {
            active: false,
            stage: 0,
            total_stages: ENROLL_TOTAL_STAGES,
            status: "idle".into(),
            message: "".into(),
            error: None,
        }
    }
}

#[derive(Clone)]
pub struct UsbSensor {
    inner: Arc<Mutex<Option<DeviceHandle<GlobalContext>>>>,
    busy_mode: Arc<Mutex<SensorBusyMode>>,
    cancel_requested: Arc<AtomicBool>,
    enroll_progress: Arc<Mutex<EnrollProgress>>,
}

#[allow(dead_code)]
impl UsbSensor {
    pub fn new() -> Self {
        let sensor = Self {
            inner: Arc::new(Mutex::new(None)),
            busy_mode: Arc::new(Mutex::new(SensorBusyMode::Idle)),
            cancel_requested: Arc::new(AtomicBool::new(false)),
            enroll_progress: Arc::new(Mutex::new(EnrollProgress::default())),
        };
        #[cfg(not(target_os = "android"))]
        if let Err(e) = sensor.try_connect() {
            // Not fatal: the module re-enumerates by itself, so every command retries the
            // connection. Say so, otherwise a missing sensor looks like a silent daemon.
            println!("[SENSOR] Fingerprint sensor not available yet: {}", e);
        }
        sensor
    }

    pub fn is_hardware_plugged() -> bool {
        #[cfg(target_os = "android")]
        return false;
        #[cfg(not(target_os = "android"))]
        {
            if let Ok(devices) = rusb::devices() {
                for dev in devices.iter() {
                    if let Ok(desc) = dev.device_descriptor() {
                        if desc.vendor_id() == VENDOR_ID && desc.product_id() == PRODUCT_ID {
                            return true;
                        }
                    }
                }
            }
            false
        }
    }

    pub fn busy_mode(&self) -> SensorBusyMode {
        *self.busy_mode.lock()
    }

    pub fn cancel_current_op(&self) {
        self.cancel_requested.store(true, Ordering::SeqCst);
        let mut p = self.enroll_progress.lock();
        p.active = false;
        p.status = "error".into();
        p.error = Some("Operation cancelled".into());
    }

    pub fn get_enroll_progress(&self) -> EnrollProgress {
        self.enroll_progress.lock().clone()
    }

    pub fn try_connect(&self) -> Result<(), String> {
        let mut guard = self.inner.lock();
        if guard.is_some() {
            return Ok(());
        }

        let devices = rusb::devices().map_err(|e| format!("Failed to list USB devices: {}", e))?;
        let mut target = None;
        for dev in devices.iter() {
            if let Ok(desc) = dev.device_descriptor() {
                if desc.vendor_id() == VENDOR_ID && desc.product_id() == PRODUCT_ID {
                    target = Some(dev);
                    break;
                }
            }
        }

        let dev = target.ok_or_else(|| "USB fingerprint sensor (3274:8012) not found".to_string())?;
        let handle = dev.open().map_err(|e| format!("Failed to open USB device: {}", e))?;

        if let Ok(active) = handle.kernel_driver_active(0) {
            if active {
                let _ = handle.detach_kernel_driver(0);
            }
        }

        handle.claim_interface(0).map_err(|e| format!("Failed to claim interface 0: {}", e))?;

        // The chip only reports touches after it answered this handshake, so arm it on every
        // (re)connect. The confirmation is drained here and the reply is not required: a
        // freshly enumerated device can miss the first write.
        let _ = Self::handshake(&handle);

        *guard = Some(handle);
        println!("[SENSOR] Connected successfully to Microarray MAFP USB sensor (3274:8012)!");
        Ok(())
    }

    /// Vendor arm/keepalive packet, byte for byte the one the module itself sends at connect
    /// time (`0x23` with the `0xA2` trailer). The chip confirms it with `0x23`.
    /// Note `build_packet([0x23])` is *not* the same packet: the chip ignores that framing
    /// completely and it must not be sent before sampling finger touches.
    fn handshake(handle: &DeviceHandle<GlobalContext>) -> Result<(), rusb::Error> {
        handle.write_bulk(EP_OUT, HANDSHAKE_PKT, Duration::from_millis(500))?;
        let mut resp_buf = [0u8; 64];
        let _ = handle.read_bulk(EP_IN, &mut resp_buf, Duration::from_millis(500));
        Ok(())
    }

    /// Re-arm the chip right before sampling. Also re-opens the device when the previous
    /// handle went stale, which happens whenever the module re-enumerates.
    pub fn rearm(&self) -> Result<(), String> {
        let mut guard = self.inner.lock();
        if guard.is_none() {
            drop(guard);
            self.try_connect()?;
            guard = self.inner.lock();
        }

        let handle = guard.as_mut().ok_or_else(|| "USB device not connected".to_string())?;
        let res = Self::handshake(handle);
        drop(guard);

        match res {
            Ok(()) => Ok(()),
            Err(e) => {
                let msg = format!("USB handshake failed: {}", e);
                self.invalidate_handle_if_gone(&e, &msg);
                Err(msg)
            }
        }
    }

    /// Drop the cached handle when the transfer error means the device is gone. The next
    /// command then re-opens the module instead of failing forever on a dead handle.
    fn invalidate_handle_if_gone(&self, err: &rusb::Error, context: &str) {
        if !matches!(
            err,
            rusb::Error::NoDevice | rusb::Error::Pipe | rusb::Error::Io | rusb::Error::NotFound
        ) {
            return;
        }
        let mut guard = self.inner.lock();
        if guard.take().is_some() {
            println!(
                "[SENSOR] [!] {}: {}. Released the stale USB handle; the next command re-opens the sensor.",
                context, err
            );
        }
    }

    fn build_packet(cmd: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0xEF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF]);
        pkt.push(0x01);
        let len = (cmd.len() + 2) as u16;
        pkt.push((len >> 8) as u8);
        pkt.push((len & 0xFF) as u8);
        pkt.extend_from_slice(cmd);

        let mut csum: u16 = 0x01 + (len >> 8) + (len & 0xFF);
        for &b in cmd {
            csum = csum.wrapping_add(b as u16);
        }
        pkt.push((csum >> 8) as u8);
        pkt.push((csum & 0xFF) as u8);
        pkt
    }

    fn send_command(&self, cmd: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
        let trace = std::env::var_os("VRTFIDO_SENSOR_TRACE").is_some();
        let t0 = Instant::now();
        let result = self.send_command_inner(cmd, timeout, trace);
        if trace {
            let ms = t0.elapsed().as_millis();
            match &result {
                Ok(data) => println!(
                    "[TRACE] usb cmd={:02X?} -> ok in {}ms data={:02X?}",
                    cmd, ms, data
                ),
                Err(e) => println!("[TRACE] usb cmd={:02X?} -> ERR in {}ms: {}", cmd, ms, e),
            }
        }
        result
    }

    fn send_command_inner(&self, cmd: &[u8], timeout: Duration, trace: bool) -> Result<Vec<u8>, String> {
        let mut guard = self.inner.lock();
        if guard.is_none() {
            drop(guard);
            self.try_connect()?;
            guard = self.inner.lock();
        }

        let handle = guard.as_mut().ok_or_else(|| "USB device not connected".to_string())?;
        let res = Self::transfer(handle, cmd, timeout, trace);
        drop(guard);

        match res {
            Ok(data) => Ok(data),
            Err((msg, err)) => {
                // The MAFP module drops off the bus on its own (and re-enumerates under a new
                // device node); a cached handle then fails with "No such device" on every later
                // command, which used to look like "finger never detected".
                if let Some(err) = err {
                    self.invalidate_handle_if_gone(&err, &msg);
                }
                Err(msg)
            }
        }
    }

    /// One command/response round trip. `Err` carries the message and, when the USB link itself
    /// broke (as opposed to a chip-level confirmation code), the rusb error behind it.
    fn transfer(
        handle: &DeviceHandle<GlobalContext>,
        cmd: &[u8],
        timeout: Duration,
        trace: bool,
    ) -> Result<Vec<u8>, (String, Option<rusb::Error>)> {
        let pkt = Self::build_packet(cmd);

        if let Err(e) = handle.write_bulk(EP_OUT, &pkt, timeout) {
            return Err((format!("USB write error: {}", e), Some(e)));
        }

        let mut resp_buf = [0u8; 64];
        let bytes_read = match handle.read_bulk(EP_IN, &mut resp_buf, timeout) {
            Ok(n) => n,
            Err(e) => return Err((format!("USB read error: {}", e), Some(e))),
        };

        if trace {
            println!(
                "[TRACE] usb raw bytes_read={} resp={:02X?}",
                bytes_read,
                &resp_buf[..bytes_read.min(64)]
            );
        }

        if bytes_read < 11 {
            return Err(("Response packet too short".into(), None));
        }
        if resp_buf[0] != 0xEF || resp_buf[1] != 0x01 || resp_buf[6] != 0x07 {
            return Err(("Invalid response packet".into(), None));
        }

        let payload_len = (((resp_buf[7] as u16) << 8) | (resp_buf[8] as u16)) as usize;
        if payload_len < 2 || 9 + payload_len > bytes_read {
            return Err(("Invalid payload length".into(), None));
        }

        let data = &resp_buf[9..9 + payload_len - 2];
        Ok(data.to_vec())
    }

    /// A single `GET_IMAGE` poll. `Ok(true)` = finger on the sensor (confirmation code
    /// `0x00`), `Ok(false)` = sensor clear (the chip answers `0x02`), `Err` = the USB link
    /// failed — callers must not read that as "no finger".
    fn poll_finger(&self) -> Result<bool, String> {
        let data = self.send_command(&[CMD_GET_IMAGE], Duration::from_millis(300))?;
        Ok(!data.is_empty() && data[0] == 0x00)
    }

    pub fn wait_for_finger_press(&self, timeout_secs: u64) -> TouchOutcome {
        let start = Instant::now();
        let timeout = Duration::from_secs(timeout_secs);
        let mut link_seen = false;
        let mut last_error = String::new();

        while start.elapsed() < timeout {
            if self.cancel_requested.load(Ordering::SeqCst) {
                return TouchOutcome::Cancelled;
            }
            match self.poll_finger() {
                Ok(true) => return TouchOutcome::Touched,
                Ok(false) => {
                    link_seen = true;
                    sleep(TOUCH_POLL_INTERVAL);
                }
                Err(e) => {
                    // Unplugged or mid-re-enumeration: `send_command` already dropped the dead
                    // handle, so keep polling — the operation resumes once the sensor is back.
                    last_error = e;
                    sleep(TOUCH_RETRY_INTERVAL);
                }
            }
        }

        if link_seen {
            TouchOutcome::TimedOut
        } else {
            TouchOutcome::Unavailable(last_error)
        }
    }

    /// Wait until the sensor is clear again. Unlike the old version this does not give up
    /// silently: the caller has to know that the finger never left the sensor, otherwise the
    /// next stage samples the same press and the stored template is worthless.
    pub fn wait_for_finger_lift(&self, timeout_secs: u64) -> TouchOutcome {
        let start = Instant::now();
        let timeout = Duration::from_secs(timeout_secs);
        let mut link_seen = false;
        let mut last_error = String::new();

        while start.elapsed() < timeout {
            if self.cancel_requested.load(Ordering::SeqCst) {
                return TouchOutcome::Cancelled;
            }
            match self.poll_finger() {
                Ok(false) => return TouchOutcome::Lifted,
                Ok(true) => {
                    link_seen = true;
                    sleep(TOUCH_LIFT_POLL_INTERVAL);
                }
                Err(e) => {
                    last_error = e;
                    sleep(TOUCH_RETRY_INTERVAL);
                }
            }
        }

        if link_seen {
            TouchOutcome::TimedOut
        } else {
            TouchOutcome::Unavailable(last_error)
        }
    }

    pub fn find_free_fid_slot(&self) -> Result<u16, String> {
        let resp = self.send_command(&[CMD_READ_INDEX, 0x00], Duration::from_millis(1000))?;
        if resp.is_empty() || resp[0] != 0x00 || resp.len() < 5 {
            // Never treat an unreadable slot table as "memory full": clearing the chip wipes
            // every enrolled template, so only a valid table may trigger CMD 0x0D below.
            return Err(format!("USB chip did not report its slot table (response: {:?})", resp));
        }

        let bitmap = &resp[1..5];
        for byte_idx in 0..4 {
            let b = bitmap[byte_idx];
            for bit in 0..8 {
                let slot = (byte_idx * 8 + bit) as u16;
                if slot < 30 && (b & (1 << bit)) == 0 {
                    return Ok(slot);
                }
            }
        }

        println!("[SENSOR] USB chip memory full, clearing via CMD 0x0D (Empty)...");
        let _ = self.send_command(&[CMD_EMPTY], Duration::from_millis(1500));
        Ok(0)
    }

    pub fn delete_slot(&self, slot: u32) -> Result<(), String> {
        let fid = (slot & 0x1F) as u16;
        let del_cmd = [CMD_DELETE_CHAR, (fid >> 8) as u8, (fid & 0xFF) as u8, 0x00, 0x01];
        let res = self.send_command(&del_cmd, Duration::from_millis(1500))?;
        if !res.is_empty() && res[0] == 0x00 {
            println!("[SENSOR] [+] Deleted template slot {} from USB chip successfully!", fid);
            Ok(())
        } else {
            Err(format!("Error deleting template slot {} from chip: {:?}", fid, res))
        }
    }

    pub fn clear_chip_templates(&self) -> Result<(), String> {
        let res = self.send_command(&[CMD_EMPTY], Duration::from_millis(1500))?;
        if !res.is_empty() && res[0] == 0x00 {
            println!("[SENSOR] [+] Cleared all templates from USB chip!");
            Ok(())
        } else {
            Err(format!("Error clearing chip memory: {:?}", res))
        }
    }

    pub fn enroll_fingerprint_pipeline(&self, preferred_slot: u32) -> Result<u16, String> {
        {
            let mut busy = self.busy_mode.lock();
            if *busy != SensorBusyMode::Idle {
                return Err("USB sensor busy with another operation".into());
            }
            *busy = SensorBusyMode::Enrolling;
        }
        self.cancel_requested.store(false, Ordering::SeqCst);

        {
            let mut p = self.enroll_progress.lock();
            p.active = true;
            p.stage = 1;
            p.total_stages = ENROLL_TOTAL_STAGES;
            p.status = "waiting_touch".into();
            p.message = format!("Stage 1/{}: Please place finger on USB sensor...", ENROLL_TOTAL_STAGES);
            p.error = None;
        }

        let run_result = self.execute_enroll_stages(preferred_slot);

        {
            let mut p = self.enroll_progress.lock();
            match &run_result {
                Ok(fid) => {
                    p.active = false;
                    p.status = "completed".into();
                    p.message = format!("Captured 6 stages and saved to USB chip slot {}!", fid);
                    p.error = None;
                }
                Err(err) => {
                    p.active = false;
                    p.status = "error".into();
                    p.error = Some(err.clone());
                }
            }
            let mut busy = self.busy_mode.lock();
            *busy = SensorBusyMode::Idle;
        }

        run_result
    }

    fn set_progress(&self, stage: u32, status: &str, message: &str) {
        let mut p = self.enroll_progress.lock();
        p.stage = stage;
        p.status = status.to_string();
        p.message = message.to_string();
    }

    /// Between two captures the finger has to leave the sensor: the chip builds its model
    /// from six independent presses, so a finger that never lifts would feed the same press
    /// into several stages and the stored template would never match again.
    fn require_lift(&self, context: &str) -> Result<(), String> {
        match self.wait_for_finger_lift(ENROLL_LIFT_TIMEOUT_SECS) {
            TouchOutcome::Lifted => Ok(()),
            TouchOutcome::Cancelled => Err("Fingerprint enrollment cancelled".into()),
            TouchOutcome::Unavailable(e) => Err(format!(
                "USB fingerprint sensor stopped responding after {} ({}). Replug the sensor and try again.",
                context, e
            )),
            TouchOutcome::TimedOut => Err(format!(
                "Finger stayed on the sensor for {}s after {}. Every one of the {} stages needs its own \
                 press — lift your finger and start the enrollment again.",
                ENROLL_LIFT_TIMEOUT_SECS, context, ENROLL_TOTAL_STAGES
            )),
            TouchOutcome::Touched => Err(format!(
                "Unexpected sensor state while waiting for the finger to lift after {}.",
                context
            )),
        }
    }

    /// 6-stage enrollment loop: IF ANY STAGE FAILS, KEEP STAGE AND ALLOW RETRY!
    fn execute_enroll_stages(&self, preferred_slot: u32) -> Result<u16, String> {
        // Re-arm first: the module only reports touches after it answered its handshake, and
        // this also re-opens the device when the handle went stale. The bogus
        // `build_packet([0x23])` that used to sit here is gone — the chip ignores that framing.
        self.rearm()?;

        let fid = match self.find_free_fid_slot() {
            Ok(s) => s,
            Err(e) => {
                println!(
                    "[SENSOR] [WARN] {} — enrolling into the database-selected slot {} instead.",
                    e,
                    preferred_slot & 0x1F
                );
                (preferred_slot & 0x1F) as u16
            }
        };
        println!("[SENSOR] Enrollment slot on USB chip: {}", fid);

        let mut current_stage = 1u32;
        let mut retry_count = 0u32;
        let mut unavailable_windows = 0u32;

        while current_stage <= ENROLL_TOTAL_STAGES {
            if self.cancel_requested.load(Ordering::SeqCst) {
                return Err("Fingerprint enrollment cancelled".into());
            }

            // Update waiting for finger press state
            let prompt = if retry_count > 0 {
                format!(
                    "Stage {}/{}: Image unclear, place the finger flat on the sensor again...",
                    current_stage, ENROLL_TOTAL_STAGES
                )
            } else {
                format!(
                    "Stage {}/{}: Place finger on USB sensor...",
                    current_stage, ENROLL_TOTAL_STAGES
                )
            };
            self.set_progress(current_stage, "waiting_touch", &prompt);
            println!(
                "[ENROLL] Stage {}/{}: Waiting for finger touch (Attempt {}/{})...",
                current_stage, ENROLL_TOTAL_STAGES, retry_count + 1, MAX_STAGE_RETRIES
            );

            // Wait for finger touch (30s timeout per attempt)
            match self.wait_for_finger_press(30) {
                TouchOutcome::Touched => unavailable_windows = 0,
                TouchOutcome::Cancelled => return Err("Cancelled".into()),
                TouchOutcome::Unavailable(err) => {
                    // The module re-enumerates on its own; a dead handle made every poll fail and
                    // the old code reported that as "no finger" forever. Keep polling so a replug
                    // resumes the enrollment, but never hold the sensor slot indefinitely.
                    unavailable_windows += 1;
                    println!("[ENROLL] USB sensor unavailable ({}), still waiting...", err);
                    if unavailable_windows >= 2 {
                        return Err(format!(
                            "USB fingerprint sensor stopped responding ({}). Replug the sensor and try again.",
                            err
                        ));
                    }
                    self.set_progress(
                        current_stage,
                        "waiting_touch",
                        "USB sensor not detected — replug the fingerprint sensor (still waiting)...",
                    );
                    continue;
                }
                TouchOutcome::TimedOut => {
                    println!("[ENROLL] No finger touch detected, continuing to wait...");
                    self.set_progress(
                        current_stage,
                        "waiting_touch",
                        &format!(
                            "Stage {}/{}: No finger detected — place your finger flat on the sensor...",
                            current_stage, ENROLL_TOTAL_STAGES
                        ),
                    );
                    continue;
                }
                TouchOutcome::Lifted => {
                    return Err("Unexpected sensor state while waiting for a touch".into());
                }
            }

            // Extract GenChar features into corresponding slot
            let gen_res = self.send_command(&[CMD_GEN_CHAR, current_stage as u8], Duration::from_millis(1000));
            let is_success = match &gen_res {
                Ok(res) => !res.is_empty() && res[0] == 0x00,
                Err(_) => false,
            };

            if is_success {
                // Stage succeeded -> advance to next stage!
                self.set_progress(
                    current_stage,
                    "finger_lift",
                    &format!(
                        "Captured stage {}/{}! Please lift your finger...",
                        current_stage, ENROLL_TOTAL_STAGES
                    ),
                );
                println!(
                    "[ENROLL] [+] Stage {}/{}: Stage captured successfully! Waiting for finger lift...",
                    current_stage, ENROLL_TOTAL_STAGES
                );

                self.require_lift(&format!("stage {}", current_stage))?;
                sleep(Duration::from_millis(250));

                current_stage += 1;
                retry_count = 0;
            } else {
                // Sample error -> DO NOT EXIT! Keep current stage and retry!
                // (due to skewed finger, lifting too fast, or sensor blur)
                retry_count += 1;
                println!(
                    "[ENROLL] [RETRY] Stage {}/{}: Quality insufficient (Code: {:?}). Waiting for finger lift to retry...",
                    current_stage, ENROLL_TOTAL_STAGES, gen_res
                );

                self.set_progress(
                    current_stage,
                    "finger_lift",
                    &format!(
                        "Image unclear or finger moved! Please lift finger to retry stage {}/{}...",
                        current_stage, ENROLL_TOTAL_STAGES
                    ),
                );

                self.require_lift(&format!("the failed capture of stage {}", current_stage))?;
                sleep(Duration::from_millis(300));

                if retry_count >= MAX_STAGE_RETRIES {
                    return Err(format!(
                        "Failed to recognize stage {} after {} attempts. Please try again.",
                        current_stage, MAX_STAGE_RETRIES
                    ));
                }
            }
        }

        // Collected all 6 stages -> Synthesize RegModel (CMD 0x05)
        {
            let mut p = self.enroll_progress.lock();
            p.status = "waiting_touch".into();
            p.message = "Collected 6 stages! Synthesizing fingerprint model on chip...".into();
        }
        println!("[ENROLL] Collected 6 stages! Sending RegModel command (CMD 0x05)...");
        let reg_res = self.send_command(&[CMD_REG_MODEL], Duration::from_millis(1500))?;
        if reg_res.is_empty() || reg_res[0] != 0x00 {
            return Err("Failed to synthesize fingerprint model from 6 stages on chip".into());
        }

        // Store into flash memory on chip (StoreChar)
        let store_cmd = [CMD_STORE_CHAR, 0x01, (fid >> 8) as u8, (fid & 0xFF) as u8];
        let store_res = self.send_command(&store_cmd, Duration::from_millis(1500))?;

        if store_res.is_empty() || store_res[0] != 0x00 {
            println!("[SENSOR] [RETRY] StoreChar returned code {:?}, cleaning chip and storing in slot 0...", store_res);
            let _ = self.send_command(&[CMD_EMPTY], Duration::from_millis(1500));
            let retry_store = [CMD_STORE_CHAR, 0x01, 0x00, 0x00];
            let retry_res = self.send_command(&retry_store, Duration::from_millis(1500))?;
            if retry_res.is_empty() || retry_res[0] != 0x00 {
                return Err(format!("Failed to write template to USB chip (code: {:?})", retry_res));
            }
            println!("[SENSOR] [+] Completed fingerprint enrollment to USB chip slot 0!");
            return Ok(0);
        }

        println!("[SENSOR] [+] Completed fingerprint enrollment to USB chip slot {}!", fid);
        Ok(fid)
    }

    /// Verify fingerprint against list of enrolled slots
    pub fn verify_fingerprint(&self, enrolled_slots: &[u32], timeout_secs: u64) -> Result<bool, String> {
        if enrolled_slots.is_empty() {
            return Err("No fingerprints enrolled in the system".into());
        }

        {
            let mut busy = self.busy_mode.lock();
            if *busy != SensorBusyMode::Idle {
                return Err("USB sensor busy".into());
            }
            *busy = SensorBusyMode::Verifying;
        }

        let res = self.execute_verification(enrolled_slots, timeout_secs);

        {
            let mut busy = self.busy_mode.lock();
            *busy = SensorBusyMode::Idle;
        }
        res
    }

    fn execute_verification(&self, enrolled_slots: &[u32], timeout_secs: u64) -> Result<bool, String> {
        match self.wait_for_finger_press(timeout_secs) {
            TouchOutcome::Touched => {}
            TouchOutcome::Cancelled => return Err("Fingerprint verification cancelled".into()),
            TouchOutcome::Unavailable(e) => {
                return Err(format!(
                    "USB fingerprint sensor not responding ({}). Replug the sensor and try again.",
                    e
                ));
            }
            TouchOutcome::TimedOut => return Err("Finger touch timed out".into()),
            TouchOutcome::Lifted => {
                return Err("Unexpected sensor state while waiting for a touch".into());
            }
        }

        // Extract touched finger features into char-buf slot 1
        let gen_res = self.send_command(&[CMD_GEN_CHAR, 0x01], Duration::from_millis(1000))?;
        if gen_res.is_empty() || gen_res[0] != 0x00 {
            let _ = self.wait_for_finger_lift(5);
            return Err("Failed to capture fingerprint image (Please place finger flat on sensor)".into());
        }

        // Match against ALL enrolled slots with CMD_SEARCH (0x66)
        for &slot_u32 in enrolled_slots {
            let slot = (slot_u32 & 0x1F) as u16;
            let search_cmd = [CMD_SEARCH, (slot >> 8) as u8, (slot & 0xFF) as u8];
            if let Ok(res) = self.send_command(&search_cmd, Duration::from_millis(800)) {
                if !res.is_empty() && res[0] == 0x00 {
                    println!("[SENSOR] [MATCH] >>> FINGERPRINT MATCHED SLOT {} ON USB CHIP! <<<", slot);
                    let _ = self.wait_for_finger_lift(5);
                    return Ok(true);
                } else {
                    println!("[SENSOR] [SEARCH] Slot {}: No match (response code: {:?})", slot, res);
                }
            }
        }

        // IF ALL SLOTS MISMATCH -> REJECT!
        println!("[SENSOR] [REJECT] >>> FINGERPRINT DOES NOT MATCH ANY ENROLLED TEMPLATE! REJECTED! <<<");
        let _ = self.wait_for_finger_lift(5);
        Ok(false)
    }
}
