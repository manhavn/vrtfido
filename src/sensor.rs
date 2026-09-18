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
const CMD_READ_INDEX: u8 = 0x1F;
const CMD_SEARCH: u8 = 0x66;

pub const ENROLL_TOTAL_STAGES: u32 = 6;
pub const MAX_STAGE_RETRIES: u32 = 10;

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
        let _ = sensor.try_connect();
        sensor
    }

    pub fn is_hardware_plugged() -> bool {
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

    pub fn busy_mode(&self) -> SensorBusyMode {
        *self.busy_mode.lock()
    }

    pub fn cancel_current_op(&self) {
        self.cancel_requested.store(true, Ordering::SeqCst);
        let mut p = self.enroll_progress.lock();
        p.active = false;
        p.status = "error".into();
        p.error = Some("Đã hủy bỏ thao tác".into());
    }

    pub fn get_enroll_progress(&self) -> EnrollProgress {
        self.enroll_progress.lock().clone()
    }

    pub fn try_connect(&self) -> Result<(), String> {
        let mut guard = self.inner.lock();
        if guard.is_some() {
            return Ok(());
        }

        let devices = rusb::devices().map_err(|e| format!("Lỗi liệt kê USB: {}", e))?;
        let mut target = None;
        for dev in devices.iter() {
            if let Ok(desc) = dev.device_descriptor() {
                if desc.vendor_id() == VENDOR_ID && desc.product_id() == PRODUCT_ID {
                    target = Some(dev);
                    break;
                }
            }
        }

        let dev = target.ok_or_else(|| "Không tìm thấy USB cảm biến vân tay (3274:8012)".to_string())?;
        let handle = dev.open().map_err(|e| format!("Không thể mở USB: {}", e))?;

        if let Ok(active) = handle.kernel_driver_active(0) {
            if active {
                let _ = handle.detach_kernel_driver(0);
            }
        }

        handle.claim_interface(0).map_err(|e| format!("Không thể claim interface 0: {}", e))?;

        let _ = handle.write_bulk(EP_OUT, HANDSHAKE_PKT, Duration::from_millis(500));
        let mut resp_buf = [0u8; 64];
        let _ = handle.read_bulk(EP_IN, &mut resp_buf, Duration::from_millis(500));

        *guard = Some(handle);
        println!("[SENSOR] Đã kết nối thành công với cảm biến USB Microarray MAFP (3274:8012)!");
        Ok(())
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
        let mut guard = self.inner.lock();
        if guard.is_none() {
            drop(guard);
            self.try_connect()?;
            guard = self.inner.lock();
        }

        let handle = guard.as_mut().ok_or_else(|| "USB chưa kết nối".to_string())?;
        let pkt = Self::build_packet(cmd);

        handle
            .write_bulk(EP_OUT, &pkt, timeout)
            .map_err(|e| format!("Lỗi ghi USB: {}", e))?;

        let mut resp_buf = [0u8; 64];
        let bytes_read = handle
            .read_bulk(EP_IN, &mut resp_buf, timeout)
            .map_err(|e| format!("Lỗi đọc USB: {}", e))?;

        if bytes_read < 11 {
            return Err("Gói tin phản hồi quá ngắn".into());
        }
        if resp_buf[0] != 0xEF || resp_buf[1] != 0x01 || resp_buf[6] != 0x07 {
            return Err("Gói tin phản hồi không hợp lệ".into());
        }

        let payload_len = (((resp_buf[7] as u16) << 8) | (resp_buf[8] as u16)) as usize;
        if payload_len < 2 || 9 + payload_len > bytes_read {
            return Err("Kích thước payload không hợp lệ".into());
        }

        let data = &resp_buf[9..9 + payload_len - 2];
        Ok(data.to_vec())
    }

    pub fn is_finger_present(&self) -> bool {
        match self.send_command(&[CMD_GET_IMAGE], Duration::from_millis(300)) {
            Ok(data) => !data.is_empty() && data[0] == 0x00,
            Err(_) => false,
        }
    }

    pub fn wait_for_finger_press(&self, timeout_secs: u64) -> Result<bool, String> {
        let start = Instant::now();
        let timeout = Duration::from_secs(timeout_secs);

        while start.elapsed() < timeout {
            if self.cancel_requested.load(Ordering::SeqCst) {
                return Err("Thao tác đã bị hủy".into());
            }
            if self.is_finger_present() {
                return Ok(true);
            }
            sleep(Duration::from_millis(100));
        }
        Err("Hết thời gian chờ chạm ngón tay (Timeout)".into())
    }

    pub fn wait_for_finger_lift(&self, timeout_secs: u64) -> Result<(), String> {
        let start = Instant::now();
        let timeout = Duration::from_secs(timeout_secs);

        while start.elapsed() < timeout {
            if self.cancel_requested.load(Ordering::SeqCst) {
                return Err("Thao tác đã bị hủy".into());
            }
            if !self.is_finger_present() {
                return Ok(());
            }
            sleep(Duration::from_millis(80));
        }
        Ok(())
    }

    pub fn find_free_fid_slot(&self) -> Result<u16, String> {
        let resp = self.send_command(&[CMD_READ_INDEX, 0x00], Duration::from_millis(1000))?;
        if !resp.is_empty() && resp[0] == 0x00 && resp.len() >= 5 {
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
        }
        println!("[SENSOR] Bộ nhớ chip USB đã đầy, đang dọn sạch bằng CMD 0x0D (Empty)...");
        let _ = self.send_command(&[CMD_EMPTY], Duration::from_millis(1500));
        Ok(0)
    }

    pub fn clear_chip_templates(&self) -> Result<(), String> {
        let res = self.send_command(&[CMD_EMPTY], Duration::from_millis(1500))?;
        if !res.is_empty() && res[0] == 0x00 {
            println!("[SENSOR] [+] Đã dọn sạch toàn bộ templates trên chip USB!");
            Ok(())
        } else {
            Err(format!("Lỗi xóa bộ nhớ chip: {:?}", res))
        }
    }

    pub fn enroll_fingerprint_pipeline(&self, preferred_slot: u32) -> Result<u16, String> {
        {
            let mut busy = self.busy_mode.lock();
            if *busy != SensorBusyMode::Idle {
                return Err("Cảm biến USB đang bận xử lý thao tác khác".into());
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
            p.message = format!("Lần 1/{}: Vui lòng chạm ngón tay vào cảm biến USB...", ENROLL_TOTAL_STAGES);
            p.error = None;
        }

        let run_result = self.execute_enroll_stages(preferred_slot);

        {
            let mut p = self.enroll_progress.lock();
            match &run_result {
                Ok(fid) => {
                    p.active = false;
                    p.status = "completed".into();
                    p.message = format!("Đã quét đủ 6 mẫu và lưu vào chip USB slot {}!", fid);
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

    /// Chu trình lấy mẫu 6 bước: NẾU BƯỚC NÀO LỖI THÌ GIỮ NGUYÊN BƯỚC ĐÓ VÀ CHO PHÉP THỬ LẠI!
    fn execute_enroll_stages(&self, preferred_slot: u32) -> Result<u16, String> {
        let _ = self.send_command(&[0x23], Duration::from_millis(500));
        sleep(Duration::from_millis(100));

        let fid = match self.find_free_fid_slot() {
            Ok(s) => s,
            Err(_) => (preferred_slot & 0x1F) as u16,
        };
        println!("[SENSOR] Slot đăng ký trên chip USB: {}", fid);

        let mut current_stage = 1u32;
        let mut retry_count = 0u32;

        while current_stage <= ENROLL_TOTAL_STAGES {
            if self.cancel_requested.load(Ordering::SeqCst) {
                return Err("Đã hủy bỏ quá trình quét vân tay".into());
            }

            // Cập nhật trạng thái chờ chạm ngón tay
            {
                let mut p = self.enroll_progress.lock();
                p.stage = current_stage;
                p.status = "waiting_touch".into();
                if retry_count > 0 {
                    p.message = format!(
                        "Lần {}/{}: Mẫu chưa rõ, vui lòng chạm lại phẳng ngón tay lên cảm biến...",
                        current_stage, ENROLL_TOTAL_STAGES
                    );
                } else {
                    p.message = format!(
                        "Lần {}/{}: Chạm ngón tay vào cảm biến USB...",
                        current_stage, ENROLL_TOTAL_STAGES
                    );
                }
            }
            println!(
                "[ENROLL] Lần {}/{}: Đang chờ chạm ngón tay (Lần thử {}/{})...",
                current_stage, ENROLL_TOTAL_STAGES, retry_count + 1, MAX_STAGE_RETRIES
            );

            // Chờ ngón tay chạm (timeout 30s mỗi lần thử)
            match self.wait_for_finger_press(30) {
                Ok(true) => {}
                _ => {
                    if self.cancel_requested.load(Ordering::SeqCst) {
                        return Err("Đã hủy bỏ".into());
                    }
                    println!("[ENROLL] Chưa phát hiện chạm ngón tay, tiếp tục chờ...");
                    continue;
                }
            }

            // Rút trích đặc trưng GenChar vào slot tương ứng
            let gen_res = self.send_command(&[CMD_GEN_CHAR, current_stage as u8], Duration::from_millis(1000));
            let is_success = match &gen_res {
                Ok(res) => !res.is_empty() && res[0] == 0x00,
                Err(_) => false,
            };

            if is_success {
                // Thành công ở bước này -> tiến lên bước tiếp theo!
                {
                    let mut p = self.enroll_progress.lock();
                    p.status = "finger_lift".into();
                    p.message = format!(
                        "Đã ghi nhận mẫu {}/{}! Hãy nhấc ngón tay ra...",
                        current_stage, ENROLL_TOTAL_STAGES
                    );
                }
                println!(
                    "[ENROLL] [+] Lần {}/{}: Ghi nhận mẫu thành công! Đang chờ nhấc ngón tay...",
                    current_stage, ENROLL_TOTAL_STAGES
                );

                self.wait_for_finger_lift(15)?;
                sleep(Duration::from_millis(250));

                current_stage += 1;
                retry_count = 0;
            } else {
                // Mẫu bị lỗi (do ngón tay lệch, nhấc quá nhanh hoặc cảm biến chưa bắt nét)
                // -> KHÔNG THOÁT! GIỮ NGUYÊN BƯỚC ĐÓ VÀ CHO THỬ LẠI!
                retry_count += 1;
                println!(
                    "[ENROLL] [RETRY] Lần {}/{}: Mẫu chưa đạt chất lượng (Code: {:?}). Đang chờ nhấc ngón để thử lại...",
                    current_stage, ENROLL_TOTAL_STAGES, gen_res
                );

                {
                    let mut p = self.enroll_progress.lock();
                    p.status = "finger_lift".into();
                    p.message = format!(
                        "Mẫu chưa rõ hoặc ngón tay di chuyển! Hãy nhấc ngón tay ra để thử lại lần {}/{}...",
                        current_stage, ENROLL_TOTAL_STAGES
                    );
                }

                self.wait_for_finger_lift(10)?;
                sleep(Duration::from_millis(300));

                if retry_count >= MAX_STAGE_RETRIES {
                    return Err(format!(
                        "Không thể nhận diện mẫu lần {} sau {} lần thử. Vui lòng bấm thử lại.",
                        current_stage, MAX_STAGE_RETRIES
                    ));
                }
            }
        }

        // Đã thu thập đủ 6 mẫu hợp lệ -> Tổng hợp mô hình RegModel (CMD 0x05)
        {
            let mut p = self.enroll_progress.lock();
            p.status = "waiting_touch".into();
            p.message = "Đã thu thập đủ 6 mẫu! Đang tổng hợp dữ liệu vân tay trên chip...".into();
        }
        println!("[ENROLL] Đã thu thập đủ 6 mẫu! Đang gửi lệnh RegModel (CMD 0x05)...");
        let reg_res = self.send_command(&[CMD_REG_MODEL], Duration::from_millis(1500))?;
        if reg_res.is_empty() || reg_res[0] != 0x00 {
            return Err("Lỗi tổng hợp dữ liệu vân tay từ 6 mẫu trên chip".into());
        }

        // Lưu vào bộ nhớ flash trên chip (StoreChar)
        let store_cmd = [CMD_STORE_CHAR, 0x01, (fid >> 8) as u8, (fid & 0xFF) as u8];
        let store_res = self.send_command(&store_cmd, Duration::from_millis(1500))?;

        if store_res.is_empty() || store_res[0] != 0x00 {
            println!("[SENSOR] [RETRY] StoreChar trả về mã {:?}, đang dọn dẹp chip và lưu vào slot 0...", store_res);
            let _ = self.send_command(&[CMD_EMPTY], Duration::from_millis(1500));
            let retry_store = [CMD_STORE_CHAR, 0x01, 0x00, 0x00];
            let retry_res = self.send_command(&retry_store, Duration::from_millis(1500))?;
            if retry_res.is_empty() || retry_res[0] != 0x00 {
                return Err(format!("Lỗi ghi mẫu vào chip USB (code: {:?})", retry_res));
            }
            println!("[SENSOR] [+] Đã hoàn tất đăng ký vân tay vào chip USB slot 0!");
            return Ok(0);
        }

        println!("[SENSOR] [+] Đã hoàn tất đăng ký vân tay vào chip USB slot {}!", fid);
        Ok(fid)
    }

    /// Xác thực vân tay THẬT đối chiếu với danh sách slot đã đăng ký
    pub fn verify_fingerprint(&self, enrolled_slots: &[u32], timeout_secs: u64) -> Result<bool, String> {
        if enrolled_slots.is_empty() {
            return Err("Chưa có vân tay nào được đăng ký trong hệ thống".into());
        }

        {
            let mut busy = self.busy_mode.lock();
            if *busy != SensorBusyMode::Idle {
                return Err("Cảm biến USB đang bận".into());
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
        self.wait_for_finger_press(timeout_secs)?;

        // Rút trích đặc trưng ngón tay vừa chạm vào char-buf slot 1
        let gen_res = self.send_command(&[CMD_GEN_CHAR, 0x01], Duration::from_millis(1000))?;
        if gen_res.is_empty() || gen_res[0] != 0x00 {
            let _ = self.wait_for_finger_lift(5);
            return Err("Không nhận diện được hình ảnh vân tay (Vui lòng chạm lại phẳng ngón)".into());
        }

        // So khớp với TẤT CẢ các slot đã đăng ký bằng lệnh CMD_SEARCH (0x66)
        for &slot_u32 in enrolled_slots {
            let slot = (slot_u32 & 0x1F) as u16;
            let search_cmd = [CMD_SEARCH, (slot >> 8) as u8, (slot & 0xFF) as u8];
            if let Ok(res) = self.send_command(&search_cmd, Duration::from_millis(800)) {
                if !res.is_empty() && res[0] == 0x00 {
                    println!("[SENSOR] [MATCH] >>> VÂN TAY TRÙNG KHỚP VỚI SLOT {} TRÊN CHIP USB! <<<", slot);
                    let _ = self.wait_for_finger_lift(5);
                    return Ok(true);
                } else {
                    println!("[SENSOR] [SEARCH] Slot {}: Không khớp (mã phản hồi: {:?})", slot, res);
                }
            }
        }

        // NẾU TẤT CẢ CÁC SLOT ĐỀU KHÔNG KHỚP -> TUYỆT ĐỐI TỪ CHỐI!
        println!("[SENSOR] [REJECT] >>> VÂN TAY KHÔNG KHỚP VỚI BẤT KỲ MẪU NÀO ĐÃ CÀI ĐẶT! TỪ CHỐI! <<<");
        let _ = self.wait_for_finger_lift(5);
        Ok(false)
    }
}
