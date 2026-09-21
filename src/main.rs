mod db;
mod security;
mod sensor;
mod web;
use ciborium::Value;
use db::Db;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::Generate;
use security::SecurityEngine;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::process::Command;
use std::mem::{size_of, zeroed};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use web::AppState;

// --- 1. Linux Kernel UHID ABI ---
pub const UHID_START: u32 = 2;
pub const UHID_STOP: u32 = 3;
pub const UHID_OPEN: u32 = 4;
pub const UHID_CLOSE: u32 = 5;
pub const UHID_OUTPUT: u32 = 6;
pub const UHID_GET_REPORT: u32 = 9;
pub const UHID_GET_REPORT_REPLY: u32 = 10;
pub const UHID_CREATE2: u32 = 11;
pub const UHID_INPUT2: u32 = 12;
pub const UHID_SET_REPORT: u32 = 13;
pub const UHID_SET_REPORT_REPLY: u32 = 14;

pub const BUS_USB: u16 = 3;

#[repr(C, packed)]
pub struct UhidCreate2Req {
    pub name: [u8; 128],
    pub phys: [u8; 64],
    pub uniq: [u8; 64],
    pub rd_size: u16,
    pub bus: u16,
    pub vendor: u32,
    pub product: u32,
    pub version: u32,
    pub country: u32,
    pub rd_data: [u8; 4096],
}

#[repr(C, packed)]
pub struct UhidInput2Req {
    pub size: u16,
    pub data: [u8; 4096],
}

#[repr(C, packed)]
pub struct UhidOutputReq {
    pub data: [u8; 4096],
    pub size: u16,
    pub rtype: u8,
}

#[repr(C, packed)]
pub struct UhidGetReportReq {
    pub id: u32,
    pub rnum: u8,
    pub rtype: u8,
}

#[repr(C, packed)]
pub struct UhidGetReportReplyReq {
    pub id: u32,
    pub err: u16,
    pub size: u16,
    pub data: [u8; 4096],
}

#[repr(C, packed)]
pub struct UhidSetReportReq {
    pub id: u32,
    pub rnum: u8,
    pub rtype: u8,
    pub size: u16,
    pub data: [u8; 4096],
}

#[repr(C, packed)]
pub struct UhidSetReportReplyReq {
    pub id: u32,
    pub err: u16,
}

#[repr(C)]
pub union UhidEventUnion {
    pub create2: std::mem::ManuallyDrop<UhidCreate2Req>,
    pub output: std::mem::ManuallyDrop<UhidOutputReq>,
    pub input2: std::mem::ManuallyDrop<UhidInput2Req>,
    pub get_report: std::mem::ManuallyDrop<UhidGetReportReq>,
    pub get_report_reply: std::mem::ManuallyDrop<UhidGetReportReplyReq>,
    pub set_report: std::mem::ManuallyDrop<UhidSetReportReq>,
    pub set_report_reply: std::mem::ManuallyDrop<UhidSetReportReplyReq>,
    pub raw: [u8; 4376],
}

#[repr(C)]
pub struct UhidEvent {
    pub event_type: u32,
    pub u: UhidEventUnion,
}

// Chuẩn FIDO Alliance HID Report Descriptor (34 bytes, 64-byte IN/OUT reports)
pub const FIDO_REPORT_DESC: &[u8] = &[
    0x06, 0xd0, 0xf1, // USAGE_PAGE (FIDO Alliance)
    0x09, 0x01,       // USAGE (U2F / FIDO Authenticator)
    0xa1, 0x01,       // COLLECTION (Application)
    0x09, 0x20,       //   USAGE (Input Report Data)
    0x15, 0x00,       //   LOGICAL_MINIMUM (0)
    0x26, 0xff, 0x00, //   LOGICAL_MAXIMUM (255)
    0x75, 0x08,       //   REPORT_SIZE (8)
    0x95, 0x40,       //   REPORT_COUNT (64)
    0x81, 0x02,       //   INPUT (Data,Var,Abs)
    0x09, 0x21,       //   USAGE (Output Report Data)
    0x15, 0x00,       //   LOGICAL_MINIMUM (0)
    0x26, 0xff, 0x00, //   LOGICAL_MAXIMUM (255)
    0x75, 0x08,       //   REPORT_SIZE (8)
    0x95, 0x40,       //   REPORT_COUNT (64)
    0x91, 0x02,       //   OUTPUT (Data,Var,Abs)
    0xc0,             // END_COLLECTION
];

pub struct UhidDevice {
    file: File,
}

impl UhidDevice {
    pub fn open() -> std::io::Result<Self> {
        let mut file = match OpenOptions::new().read(true).write(true).open("/dev/uhid") {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied || e.kind() == std::io::ErrorKind::NotFound => {
                if ensure_uhid_permission() {
                    OpenOptions::new().read(true).write(true).open("/dev/uhid")?
                } else {
                    return Err(e);
                }
            }
            Err(e) => return Err(e),
        };

        let mut ev: UhidEvent = unsafe { zeroed() };
        ev.event_type = UHID_CREATE2;
        unsafe {
            let req = &mut *ev.u.create2;
            let name = b"vrtfido - Virtual FIDO2 Authenticator";
            req.name[..name.len()].copy_from_slice(name);
            req.bus = BUS_USB;
            req.vendor = 0x1234;
            req.product = 0x5678;
            req.version = 1;
            req.rd_size = FIDO_REPORT_DESC.len() as u16;
            req.rd_data[..FIDO_REPORT_DESC.len()].copy_from_slice(FIDO_REPORT_DESC);
        }

        let slice = unsafe {
            std::slice::from_raw_parts(&ev as *const _ as *const u8, size_of::<UhidEvent>())
        };
        file.write_all(slice)?;
        file.flush()?;

        Ok(Self { file })
    }

    pub fn read_event(&mut self) -> std::io::Result<UhidEvent> {
        let mut ev: UhidEvent = unsafe { zeroed() };
        let slice = unsafe {
            std::slice::from_raw_parts_mut(&mut ev as *mut _ as *mut u8, size_of::<UhidEvent>())
        };
        self.file.read_exact(slice)?;
        Ok(ev)
    }

    pub fn write_event(&mut self, ev: &UhidEvent) -> std::io::Result<()> {
        let slice = unsafe {
            std::slice::from_raw_parts(ev as *const _ as *const u8, size_of::<UhidEvent>())
        };
        self.file.write_all(slice)?;
        self.file.flush()?;
        Ok(())
    }

    pub fn send_report(&mut self, report: &[u8; 64]) -> std::io::Result<()> {
        let mut ev: UhidEvent = unsafe { zeroed() };
        ev.event_type = UHID_INPUT2;
        unsafe {
            let req = &mut *ev.u.input2;
            req.size = 64;
            req.data[..64].copy_from_slice(report);
        }
        self.write_event(&ev)
    }
}

/// Kiểm tra xem /dev/uhid có thể truy cập (read + write) không.
/// Nếu chưa có quyền, tự động gọi sudo/pkexec để nạp module và cấp quyền chmod 666.
pub fn ensure_uhid_permission() -> bool {
    // 1. Kiểm tra nếu đã mở được /dev/uhid với quyền read + write
    if OpenOptions::new().read(true).write(true).open("/dev/uhid").is_ok() {
        return true;
    }

    println!("[UHID] [!] Chưa có quyền truy cập /dev/uhid.");
    println!("[UHID] [*] Đang tự động yêu cầu cấp quyền qua sudo...");

    // Nạp kernel module uhid nếu chưa nạp và cấp quyền đọc/ghi
    let cmd_str = "modprobe uhid 2>/dev/null || true; chmod 666 /dev/uhid";

    // 2. Ưu tiên chạy sudo (hoạt động tốt trong terminal)
    let sudo_status = Command::new("sudo")
        .args(["sh", "-c", cmd_str])
        .status();

    let success = match sudo_status {
        Ok(s) if s.success() => true,
        _ => {
            // Nếu sudo thất bại hoặc không có TTY, thử qua pkexec (GUI dialog trên Linux Desktop)
            if std::env::var("DISPLAY").is_ok() || std::env::var("WAYLAND_DISPLAY").is_ok() {
                if let Ok(pk_status) = Command::new("pkexec")
                    .args(["sh", "-c", cmd_str])
                    .status()
                {
                    pk_status.success()
                } else {
                    false
                }
            } else {
                false
            }
        }
    };

    if success {
        if OpenOptions::new().read(true).write(true).open("/dev/uhid").is_ok() {
            println!("[UHID] [+] Đã cấp quyền truy cập /dev/uhid thành công!");
            return true;
        }
    }

    eprintln!("[UHID] [-] Không thể tự động cấp quyền cho /dev/uhid qua sudo.");
    eprintln!("[UHID] [!] Bạn có thể cấp quyền thủ công bằng lệnh:");
    eprintln!("          sudo chmod 666 /dev/uhid");
    eprintln!("       hoặc cấu hình udev rule vĩnh viễn (khuyên dùng):");
    eprintln!("          echo 'KERNEL==\"uhid\", MODE=\"0666\"' | sudo tee /etc/udev/rules.d/99-uhid.rules");
    eprintln!("          sudo udevadm control --reload-rules && sudo udevadm trigger");
    false
}

// --- 2. CTAPHID Framing & Reassembly ---
pub const CTAPHID_CMD_PING: u8 = 0x81;
pub const CTAPHID_CMD_INIT: u8 = 0x86;
pub const CTAPHID_CMD_CBOR: u8 = 0x90;

struct IncomingMessage {
    cid: u32,
    cmd: u8,
    total_len: usize,
    payload: Vec<u8>,
    next_seq: u8,
}

struct CtaphidParser {
    pending: Option<IncomingMessage>,
}

impl CtaphidParser {
    fn new() -> Self {
        Self { pending: None }
    }

    fn process_packet(&mut self, pkt: &[u8; 64]) -> Option<(u32, u8, Vec<u8>)> {
        let cid = u32::from_be_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);
        let b4 = pkt[4];

        if b4 & 0x80 != 0 {
            let cmd = b4;
            let total_len = u16::from_be_bytes([pkt[5], pkt[6]]) as usize;
            let chunk_len = total_len.min(57);
            let payload = pkt[7..7 + chunk_len].to_vec();

            if payload.len() == total_len {
                self.pending = None;
                Some((cid, cmd, payload))
            } else {
                self.pending = Some(IncomingMessage {
                    cid,
                    cmd,
                    total_len,
                    payload,
                    next_seq: 0,
                });
                None
            }
        } else {
            let seq = b4;
            if let Some(mut msg) = self.pending.take() {
                if msg.cid == cid && seq == msg.next_seq {
                    let needed = msg.total_len - msg.payload.len();
                    let chunk_len = needed.min(59);
                    msg.payload.extend_from_slice(&pkt[5..5 + chunk_len]);
                    msg.next_seq += 1;

                    if msg.payload.len() == msg.total_len {
                        Some((msg.cid, msg.cmd, msg.payload))
                    } else {
                        self.pending = Some(msg);
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        }
    }
}

pub fn frame_response(cid: u32, cmd: u8, payload: &[u8]) -> Vec<[u8; 64]> {
    let mut packets = Vec::new();
    let total_len = payload.len();

    let mut init_pkt = [0u8; 64];
    init_pkt[0..4].copy_from_slice(&cid.to_be_bytes());
    init_pkt[4] = cmd | 0x80;
    init_pkt[5..7].copy_from_slice(&(total_len as u16).to_be_bytes());

    let chunk1_len = total_len.min(57);
    init_pkt[7..7 + chunk1_len].copy_from_slice(&payload[..chunk1_len]);
    packets.push(init_pkt);

    let mut offset = chunk1_len;
    let mut seq = 0u8;
    while offset < total_len {
        let mut cont_pkt = [0u8; 64];
        cont_pkt[0..4].copy_from_slice(&cid.to_be_bytes());
        cont_pkt[4] = seq;

        let chunk_len = (total_len - offset).min(59);
        cont_pkt[5..5 + chunk_len].copy_from_slice(&payload[offset..offset + chunk_len]);
        packets.push(cont_pkt);

        offset += chunk_len;
        seq += 1;
    }

    packets
}

// --- 3. CTAP2 Logic with SQLite & SecurityEngine ---
static NEXT_CID: AtomicU32 = AtomicU32::new(0x10203040);

fn handle_cbor(
    db: &Db,
    security: &SecurityEngine,
    tokio_handle: &tokio::runtime::Handle,
    debug_mode: bool,
    payload: &[u8],
) -> Vec<u8> {
    if payload.is_empty() {
        return vec![0x01]; // CTAP1_ERR_INVALID_COMMAND
    }
    let ctap2_cmd = payload[0];

    match ctap2_cmd {
        // 0x04: authenticatorGetInfo
        0x04 => {
            if debug_mode {
                println!("[CTAP2] Nhận lệnh: authenticatorGetInfo");
                db.log_debug("DEBUG", "CTAP2", "authenticatorGetInfo request received");
            }

            let options = vec![
                (Value::Text("rk".into()), Value::Bool(true)), // Passkey / Resident Key
                (Value::Text("up".into()), Value::Bool(true)), // User Presence
                (Value::Text("uv".into()), Value::Bool(true)), // User Verification
            ];
            let info_map = vec![
                (
                    Value::Integer(1.into()),
                    Value::Array(vec![
                        Value::Text("FIDO_2_0".into()),
                        Value::Text("FIDO_2_1".into()),
                    ]),
                ),
                (Value::Integer(3.into()), Value::Bytes(vec![0u8; 16])), // AAGUID
                (Value::Integer(4.into()), Value::Map(options)),
                (Value::Integer(5.into()), Value::Integer(1200.into())), // maxMsgSize
            ];

            let mut out = vec![0x00]; // CTAP2_OK
            ciborium::into_writer(&Value::Map(info_map), &mut out).unwrap();
            out
        }

        // 0x01: authenticatorMakeCredential (Đăng ký WebAuthn)
        0x01 => {
            println!("\n[CTAP2] =================== YÊU CẦU ĐĂNG KÝ WEBAUTHN MỚI ===================");

            let mut rp_id = "webauthn.io".to_string();
            let mut user_name = "User".to_string();
            let mut user_display_name = "User".to_string();
            let mut user_id = vec![0u8; 16];

            if let Ok(Value::Map(entries)) = ciborium::from_reader(&payload[1..]) {
                for (k, v) in entries {
                    if k == Value::Integer(2.into()) {
                        // RP Map
                        if let Value::Map(rp_map) = v {
                            for (rk, rv) in rp_map {
                                if rk == Value::Text("id".to_string()) {
                                    if let Value::Text(id_str) = rv {
                                        rp_id = id_str;
                                    }
                                }
                            }
                        }
                    } else if k == Value::Integer(3.into()) {
                        // User Map
                        if let Value::Map(user_map) = v {
                            for (uk, uv) in user_map {
                                if uk == Value::Text("name".to_string()) {
                                    if let Value::Text(s) = uv {
                                        user_name = s;
                                    }
                                } else if uk == Value::Text("displayName".to_string()) {
                                    if let Value::Text(s) = uv {
                                        user_display_name = s;
                                    }
                                } else if uk == Value::Text("id".to_string()) {
                                    if let Value::Bytes(b) = uv {
                                        user_id = b;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            println!("[CTAP2] Relying Party (Domain): {}", rp_id);
            println!("[CTAP2] Tài khoản: {} ({})", user_name, user_display_name);

            if debug_mode {
                db.log_debug(
                    "DEBUG",
                    "CTAP2",
                    &format!("MakeCredential for RP: {}, User: {}", rp_id, user_name),
                );
            }

            // GỌI XÁC THỰC NGƯỜI DÙNG QUA SECURITY ENGINE (Web CMS sẽ hiển thị modal xác nhận)
            println!("[SECURITY] Đang chờ xác nhận từ Web CMS (http://localhost:10209)...");
            let verify_result = tokio_handle.block_on(security.request_user_verification(
                &rp_id,
                "MakeCredential",
                &user_name,
            ));

            let auth_method = match verify_result {
                Ok(method) => {
                    println!("[SECURITY] Xác thực thành công bằng phương thức: {}", method);
                    method
                }
                Err(err) => {
                    println!("[SECURITY] Xác thực thất bại / bị từ chối: {}", err);
                    db.log_auth(
                        None,
                        &rp_id,
                        "MakeCredential",
                        "REJECTED",
                        "NONE",
                        Some(&err),
                    );
                    return vec![0x27]; // CTAP2_ERR_OPERATION_DENIED
                }
            };

            // Sinh khóa P-256 mới
            let signing_key = SigningKey::generate();
            let verifying_key = signing_key.verifying_key();
            let point = verifying_key.to_sec1_point(false);
            let x = point.x().unwrap().to_vec();
            let y = point.y().unwrap().to_vec();

            let cose_key = Value::Map(vec![
                (Value::Integer(1.into()), Value::Integer(2.into())),    // kty: EC2
                (Value::Integer(3.into()), Value::Integer((-7).into())),   // alg: ES256
                (Value::Integer((-1).into()), Value::Integer(1.into())),   // crv: P-256
                (Value::Integer((-2).into()), Value::Bytes(x)),
                (Value::Integer((-3).into()), Value::Bytes(y)),
            ]);
            let mut cose_bytes = Vec::new();
            ciborium::into_writer(&cose_key, &mut cose_bytes).unwrap();

            // Sinh Credential ID ngẫu nhiên (32 bytes)
            let cred_id: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
            let cred_id_hex = hex::encode(&cred_id);

            // Lưu Credential vào SQLite Database (tự động kiểm tra trùng theo RP và tài khoản để ghi đè)
            let sec1_key_bytes = signing_key.to_bytes();
            let is_update = match db.save_credential(
                &cred_id_hex,
                &rp_id,
                &user_id,
                &user_name,
                &user_display_name,
                sec1_key_bytes.as_slice(),
                &cose_bytes,
                1,
            ) {
                Ok(updated) => updated,
                Err(e) => {
                    eprintln!("[DB] Lỗi lưu credential: {}", e);
                    return vec![0x01];
                }
            };

            // Ghi log audit vào SQLite
            let log_msg = if is_update {
                format!("Cập nhật và ghi đè thành công tài khoản '{}' trên domain '{}'", user_name, rp_id)
            } else {
                format!("Đăng ký thành công tài khoản '{}' trên domain '{}'", user_name, rp_id)
            };
            db.log_auth(
                Some(&cred_id_hex),
                &rp_id,
                "MakeCredential",
                "SUCCESS",
                &auth_method,
                Some(&log_msg),
            );
            // Dựng authenticatorData
            let rp_id_hash = Sha256::digest(rp_id.as_bytes());
            let flags = 0x01 | 0x04 | 0x40; // UP | UV | AT
            let sign_count = 1u32;

            let mut auth_data = Vec::new();
            auth_data.extend_from_slice(&rp_id_hash);
            auth_data.push(flags);
            auth_data.extend_from_slice(&sign_count.to_be_bytes());
            auth_data.extend_from_slice(&[0u8; 16]); // AAGUID
            auth_data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
            auth_data.extend_from_slice(&cred_id);
            auth_data.extend_from_slice(&cose_bytes);

            let resp_map = vec![
                (Value::Integer(1.into()), Value::Text("none".into())),
                (Value::Integer(2.into()), Value::Bytes(auth_data)),
                (Value::Integer(3.into()), Value::Map(vec![])),
            ];

            let mut out = vec![0x00]; // CTAP2_OK
            ciborium::into_writer(&Value::Map(resp_map), &mut out).unwrap();
            if is_update {
                println!("[+] Phát hiện tài khoản '{}' đã tồn tại trên domain '{}' -> Đã cập nhật và ghi đè dữ liệu mới thành công!", user_name, rp_id);
            } else {
                println!("[+] Đăng ký WebAuthn thành công! Đã lưu vào SQLite Database.");
            }
            out
        }

        // 0x02: authenticatorGetAssertion (Đăng nhập WebAuthn)
        0x02 => {
            println!("\n[CTAP2] =================== YÊU CẦU ĐĂNG NHẬP / XÁC THỰC ===================");

            let mut rp_id = "webauthn.io".to_string();
            let mut client_data_hash = vec![0u8; 32];
            let mut allow_list = Vec::new();

            if let Ok(Value::Map(entries)) = ciborium::from_reader(&payload[1..]) {
                for (k, v) in entries {
                    if k == Value::Integer(1.into()) {
                        if let Value::Text(s) = v {
                            rp_id = s;
                        }
                    } else if k == Value::Integer(2.into()) {
                        if let Value::Bytes(b) = v {
                            client_data_hash = b;
                        }
                    } else if k == Value::Integer(3.into()) {
                        if let Value::Array(list) = v {
                            for item in list {
                                if let Value::Map(desc) = item {
                                    for (dk, dv) in desc {
                                        if dk == Value::Text("id".to_string()) {
                                            if let Value::Bytes(cid) = dv {
                                                allow_list.push(hex::encode(&cid));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            println!("[CTAP2] Relying Party (Domain): {}", rp_id);
            if debug_mode {
                db.log_debug(
                    "DEBUG",
                    "CTAP2",
                    &format!("GetAssertion for RP: {}, AllowList: {:?}", rp_id, allow_list),
                );
            }

            // Tìm credential trong SQLite
            let all_creds = db.get_credentials().unwrap_or_default();
            let matched_cred = if !allow_list.is_empty() {
                all_creds
                    .iter()
                    .find(|c| c.rp_id == rp_id && allow_list.contains(&c.id))
                    .cloned()
            } else {
                all_creds.iter().find(|c| c.rp_id == rp_id).cloned()
            };

            let cred = match matched_cred {
                Some(c) => c,
                None => {
                    println!("[-] Không tìm thấy credential trong SQLite cho domain '{}'", rp_id);
                    db.log_auth(
                        None,
                        &rp_id,
                        "GetAssertion",
                        "FAILED",
                        "NONE",
                        Some("Không tìm thấy credential cho RP"),
                    );
                    return vec![0x2e]; // CTAP2_ERR_NO_CREDENTIALS
                }
            };

            println!("[CTAP2] Tìm thấy tài khoản: {} ({})", cred.user_name, cred.user_display_name);

            // GỌI XÁC THỰC NGƯỜI DÙNG QUA SECURITY ENGINE
            println!("[SECURITY] Đang chờ xác nhận từ Web CMS (http://localhost:10209)...");
            let verify_result = tokio_handle.block_on(security.request_user_verification(
                &rp_id,
                "GetAssertion",
                &cred.user_name,
            ));

            let auth_method = match verify_result {
                Ok(method) => {
                    println!("[SECURITY] Xác thực thành công bằng phương thức: {}", method);
                    method
                }
                Err(err) => {
                    println!("[SECURITY] Xác thực thất bại / bị từ chối: {}", err);
                    db.log_auth(
                        Some(&cred.id),
                        &rp_id,
                        "GetAssertion",
                        "REJECTED",
                        "NONE",
                        Some(&err),
                    );
                    return vec![0x27]; // CTAP2_ERR_OPERATION_DENIED
                }
            };

            // Tăng sign_count trong database
            let new_count = db.increment_sign_count(&cred.id).unwrap_or(cred.sign_count + 1);

            // Dựng authenticatorData
            let rp_id_hash = Sha256::digest(rp_id.as_bytes());
            let flags = 0x01 | 0x04; // UP | UV

            let mut auth_data = Vec::new();
            auth_data.extend_from_slice(&rp_id_hash);
            auth_data.push(flags);
            auth_data.extend_from_slice(&new_count.to_be_bytes());

            // Ký message = authData + clientDataHash
            let mut message = Vec::new();
            message.extend_from_slice(&auth_data);
            message.extend_from_slice(&client_data_hash);

            let private_key_bytes = hex::decode(&cred.private_key_sec1_hex).unwrap_or_default();
            let signing_key = match SigningKey::from_slice(&private_key_bytes) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("[CRYPTO] Lỗi khôi phục private key: {}", e);
                    return vec![0x01];
                }
            };

            let (sig, _) = signing_key.sign(&message);
            let der_sig = sig.to_der();

            let cred_id_bytes = hex::decode(&cred.id).unwrap_or_default();
            let cred_descriptor = Value::Map(vec![
                (Value::Text("id".into()), Value::Bytes(cred_id_bytes)),
                (Value::Text("type".into()), Value::Text("public-key".into())),
            ]);

            let resp_map = vec![
                (Value::Integer(1.into()), cred_descriptor),
                (Value::Integer(2.into()), Value::Bytes(auth_data)),
                (Value::Integer(3.into()), Value::Bytes(der_sig.as_bytes().to_vec())),
            ];

            // Ghi log audit thành công
            db.log_auth(
                Some(&cred.id),
                &rp_id,
                "GetAssertion",
                "SUCCESS",
                &auth_method,
                Some(&format!("Xác thực thành công tài khoản '{}' (Counter: {})", cred.user_name, new_count)),
            );

            let mut out = vec![0x00]; // CTAP2_OK
            ciborium::into_writer(&Value::Map(resp_map), &mut out).unwrap();
            println!("[+] Ký Assertion thành công! Đã cập nhật sign_count vào SQLite.");
            out
        }

        _ => {
            if debug_mode {
                println!("[CTAP2] Lệnh chưa hỗ trợ: 0x{:02x}", ctap2_cmd);
                db.log_debug("WARN", "CTAP2", &format!("Unsupported CTAP2 command: 0x{:02x}", ctap2_cmd));
            }
            vec![0x2b] // CTAP2_ERR_UNSUPPORTED_OPTION
        }
    }
}

fn handle_frame(
    dev: &mut UhidDevice,
    parser: &mut CtaphidParser,
    db: &Db,
    security: &SecurityEngine,
    tokio_handle: &tokio::runtime::Handle,
    debug_mode: bool,
    frame: &[u8; 64],
) -> std::io::Result<()> {
    if let Some((cid, cmd, payload)) = parser.process_packet(frame) {
        if cmd == CTAPHID_CMD_INIT {
            let allocated_cid = NEXT_CID.fetch_add(1, Ordering::SeqCst);
            if debug_mode {
                println!("[CTAPHID] INIT -> Cấp CID: 0x{:08x}", allocated_cid);
                db.log_debug("DEBUG", "CTAPHID", &format!("INIT handshake, allocated CID: 0x{:08x}", allocated_cid));
            }

            let mut resp = Vec::new();
            resp.extend_from_slice(&payload);
            resp.extend_from_slice(&allocated_cid.to_be_bytes());
            resp.push(2);
            resp.extend_from_slice(&[1, 0, 0]);
            resp.push(0x04); // CAPFLAG_CBOR

            for f in frame_response(cid, cmd, &resp) {
                dev.send_report(&f)?;
            }
        } else if cmd == CTAPHID_CMD_PING {
            for f in frame_response(cid, cmd, &payload) {
                dev.send_report(&f)?;
            }
        } else if cmd == CTAPHID_CMD_CBOR {
            let cbor_resp = handle_cbor(db, security, tokio_handle, debug_mode, &payload);
            for f in frame_response(cid, cmd, &cbor_resp) {
                dev.send_report(&f)?;
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Phân tích tham số CLI
    let args: Vec<String> = std::env::args().collect();
    let debug_mode = args.iter().any(|a| a == "--debug" || a == "-d");
    let unlimited_fps = args.iter().any(|a| a == "--unlimited-fps" || a == "--unlimited-fingerprints" || a == "-u");

    println!("============================================================");
    println!("             vrtfido - Virtual FIDO2 / WebAuthn CMS         ");
    println!("============================================================");
    if debug_mode {
        println!("[CLI] Chế độ DEBUG: ĐÃ BẬT (--debug)");
    } else {
        println!("[CLI] Chế độ DEBUG: TẮT (Dùng '--debug' nếu muốn xem packet thô)");
    }
    if unlimited_fps {
        println!("[CLI] Chế độ VÂN TAY: KHÔNG GIỚI HẠN (--unlimited-fps)");
    } else {
        println!("[CLI] Chế độ VÂN TAY: GIỚI HẠN 10 (Dùng '--unlimited-fps' để bỏ giới hạn)");
    }

    // 2. Kiểm tra và tự động cấp quyền truy cập /dev/uhid qua sudo nếu chưa có
    println!("[UHID] Kiểm tra quyền truy cập /dev/uhid...");
    ensure_uhid_permission();

    // 3. Khởi tạo SQLite Database
    let db_path = "authenticator.db";
    let db = Db::open(db_path)?;
    println!("[DB] Khởi tạo SQLite thành công: {}", db_path);
    db.log_debug("INFO", "SYSTEM", "Virtual FIDO2 Manager started");

    // 4. Khởi tạo SecurityEngine & AppState
    let sensor = sensor::UsbSensor::new();
    let security = SecurityEngine::new(db.clone(), sensor.clone(), unlimited_fps);
    let debug_mode_arc = Arc::new(AtomicBool::new(debug_mode));
    let uhid_connected = Arc::new(AtomicBool::new(false));

    let app_state = AppState {
        db: db.clone(),
        security: security.clone(),
        debug_mode: debug_mode_arc.clone(),
        uhid_connected: uhid_connected.clone(),
        unlimited_fps,
    };

    // 5. Khởi động Web CMS Server trên cổng 10209
    let app = web::create_router(app_state);
    let port = 10209;
    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("[CMS] Web Management CMS đang chạy tại: http://localhost:{}", port);
    println!("[CMS] Mở trình duyệt truy cập http://localhost:{} để quản lý và duyệt xác thực\n", port);

    // Chạy Web Server trong background task
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            eprintln!("[CMS] Lỗi Web Server: {}", e);
        }
    });

    // 6. Khởi động UHID Daemon trong dedicated thread
    let tokio_handle = tokio::runtime::Handle::current();
    let uhid_flag = uhid_connected.clone();
    let db_uhid = db.clone();
    let security_uhid = security.clone();

    std::thread::spawn(move || {
        println!("[UHID] Đang mở /dev/uhid...");
        let mut dev = match UhidDevice::open() {
            Ok(d) => {
                uhid_flag.store(true, Ordering::SeqCst);
                println!("[UHID] [+] Thiết bị FIDO2 ảo đã được tạo thành công trên Kernel!");
                println!("[UHID] [+] Trình duyệt đã có thể nhận diện USB FIDO2.");
                d
            }
            Err(e) => {
                eprintln!("\n[UHID] [!] LỖI TRUY CẬP /dev/uhid: {}", e);
                eprintln!("[UHID] [!] Hãy chạy 'sudo chmod 666 /dev/uhid' hoặc chạy app với quyền root.");
                db_uhid.log_debug("ERROR", "UHID", &format!("Failed to open /dev/uhid: {}", e));
                return;
            }
        };

        let mut parser = CtaphidParser::new();

        loop {
            let ev = match dev.read_event() {
                Ok(e) => e,
                Err(err) => {
                    eprintln!("[UHID] Lỗi đọc sự kiện kernel: {}", err);
                    break;
                }
            };

            match ev.event_type {
                UHID_START => {
                    if debug_mode {
                        println!("[Kernel] UHID_START");
                    }
                }
                UHID_STOP => {
                    if debug_mode {
                        println!("[Kernel] UHID_STOP");
                    }
                }
                UHID_OPEN => {
                    println!("[Kernel] Ứng dụng đã mở /dev/hidraw");
                }
                UHID_CLOSE => {
                    if debug_mode {
                        println!("[Kernel] Ứng dụng đã đóng /dev/hidraw");
                    }
                }

                // Phản hồi ngay lập tức để kernel không bị block
                UHID_GET_REPORT => {
                    let get_rep = unsafe { &*ev.u.get_report };
                    let req_id = get_rep.id;
                    let mut reply: UhidEvent = unsafe { zeroed() };
                    reply.event_type = UHID_GET_REPORT_REPLY;
                    unsafe {
                        let r = &mut *reply.u.get_report_reply;
                        r.id = req_id;
                        r.err = 0;
                        r.size = 0;
                    }
                    let _ = dev.write_event(&reply);
                }

                UHID_SET_REPORT => {
                    let set_rep = unsafe { &*ev.u.set_report };
                    let req_id = set_rep.id;
                    let rep_size = set_rep.size as usize;
                    let raw_data = &set_rep.data[..rep_size.min(4096)];

                    let pkt_slice = if rep_size == 65 && raw_data[0] == 0 {
                        &raw_data[1..65]
                    } else if rep_size >= 64 {
                        &raw_data[0..64]
                    } else {
                        raw_data
                    };

                    if pkt_slice.len() == 64 {
                        let mut frame = [0u8; 64];
                        frame.copy_from_slice(pkt_slice);
                        let _ = handle_frame(
                            &mut dev,
                            &mut parser,
                            &db_uhid,
                            &security_uhid,
                            &tokio_handle,
                            debug_mode,
                            &frame,
                        );
                    }

                    let mut reply: UhidEvent = unsafe { zeroed() };
                    reply.event_type = UHID_SET_REPORT_REPLY;
                    unsafe {
                        let r = &mut *reply.u.set_report_reply;
                        r.id = req_id;
                        r.err = 0;
                    }
                    let _ = dev.write_event(&reply);
                }

                UHID_OUTPUT => {
                    let out = unsafe { &*ev.u.output };
                    let rep_size = out.size as usize;
                    let raw_data = &out.data[..rep_size.min(4096)];

                    let pkt_slice = if rep_size == 65 && raw_data[0] == 0 {
                        &raw_data[1..65]
                    } else if rep_size >= 64 {
                        &raw_data[0..64]
                    } else {
                        raw_data
                    };

                    if pkt_slice.len() == 64 {
                        let mut frame = [0u8; 64];
                        frame.copy_from_slice(pkt_slice);
                        let _ = handle_frame(
                            &mut dev,
                            &mut parser,
                            &db_uhid,
                            &security_uhid,
                            &tokio_handle,
                            debug_mode,
                            &frame,
                        );
                    }
                }

                _ => {}
            }
        }
    });

    // Giữ tiến trình chính chạy vô hạn
    tokio::signal::ctrl_c().await?;
    println!("\n[!] Nhận tín hiệu dừng (Ctrl+C). Đang tắt ứng dụng...");
    Ok(())
}
