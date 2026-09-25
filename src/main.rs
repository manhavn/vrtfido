mod autostart;
mod db;
mod security;
mod sensor;
mod tray;
mod web;
mod passkey;
use ciborium::Value;
use db::Db;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::Generate;
use security::SecurityEngine;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::path::Path;
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

/// USB ids announced by the virtual FIDO2 device. `uhid` devices have no USB descriptor, so the
/// kernel simply republishes these two numbers as `HID_ID=<bus>:<vendor>:<product>` in sysfs and
/// `udevadm` output - nothing on the authentication path reads them (clients discover the device by
/// the FIDO usage page in the report descriptor and identify it through CTAP2 `authenticatorGetInfo`
/// / the AAGUID).
///
/// They stay project-specific on purpose: reusing a real vendor's ids could make the kernel apply
/// that vendor's HID quirks, and a distinct pair keeps VrtFido recognisable next to a physical
/// authenticator. 0x5652 is "VR" in ASCII, 0xF1D0 is the FIDO usage page.
pub const VIRTUAL_HID_VENDOR_ID: u32 = 0x5652;
pub const VIRTUAL_HID_PRODUCT_ID: u32 = 0xF1D0;

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

// FIDO Alliance HID Report Descriptor (34 bytes, 64-byte IN/OUT reports)
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
            let name = b"VrtFido - Virtual FIDO2 Authenticator";
            req.name[..name.len()].copy_from_slice(name);
            req.bus = BUS_USB;
            req.vendor = VIRTUAL_HID_VENDOR_ID;
            req.product = VIRTUAL_HID_PRODUCT_ID;
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
        // Try pkexec (Polkit graphical authentication dialog)
        if let Ok(pk_status) = Command::new("pkexec")
            .args(["sh", "-c", cmd_str])
            .status()
        {
            if pk_status.success() {
                success = true;
            }
        }

        // Try zenity password dialog if pkexec failed or not available
        if !success && Command::new("which").arg("zenity").output().map(|o| o.status.success()).unwrap_or(false) {
            let zenity_cmd = format!(
                "zenity --password --title=\"VrtFido - Cấp quyền /dev/uhid vĩnh viễn\" | sudo -S sh -c '{}'",
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

    false
}

/// Check if /dev/uhid is accessible (read + write).
/// If permission is missing or permanent rule is not configured, automatically request permission.
pub fn ensure_uhid_permission() -> bool {
    let can_open = OpenOptions::new().read(true).write(true).open("/dev/uhid").is_ok();
    let has_rules = has_permanent_uhid_rule();

    // If /dev/uhid is already accessible AND permanent rule is in place, nothing to do
    if can_open && has_rules {
        return true;
    }

    // If not accessible or missing permanent rules, automatically configure permanent permission
    if !can_open || autostart::is_autostart_enabled() {
        if ensure_permanent_uhid_permission() {
            return true;
        }
    }

    if can_open {
        println!("[UHID] [!] Continuing with session /dev/uhid access.");
        return true;
    }

    eprintln!("[UHID] [-] Could not automatically grant permanent permission for /dev/uhid.");
    eprintln!("[UHID] [!] You can grant permission manually with:");
    eprintln!("          echo 'uhid' | sudo tee /etc/modules-load.d/uhid.conf");
    eprintln!("          echo 'KERNEL==\"uhid\", MODE=\"0666\"' | sudo tee /etc/udev/rules.d/99-uhid.rules");
    eprintln!("          sudo modprobe uhid");
    eprintln!("          sudo udevadm control --reload-rules && sudo udevadm trigger");
    false
}

// --- 2. CTAPHID Framing & Reassembly ---
// Host request opcodes, without the packet-type bit. On the wire byte 4 of an *initial* packet is
// the command with `CTAPHID_INIT_PACKET_BIT` set - browsers set it exactly like devices do
// (Chrome's `FidoHidInitPacket::GetSerializedData` writes `command | 0x80`, so INIT arrives as
// 0x86, CBOR as 0x90 and PING as 0x81), and both directions mask the bit off again
// (`FidoHidInitPacket::CreateFromSerializedData` reads `byte & 0x7f`). Byte 4 must therefore be
// masked before a command is matched, never compared raw: a raw comparison against 0x06 silently
// ignored every request Chrome sent on Linux.
pub const CTAPHID_CMD_PING: u8 = 0x01;
pub const CTAPHID_CMD_INIT: u8 = 0x06;
pub const CTAPHID_CMD_CBOR: u8 = 0x10;
/// Set in byte 4 of an initial packet, clear in continuation packets (which carry a 7-bit sequence
/// number there instead, starting at 0).
const CTAPHID_INIT_PACKET_BIT: u8 = 0x80;
/// Continuation frames carry the sequence number in the command byte, starting at 0.
const CTAPHID_CMD_CONTINUATION: u8 = 0x00;

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

        if let Some(mut msg) = self.pending.take() {
            // A message is still being assembled, so a packet whose byte 4 is the expected 7-bit
            // sequence number continues it.
            if b4 & CTAPHID_INIT_PACKET_BIT == 0 && msg.cid == cid && b4 == msg.next_seq {
                let needed = msg.total_len - msg.payload.len();
                let chunk_len = needed.min(59);
                msg.payload.extend_from_slice(&pkt[5..5 + chunk_len]);
                msg.next_seq += 1;

                if msg.payload.len() == msg.total_len {
                    return Some((msg.cid, msg.cmd, msg.payload));
                }
                self.pending = Some(msg);
                return None;
            }
            if b4 & CTAPHID_INIT_PACKET_BIT == 0 {
                // A continuation frame that does not fit the message being assembled: the partial
                // message is dropped, as the specification requires for a protocol error, and the
                // frame itself carries no command to run.
                return None;
            }
            // Otherwise the packet is an initial one, so the host either abandoned the partial
            // message or another channel started talking: fall through and serve it.
        }

        // Initial packet: cmd | BCNTH | BCNTL | data. The packet-type bit is masked off before the
        // command is matched, so a browser's 0x86/0x90/0x81 and a bare 0x06/0x10/0x01 both work.
        let cmd = b4 & !CTAPHID_INIT_PACKET_BIT;
        if cmd == CTAPHID_CMD_CONTINUATION {
            return None; // a stray continuation frame without a message to continue
        }
        let total_len = u16::from_be_bytes([pkt[5], pkt[6]]) as usize;
        let chunk_len = total_len.min(57);
        let payload = pkt[7..7 + chunk_len].to_vec();

        if payload.len() == total_len {
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
    }
}

pub fn frame_response(cid: u32, cmd: u8, payload: &[u8]) -> Vec<[u8; 64]> {
    let mut packets = Vec::new();
    let total_len = payload.len();

    let mut init_pkt = [0u8; 64];
    init_pkt[0..4].copy_from_slice(&cid.to_be_bytes());
    init_pkt[4] = cmd | CTAPHID_INIT_PACKET_BIT;
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
                println!("[CTAP2] Received command: authenticatorGetInfo");
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
                (Value::Integer(3.into()), Value::Bytes(passkey::AAGUID.to_vec())), // AAGUID
                (Value::Integer(4.into()), Value::Map(options)),
                (Value::Integer(5.into()), Value::Integer(1200.into())), // maxMsgSize
                // CTAP 2.1 transports (key 9). Clients copy this list into the credential they
                // hand to the site: Chromium's `make_credential_task.cc` fills
                // `AuthenticatorMakeCredentialResponse::transports` from `device_info()->transports`,
                // which is this member, so `AuthenticatorAttestationResponse.getTransports()`
                // returns it verbatim.
                (
                    Value::Integer(9.into()),
                    Value::Array(
                        ["ble", "hybrid", "internal", "nfc", "usb"]
                            .into_iter()
                            .map(|t| Value::Text(t.into()))
                            .collect(),
                    ),
                ),
            ];

            let mut out = vec![0x00]; // CTAP2_OK
            ciborium::into_writer(&Value::Map(info_map), &mut out).unwrap();
            out
        }

        // 0x01: authenticatorMakeCredential (WebAuthn Registration)
        0x01 => {
            println!("\n[CTAP2] =================== NEW WEBAUTHN REGISTRATION REQUEST ===================");

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

            let is_dummy_probe = crate::db::Db::is_dummy_probe(&rp_id, &user_name);

            if is_dummy_probe {
                println!("[CTAP2] Relying Party (Domain): {} [BROWSER TOUCH/PRESENCE PROBE]", rp_id);
            } else {
                println!("[CTAP2] Relying Party (Domain): {}", rp_id);
            }
            println!("[CTAP2] Account: {} ({})", user_name, user_display_name);

            if debug_mode {
                db.log_debug(
                    "DEBUG",
                    "CTAP2",
                    &format!("MakeCredential for RP: {}, User: {} (dummy probe: {})", rp_id, user_name, is_dummy_probe),
                );
            }

            let auth_method = if is_dummy_probe {
                println!("[SECURITY] Browser touch/blink presence probe detected ('{}') -> Auto-acknowledged without prompting user or saving to database.", rp_id);
                "INTERNAL_PROBE".to_string()
            } else {
                // Request user verification via SecurityEngine (Web CMS will show confirmation modal)
                println!("[SECURITY] Waiting for confirmation from Web CMS (http://localhost:10209)...");
                let verify_result = tokio_handle.block_on(security.request_user_verification(
                    &rp_id,
                    "MakeCredential",
                    &user_name,
                ));

                match verify_result {
                    Ok(method) => {
                        println!("[SECURITY] Verification succeeded using method: {}", method);
                        method
                    }
                    Err(err) => {
                        println!("[SECURITY] Verification failed / rejected: {}", err);
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
                }
            };
            // Generate new P-256 key
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

            // Generate random Credential ID (32 bytes)
            let cred_id: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
            let cred_id_hex = hex::encode(&cred_id);

            // Save Credential to database (only for legitimate sites, skip dummy probes)
            let is_update = if !is_dummy_probe {
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
                        eprintln!("[DB] Error saving credential: {}", e);
                        return vec![0x01];
                    }
                };

                // Write audit log to database
                let log_msg = if is_update {
                    format!("Updated and overwrote credential for account '{}' on domain '{}'", user_name, rp_id)
                } else {
                    format!("Registered credential for account '{}' on domain '{}'", user_name, rp_id)
                };
                db.log_auth(
                    Some(&cred_id_hex),
                    &rp_id,
                    "MakeCredential",
                    "SUCCESS",
                    &auth_method,
                    Some(&log_msg),
                );
                is_update
            } else {
                false
            };
            // Build authenticatorData
            let rp_id_hash = Sha256::digest(rp_id.as_bytes());
            let flags = 0x01 | 0x04 | 0x40; // UP | UV | AT
            let sign_count = 1u32;

            let mut auth_data = Vec::new();
            auth_data.extend_from_slice(&rp_id_hash);
            auth_data.push(flags);
            auth_data.extend_from_slice(&sign_count.to_be_bytes());
            auth_data.extend_from_slice(&passkey::AAGUID); // AAGUID
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
            if is_dummy_probe {
                println!("[+] Handled browser touch/blink probe successfully (not saved to database).");
            } else if is_update {
                println!("[+] Account '{}' already exists on domain '{}' -> Updated and overwrote with new data!", user_name, rp_id);
            } else {
                println!("[+] WebAuthn registration successful! Saved to database.");
            }
            out
        }

        // 0x02: authenticatorGetAssertion (WebAuthn Sign-in)
        0x02 => {
            println!("\n[CTAP2] =================== SIGN-IN / AUTHENTICATION REQUEST ===================");

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

            // Find credential in database
            let all_creds = db.get_credentials().unwrap_or_default();
            let (cred, is_user_specified) = if !allow_list.is_empty() {
                let found = all_creds
                    .iter()
                    .find(|c| c.rp_id.eq_ignore_ascii_case(&rp_id) && allow_list.contains(&c.id))
                    .cloned();
                (found, true)
            } else {
                let rp_creds: Vec<_> = all_creds
                    .iter()
                    .filter(|c| c.rp_id.eq_ignore_ascii_case(&rp_id))
                    .cloned()
                    .collect();
                (rp_creds.first().cloned(), false)
            };

            let initial_cred = match cred {
                Some(c) => c,
                None => {
                    println!("[-] Credential not found in database for domain '{}'", rp_id);
                    db.log_auth(
                        None,
                        &rp_id,
                        "GetAssertion",
                        "FAILED",
                        "NONE",
                        Some("Credential not found for RP"),
                    );
                    return vec![0x2e]; // CTAP2_ERR_NO_CREDENTIALS
                }
            };

            // Build account list if RP did not specify a user (allow_list is empty)
            let (accounts_list, default_cred_id) = if !is_user_specified {
                let rp_creds: Vec<_> = all_creds
                    .iter()
                    .filter(|c| c.rp_id.eq_ignore_ascii_case(&rp_id))
                    .cloned()
                    .collect();
                let list: Vec<crate::security::PendingAccountOption> = rp_creds
                    .iter()
                    .map(|c| crate::security::PendingAccountOption {
                        id: c.id.clone(),
                        user_name: c.user_name.clone(),
                        user_display_name: c.user_display_name.clone(),
                        last_used_at: c.last_used_at.clone(),
                        created_at: c.created_at.clone(),
                    })
                    .collect();
                let default_id = rp_creds.first().map(|c| c.id.clone());
                (list, default_id)
            } else {
                (Vec::new(), None)
            };

            println!("[CTAP2] Found account: {} ({})", initial_cred.user_name, initial_cred.user_display_name);

            // Request user verification via SecurityEngine
            println!("[SECURITY] Waiting for confirmation from Web CMS (http://localhost:10209)...");
            let verify_result = tokio_handle.block_on(security.request_user_verification_with_accounts(
                &rp_id,
                "GetAssertion",
                &initial_cred.user_name,
                accounts_list,
                default_cred_id,
            ));

            let (auth_method, selected_cred_id) = match verify_result {
                Ok(success) => {
                    println!("[SECURITY] Verification succeeded using method: {}", success.method);
                    (success.method, success.selected_credential_id)
                }
                Err(err) => {
                    println!("[SECURITY] Verification failed / rejected: {}", err);
                    db.log_auth(
                        Some(&initial_cred.id),
                        &rp_id,
                        "GetAssertion",
                        "REJECTED",
                        "NONE",
                        Some(&err),
                    );
                    return vec![0x27]; // CTAP2_ERR_OPERATION_DENIED
                }
            };

            // If user selected a different account in Web CMS when website did not specify user
            let cred = if !is_user_specified {
                if let Some(sel_id) = &selected_cred_id {
                    if let Some(c) = all_creds.iter().find(|c| c.id == *sel_id && c.rp_id.eq_ignore_ascii_case(&rp_id)) {
                        println!("[CTAP2] Account selected for authentication: {} ({}) [ID: {}]", c.user_name, c.user_display_name, c.id);
                        c.clone()
                    } else {
                        println!("[CTAP2] Selected ID not found, using default: {} ({}) [ID: {}]", initial_cred.user_name, initial_cred.user_display_name, initial_cred.id);
                        initial_cred
                    }
                } else {
                    println!("[CTAP2] No specific account selected, using default: {} ({}) [ID: {}]", initial_cred.user_name, initial_cred.user_display_name, initial_cred.id);
                    initial_cred
                }
            } else {
                initial_cred
            };
            // Increment sign_count in database
            let new_count = db.increment_sign_count(&cred.id).unwrap_or(cred.sign_count + 1);

            // Build authenticatorData
            let rp_id_hash = Sha256::digest(rp_id.as_bytes());
            let flags = 0x01 | 0x04; // UP | UV

            let mut auth_data = Vec::new();
            auth_data.extend_from_slice(&rp_id_hash);
            auth_data.push(flags);
            auth_data.extend_from_slice(&new_count.to_be_bytes());

            // Sign message = authData + clientDataHash
            let mut message = Vec::new();
            message.extend_from_slice(&auth_data);
            message.extend_from_slice(&client_data_hash);

            let private_key_bytes = hex::decode(&cred.private_key_sec1_hex).unwrap_or_default();
            let signing_key = match SigningKey::from_slice(&private_key_bytes) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("[CRYPTO] Error recovering private key: {}", e);
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

            let user_id_bytes = hex::decode(&cred.user_id_hex).unwrap_or_default();
            let mut user_map = vec![
                (Value::Text("id".into()), Value::Bytes(user_id_bytes)),
            ];
            if !cred.user_name.is_empty() {
                user_map.push((Value::Text("name".into()), Value::Text(cred.user_name.clone())));
            }
            if !cred.user_display_name.is_empty() {
                user_map.push((Value::Text("displayName".into()), Value::Text(cred.user_display_name.clone())));
            }

            let resp_map = vec![
                (Value::Integer(1.into()), cred_descriptor),
                (Value::Integer(2.into()), Value::Bytes(auth_data)),
                (Value::Integer(3.into()), Value::Bytes(der_sig.as_bytes().to_vec())),
                (Value::Integer(4.into()), Value::Map(user_map)),
            ];

            // Write audit log
            db.log_auth(
                Some(&cred.id),
                &rp_id,
                "GetAssertion",
                "SUCCESS",
                &auth_method,
                Some(&format!("Authenticated account '{}' successfully (Counter: {})", cred.user_name, new_count)),
            );

            let mut out = vec![0x00]; // CTAP2_OK
            ciborium::into_writer(&Value::Map(resp_map), &mut out).unwrap();
            println!("[+] Assertion signed successfully! Updated sign_count in database.");
            out
        }

        _ => {
            if debug_mode {
                println!("[CTAP2] Unsupported command: 0x{:02x}", ctap2_cmd);
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
                println!("[CTAPHID] INIT -> Allocated CID: 0x{:08x}", allocated_cid);
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
    // 1. Parse CLI arguments & environment variables
    let args: Vec<String> = std::env::args().collect();
    let show_help = args.iter().any(|a| a == "--help" || a == "-h");
    let check_quit = args.iter().any(|a| a == "--quit" || a == "-q" || a == "--stop");
    let check_daemon = args.iter().any(|a| a == "--daemon" || a == "-b");
    let debug_mode = args.iter().any(|a| a == "--debug" || a == "-d");
    let unlimited_fps = args.iter().any(|a| a == "--unlimited-fps" || a == "--unlimited-fingerprints" || a == "-u");
    let exit_after_import = args.iter().any(|a| a == "--exit-after-import");
    let no_tray = args.iter().any(|a| a == "--no-tray");
    let check_clean_logs: Option<String> = {
        let mut target = None;
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            if a == "--clean-logs" || a == "clean-logs" || a == "--clear-logs" || a == "clear-logs" {
                let next_val = args.get(i + 1).and_then(|s| {
                    if s.starts_with('-') {
                        None
                    } else {
                        Some(s.clone())
                    }
                });
                target = Some(next_val.unwrap_or_else(|| "all".to_string()));
                break;
            } else if a.starts_with("--clean-logs=") || a.starts_with("--clear-logs=") {
                let val = a.split_once('=').map(|(_, v)| v.to_string()).unwrap_or_default();
                target = Some(if val.is_empty() { "all".to_string() } else { val });
                break;
            }
            i += 1;
        }
        target
    };
    let pid_file = std::env::temp_dir().join("vrtfido.pid");

    // Handle --quit: Stop running vrtfido process
    if check_quit {
        let running_pid: Option<i32> = if pid_file.exists() {
            std::fs::read_to_string(&pid_file)
                .ok()
                .and_then(|s| s.trim().parse::<i32>().ok())
                .filter(|&pid| unsafe { libc::kill(pid, 0) == 0 })
        } else {
            None
        };

        let target_pid = running_pid.or_else(|| {
            let my_pid = std::process::id() as i32;
            if let Ok(entries) = std::fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    if let Ok(name) = entry.file_name().into_string() {
                        if let Ok(pid) = name.parse::<i32>() {
                            if pid != my_pid {
                                let comm_path = format!("/proc/{}/comm", pid);
                                if let Ok(comm) = std::fs::read_to_string(comm_path) {
                                    if comm.trim() == "vrtfido" {
                                        return Some(pid);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            None
        });

        if let Some(pid) = target_pid {
            println!("[DAEMON] Sending stop signal to VrtFido process (PID: {})...", pid);
            unsafe { libc::kill(pid, libc::SIGTERM) };

            let mut stopped = false;
            for _ in 0..50 {
                std::thread::sleep(std::time::Duration::from_millis(100));
                if unsafe { libc::kill(pid, 0) != 0 } {
                    stopped = true;
                    break;
                }
            }

            if !stopped {
                println!("[DAEMON] Process not responding, forcing stop (SIGKILL)...");
                unsafe { libc::kill(pid, libc::SIGKILL) };
                std::thread::sleep(std::time::Duration::from_millis(200));
            }

            let _ = std::fs::remove_file(&pid_file);
            println!("[DAEMON] [+] Stopped VrtFido process (PID: {}) successfully.", pid);
            return Ok(());
        } else {
            let _ = std::fs::remove_file(&pid_file);
            println!("[DAEMON] [-] No running VrtFido process found.");
            return Ok(());
        }
    }

    // Handle --daemon: Run in background
    if check_daemon {
        if let Ok(content) = std::fs::read_to_string(&pid_file) {
            if let Ok(existing_pid) = content.trim().parse::<i32>() {
                if unsafe { libc::kill(existing_pid, 0) == 0 } {
                    eprintln!("[DAEMON] [!] VrtFido is already running with PID: {}. Use 'vrtfido --quit' to stop first.", existing_pid);
                    std::process::exit(1);
                }
            }
        }

        let child_args: Vec<String> = args
            .iter()
            .skip(1)
            .filter(|a| *a != "--daemon" && *a != "-b")
            .cloned()
            .collect();
        println!("[UHID] Checking /dev/uhid access permission...");
        ensure_uhid_permission();

        let current_exe = std::env::current_exe()?;
        let log_file_path = std::env::temp_dir().join("vrtfido.log");
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file_path)?;

        let err_file = log_file.try_clone()?;

        let child = std::process::Command::new(current_exe)
            .args(&child_args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::from(log_file))
            .stderr(std::process::Stdio::from(err_file))
            .spawn()?;

        let child_pid = child.id() as i32;
        let _ = std::fs::write(&pid_file, child_pid.to_string());

        std::thread::sleep(std::time::Duration::from_millis(300));
        if unsafe { libc::kill(child_pid, 0) != 0 } {
            let _ = std::fs::remove_file(&pid_file);
            eprintln!("[DAEMON] [!] Background daemon failed to start. Check log file at: {}", log_file_path.display());
            std::process::exit(1);
        }

        println!("============================================================");
        println!("             VrtFido - Virtual FIDO2 / WebAuthn CMS         ");
        println!("============================================================");
        println!("[DAEMON] [+] Started VrtFido daemon successfully!");
        println!("[DAEMON]     - Process (PID): {}", child_pid);
        println!("[DAEMON]     - Log file: {}", log_file_path.display());
        println!("[DAEMON]     - Web CMS: http://localhost:10209");
        println!("[DAEMON] Use 'vrtfido --quit' to stop the process.\n");
        return Ok(());
    }

    if show_help {
        println!("============================================================");
        println!("             VrtFido - Virtual FIDO2 / WebAuthn CMS         ");
        println!("============================================================");
        println!("Usage: vrtfido [OPTIONS]\n");
        println!("Options:");
        println!("      --daemon, -b              Run application in background (daemon mode)");
        println!("  -q, --quit, --stop            Stop running vrtfido process (foreground or daemon)");
        println!("  -d, --debug                   Enable packet debug mode");
        println!("  -u, --unlimited-fps           Unlimited fingerprint slots (default: 10)");
        println!("      --no-tray                 Disable system tray icon");
        println!("  -D, --database, --db <SPEC>   Database path or connection URL (default: authenticator.db)");
        println!("                                Supported:");
        println!("                                  - SQLite:     authenticator.db or sqlite:my.db");
        println!("                                  - PostgreSQL: postgresql://user:pass@host:port/dbname");
        println!("                                  - LibSQL:     libsql://... or https://... (Turso) or file");
        println!("                                  - MySQL:      mysql://user:pass@host:port/dbname");
        println!("                                  - MariaDB:    mariadb://user:pass@host:port/dbname");
        println!("      --db-type <TYPE>          Specify DB type (sqlite, postgres, libsql, mysql, mariadb)");
        println!("      --auth-token <TOKEN>      Authentication token for LibSQL / Turso Cloud");
        println!("      --export <FILE.json>      Export 100% database data to JSON file and exit");
        println!("      --import <FILE.json>      Import data from JSON file into current database");
        println!("      --exit-after-import       Exit immediately after import (do not start server)");
        println!("      --clean-logs, clean-logs [TYPE]");
        println!("                                Clear logs (all, auth, debug) and exit");
        println!("  -h, --help                    Show this help message\n");
        println!("Environment variables:");
        println!("  DATABASE_URL / DB_URL         Connection string or database file path");
        println!("  DB_TYPE                       Database type");
        println!("  LIBSQL_AUTH_TOKEN             LibSQL authentication token");
        return Ok(());
    }

    let get_opt = |name: &str, short: Option<&str>| -> Option<String> {
        let prefix = format!("{}=", name);
        for (i, a) in args.iter().enumerate() {
            if a == name || short.map_or(false, |s| a == s) {
                if i + 1 < args.len() {
                    return Some(args[i + 1].clone());
                }
            } else if a.starts_with(&prefix) {
                return Some(a[prefix.len()..].to_string());
            }
        }
        None
    };

    let db_spec = get_opt("--database", Some("-D"))
        .or_else(|| get_opt("--db", None))
        .or_else(|| std::env::var("DATABASE_URL").ok())
        .or_else(|| std::env::var("DB_URL").ok())
        .unwrap_or_else(|| "authenticator.db".to_string());

    let db_type = get_opt("--db-type", None)
        .or_else(|| std::env::var("DB_TYPE").ok())
        .or_else(|| std::env::var("DATABASE_TYPE").ok());

    let auth_token = get_opt("--auth-token", None)
        .or_else(|| get_opt("--db-token", None))
        .or_else(|| std::env::var("LIBSQL_AUTH_TOKEN").ok())
        .or_else(|| std::env::var("DATABASE_AUTH_TOKEN").ok());

    let export_file = get_opt("--export", None);
    let import_file = get_opt("--import", None);

    let mask_db_url = |url: &str| -> String {
        if let Ok(mut parsed) = url::Url::parse(url) {
            if parsed.password().is_some() {
                let _ = parsed.set_password(Some("***"));
            }
            parsed.to_string()
        } else {
            url.to_string()
        }
    };

    println!("============================================================");
    println!("             VrtFido - Virtual FIDO2 / WebAuthn CMS         ");
    println!("============================================================");
    if debug_mode {
        println!("[CLI] DEBUG mode: ON (--debug)");
    } else {
        println!("[CLI] DEBUG mode: OFF (Use '--debug' to view raw packets)");
    }
    if unlimited_fps {
        println!("[CLI] FINGERPRINT mode: UNLIMITED (--unlimited-fps)");
    } else {
        println!("[CLI] FINGERPRINT mode: LIMITED TO 10 (Use '--unlimited-fps' to remove limit)");
    }


    // 2. Initialize Database connection
    println!("[DB] Connecting to database: {}", mask_db_url(&db_spec));
    let db = Db::open_with_options(&db_spec, db_type.as_deref(), auth_token.as_deref())?;
    println!("[DB] [+] Successfully connected to database backend: {}", db.backend_name());
    if check_clean_logs.is_none() && export_file.is_none() {
        db.log_debug("INFO", "SYSTEM", &format!("Virtual FIDO2 Manager started with {} backend", db.backend_name()));
    }

    // Handle Clean Logs if requested
    if let Some(target) = check_clean_logs {
        let target_norm = target.trim().to_lowercase();
        println!("[CLEAN] Starting log cleanup (mode: {})...", target_norm);

        let clean_auth = target_norm == "all" || target_norm == "auth" || target_norm == "audit";
        let clean_debug = target_norm == "all" || target_norm == "debug";

        if !clean_auth && !clean_debug {
            eprintln!("[CLEAN] [!] Invalid log type: '{}'. Supported: all, auth, debug", target);
            std::process::exit(1);
        }

        let mut auth_deleted = 0;
        let mut debug_deleted = 0;

        if clean_auth {
            match db.clear_auth_logs() {
                Ok(count) => {
                    auth_deleted = count;
                    println!("[CLEAN] [+] Deleted {} authentication log records (auth_logs).", count);
                }
                Err(e) => {
                    eprintln!("[CLEAN] [!] Error deleting auth_logs: {}", e);
                    return Err(e.into());
                }
            }
        }

        if clean_debug {
            match db.clear_debug_logs() {
                Ok(count) => {
                    debug_deleted = count;
                    println!("[CLEAN] [+] Deleted {} debug log records (debug_logs).", count);
                }
                Err(e) => {
                    eprintln!("[CLEAN] [!] Error deleting debug_logs: {}", e);
                    return Err(e.into());
                }
            }

            // Clean daemon log file if exists
            let daemon_log_path = std::env::temp_dir().join("vrtfido.log");
            if daemon_log_path.exists() {
                match std::fs::write(&daemon_log_path, "") {
                    Ok(_) => println!("[CLEAN] [+] Cleaned daemon log file: {}", daemon_log_path.display()),
                    Err(e) => eprintln!("[CLEAN] [!] Could not clean daemon log file: {}", e),
                }
            }
        }

        println!("============================================================");
        println!("[CLEAN] [+] Log cleanup complete! Deleted: {} auth logs, {} debug logs.", auth_deleted, debug_deleted);
        return Ok(());
    }

    // Handle data import if requested
    if let Some(import_path) = import_file {
        println!("[MIGRATION] Importing data from file: {}", import_path);
        match db.import_from_file(&import_path) {
            Ok(stats) => {
                println!("[MIGRATION] [+] Data imported successfully!");
                println!("            - Credentials: {}", stats.credentials_imported);
                println!("            - Fingerprints: {}", stats.fingerprints_imported);
                println!("            - Auth logs: {}", stats.auth_logs_imported);
                println!("            - Debug logs: {}", stats.debug_logs_imported);
                println!("            - Security settings: {}", if stats.security_settings_updated { "Updated (PIN, UV)" } else { "Unchanged" });
            }
            Err(e) => {
                eprintln!("[MIGRATION] [!] Import error: {}", e);
                return Err(e.into());
            }
        }
        if exit_after_import {
            println!("[MIGRATION] Completed import and exiting (--exit-after-import).");
            return Ok(());
        }
    }

    // Handle data export if requested
    if let Some(export_path) = export_file {
        println!("[MIGRATION] Exporting 100% database data to file: {}", export_path);
        match db.export_to_file(&export_path) {
            Ok(_) => {
                let creds = db.get_credentials().map(|c| c.len()).unwrap_or(0);
                println!("[MIGRATION] [+] Successfully exported data to: {}", export_path);
                println!("            - Total credentials saved: {}", creds);
                return Ok(());
            }
            Err(e) => {
                eprintln!("[MIGRATION] [!] Export error: {}", e);
            }
        }
    }

    // 3. Check and grant /dev/uhid access via sudo if needed
    println!("[UHID] Checking /dev/uhid access permission...");
    ensure_uhid_permission();
    // 4. Initialize SecurityEngine & AppState
    let sensor = sensor::UsbSensor::new();
    let security = SecurityEngine::new(db.clone(), sensor.clone(), unlimited_fps);
    let debug_mode_arc = Arc::new(AtomicBool::new(debug_mode));
    let uhid_connected = Arc::new(AtomicBool::new(false));

    let port = get_opt("--port", Some("-p"))
        .or_else(|| std::env::var("PORT").ok())
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(10209);
    let app_state = AppState {
        db: db.clone(),
        security: security.clone(),
        debug_mode: debug_mode_arc.clone(),
        uhid_connected: uhid_connected.clone(),
        unlimited_fps,
        port,
    };

    // 5. Start Web CMS Server on port
    let app = web::create_router(app_state);
    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("[CMS] Web Management CMS is running at: http://localhost:{}", port);
    println!("[CMS] Open browser at http://localhost:{} to manage and approve verification requests\n", port);

    // Run Web Server in background task
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            eprintln!("[CMS] Web Server error: {}", e);
        }
    });

    // 6. Start UHID Daemon in dedicated thread
    let tokio_handle = tokio::runtime::Handle::current();
    let uhid_flag = uhid_connected.clone();
    let db_uhid = db.clone();
    let security_uhid = security.clone();

    std::thread::spawn(move || {
        println!("[UHID] Opening /dev/uhid...");
        let mut dev = match UhidDevice::open() {
            Ok(d) => {
                uhid_flag.store(true, Ordering::SeqCst);
                println!("[UHID] [+] Virtual FIDO2 device created on kernel successfully!");
                println!("[UHID] [+] Browsers can now detect the USB FIDO2 device.");
                d
            }
            Err(e) => {
                eprintln!("\n[UHID] [!] ERROR ACCESSING /dev/uhid: {}", e);
                eprintln!("[UHID] [!] Please run 'sudo chmod 666 /dev/uhid' or run the application as root.");
                db_uhid.log_debug("ERROR", "UHID", &format!("Failed to open /dev/uhid: {}", e));
                return;
            }
        };

        let mut parser = CtaphidParser::new();

        loop {
            let ev = match dev.read_event() {
                Ok(e) => e,
                Err(err) => {
                    eprintln!("[UHID] Error reading kernel event: {}", err);
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
                    println!("[Kernel] Application opened /dev/hidraw");
                }
                UHID_CLOSE => {
                    if debug_mode {
                        println!("[Kernel] Application closed /dev/hidraw");
                    }
                }

                // Reply immediately so kernel is not blocked
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

    // 7. Start System Tray icon in background
    let _tray_handle = if !no_tray {
        tray::spawn_tray(port).await
    } else {
        println!("[TRAY] System tray disabled (--no-tray)");
        None
    };

    // Write PID file for --quit command
    let _ = std::fs::write(&pid_file, std::process::id().to_string());
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("\n[!] Received stop signal (Ctrl+C). Shutting down...");
        }
        _ = sigterm.recv() => {
            println!("\n[!] Received stop signal (SIGTERM). Shutting down...");
        }
    }

    if let Some(handle) = _tray_handle {
        println!("[TRAY] Shutting down system tray service...");
        handle.shutdown().await;
    }

    let _ = std::fs::remove_file(&pid_file);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds the initial frame of a CTAPHID message: `total` is the length of the whole message,
    /// `data` is the part carried by this frame (at most 57 bytes).
    fn initial_packet(cid: u32, cmd: u8, total: usize, data: &[u8]) -> [u8; 64] {
        assert!(data.len() <= 57);
        let mut pkt = [0u8; 64];
        pkt[0..4].copy_from_slice(&cid.to_be_bytes());
        pkt[4] = cmd;
        pkt[5..7].copy_from_slice(&(total as u16).to_be_bytes());
        pkt[7..7 + data.len()].copy_from_slice(data);
        pkt
    }

    #[test]
    fn ctaphid_accepts_a_host_init_request() {
        // Broadcast CID, INIT, 8-byte nonce. A host that leaves byte 4 bare is accepted too, so
        // both the browser form (0x86, see below) and the bare opcode work.
        let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let frame = initial_packet(0xFFFFFFFF, CTAPHID_CMD_INIT, nonce.len(), &nonce);
        let mut parser = CtaphidParser::new();
        assert_eq!(
            parser.process_packet(&frame),
            Some((0xFFFFFFFF, CTAPHID_CMD_INIT, nonce.to_vec()))
        );

        let stray = [0u8; 64];
        assert_eq!(parser.process_packet(&stray), None, "stray continuation frame");
    }

    /// Regression: Chrome sends the command byte of every initial packet with 0x80 set, so a real
    /// browser INIT arrives as 0x86 (CBOR as 0x90, PING as 0x81). Matching the raw byte against the
    /// bare opcode dropped the INIT, the handshake timed out and no site ever reached the dashboard.
    #[test]
    fn ctaphid_accepts_the_browser_initial_packet_bit() {
        let nonce = [9u8, 8, 7, 6, 5, 4, 3, 2];
        let frame = initial_packet(
            0xFFFFFFFF,
            CTAPHID_CMD_INIT | CTAPHID_INIT_PACKET_BIT,
            nonce.len(),
            &nonce,
        );
        let mut parser = CtaphidParser::new();
        assert_eq!(
            parser.process_packet(&frame),
            Some((0xFFFFFFFF, CTAPHID_CMD_INIT, nonce.to_vec())),
            "0x86 must be recognised as authenticatorINIT"
        );
    }

    #[test]
    fn ctaphid_ignores_a_continuation_without_a_message_to_continue() {
        let mut parser = CtaphidParser::new();
        let mut stray = [0u8; 64];
        stray[0..4].copy_from_slice(&0x0A0B0C0Du32.to_be_bytes());
        stray[4] = 0; // first continuation sequence, but nothing is being reassembled
        assert_eq!(parser.process_packet(&stray), None);
    }

    #[test]
    fn ctaphid_reassembles_a_fragmented_request() {
        let cid = 0x11223344u32;
        let payload: Vec<u8> = (0..70u8).collect();
        let mut parser = CtaphidParser::new();

        let head = initial_packet(cid, CTAPHID_CMD_CBOR, payload.len(), &payload[..57]);
        assert_eq!(parser.process_packet(&head), None, "70 bytes need a second frame");

        let mut tail = [0u8; 64];
        tail[0..4].copy_from_slice(&cid.to_be_bytes());
        tail[4] = 0; // sequence number of the first continuation
        tail[5..5 + (payload.len() - 57)].copy_from_slice(&payload[57..]);
        assert_eq!(
            parser.process_packet(&tail),
            Some((cid, CTAPHID_CMD_CBOR, payload))
        );
    }

    #[test]
    fn ctaphid_reassembles_a_browser_fragmented_request() {
        let cid = 0x11223344u32;
        let payload: Vec<u8> = (0..70u8).collect();
        let mut parser = CtaphidParser::new();

        // Chrome marks the first packet with the initial-packet bit and sends continuations as
        // plain sequence numbers.
        let head = initial_packet(
            cid,
            CTAPHID_CMD_CBOR | CTAPHID_INIT_PACKET_BIT,
            payload.len(),
            &payload[..57],
        );
        assert_eq!(parser.process_packet(&head), None, "70 bytes need a second frame");

        let mut tail = [0u8; 64];
        tail[0..4].copy_from_slice(&cid.to_be_bytes());
        tail[4] = 0;
        tail[5..5 + (payload.len() - 57)].copy_from_slice(&payload[57..]);
        assert_eq!(
            parser.process_packet(&tail),
            Some((cid, CTAPHID_CMD_CBOR, payload))
        );
    }

    #[test]
    fn ctaphid_serves_a_new_initial_packet_over_a_partial_message() {
        let cid = 0x11223344u32;
        let mut parser = CtaphidParser::new();

        // Take a fragmented request that stops after its first packet, then hand the parser a fresh
        // INIT: the abandoned message must not swallow the new channel handshake.
        let head = initial_packet(
            cid,
            CTAPHID_CMD_CBOR | CTAPHID_INIT_PACKET_BIT,
            70,
            &[0u8; 57],
        );
        assert_eq!(parser.process_packet(&head), None);

        let nonce = [4u8, 3, 2, 1, 0, 1, 2, 3];
        let init = initial_packet(
            0xFFFFFFFF,
            CTAPHID_CMD_INIT | CTAPHID_INIT_PACKET_BIT,
            nonce.len(),
            &nonce,
        );
        assert_eq!(
            parser.process_packet(&init),
            Some((0xFFFFFFFF, CTAPHID_CMD_INIT, nonce.to_vec()))
        );
    }

    #[test]
    fn ctaphid_response_frames_are_marked_and_sequenced() {
        let cid = 0x0A0B0C0Du32;
        let payload: Vec<u8> = (0..70u8).collect();
        let frames = frame_response(cid, CTAPHID_CMD_CBOR, &payload);

        assert_eq!(frames[0][4], CTAPHID_CMD_CBOR | CTAPHID_INIT_PACKET_BIT);
        assert_eq!(&frames[0][0..4], &cid.to_be_bytes());
        assert_eq!(u16::from_be_bytes([frames[0][5], frames[0][6]]), 70);
        assert_eq!(&frames[0][7..], &payload[..57]);
        assert_eq!(frames[1][4], 0, "continuation carries the sequence number");
        assert_eq!(&frames[1][5..5 + 13], &payload[57..]);
        assert_eq!(frame_response(cid, CTAPHID_CMD_INIT, &[0])[0][4], 0x86);
    }

    /// End-to-end regression for the browser handshake: feed the exact INIT frame Chrome writes
    /// (opcode 0x86) into the request handler and check the report that goes back to the kernel.
    #[tokio::test]
    async fn a_browser_init_request_is_answered_on_the_wire() {
        use std::io::{Seek, SeekFrom};

        let path = std::env::temp_dir().join(format!("vrtfido-uhid-test-{}.bin", std::process::id()));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .expect("temp report sink");
        let mut dev = UhidDevice { file };

        let db = Db::open(":memory:").expect("in-memory db");
        let security = SecurityEngine::new(db.clone(), sensor::UsbSensor::new(), false);
        let mut parser = CtaphidParser::new();
        let nonce = [9u8, 8, 7, 6, 5, 4, 3, 2];
        let frame = initial_packet(
            0xFFFFFFFF,
            CTAPHID_CMD_INIT | CTAPHID_INIT_PACKET_BIT,
            nonce.len(),
            &nonce,
        );

        handle_frame(
            &mut dev,
            &mut parser,
            &db,
            &security,
            &tokio::runtime::Handle::current(),
            false,
            &frame,
        )
        .expect("an INIT request must be answered");

        dev.file.seek(SeekFrom::Start(0)).expect("rewind sink");
        let mut written = Vec::new();
        dev.file.read_to_end(&mut written).expect("read back sink");
        let _ = std::fs::remove_file(&path);

        // uhid_input2_req: size (u16) then 64-byte report data.
        assert_eq!(u16::from_le_bytes([written[4], written[5]]), 64);
        let report = &written[6..70];
        assert_eq!(&report[0..4], &0xFFFFFFFFu32.to_be_bytes(), "broadcast channel");
        assert_eq!(report[4], 0x86, "INIT response");
        assert_eq!(u16::from_be_bytes([report[5], report[6]]), 17);
        assert_eq!(&report[7..15], &nonce, "nonce is echoed");
        let allocated = u32::from_be_bytes([report[15], report[16], report[17], report[18]]);
        assert_ne!(allocated, 0xFFFFFFFF, "a real channel id is allocated");
        assert_eq!(report[19], 2, "CTAPHID protocol version 2");
        assert_eq!(report[23], 0x04, "CBOR capability flag");
    }

    #[test]
    fn virtual_authenticator_ids_are_project_specific() {
        assert_ne!(VIRTUAL_HID_VENDOR_ID, 0);
        assert_ne!(VIRTUAL_HID_PRODUCT_ID, 0);
        assert_ne!(
            (VIRTUAL_HID_VENDOR_ID as u16, VIRTUAL_HID_PRODUCT_ID as u16),
            (sensor::VENDOR_ID, sensor::PRODUCT_ID),
            "the virtual FIDO device must not reuse the fingerprint sensor's USB ids"
        );
    }

    #[tokio::test]
    async fn get_info_reports_project_aaguid() {
        let db = Db::open(":memory:").expect("in-memory db");
        let security = SecurityEngine::new(db.clone(), sensor::UsbSensor::new(), false);
        let response = handle_cbor(
            &db,
            &security,
            &tokio::runtime::Handle::current(),
            false,
            &[0x04], // authenticatorGetInfo
        );

        assert_eq!(response[0], 0x00, "CTAP2_OK status byte");
        let Value::Map(entries) =
            ciborium::from_reader(&response[1..]).expect("GetInfo payload must be CBOR")
        else {
            panic!("GetInfo payload must be a CBOR map");
        };
        let aaguid = entries
            .iter()
            .find_map(|(key, value)| {
                if key == &Value::Integer(3.into()) { Some(value.clone()) } else { None }
            })
            .expect("GetInfo must carry an AAGUID (key 3)");
        let Value::Bytes(bytes) = aaguid else {
            panic!("GetInfo AAGUID must be a byte string");
        };

        assert_ne!(passkey::AAGUID, [0u8; 16], "AAGUID must identify VrtFido");
        assert_eq!(bytes, passkey::AAGUID.to_vec());

        // Without key 9 a browser reports an empty transport list for every credential it creates
        // with this authenticator.
        let transports = entries
            .iter()
            .find_map(|(key, value)| {
                if key == &Value::Integer(9.into()) { Some(value.clone()) } else { None }
            })
            .expect("GetInfo must carry transports (key 9)");
        assert_eq!(
            transports,
            Value::Array(
                ["ble", "hybrid", "internal", "nfc", "usb"]
                    .into_iter()
                    .map(|t| Value::Text(t.into()))
                    .collect::<Vec<_>>()
            )
        );
    }
}
