use crate::autostart;
use ksni::menu::{CheckmarkItem, MenuItem, StandardItem};
use ksni::{Tray, TrayMethods};

pub struct VrtfidoTray {
    pub port: u16,
    pub autostart_enabled: bool,
}

impl VrtfidoTray {
    pub fn new(port: u16) -> Self {
        let autostart_enabled = autostart::is_autostart_enabled();
        Self {
            port,
            autostart_enabled,
        }
    }

    pub fn dashboard_url(&self) -> String {
        format!("http://localhost:{}", self.port)
    }

    pub fn open_dashboard(&self) {
        let url = self.dashboard_url();
        println!("[TRAY] Opening dashboard in browser: {}", url);
        if let Err(e) = open::that(&url) {
            eprintln!("[TRAY] Failed to open browser for {}: {}", url, e);
        }
    }
}

impl Tray for VrtfidoTray {
    fn id(&self) -> String {
        "vrtfido".into()
    }

    fn title(&self) -> String {
        "VrtFido".into()
    }

    fn category(&self) -> ksni::Category {
        ksni::Category::ApplicationStatus
    }

    fn status(&self) -> ksni::Status {
        ksni::Status::Active
    }

    fn icon_name(&self) -> String {
        "security-high".into()
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        vec![create_tray_icon_pixmap()]
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            title: "VrtFido - Virtual FIDO2 / WebAuthn".into(),
            description: format!("Web CMS: http://localhost:{}", self.port),
            ..Default::default()
        }
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        self.open_dashboard();
    }

    fn menu_about_to_show(&mut self) {
        self.autostart_enabled = autostart::is_autostart_enabled();
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        vec![
            StandardItem {
                label: "Dashboard".into(),
                icon_name: "web-browser".into(),
                activate: Box::new(|this: &mut Self| {
                    this.open_dashboard();
                }),
                ..Default::default()
            }
            .into(),
            CheckmarkItem {
                label: "Start with the system".into(),
                checked: self.autostart_enabled,
                activate: Box::new(|this: &mut Self| {
                    let new_state = !this.autostart_enabled;
                    match autostart::set_autostart_enabled(new_state) {
                        Ok(()) => {
                            this.autostart_enabled = new_state;
                            println!(
                                "[TRAY] Autostart with system {}",
                                if new_state { "enabled" } else { "disabled" }
                            );
                            if new_state && !crate::has_permanent_uhid_rule() {
                                println!("[TRAY] Setting up permanent /dev/uhid udev rule for system autostart...");
                                std::thread::spawn(|| {
                                    let _ = crate::ensure_permanent_uhid_permission();
                                });
                            }
                        }
                        Err(e) => {
                            eprintln!("[TRAY] Failed to toggle autostart: {}", e);
                        }
                    }
                }),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Quit".into(),
                icon_name: "application-exit".into(),
                activate: Box::new(|_| {
                    println!("[TRAY] Quit requested from tray menu. Shutting down...");
                    unsafe { libc::kill(std::process::id() as i32, libc::SIGTERM) };
                }),
                ..Default::default()
            }
            .into(),
        ]
    }
}

/// Create a 24x24 ARGB32 icon pixmap fallback
pub fn create_tray_icon_pixmap() -> ksni::Icon {
    const SIZE: usize = 24;
    let mut data = Vec::with_capacity(SIZE * SIZE * 4);

    for y in 0..SIZE {
        for x in 0..SIZE {
            let dx = (x as i32) - 11;
            let dy = (y as i32) - 11;

            let in_shield = if y < 14 {
                // Top half: rounded rectangle
                x >= 3 && x <= 20 && y >= 3
            } else {
                // Bottom half: shield point tapering to bottom center
                let width_at_y = 9 - (y as i32 - 13);
                dx.abs() <= width_at_y && y <= 21
            };

            if in_shield {
                // Key emblem in center: circle + vertical stem
                let is_key_circle = (dx * dx + (dy + 2) * (dy + 2)) <= 4;
                let is_key_stem = dx.abs() <= 1 && dy >= 0 && dy <= 4;

                if is_key_circle || is_key_stem {
                    // White emblem (#ffffff): A=255, R=255, G=255, B=255
                    data.push(255);
                    data.push(255);
                    data.push(255);
                    data.push(255);
                } else {
                    // Shield background (#2563eb blue): A=255, R=37, G=99, B=235
                    data.push(255);
                    data.push(37);
                    data.push(99);
                    data.push(235);
                }
            } else {
                // Transparent: A=0, R=0, G=0, B=0
                data.push(0);
                data.push(0);
                data.push(0);
                data.push(0);
            }
        }
    }

    ksni::Icon {
        width: SIZE as i32,
        height: SIZE as i32,
        data,
    }
}

/// Spawn the system tray service in the background.
/// Gracefully handles headless environments where D-Bus or StatusNotifierWatcher is absent.
pub async fn spawn_tray(port: u16) -> Option<ksni::Handle<VrtfidoTray>> {
    let tray = VrtfidoTray::new(port);
    println!("[TRAY] Initializing system tray icon (Port: {})...", port);

    match tray.assume_sni_available(true).spawn().await {
        Ok(handle) => {
            println!("[TRAY] [+] System tray icon registered successfully!");
            Some(handle)
        }
        Err(e) => {
            eprintln!("[TRAY] [!] Warning: Could not register system tray: {}", e);
            eprintln!(
                "[TRAY] [!] Running without tray icon (Web CMS still accessible at http://localhost:{})",
                port
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tray_icon_pixmap_dimensions() {
        let icon = create_tray_icon_pixmap();
        assert_eq!(icon.width, 24);
        assert_eq!(icon.height, 24);
        assert_eq!(icon.data.len(), 24 * 24 * 4);
    }

    #[test]
    fn test_tray_urls_and_titles() {
        let tray = VrtfidoTray::new(10209);
        assert_eq!(tray.dashboard_url(), "http://localhost:10209");
        assert_eq!(tray.id(), "vrtfido");
        assert_eq!(tray.title(), "VrtFido");
        assert_eq!(tray.icon_name(), "security-high");
    }

    #[test]
    fn test_tray_menu_structure() {
        let tray = VrtfidoTray::new(10209);
        let menu = tray.menu();
        // Menu should have at least: Dashboard, Start with the system, Separator, Quit
        assert_eq!(menu.len(), 4);
    }
}
