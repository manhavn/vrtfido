use crate::autostart;
use ksni::menu::{CheckmarkItem, MenuItem, StandardItem};
use ksni::{Tray, TrayMethods};

pub struct VrtfidoTray {
    pub port: u16,
    pub autostart_enabled: bool,
    /// `--uhid`: without the virtual device there is nothing that needs `/dev/uhid` access, so
    /// enabling autostart must not configure the udev rule.
    pub uhid_enabled: bool,
}

impl VrtfidoTray {
    pub fn new(port: u16, uhid_enabled: bool) -> Self {
        let autostart_enabled = autostart::is_autostart_enabled();
        Self {
            port,
            autostart_enabled,
            uhid_enabled,
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

    /// Left empty on purpose: a themed name would replace the item's own
    /// pixmap, and the panel would draw a generic shield instead of the
    /// VrtFido logo that the tray, the dashboard and the extension share.
    fn icon_name(&self) -> String {
        String::new()
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        create_tray_icon_pixmap()
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
                            if new_state && this.uhid_enabled && !crate::has_permanent_uhid_rule() {
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
                    crate::platform::terminate(std::process::id());
                }),
                ..Default::default()
            }
            .into(),
        ]
    }
}

/// The shared VrtFido logo as raw ARGB32, which is what `StatusNotifierItem`
/// carries: pixels, not a PNG. Both sizes are the same artwork the extension,
/// the dashboard and the Android launcher use, written by `tools/gen-icons.py`;
/// embedding them as bytes keeps a PNG decoder out of the daemon.
const ICON_24: &[u8] = include_bytes!("../assets/tray-24.argb");
const ICON_48: &[u8] = include_bytes!("../assets/tray-48.argb");

/// Panel pixmaps, smallest first: hosts pick the size their panel wants and
/// scale from there, and HiDPI panels take the larger one.
pub fn create_tray_icon_pixmap() -> Vec<ksni::Icon> {
    vec![tray_icon(24, ICON_24), tray_icon(48, ICON_48)]
}

fn tray_icon(size: i32, data: &'static [u8]) -> ksni::Icon {
    debug_assert_eq!(data.len(), (size * size * 4) as usize);
    ksni::Icon {
        width: size,
        height: size,
        data: data.to_vec(),
    }
}

/// Spawn the system tray service in the background.
/// Gracefully handles headless environments where D-Bus or StatusNotifierWatcher is absent.
pub async fn spawn_tray(port: u16, uhid_enabled: bool) -> Option<ksni::Handle<VrtfidoTray>> {
    let tray = VrtfidoTray::new(port, uhid_enabled);
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
    fn test_tray_icon_is_the_shared_logo() {
        let icons = create_tray_icon_pixmap();
        assert_eq!(icons.len(), 2);
        for (icon, size) in icons.iter().zip([24usize, 48]) {
            assert_eq!((icon.width, icon.height), (size as i32, size as i32));
            assert_eq!(icon.data.len(), size * size * 4);

            let pixel = |x: usize, y: usize| {
                let at = (y * size + x) * 4;
                (
                    icon.data[at],
                    icon.data[at + 1],
                    icon.data[at + 2],
                    icon.data[at + 3],
                )
            };
            // ARGB32, network byte order: the rounded square leaves the corner
            // transparent, and design point (45, 61) sits well inside the navy
            // shield plate that every consumer of the logo draws.
            assert_eq!(pixel(0, 0).3, 0, "corner is not transparent at {size}px");
            let x = 45 * size / 128;
            let y = 61 * size / 128;
            assert_eq!(
                pixel(x, y),
                (255, 0x14, 0x23, 0x3C),
                "shield plate colour is not ARGB #FF14233C at {size}px"
            );
        }
    }

    #[test]
    fn test_tray_urls_and_titles() {
        let tray = VrtfidoTray::new(10209, true);
        assert_eq!(tray.dashboard_url(), "http://localhost:10209");
        assert_eq!(tray.id(), "vrtfido");
        assert_eq!(tray.title(), "VrtFido");
        // A themed icon name would make the panel ignore the logo pixmap.
        assert_eq!(tray.icon_name(), "");
    }

    #[test]
    fn test_tray_menu_structure() {
        let tray = VrtfidoTray::new(10209, false);
        let menu = tray.menu();
        // Menu should have at least: Dashboard, Start with the system, Separator, Quit
        assert_eq!(menu.len(), 4);
    }
}
