// crates/heartwood-device/src/oled.rs
//! OLED display driver with terminal fallback for non-Pi environments.

use qrcode::{QrCode, EcLevel};
use qrcode::render::unicode;
use tracing::info;

/// OLED display abstraction.
///
/// On a Raspberry Pi with `/dev/i2c-1` present, hardware control can be
/// wired in. On development machines the methods fall back to terminal
/// output so the rest of the binary can run unmodified.
pub struct Oled {
    /// `true` when real I2C hardware was detected at startup.
    pub is_hardware: bool,
}

impl Oled {
    /// Initialise the display driver.
    ///
    /// Detects hardware presence by checking for `/dev/i2c-1`.
    pub fn new() -> Self {
        let is_hardware = std::path::Path::new("/dev/i2c-1").exists();
        Self { is_hardware }
    }

    /// Show a single line of text on the display (or log to terminal).
    pub fn show_text(&self, text: &str) {
        if self.is_hardware {
            // TODO: write to SSD1306 via i2c-linux / rppal.
            info!("[OLED] {}", text);
        } else {
            println!("[OLED] {}", text);
        }
    }

    /// Render `data` as a QR code and display it (terminal in fallback mode).
    pub fn show_qr(&self, data: &str) {
        match QrCode::with_error_correction_level(data, EcLevel::M) {
            Ok(code) => {
                let image = code
                    .render::<unicode::Dense1x2>()
                    .dark_color(unicode::Dense1x2::Dark)
                    .light_color(unicode::Dense1x2::Light)
                    .build();
                if self.is_hardware {
                    info!("[OLED QR] {}", data);
                } else {
                    println!("[OLED QR for: {}]", data);
                    println!("{}", image);
                }
            }
            Err(e) => {
                self.show_text(&format!("QR error: {}", e));
            }
        }
    }

    /// Show a BIP-39 mnemonic word during setup (e.g. "3. abandon").
    pub fn show_mnemonic_word(&self, num: usize, word: &str) {
        self.show_text(&format!("{}. {}", num, word));
    }

    /// Clear the display.
    pub fn clear(&self) {
        if self.is_hardware {
            info!("[OLED] <clear>");
        } else {
            println!("[OLED] <clear>");
        }
    }
}

impl Default for Oled {
    fn default() -> Self {
        Self::new()
    }
}
