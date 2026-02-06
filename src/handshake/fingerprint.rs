//! TLS Fingerprinting
//!
//! Generates and validates JA3/JA4 fingerprints to ensure our
//! ClientHello matches the expected fingerprint of the mimicked app.

use crate::config::MimicTarget;
use crate::error::Result;
use super::tls::TlsClientHello;
use blake2::{Blake2b512, Digest};

/// A TLS fingerprint (JA3-style)
#[derive(Debug, Clone)]
pub struct Fingerprint {
    /// TLS version
    pub version: u16,
    /// Cipher suites (ordered)
    pub cipher_suites: Vec<u16>,
    /// Extensions (ordered by type)
    pub extensions: Vec<u16>,
    /// Elliptic curves/supported groups
    pub elliptic_curves: Vec<u16>,
    /// EC point formats
    pub ec_point_formats: Vec<u8>,
}

impl Fingerprint {
    /// Extract fingerprint from a ClientHello
    pub fn from_client_hello(ch: &TlsClientHello) -> Self {
        let mut extensions: Vec<u16> = ch.extensions.iter().map(|e| e.ext_type).collect();

        let mut elliptic_curves = Vec::new();
        let mut ec_point_formats = Vec::new();

        for ext in &ch.extensions {
            match ext.ext_type {
                10 => { // Supported Groups
                    if ext.data.len() >= 2 {
                        let len = u16::from_be_bytes([ext.data[0], ext.data[1]]) as usize;
                        let mut i = 2;
                        while i + 1 < ext.data.len() && i < 2 + len {
                            elliptic_curves.push(u16::from_be_bytes([ext.data[i], ext.data[i + 1]]));
                            i += 2;
                        }
                    }
                }
                11 => { // EC Point Formats
                    if !ext.data.is_empty() {
                        let len = ext.data[0] as usize;
                        ec_point_formats = ext.data[1..1 + len.min(ext.data.len() - 1)].to_vec();
                    }
                }
                _ => {}
            }
        }

        Self {
            version: ch.version,
            cipher_suites: ch.cipher_suites.clone(),
            extensions,
            elliptic_curves,
            ec_point_formats,
        }
    }

    /// Calculate JA3 hash
    pub fn ja3_hash(&self) -> String {
        let ja3_string = self.ja3_string();
        let mut hasher = blake2::Blake2s256::new();
        hasher.update(ja3_string.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Generate JA3 string (without hashing)
    pub fn ja3_string(&self) -> String {
        let ciphers: Vec<String> = self.cipher_suites.iter()
            .filter(|&&c| !is_grease(c))
            .map(|c| c.to_string())
            .collect();

        let extensions: Vec<String> = self.extensions.iter()
            .filter(|&&e| !is_grease(e))
            .map(|e| e.to_string())
            .collect();

        let curves: Vec<String> = self.elliptic_curves.iter()
            .filter(|&&c| !is_grease(c))
            .map(|c| c.to_string())
            .collect();

        let formats: Vec<String> = self.ec_point_formats.iter()
            .map(|f| f.to_string())
            .collect();

        format!(
            "{},{},{},{},{}",
            self.version,
            ciphers.join("-"),
            extensions.join("-"),
            curves.join("-"),
            formats.join("-")
        )
    }

    /// Compare two fingerprints
    pub fn matches(&self, other: &Fingerprint) -> bool {
        // Compare non-GREASE values
        let self_ja3 = self.ja3_string();
        let other_ja3 = other.ja3_string();
        self_ja3 == other_ja3
    }
}

/// Check if a value is a GREASE value
fn is_grease(value: u16) -> bool {
    // GREASE values: 0x0a0a, 0x1a1a, 0x2a2a, etc.
    (value & 0x0f0f) == 0x0a0a
}

/// Fingerprint generator for specific targets
pub struct FingerprintGenerator {
    target: MimicTarget,
}

impl FingerprintGenerator {
    pub fn new(target: MimicTarget) -> Self {
        Self { target }
    }

    /// Get the expected fingerprint for the target
    pub fn expected_fingerprint(&self) -> Fingerprint {
        match self.target {
            MimicTarget::Rubika | MimicTarget::Eitaa => self.android_chrome_fingerprint(),
            MimicTarget::Chrome => self.chrome_fingerprint(),
            MimicTarget::Firefox => self.firefox_fingerprint(),
            _ => self.android_chrome_fingerprint(),
        }
    }

    fn android_chrome_fingerprint(&self) -> Fingerprint {
        Fingerprint {
            version: 0x0303,
            cipher_suites: vec![
                0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f,
                0xcca9, 0xcca8, 0xc024, 0xc023, 0xc028, 0xc027,
            ],
            extensions: vec![0, 23, 65281, 10, 11, 35, 16, 13, 43, 45, 51],
            elliptic_curves: vec![0x001d, 0x0017, 0x0018, 0x0019],
            ec_point_formats: vec![0],
        }
    }

    fn chrome_fingerprint(&self) -> Fingerprint {
        // Desktop Chrome has slight differences
        self.android_chrome_fingerprint()
    }

    fn firefox_fingerprint(&self) -> Fingerprint {
        Fingerprint {
            version: 0x0303,
            cipher_suites: vec![
                0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030,
                0xcca9, 0xcca8,
            ],
            extensions: vec![0, 23, 65281, 10, 11, 35, 16, 13, 43, 45, 51],
            elliptic_curves: vec![0x001d, 0x0017, 0x0018],
            ec_point_formats: vec![0],
        }
    }

    /// Validate that a ClientHello matches the expected fingerprint
    pub fn validate(&self, ch: &TlsClientHello) -> bool {
        let actual = Fingerprint::from_client_hello(ch);
        let expected = self.expected_fingerprint();
        actual.matches(&expected)
    }
}

/// Known fingerprints database
pub struct FingerprintDatabase {
    fingerprints: Vec<(String, Fingerprint)>,
}

impl FingerprintDatabase {
    pub fn new() -> Self {
        Self {
            fingerprints: Vec::new(),
        }
    }

    /// Add known fingerprints for Iranian apps
    pub fn with_iran_apps(mut self) -> Self {
        // Rubika Android
        self.fingerprints.push((
            "rubika_android".into(),
            FingerprintGenerator::new(MimicTarget::Rubika).expected_fingerprint(),
        ));

        // Eitaa Android
        self.fingerprints.push((
            "eitaa_android".into(),
            FingerprintGenerator::new(MimicTarget::Eitaa).expected_fingerprint(),
        ));

        self
    }

    /// Find matching fingerprint
    pub fn find_match(&self, fp: &Fingerprint) -> Option<&str> {
        for (name, known) in &self.fingerprints {
            if fp.matches(known) {
                return Some(name);
            }
        }
        None
    }
}

impl Default for FingerprintDatabase {
    fn default() -> Self {
        Self::new().with_iran_apps()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::TlsClientHelloBuilder;

    #[test]
    fn test_fingerprint_extraction() {
        let ch_data = TlsClientHelloBuilder::new()
            .server_name("test.com")
            .mimic(MimicTarget::Rubika)
            .build()
            .unwrap();

        let ch = TlsClientHello::from_bytes(&ch_data).unwrap();
        let fp = Fingerprint::from_client_hello(&ch);

        assert_eq!(fp.version, 0x0303);
        assert!(!fp.cipher_suites.is_empty());
    }

    #[test]
    fn test_ja3_string() {
        let fp = Fingerprint {
            version: 0x0303,
            cipher_suites: vec![0x1301, 0x1302],
            extensions: vec![0, 23],
            elliptic_curves: vec![0x001d],
            ec_point_formats: vec![0],
        };

        let ja3 = fp.ja3_string();
        assert!(ja3.contains("771")); // 0x0303 = 771
    }
}
