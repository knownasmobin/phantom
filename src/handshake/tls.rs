//! TLS ClientHello construction
//!
//! Builds fake TLS ClientHello packets that appear legitimate to DPI.
//! The actual tunnel data will be sent after this "handshake" completes.

use crate::config::MimicTarget;
use crate::error::{PhantomError, Result};
use crate::utils::random_bytes;

/// TLS record types
pub mod record_type {
    pub const HANDSHAKE: u8 = 22;
    pub const CHANGE_CIPHER_SPEC: u8 = 20;
    pub const ALERT: u8 = 21;
    pub const APPLICATION_DATA: u8 = 23;
}

/// TLS handshake types
pub mod handshake_type {
    pub const CLIENT_HELLO: u8 = 1;
    pub const SERVER_HELLO: u8 = 2;
    pub const CERTIFICATE: u8 = 11;
    pub const SERVER_KEY_EXCHANGE: u8 = 12;
    pub const SERVER_HELLO_DONE: u8 = 14;
    pub const CLIENT_KEY_EXCHANGE: u8 = 16;
    pub const FINISHED: u8 = 20;
}

/// TLS extension types
pub mod extension_type {
    pub const SERVER_NAME: u16 = 0;
    pub const EC_POINT_FORMATS: u16 = 11;
    pub const SUPPORTED_GROUPS: u16 = 10;
    pub const SIGNATURE_ALGORITHMS: u16 = 13;
    pub const APPLICATION_LAYER_PROTOCOL_NEGOTIATION: u16 = 16;
    pub const EXTENDED_MASTER_SECRET: u16 = 23;
    pub const COMPRESS_CERTIFICATE: u16 = 27;
    pub const SESSION_TICKET: u16 = 35;
    pub const SUPPORTED_VERSIONS: u16 = 43;
    pub const PSK_KEY_EXCHANGE_MODES: u16 = 45;
    pub const KEY_SHARE: u16 = 51;
    pub const RENEGOTIATION_INFO: u16 = 65281;
}

/// A TLS ClientHello message
#[derive(Debug, Clone)]
pub struct TlsClientHello {
    /// TLS version (0x0303 for TLS 1.2, 0x0301 for TLS 1.0)
    pub version: u16,
    /// Random bytes (32 bytes)
    pub random: [u8; 32],
    /// Session ID
    pub session_id: Vec<u8>,
    /// Cipher suites
    pub cipher_suites: Vec<u16>,
    /// Compression methods
    pub compression_methods: Vec<u8>,
    /// Extensions
    pub extensions: Vec<TlsExtension>,
}

#[derive(Debug, Clone)]
pub struct TlsExtension {
    pub ext_type: u16,
    pub data: Vec<u8>,
}

impl TlsClientHello {
    /// Convert to wire format
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut handshake = Vec::new();

        // Client version
        handshake.extend_from_slice(&self.version.to_be_bytes());

        // Random
        handshake.extend_from_slice(&self.random);

        // Session ID
        handshake.push(self.session_id.len() as u8);
        handshake.extend_from_slice(&self.session_id);

        // Cipher suites
        let cipher_len = (self.cipher_suites.len() * 2) as u16;
        handshake.extend_from_slice(&cipher_len.to_be_bytes());
        for suite in &self.cipher_suites {
            handshake.extend_from_slice(&suite.to_be_bytes());
        }

        // Compression methods
        handshake.push(self.compression_methods.len() as u8);
        handshake.extend_from_slice(&self.compression_methods);

        // Extensions
        let mut extensions_data = Vec::new();
        for ext in &self.extensions {
            extensions_data.extend_from_slice(&ext.ext_type.to_be_bytes());
            extensions_data.extend_from_slice(&(ext.data.len() as u16).to_be_bytes());
            extensions_data.extend_from_slice(&ext.data);
        }
        handshake.extend_from_slice(&(extensions_data.len() as u16).to_be_bytes());
        handshake.extend(extensions_data);

        // Build full record
        let mut record = Vec::new();

        // TLS record header
        record.push(record_type::HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 for record layer

        // Handshake header
        let mut handshake_msg = Vec::new();
        handshake_msg.push(handshake_type::CLIENT_HELLO);

        // Length (3 bytes)
        let len = handshake.len() as u32;
        handshake_msg.push((len >> 16) as u8);
        handshake_msg.push((len >> 8) as u8);
        handshake_msg.push(len as u8);

        handshake_msg.extend(handshake);

        // Record length
        record.extend_from_slice(&(handshake_msg.len() as u16).to_be_bytes());
        record.extend(handshake_msg);

        record
    }

    /// Parse from wire format
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 5 {
            return Err(PhantomError::PacketParse("TLS record too short".into()));
        }

        // Skip TLS record header (5 bytes)
        let handshake = &data[5..];

        if handshake.len() < 4 {
            return Err(PhantomError::PacketParse("Handshake too short".into()));
        }

        // Skip handshake header (4 bytes)
        let client_hello = &handshake[4..];

        if client_hello.len() < 38 {
            return Err(PhantomError::PacketParse("ClientHello too short".into()));
        }

        let version = u16::from_be_bytes([client_hello[0], client_hello[1]]);

        let mut random = [0u8; 32];
        random.copy_from_slice(&client_hello[2..34]);

        let session_id_len = client_hello[34] as usize;
        let mut offset = 35;

        if offset + session_id_len > client_hello.len() {
            return Err(PhantomError::PacketParse(
                "Session ID exceeds packet".into(),
            ));
        }
        let session_id = client_hello[offset..offset + session_id_len].to_vec();
        offset += session_id_len;

        // Parse cipher suites
        if offset + 2 > client_hello.len() {
            return Err(PhantomError::PacketParse(
                "Cipher suites length missing".into(),
            ));
        }
        let cipher_len =
            u16::from_be_bytes([client_hello[offset], client_hello[offset + 1]]) as usize;
        offset += 2;

        if offset + cipher_len > client_hello.len() {
            return Err(PhantomError::PacketParse(
                "Cipher suites exceed packet".into(),
            ));
        }
        let mut cipher_suites = Vec::new();
        let cipher_end = offset + cipher_len;
        while offset + 1 < cipher_end {
            let suite = u16::from_be_bytes([client_hello[offset], client_hello[offset + 1]]);
            cipher_suites.push(suite);
            offset += 2;
        }
        offset = cipher_end;

        // Parse compression methods
        if offset >= client_hello.len() {
            return Err(PhantomError::PacketParse(
                "Compression methods missing".into(),
            ));
        }
        let comp_len = client_hello[offset] as usize;
        offset += 1;

        if offset + comp_len > client_hello.len() {
            return Err(PhantomError::PacketParse(
                "Compression methods exceed packet".into(),
            ));
        }
        let compression_methods = client_hello[offset..offset + comp_len].to_vec();
        offset += comp_len;

        // Parse extensions
        let mut extensions = Vec::new();
        if offset + 2 <= client_hello.len() {
            let ext_len =
                u16::from_be_bytes([client_hello[offset], client_hello[offset + 1]]) as usize;
            offset += 2;

            let ext_end = offset + ext_len;
            while offset + 4 <= ext_end && offset + 4 <= client_hello.len() {
                if extensions.len() >= 64 {
                    break;
                }
                let ext_type = u16::from_be_bytes([client_hello[offset], client_hello[offset + 1]]);
                let data_len =
                    u16::from_be_bytes([client_hello[offset + 2], client_hello[offset + 3]])
                        as usize;
                offset += 4;

                if offset + data_len <= client_hello.len() {
                    let data = client_hello[offset..offset + data_len].to_vec();
                    extensions.push(TlsExtension { ext_type, data });
                    offset += data_len;
                } else {
                    break;
                }
            }
        }

        Ok(Self {
            version,
            random,
            session_id,
            cipher_suites,
            compression_methods,
            extensions,
        })
    }

    /// Get the SNI from extensions
    pub fn get_sni(&self) -> Option<String> {
        for ext in &self.extensions {
            if ext.ext_type == extension_type::SERVER_NAME && ext.data.len() > 5 {
                // SNI extension format: list_len(2) + type(1) + name_len(2) + name
                let name_len = u16::from_be_bytes([ext.data[3], ext.data[4]]) as usize;
                if ext.data.len() >= 5 + name_len {
                    return String::from_utf8(ext.data[5..5 + name_len].to_vec()).ok();
                }
            }
        }
        None
    }
}

/// Builder for TLS ClientHello
pub struct TlsClientHelloBuilder {
    server_name: Option<String>,
    mimic_target: MimicTarget,
    randomize: bool,
    session_id: Option<Vec<u8>>,
}

impl TlsClientHelloBuilder {
    pub fn new() -> Self {
        Self {
            server_name: None,
            mimic_target: MimicTarget::Rubika,
            randomize: false,
            session_id: None,
        }
    }

    pub fn server_name(mut self, sni: &str) -> Self {
        self.server_name = Some(sni.to_string());
        self
    }

    pub fn mimic(mut self, target: MimicTarget) -> Self {
        self.mimic_target = target;
        self
    }

    pub fn randomize(mut self) -> Self {
        self.randomize = true;
        self
    }

    pub fn session_id(mut self, id: Vec<u8>) -> Self {
        self.session_id = Some(id);
        self
    }

    pub fn build(self) -> Result<Vec<u8>> {
        let sni = self
            .server_name
            .clone()
            .unwrap_or_else(|| self.mimic_target.default_sni().to_string());

        let random: [u8; 32] = random_bytes(32)
            .try_into()
            .expect("random_bytes(32) always returns 32 bytes");

        let session_id = self.session_id.clone().unwrap_or_else(|| random_bytes(32));

        // Get cipher suites and extensions based on mimic target
        let (cipher_suites, extensions) = self.get_target_profile(&sni);

        let client_hello = TlsClientHello {
            version: 0x0303, // TLS 1.2
            random,
            session_id,
            cipher_suites,
            compression_methods: vec![0], // No compression
            extensions,
        };

        Ok(client_hello.to_bytes())
    }

    fn get_target_profile(&self, sni: &str) -> (Vec<u16>, Vec<TlsExtension>) {
        match self.mimic_target {
            MimicTarget::Rubika | MimicTarget::Eitaa => self.android_chrome_profile(sni),
            MimicTarget::Chrome => self.chrome_desktop_profile(sni),
            MimicTarget::Firefox => self.firefox_profile(sni),
            _ => self.android_chrome_profile(sni),
        }
    }

    /// Android Chrome profile (common for Iranian apps)
    fn android_chrome_profile(&self, sni: &str) -> (Vec<u16>, Vec<TlsExtension>) {
        // Cipher suites matching Android Chrome
        let cipher_suites = vec![
            0x1301, // TLS_AES_128_GCM_SHA256
            0x1302, // TLS_AES_256_GCM_SHA384
            0x1303, // TLS_CHACHA20_POLY1305_SHA256
            0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            0xc024, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
            0xc023, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
            0xc028, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
            0xc027, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
        ];

        let extensions = vec![
            // SNI
            self.build_sni_extension(sni),
            // Extended Master Secret
            TlsExtension {
                ext_type: extension_type::EXTENDED_MASTER_SECRET,
                data: vec![],
            },
            // Renegotiation Info
            TlsExtension {
                ext_type: extension_type::RENEGOTIATION_INFO,
                data: vec![0],
            },
            // Supported Groups
            TlsExtension {
                ext_type: extension_type::SUPPORTED_GROUPS,
                data: vec![
                    0x00, 0x08, // Length
                    0x00, 0x1d, // x25519
                    0x00, 0x17, // secp256r1
                    0x00, 0x18, // secp384r1
                    0x00, 0x19, // secp521r1
                ],
            },
            // EC Point Formats
            TlsExtension {
                ext_type: extension_type::EC_POINT_FORMATS,
                data: vec![0x01, 0x00], // uncompressed
            },
            // Session Ticket
            TlsExtension {
                ext_type: extension_type::SESSION_TICKET,
                data: vec![],
            },
            // ALPN
            TlsExtension {
                ext_type: extension_type::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                data: vec![
                    0x00, 0x0c, // Length
                    0x02, b'h', b'2', // h2
                    0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1', // http/1.1
                ],
            },
            // Signature Algorithms
            TlsExtension {
                ext_type: extension_type::SIGNATURE_ALGORITHMS,
                data: vec![
                    0x00, 0x12, // Length
                    0x04, 0x03, // ecdsa_secp256r1_sha256
                    0x08, 0x04, // rsa_pss_rsae_sha256
                    0x04, 0x01, // rsa_pkcs1_sha256
                    0x05, 0x03, // ecdsa_secp384r1_sha384
                    0x08, 0x05, // rsa_pss_rsae_sha384
                    0x05, 0x01, // rsa_pkcs1_sha384
                    0x08, 0x06, // rsa_pss_rsae_sha512
                    0x06, 0x01, // rsa_pkcs1_sha512
                    0x02, 0x01, // rsa_pkcs1_sha1
                ],
            },
            // Supported Versions
            TlsExtension {
                ext_type: extension_type::SUPPORTED_VERSIONS,
                data: vec![
                    0x03, // Length
                    0x03, 0x04, // TLS 1.3
                          //0x03, 0x03, // TLS 1.2
                ],
            },
            // PSK Key Exchange Modes
            TlsExtension {
                ext_type: extension_type::PSK_KEY_EXCHANGE_MODES,
                data: vec![0x01, 0x01], // psk_dhe_ke
            },
            // Key Share (x25519)
            self.build_key_share_extension(),
        ];

        (cipher_suites, extensions)
    }

    /// Desktop Chrome profile
    fn chrome_desktop_profile(&self, sni: &str) -> (Vec<u16>, Vec<TlsExtension>) {
        // Similar to Android but with GREASE
        self.android_chrome_profile(sni)
    }

    /// Firefox profile
    fn firefox_profile(&self, sni: &str) -> (Vec<u16>, Vec<TlsExtension>) {
        // Firefox has slightly different cipher suite order
        let cipher_suites = vec![
            0x1301, // TLS_AES_128_GCM_SHA256
            0x1303, // TLS_CHACHA20_POLY1305_SHA256
            0x1302, // TLS_AES_256_GCM_SHA384
            0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        ];

        let extensions = vec![
            self.build_sni_extension(sni),
            TlsExtension {
                ext_type: extension_type::EXTENDED_MASTER_SECRET,
                data: vec![],
            },
            TlsExtension {
                ext_type: extension_type::RENEGOTIATION_INFO,
                data: vec![0],
            },
            TlsExtension {
                ext_type: extension_type::SUPPORTED_GROUPS,
                data: vec![
                    0x00, 0x06, 0x00, 0x1d, // x25519
                    0x00, 0x17, // secp256r1
                    0x00, 0x18, // secp384r1
                ],
            },
            TlsExtension {
                ext_type: extension_type::EC_POINT_FORMATS,
                data: vec![0x01, 0x00],
            },
            TlsExtension {
                ext_type: extension_type::SESSION_TICKET,
                data: vec![],
            },
            TlsExtension {
                ext_type: extension_type::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                data: vec![
                    0x00, 0x0c, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.',
                    b'1',
                ],
            },
            TlsExtension {
                ext_type: extension_type::SIGNATURE_ALGORITHMS,
                data: vec![
                    0x00, 0x10, 0x04, 0x03, // ecdsa_secp256r1_sha256
                    0x05, 0x03, // ecdsa_secp384r1_sha384
                    0x06, 0x03, // ecdsa_secp521r1_sha512
                    0x08, 0x04, // rsa_pss_rsae_sha256
                    0x08, 0x05, // rsa_pss_rsae_sha384
                    0x08, 0x06, // rsa_pss_rsae_sha512
                    0x04, 0x01, // rsa_pkcs1_sha256
                    0x05, 0x01, // rsa_pkcs1_sha384
                ],
            },
            TlsExtension {
                ext_type: extension_type::SUPPORTED_VERSIONS,
                data: vec![
                    0x03, 0x03, 0x04, // TLS 1.3
                ],
            },
            TlsExtension {
                ext_type: extension_type::PSK_KEY_EXCHANGE_MODES,
                data: vec![0x01, 0x01],
            },
            self.build_key_share_extension(),
        ];

        (cipher_suites, extensions)
    }

    fn build_sni_extension(&self, sni: &str) -> TlsExtension {
        let name_bytes = sni.as_bytes();
        let name_len = name_bytes.len() as u16;
        let list_len = name_len + 3;

        let mut data = Vec::new();
        data.extend_from_slice(&list_len.to_be_bytes());
        data.push(0); // Host name type
        data.extend_from_slice(&name_len.to_be_bytes());
        data.extend_from_slice(name_bytes);

        TlsExtension {
            ext_type: extension_type::SERVER_NAME,
            data,
        }
    }

    fn build_key_share_extension(&self) -> TlsExtension {
        // Generate random x25519 public key (32 bytes)
        let public_key = random_bytes(32);

        let mut data = Vec::new();
        // Client key share length
        data.extend_from_slice(&(36u16).to_be_bytes()); // 2 + 2 + 32
                                                        // x25519 group
        data.extend_from_slice(&(0x001du16).to_be_bytes());
        // Key length
        data.extend_from_slice(&(32u16).to_be_bytes());
        // Public key
        data.extend_from_slice(&public_key);

        TlsExtension {
            ext_type: extension_type::KEY_SHARE,
            data,
        }
    }
}

impl Default for TlsClientHelloBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_hello_builder() {
        let data = TlsClientHelloBuilder::new()
            .server_name("messenger.rubika.ir")
            .mimic(MimicTarget::Rubika)
            .build()
            .unwrap();

        // Should start with TLS record header
        assert_eq!(data[0], record_type::HANDSHAKE);
        assert_eq!(data[1], 0x03); // TLS 1.0 record
        assert_eq!(data[2], 0x01);
    }

    #[test]
    fn test_client_hello_parse() {
        let original = TlsClientHelloBuilder::new()
            .server_name("test.example.com")
            .build()
            .unwrap();

        let parsed = TlsClientHello::from_bytes(&original).unwrap();
        assert_eq!(parsed.get_sni(), Some("test.example.com".to_string()));
    }
}
