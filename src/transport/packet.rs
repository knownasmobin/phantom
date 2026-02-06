//! Packet structures and builders for raw packet crafting

use crate::error::{PhantomError, Result};
use crate::utils::{internet_checksum, tcp_checksum, icmp_checksum, random_u16, random_u32};
use std::net::Ipv4Addr;

/// IP Header (20 bytes without options)
#[derive(Debug, Clone)]
pub struct IpHeader {
    pub version: u8,           // 4 bits
    pub ihl: u8,               // 4 bits (header length in 32-bit words)
    pub dscp: u8,              // 6 bits
    pub ecn: u8,               // 2 bits
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,             // 3 bits
    pub fragment_offset: u16,  // 13 bits
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
}

impl IpHeader {
    pub const MIN_SIZE: usize = 20;

    pub fn new(protocol: u8, src: Ipv4Addr, dst: Ipv4Addr) -> Self {
        Self {
            version: 4,
            ihl: 5, // No options
            dscp: 0,
            ecn: 0,
            total_length: 0, // Set later
            identification: random_u16(),
            flags: 0x02, // Don't Fragment
            fragment_offset: 0,
            ttl: 64,
            protocol,
            checksum: 0, // Calculated later
            src_ip: src,
            dst_ip: dst,
        }
    }

    pub fn to_bytes(&self) -> [u8; 20] {
        let mut buf = [0u8; 20];

        buf[0] = (self.version << 4) | self.ihl;
        buf[1] = (self.dscp << 2) | self.ecn;
        buf[2..4].copy_from_slice(&self.total_length.to_be_bytes());
        buf[4..6].copy_from_slice(&self.identification.to_be_bytes());

        let flags_frag = ((self.flags as u16) << 13) | self.fragment_offset;
        buf[6..8].copy_from_slice(&flags_frag.to_be_bytes());

        buf[8] = self.ttl;
        buf[9] = self.protocol;
        buf[10..12].copy_from_slice(&self.checksum.to_be_bytes());
        buf[12..16].copy_from_slice(&self.src_ip.octets());
        buf[16..20].copy_from_slice(&self.dst_ip.octets());

        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 20 {
            return Err(PhantomError::PacketParse("IP header too short".into()));
        }

        let version = data[0] >> 4;
        let ihl = data[0] & 0x0F;

        if version != 4 {
            return Err(PhantomError::PacketParse(format!("Invalid IP version: {}", version)));
        }

        let flags_frag = u16::from_be_bytes([data[6], data[7]]);

        Ok(Self {
            version,
            ihl,
            dscp: data[1] >> 2,
            ecn: data[1] & 0x03,
            total_length: u16::from_be_bytes([data[2], data[3]]),
            identification: u16::from_be_bytes([data[4], data[5]]),
            flags: (flags_frag >> 13) as u8,
            fragment_offset: flags_frag & 0x1FFF,
            ttl: data[8],
            protocol: data[9],
            checksum: u16::from_be_bytes([data[10], data[11]]),
            src_ip: Ipv4Addr::new(data[12], data[13], data[14], data[15]),
            dst_ip: Ipv4Addr::new(data[16], data[17], data[18], data[19]),
        })
    }

    pub fn calculate_checksum(&mut self) {
        self.checksum = 0;
        let bytes = self.to_bytes();
        self.checksum = internet_checksum(&bytes);
    }
}

/// TCP Header (20 bytes without options)
#[derive(Debug, Clone)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset: u8,   // 4 bits (header length in 32-bit words)
    pub reserved: u8,      // 3 bits
    pub flags: TcpFlags,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TcpFlags {
    pub ns: bool,
    pub cwr: bool,
    pub ece: bool,
    pub urg: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,
}

impl TcpFlags {
    pub fn syn() -> Self {
        Self { syn: true, ..Default::default() }
    }

    pub fn syn_ack() -> Self {
        Self { syn: true, ack: true, ..Default::default() }
    }

    pub fn ack() -> Self {
        Self { ack: true, ..Default::default() }
    }

    pub fn psh_ack() -> Self {
        Self { psh: true, ack: true, ..Default::default() }
    }

    pub fn fin_ack() -> Self {
        Self { fin: true, ack: true, ..Default::default() }
    }

    pub fn rst() -> Self {
        Self { rst: true, ..Default::default() }
    }

    pub fn to_u16(&self) -> u16 {
        let mut flags: u16 = 0;
        if self.ns  { flags |= 0x100; }
        if self.cwr { flags |= 0x080; }
        if self.ece { flags |= 0x040; }
        if self.urg { flags |= 0x020; }
        if self.ack { flags |= 0x010; }
        if self.psh { flags |= 0x008; }
        if self.rst { flags |= 0x004; }
        if self.syn { flags |= 0x002; }
        if self.fin { flags |= 0x001; }
        flags
    }

    pub fn from_u16(flags: u16) -> Self {
        Self {
            ns:  flags & 0x100 != 0,
            cwr: flags & 0x080 != 0,
            ece: flags & 0x040 != 0,
            urg: flags & 0x020 != 0,
            ack: flags & 0x010 != 0,
            psh: flags & 0x008 != 0,
            rst: flags & 0x004 != 0,
            syn: flags & 0x002 != 0,
            fin: flags & 0x001 != 0,
        }
    }
}

impl TcpHeader {
    pub const MIN_SIZE: usize = 20;

    pub fn new(src_port: u16, dst_port: u16) -> Self {
        Self {
            src_port,
            dst_port,
            seq_num: random_u32(),
            ack_num: 0,
            data_offset: 5, // No options
            reserved: 0,
            flags: TcpFlags::default(),
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
        }
    }

    pub fn to_bytes(&self) -> [u8; 20] {
        let mut buf = [0u8; 20];

        buf[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        buf[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        buf[4..8].copy_from_slice(&self.seq_num.to_be_bytes());
        buf[8..12].copy_from_slice(&self.ack_num.to_be_bytes());

        let offset_flags = ((self.data_offset as u16) << 12) | self.flags.to_u16();
        buf[12..14].copy_from_slice(&offset_flags.to_be_bytes());

        buf[14..16].copy_from_slice(&self.window.to_be_bytes());
        buf[16..18].copy_from_slice(&self.checksum.to_be_bytes());
        buf[18..20].copy_from_slice(&self.urgent_ptr.to_be_bytes());

        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 20 {
            return Err(PhantomError::PacketParse("TCP header too short".into()));
        }

        let offset_flags = u16::from_be_bytes([data[12], data[13]]);

        Ok(Self {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            seq_num: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            ack_num: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            data_offset: (offset_flags >> 12) as u8,
            reserved: 0,
            flags: TcpFlags::from_u16(offset_flags & 0x1FF),
            window: u16::from_be_bytes([data[14], data[15]]),
            checksum: u16::from_be_bytes([data[16], data[17]]),
            urgent_ptr: u16::from_be_bytes([data[18], data[19]]),
        })
    }

    pub fn calculate_checksum(&mut self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, payload: &[u8]) {
        self.checksum = 0;
        let mut tcp_data = self.to_bytes().to_vec();
        tcp_data.extend_from_slice(payload);
        self.checksum = tcp_checksum(src_ip, dst_ip, 6, &tcp_data);
    }
}

/// ICMP Header (8 bytes for Echo)
#[derive(Debug, Clone)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub identifier: u16,
    pub sequence: u16,
}

impl IcmpHeader {
    pub const SIZE: usize = 8;

    // ICMP Types
    pub const ECHO_REPLY: u8 = 0;
    pub const ECHO_REQUEST: u8 = 8;

    pub fn echo_request(identifier: u16, sequence: u16) -> Self {
        Self {
            icmp_type: Self::ECHO_REQUEST,
            code: 0,
            checksum: 0,
            identifier,
            sequence,
        }
    }

    pub fn echo_reply(identifier: u16, sequence: u16) -> Self {
        Self {
            icmp_type: Self::ECHO_REPLY,
            code: 0,
            checksum: 0,
            identifier,
            sequence,
        }
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[0] = self.icmp_type;
        buf[1] = self.code;
        buf[2..4].copy_from_slice(&self.checksum.to_be_bytes());
        buf[4..6].copy_from_slice(&self.identifier.to_be_bytes());
        buf[6..8].copy_from_slice(&self.sequence.to_be_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 8 {
            return Err(PhantomError::PacketParse("ICMP header too short".into()));
        }

        Ok(Self {
            icmp_type: data[0],
            code: data[1],
            checksum: u16::from_be_bytes([data[2], data[3]]),
            identifier: u16::from_be_bytes([data[4], data[5]]),
            sequence: u16::from_be_bytes([data[6], data[7]]),
        })
    }

    pub fn calculate_checksum(&mut self, payload: &[u8]) {
        self.checksum = 0;
        let mut icmp_data = self.to_bytes().to_vec();
        icmp_data.extend_from_slice(payload);
        self.checksum = icmp_checksum(&icmp_data);
    }
}

/// A complete packet (IP + transport + payload)
#[derive(Debug, Clone)]
pub struct Packet {
    pub ip: IpHeader,
    pub transport: TransportHeader,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum TransportHeader {
    Tcp(TcpHeader),
    Icmp(IcmpHeader),
    Raw, // For Protocol 115, no transport header
}

impl Packet {
    pub fn to_bytes(&mut self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Calculate total length
        let transport_len = match &self.transport {
            TransportHeader::Tcp(_) => TcpHeader::MIN_SIZE,
            TransportHeader::Icmp(_) => IcmpHeader::SIZE,
            TransportHeader::Raw => 0,
        };
        self.ip.total_length = (IpHeader::MIN_SIZE + transport_len + self.payload.len()) as u16;

        // Calculate checksums
        self.ip.calculate_checksum();

        match &mut self.transport {
            TransportHeader::Tcp(tcp) => {
                tcp.calculate_checksum(self.ip.src_ip, self.ip.dst_ip, &self.payload);
            }
            TransportHeader::Icmp(icmp) => {
                icmp.calculate_checksum(&self.payload);
            }
            TransportHeader::Raw => {}
        }

        // Build packet
        buf.extend_from_slice(&self.ip.to_bytes());
        match &self.transport {
            TransportHeader::Tcp(tcp) => buf.extend_from_slice(&tcp.to_bytes()),
            TransportHeader::Icmp(icmp) => buf.extend_from_slice(&icmp.to_bytes()),
            TransportHeader::Raw => {}
        }
        buf.extend_from_slice(&self.payload);

        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let ip = IpHeader::from_bytes(data)?;
        let header_len = (ip.ihl as usize) * 4;

        if data.len() < header_len {
            return Err(PhantomError::PacketParse("Packet too short".into()));
        }

        let transport_data = &data[header_len..];

        let (transport, payload_offset) = match ip.protocol {
            6 => {
                let tcp = TcpHeader::from_bytes(transport_data)?;
                let offset = (tcp.data_offset as usize) * 4;
                (TransportHeader::Tcp(tcp), offset)
            }
            1 => {
                let icmp = IcmpHeader::from_bytes(transport_data)?;
                (TransportHeader::Icmp(icmp), IcmpHeader::SIZE)
            }
            115 => (TransportHeader::Raw, 0),
            _ => (TransportHeader::Raw, 0),
        };

        let payload = if payload_offset < transport_data.len() {
            transport_data[payload_offset..].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self { ip, transport, payload })
    }
}

/// Builder for constructing packets
pub struct PacketBuilder {
    ip: IpHeader,
    transport: Option<TransportHeader>,
    payload: Vec<u8>,
}

impl PacketBuilder {
    pub fn new(protocol: u8, src: Ipv4Addr, dst: Ipv4Addr) -> Self {
        Self {
            ip: IpHeader::new(protocol, src, dst),
            transport: None,
            payload: Vec::new(),
        }
    }

    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ip.ttl = ttl;
        self
    }

    pub fn identification(mut self, id: u16) -> Self {
        self.ip.identification = id;
        self
    }

    pub fn tcp(mut self, src_port: u16, dst_port: u16) -> Self {
        self.ip.protocol = 6;
        self.transport = Some(TransportHeader::Tcp(TcpHeader::new(src_port, dst_port)));
        self
    }

    pub fn tcp_flags(mut self, flags: TcpFlags) -> Self {
        if let Some(TransportHeader::Tcp(ref mut tcp)) = self.transport {
            tcp.flags = flags;
        }
        self
    }

    pub fn tcp_seq(mut self, seq: u32) -> Self {
        if let Some(TransportHeader::Tcp(ref mut tcp)) = self.transport {
            tcp.seq_num = seq;
        }
        self
    }

    pub fn tcp_ack(mut self, ack: u32) -> Self {
        if let Some(TransportHeader::Tcp(ref mut tcp)) = self.transport {
            tcp.ack_num = ack;
        }
        self
    }

    pub fn tcp_window(mut self, window: u16) -> Self {
        if let Some(TransportHeader::Tcp(ref mut tcp)) = self.transport {
            tcp.window = window;
        }
        self
    }

    pub fn icmp_echo_request(mut self, id: u16, seq: u16) -> Self {
        self.ip.protocol = 1;
        self.transport = Some(TransportHeader::Icmp(IcmpHeader::echo_request(id, seq)));
        self
    }

    pub fn icmp_echo_reply(mut self, id: u16, seq: u16) -> Self {
        self.ip.protocol = 1;
        self.transport = Some(TransportHeader::Icmp(IcmpHeader::echo_reply(id, seq)));
        self
    }

    pub fn protocol_115(mut self) -> Self {
        self.ip.protocol = 115;
        self.transport = Some(TransportHeader::Raw);
        self
    }

    pub fn payload(mut self, data: &[u8]) -> Self {
        self.payload = data.to_vec();
        self
    }

    pub fn build(self) -> Packet {
        Packet {
            ip: self.ip,
            transport: self.transport.unwrap_or(TransportHeader::Raw),
            payload: self.payload,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_header_roundtrip() {
        let mut ip = IpHeader::new(6, "192.168.1.1".parse().unwrap(), "10.0.0.1".parse().unwrap());
        ip.total_length = 60;
        ip.calculate_checksum();

        let bytes = ip.to_bytes();
        let parsed = IpHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.src_ip, ip.src_ip);
        assert_eq!(parsed.dst_ip, ip.dst_ip);
        assert_eq!(parsed.protocol, 6);
    }

    #[test]
    fn test_tcp_header_roundtrip() {
        let mut tcp = TcpHeader::new(12345, 443);
        tcp.flags = TcpFlags::syn();
        tcp.seq_num = 1000;

        let bytes = tcp.to_bytes();
        let parsed = TcpHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.src_port, 12345);
        assert_eq!(parsed.dst_port, 443);
        assert!(parsed.flags.syn);
    }
}
