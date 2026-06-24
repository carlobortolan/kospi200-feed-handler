use std::fs::File;
use std::io::{Error, ErrorKind};
use std::net::UdpSocket;
use std::time::SystemTime;

const MAX_CAPTURE_SIZE: usize = 16 * 1024 * 1024; // 16 MB
const TARGET_PORTS: [u16; 2] = [15515, 15516]; // Specified UDP broadcast ports for the market data feed/// Global metadata for the parsed PCAP file.

/// Global metadata for the parsed PCAP file.
///
/// Extracted from the 24-byte global header to define how subsequent
/// timestamps and packet lengths should be decoded.
struct PcapContext {
    /// True if the PCAP was captured on a machine with opposite endianness.
    is_swapped: bool,

    /// True if the PCAP records timestamps in ns rather than default ms.
    is_nano: bool,

    /// Data Link Layer protocol used to calculate exact offsets when stripping network headers.
    link_type: u32,
}

/// Parses a PCAP file using zero-copy memory mapping (`mmap`).
///
/// Bypasses standard I/O syscall overhead by mapping the entire file into virtual
/// memory. Yields raw byte slices to the callback to avoid UTF-8 validation overhead.
pub fn run_pcap_source<F>(filename: &str, mut callback: F) -> Result<(), Box<dyn std::error::Error>>
where
    F: FnMut(u32, u32, &[u8]),
{
    let file = File::open(filename)?;

    // TODO: Assuming that PCAP file is not being truncated by another process
    // while reading it, which is standard for historical backtesting.
    let mmap = unsafe { memmap2::MmapOptions::new().map(&file)? };

    if mmap.len() < 24 {
        return Err(Box::new(Error::new(
            ErrorKind::UnexpectedEof,
            "File too small",
        )));
    }

    let context = read_pcap_context(&mmap[0..24])?;
    let mut cursor = 24;

    while cursor + 16 <= mmap.len() {
        let header = &mmap[cursor..cursor + 16];
        cursor += 16;

        let incl_len = read_u32(&header[8..12], context.is_swapped) as usize;

        if incl_len > MAX_CAPTURE_SIZE || cursor + incl_len > mmap.len() {
            cursor += incl_len;
            continue;
        }

        let ts_sec = read_u32(&header[0..4], context.is_swapped);
        let ts_fraction = read_u32(&header[4..8], context.is_swapped);
        let ts_usec = if context.is_nano {
            ts_fraction / 1000
        } else {
            ts_fraction
        };

        let packet_data = &mmap[cursor..cursor + incl_len];
        cursor += incl_len;

        if let Some(payload) = extract_udp_payload(packet_data, context.link_type) {
            callback(ts_sec, ts_usec, payload);
        }
    }
    Ok(())
}

/// Listens to a live UDP multicast or unicast feed.
///
/// Since the OS natively handles stripping the Data Link, Network, and Transport
/// layer headers, this function directly yields the application payload to the callback.
pub fn run_udp_source<F>(addr: &str, mut callback: F) -> Result<(), Box<dyn std::error::Error>>
where
    F: FnMut(u32, u32, &[u8]),
{
    let socket = UdpSocket::bind(addr)?;

    // If multicast IP (e.g., 239.0.0.1), join the group
    let ip: std::net::IpAddr = addr.split(':').next().unwrap().parse()?;
    if ip.is_multicast() {
        if let std::net::IpAddr::V4(ipv4) = ip {
            socket.join_multicast_v4(&ipv4, &std::net::Ipv4Addr::UNSPECIFIED)?;
        }
    }

    let mut buf = [0u8; 65536]; // Max UDP packet size (64 KB)

    loop {
        let (len, _src) = socket.recv_from(&mut buf)?;

        // UDP Packet arrival time
        let now: std::time::Duration = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
        let ts_sec = now.as_secs() as u32;
        let ts_usec = now.subsec_micros();

        callback(ts_sec, ts_usec, &buf[..len]);
    }
}

/// Parses the 24-byte PCAP global header.
///
/// Validates the PCAP magic number to determine the file's endianness
/// (native vs swapped) and timestamp precision (μs vs ns).
fn read_pcap_context(header: &[u8]) -> Result<PcapContext, Box<dyn std::error::Error>> {
    let magic = u32::from_ne_bytes(header[0..4].try_into().unwrap());
    let (is_swapped, is_nano) = match magic {
        0xa1b2c3d4 => (false, false),
        0xd4c3b2a1 => (true, false),
        0xa1b23c4d => (false, true),
        0x4d3cb2a1 => (true, true),
        _ => {
            return Err(Box::new(Error::new(
                ErrorKind::InvalidData,
                "invalid PCAP magic",
            )));
        }
    };

    let link_type = read_u32(&header[20..24], is_swapped);
    Ok(PcapContext {
        is_swapped,
        is_nano,
        link_type,
    })
}

/// Extract u32 from a raw byte slice.
///
/// Reads the bytes using the host CPU's native endianness. If the PCAP file
/// was captured on a machine with a different architecture (`swapped == true`),
/// it safely reverses the byte order to yield the correct integer.
fn read_u32(data: &[u8], swapped: bool) -> u32 {
    let value = u32::from_ne_bytes(data[0..4].try_into().unwrap());
    if swapped { value.swap_bytes() } else { value }
}

/// Strips the Data Link, Network and Transport layer headers from a raw network frame.
///
/// Returns `Some(&[u8])` pointing to the raw UDP payload if the packet is a valid IPv4
/// UDP datagram destined for the target market data ports. Otherwise, returns `None`.
fn extract_udp_payload(packet: &[u8], link_type: u32) -> Option<&[u8]> {
    // L1: Data Link Layer
    let mut offset = match link_type {
        1 => 14, // Ethernet header = 6 bytes Destination MAC + 6 bytes Source MAC + 2 bytes EtherType
        113 => 16, // Linux cooked capture
        12 => 0, // Raw IP
        _ => return None,
    };

    if link_type == 1 {
        if packet.len() < 14 {
            return None;
        }

        let eth_type = u16::from_be_bytes([packet[12], packet[13]]);

        // VLAN tagged Ethernet
        if eth_type == 0x8100 {
            offset += 4;
        }
    }

    // Validate IP Header
    if packet.len() < offset + 20 || packet[offset] >> 4 != 4 {
        return None;
    }

    // L2: Network Layer; Add IPv4 IHL to offset
    let ip_header_len = ((packet[offset] & 0x0f) as usize) * 4;

    let udp_offset = offset + ip_header_len;

    // L3: Transport Layer
    // UDP Header = 2 bytes Source Port + 2 bytes Destination Port + 2 bytes Length + 2 bytes Checksum
    if packet.len() < udp_offset + 8 {
        return None;
    }

    // Validate Protocol (10th byte of IPv4 Header == 17 => UDP)
    if packet[offset + 9] != 17 {
        return None;
    }

    // Validate Destination Port to match TARGET_PORTS
    let dst_port = u16::from_be_bytes([packet[udp_offset + 2], packet[udp_offset + 3]]); // Network Byte Order
    if !TARGET_PORTS.contains(&dst_port) {
        return None;
    }

    // L4: Application Layer
    Some(&packet[udp_offset + 8..])
}
