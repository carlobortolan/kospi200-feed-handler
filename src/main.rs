#![forbid(unsafe_code)]

use std::env;
use std::fs::File;
use std::io::{BufReader, Error, ErrorKind, Read};

const TARGET_PORTS: [u16; 2] = [15515, 15516];

struct PcapContext {
    swapped: bool,
    link_type: u32,
}

fn read_u16(data: &[u8], swapped: bool) -> u16 {
    let value = u16::from_ne_bytes([data[0], data[1]]);
    if swapped { value.swap_bytes() } else { value }
}

fn read_u32(data: &[u8], swapped: bool) -> u32 {
    let value = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);

    if swapped { value.swap_bytes() } else { value }
}

fn extract_udp_payload(packet: &[u8], link_type: u32) -> Option<&[u8]> {
    let mut offset = match link_type {
        1 => 14,   // Ethernet
        113 => 16, // Linux cooked capture
        12 => 0,   // Raw IP
        _ => return None,
    };

    if packet.len() < offset + 20 {
        return None;
    }

    let version = packet[offset] >> 4;

    if version != 4 {
        return None;
    }

    let ip_header_length = ((packet[offset] & 0x0f) as usize) * 4;

    if packet.len() < offset + ip_header_length {
        return None;
    }

    let protocol = packet[offset + 9];

    if protocol != 17 {
        return None;
    }

    let udp_offset = offset + ip_header_length;

    if packet.len() < udp_offset + 8 {
        return None;
    }

    let destination_port = u16::from_be_bytes([packet[udp_offset + 2], packet[udp_offset + 3]]);

    if !TARGET_PORTS.contains(&destination_port) {
        return None;
    }

    let payload_offset = udp_offset + 8;

    if payload_offset >= packet.len() {
        return None;
    }

    Some(&packet[payload_offset..])
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <pcap_file>", args[0]);
        std::process::exit(1);
    }

    let file = File::open(&args[1])?;
    let mut reader = BufReader::new(file);

    let mut global_header = [0u8; 24];

    reader.read_exact(&mut global_header)?;

    let magic = u32::from_ne_bytes([
        global_header[0],
        global_header[1],
        global_header[2],
        global_header[3],
    ]);

    let swapped = match magic {
        0xa1b2c3d4 => false,
        0xd4c3b2a1 => true,
        _ => {
            return Err(Box::new(Error::new(
                ErrorKind::InvalidData,
                "invalid pcap magic",
            )));
        }
    };

    let link_type = read_u32(&global_header[20..24], swapped);

    let ctx = PcapContext { swapped, link_type };

    let mut packet_header = [0u8; 16];

    loop {
        match reader.read_exact(&mut packet_header) {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(Box::new(e)),
        }

        let captured_length = read_u32(&packet_header[8..12], ctx.swapped);

        let mut packet = vec![0u8; captured_length as usize];

        reader.read_exact(&mut packet)?;

        if let Some(payload) = extract_udp_payload(&packet, ctx.link_type) {
            println!("udp payload found: {} bytes", payload.len());
        }
    }

    Ok(())
}
