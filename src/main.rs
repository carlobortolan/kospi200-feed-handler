#![forbid(unsafe_code)]

use std::env;
use std::fs::File;
use std::io::{BufReader, Error, ErrorKind, Read};

const TARGET_PORTS: [u16; 2] = [15515, 15516];
const QUOTE_PACKET_MAGIC: &[u8] = b"B6034";
const QUOTE_PACKET_LENGTH: usize = 215;

struct PcapContext {
    swapped: bool,
    link_type: u32,
}

fn read_u32(data: &[u8], swapped: bool) -> u32 {
    let value = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);

    if swapped { value.swap_bytes() } else { value }
}

fn extract_udp_payload(packet: &[u8], link_type: u32) -> Option<&[u8]> {
    let offset = match link_type {
        1 => 14,
        113 => 16,
        12 => 0,
        _ => return None,
    };

    if packet.len() < offset + 20 {
        return None;
    }

    if packet[offset] >> 4 != 4 {
        return None;
    }

    let ip_header_length = ((packet[offset] & 0x0f) as usize) * 4;

    let udp_offset = offset + ip_header_length;

    if packet.len() < udp_offset + 8 {
        return None;
    }

    if packet[offset + 9] != 17 {
        return None;
    }

    let dst_port = u16::from_be_bytes([packet[udp_offset + 2], packet[udp_offset + 3]]);

    if !TARGET_PORTS.contains(&dst_port) {
        return None;
    }

    Some(&packet[udp_offset + 8..])
}

fn extract_quote(payload: &[u8]) -> Option<&[u8]> {
    if payload.len() < QUOTE_PACKET_LENGTH {
        return None;
    }

    if &payload[0..5] != QUOTE_PACKET_MAGIC {
        return None;
    }

    Some(&payload[..QUOTE_PACKET_LENGTH])
}

fn format_output_string(ts_sec: u32, ts_usec: u32, payload: &[u8]) -> String {
    let issue_code = std::str::from_utf8(&payload[5..17]).unwrap_or("");

    let accept_time = std::str::from_utf8(&payload[206..214]).unwrap_or("");

    let mut output = format!("{}.{:06} {} {}", ts_sec, ts_usec, accept_time, issue_code);

    let bids = [
        (77, 82, 82, 89),
        (65, 70, 70, 77),
        (53, 58, 58, 65),
        (41, 46, 46, 53),
        (29, 34, 34, 41),
    ];

    for &(ps, pe, qs, qe) in bids.iter() {
        let price = std::str::from_utf8(&payload[ps..pe]).unwrap_or("");

        let qty = std::str::from_utf8(&payload[qs..qe]).unwrap_or("");

        output.push_str(&format!(" {}@{}", qty, price));
    }

    let asks = [
        (96, 101, 101, 108),
        (108, 113, 113, 120),
        (120, 125, 125, 132),
        (132, 137, 137, 144),
        (144, 149, 149, 156),
    ];

    for &(ps, pe, qs, qe) in asks.iter() {
        let price = std::str::from_utf8(&payload[ps..pe]).unwrap_or("");

        let qty = std::str::from_utf8(&payload[qs..qe]).unwrap_or("");

        output.push_str(&format!(" {}@{}", qty, price));
    }

    output
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

    let ctx = PcapContext {
        swapped,
        link_type: read_u32(&global_header[20..24], swapped),
    };

    let mut packet_header = [0u8; 16];

    loop {
        match reader.read_exact(&mut packet_header) {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(Box::new(e)),
        }

        let length = read_u32(&packet_header[8..12], ctx.swapped);

        let mut packet = vec![0u8; length as usize];

        reader.read_exact(&mut packet)?;

        if let Some(payload) = extract_udp_payload(&packet, ctx.link_type) {
            if let Some(quote) = extract_quote(payload) {
                let ts_sec = read_u32(&packet_header[0..4], ctx.swapped);

                let ts_usec = read_u32(&packet_header[4..8], ctx.swapped);

                println!("{}", format_output_string(ts_sec, ts_usec, quote));
            }
        }
    }

    Ok(())
}
