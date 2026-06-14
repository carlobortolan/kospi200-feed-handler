#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::env;
use std::fs::File;
use std::io::{BufReader, Error, ErrorKind, Read};

const TARGET_PORTS: [u16; 2] = [15515, 15516];
const QUOTE_PACKET_MAGIC: &[u8] = b"B6034";
const QUOTE_PACKET_LENGTH: usize = 215;
const MAX_DELAY_MICROSECONDS: u64 = 3_000_000;
const MAX_CAPTURE_SIZE: usize = 16 * 1024 * 1024;

#[derive(Debug, Eq, PartialEq)]
struct QuotePacket {
    accept_key: u64,
    pkt_time: u64,
    output: String,
}

impl Ord for QuotePacket {
    fn cmp(&self, other: &Self) -> Ordering {
        self.accept_key
            .cmp(&other.accept_key)
            .then_with(|| self.pkt_time.cmp(&other.pkt_time))
    }
}

impl PartialOrd for QuotePacket {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

struct PcapContext {
    swapped: bool,
    is_nano: bool,
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

    let ip_len = ((packet[offset] & 0x0f) as usize) * 4;

    if ip_len < 20 {
        return None;
    }

    let udp_offset = offset + ip_len;

    if packet.len() < udp_offset + 8 {
        return None;
    }

    if packet[offset + 9] != 17 {
        return None;
    }

    let port = u16::from_be_bytes([packet[udp_offset + 2], packet[udp_offset + 3]]);

    if !TARGET_PORTS.contains(&port) {
        return None;
    }

    Some(&packet[udp_offset + 8..])
}

fn extract_quote(payload: &[u8]) -> Option<&[u8]> {
    if payload.len() < QUOTE_PACKET_LENGTH {
        return None;
    }

    if &payload[..5] != QUOTE_PACKET_MAGIC {
        return None;
    }

    Some(&payload[..QUOTE_PACKET_LENGTH])
}

fn format_output_string(ts_sec: u32, ts_fraction: u32, payload: &[u8]) -> String {
    let issue = std::str::from_utf8(&payload[5..17]).unwrap_or("");

    let accept = std::str::from_utf8(&payload[206..214]).unwrap_or("");

    let mut output = String::with_capacity(256);

    output.push_str(&format!(
        "{}.{:06} {} {}",
        ts_sec, ts_fraction, accept, issue
    ));

    output
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    let file_name = args.get(1).ok_or("missing file")?;

    let file = File::open(file_name)?;

    let mut reader = BufReader::with_capacity(256 * 1024, file);

    let mut global = [0u8; 24];

    reader.read_exact(&mut global)?;

    let magic = u32::from_ne_bytes([global[0], global[1], global[2], global[3]]);

    let (swapped, is_nano) = match magic {
        0xa1b2c3d4 => (false, false),
        0xd4c3b2a1 => (true, false),
        0xa1b23c4d => (false, true),
        0x4d3cb2a1 => (true, true),
        _ => {
            return Err(Box::new(Error::new(ErrorKind::InvalidData, "invalid pcap")));
        }
    };

    let ctx = PcapContext {
        swapped,
        is_nano,
        link_type: read_u32(&global[20..24], swapped),
    };

    let mut heap = BinaryHeap::<Reverse<QuotePacket>>::new();

    let mut packet_buffer = Vec::new();

    let mut header = [0u8; 16];

    while reader.read_exact(&mut header).is_ok() {
        let incl_len = read_u32(&header[8..12], ctx.swapped) as usize;

        if incl_len > MAX_CAPTURE_SIZE {
            continue;
        }

        packet_buffer.resize(incl_len, 0);

        reader.read_exact(&mut packet_buffer)?;

        let packet = &packet_buffer[..incl_len];

        if let Some(payload) = extract_udp_payload(packet, ctx.link_type) {
            if let Some(quote) = extract_quote(payload) {
                let key = u64::from_be_bytes(quote[206..214].try_into().unwrap());

                heap.push(Reverse(QuotePacket {
                    accept_key: key,
                    pkt_time: 0,
                    output: format_output_string(0, 0, quote),
                }));
            }
        }
    }

    while let Some(Reverse(packet)) = heap.pop() {
        println!("{}", packet.output);
    }

    Ok(())
}
