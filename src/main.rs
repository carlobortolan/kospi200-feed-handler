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

    let ip_header_length = ((packet[offset] & 0x0f) as usize) * 4;

    if ip_header_length < 20 {
        return None;
    }

    if packet.len() < offset + ip_header_length {
        return None;
    }

    if packet[offset + 9] != 17 {
        return None;
    }

    let udp_offset = offset + ip_header_length;

    if packet.len() < udp_offset + 8 {
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

    if &payload[..5] != QUOTE_PACKET_MAGIC {
        return None;
    }

    if payload.len() < 214 {
        return None;
    }

    Some(&payload[..QUOTE_PACKET_LENGTH])
}

fn format_timestamp(seconds: u32, fraction: u32, nano: bool) -> u64 {
    let micros = if nano { fraction / 1000 } else { fraction };

    seconds as u64 * 1_000_000 + micros as u64
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        return Err("missing pcap file".into());
    }

    let file = File::open(&args[1])?;
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
            return Err(Box::new(Error::new(
                ErrorKind::InvalidData,
                "invalid pcap magic",
            )));
        }
    };

    let ctx = PcapContext {
        swapped,
        is_nano,
        link_type: read_u32(&global[20..24], swapped),
    };

    let mut heap = BinaryHeap::<Reverse<QuotePacket>>::new();

    let mut max_pkt_time = 0u64;

    let mut packet_header = [0u8; 16];

    loop {
        match reader.read_exact(&mut packet_header) {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(Box::new(e)),
        }

        let incl_len = read_u32(&packet_header[8..12], ctx.swapped) as usize;

        if incl_len > MAX_CAPTURE_SIZE {
            let mut skip = vec![0u8; incl_len];
            if reader.read_exact(&mut skip).is_err() {
                break;
            }
            continue;
        }

        let ts_sec = read_u32(&packet_header[0..4], ctx.swapped);

        let ts_fraction = read_u32(&packet_header[4..8], ctx.swapped);

        let pkt_time = format_timestamp(ts_sec, ts_fraction, ctx.is_nano);

        if pkt_time > max_pkt_time {
            max_pkt_time = pkt_time;
        }

        let mut packet = vec![0u8; incl_len];

        if reader.read_exact(&mut packet).is_err() {
            break;
        }

        if let Some(payload) = extract_udp_payload(&packet, ctx.link_type) {
            if let Some(quote) = extract_quote(payload) {
                if let Ok(key_bytes) = <[u8; 8]>::try_from(&quote[206..214]) {
                    let key = u64::from_be_bytes(key_bytes);

                    heap.push(Reverse(QuotePacket {
                        accept_key: key,
                        pkt_time,
                        output: format!("{}", key),
                    }));
                }
            }
        }
    }

    while let Some(Reverse(packet)) = heap.pop() {
        println!("{}", packet.output);
    }

    Ok(())
}
