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

    let udp_offset = offset + ip_len;

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
    let issue = std::str::from_utf8(&payload[5..17]).unwrap_or("");

    let accept = std::str::from_utf8(&payload[206..214]).unwrap_or("");

    format!("{}.{:06} {} {}", ts_sec, ts_usec, accept, issue)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    let mut reorder = false;
    let mut filename = None;

    for arg in args.iter().skip(1) {
        if arg == "-r" {
            reorder = true;
        } else {
            filename = Some(arg);
        }
    }

    let file = File::open(filename.ok_or("missing file")?)?;

    let mut reader = BufReader::new(file);

    let mut global_header = [0u8; 24];
    reader.read_exact(&mut global_header)?;

    let magic = u32::from_ne_bytes([
        global_header[0],
        global_header[1],
        global_header[2],
        global_header[3],
    ]);

    let swapped = magic == 0xd4c3b2a1;

    let ctx = PcapContext {
        swapped,
        link_type: read_u32(&global_header[20..24], swapped),
    };

    let mut heap: BinaryHeap<Reverse<QuotePacket>> = BinaryHeap::new();

    let mut max_pkt_time = 0u64;

    let mut packet_header = [0u8; 16];

    loop {
        if reader.read_exact(&mut packet_header).is_err() {
            break;
        }

        let length = read_u32(&packet_header[8..12], ctx.swapped);

        let ts_sec = read_u32(&packet_header[0..4], ctx.swapped);

        let ts_usec = read_u32(&packet_header[4..8], ctx.swapped);

        let current_time = ts_sec as u64 * 1_000_000 + ts_usec as u64;

        if current_time > max_pkt_time {
            max_pkt_time = current_time;
        }

        let mut packet = vec![0u8; length as usize];
        reader.read_exact(&mut packet)?;

        if let Some(payload) = extract_udp_payload(&packet, ctx.link_type) {
            if let Some(quote) = extract_quote(payload) {
                let accept_key = u64::from_be_bytes(quote[206..214].try_into().unwrap());

                let output = format_output_string(ts_sec, ts_usec, quote);

                if reorder {
                    heap.push(Reverse(QuotePacket {
                        accept_key,
                        pkt_time: current_time,
                        output,
                    }));

                    while let Some(Reverse(packet)) = heap.peek() {
                        if packet.pkt_time + MAX_DELAY_MICROSECONDS <= max_pkt_time {
                            println!("{}", heap.pop().unwrap().0.output);
                        } else {
                            break;
                        }
                    }
                } else {
                    println!("{}", output);
                }
            }
        }
    }

    while let Some(Reverse(packet)) = heap.pop() {
        println!("{}", packet.output);
    }

    Ok(())
}
