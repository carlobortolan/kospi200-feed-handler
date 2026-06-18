#![forbid(unsafe_code)]

/*
 * Time Complexity:
 * O(N * log K) where N is the number of packets and K is the maximum number
 * of packets buffered in the reorder window.
 *
 * Space Complexity:
 * O(K) where K is the maximum reorder buffer size.
 */

use std::cmp::Ordering;
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fmt::Write as _; // Required for the write! macro optimization
use std::fs::File;
use std::io::{BufReader, Error, ErrorKind, Read};

const MAX_DELAY_MICROSECONDS: u64 = 3_000_000;

const MAX_CAPTURE_SIZE: usize = 16 * 1024 * 1024;

const QUOTE_PACKET_MAGIC: &[u8] = b"B6034";

const QUOTE_PACKET_LENGTH: usize = 215;

const TARGET_PORTS: [u16; 2] = [15515, 15516];

/// Statistics returned after parsing.
///
/// Used by:
/// - CLI diagnostics
/// - integration tests
/// - performance validation
#[derive(Debug, Default)]
pub struct ParseStats {
    pub quotes: usize,
    pub max_heap_size: usize,
}

#[derive(Eq, PartialEq)]
struct QuotePacket {
    accept_key: u64,
    pkt_time: u64,

    ts_sec: u32,
    ts_usec: u32,

    payload: [u8; QUOTE_PACKET_LENGTH],
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
    is_swapped: bool,

    is_nano: bool,

    link_type: u32,
}

/// Parse a PCAP file and stream every output line.
///
/// This avoids storing the entire output in memory.
pub fn parse_pcap_with_stats<F>(
    filename: &str,
    reorder: bool,
    mut callback: F,
) -> Result<ParseStats, Box<dyn std::error::Error>>
where
    F: FnMut(String),
{
    let file = File::open(filename)?;

    let mut reader = BufReader::with_capacity(256 * 1024, file);

    let context = read_pcap_context(&mut reader)?;

    let mut heap = BinaryHeap::<Reverse<QuotePacket>>::new();

    let mut packet_buffer = Vec::new();

    let mut packet_header = [0u8; 16];

    let mut max_time = 0u64;

    let mut stats = ParseStats::default();

    while reader.read_exact(&mut packet_header).is_ok() {
        let incl_len = read_u32(&packet_header[8..12], context.is_swapped) as usize;

        if incl_len > MAX_CAPTURE_SIZE {
            continue;
        }

        let ts_sec = read_u32(&packet_header[0..4], context.is_swapped);

        let ts_fraction = read_u32(&packet_header[4..8], context.is_swapped);

        let ts_usec = if context.is_nano {
            ts_fraction / 1000
        } else {
            ts_fraction
        };

        let pkt_time = ts_sec as u64 * 1_000_000 + ts_usec as u64;

        max_time = max_time.max(pkt_time);

        packet_buffer.resize(incl_len, 0);

        reader.read_exact(&mut packet_buffer)?;

        if let Some(payload) = extract_udp_payload(&packet_buffer, context.link_type) {
            if let Some(quote) = extract_quote(payload) {
                stats.quotes += 1;

                if !reorder {
                    callback(format_output_string(ts_sec, ts_usec, quote));

                    continue;
                }

                let accept_key = u64::from_be_bytes(quote[206..214].try_into().unwrap());

                // Copy bytes safely into fixed-size array
                let mut payload_arr = [0u8; QUOTE_PACKET_LENGTH];

                payload_arr.copy_from_slice(quote);

                heap.push(Reverse(QuotePacket {
                    accept_key,
                    pkt_time,
                    ts_sec,
                    ts_usec,
                    payload: payload_arr,
                }));

                stats.max_heap_size = stats.max_heap_size.max(heap.len());

                flush_expired(&mut heap, max_time, &mut callback);
            }
        }
    }

    if reorder {
        while let Some(Reverse(packet)) = heap.pop() {
            callback(format_output_string(
                packet.ts_sec,
                packet.ts_usec,
                &packet.payload,
            ));
        }
    }

    Ok(stats)
}

/// Convenience function for tests.
///
/// Collects all output into memory.
pub fn parse_pcap(
    filename: &str,
    reorder: bool,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut result = Vec::new();

    parse_pcap_with_stats(filename, reorder, |line| {
        result.push(line);
    })?;

    Ok(result)
}

/// Convenience function for golden-file tests.
pub fn parse_to_string(filename: &str, reorder: bool) -> String {
    parse_pcap(filename, reorder).unwrap().join("\n")
}

fn read_u32(data: &[u8], swapped: bool) -> u32 {
    let value = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);

    if swapped { value.swap_bytes() } else { value }
}

fn read_pcap_context(
    reader: &mut BufReader<File>,
) -> Result<PcapContext, Box<dyn std::error::Error>> {
    let mut global_header = [0u8; 24];

    reader.read_exact(&mut global_header)?;

    let magic = u32::from_ne_bytes(global_header[0..4].try_into().unwrap());

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

    let link_type = read_u32(&global_header[20..24], is_swapped);

    Ok(PcapContext {
        is_swapped,
        is_nano,
        link_type,
    })
}

fn extract_udp_payload(packet: &[u8], link_type: u32) -> Option<&[u8]> {
    let mut offset = match link_type {
        // Ethernet
        1 => 14,

        // Linux cooked capture
        113 => 16,

        // Raw IP
        12 => 0,

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

    if packet.len() < offset + 20 {
        return None;
    }

    let version = packet[offset] >> 4;

    if version != 4 {
        return None;
    }

    let ip_header_len = ((packet[offset] & 0x0f) as usize) * 4;

    let udp_offset = offset + ip_header_len;

    if packet.len() < udp_offset + 8 {
        return None;
    }

    let protocol = packet[offset + 9];

    if protocol != 17 {
        return None;
    }

    let dst_port = u16::from_be_bytes([packet[udp_offset + 2], packet[udp_offset + 3]]);

    if !TARGET_PORTS.contains(&dst_port) {
        return None;
    }

    Some(&packet[udp_offset + 8..])
}

pub fn extract_quote(payload: &[u8]) -> Option<&[u8]> {
    if payload.len() < QUOTE_PACKET_LENGTH {
        return None;
    }

    if &payload[..5] != QUOTE_PACKET_MAGIC {
        return None;
    }

    Some(&payload[..QUOTE_PACKET_LENGTH])
}

fn flush_expired<F>(heap: &mut BinaryHeap<Reverse<QuotePacket>>, max_time: u64, callback: &mut F)
where
    F: FnMut(String),
{
    while let Some(Reverse(packet)) = heap.peek() {
        if packet.pkt_time + MAX_DELAY_MICROSECONDS <= max_time {
            let packet = heap.pop().unwrap().0;

            callback(format_output_string(
                packet.ts_sec,
                packet.ts_usec,
                &packet.payload,
            ));
        } else {
            break;
        }
    }
}

pub fn format_output_string(ts_sec: u32, ts_usec: u32, payload: &[u8]) -> String {
    let issue = std::str::from_utf8(&payload[5..17]).unwrap_or("");

    let accept = std::str::from_utf8(&payload[206..214]).unwrap_or("");

    let mut out = String::with_capacity(256);

    let _ = write!(out, "{}.{:06} {} {}", ts_sec, ts_usec, accept, issue);

    // Bids: 5th to 1st
    let bid_offsets = [
        (77, 82, 82, 89), // 5th
        (65, 70, 70, 77), // 4th
        (53, 58, 58, 65), // 3rd
        (41, 46, 46, 53), // 2nd
        (29, 34, 34, 41), // 1st
    ];
    for &(ps, pe, qs, qe) in &bid_offsets {
        let qty = std::str::from_utf8(&payload[qs..qe]).unwrap_or("");
        let price = std::str::from_utf8(&payload[ps..pe]).unwrap_or("");
        let _ = write!(out, " {}@{}", qty, price);
    }

    // Asks: 1st to 5th
    let ask_offsets = [
        (96, 101, 101, 108),  // 1st
        (108, 113, 113, 120), // 2nd
        (120, 125, 125, 132), // 3rd
        (132, 137, 137, 144), // 4th
        (144, 149, 149, 156), // 5th
    ];
    for &(ps, pe, qs, qe) in &ask_offsets {
        let qty = std::str::from_utf8(&payload[qs..qe]).unwrap_or("");
        let price = std::str::from_utf8(&payload[ps..pe]).unwrap_or("");
        let _ = write!(out, " {}@{}", qty, price);
    }

    for &(price_start, price_end, qty_start, qty_end) in &ask_offsets {
        let price = std::str::from_utf8(&payload[price_start..price_end]).unwrap_or("");

        let qty = std::str::from_utf8(&payload[qty_start..qty_end]).unwrap_or("");

        let _ = write!(out, " {}@{}", qty, price);
    }

    out
}
