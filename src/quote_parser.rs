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
use std::fs::File;
use std::io::Write as IoWrite;
use std::io::{Error, ErrorKind};

const MAX_DELAY_MICROSECONDS: u64 = 3_000_000; // 3 seconds
const MAX_CAPTURE_SIZE: usize = 16 * 1024 * 1024; // 16 MB
const QUOTE_PACKET_MAGIC: &[u8] = b"B6034"; // Kospi 200 Quote packet identifier 
const QUOTE_PACKET_LENGTH: usize = 215; // 215 bytes total, see quote packet Specification 
const TARGET_PORTS: [u16; 2] = [15515, 15516]; // Specified UDP broadcast ports for the market data feed

/// Statistics returned after parsing.
#[derive(Debug, Default)]
pub struct ParseStats {
    /// Total number of valid KOSPI 200 quote packets successfully parsed.
    pub quotes: usize,
    /// Peak number of packets held concurrently in the sliding window.
    pub max_heap_size: usize,
}

/// Represents a single Quote packet waiting in the sliding window.
///
/// This struct does not copy the payload (zero-copy architecture), but
/// holds a slice reference (`&'a [u8]`) pointing to the memory-mapped
/// PCAP file, bypassing heap allocations.
#[derive(Eq, PartialEq)]
pub struct QuotePacket<'a> {
    /// 8-byte exchange accept time (e.g., "09000123") used later for sorting.
    accept_key: u64,

    /// Network arrival time (μs) used to calculate the sliding window.
    pkt_time: u64,

    /// Cached network timestamp (seconds) used for final string formatting.
    ts_sec: u32,

    /// Cached network timestamp (μs) used for final string formatting.
    ts_usec: u32,

    /// Application data stored inline to keep the heap cache-friendly.
    payload: &'a [u8], // 8 bytes fat pointer for zero-copy payload reference
}

/// Orders packets chronologically by the exchange's `accept_key` (Wall Clock).
/// If two packets have the same accept time, fallback to the `pkt_time` (Network Clock).
impl<'a> Ord for QuotePacket<'a> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.accept_key
            .cmp(&other.accept_key)
            .then_with(|| self.pkt_time.cmp(&other.pkt_time))
    }
}

/// Implements partial ordering by delegating to the total ordering defined in `Ord`.
///
/// Required by Rust's trait system to allow `QuotePacket` to be sorted in `BinaryHeap`.
impl<'a> PartialOrd for QuotePacket<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

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
pub fn parse_pcap_with_stats<F>(
    filename: &str,
    reorder: bool,
    mut callback: F,
) -> Result<ParseStats, Box<dyn std::error::Error>>
where
    F: FnMut(&[u8]),
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

    let mut heap = BinaryHeap::<Reverse<QuotePacket>>::new();
    let mut max_time = 0u64;
    let mut stats = ParseStats::default();
    let mut format_buf: Vec<u8> = Vec::with_capacity(256);

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
        let pkt_time = ts_sec as u64 * 1_000_000 + ts_usec as u64;

        let packet_data = &mmap[cursor..cursor + incl_len];
        cursor += incl_len;

        if let Some(payload) = extract_udp_payload(packet_data, context.link_type) {
            if let Some(quote) = extract_quote(payload) {
                stats.quotes += 1;
                max_time = max_time.max(pkt_time);

                if !reorder {
                    format_output_string(ts_sec, ts_usec, quote, &mut format_buf);
                    callback(&format_buf);
                    continue;
                }

                let accept_key = u64::from_be_bytes(quote[206..214].try_into().unwrap());

                heap.push(Reverse(QuotePacket {
                    accept_key,
                    pkt_time,
                    ts_sec,
                    ts_usec,
                    payload: quote, // Just storing the slice pointer!
                }));

                stats.max_heap_size = stats.max_heap_size.max(heap.len());

                while let Some(Reverse(packet)) = heap.peek() {
                    if packet.pkt_time + MAX_DELAY_MICROSECONDS <= max_time {
                        let packet = heap.pop().unwrap().0;
                        format_output_string(
                            packet.ts_sec,
                            packet.ts_usec,
                            packet.payload,
                            &mut format_buf,
                        );
                        callback(&format_buf);
                    } else {
                        break;
                    }
                }
            }
        }
    }

    if reorder {
        while let Some(Reverse(packet)) = heap.pop() {
            format_output_string(
                packet.ts_sec,
                packet.ts_usec,
                packet.payload,
                &mut format_buf,
            );
            callback(&format_buf);
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
        result.push(String::from_utf8_lossy(line).into_owned())
    })?;

    Ok(result)
}

/// Convenience function for golden-file tests.
pub fn parse_to_string(filename: &str, reorder: bool) -> String {
    parse_pcap(filename, reorder).unwrap().join("\n")
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

/// Validates that a UDP payload is a complete KOSPI 200 Quote Packet.
///
/// Checks against the expected payload length and the `B6034` magic byte header.
pub fn extract_quote(payload: &[u8]) -> Option<&[u8]> {
    if payload.len() < QUOTE_PACKET_LENGTH {
        return None;
    }

    if &payload[..5] != QUOTE_PACKET_MAGIC {
        return None;
    }

    Some(&payload[..QUOTE_PACKET_LENGTH])
}

/// Formats the raw 215-byte quote into a readable text using raw byte operations.
///
/// Takes a mutable reference to a pre-allocated `Vec<u8>` buffer. By repeatedly
/// clearing and writing to this same buffer using `extend_from_slice`, it  eliminates 
/// per-packet heap allocations and expensive UTF-8 validation checks.
pub fn format_output_string(ts_sec: u32, ts_usec: u32, payload: &[u8], out: &mut Vec<u8>) {
    out.clear();

    // 1. Write the Unix epoch timestamps. (Vec<u8> implements std::io::Write)
    let _ = write!(out, "{}.{:06} ", ts_sec, ts_usec);

    // 2. Blit the Accept Time and Issue Code raw bytes
    out.extend_from_slice(&payload[206..214]);
    out.push(b' ');
    out.extend_from_slice(&payload[5..17]);

    // 3. Bids: 5th to 1st
    let bid_offsets = [
        (77, 82, 82, 89), // 5th
        (65, 70, 70, 77), // 4th
        (53, 58, 58, 65), // 3rd
        (41, 46, 46, 53), // 2nd
        (29, 34, 34, 41), // 1st
    ];
    for &(ps, pe, qs, qe) in &bid_offsets {
        out.push(b' ');
        out.extend_from_slice(&payload[qs..qe]); // qty bytes
        out.push(b'@');
        out.extend_from_slice(&payload[ps..pe]); // price bytes
    }

    // 4. Asks: 1st to 5th
    let ask_offsets = [
        (96, 101, 101, 108),  // 1st
        (108, 113, 113, 120), // 2nd
        (120, 125, 125, 132), // 3rd
        (132, 137, 137, 144), // 4th
        (144, 149, 149, 156), // 5th
    ];
    for &(ps, pe, qs, qe) in &ask_offsets {
        out.push(b' ');
        out.extend_from_slice(&payload[qs..qe]); // qty bytes
        out.push(b'@');
        out.extend_from_slice(&payload[ps..pe]); // price bytes
    }
}
