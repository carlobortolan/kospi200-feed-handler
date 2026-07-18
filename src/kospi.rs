/*
 * Time Complexity:
 * O(N * log K) where N is the number of packets and K is the maximum number
 * of packets buffered in the reorder window.
 *
 * Space Complexity:
 * O(K) where K is the maximum reorder buffer size (Slab capacity).
 */

use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;
use std::io::Write;

const MAX_DELAY_MICROSECONDS: u64 = 3_000_000; // 3 seconds
const QUOTE_PACKET_MAGIC: &[u8] = b"B6034"; // Kospi 200 Quote packet identifier
const QUOTE_PACKET_LENGTH: usize = 215; // 215 bytes total, see quote packet Specification

/// Represents the sorting key for a single Quote packet waiting in the sliding window.
///
/// Storing only the sorting keys and an index (24 bytes with padding), avoids copying
/// 215-byte payloads every time the heap sifts elements.
#[derive(Eq, PartialEq)]
pub struct HeapItem {
    /// 8-byte exchange accept time (e.g., "09000123") used later for sorting.
    accept_key: u64,

    /// 8-byte network arrival time (μs) used to calculate the sliding window.
    pkt_time: u64,

    /// 4-byte index mapping to the pre-allocated arena/slab.
    arena_idx: u32,
}

/// Orders packets chronologically by the exchange's `accept_key` (Wall Clock).
/// If two packets have the same accept time, fallback to the `pkt_time` (Network Clock).
impl Ord for HeapItem {
    fn cmp(&self, other: &Self) -> Ordering {
        self.accept_key
            .cmp(&other.accept_key)
            .then_with(|| self.pkt_time.cmp(&other.pkt_time))
    }
}

/// Implements partial ordering by delegating to the total ordering defined in `Ord`.
///
/// Required by Rust's trait system to allow `HeapItem` to be sorted in `BinaryHeap`.
impl PartialOrd for HeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The actual quote payload whcih gets stored sequentially in the Arena.
///
/// Stored inline as a fixed-size array to keep memory cache-friendly and
/// to prevent fragmented heap allocations. Total size: 224 bytes.
pub struct QuoteData {
    /// 4-byte cached network timestamp (seconds) used for final string formatting.
    ts_sec: u32,

    /// 4-byte cached network timestamp (μs) used for final string formatting.
    ts_usec: u32,

    /// 215-byte application data.
    payload: [u8; QUOTE_PACKET_LENGTH],
}

/// Stateful parser and reorder buffer for the KOSPI 200 market data feed.
///
/// Slab and Min-Heap guarantee zero-allocation regardless of whether data
/// arrives via PCAP or a live UDP socket.
pub struct KospiHandler {
    /// Flag to re-order messages according to the quote accept time at the exchange.
    reorder: bool,

    /// Holds 24-byte sorting keys that contain arena index / slab pointer.
    heap: BinaryHeap<Reverse<HeapItem>>,

    /// Slab allocator for 224-byte payloads.
    arena: Vec<QuoteData>,

    /// Tracks recycled indices in the arena; O(1) slot reuse since processed
    /// QuoteData items are not deleted from arena, but overwritten by new items.  
    free_list: Vec<u32>,

    /// The highest network timestamp seen so far (µs).
    max_time: u64,

    /// Total number of valid KOSPI 200 quote packets successfully parsed.
    pub quotes_parsed: usize,

    /// Peak number of packets held concurrently in the sliding window.
    pub max_heap_size: usize,

    /// Buffer to batch I/O string formatting, preventing repeated syscalls
    /// to the underlying `StdoutLock`.
    format_buf: Vec<u8>,
}

impl KospiHandler {
    pub fn new(reorder: bool) -> Self {
        Self {
            reorder,
            // TODO: Find out if 1_000_000 is realistic/enough
            heap: BinaryHeap::with_capacity(1_000_000), // Pre-allocate to prevent mid-stream latency spikes
            arena: Vec::with_capacity(1_000_000),
            free_list: Vec::with_capacity(1_000_000),
            max_time: 0,
            quotes_parsed: 0,
            max_heap_size: 0,
            format_buf: Vec::with_capacity(256), // Final output string of a single KOSPI quote ~180 chars
        }
    }

    /// Feeds UDP payload into the heap using 3-second sliding window.
    ///
    /// Validates the magic bytes, manages the slab allocator memory mapping,
    /// and flushes expired packets that fall outside the 3-second sliding window.
    pub fn on_packet(
        &mut self,
        ts_sec: u32,
        ts_usec: u32,
        payload: &[u8],
        output: &mut impl Write,
    ) {
        if payload.len() < QUOTE_PACKET_LENGTH || &payload[..5] != QUOTE_PACKET_MAGIC {
            return; // Not a valid KOSPI Quote
        }

        self.quotes_parsed += 1;
        let pkt_time = ts_sec as u64 * 1_000_000 + ts_usec as u64;
        self.max_time = self.max_time.max(pkt_time);

        if !self.reorder {
            Self::format_and_write(
                &mut self.format_buf,
                ts_sec,
                ts_usec,
                &payload[..QUOTE_PACKET_LENGTH],
                output,
            );
            return;
        }

        // Quote accept time as key for heap
        let accept_key = u64::from_be_bytes(payload[206..214].try_into().unwrap());

        // --- SLAB ALLOCATOR: Request memory slot ---
        // Pop unused index to overwrite slot used by already processed packet.
        let arena_idx = if let Some(idx) = self.free_list.pop() {
            // Reuse an empty slot (Zero allocations)
            let data = &mut self.arena[idx as usize];
            data.ts_sec = ts_sec;
            data.ts_usec = ts_usec;
            data.payload
                .copy_from_slice(&payload[..QUOTE_PACKET_LENGTH]);
            idx
        } else {
            // Expand the arena if no slots are free
            let idx = self.arena.len() as u32;
            let mut payload_arr = [0u8; QUOTE_PACKET_LENGTH];
            payload_arr.copy_from_slice(&payload[..QUOTE_PACKET_LENGTH]);
            self.arena.push(QuoteData {
                ts_sec,
                ts_usec,
                payload: payload_arr,
            });
            idx
        };

        // Push 24 byte long key (20 bytes data + 4 bytes padding) to the heap
        // (see: https://doc.rust-lang.org/reference/type-layout.html)
        self.heap.push(Reverse(HeapItem {
            accept_key, // 8 bytes
            pkt_time,   // 8 bytes
            arena_idx,  // 4 bytes
        }));

        self.max_heap_size = self.max_heap_size.max(self.heap.len());

        // --- FLUSH EXPIRED PACKETS ---
        while let Some(Reverse(item)) = self.heap.peek() {
            // UDP does not guarantee delivery order. If packet in the heap is
            // more than 3 seconds older than max_time, it is safe to flush
            if item.pkt_time + MAX_DELAY_MICROSECONDS <= self.max_time {
                let item = self.heap.pop().unwrap().0;

                // Read from the arena using the integer ID
                let data = &self.arena[item.arena_idx as usize];
                Self::format_and_write(
                    &mut self.format_buf,
                    data.ts_sec,
                    data.ts_usec,
                    &data.payload,
                    output,
                );

                // After packet is printed, it is no longer needed in the arena.
                // Return the slot to the free list so it can be overwritten.
                self.free_list.push(item.arena_idx);
            } else {
                break;
            }
        }
    }

    /// Flushes any remaining packets in the heap when the stream ends.
    pub fn flush_all(&mut self, output: &mut impl Write) {
        while let Some(Reverse(item)) = self.heap.pop() {
            let data = &self.arena[item.arena_idx as usize];
            Self::format_and_write(
                &mut self.format_buf,
                data.ts_sec,
                data.ts_usec,
                &data.payload,
                output,
            );
            // No need to push to free_list here, since we are shutting down.
        }
    }

    /// Formats the raw 215-byte quote into a readable text using raw byte operations.
    ///
    /// Takes a mutable reference to a pre-allocated `Vec<u8>` buffer. By repeatedly
    /// clearing and writing to this same buffer using `extend_from_slice`, it eliminates
    /// per-packet heap allocations and expensive UTF-8 validation checks.
    fn format_and_write(
        format_buf: &mut Vec<u8>,
        ts_sec: u32,
        ts_usec: u32,
        payload: &[u8],
        out: &mut impl Write,
    ) {
        format_buf.clear();

        // 1. Write the Unix epoch timestamps using itoa
        let mut num_buf = itoa::Buffer::new();

        // Write seconds
        format_buf.extend_from_slice(num_buf.format(ts_sec).as_bytes());
        format_buf.push(b'.');

        // Write microseconds with branchless zero-padding
        let usec_bytes = num_buf.format(ts_usec).as_bytes();
        let pad_len = 6usize.saturating_sub(usec_bytes.len());

        format_buf.extend_from_slice(&b"000000"[..pad_len]); // Pad
        format_buf.extend_from_slice(usec_bytes); // Digits
        format_buf.push(b' '); // Space delimiter

        // 2. Blit the Accept Time and Issue Code raw bytes
        format_buf.extend_from_slice(&payload[206..214]);
        format_buf.push(b' ');
        format_buf.extend_from_slice(&payload[5..17]);

        // 3. Bids: 5th to 1st
        let bid_offsets = [
            (77, 82, 82, 89), // 5th
            (65, 70, 70, 77), // 4th
            (53, 58, 58, 65), // 3rd
            (41, 46, 46, 53), // 2nd
            (29, 34, 34, 41), // 1st
        ];

        for &(ps, pe, qs, qe) in &bid_offsets {
            format_buf.push(b' ');
            format_buf.extend_from_slice(&payload[qs..qe]); // qty bytes
            format_buf.push(b'@');
            format_buf.extend_from_slice(&payload[ps..pe]); // price bytes
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
            format_buf.push(b' ');
            format_buf.extend_from_slice(&payload[qs..qe]); // qty bytes
            format_buf.push(b'@');
            format_buf.extend_from_slice(&payload[ps..pe]); // price bytes
        }

        format_buf.push(b'\n');
        out.write_all(format_buf).unwrap();
    }
}
