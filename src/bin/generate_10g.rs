use std::fs::File;
use std::io::{BufWriter, Read, Write};

// KOSPI payload Accept Time at index 206 and packet has standard Ethernet(14) + IP(20) + UDP(8) headers -> the PCAP offset is 248.
const ACCEPT_TIME_PCAP_OFFSET: usize = 248;

// 1800 loops * 5.6 MB = ~10.08 GB
const LOOP_COUNT: u32 = 1800;

fn main() {
    println!("Reading original PCAP...");
    let mut input_file =
        File::open("data/mdf-kospi200.20110216-0.pcap").expect("Failed to open source PCAP");
    let mut input_data = Vec::new();
    input_file.read_to_end(&mut input_data).unwrap();

    let global_header = &input_data[0..24];

    // Extract packets
    let mut packets = Vec::new();
    let mut cursor = 24;
    while cursor < input_data.len() {
        let ts_sec = u32::from_le_bytes(input_data[cursor..cursor + 4].try_into().unwrap());
        let ts_usec = u32::from_le_bytes(input_data[cursor + 4..cursor + 8].try_into().unwrap());
        let incl_len =
            u32::from_le_bytes(input_data[cursor + 8..cursor + 12].try_into().unwrap()) as usize;
        let orig_len = u32::from_le_bytes(input_data[cursor + 12..cursor + 16].try_into().unwrap());

        let payload = &input_data[cursor + 16..cursor + 16 + incl_len];
        packets.push((ts_sec, ts_usec, incl_len as u32, orig_len, payload.to_vec()));

        cursor += 16 + incl_len;
    }

    let first_ts = packets.first().unwrap().0;
    let last_ts = packets.last().unwrap().0;
    // Calculate exact duration of the original file, plus 1 second to prevent overlap
    let loop_delta_secs = last_ts - first_ts + 1;

    println!("Original file parsed. Contains {} packets.", packets.len());
    println!(
        "Loop delta: {} seconds. Generating 10GB file...",
        loop_delta_secs
    );

    let output_file = File::create("data/test-large10g.pcap").expect("Failed to create output PCAP");
    let mut writer = BufWriter::with_capacity(1024 * 1024 * 16, output_file); // 16MB write buffer

    writer.write_all(global_header).unwrap();

    for n in 0..LOOP_COUNT {
        let shift_secs = n * loop_delta_secs;

        for pkt in &packets {
            // 1. Shift the PCAP Network Time
            let new_ts_sec = pkt.0 + shift_secs;

            writer.write_all(&new_ts_sec.to_le_bytes()).unwrap();
            writer.write_all(&pkt.1.to_le_bytes()).unwrap();
            writer.write_all(&pkt.2.to_le_bytes()).unwrap();
            writer.write_all(&pkt.3.to_le_bytes()).unwrap();

            // 2. Shift the KOSPI Exchange Accept Time
            let mut new_payload = pkt.4.clone();

            if new_payload.len() >= ACCEPT_TIME_PCAP_OFFSET + 8 {
                shift_accept_time(
                    &mut new_payload[ACCEPT_TIME_PCAP_OFFSET..ACCEPT_TIME_PCAP_OFFSET + 8],
                    shift_secs,
                );
            }

            writer.write_all(&new_payload).unwrap();
        }

        if n % 100 == 0 {
            println!("Completed loop {} / {}", n, LOOP_COUNT);
        }
    }

    writer.flush().unwrap();
    println!("10GB PCAP generation complete.");
}

/// Parses an 8-byte ASCII time array (HHMMSScc), adds the shifted seconds and overwrites the array.
fn shift_accept_time(bytes: &mut [u8], shift_secs: u32) {
    let h = (bytes[0] - b'0') as u32 * 10 + (bytes[1] - b'0') as u32;
    let m = (bytes[2] - b'0') as u32 * 10 + (bytes[3] - b'0') as u32;
    let s = (bytes[4] - b'0') as u32 * 10 + (bytes[5] - b'0') as u32;

    let total_secs = h * 3600 + m * 60 + s + shift_secs;

    let new_h = (total_secs / 3600) % 24;
    let new_m = (total_secs / 60) % 60;
    let new_s = total_secs % 60;

    bytes[0] = b'0' + (new_h / 10) as u8;
    bytes[1] = b'0' + (new_h % 10) as u8;
    bytes[2] = b'0' + (new_m / 10) as u8;
    bytes[3] = b'0' + (new_m % 10) as u8;
    bytes[4] = b'0' + (new_s / 10) as u8;
    bytes[5] = b'0' + (new_s % 10) as u8;
}
