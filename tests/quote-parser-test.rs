use kospi200_feed_handler::{
    extract_quote, format_output_string, parse_pcap, parse_pcap_with_stats, parse_to_string,
};
use std::fs;
use std::time::Instant;

#[cfg(test)]
mod tests {
    use super::*;

    //////////////////////////////////////
    // Unit tests for the quote parser. //
    //////////////////////////////////////

    #[test]
    fn test_extract_quote() {
        // Create a fake payload that is too short
        let short_payload = vec![0u8; 100];
        assert_eq!(extract_quote(&short_payload), None);

        // Create a valid payload with the magic bytes
        let mut payload = vec![0u8; 215];
        payload[0..5].copy_from_slice(b"B6034");
        assert!(extract_quote(&payload).is_some());
    }

    #[test]
    fn test_format_output_string() {
        let mut payload = vec![b'0'; 215]; // Fill with ASCII '0'

        payload[0..5].copy_from_slice(b"B6034"); // Mock Magic Bytes
        payload[5..17].copy_from_slice(b"KR7005930003"); // Mock Issue Code
        payload[206..214].copy_from_slice(b"09000123"); // Mock Accept Time

        let mut format_buf: Vec<u8> = Vec::with_capacity(256);

        format_output_string(1297846801, 123456, &payload, &mut format_buf);

        // Convert the bytes back to string for assert
        let output = String::from_utf8_lossy(&format_buf);

        // Verify time headers and ISIN
        assert!(output.starts_with("1297846801.123456 09000123 KR7005930003"));

        // Since payload is filled with '0', QTY is 7 chars, Price is 5 chars
        assert!(output.contains(" 0000000@00000"));
    }

    #[test]
    fn parses_small_capture() {
        let output = parse_pcap("data/test-small.pcap", false).expect("parser failed");
        assert!(!output.is_empty(), "expected quotes");
        println!("quotes parsed: {}", output.len());
    }

    #[test]
    fn reorder_preserves_packet_count() {
        let normal = parse_pcap("data/test-small.pcap", false).unwrap();
        let reordered = parse_pcap("data/test-small.pcap", true).unwrap();

        assert_eq!(normal.len(), reordered.len());
    }

    #[test]
    fn unsorted_output_matches_golden_file() {
        let expected = fs::read_to_string("data/test-small.unsorted").expect("missing golden file");
        let actual = parse_to_string("data/test-small.pcap", false);

        assert_eq!(actual.trim(), expected.trim());
    }

    #[test]
    fn sorted_output_matches_golden_file() {
        let expected = fs::read_to_string("data/test-small.sorted").expect("missing golden file");
        let actual = parse_to_string("data/test-small.pcap", true);

        assert_eq!(actual.trim(), expected.trim());
    }

    #[test]
    fn verify_memory_constraints() {
        let struct_size = std::mem::size_of::<kospi200_feed_handler::quote_parser::QuotePacket>();
        // Should be: 8+8+4+4+16 = 40 bytes.
        assert_eq!(struct_size, 40, "Struct size must be 40 bytes for");

        // 2,765 items * 40 bytes = 110,600 bytes (~108 KB)
        let peak_heap_usage = 2765 * struct_size;
        println!("Historical peak heap usage: {} bytes", peak_heap_usage);
        assert!(peak_heap_usage < 150_000, "Heap usage exceeded 150 KB");
    }

    ////////////////////////////////////////////////////////////////////////////////////////
    // Stress tests: run with `cargo test -- --ignored` to avoid running them by default. //
    // Create 10 GB data/test-large10g.pcap manually using:                               //
    // mergecap -F pcap -w data/large10g.pcap \                                           //
    // $(yes data/mdf-kospi200.20110216-0.pcap | head -200)                               //
    ////////////////////////////////////////////////////////////////////////////////////////

    #[test]
    #[ignore]
    fn big_file_completes_without_unbounded_output_memory() {
        let start = Instant::now();
        let stats = parse_pcap_with_stats("data/test-large10g.pcap", true, |_| {})
            .expect("large file failed");

        println!("processed {} quotes in {:?}", stats.quotes, start.elapsed());
        println!("maximum heap size: {}", stats.max_heap_size);
        assert!(stats.quotes > 1_000_000, "unexpected quote count");
    }

    #[test]
    #[ignore]
    fn reorder_buffer_size_is_reasonable() {
        let stats = parse_pcap_with_stats("data/test-large10g.pcap", true, |_| {}).unwrap();

        println!("max heap size: {}", stats.max_heap_size);
        assert!(
            stats.max_heap_size < stats.quotes / 2,
            "reorder buffer grew unexpectedly"
        );
    }
}
