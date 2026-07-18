#[cfg(test)]
mod tests {
    use kospi200_parser::kospi::{HeapItem, KospiHandler, QuoteData};
    use kospi200_parser::sources::run_pcap_source;
    use std::fs;
    use std::time::Instant;

    //////////////////////////////////////
    // Test Helpers for the new API.    //
    //////////////////////////////////////

    /// Replicates the old `parse_pcap` by streaming the source into the handler
    /// and capturing the byte output into a Vec of Strings.
    fn parse_to_output(filename: &str, reorder: bool) -> (Vec<String>, KospiHandler) {
        let mut handler = KospiHandler::new(reorder);
        let mut output_bytes = Vec::new();

        run_pcap_source(filename, |sec, usec, payload| {
            handler.on_packet(sec, usec, payload, &mut output_bytes);
        })
        .expect("PCAP source failed");

        handler.flush_all(&mut output_bytes);

        let lines = String::from_utf8_lossy(&output_bytes)
            .lines()
            .map(|s| s.to_string())
            .collect();

        (lines, handler)
    }

    //////////////////////////////////////
    // Unit tests for the quote parser. //
    //////////////////////////////////////

    #[test]
    fn test_extract_quote_and_format() {
        let mut handler = KospiHandler::new(false);
        let mut output = Vec::new();

        // 1. Fake payload that is too short
        let short_payload = vec![0u8; 100];
        handler.on_packet(1297846801, 123456, &short_payload, &mut output);
        assert_eq!(handler.quotes_parsed, 0, "Should ignore short packets");

        // 2. Valid payload with Magic Bytes
        let mut payload = vec![b'0'; 215]; // Fill with ASCII '0'
        payload[0..5].copy_from_slice(b"B6034"); // Mock Magic Bytes
        payload[5..17].copy_from_slice(b"KR7005930003"); // Mock Issue Code
        payload[206..214].copy_from_slice(b"09000123"); // Mock Accept Time

        handler.on_packet(1297846801, 123456, &payload, &mut output);
        assert_eq!(handler.quotes_parsed, 1, "Should parse valid quote");

        // Convert the bytes back to string for assert
        let out_str = String::from_utf8_lossy(&output);
        // Verify time headers and ISIN
        assert!(out_str.starts_with("1297846801.123456 09000123 KR7005930003"));
        // Since payload is filled with '0', QTY is 7 chars, Price is 5 chars
        assert!(out_str.contains(" 0000000@00000"));
    }

    #[test]
    fn parses_small_capture() {
        let (lines, handler) = parse_to_output("data/test-small.pcap", false);
        assert!(!lines.is_empty(), "expected quotes");
        assert_eq!(lines.len(), handler.quotes_parsed);
        println!("quotes parsed: {}", handler.quotes_parsed);
    }

    #[test]
    fn reorder_preserves_packet_count() {
        let (normal, _) = parse_to_output("data/test-small.pcap", false);
        let (reordered, _) = parse_to_output("data/test-small.pcap", true);

        assert_eq!(normal.len(), reordered.len());
    }

    #[test]
    fn unsorted_output_matches_golden_file() {
        let expected = fs::read_to_string("data/test-small.unsorted").expect("missing golden file");
        let (lines, _) = parse_to_output("data/test-small.pcap", false);
        let actual = lines.join("\n");

        assert_eq!(actual.trim(), expected.trim());
    }

    #[test]
    fn sorted_output_matches_golden_file() {
        let expected = fs::read_to_string("data/test-small.sorted").expect("missing golden file");
        let (lines, _) = parse_to_output("data/test-small.pcap", true);
        let actual = lines.join("\n");

        assert_eq!(actual.trim(), expected.trim());
    }

    #[test]
    fn verify_memory_constraints() {
        // Assert slob struct size
        let heap_item_size = std::mem::size_of::<HeapItem>();
        let arena_item_size = std::mem::size_of::<QuoteData>();

        assert_eq!(
            heap_item_size, 24,
            "HeapItem must be 24 bytes (20 data + 4 padding)"
        );
        assert_eq!(arena_item_size, 224, "QuoteData must be 224 bytes");

        // Calculate max heap tracking weight for 3 million in-flight packets
        let max_packets = 3_000_000;
        let heap_weight_mb = (max_packets * heap_item_size) / 1_024 / 1_024;

        println!("Heap tree size at 3M packets: {} MB", heap_weight_mb);
        assert!(
            heap_weight_mb < 100,
            "Heap tree metadata must remain highly cacheable"
        );
    }

    ////////////////////////////////////////////////////////////////////////////////////////
    // Stress tests: run with `cargo test -- --ignored` to avoid running them by default. //
    // Create 10 GB data/test-large10g.pcap manually first:                               //
    // $ cargo run --release --bin generate_10g                                           //
    ////////////////////////////////////////////////////////////////////////////////////////

    #[test]
    #[ignore]
    fn big_file_completes_without_unbounded_output_memory() {
        let start = Instant::now();
        let mut handler = KospiHandler::new(true);
        let mut dummy_out = std::io::sink(); // Ignore string output for speed

        run_pcap_source("data/test-large10g.pcap", |sec, usec, payload| {
            handler.on_packet(sec, usec, payload, &mut dummy_out);
        })
        .expect("large file failed");

        println!(
            "processed {} quotes in {:?}",
            handler.quotes_parsed,
            start.elapsed()
        );
        println!("maximum heap size: {}", handler.max_heap_size);
        assert!(handler.quotes_parsed > 1_000_000, "unexpected quote count");
    }

    #[test]
    #[ignore]
    fn reorder_buffer_size_is_reasonable() {
        let mut handler = KospiHandler::new(true);
        let mut dummy_out = std::io::sink();

        run_pcap_source("data/test-large10g.pcap", |sec, usec, payload| {
            handler.on_packet(sec, usec, payload, &mut dummy_out);
        })
        .unwrap();

        println!("max heap size: {}", handler.max_heap_size);
        assert!(
            handler.max_heap_size < handler.quotes_parsed / 2,
            "reorder buffer grew unexpectedly"
        );
    }
}
