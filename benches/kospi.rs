use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use kospi200_parser::{KospiHandler, run_pcap_source};

fn kospi_benchmark(c: &mut Criterion) {
    // Macro (File IO + Parsing + Heap operations)
    c.bench_function("run_pcap_source", |b| {
        let filename = "data/mdf-kospi200.20110216-0.pcap";
        b.iter(|| {
            let mut kospi_handler = KospiHandler::new(true);

            let _ = run_pcap_source(black_box(filename), |sec, usec, payload| {
                kospi_handler.on_packet(sec, usec, payload, |_quote| {});
            });
            kospi_handler.flush_all(|_quote| {});
        })
    });

    // Micro (Parsing + Heap operations)
    c.bench_function("on_packet", |b| {
        let mut kospi_handler = KospiHandler::new(true);

        let mut payload = [0u8; 215];
        payload[0..5].copy_from_slice(b"B6034");
        payload[206..214].copy_from_slice(b"09002892");

        let mut ts_sec: u32 = 1297814428;
        let mut ts_usec: u32 = 958808;

        b.iter(|| {
            // Advance 1ms
            ts_usec += 1000;
            if ts_usec >= 1_000_000 {
                ts_sec += 1;
                ts_usec -= 1_000_000;
            }

            kospi_handler.on_packet(
                black_box(ts_sec),
                black_box(ts_usec),
                black_box(&payload),
                |_quote| {},
            );
        });
    });
}

criterion_group!(benches, kospi_benchmark);
criterion_main!(benches);
