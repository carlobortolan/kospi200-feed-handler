# Kospi200 Feed Handler

<!-- ![tests][actions-test-badge] -->

[![MIT/Apache 2.0 licensed][license-badge]]()

<!--
[![Crate][crates-badge]][crates-url]
[![docs.rs][docsrs-badge]][docs-url]
[![codecov-kospi200-feed-handler][codecov-badge]][codecov-url]
![Crates.io MSRV][crates-msrv-badge]
![Crates.io downloads][crates-download-badge]

[actions-test-badge]: https://github.com/carlobortolan/kospi200-feed-handler/actions/workflows/ci.yml/badge.svg
[crates-badge]: https://img.shields.io/crates/v/kospi200-feed-handler.svg
[crates-url]: https://crates.io/crates/kospi200-feed-handler
[license-badge]: https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg
[docsrs-badge]: https://img.shields.io/docsrs/kospi200-feed-handler
[docs-url]: https://docs.rs/kospi200-feed-handler/*/kospi200-feed-handler
[codecov-badge]: https://codecov.io/gh/carlobortolan/kospi200-feed-handler/graph/badge.svg?token=NJ4HW3OQFY
[codecov-url]: https://codecov.io/gh/carlobortolan/kospi200-feed-handler
[crates-msrv-badge]: https://img.shields.io/crates/msrv/kospi200-feed-handler
[crates-download-badge]: https://img.shields.io/crates/d/kospi200-feed-handler
-->

[license-badge]: https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg

Parses and prints quote messages from a market data feed. When invoked with an `-r` flag, the program re-orders the messages according to the quote accept time at the exchange.

It is designed to consume data either directly from UDP broadcast streams on ports 15515/15516 or by replaying an existing pcap file. Quote packets begin with the ASCII bytes `B6034`, and contain the five current best bids and ask liquidity on the market.

The parser currently uses zero-copy memory mapping (`memmap2`), pushing 8-byte slice pointers to a sliding-window Min-Heap and then formatting outbound strings dynamically via `itoa`.

## Performance

**Benchmark (11 GB PCAP file | 42.5M Packets | 32M Quotes)**

- User time (seconds): **22.24 seconds**
- System time (seconds): **1.15 seconds**
- Elapsed (wall clock) time: **23.61 seconds**
- Throughput: **~465 MB/s** (Single-threaded)
- Max application heap: **<150 KB** (for historical data) **to ~20 MB** (for 5.5M+ packet stress-test bursts); Heap size is bounded dynanically by 3-second reorder window to remain stable at $O(K)$ complexity regardless of total file size.

_Measured on a selfhosted VM with 32 GB RAM, AMD Ryzen 7 PRO 6850U @ 2.70GHz, and Manjaro Linux x86_64_

## Output format:

Prints the packet and quote accept times, the issue code, followed by the bids from 5th to 1st, then the asks from 1st to 5th; e.g.:

```xml
<pkt-time> <accept-time> <issue-code> <bqty5>@<bprice5> ... <bqty1>@<bprice1> <aqty1>@<aprice1> ... <aqty5>@<aprice5>
```

## Example usage:

```sh
# 1. Compile the program:
$ cargo build --release

# 2. Run tests:
$ cargo test

# 3. Parse a pcap file:
$ target/release/parse-quote -r data/mdf-kospi200.20110216-0.pcap
...
1297814429.998584 09002997 KR4301F32505 0000134@00092 0000199@00093 0000231@00094 0000094@00095 0000308@00096 0000234@00097 0000130@00098 0000282@00099 0000415@00100 0000052@00101
...
```

The handler assumes that the difference between the quote accept time and the pcap packet time is never more than 3 seconds.

## Minimum supported Rust version (MSRV)

This crate requires a Rust version of 1.85.0 or higher. Increases in MSRV will be considered a semver non-breaking API change and require a version increase (PATCH until 1.0.0, MINOR after 1.0.0).

## License

This project is licensed under either of:

- [MIT license](LICENSE-MIT.md) or
- [Apache License, Version 2.0](LICENSE-APACHE.md)

at your option.

This project is inspired by [this video: Saturating the NIC: A Network Optimization Adventure](https://www.youtube.com/watch?v=Y2Cn7o8QZvA) and [this page](https://www.tsurucapital.com/en/code-sample.html/).

---

© Carlo Bortolan

> Carlo Bortolan &nbsp;&middot;&nbsp;
> GitHub [carlobortolan](https://github.com/carlobortolan) &nbsp;&middot;&nbsp;
> contact via [carlobortolan@gmail.com](mailto:carlobortolan@gmail.com)
