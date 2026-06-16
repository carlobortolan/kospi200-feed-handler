# Kospi200 Feed Handler

![MIT/Apache 2.0 licensed][license-badge]

[license-badge]: https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg

Parses and prints quote messages from a market data feed. When invoked with an `-r` flag, the program re-orders the messages according to the quote accept time at the exchange.

It is designed to consume data either directly from UDP broadcast streams on ports 15515/15516 or by replaying an existing pcap file. Quote packets begin with the ASCII bytes `B6034`, and contain the five current best bids and ask liquidity on the market.

## Output format:

Prints the packet and quote accept times, the issue code, followed by the bids from 5th to 1st, then the asks from 1st to 5th; e.g.:

```xml
<pkt-time> <accept-time> <issue-code> <bqty5>@<bprice5> ... <bqty1>@<bprice1> <aqty1>@<aprice1> ... <aqty5>@<aprice5>
```

## Example usage:

```sh
# 1. Compile the program:
$ cargo build --release
# 2. Parse a pcap file:
$ ./parse-quote mdf-kospi200.20110216-0.pcap
...
1297814429.998584 09002997 KR4301F32505 0000134@00092 0000199@00093 0000231@00094 0000094@00095 0000308@00096 0000234@00097 0000130@00098 0000282@00099 0000415@00100 0000052@00101
...
```

The handler assumes that the difference between the quote accept time and the pcap packet time is never more than 3 seconds.

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
