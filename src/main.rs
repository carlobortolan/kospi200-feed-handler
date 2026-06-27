use std::env;
use std::io::{BufWriter, stdout};

use kospi200_parser::kospi::KospiHandler;
use kospi200_parser::sources::{run_pcap_source, run_udp_source};

enum DataSource {
    Pcap(String),
    Udp(String),
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let mut reorder = false;
    let mut source = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-r" => reorder = true,
            "--pcap" => {
                source = Some(DataSource::Pcap(
                    args.next().expect("Missing PCAP filename"),
                ))
            }
            "--udp" => source = Some(DataSource::Udp(args.next().expect("Missing UDP IP:Port"))),
            _ => {
                eprintln!(
                    "Usage: {} [-r] [--pcap <file.pcap> | --udp <ip:port>]",
                    env::args().next().unwrap()
                );
                std::process::exit(1);
            }
        }
    }

    let source = source.expect("Must specify either --pcap or --udp");

    let stdout = stdout();
    let mut output = BufWriter::new(stdout.lock());

    // Instantiate stateful KOSPI parser
    let mut kospi_handler = KospiHandler::new(reorder);

    match source {
        DataSource::Pcap(filename) => {
            eprintln!("Replaying PCAP file: {}", filename);
            run_pcap_source(&filename, |sec, usec, payload| {
                kospi_handler.on_packet(sec, usec, payload, &mut output);
            })?;
        }
        DataSource::Udp(addr) => {
            eprintln!("Listening on UDP feed: {}", addr);
            run_udp_source(&addr, |sec, usec, payload| {
                kospi_handler.on_packet(sec, usec, payload, &mut output);
            })?;
        }
    }

    // Flush any remaining items in the reorder heap
    kospi_handler.flush_all(&mut output);

    eprintln!("quotes parsed: {}", kospi_handler.quotes_parsed);
    if reorder {
        eprintln!("maximum heap size: {}", kospi_handler.max_heap_size);
    }

    Ok(())
}
