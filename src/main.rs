use std::env;
use std::io::BufWriter;

use kospi200_feed_handler::parse_pcap_with_stats;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    let mut reorder = false;
    let mut filename = None;

    for arg in args.iter().skip(1) {
        if arg == "-r" {
            reorder = true;
        } else if filename.is_none() {
            filename = Some(arg.clone());
        } else {
            eprintln!("usage: {} [-r] <pcap_file>", args[0]);
            std::process::exit(1);
        }
    }

    let filename = filename.ok_or("missing PCAP filename")?;

    // Instead of println!() use buffered writer to lock stdout and batch writes
    let stdout = std::io::stdout();
    let mut output = BufWriter::new(stdout.lock());

    let stats = parse_pcap_with_stats(&filename, reorder, |line| {
        use std::io::Write;
        writeln!(output, "{}", line).expect("failed writing output");
    })?;

    eprintln!("quotes parsed: {}", stats.quotes);

    if reorder {
        eprintln!("maximum heap size: {}", stats.max_heap_size);
    }

    Ok(())
}
