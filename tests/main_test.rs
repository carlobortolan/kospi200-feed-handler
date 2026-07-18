use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_main_invalid_flag() {
    let mut cmd = Command::cargo_bin("parse-quote").unwrap();

    // Triggers the `_` match arm and `std::process::exit(1)`
    cmd.arg("--some-unknown-flag")
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("Usage:"));
}

#[test]
fn test_main_missing_source() {
    let mut cmd = Command::cargo_bin("parse-quote").unwrap();

    // Triggers `source.expect("Must specify either --pcap or --udp")`
    cmd.arg("-r")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Must specify either --pcap or --udp",
        ));
}

#[test]
fn test_main_missing_pcap_filename() {
    let mut cmd = Command::cargo_bin("parse-quote").unwrap();

    // Triggers `args.next().expect("Missing PCAP filename")`
    cmd.arg("--pcap")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Missing PCAP filename"));
}

#[test]
fn test_main_missing_udp_address() {
    let mut cmd = Command::cargo_bin("parse-quote").unwrap();

    // Triggers `args.next().expect("Missing UDP IP:Port")`
    cmd.arg("--udp")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Missing UDP IP:Port"));
}

#[test]
fn test_main_pcap_unsorted() {
    let mut cmd = Command::cargo_bin("parse-quote").unwrap();

    // Triggers `DataSource::Pcap` match arm and cleanly exits
    cmd.arg("--pcap")
        .arg("data/test-small.pcap")
        .assert()
        .success()
        .stderr(predicate::str::contains("quotes parsed:"));
}

#[test]
fn test_main_pcap_sorted() {
    let mut cmd = Command::cargo_bin("parse-quote").unwrap();

    // Triggers `-r` branch, `DataSource::Pcap`, and the `if reorder` block at the bottom
    cmd.arg("-r")
        .arg("--pcap")
        .arg("data/test-small.pcap")
        .assert()
        .success()
        .stderr(predicate::str::contains("maximum heap size:"));
}

#[test]
fn test_main_udp_bind_failure() {
    let mut cmd = Command::cargo_bin("parse-quote").unwrap();

    // To cover the `DataSource::Udp` arm without hanging the test suite in an infinite loop,
    // intentionally pass an invalid IP. This executes the match arm, but gracefully fails
    // during `UdpSocket::bind` inside `run_udp_source`, returning the Error via `?`.
    cmd.arg("--udp")
        .arg("999.999.999.999:1234")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Listening on UDP feed"));
}
