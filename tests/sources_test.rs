use kospi200_parser::sources::run_udp_source;
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

#[test]
fn test_udp_source_invalid_bind() {
    // Attempt to bind to a completely invalid IP
    let result = run_udp_source("999.999.999.999:1234", |_, _, _| true);
    assert!(result.is_err(), "Expected an error for invalid IP bind");
}

#[test]
fn test_udp_source_receives_packet_and_exits() {
    let addr = "127.0.0.1:15516";

    // 1. Spawn a background thread to send a fake market data packet
    thread::spawn(move || {
        // Give the listener a fraction of a second to bind to the port
        thread::sleep(Duration::from_millis(50));
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(b"KOSPI_DUMMY_PAYLOAD", addr).unwrap();
    });

    // 2. Run the listener on the main thread.
    // It will block until the packet arrives, evaluate the assert and then exit.
    let result = run_udp_source(addr, |_sec, _usec, payload| {
        assert_eq!(payload, b"KOSPI_DUMMY_PAYLOAD");
        false // Gracefully shut down the loop
    });

    assert!(result.is_ok(), "UDP source should have exited cleanly");
}

#[test]
fn test_udp_multicast_join_branch() {
    let addr = "224.0.0.1:15517";

    thread::spawn(move || {
        thread::sleep(Duration::from_millis(50));
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let _ = sender.send_to(b"MULTI", addr);
    });

    let _ = run_udp_source(addr, |_, _, _| false);
}
