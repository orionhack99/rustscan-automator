#[path = "../support/mod.rs"]
mod support;

use rustscan_automator::model::scan_mode::ScanMode;
use rustscan_automator::recon;

#[test]
fn network_mode_collapses_to_live_hosts() {
    let dir = tempfile::tempdir().unwrap();
    let config = support::config(ScanMode::Network, dir.path().to_path_buf());

    let runner = support::FakeRunner::new(&["10.0.0.5 -> [22,80]", "10.0.0.6 -> [22]"]);

    let summary = recon::execute(&config, &runner).expect("run succeeds");

    assert_eq!(summary.counts.live_hosts, 2);
    // Host-only findings carry no ports.
    assert_eq!(summary.counts.open_tcp_ports, 0);

    let calls = runner.calls();
    assert_eq!(calls.len(), 1);
    assert!(calls[0].iter().any(|arg| arg == "-g"));
    // Discovery uses a bounded port list rather than the full range.
    let position = calls[0].iter().position(|arg| arg == "-p");
    assert!(position.is_some(), "network discovery uses -p");
}
