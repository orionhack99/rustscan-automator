#[path = "../support/mod.rs"]
mod support;

use rustscan_automator::model::scan_mode::ScanMode;
use rustscan_automator::recon;
use rustscan_automator::scanner::dependency::nmap_available;

#[test]
fn service_mode_annotates_services_with_explicit_ports() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = support::config(ScanMode::Service, dir.path().to_path_buf());
    config.extra_ports = Some("22,80".to_string());

    let runner = support::FakeRunner::new(&[
        "22/tcp   open  ssh     OpenSSH 8.2p1",
        "80/tcp   open  http    nginx 1.18.0",
    ]);

    let summary = recon::execute(&config, &runner).expect("run succeeds");

    if nmap_available() {
        assert_eq!(summary.counts.identified_services, 2);
        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        assert!(
            calls[0].iter().any(|arg| arg == "--"),
            "nmap handoff present"
        );
        assert!(calls[0].iter().any(|arg| arg == "-sV"));
    } else {
        assert!(!summary.failures.is_empty() || !summary.phases.is_empty());
    }
}

#[test]
fn service_mode_deduplicates_ports_from_handoff() {
    if !nmap_available() {
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let mut config = support::config(ScanMode::Service, dir.path().to_path_buf());
    config.extra_ports = Some("22".to_string());

    // RustScan prints its discovered ports, then nmap reports the same port
    // with service details; the annotated entry must win exactly once.
    let runner =
        support::FakeRunner::new(&["10.0.0.5 -> [22]", "22/tcp   open  ssh     OpenSSH 8.2p1"]);

    let summary = recon::execute(&config, &runner).expect("run succeeds");
    assert_eq!(summary.counts.open_tcp_ports, 1);
    assert_eq!(summary.counts.identified_services, 1);
}

#[test]
fn service_mode_discovers_ports_when_not_supplied() {
    let dir = tempfile::tempdir().unwrap();
    let config = support::config(ScanMode::Service, dir.path().to_path_buf());

    // First call = port discovery (greppable), subsequent = service lines.
    let runner = support::FakeRunner::with_status(0, &["22/tcp open ssh OpenSSH 8.2p1"])
        .queue(0, &["10.0.0.5 -> [22,80]"]);

    let summary = recon::execute(&config, &runner).expect("run succeeds");

    if nmap_available() {
        let calls = runner.calls();
        assert_eq!(calls.len(), 2, "discovery then service scan");
        assert!(calls[0].iter().any(|arg| arg == "-g"));
        assert!(calls[1].iter().any(|arg| arg == "--"));
        assert!(summary.counts.identified_services >= 1);
    }
}
