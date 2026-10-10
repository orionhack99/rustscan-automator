#[path = "../support/mod.rs"]
mod support;

use rustscan_automator::model::scan_mode::ScanMode;
use rustscan_automator::recon;

#[test]
fn port_mode_records_findings_and_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let config = support::config(ScanMode::Port, dir.path().to_path_buf());
    let runner = support::FakeRunner::new(&["10.0.0.5 -> [22,80]"]);

    let summary = recon::execute(&config, &runner).expect("run succeeds");

    assert_eq!(summary.counts.open_tcp_ports, 2);
    assert_eq!(summary.counts.live_hosts, 1);
    assert_eq!(summary.phases.len(), 1);
    assert!(summary.failures.is_empty());

    for artifact in &summary.artifacts {
        assert!(
            std::path::Path::new(artifact).exists(),
            "missing artifact {artifact}"
        );
    }

    let calls = runner.calls();
    assert_eq!(calls.len(), 1);
    assert!(
        calls[0].iter().any(|arg| arg == "-g"),
        "expects greppable mode"
    );
    assert!(calls[0].iter().any(|arg| arg == "-a"));
}

#[test]
fn port_mode_handles_zero_findings() {
    let dir = tempfile::tempdir().unwrap();
    let config = support::config(ScanMode::Port, dir.path().to_path_buf());
    let runner = support::FakeRunner::new(&[]);

    let summary = recon::execute(&config, &runner).expect("run succeeds");
    assert_eq!(summary.counts.open_tcp_ports, 0);
    assert!(summary.failures.is_empty());
}
