#[path = "../support/mod.rs"]
mod support;

use rustscan_automator::model::run::PhaseStatus;
use rustscan_automator::model::scan_mode::ScanMode;
use rustscan_automator::recon;
use rustscan_automator::scanner::dependency::nmap_available;

#[test]
fn comprehensive_runs_multiple_phases() {
    if !nmap_available() {
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let config = support::config(ScanMode::Full, dir.path().to_path_buf());

    let runner = support::FakeRunner::with_status(0, &[])
        .queue(0, &["10.0.0.5 -> [22,80]"])
        .queue(
            0,
            &["22/tcp open ssh OpenSSH 8.2p1", "80/tcp open http nginx"],
        )
        .queue(0, &["22/tcp open ssh OpenSSH 8.2p1"]);

    let summary = recon::execute(&config, &runner).expect("run succeeds");

    assert!(summary.failures.is_empty());
    assert!(summary
        .phases
        .iter()
        .any(|phase| phase.name == "full-port-sweep"));
    assert!(summary.phases.iter().any(|phase| phase.name == "service"));
    assert!(summary.phases.iter().any(|phase| phase.name == "vuln"));
    assert_eq!(runner.calls().len(), 3);
}

#[test]
fn comprehensive_records_non_fatal_phase_failure() {
    if !nmap_available() {
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let config = support::config(ScanMode::Full, dir.path().to_path_buf());

    // Phase 2 (service) fails; phases 1 and 3 succeed.
    let runner = support::FakeRunner::with_status(0, &[])
        .queue(0, &["10.0.0.5 -> [22]"])
        .queue(1, &[])
        .queue(0, &["22/tcp open ssh OpenSSH 8.2p1"]);

    let summary = recon::execute(&config, &runner).expect("run still succeeds");

    assert!(
        summary
            .failures
            .iter()
            .any(|failure| failure.contains("service")),
        "expected a non-fatal service failure, got {:?}",
        summary.failures
    );
    assert!(
        !summary
            .failures
            .iter()
            .any(|failure| failure.contains("vuln")),
        "vuln phase should have succeeded"
    );
    assert!(summary
        .phases
        .iter()
        .any(|phase| phase.name == "service" && phase.status == PhaseStatus::Failed));
}
