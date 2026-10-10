//! Manual smoke test. Ignored by default because it needs real RustScan and
//! nmap binaries plus a live target; `cargo test` must stay hermetic.

#[test]
#[ignore = "requires live RustScan + nmap and a reachable target"]
fn smoke_port_scan_loopback() {
    use rustscan_automator::model::run::RunConfiguration;
    use rustscan_automator::model::scan_mode::ScanMode;
    use rustscan_automator::model::target::Target;
    use rustscan_automator::recon;
    use rustscan_automator::scanner::runner::ProcessRunner;

    let config = RunConfiguration {
        target: Target::parse("127.0.0.1").unwrap(),
        mode: ScanMode::Port,
        output_dir: std::env::temp_dir().join("rustscan-automator-smoke"),
        dns_server: None,
        rustscan_path: None,
        batch_size: None,
        timeout_ms: None,
        extra_ports: Some("1-1000".to_string()),
        interactive: false,
        no_color: true,
    };

    let summary = recon::execute(&config, &ProcessRunner).expect("smoke run succeeds");
    assert_eq!(summary.mode, "port");
}
