//! Guards the reconnaissance-only scope: no exploitation, brute-force, or
//! third-party enumeration tooling may ever be passed to the engine.

use rustscan_automator::model::scan_mode::ScanMode;
use rustscan_automator::scanner::command::{build_rustscan_args, validate_nmap_args, ScanArgs};

const FORBIDDEN: &[&str] = &[
    "nikto",
    "dirb",
    "gobuster",
    "ffuf",
    "wpscan",
    "metasploit",
    "msf",
    "brute",
    "exploit",
    "enum4linux",
    "smbmap",
    "dnsrecon",
];

fn args_for(mode: ScanMode) -> Vec<String> {
    build_rustscan_args(&ScanArgs {
        mode,
        target: "10.0.0.5",
        ports: Some("22,80".to_string()),
        dns: None,
        batch_size: None,
        timeout_ms: None,
    })
    .expect("valid args")
}

#[test]
fn built_commands_never_reference_third_party_tools() {
    for mode in [
        ScanMode::Network,
        ScanMode::Port,
        ScanMode::Service,
        ScanMode::Vuln,
        ScanMode::Udp,
        ScanMode::Full,
        ScanMode::Guidance,
    ] {
        let joined = args_for(mode).join(" ").to_ascii_lowercase();
        for tool in FORBIDDEN {
            assert!(
                !joined.contains(tool),
                "mode {mode:?} referenced forbidden token '{tool}': {joined}"
            );
        }
    }
}

#[test]
fn rejects_forbidden_script_category() {
    assert!(validate_nmap_args(&["--script".to_string(), "brute".to_string()]).is_err());
    assert!(validate_nmap_args(&["--script".to_string(), "exploit".to_string()]).is_err());
}

#[test]
fn accepts_recon_only_nmap_args() {
    assert!(validate_nmap_args(&["-sV".to_string(), "-sC".to_string(), "-Pn".to_string()]).is_ok());
    assert!(validate_nmap_args(&["--script".to_string(), "vuln".to_string()]).is_ok());
    assert!(validate_nmap_args(&["--script".to_string(), "default".to_string()]).is_ok());
}
