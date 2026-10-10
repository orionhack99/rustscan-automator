use rustscan_automator::model::scan_mode::ScanMode;
use rustscan_automator::scanner::dependency::{ensure_privileges, recon_skip_reason};

#[test]
fn non_privileged_modes_are_allowed() {
    for mode in [
        ScanMode::Port,
        ScanMode::Network,
        ScanMode::Service,
        ScanMode::Vuln,
        ScanMode::Full,
        ScanMode::Guidance,
    ] {
        assert!(
            ensure_privileges(mode).is_ok(),
            "{mode:?} should not require privileges"
        );
    }
}

#[test]
fn skip_reason_reflects_nmap_presence() {
    assert!(recon_skip_reason(true).is_none());
    assert!(recon_skip_reason(false).is_some());
}

#[test]
fn mode_properties() {
    assert!(ScanMode::Udp.requires_privileges());
    assert!(!ScanMode::Port.requires_privileges());
    assert!(ScanMode::Service.requires_nmap());
    assert!(ScanMode::Vuln.requires_nmap());
    assert!(ScanMode::Full.requires_nmap());
    assert!(!ScanMode::Port.requires_nmap());
}

#[test]
fn parses_mode_aliases() {
    assert_eq!(ScanMode::parse("script").unwrap(), ScanMode::Service);
    assert_eq!(ScanMode::parse("VULNS").unwrap(), ScanMode::Vuln);
    assert_eq!(ScanMode::parse("all").unwrap(), ScanMode::Full);
    assert_eq!(ScanMode::parse("recon").unwrap(), ScanMode::Guidance);
    assert!(ScanMode::parse("bogus").is_err());
}
