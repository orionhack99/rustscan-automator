use rustscan_automator::model::finding::{PortState, Protocol};
use rustscan_automator::scanner::service_parser::parse_service_line;

#[test]
fn parses_tcp_service_line_without_reason() {
    let finding = parse_service_line("22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5")
        .expect("parsed");
    assert_eq!(finding.port, Some(22));
    assert_eq!(finding.protocol, Some(Protocol::Tcp));
    assert_eq!(finding.state, Some(PortState::Open));
    assert_eq!(finding.service.as_deref(), Some("ssh"));
    assert_eq!(
        finding.version.as_deref(),
        Some("OpenSSH 8.2p1 Ubuntu 4ubuntu0.5")
    );
}

#[test]
fn strips_reason_prefix_from_version() {
    let finding = parse_service_line(
        "8321/tcp open  http    syn-ack ttl 64 SimpleHTTPServer 0.6 (Python 3.14.7)",
    )
    .expect("parsed");
    assert_eq!(finding.service.as_deref(), Some("http"));
    assert_eq!(
        finding.version.as_deref(),
        Some("SimpleHTTPServer 0.6 (Python 3.14.7)")
    );
}

#[test]
fn parses_udp_open_filtered() {
    let finding = parse_service_line("53/udp open|filtered domain").expect("parsed");
    assert_eq!(finding.port, Some(53));
    assert_eq!(finding.protocol, Some(Protocol::Udp));
    assert_eq!(finding.state, Some(PortState::OpenFiltered));
    assert_eq!(finding.service.as_deref(), Some("domain"));
    assert!(finding.version.is_none());
}

#[test]
fn drops_unknown_version() {
    let finding = parse_service_line("80/tcp open http unknown").expect("parsed");
    assert_eq!(finding.service.as_deref(), Some("http"));
    assert!(finding.version.is_none());
}

#[test]
fn ignores_closed_and_noise() {
    assert!(parse_service_line("22/tcp closed ssh").is_none());
    assert!(parse_service_line("22/tcp filtered ssh").is_none());
    assert!(parse_service_line("Nmap scan report for 10.0.0.5").is_none());
    assert!(parse_service_line("PORT     STATE SERVICE REASON         VERSION").is_none());
    assert!(parse_service_line("").is_none());
}
