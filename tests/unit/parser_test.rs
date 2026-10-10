use rustscan_automator::model::finding::{PortState, Protocol};
use rustscan_automator::scanner::parser::{looks_like_finding, parse_greppable_lines};

#[test]
fn parses_rustscan_arrow_format_with_multiple_ports() {
    let findings = parse_greppable_lines("10.0.0.5 -> [22,80,443]");
    assert_eq!(findings.len(), 3);
    assert_eq!(findings[0].host, "10.0.0.5");
    assert_eq!(findings[0].port, Some(22));
    assert_eq!(findings[1].port, Some(80));
    assert_eq!(findings[2].port, Some(443));
    assert_eq!(findings[0].protocol, Some(Protocol::Tcp));
    assert_eq!(findings[0].state, Some(PortState::Open));
}

#[test]
fn parses_arrow_format_with_single_port_and_spacing() {
    let findings = parse_greppable_lines("  127.0.0.1 -> [8231]  ");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].host, "127.0.0.1");
    assert_eq!(findings[0].port, Some(8231));
}

#[test]
fn parses_legacy_prefixed_and_bare_lines() {
    let prefixed = parse_greppable_lines("Open 10.0.0.5:22");
    assert_eq!(prefixed.len(), 1);
    assert_eq!(prefixed[0].port, Some(22));

    let bare = parse_greppable_lines("192.168.1.1:8080");
    assert_eq!(bare.len(), 1);
    assert_eq!(bare[0].host, "192.168.1.1");
    assert_eq!(bare[0].port, Some(8080));
}

#[test]
fn ignores_non_findings() {
    assert!(parse_greppable_lines("").is_empty());
    assert!(parse_greppable_lines("Openning...").is_empty());
    assert!(parse_greppable_lines("Open badline").is_empty());
    assert!(parse_greppable_lines("Open host:0").is_empty());
    assert!(parse_greppable_lines("host -> []").is_empty());
    assert!(parse_greppable_lines("host -> [0]").is_empty());
}

#[test]
fn detects_greppable_lines() {
    assert!(looks_like_finding("10.0.0.5 -> [22]"));
    assert!(looks_like_finding("Open 10.0.0.5:22"));
    assert!(!looks_like_finding("random output"));
    assert!(!looks_like_finding(""));
}

fn fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(path).expect("fixture readable")
}

#[test]
fn parses_fixture_files() {
    let open = fixture("greppable_open.txt");
    let findings: Vec<_> = open.lines().flat_map(parse_greppable_lines).collect();
    assert_eq!(findings.len(), 4);

    let cidr = fixture("greppable_cidr.txt");
    let findings: Vec<_> = cidr.lines().flat_map(parse_greppable_lines).collect();
    assert_eq!(findings.len(), 3);
    assert_eq!(findings[0].host, "10.0.0.0/30");

    let empty = fixture("greppable_empty.txt");
    assert!(empty
        .lines()
        .flat_map(parse_greppable_lines)
        .next()
        .is_none());

    let malformed = fixture("greppable_malformed.txt");
    let findings: Vec<_> = malformed.lines().flat_map(parse_greppable_lines).collect();
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].port, Some(22));
    assert_eq!(findings[1].port, Some(8080));
}
