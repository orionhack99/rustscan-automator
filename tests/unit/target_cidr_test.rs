use rustscan_automator::model::target::{Target, TargetKind};

#[test]
fn classifies_ip_hostname_and_cidr() {
    assert_eq!(Target::parse("10.0.0.1").unwrap().kind, TargetKind::Ip);
    assert_eq!(
        Target::parse("example.com").unwrap().kind,
        TargetKind::Hostname
    );
    assert_eq!(Target::parse("10.0.0.0/24").unwrap().kind, TargetKind::Cidr);
    assert_eq!(Target::parse("::1").unwrap().kind, TargetKind::Ip);
}

#[test]
fn cidr_ranges_are_flagged() {
    assert!(Target::parse("10.0.0.0/24").unwrap().is_network_range());
    assert!(!Target::parse("10.0.0.1").unwrap().is_network_range());
}

#[test]
fn rejects_invalid_targets() {
    assert!(Target::parse("").is_err());
    assert!(Target::parse("   ").is_err());
    assert!(Target::parse("10.0.0.0/99").is_err());
    assert!(Target::parse("10.0.0.0/notanumber").is_err());
    assert!(Target::parse("-bad-").is_err());
    assert!(Target::parse("has space").is_err());
}

#[test]
fn produces_filesystem_safe_labels() {
    assert_eq!(Target::parse("10.0.0.0/24").unwrap().label, "10.0.0.0-24");
    assert_eq!(Target::parse("example.com").unwrap().label, "example.com");
}
