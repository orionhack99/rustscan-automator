//! CLI contract tests: exit codes and the end-to-end path through the real
//! process boundary using a fake RustScan shell script (no network access).

use std::os::unix::fs::PermissionsExt;

use assert_cmd::Command;
use predicates::prelude::*;

fn bin() -> Command {
    Command::cargo_bin("rustscan-automator").expect("binary builds")
}

#[test]
fn help_exits_zero() {
    bin().arg("--help").assert().success();
}

#[test]
fn version_exits_zero() {
    bin().arg("--version").assert().success();
}

#[test]
fn missing_required_args_exit_2() {
    bin().assert().code(2);
}

#[test]
fn unknown_mode_exits_2() {
    bin()
        .args(["-H", "10.0.0.5", "-t", "bogus"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unknown scan type"));
}

#[test]
fn invalid_target_exits_2() {
    bin()
        .args(["-H", "not a host!!", "-t", "port"])
        .assert()
        .code(2);
}

#[test]
fn conflicting_port_options_exit_2() {
    bin()
        .args([
            "-H",
            "10.0.0.5",
            "-t",
            "port",
            "--ports",
            "22",
            "--ports-file",
            "/tmp/ports.txt",
        ])
        .assert()
        .code(2);
}

#[test]
fn missing_engine_exits_3() {
    bin()
        .args([
            "-H",
            "10.0.0.5",
            "-t",
            "port",
            "--static-rustscan",
            "/nonexistent/rustscan",
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("missing dependency"));
}

#[test]
fn port_mode_with_fake_engine_writes_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("fake-rustscan.sh");
    std::fs::write(&script, "#!/bin/sh\necho '10.0.0.5 -> [22,80]'\n").unwrap();
    let mut permissions = std::fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&script, permissions).unwrap();

    let out = dir.path().join("out");
    bin()
        .args([
            "-H",
            "10.0.0.5",
            "-t",
            "port",
            "--output",
            out.to_str().unwrap(),
            "--static-rustscan",
            script.to_str().unwrap(),
            "--yes",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("10.0.0.5 -> [22,80]"));

    let target_dir = out.join("10.0.0.5");
    assert!(target_dir.is_dir(), "target output directory exists");
    let entries = std::fs::read_dir(&target_dir).unwrap().count();
    assert!(
        entries >= 4,
        "expected at least 4 artifacts, found {entries}"
    );
}
