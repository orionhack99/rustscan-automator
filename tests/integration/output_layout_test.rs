#[path = "../support/mod.rs"]
mod support;

use rustscan_automator::model::scan_mode::ScanMode;
use rustscan_automator::recon;

#[test]
fn repeated_runs_do_not_overwrite_artifacts() {
    let dir = tempfile::tempdir().unwrap();

    let first = support::config(ScanMode::Port, dir.path().to_path_buf());
    let first_summary =
        recon::execute(&first, &support::FakeRunner::new(&["10.0.0.5 -> [22]"])).unwrap();

    let second = support::config(ScanMode::Port, dir.path().to_path_buf());
    let second_summary =
        recon::execute(&second, &support::FakeRunner::new(&["10.0.0.5 -> [22]"])).unwrap();

    for artifact in first_summary
        .artifacts
        .iter()
        .chain(&second_summary.artifacts)
    {
        assert!(
            std::path::Path::new(artifact).exists(),
            "missing {artifact}"
        );
    }

    // The mode result files must differ between the two runs.
    let first_mode: Vec<_> = first_summary
        .artifacts
        .iter()
        .filter(|path| path.ends_with(".txt") && !path.contains("summary"))
        .collect();
    let second_mode: Vec<_> = second_summary
        .artifacts
        .iter()
        .filter(|path| path.ends_with(".txt") && !path.contains("summary"))
        .collect();
    assert_ne!(first_mode, second_mode);
}

#[test]
fn artifacts_live_under_the_target_label() {
    let dir = tempfile::tempdir().unwrap();
    let config = support::config(ScanMode::Port, dir.path().to_path_buf());
    let summary = recon::execute(&config, &support::FakeRunner::new(&[])).unwrap();

    let target_dir = dir.path().join("10.0.0.5");
    assert!(target_dir.is_dir());
    for artifact in &summary.artifacts {
        assert!(
            artifact.starts_with(target_dir.to_str().unwrap()),
            "artifact {artifact} should be under the target directory"
        );
    }
}
