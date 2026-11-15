use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_tuta-bridge"))
        .args(args)
        .output()
        .expect("failed to run tuta-bridge binary")
}

#[test]
fn help_exits_successfully_with_usage() {
    let output = run(&["--help"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "stdout was: {stdout}");
}

#[test]
fn version_exits_successfully() {
    let output = run(&["--version"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("tuta-bridge"), "stdout was: {stdout}");
}

#[test]
fn unknown_subcommand_exits_with_usage_code() {
    let output = run(&["bogus"]);
    assert_eq!(output.status.code(), Some(2));
}
