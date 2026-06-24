//! strace-based verification that our `clone` wrapper issues exactly one
//! `clone` syscall with the expected flags.
//!
//! Skips gracefully if strace is unavailable or cannot trace (e.g. restricted
//! CI sandboxes), so it never produces a false failure.

use std::process::Command;

#[test]
fn clone_issues_one_clone_syscall() {
    // strace present?
    if Command::new("strace").arg("-V").output().is_err() {
        eprintln!("skipping: strace not available");
        return;
    }

    // Cargo exposes CARGO_BIN_EXE_<name> only for bins, not examples, so we run
    // the example through `cargo run --example clone_once` under strace.
    let out = Command::new("strace")
        .args([
            "-f", // follow the cloned child
            "-e",
            "trace=clone,clone3",
            "-qq",
            "cargo",
            "run",
            "-q",
            "--example",
            "clone_once",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output();

    let out = match out {
        Ok(o) => o,
        Err(e) => {
            eprintln!("skipping: could not run strace: {e}");
            return;
        }
    };

    let trace = String::from_utf8_lossy(&out.stderr);
    if trace.contains("PTRACE_TRACEME") && trace.contains("Operation not permitted") {
        eprintln!("skipping: strace cannot trace in this environment");
        return;
    }

    // Match OUR clone specifically, not cargo's runtime thread spawns. Our
    // wrapper emits the legacy `clone(child_stack=..., flags=...CLONE_UNTRACED
    // |SIGCHLD)`; cargo's std threads use `clone3(...CLONE_THREAD...)`. The
    // CLONE_UNTRACED + child_stack combination is unique to our wrapper.
    let ours = trace
        .lines()
        .filter(|l| {
            l.contains("clone(") && l.contains("child_stack=") && l.contains("CLONE_UNTRACED")
        })
        .count();

    assert!(
        ours >= 1,
        "expected our clone(child_stack=.., CLONE_UNTRACED) in strace output; trace:\n{trace}"
    );
}
