//! Shared helpers for `corus-core` integration tests.

use std::path::Path;
use std::process::{Command, Output};

/// Return true when `tool` can be executed from `PATH`.
pub fn have_tool(tool: &str) -> bool {
    Command::new(tool).arg("--version").output().is_ok()
        || Command::new(tool).arg("--help").output().is_ok()
}

/// Run `readelf -h path`, or skip the caller's external-tool assertions when
/// `readelf` is not available in `PATH`.
#[allow(dead_code)]
pub fn readelf_header(path: &Path) -> Option<Output> {
    if !have_tool("readelf") {
        eprintln!("skipping: readelf not available");
        return None;
    }

    match Command::new("readelf").arg("-h").arg(path).output() {
        Ok(output) => Some(output),
        Err(_) => {
            eprintln!("skipping: readelf not available");
            None
        }
    }
}
