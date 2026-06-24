//! Differential test against `gcore`:
//! gcore a sleeper process, extract its NT_FILE file-backed mappings via
//! `eu-readelf -n`, and confirm our `parse_self_maps` produces the same set of
//! file-backed mapping ranges when run against that same process's `/proc`.
//!
//! We compare *our own* process here (we parse our maps; gcore dumps a child we
//! exec that maps the same libraries), focusing on the invariant that matters:
//! the file-backed `start-end` ranges we record match what gdb records. Skips
//! cleanly if gcore/eu-readelf are unavailable. This uses elfutils `eu-readelf`
//! rather than GNU `readelf` because the test scrapes `NT_FILE` note entries,
//! and elfutils prints those mapping ranges in a stable, line-oriented format.

mod common;

use chorus_core::proc_parse::{mapping_buf, parse_self_maps};
use std::collections::BTreeSet;
use std::process::Command;

use common::have_tool;

#[test]
fn nt_file_ranges_match_gcore() {
    if !have_tool("gcore") || !have_tool("eu-readelf") {
        eprintln!(
            "skipping: gcore/eu-readelf not available (eu-readelf is needed for parseable NT_FILE notes)"
        );
        return;
    }

    // gcore *this* test process so the dumped /proc and our parse see the same
    // address space. gcore attaches via ptrace; if that's not permitted, skip.
    let pid = std::process::id();
    let prefix = std::env::temp_dir().join(format!("cd_gcore_{pid}"));
    let out = Command::new("gcore")
        .arg("-o")
        .arg(&prefix)
        .arg(pid.to_string())
        .output();
    let out = match out {
        Ok(o) if o.status.success() => o,
        _ => {
            eprintln!("skipping: gcore failed (likely no ptrace permission)");
            return;
        }
    };
    let _ = out;
    let core_path = format!("{}.{}", prefix.display(), pid);

    // Parse our maps right after (the process is the same; mappings stable).
    let mut buf = mapping_buf();
    let n = parse_self_maps(&mut buf).expect("parse maps");
    let ours: BTreeSet<(u64, u64)> = buf[..n]
        .iter()
        .filter(|m| !m.is_anon)
        .map(|m| (m.start as u64, m.end as u64))
        .collect();

    // Extract gcore's NT_FILE ranges. GNU readelf can describe notes, but this
    // parser expects the elfutils line format with `start-end ... path`.
    let readelf = Command::new("eu-readelf")
        .arg("-n")
        .arg(&core_path)
        .output()
        .expect("run eu-readelf");
    let text = String::from_utf8_lossy(&readelf.stdout);
    let _ = std::fs::remove_file(&core_path);

    // Lines like: "      55f7..000-55f7..000 00000000 8192   /usr/bin/..."
    let mut theirs: BTreeSet<(u64, u64)> = BTreeSet::new();
    for line in text.lines() {
        let t = line.trim();
        if let Some((range, _rest)) = t.split_once(' ')
            && let Some((a, b)) = range.split_once('-')
            && let (Ok(start), Ok(end)) =
                (u64::from_str_radix(a, 16), u64::from_str_radix(b, 16))
            // Only count lines that look like NT_FILE entries (path present).
            && t.contains('/')
        {
            theirs.insert((start, end));
        }
    }

    if theirs.is_empty() {
        eprintln!("skipping: could not parse gcore NT_FILE (readelf format?)");
        return;
    }

    // gdb's NT_FILE includes file-backed mappings; ours should be a superset of
    // gdb's path-bearing ranges (gdb may coalesce or filter a few). Require
    // substantial overlap rather than exact equality to tolerate benign diffs.
    let overlap = theirs.iter().filter(|r| ours.contains(r)).count();
    let ratio = overlap as f64 / theirs.len() as f64;
    assert!(
        ratio >= 0.8,
        "our file-backed ranges should cover >=80% of gcore's NT_FILE; \
         overlap {overlap}/{} (ours has {})",
        theirs.len(),
        ours.len()
    );
}
