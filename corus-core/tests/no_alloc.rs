//! Hardening guard: the `no_std` engine must never reference libc allocation or
//! pthread-lock symbols. Everything reachable after thread
//! suspension lives here, so a `malloc`/`pthread_mutex_lock` reference would be
//! a latent deadlock on the dump path.
//!
//! This inspects the compiled `corus-core` rlib with `nm` and fails if any
//! forbidden symbol appears as an undefined reference. Skips if `nm`/the rlib
//! can't be found (e.g. unusual build layouts).

mod common;

use std::process::Command;

use common::have_tool;

#[test]
fn engine_rlib_has_no_alloc_or_lock_symbols() {
    if !have_tool("nm") {
        eprintln!("skipping: nm not available");
        return;
    }

    // Find our own rlib under target/.../deps/libcorus_core-*.rlib.
    let mut dir = std::env::current_exe().unwrap();
    // .../deps/no_alloc-<hash>  -> .../deps
    dir.pop();
    let rlib = std::fs::read_dir(&dir).ok().and_then(|entries| {
        entries.flatten().map(|e| e.path()).find(|p| {
            let n = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            n.starts_with("libcorus_core-") && n.ends_with(".rlib")
        })
    });
    let rlib = match rlib {
        Some(p) => p,
        None => {
            eprintln!("skipping: corus_core rlib not found in {dir:?}");
            return;
        }
    };

    let out = Command::new("nm").arg(&rlib).output().expect("run nm");
    let text = String::from_utf8_lossy(&out.stdout);

    // Undefined references (lines like "         U malloc").
    let forbidden = [
        "malloc",
        "calloc",
        "realloc",
        "free",
        "posix_memalign",
        "pthread_mutex_lock",
        "pthread_mutex_unlock",
        "__libc_",
    ];
    let mut hits = Vec::new();
    for line in text.lines() {
        // Format: "<addr or blank> U <symbol>" for undefined symbols.
        let mut it = line.split_whitespace();
        let (kind, sym) = match (it.next(), it.next(), it.next()) {
            (Some("U"), Some(sym), _) => ("U", sym),
            (Some(_addr), Some("U"), Some(sym)) => ("U", sym),
            _ => continue,
        };
        let _ = kind;
        if forbidden.iter().any(|f| sym.contains(f)) {
            hits.push(sym.to_string());
        }
    }

    assert!(
        hits.is_empty(),
        "corus-core (the post-suspension engine) must not reference libc \
         allocation/lock symbols, but found: {hits:?}"
    );
}
