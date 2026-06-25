//! Verifies the two [`corus::DumpStrategy`] choices behave as documented:
//!
//! - `ForkSnapshot` (default): sibling threads keep running *while* the core is
//!   written, because the dump forks a copy-on-write snapshot and resumes them
//!   as soon as registers are captured. A busy sibling makes near-full forward
//!   progress across the dump.
//! - `InProcessFrozen`: every sibling stays frozen for the whole write. The same
//!   busy sibling makes almost no progress across the dump - but the core is
//!   still produced correctly.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use common::ptrace_denied;
use corus::DumpStrategy;

/// Spin a sibling that bumps a counter as fast as it can, so we can observe
/// whether it kept running during the dump. Returns its handle + shared state.
fn spawn_busy_sibling() -> (Arc<AtomicBool>, Arc<AtomicU64>, std::thread::JoinHandle<()>) {
    let stop = Arc::new(AtomicBool::new(false));
    let counter = Arc::new(AtomicU64::new(0));
    let (s, c) = (stop.clone(), counter.clone());
    let handle = std::thread::spawn(move || {
        while !s.load(Ordering::Relaxed) {
            // Relaxed increments in a tight loop; the absolute rate doesn't
            // matter, only that it advances while the thread is not frozen.
            c.fetch_add(1, Ordering::Relaxed);
            std::hint::spin_loop();
        }
    });
    (stop, counter, handle)
}

/// Touch a sizable chunk of heap so the dump has real memory to stream, making
/// the write phase clearly longer than the register-capture freeze.
fn allocate_dirty_pages(mb: usize) -> Vec<u8> {
    let mut buf = vec![0u8; mb * 1024 * 1024];
    // Dirty every page so it can't be elided to zero-fill.
    for (i, b) in buf.iter_mut().enumerate() {
        *b = (i as u8) | 1;
    }
    std::hint::black_box(&buf);
    buf
}

/// Outcome of one measured dump: the sibling's rate during the dump as a
/// fraction of its calm baseline rate, and the resulting core size.
struct Measured {
    fraction: f64,
    core_len: u64,
}

/// Run one dump with `strategy` while a sibling spins, measuring how much the
/// sibling progressed during the dump relative to baseline. Returns `None` if
/// ptrace is unavailable (caller should skip).
fn measure(strategy: DumpStrategy, label: &str) -> Option<Measured> {
    // A large dirty region makes the write phase dominate the dump so the
    // strategies separate cleanly: under InProcessFrozen the sibling is frozen
    // for ~all of it, under ForkSnapshot it runs for ~all of it.
    let _heap = allocate_dirty_pages(128);
    let (stop, counter, handle) = spawn_busy_sibling();

    // Calm baseline window: counts per second with nothing else happening.
    let warm = Duration::from_millis(100);
    let base_start = counter.load(Ordering::Relaxed);
    std::thread::sleep(warm);
    let base_end = counter.load(Ordering::Relaxed);
    let baseline_rate = (base_end - base_start) as f64 / warm.as_secs_f64();

    let core = tempfile::Builder::new()
        .prefix("cd_strategy_")
        .suffix(".core")
        .tempfile()
        .expect("create temp output");

    // SAFETY: this test process obeys the suspend contract (the sibling only
    // touches atomics, so it holds no libc locks across the freeze).
    let before = counter.load(Ordering::Relaxed);
    let t0 = std::time::Instant::now();
    let r = unsafe {
        corus::CoreDump::builder()
            .strategy(strategy)
            .write_to_path(core.path())
    };
    let dump_elapsed = t0.elapsed();
    let after = counter.load(Ordering::Relaxed);

    stop.store(true, Ordering::Relaxed);
    let _ = handle.join();

    if ptrace_denied(r, label) {
        return None;
    }

    let core_len = core.path().metadata().map(|m| m.len()).unwrap_or(0);
    let dump_rate = (after - before) as f64 / dump_elapsed.as_secs_f64();
    let fraction = dump_rate / baseline_rate;
    eprintln!(
        "{label}: baseline {baseline_rate:.0}/s, during-dump {dump_rate:.0}/s \
         ({:.0}% of baseline), dump {:.1}ms, core {core_len} bytes",
        100.0 * fraction,
        dump_elapsed.as_secs_f64() * 1000.0,
    );
    Some(Measured { fraction, core_len })
}

/// Both strategies produce a valid core, but they differ sharply in how much a
/// busy sibling keeps running *during* the write: `ForkSnapshot` resumes the
/// siblings as soon as registers are captured (so the sibling runs for ~all of
/// the write), while `InProcessFrozen` keeps them stopped for the whole write.
///
/// Absolute rates are environment-dependent (core count, CI load, disk speed),
/// so the durable signal is the *relative* one measured in the same run: the
/// fork-snapshot sibling makes far more progress than the frozen one. We avoid
/// brittle absolute thresholds.
#[test]
fn strategy_controls_whether_siblings_run_during_write() -> Result<(), Box<dyn std::error::Error>> {
    let Some(fork) = measure(DumpStrategy::ForkSnapshot, "ForkSnapshot dump") else {
        return Ok(());
    };
    let Some(frozen) = measure(DumpStrategy::InProcessFrozen, "InProcessFrozen dump") else {
        return Ok(());
    };

    // Both strategies must produce a valid, sizable core (128 MiB dirtied).
    assert!(fork.core_len > 1024 * 1024, "ForkSnapshot core too small");
    assert!(
        frozen.core_len > 1024 * 1024,
        "InProcessFrozen core too small"
    );

    // The fork snapshot keeps the sibling clearly running (frozen only for the
    // brief register capture). A low floor that holds even on a single core,
    // where the sibling time-shares with the snapshot writer.
    assert!(
        fork.fraction > 0.25,
        "ForkSnapshot: sibling ran at only {:.0}% of baseline - expected it to \
         keep running while the snapshot child wrote the core",
        100.0 * fork.fraction,
    );

    // The decisive, environment-robust check: the fork-snapshot sibling makes
    // substantially more progress during the write than the frozen one. If the
    // strategy flag were ignored, the two would be indistinguishable.
    assert!(
        fork.fraction > 2.0 * frozen.fraction,
        "expected ForkSnapshot ({:.0}%) to keep the sibling running much more \
         than InProcessFrozen ({:.0}%); the strategy may not be taking effect",
        100.0 * fork.fraction,
        100.0 * frozen.fraction,
    );
    Ok(())
}
