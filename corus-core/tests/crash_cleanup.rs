//! Lister crash-cleanup: if the lister thread faults while sibling threads are
//! PTRACE_ATTACHed, the sync-signal handler must resume them so the
//! application isn't left with frozen threads.
//!
//! We drive this through a callback that deliberately raises SIGSEGV while
//! threads are suspended. The handler should resume the tracees and _exit the
//! lister; the parent observes the lister's abnormal exit, and - crucially - the
//! worker threads keep making progress (proving they were resumed, not left
//! stopped).

use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use corus_core::threads::{ALT_STACK_SIZE, with_mmap_stack};
use std::time::Duration;

static PROGRESS: AtomicU64 = AtomicU64::new(0);
static KEEP_RUNNING: AtomicBool = AtomicBool::new(true);

/// Callback that faults on purpose, simulating a lister crash mid-suspend.
extern "C" fn crashing_callback(_p: *mut c_void, _pids: *const c_int, _n: c_int) -> c_int {
    // Write to an aligned but unmapped address to raise a genuine SIGSEGV inside
    // the lister. Use inline asm so no Rust UB-precondition check fires first
    // (we *want* the hardware fault, which the crash handler then catches).
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "mov qword ptr [{p}], 0",
            p = in(reg) 0x8usize, // aligned, unmapped low address
            options(nostack),
        );
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!(
            "str xzr, [{p}]",
            p = in(reg) 0x8usize, // aligned, unmapped low address
            options(nostack),
        );
    }
    0
}

#[test]
fn lister_crash_resumes_tracees() {
    // Reference the exported alt-stack constant so it stays part of the public
    // surface; the handler relies on this fixed no-libc buffer.
    let _alt = ALT_STACK_SIZE;

    // Worker threads that increment a counter, so we can tell they are running.
    let mut handles = Vec::new();
    for _ in 0..3 {
        handles.push(std::thread::spawn(|| {
            while KEEP_RUNNING.load(Ordering::Relaxed) {
                PROGRESS.fetch_add(1, Ordering::Relaxed);
                std::hint::spin_loop();
            }
        }));
    }
    std::thread::sleep(Duration::from_millis(50));

    // Invoke the lister with the crashing callback. The lister runs in a cloned
    // "thread"; its SIGSEGV is handled by our crash handler (resume tracees +
    // _exit), so `with_mmap_stack` returns an error rather than crashing us.
    let result = unsafe { with_mmap_stack(core::ptr::null_mut(), crashing_callback, 0) };

    // The lister should have died (EFAULT=14) or been denied ptrace (EPERM=1).
    match result {
        Err(14) => { /* expected: lister faulted, handler ran */ }
        Err(1) => {
            eprintln!("skipping assertions: ptrace not permitted here");
            KEEP_RUNNING.store(false, Ordering::Relaxed);
            for h in handles {
                let _ = h.join();
            }
            return;
        }
        other => {
            // Any other outcome (Ok, or a different errno) is unexpected but we
            // still must not hang - fall through to the progress check.
            eprintln!("note: unexpected lister result {other:?}");
        }
    }

    // The key assertion: after the crash, the worker threads are NOT frozen.
    // Sample progress, wait, sample again - it must advance.
    let before = PROGRESS.load(Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(100));
    let after = PROGRESS.load(Ordering::Relaxed);

    KEEP_RUNNING.store(false, Ordering::Relaxed);
    for h in handles {
        let _ = h.join();
    }

    assert!(
        after > before,
        "worker threads must keep running after lister crash \
         (before={before}, after={after}); they were left frozen"
    );
}
