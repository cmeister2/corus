//! Dump this process through the safe Rust builder.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

#[inline(never)]
/// Innermost frame that writes the core through the Rust API.
fn dump_from_deep_frame(path: &Path) -> Result<(), chorus::Error> {
    let marker = 0xC0DE_D00D_FEED_FACE_u64;
    std::hint::black_box(marker);

    unsafe { chorus::CoreDump::builder().write_to_path(path) }
}

#[inline(never)]
/// Middle frame kept visible in debugger backtraces.
fn call_level_two(path: &Path) -> Result<(), chorus::Error> {
    dump_from_deep_frame(path)
}

#[inline(never)]
/// Outermost helper frame kept visible in debugger backtraces.
fn call_level_one(path: &Path) -> Result<(), chorus::Error> {
    call_level_two(path)
}

/// Default output path when the example is run without an argument.
fn default_core_path() -> PathBuf {
    std::env::temp_dir().join(format!("coredumper-self-{}.core", std::process::id()))
}

fn main() {
    let core_path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(default_core_path);

    let keep_running = Arc::new(AtomicBool::new(true));
    let mut workers = Vec::new();
    for worker_id in 0usize..2 {
        let keep_running = Arc::clone(&keep_running);
        workers.push(thread::spawn(move || {
            let mut ticks = worker_id;
            while keep_running.load(Ordering::Relaxed) {
                ticks = ticks.wrapping_add(1);
                std::hint::black_box(ticks);
                std::hint::spin_loop();
            }
        }));
    }

    thread::sleep(Duration::from_millis(50));
    println!(
        "dumping process {} to {}",
        std::process::id(),
        core_path.display()
    );

    let result = call_level_one(&core_path);

    keep_running.store(false, Ordering::Relaxed);
    for worker in workers {
        let _ = worker.join();
    }

    match result {
        Ok(()) => {
            println!("wrote {}", core_path.display());
            println!(
                "try: gdb {} {}",
                std::env::current_exe().unwrap().display(),
                core_path.display()
            );
        }
        Err(err) => {
            eprintln!("failed to write core: {err:?}");
            std::process::exit(1);
        }
    }
}
