//! Dump this process to a core file given as argv[1]. Used by the gdb-load
//! integration test. Establishes a recognizable call stack first so `bt` has
//! something to show.

use std::os::fd::AsRawFd;

#[inline(never)]
/// Innermost frame that actually writes the core file.
fn deep_frame_c(core_path: &str) {
    // A distinctive local so we can confirm gdb sees this frame's variables.
    let marker: u64 = 0xC0FF_EE12_3456_7890;
    std::hint::black_box(marker);

    let f = std::fs::File::create(core_path).expect("create core file");
    let fd = f.as_raw_fd();
    let rc =
        unsafe { chorus_core::write_core_dump_to_fd(fd) }.unwrap_or_else(|error| error.errno());
    std::hint::black_box(&f);
    if rc != 0 {
        eprintln!("dump failed");
        std::process::exit(2);
    }
}

#[inline(never)]
/// Middle frame kept visible in gdb backtraces.
fn deep_frame_b(core_path: &str) {
    deep_frame_c(core_path);
}

#[inline(never)]
/// Outermost named frame kept visible in gdb backtraces.
fn deep_frame_a(core_path: &str) {
    deep_frame_b(core_path);
}

fn main() {
    let core_path = std::env::args()
        .nth(1)
        .expect("usage: dump_self <core-path>");
    // Spawn a couple of worker threads so the core has multiple PRSTATUS notes.
    let kr = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let mut hs = Vec::new();
    for _ in 0..2 {
        let k = kr.clone();
        hs.push(std::thread::spawn(move || {
            while k.load(std::sync::atomic::Ordering::Relaxed) {
                std::hint::spin_loop();
            }
        }));
    }
    std::thread::sleep(std::time::Duration::from_millis(50));

    deep_frame_a(&core_path);

    kr.store(false, std::sync::atomic::Ordering::Relaxed);
    for h in hs {
        let _ = h.join();
    }
    println!("ok");
}
