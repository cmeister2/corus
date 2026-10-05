//! Check sibling progress while a core stream is deliberately blocked.
//! A separate reader process observes a shared counter during the actual write.

mod common;

use core::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use common::ptrace_denied;
use corus::DumpStrategy;
use corus_core::corus_syscall::{linux::EINTR, sys};
use corus_core::io::{Pipe, c_read};

/// Spin a sibling that bumps a counter as fast as it can, so we can observe
/// whether it kept running during the dump. The counter is shared with a reader process.
fn spawn_busy_sibling(counter_address: usize) -> (Arc<AtomicBool>, std::thread::JoinHandle<()>) {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_worker = stop.clone();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let counter = unsafe { &*(counter_address as *const AtomicU64) };
        let tid = corus_core::corus_syscall::sys::gettid().expect("sibling tid");
        ready_tx.send(tid).expect("publish sibling tid");
        while !stop_worker.load(Ordering::Relaxed) {
            counter.fetch_add(1, Ordering::Relaxed);
            std::hint::spin_loop();
        }
    });
    let tid = ready_rx.recv().expect("sibling started");
    eprintln!("corus-strategy sibling.tid={tid}");
    (stop, handle)
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

/// Atomic observations shared with the independently running core reader.
struct SharedProgress {
    counter: AtomicU64,
    during_write: AtomicU64,
    core_len: AtomicU64,
    sampled: AtomicBool,
}

/// Drain the core, pausing after enough data to ensure serialization has started.
/// Runs in the fork child using only raw syscalls and shared atomics.
unsafe fn observe_write(fd: i32, shared: *const SharedProgress) -> ! {
    let shared = unsafe { &*shared };
    let mut buffer = [0u8; 4096];
    let mut total = 0;
    loop {
        let bytes = match unsafe { c_read(fd, buffer.as_mut_ptr().cast(), buffer.len()) } {
            Ok(0) => break,
            Ok(bytes) => bytes,
            Err(_) => sys::exit(1),
        };
        total += bytes as u64;
        if total >= 64 * 1024 && !shared.sampled.load(Ordering::SeqCst) {
            let before = shared.counter.load(Ordering::SeqCst);
            loop {
                match unsafe { sys::poll(core::ptr::null_mut(), 0, 50) } {
                    Ok(_) => break,
                    Err(EINTR) => continue,
                    Err(_) => sys::exit(1),
                }
            }
            shared.during_write.store(
                shared.counter.load(Ordering::SeqCst) - before,
                Ordering::SeqCst,
            );
            shared.sampled.store(true, Ordering::SeqCst);
        }
    }
    shared.core_len.store(total, Ordering::SeqCst);
    sys::exit(0)
}

/// Sibling progress observed while output was blocked, plus the core size.
struct Measured {
    progress: u64,
    core_len: u64,
}

/// Run a dump with a separate reader, which cannot be suspended with the siblings.
/// Returns `None` if ptrace is unavailable.
fn measure(
    strategy: DumpStrategy,
    label: &str,
) -> Result<Option<Measured>, Box<dyn std::error::Error>> {
    eprintln!("corus-strategy {label} begin pid={}", std::process::id());
    let _heap = allocate_dirty_pages(8);
    let memory = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            mem::size_of::<SharedProgress>(),
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(memory, libc::MAP_FAILED);
    let shared = memory as *mut SharedProgress;
    unsafe {
        shared.write(SharedProgress {
            counter: AtomicU64::new(0),
            during_write: AtomicU64::new(0),
            core_len: AtomicU64::new(0),
            sampled: AtomicBool::new(false),
        });
    }
    let [read_fd, write_fd] = Pipe::new()
        .map_err(std::io::Error::from_raw_os_error)?
        .into_fds();
    let observer = sys::fork().map_err(std::io::Error::from_raw_os_error)?;
    if observer == 0 {
        let _ = sys::close(write_fd);
        unsafe { observe_write(read_fd, shared) };
    }
    let _ = sys::close(read_fd);
    let output = unsafe { OwnedFd::from_raw_fd(write_fd) };
    let shared_ref = unsafe { &*shared };
    let (stop, handle) = spawn_busy_sibling(&shared_ref.counter as *const AtomicU64 as usize);
    let result = unsafe {
        corus::CoreDump::builder()
            .strategy(strategy)
            .write_to_fd(output.as_raw_fd())
    };
    drop(output);
    stop.store(true, Ordering::Relaxed);
    let _ = handle.join();
    let mut status = 0;
    loop {
        match unsafe { sys::wait4(observer as i32, &mut status, 0, core::ptr::null_mut()) } {
            Ok(_) => break,
            Err(EINTR) => continue,
            Err(errno) => return Err(std::io::Error::from_raw_os_error(errno).into()),
        }
    }
    let measured = Measured {
        progress: shared_ref.during_write.load(Ordering::SeqCst),
        core_len: shared_ref.core_len.load(Ordering::SeqCst),
    };
    let sampled = shared_ref.sampled.load(Ordering::SeqCst);
    assert_eq!(
        unsafe { libc::munmap(memory, mem::size_of::<SharedProgress>()) },
        0
    );
    eprintln!(
        "corus-strategy {label} end result={result:?} progress={} core_len={}",
        measured.progress, measured.core_len
    );
    if std::env::var_os("CORUS_DIAGNOSTIC_STRICT").is_some() {
        assert!(result.is_ok(), "diagnostic dump must not skip: {result:?}");
    }
    if ptrace_denied(result, label) {
        return Ok(None);
    }
    assert_eq!(status, 0, "core reader must exit successfully");
    assert!(sampled, "core reader must observe a blocked write");
    Ok(Some(measured))
}

/// Check progress during the blocked write rather than timing the whole API call.
#[test]
fn strategy_controls_whether_siblings_run_during_write() -> Result<(), Box<dyn std::error::Error>> {
    let Some(fork) = measure(DumpStrategy::ForkSnapshot, "ForkSnapshot dump")? else {
        return Ok(());
    };
    let Some(frozen) = measure(DumpStrategy::InProcessFrozen, "InProcessFrozen dump")? else {
        return Ok(());
    };

    assert!(fork.core_len > 1024 * 1024, "ForkSnapshot core too small");
    assert!(
        frozen.core_len > 1024 * 1024,
        "InProcessFrozen core too small"
    );

    assert!(
        fork.progress > 0,
        "ForkSnapshot must resume the sibling while the core stream is blocked"
    );
    assert_eq!(
        frozen.progress, 0,
        "InProcessFrozen must keep the sibling stopped while the core stream is blocked"
    );
    Ok(())
}
