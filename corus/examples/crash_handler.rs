//! Install Corus as a crash handler and dump the process from inside a
//! `SIGSEGV` handler.
//!
//! This is the case the README leads with: a live process that dumps *itself*
//! from an arbitrary, hostile call site - a signal handler running after a
//! fault. Corus is a good fit here precisely because its dump path is
//! `no_std`, allocation-free, and libc-free, so it does not depend on heap or
//! libc state that a fault may have corrupted.
//!
//! The handler follows the async-signal-safe rules a real crash handler must:
//!
//! * The output fd is opened **before** the handler runs, so the handler never
//!   allocates or calls `open` on the crash path. (`write_to_fd`, not
//!   `write_to_path`.)
//! * The handler is registered on an **alternate signal stack** (`SA_ONSTACK`
//!   + `sigaltstack`), so a stack-overflow fault still has a stack to run on.
//! * Only async-signal-safe calls are used to report progress (`write(2)` of a
//!   static string, not `println!`).
//!
//! For CI determinism this example writes the core and then `_exit(0)`s. A
//! production handler would instead restore the default disposition and
//! re-raise the signal (see `reraise` below) so the process still dies with the
//! original signal and the kernel records the right termination status.

use std::os::fd::RawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI32, Ordering};

/// The output fd, published before the handler can run so the handler only has
/// to read it.
static CORE_FD: AtomicI32 = AtomicI32::new(-1);

/// Async-signal-safe: write a whole byte string to `fd`, ignoring short writes.
fn write_all_signal_safe(fd: RawFd, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        // SAFETY: `write(2)` is async-signal-safe; `bytes` is a valid slice.
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if n <= 0 {
            break;
        }
        bytes = &bytes[n as usize..];
    }
}

/// Async-signal-safe: write a signed integer as decimal to `fd`. No allocation
/// or libc formatting - renders into a fixed on-stack buffer.
fn write_i32_signal_safe(fd: RawFd, mut v: i32) {
    let mut buf = [0u8; 12];
    let mut i = buf.len();
    let neg = v < 0;
    // Work in the negative domain to handle i32::MIN without overflow.
    let mut n = if neg { v } else { -v };
    loop {
        i -= 1;
        buf[i] = b'0' + (-(n % 10)) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    if neg {
        i -= 1;
        buf[i] = b'-';
    }
    let _ = &mut v;
    write_all_signal_safe(fd, &buf[i..]);
}

/// The `SIGSEGV` handler. Runs on the alternate stack after a fault.
extern "C" fn on_sigsegv(_sig: libc::c_int) {
    let fd = CORE_FD.load(Ordering::Acquire);
    if fd < 0 {
        write_all_signal_safe(libc::STDERR_FILENO, b"no core fd; aborting\n");
        // SAFETY: `_exit` is async-signal-safe.
        unsafe { libc::_exit(1) };
    }

    // Dump this process to the pre-opened fd. The engine performs no heap
    // allocation and touches no libc state on the dump path - it works out of
    // fixed-size on-stack buffers instead (which is why the alternate signal
    // stack below is sized generously). It is not stack-free, but its stack use
    // is bounded and does not depend on the allocator or libc.
    //
    // SAFETY: clones a thread sharing this address space and ptrace-stops the
    // others; `fd` is writable and owned for the process lifetime.
    let rc = unsafe { corus::CoreDump::builder().write_to_fd(fd) };

    match rc {
        Ok(()) => write_all_signal_safe(libc::STDERR_FILENO, b"crash_handler: wrote core\n"),
        Err(e) => {
            // INSTRUMENTATION (test-only): report which failure variant and its
            // errno-style code so CI logs pinpoint the cause. Async-signal-safe:
            // matches on a Copy enum and writes decimals via a stack buffer.
            write_all_signal_safe(libc::STDERR_FILENO, b"crash_handler: dump failed variant=");
            let errno = match e {
                corus::Error::Failed => {
                    write_all_signal_safe(libc::STDERR_FILENO, b"Failed");
                    None
                }
                corus::Error::Io => {
                    write_all_signal_safe(libc::STDERR_FILENO, b"Io");
                    None
                }
                corus::Error::Core(ce) => {
                    write_all_signal_safe(libc::STDERR_FILENO, b"Core");
                    Some(ce.errno())
                }
                _ => {
                    write_all_signal_safe(libc::STDERR_FILENO, b"Unknown");
                    None
                }
            };
            if let Some(code) = errno {
                write_all_signal_safe(libc::STDERR_FILENO, b" errno=");
                write_i32_signal_safe(libc::STDERR_FILENO, code);
            }
            write_all_signal_safe(libc::STDERR_FILENO, b"\n");
        }
    }

    // A production handler would `reraise()` here instead of exiting cleanly.
    let _ = reraise;

    // SAFETY: `_exit` is async-signal-safe and does not run destructors.
    unsafe { libc::_exit(if rc.is_ok() { 0 } else { 1 }) };
}

/// Restore the default disposition for `SIGSEGV` and re-raise it, so the
/// process terminates with the original signal. Kept for documentation; the
/// example `_exit`s instead so CI can assert a clean run.
#[allow(dead_code)]
fn reraise() -> ! {
    // SAFETY: resetting to SIG_DFL and re-raising are async-signal-safe.
    unsafe {
        libc::signal(libc::SIGSEGV, libc::SIG_DFL);
        libc::raise(libc::SIGSEGV);
        libc::_exit(139); // 128 + SIGSEGV, in case the raise is delayed.
    }
}

/// Install the alternate signal stack and the `SIGSEGV` handler.
fn install_handler() {
    // Alternate stack, leaked so it lives for the whole process.
    let stack_size = libc::SIGSTKSZ.max(64 * 1024);
    let mem = vec![0u8; stack_size].into_boxed_slice();
    let stack = libc::stack_t {
        ss_sp: Box::into_raw(mem).cast(),
        ss_flags: 0,
        ss_size: stack_size,
    };
    // SAFETY: `stack` is a valid, live alternate stack.
    let rc = unsafe { libc::sigaltstack(&stack, std::ptr::null_mut()) };
    assert_eq!(rc, 0, "sigaltstack failed");

    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = on_sigsegv as *const () as usize;
    action.sa_flags = libc::SA_ONSTACK | libc::SA_NODEFER | libc::SA_RESETHAND;
    // SAFETY: clearing the mask set is safe on a zeroed sigaction.
    unsafe { libc::sigemptyset(&mut action.sa_mask) };

    // SAFETY: installing a handler with a valid sigaction.
    let rc = unsafe { libc::sigaction(libc::SIGSEGV, &action, std::ptr::null_mut()) };
    assert_eq!(rc, 0, "sigaction failed");
}

/// Default output path when the example is run without an argument.
fn default_core_path() -> PathBuf {
    std::env::temp_dir().join(format!("corus-crash-{}.core", std::process::id()))
}

/// Deliberately dereference a null pointer to raise `SIGSEGV`. Kept
/// non-inlined so it stays visible in the dumped backtrace.
#[inline(never)]
fn trigger_fault() {
    // Deliberate null write to raise SIGSEGV.
    let p: *mut u8 = std::ptr::null_mut();
    // SAFETY: intentionally faulting to demonstrate the crash handler.
    unsafe { p.write_volatile(0) };
    std::hint::black_box(p);
}

fn main() {
    let core_path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(default_core_path);

    // Open the output fd up front, so the handler never has to.
    let c_path = std::ffi::CString::new(core_path.as_os_str().as_encoded_bytes())
        .expect("path has no interior NUL");
    // SAFETY: `c_path` is a valid NUL-terminated C string.
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC,
            0o600,
        )
    };
    assert!(fd >= 0, "could not open {}", core_path.display());
    CORE_FD.store(fd, Ordering::Release);

    install_handler();

    println!(
        "crash_handler: process {} will fault and dump to {}",
        std::process::id(),
        core_path.display()
    );

    trigger_fault();

    // Unreachable: the handler `_exit`s.
    eprintln!("crash_handler: fault did not trigger the handler");
    std::process::exit(2);
}
