//! Minimal program that performs exactly one `clone` via our wrapper, for
//! strace-based verification (see tests/strace_clone.rs).
//!
//! The child writes one byte to stdout and exits; the parent waits and exits 0.

use chorus_syscall::sys;
use core::ffi::c_void;

/// Share the address space with the child.
const CLONE_VM: usize = 0x0000_0100;
/// Share filesystem context with the child.
const CLONE_FS: usize = 0x0000_0200;
/// Share the file descriptor table with the child.
const CLONE_FILES: usize = 0x0000_0400;
/// Do not let tracing follow this helper clone.
const CLONE_UNTRACED: usize = 0x0080_0000;
/// Signal delivered to the parent when the child exits.
const SIGCHLD: usize = 17;

/// Child entry point used by the clone wrapper smoke example.
extern "C" fn child(_arg: *mut c_void) -> i32 {
    let b = [b'k'];
    let _ = unsafe { sys::write(1, b.as_ptr() as *const c_void, 1) };
    0
}

fn main() {
    const N: usize = 64 * 1024;
    let mut stack = vec![0u8; N];
    let top = unsafe { stack.as_mut_ptr().add(N) } as *mut c_void;
    let flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_UNTRACED | SIGCHLD;
    let tid = unsafe {
        chorus_syscall::clone(
            child,
            top,
            flags,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    let tid = chorus_syscall::from_ret(tid).expect("clone");
    let mut status = 0i32;
    let _ = unsafe { sys::wait4(tid as i32, &mut status, 0x4000_0000, core::ptr::null_mut()) };
    drop(stack);
}
