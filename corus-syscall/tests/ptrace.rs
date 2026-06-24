//! ptrace attach/detach round-trip.
//!
//! ptrace is the heart of thread suspension, so we validate it directly:
//! fork a child that spins, PTRACE_ATTACH it (which stops it), wait for the
//! stop, then PTRACE_DETACH and confirm the child resumes and we can reap it.
//!
//! Uses libc only to fork/setup the victim; the ptrace/wait/kill calls under
//! test go through our wrappers.

use core::ptr;
use corus_syscall::sys;

const PTRACE_ATTACH: i32 = 16;
const PTRACE_DETACH: i32 = 17;
const SIGKILL: i32 = 9;
const SIGSTOP: i32 = 19;

#[test]
fn ptrace_attach_detach_roundtrip() {
    // Fork a child that just spins; we'll attach/detach/kill it.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");

    if pid == 0 {
        // Child: spin until killed. Avoid libc niceties; just loop on a syscall.
        loop {
            let _ = sys::sched_yield();
        }
    }

    // Parent: attach (this stops the child with SIGSTOP-like semantics).
    let r = unsafe { sys::ptrace(PTRACE_ATTACH, pid, ptr::null_mut(), ptr::null_mut()) };
    assert!(r.is_ok(), "PTRACE_ATTACH failed: {r:?}");

    // Wait for the tracee to stop.
    let mut status: i32 = 0;
    let __wall = 0x4000_0000;
    let w = unsafe { sys::wait4(pid, &mut status, __wall, ptr::null_mut()) };
    assert_eq!(w.unwrap() as i32, pid);
    // WIFSTOPPED: low byte == 0x7f
    assert_eq!(
        status & 0xff,
        0x7f,
        "tracee should be stopped, status={status:#x}"
    );
    // WSTOPSIG should be SIGSTOP
    assert_eq!(
        (status >> 8) & 0xff,
        SIGSTOP,
        "stop signal should be SIGSTOP"
    );

    // Detach, letting the child continue.
    let d = unsafe { sys::ptrace(PTRACE_DETACH, pid, ptr::null_mut(), ptr::null_mut()) };
    assert!(d.is_ok(), "PTRACE_DETACH failed: {d:?}");

    // Clean up: kill the spinning child and reap it.
    sys::kill(pid, SIGKILL).expect("kill");
    let mut final_status: i32 = 0;
    let _ = unsafe { sys::wait4(pid, &mut final_status, __wall, ptr::null_mut()) };
    // WIFSIGNALED with SIGKILL
    assert_eq!(
        final_status & 0x7f,
        SIGKILL,
        "child should die from SIGKILL"
    );
}
