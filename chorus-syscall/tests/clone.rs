//! Dedicated `sys_clone` test.
//!
//! The faithful x86_64 `clone` wrapper runs `fn(arg)` on the supplied child
//! stack and terminates the child via `exit(fn_ret)`; only the parent returns,
//! receiving the child tid. We verify:
//!   - the parent gets a positive tid,
//!   - the child actually runs `fn` (it writes a sentinel through a shared pipe,
//!     since with CLONE_VM the child shares our address space),
//!   - the child's exit status equals `fn`'s return value,
//!   - exactly one clone happens (asserted structurally via the single tid).
//!
//! A strace-level check (one `clone` syscall, expected flags) is in
//! `tests/strace_clone.rs`, gated on strace being available.

use chorus_syscall::linux::EINVAL;
use chorus_syscall::sys;
use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

// CLONE flags matching what linuxthreads.c uses for the lister thread.
const CLONE_VM: usize = 0x0000_0100;
const CLONE_FS: usize = 0x0000_0200;
const CLONE_FILES: usize = 0x0000_0400;
const CLONE_UNTRACED: usize = 0x0080_0000;
const SIGCHLD: usize = 17;

/// Child entry: write a sentinel byte to the pipe write-fd carried in `arg`,
/// then return 7 (which becomes the child's exit code).
extern "C" fn child_entry(arg: *mut c_void) -> i32 {
    let wfd = arg as usize as i32;
    let byte = [0xA5u8];
    // SAFETY: wfd is a valid pipe write end provided by the parent.
    let _ = unsafe { sys::write(wfd, byte.as_ptr() as *const c_void, 1) };
    7
}

#[test]
fn clone_runs_child_on_supplied_stack() {
    // Child stack: a generous heap buffer; clone() aligns the top for us.
    const STACK_SIZE: usize = 64 * 1024;
    let mut stack = vec![0u8; STACK_SIZE];
    let stack_top = unsafe { stack.as_mut_ptr().add(STACK_SIZE) } as *mut c_void;

    // Pipe so the child can prove it ran (CLONE_VM shares memory, but a pipe is
    // the most robust cross-"thread" signal and also exercises sys::write).
    let mut fds = [0i32; 2];
    unsafe { sys::pipe2(fds.as_mut_ptr(), 0) }.expect("pipe2");

    let flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_UNTRACED | SIGCHLD;
    let tid = unsafe {
        chorus_syscall::clone(
            child_entry,
            stack_top,
            flags,
            fds[1] as usize as *mut c_void,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    let tid = chorus_syscall::from_ret(tid).expect("clone failed");
    assert!(
        tid > 0,
        "parent should receive positive child tid, got {tid}"
    );

    // Read the sentinel the child wrote.
    let mut buf = [0u8; 1];
    let n = unsafe { sys::read(fds[0], buf.as_mut_ptr() as *mut c_void, 1) }.expect("read");
    assert_eq!(n, 1);
    assert_eq!(buf[0], 0xA5, "child did not run fn(arg)");

    // Reap the child and check its exit status == fn's return value (7).
    let mut status: i32 = 0;
    let __wall = 0x4000_0000; // __WALL
    let r = unsafe { sys::wait4(tid as i32, &mut status, __wall, ptr::null_mut()) };
    let waited = r.expect("wait4");
    assert_eq!(waited as i32, tid as i32);
    // WIFEXITED && WEXITSTATUS == 7
    assert_eq!(
        status & 0x7f,
        0,
        "child should exit normally, status={status:#x}"
    );
    assert_eq!((status >> 8) & 0xff, 7, "child exit code should be 7");

    sys::close(fds[0]).unwrap();
    sys::close(fds[1]).unwrap();
    drop(stack);
}

/// Guard: clone must reject a null fn / null stack with -EINVAL, exactly as the
/// C wrapper's leading `testq` checks do.
#[test]
fn clone_rejects_null_stack() {
    static DUMMY: AtomicI32 = AtomicI32::new(0);
    extern "C" fn noop(_: *mut c_void) -> i32 {
        DUMMY.store(1, Ordering::SeqCst);
        0
    }
    let flags = CLONE_VM | CLONE_FS | CLONE_FILES | SIGCHLD;
    let ret = unsafe {
        chorus_syscall::clone(
            noop,
            ptr::null_mut(), // null stack -> -EINVAL, child never runs
            flags,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    let res = chorus_syscall::from_ret(ret);
    assert_eq!(res, Err(EINVAL), "null stack should yield -EINVAL");
    assert_eq!(DUMMY.load(Ordering::SeqCst), 0, "child must not have run");
}
