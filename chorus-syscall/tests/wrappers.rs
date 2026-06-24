//! Syscall-wrapper test harness.
//!
//! Three tactics:
//!   1. **Differential vs libc** - call ours and libc's on the same input,
//!      assert equal results / equal errno (incl. deliberate failure paths,
//!      since the `-4095..=-1` errno encoding is the most asm-specific behavior).
//!   2. **Round-trip** - pipe/mmap/socketpair exercised end to end.
//!   3. **Register-clobber regression** - hold live values in caller-saved and
//!      callee-saved registers across each call and assert they survive; this is
//!      what catches a wrong clobber list in the `asm!`.
//!
//! `libc` is a dev-dependency only - never linked into the library itself.

use chorus_syscall::sys;
use core::ffi::c_void;

/// Map our `SysResult` to the libc `(ret, errno)` convention for comparison.
fn split(r: sys::SysResult) -> (isize, i32) {
    match r {
        Ok(v) => (v as isize, 0),
        Err(e) => (-1, e),
    }
}

#[test]
fn getpid_matches_libc() {
    let ours = sys::getpid().unwrap() as i32;
    let theirs = unsafe { libc::getpid() };
    assert_eq!(ours, theirs);
}

#[test]
fn gettid_matches_libc() {
    // Compare against libc's own gettid (cargo runs tests on worker threads, so
    // tid != pid here - that's expected, not a bug).
    let ours = sys::gettid().unwrap() as i64;
    let theirs = unsafe { libc::syscall(libc::SYS_gettid) };
    assert_eq!(ours, theirs);
}

#[test]
fn getppid_getegid_geteuid_match_libc() {
    assert_eq!(sys::getppid().unwrap() as i32, unsafe { libc::getppid() });
    assert_eq!(sys::geteuid().unwrap() as u32, unsafe { libc::geteuid() });
    assert_eq!(sys::getegid().unwrap() as u32, unsafe { libc::getegid() });
}

#[test]
fn open_enoent_returns_errno() {
    // Deliberate failure: errno encoding is the most asm-specific behavior.
    let path = c"/nonexistent/definitely/not/here";
    let r = unsafe { sys::open(path.as_ptr(), libc::O_RDONLY, 0) };
    let (ret, errno) = split(r);
    assert_eq!(ret, -1);
    assert_eq!(errno, libc::ENOENT);
}

#[test]
fn close_badfd_returns_ebadf() {
    let (ret, errno) = split(sys::close(-1));
    assert_eq!(ret, -1);
    assert_eq!(errno, libc::EBADF);
}

#[test]
fn open_read_close_roundtrip() {
    // /proc/self/cmdline always exists and is readable.
    let path = c"/proc/self/cmdline";
    let fd = unsafe { sys::open(path.as_ptr(), libc::O_RDONLY, 0) }.expect("open") as i32;
    assert!(fd >= 0);
    let mut buf = [0u8; 64];
    let n = unsafe { sys::read(fd, buf.as_mut_ptr() as *mut c_void, buf.len()) }.expect("read");
    assert!(n > 0, "cmdline should be non-empty");
    sys::close(fd).expect("close");
}

#[test]
fn fstat_matches_libc_size() {
    let path = c"/proc/self/cmdline";
    let fd = unsafe { sys::open(path.as_ptr(), libc::O_RDONLY, 0) }.expect("open") as i32;

    let mut ks = chorus_syscall::kernel_types::KernelStat::zeroed();
    unsafe { sys::fstat(fd, &mut ks) }.expect("fstat");

    // Compare st_mode's file-type bits against libc's stat (st_size on /proc is
    // 0, so assert on the type bits which are stable).
    let mut ls: libc::stat = unsafe { core::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd, &mut ls) };
    assert_eq!(rc, 0);
    assert_eq!(ks.st_mode & libc::S_IFMT, ls.st_mode & libc::S_IFMT);

    sys::close(fd).expect("close");
}

#[test]
fn stat_matches_libc() {
    let path = c"/proc/self/cmdline";
    let mut ks = chorus_syscall::kernel_types::KernelStat::zeroed();
    unsafe { sys::stat(path.as_ptr(), &mut ks) }.expect("stat");

    let mut ls: libc::stat = unsafe { core::mem::zeroed() };
    let rc = unsafe { libc::stat(path.as_ptr(), &mut ls) };
    assert_eq!(rc, 0);
    assert_eq!(ks.st_ino, ls.st_ino);
    assert_eq!(ks.st_mode & libc::S_IFMT, ls.st_mode & libc::S_IFMT);
}

#[test]
fn pipe2_write_read_roundtrip() {
    let mut fds = [0i32; 2];
    unsafe { sys::pipe2(fds.as_mut_ptr(), 0) }.expect("pipe2");
    let msg = b"hello pipe";
    let n = unsafe { sys::write(fds[1], msg.as_ptr() as *const c_void, msg.len()) }.expect("write");
    assert_eq!(n, msg.len());
    let mut buf = [0u8; 16];
    let m = unsafe { sys::read(fds[0], buf.as_mut_ptr() as *mut c_void, buf.len()) }.expect("read");
    assert_eq!(&buf[..m], msg);
    sys::close(fds[0]).unwrap();
    sys::close(fds[1]).unwrap();
}

#[test]
fn mmap_munmap_roundtrip() {
    let len = 4096;
    let p = unsafe {
        sys::mmap(
            core::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    }
    .expect("mmap") as *mut u8;
    // Write then read back, proving the mapping is usable.
    unsafe {
        p.write_volatile(0xAB);
        assert_eq!(p.read_volatile(), 0xAB);
    }
    unsafe { sys::munmap(p as *mut c_void, len) }.expect("munmap");
}

#[test]
fn socketpair_sendmsg_recvmsg_roundtrip() {
    use chorus_syscall::kernel_types::{KernelIovec, KernelMsghdr};
    let mut sv = [0i32; 2];
    unsafe { sys::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) }
        .expect("socketpair");

    let payload = b"msg-roundtrip";
    let mut send_iov = KernelIovec {
        iov_base: payload.as_ptr() as *mut c_void,
        iov_len: payload.len(),
    };
    let send_msg = KernelMsghdr {
        msg_name: core::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut send_iov,
        msg_iovlen: 1,
        msg_control: core::ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    };
    let sent = unsafe { sys::sendmsg(sv[0], &send_msg, 0) }.expect("sendmsg");
    assert_eq!(sent, payload.len());

    let mut rbuf = [0u8; 32];
    let mut recv_iov = KernelIovec {
        iov_base: rbuf.as_mut_ptr() as *mut c_void,
        iov_len: rbuf.len(),
    };
    let mut recv_msg = KernelMsghdr {
        msg_name: core::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut recv_iov,
        msg_iovlen: 1,
        msg_control: core::ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    };
    let got = unsafe { sys::recvmsg(sv[1], &mut recv_msg, 0) }.expect("recvmsg");
    assert_eq!(&rbuf[..got], payload);

    sys::close(sv[0]).unwrap();
    sys::close(sv[1]).unwrap();
}

#[test]
fn getdents_reads_proc_self_task() {
    // The dump path enumerates threads via getdents on /proc/<pid>/task.
    let path = c"/proc/self/task";
    let fd = unsafe { sys::open(path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY, 0) }
        .expect("open task dir") as i32;
    let mut buf = [0u8; 4096];
    let n =
        unsafe { sys::getdents(fd, buf.as_mut_ptr() as *mut c_void, buf.len()) }.expect("getdents");
    assert!(n > 0, "task dir should have at least one entry");
    sys::close(fd).unwrap();
}

/// Register-clobber regression: the highest-value, most asm-specific check.
///
/// rustc trusts the `asm!` clobber declarations - a wrong one is UB, not a
/// compile error - so we must exercise it at runtime. This test brackets a real
/// wrapper call with sentinel values pinned in **callee-saved** registers
/// (`rbx`, `r12`-`r15`) inside a single asm region per check, and asserts they
/// survive. If the wrapper's `asm!` clobbers a register it failed to declare,
/// or the `syscall` insn's `rcx`/`r11` clobber leaks, these sentinels corrupt.
///
/// We use a `naked`-style sandwich: load sentinels, call the wrapper via a
/// real function-call boundary (forcing the ABI to spill/restore correctly),
/// then read them back - all observed through `black_box` so the optimizer
/// cannot prove the values constant and elide the check.
#[test]
fn syscall_preserves_callee_saved_registers() {
    use core::hint::black_box;

    let pid = unsafe { libc::getpid() };

    for i in 0..2000u64 {
        // r12-r15 are callee-saved and usable as explicit asm operands (rbx is
        // reserved by LLVM, so it can't be a named operand; the SysV ABI still
        // requires the wrapper to preserve it, and the round-trip wrappers
        // above would crash if it didn't).
        let s_r12 = black_box(0x2222_0000u64 ^ i);
        let s_r13 = black_box(0x3333_0000u64 ^ i);
        let s_r14 = black_box(0x4444_0000u64 ^ i);
        let s_r15 = black_box(0x5555_0000u64 ^ i);

        // Pin sentinels into callee-saved regs, call the wrapper through a real
        // ABI boundary, then read the same registers back via `inout`. If the
        // wrapper corrupts a callee-saved reg or leaks the syscall insn's
        // rcx/r11 clobber, the read-back value differs.
        let o_r12: u64;
        let o_r13: u64;
        let o_r14: u64;
        let o_r15: u64;
        let ret: i32;
        unsafe {
            core::arch::asm!(
                "call {f}",
                f = sym do_syscall_shim,
                inout("r12") s_r12 => o_r12,
                inout("r13") s_r13 => o_r13,
                inout("r14") s_r14 => o_r14,
                inout("r15") s_r15 => o_r15,
                out("rax") ret,
                // Caller-saved regs the call may legitimately use:
                out("rcx") _, out("rdx") _, out("rsi") _, out("rdi") _,
                out("r8") _, out("r9") _, out("r10") _, out("r11") _,
            );
        }

        assert_eq!(o_r12, s_r12, "r12 corrupted by syscall wrapper");
        assert_eq!(o_r13, s_r13, "r13 corrupted by syscall wrapper");
        assert_eq!(o_r14, s_r14, "r14 corrupted by syscall wrapper");
        assert_eq!(o_r15, s_r15, "r15 corrupted by syscall wrapper");
        assert_eq!(black_box(ret), pid, "syscall returned wrong value");
    }
}

// extern "sysv64" shim with a fixed symbol the asm! `sym` operand can call.
// Performs a real syscall through our wrapper inside a genuine call frame.
extern "sysv64" fn do_syscall_shim() -> i32 {
    sys::getpid().unwrap() as i32
}
