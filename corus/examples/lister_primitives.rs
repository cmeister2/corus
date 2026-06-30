//! Lister-primitive smoke test: exercises each raw building block the thread
//! lister depends on, in isolation, with a non-zero exit on failure.
//!
//! The live dump path collapses any lister-internal failure into a single
//! coarse `ThreadList` errno by the time it reaches the public API, which makes
//! a broken primitive hard to localize - especially across architectures, where
//! a wrong syscall number, struct layout, or `O_*`/page-size constant silently
//! breaks one step. This binary checks each primitive directly and prints a
//! structured pass/fail line per step, so a regression points straight at the
//! culprit instead of an opaque dump failure.
//!
//! It is arch-neutral and runs as a fast gate before the full test suite on
//! every supported architecture (see the CI `*-primitives` step). Anything that
//! passes on x86_64 but fails on another arch is a port bug in that primitive.
//!
//! Run with:  cargo run -p corus --example lister_primitives
//! Exit code: 0 if all steps pass, 1 otherwise.
//!
//! Steps:
//!   1. clone(CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_UNTRACED) - the lister's exact
//!      flags - and confirm the child runs `fn(arg)` and its exit code is
//!      reaped intact (this is where a bad clone wrapper shows up).
//!   2. getdents64 over /proc/self/task and parse entries via KernelDirent,
//!      confirming the dirent layout yields valid numeric tids (this is where a
//!      wrong d_name offset shows up).
//!   3. ptrace ATTACH + wait + PEEKDATA + DETACH against a freshly cloned
//!      sibling that shares our VM, confirming the cross-thread ptrace dance
//!      works (this is where a ptrace request/arg problem shows up).

// This is a standalone smoke-test binary, not part of the public API; the
// crate's `missing_docs`/private-item-docs denials don't add value for its
// internal helpers.
#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]

use core::ffi::{c_int, c_void};
use core::ptr;

use corus_core::corus_syscall as syscall;
use syscall::kernel_types::KernelDirent;
use syscall::linux::{EINTR, O_DIRECTORY, O_RDONLY};
use syscall::sys;

// The lister's clone flags (see corus-core threads.rs).
const CLONE_VM: usize = 0x0000_0100;
const CLONE_FS: usize = 0x0000_0200;
const CLONE_FILES: usize = 0x0000_0400;
const CLONE_UNTRACED: usize = 0x0080_0000;
const WALL: c_int = 0x4000_0000;

// ptrace request numbers (arch-independent).
const PTRACE_ATTACH: c_int = 16;
const PTRACE_PEEKDATA: c_int = 2;
const PTRACE_DETACH: c_int = 17;

/// Shared block between this process and the cloned children (CLONE_VM).
#[repr(C)]
struct Shared {
    /// Set by the child to prove `fn(arg)` ran in the child context.
    ran: c_int,
    /// The child writes its own tid here (via gettid) for the ptrace step.
    child_tid: c_int,
    /// A sentinel word the parent PEEKDATAs out of the child.
    sentinel: u64,
    /// Set non-zero by the child to ask it to spin until the parent clears it.
    hold: c_int,
}

/// clone child for step 1: record that we ran, then exit with code 7.
extern "C" fn step1_child(arg: *mut c_void) -> i32 {
    let sh = unsafe { &mut *(arg as *mut Shared) };
    sh.ran = 1;
    7
}

/// clone child for step 3: publish tid, then spin while `hold` is set so the
/// parent can ptrace-attach and PEEKDATA a known sentinel.
extern "C" fn step3_child(arg: *mut c_void) -> i32 {
    let sh = unsafe { &mut *(arg as *mut Shared) };
    sh.child_tid = sys::gettid().map(|t| t as c_int).unwrap_or(-1);
    // Spin until the parent clears `hold`. Volatile so it isn't optimized out.
    while unsafe { ptr::read_volatile(&sh.hold) } != 0 {
        core::hint::spin_loop();
    }
    0
}

fn report(step: &str, ok: bool, detail: &str) {
    let tag = if ok { "PASS" } else { "FAIL" };
    println!("[lister-primitives] {tag:4} {step:28} {detail}");
}

/// Allocate a child stack via mmap and return (base, top-aligned).
fn alloc_stack(size: usize) -> (*mut u8, *mut c_void) {
    // 9 = PROT_READ|PROT_WRITE; MAP_PRIVATE|MAP_ANONYMOUS = 0x22.
    let base = unsafe { sys::mmap(ptr::null_mut(), size, 3, 0x22, -1, 0) }.expect("mmap stack");
    let base = base as *mut u8;
    let top = unsafe { base.add(size) } as *mut c_void;
    (base, top)
}

fn main() {
    println!("[lister-primitives] arch = {}", std::env::consts::ARCH);
    let mut failures = 0;

    // --- Step 1: clone runs the child and we reap its exit code -------------
    {
        let mut sh = Shared {
            ran: 0,
            child_tid: 0,
            sentinel: 0,
            hold: 0,
        };
        let (_, top) = alloc_stack(128 * 1024);
        let flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_UNTRACED;
        let ret = unsafe {
            syscall::clone(
                step1_child,
                top,
                flags,
                &mut sh as *mut Shared as *mut c_void,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        match syscall::from_ret(ret) {
            Err(e) => {
                report("clone(CLONE_VM)", false, &format!("clone failed errno={e}"));
                failures += 1;
            }
            Ok(pid) => {
                let pid = pid as c_int;
                let mut status: c_int = 0;
                let wr = loop {
                    match unsafe { sys::wait4(pid, &mut status, WALL, ptr::null_mut()) } {
                        Err(EINTR) => continue,
                        other => break other,
                    }
                };
                match wr {
                    Err(e) => {
                        report("clone(CLONE_VM)", false, &format!("wait4 errno={e}"));
                        failures += 1;
                    }
                    Ok(_) => {
                        let exited = status & 0x7f == 0;
                        let code = (status >> 8) & 0xff;
                        let ok = exited && code == 7 && sh.ran == 1;
                        report(
                            "clone(CLONE_VM)",
                            ok,
                            &format!(
                                "ran={} exited={} code={} (want ran=1 code=7)",
                                sh.ran, exited, code
                            ),
                        );
                        if !ok {
                            failures += 1;
                        }
                    }
                }
            }
        }
    }

    // --- Step 2: getdents64 over /proc/self/task parses to numeric tids -----
    {
        let path = c"/proc/self/task";
        match unsafe { sys::open(path.as_ptr(), O_RDONLY | O_DIRECTORY, 0) } {
            Err(e) => {
                report(
                    "getdents(/proc/self/task)",
                    false,
                    &format!("open errno={e}"),
                );
                failures += 1;
            }
            Ok(fd) => {
                let fd = fd as c_int;
                let mut buf = [0u8; 8192];
                let mut names = 0usize;
                let mut numeric = 0usize;
                let mut sample = [0u8; 32];
                let mut sample_len = 0usize;
                match unsafe { sys::getdents(fd, buf.as_mut_ptr() as *mut c_void, buf.len()) } {
                    Err(e) => {
                        report(
                            "getdents(/proc/self/task)",
                            false,
                            &format!("getdents errno={e}"),
                        );
                        failures += 1;
                    }
                    Ok(n) => {
                        let mut off = 0usize;
                        while off < n {
                            let d = unsafe { &*(buf.as_ptr().add(off) as *const KernelDirent) };
                            let reclen = d.d_reclen as usize;
                            if reclen == 0 {
                                break;
                            }
                            // Read the name up to the first NUL.
                            let name = &d.d_name;
                            let nlen = name.iter().position(|&b| b == 0).unwrap_or(name.len());
                            let nm = &name[..nlen];
                            if !nm.is_empty() {
                                names += 1;
                                if nm.iter().all(|b| b.is_ascii_digit()) {
                                    numeric += 1;
                                } else if nm != b"." && nm != b".." && sample_len == 0 {
                                    let k = nm.len().min(sample.len());
                                    sample[..k].copy_from_slice(&nm[..k]);
                                    sample_len = k;
                                }
                            }
                            off += reclen;
                        }
                        // /proc/self/task always has at least one numeric tid
                        // (this thread). "." and ".." are the only non-numeric
                        // entries expected; anything else means a bad d_name
                        // offset (garbled names).
                        let ok = numeric >= 1 && sample_len == 0;
                        let sample_str = String::from_utf8_lossy(&sample[..sample_len]);
                        report(
                            "getdents(/proc/self/task)",
                            ok,
                            &format!(
                                "entries={names} numeric_tids={numeric} unexpected_name={:?}",
                                sample_str
                            ),
                        );
                        if !ok {
                            failures += 1;
                        }
                    }
                }
                let _ = sys::close(fd);
            }
        }
    }

    // --- Step 3: ptrace ATTACH + PEEKDATA + DETACH on a CLONE_VM sibling -----
    {
        let mut sh = Shared {
            ran: 0,
            child_tid: 0,
            sentinel: 0xCAFE_F00D_1234_5678,
            hold: 1,
        };
        let (_, top) = alloc_stack(128 * 1024);
        let flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_UNTRACED;
        let ret = unsafe {
            syscall::clone(
                step3_child,
                top,
                flags,
                &mut sh as *mut Shared as *mut c_void,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        match syscall::from_ret(ret) {
            Err(e) => {
                report(
                    "ptrace(attach+peek)",
                    false,
                    &format!("clone failed errno={e}"),
                );
                failures += 1;
            }
            Ok(_) => {
                // Wait for the child to publish its tid.
                let mut spins = 0u64;
                while unsafe { ptr::read_volatile(&sh.child_tid) } == 0 && spins < 100_000_000 {
                    core::hint::spin_loop();
                    spins += 1;
                }
                let tid = sh.child_tid;
                if tid <= 0 {
                    report("ptrace(attach+peek)", false, "child never published tid");
                    failures += 1;
                } else {
                    let attach = unsafe {
                        sys::ptrace(PTRACE_ATTACH, tid, ptr::null_mut(), ptr::null_mut())
                    };
                    if let Err(e) = attach {
                        report("ptrace(attach+peek)", false, &format!("ATTACH errno={e}"));
                        failures += 1;
                        unsafe { ptr::write_volatile(&mut sh.hold, 0) };
                    } else {
                        // Reap the group-stop notification so the tracee is
                        // genuinely stopped before we PEEKDATA it. The child is
                        // still spinning (hold != 0) but ptrace-stopped.
                        let mut st: c_int = 0;
                        let _ = unsafe { sys::wait4(tid, &mut st, WALL, ptr::null_mut()) };
                        // PEEKDATA the sentinel word out of the shared VM while
                        // the tracee is stopped and alive. Linux's ptrace ABI
                        // returns the peeked word via the `data` pointer (here
                        // `out`), not the syscall return value - this mirrors the
                        // lister's `ptrace(PEEKDATA, pid, addr=&i, data=&j)`.
                        let want = sh.sentinel;
                        let mut out: u64 = 0;
                        let res = unsafe {
                            sys::ptrace(
                                PTRACE_PEEKDATA,
                                tid,
                                &sh.sentinel as *const u64 as *mut c_void,
                                &mut out as *mut u64 as *mut c_void,
                            )
                        };
                        let peek_ok = res.is_ok() && out == want;
                        let got = format!("res={res:?} out={out:#x}");
                        // Detach (resumes the tracee), then release the spin and
                        // reap it.
                        let _ = unsafe {
                            sys::ptrace(PTRACE_DETACH, tid, ptr::null_mut(), ptr::null_mut())
                        };
                        unsafe { ptr::write_volatile(&mut sh.hold, 0) };
                        let mut st2: c_int = 0;
                        let _ = unsafe { sys::wait4(tid, &mut st2, WALL, ptr::null_mut()) };
                        report(
                            "ptrace(attach+peek)",
                            peek_ok,
                            &format!("peek={got:?} want={want:#x}"),
                        );
                        if !peek_ok {
                            failures += 1;
                        }
                    }
                }
            }
        }
    }

    println!("[lister-primitives] {} failure(s)", failures);
    std::process::exit(if failures == 0 { 0 } else { 1 });
}
