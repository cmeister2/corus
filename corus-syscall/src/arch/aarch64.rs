//! aarch64 raw syscall primitives.
//!
//! Port of the `__aarch64__` `__asm__` blocks in `linux_syscall_support.h`. The
//! Linux aarch64 syscall convention:
//!   - syscall number in `x8`
//!   - args in `x0, x1, x2, x3, x4, x5`
//!   - the `svc #0` instruction performs the call
//!   - return value in `x0`; errors are returned as `-errno` in `-4095..=-1`
//!
//! Unlike x86_64 there is no scratch-register clobber dance (`svc` does not
//! clobber arg registers the way `syscall` clobbers `rcx`/`r11`). aarch64 also
//! uses the generic syscall table (`asm-generic/unistd.h`), which omits several
//! "legacy" numbers x86_64 still has (`open`, `stat`, `fork`, `poll`,
//! `getdents`, `readlink`); the typed wrappers in `sys.rs` route those to the
//! `*at`/`clone`/`ppoll`/`getdents64` equivalents on this arch.

use core::arch::asm;

/// Conservative ELF segment alignment / page-size fallback for aarch64.
///
/// aarch64 kernels ship 4K, 16K, or 64K base pages, so unlike x86_64 this is
/// **not** the authoritative page size. The dump path must source the real
/// page size from `AT_PAGESZ` in the captured auxv; this constant is only a
/// fallback / buffer-sizing value and is deliberately the largest common page
/// (64K) so any buffer sized by it is large enough on every aarch64 kernel.
pub const PAGE_SIZE: usize = 65536;

/// Raw syscall with no arguments.
///
/// # Safety
/// The caller must ensure `n` is a valid syscall number and that invoking it
/// with zero arguments is well-defined. Syscalls can have arbitrary side
/// effects on process state.
#[inline]
pub unsafe fn syscall0(n: usize) -> usize {
    let ret: usize;
    unsafe {
        asm!(
            "svc #0",
            in("x8") n,
            out("x0") ret,
            options(nostack, preserves_flags),
        );
    }
    ret
}

/// Raw syscall with one argument.
///
/// # Safety
/// See [`syscall0`]. The argument must be valid for the given syscall.
#[inline]
pub unsafe fn syscall1(n: usize, a1: usize) -> usize {
    let ret: usize;
    unsafe {
        asm!(
            "svc #0",
            in("x8") n,
            inlateout("x0") a1 => ret,
            options(nostack, preserves_flags),
        );
    }
    ret
}

/// Raw syscall with two arguments.
///
/// # Safety
/// See [`syscall0`]. Arguments must be valid for the given syscall.
#[inline]
pub unsafe fn syscall2(n: usize, a1: usize, a2: usize) -> usize {
    let ret: usize;
    unsafe {
        asm!(
            "svc #0",
            in("x8") n,
            inlateout("x0") a1 => ret,
            in("x1") a2,
            options(nostack, preserves_flags),
        );
    }
    ret
}

/// Raw syscall with three arguments.
///
/// # Safety
/// See [`syscall0`]. Arguments must be valid for the given syscall.
#[inline]
pub unsafe fn syscall3(n: usize, a1: usize, a2: usize, a3: usize) -> usize {
    let ret: usize;
    unsafe {
        asm!(
            "svc #0",
            in("x8") n,
            inlateout("x0") a1 => ret,
            in("x1") a2,
            in("x2") a3,
            options(nostack, preserves_flags),
        );
    }
    ret
}

/// Raw syscall with four arguments.
///
/// # Safety
/// See [`syscall0`]. Arguments must be valid for the given syscall.
#[inline]
pub unsafe fn syscall4(n: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> usize {
    let ret: usize;
    unsafe {
        asm!(
            "svc #0",
            in("x8") n,
            inlateout("x0") a1 => ret,
            in("x1") a2,
            in("x2") a3,
            in("x3") a4,
            options(nostack, preserves_flags),
        );
    }
    ret
}

/// Raw syscall with five arguments.
///
/// # Safety
/// See [`syscall0`]. Arguments must be valid for the given syscall.
#[inline]
pub unsafe fn syscall5(n: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> usize {
    let ret: usize;
    unsafe {
        asm!(
            "svc #0",
            in("x8") n,
            inlateout("x0") a1 => ret,
            in("x1") a2,
            in("x2") a3,
            in("x3") a4,
            in("x4") a5,
            options(nostack, preserves_flags),
        );
    }
    ret
}

/// Raw syscall with six arguments.
///
/// # Safety
/// See [`syscall0`]. Arguments must be valid for the given syscall.
#[inline]
pub unsafe fn syscall6(
    n: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> usize {
    let ret: usize;
    unsafe {
        asm!(
            "svc #0",
            in("x8") n,
            inlateout("x0") a1 => ret,
            in("x1") a2,
            in("x2") a3,
            in("x3") a4,
            in("x4") a5,
            in("x5") a6,
            options(nostack, preserves_flags),
        );
    }
    ret
}

/// Syscall numbers for aarch64 (the generic `asm-generic/unistd.h` table).
///
/// Only the subset reachable from the dump path is enumerated, mirroring the
/// x86_64 `nr` module. Names match the x86_64 module so `sys.rs` can refer to
/// `nr::READ` etc. uniformly; where aarch64 lacks a legacy call, the closest
/// generic equivalent is provided under the legacy name's role and the typed
/// wrapper adapts arguments (e.g. `OPENAT` is used to implement `open`).
pub mod nr {
    /// aarch64 syscall number `read(2)`.
    pub const READ: usize = 63;
    /// aarch64 syscall number `write(2)`.
    pub const WRITE: usize = 64;
    /// aarch64 syscall number `openat(2)` (no legacy `open`).
    pub const OPENAT: usize = 56;
    /// aarch64 syscall number `close(2)`.
    pub const CLOSE: usize = 57;
    /// aarch64 syscall number `newfstatat(2)` (no legacy `stat`).
    pub const NEWFSTATAT: usize = 79;
    /// aarch64 syscall number `fstat(2)`.
    pub const FSTAT: usize = 80;
    /// aarch64 syscall number `ppoll(2)` (no legacy `poll`).
    pub const PPOLL: usize = 73;
    /// aarch64 syscall number `lseek(2)`.
    pub const LSEEK: usize = 62;
    /// aarch64 syscall number `mmap(2)`.
    pub const MMAP: usize = 222;
    /// aarch64 syscall number `munmap(2)`.
    pub const MUNMAP: usize = 215;
    /// aarch64 syscall number `rt_sigaction(2)`.
    pub const RT_SIGACTION: usize = 134;
    /// aarch64 syscall number `rt_sigprocmask(2)`.
    pub const RT_SIGPROCMASK: usize = 135;
    /// aarch64 syscall number `socket(2)`.
    pub const SOCKET: usize = 198;
    /// aarch64 syscall number `socketpair(2)`.
    pub const SOCKETPAIR: usize = 199;
    /// aarch64 syscall number `sendmsg(2)`.
    pub const SENDMSG: usize = 211;
    /// aarch64 syscall number `recvmsg(2)`.
    pub const RECVMSG: usize = 212;
    /// aarch64 syscall number `shutdown(2)`.
    pub const SHUTDOWN: usize = 210;
    /// aarch64 syscall number `clone(2)`.
    pub const CLONE: usize = 220;
    /// aarch64 syscall number `execve(2)`.
    pub const EXECVE: usize = 221;
    /// aarch64 syscall number `exit(2)`.
    pub const EXIT: usize = 93;
    /// aarch64 syscall number `exit_group(2)`.
    pub const EXIT_GROUP: usize = 94;
    /// aarch64 syscall number `wait4(2)`.
    pub const WAIT4: usize = 260;
    /// aarch64 syscall number `kill(2)`.
    pub const KILL: usize = 129;
    /// aarch64 syscall number `tkill(2)`.
    pub const TKILL: usize = 130;
    /// aarch64 syscall number `fcntl(2)`.
    pub const FCNTL: usize = 25;
    /// aarch64 syscall number `readlinkat(2)` (no legacy `readlink`).
    pub const READLINKAT: usize = 78;
    /// aarch64 syscall number `ptrace(2)`.
    pub const PTRACE: usize = 117;
    /// aarch64 syscall number `getppid(2)`.
    pub const GETPPID: usize = 173;
    /// aarch64 syscall number `getpgid(2)` (no legacy `getpgrp`).
    pub const GETPGID: usize = 155;
    /// aarch64 syscall number `getsid(2)`.
    pub const GETSID: usize = 156;
    /// aarch64 syscall number `getpid(2)`.
    pub const GETPID: usize = 172;
    /// aarch64 syscall number `gettid(2)`.
    pub const GETTID: usize = 178;
    /// aarch64 syscall number `sigaltstack(2)`.
    pub const SIGALTSTACK: usize = 132;
    /// aarch64 syscall number `getpriority(2)`.
    pub const GETPRIORITY: usize = 141;
    /// aarch64 syscall number `prctl(2)`.
    pub const PRCTL: usize = 167;
    /// aarch64 syscall number `pipe2(2)`.
    pub const PIPE2: usize = 59;
    /// aarch64 syscall number `geteuid(2)`.
    pub const GETEUID: usize = 175;
    /// aarch64 syscall number `getegid(2)`.
    pub const GETEGID: usize = 177;
    /// aarch64 syscall number `dup(2)`.
    pub const DUP: usize = 23;
    /// aarch64 syscall number `dup3(2)`.
    pub const DUP3: usize = 24;
    /// aarch64 syscall number `getdents64(2)` (no legacy `getdents`).
    pub const GETDENTS64: usize = 61;
    /// aarch64 syscall number `sched_yield(2)`.
    pub const SCHED_YIELD: usize = 124;
}

/// Port of `LSS_NAME(clone)` for aarch64 (`linux_syscall_support.h`).
///
/// Issues a raw `clone(2)`, then - *in the child* - calls `fn(arg)` and
/// terminates via `exit(2)` with `fn`'s return value. The child **never**
/// returns from this function; only the parent does, receiving the child tid
/// (or `-errno`).
///
/// Note the aarch64 kernel `clone` argument order is
/// `(flags, child_stack, parent_tidptr, newtls, child_tidptr)` - `flags` first,
/// unlike the x86_64 register layout. The two-words-onto-child-stack dance
/// (`fn` then `arg`) and 16-byte stack alignment exactly mirror the C asm.
///
/// # Safety
/// - `child_stack` must point to the *top* of a writable, suitably sized region
///   the child can use as a stack.
/// - `fn` must be a valid function pointer; under `CLONE_VM` the child shares
///   the caller's address space, so it must be async-signal-safe and must not
///   touch the parent's live stack.
/// - `parent_tidptr`/`child_tidptr`/`newtls` must be null or valid per `flags`.
#[inline]
pub unsafe fn clone(
    func: extern "C" fn(*mut core::ffi::c_void) -> i32,
    child_stack: *mut core::ffi::c_void,
    flags: usize,
    arg: *mut core::ffi::c_void,
    parent_tidptr: *mut i32,
    newtls: *mut core::ffi::c_void,
    child_tidptr: *mut i32,
) -> usize {
    // Null-guard mirroring the C/x86_64 wrappers: a null child stack is rejected
    // with -EINVAL rather than handed to the kernel (which would otherwise reject
    // it inconsistently). `func` is an `extern "C" fn`, which is non-nullable in
    // Rust, so only the stack needs checking.
    if child_stack.is_null() {
        return -(crate::linux::EINVAL as isize) as usize;
    }

    let res: usize;
    // SAFETY: this mirrors the well-tested C `clone` wrapper. We hand the kernel
    // its argument registers (x0..x4) and pre-push fn/arg onto the child stack;
    // the child path never touches the parent's stack.
    //
    // fn/arg are pinned to fixed caller-saved registers (x9/x10) rather than
    // `in(reg)`: with `in(reg)` the compiler could allocate them onto x2/x3/x4,
    // which are *also* explicit kernel-argument registers here, so the `stp`
    // would read a register the kernel-arg setup had already overwritten,
    // producing garbage args and a spurious -EINVAL from clone(2). x9/x10 are
    // outside the syscall ABI registers (x0..x8), so no aliasing is possible.
    unsafe {
        asm!(
            // Push "arg" (high) and "fn" (low) onto the child stack with
            // writeback, so x1 (the child_stack the kernel hands to the child as
            // its sp) is decremented to point exactly at the stored pair:
            //   stp fn, arg, [x1, #-16]!  => x1 -= 16.
            // This must operate on x1 itself (not a scratch copy), or the child's
            // sp and the location of fn/arg would diverge.
            "stp x9, x10, [x1, #-16]!",
            // x0=flags, x1=child_stack, x2=ptid, x3=tls, x4=ctid; x8=__NR_clone.
            "mov x8, {nr_clone}",
            "svc #0",
            // Parent (x0 != 0) branches to done; child falls through.
            "cbnz x0, 2f",
            // --- child ---
            "ldp x1, x0, [sp], #16",   // x1 = fn, x0 = arg
            "blr x1",                  // fn(arg)
            "mov x8, {nr_exit}",       // exit(fn_ret); fn_ret already in x0
            "svc #0",
            // --- done (parent) ---
            "2:",
            nr_clone = const CLONE_NR,
            nr_exit = const EXIT_NR,
            in("x9") func,
            in("x10") arg,
            inlateout("x0") flags => res,
            inout("x1") child_stack => _,
            in("x2") parent_tidptr,
            in("x3") newtls,
            in("x4") child_tidptr,
            out("x8") _,
            options(nostack),
        );
    }
    res
}

// `const` operands to asm! must be integer paths; alias the nr constants.
/// `clone(2)` syscall number exposed as an asm const operand.
const CLONE_NR: usize = nr::CLONE;
/// `exit(2)` syscall number exposed as an asm const operand.
const EXIT_NR: usize = nr::EXIT;

// aarch64 does not use SA_RESTORER: the kernel supplies the signal-return
// trampoline, so there is no `restore_rt` to ship (unlike x86_64). The
// crash-cleanup sigaction install path must therefore not set SA_RESTORER on
// this arch.

/// Snapshot the *caller's* CPU registers into a `user_regs_struct`-layout
/// buffer (the `FRAME()` macro port), so the dumping thread's recorded
/// registers reflect the API call site rather than wherever it parks (in
/// `wait4`) during the dump.
///
/// `out` must point at the aarch64 `Regs` layout (see corus-core's `elf::Regs`):
/// the GP registers `x0..x30` occupy indices `0..=30` (`regs[N] = xN`), then
/// `sp` (index 31), `pc` (index 32), and `pstate` (index 33) - 34 `u64` slots
/// total.
///
/// `pc` is set to this function's return address (the caller's next
/// instruction) and `sp` to the caller's stack pointer, so debugger unwinding
/// of the dumped thread starts in the *caller* (e.g. `WriteCoreDump`), exactly
/// as the C macro arranges. `pstate` is left zero (the caller fills the
/// ptrace-captured regs, as the C `SET_FRAME` does).
///
/// A naked function runs no prologue: on entry `x30` (LR) holds the return
/// address and `sp` is the caller's stack pointer. `x0` holds `out` (AAPCS
/// first arg).
///
/// # Safety
/// `out` must point to at least 34 writable `u64` slots (a `Regs`).
#[unsafe(naked)]
pub unsafe extern "C" fn capture_frame(out: *mut u64) {
    core::arch::naked_asm!(
        // x0 = out. Use x0 *itself* as the base register for every store, so no
        // original register is destroyed before its slot is written. (Picking a
        // separate scratch base, e.g. `mov x9, x0`, would lose the original x9
        // before regs[9] is stored.) For a store the base register's value is
        // read only for the address and never modified, so `stp x0, x1, [x0]`
        // is well-defined; and x0 at entry holds the `out` pointer, which is the
        // caller-visible value of x0, so regs[0]=x0 is correct.
        "stp x0,  x1,  [x0, #0]", // regs[0]=x0, regs[1]=x1
        "stp x2,  x3,  [x0, #16]",
        "stp x4,  x5,  [x0, #32]",
        "stp x6,  x7,  [x0, #48]",
        "stp x8,  x9,  [x0, #64]", // regs[8]=x8, regs[9]=x9
        "stp x10, x11, [x0, #80]",
        "stp x12, x13, [x0, #96]",
        "stp x14, x15, [x0, #112]",
        "stp x16, x17, [x0, #128]",
        "stp x18, x19, [x0, #144]",
        "stp x20, x21, [x0, #160]",
        "stp x22, x23, [x0, #176]",
        "stp x24, x25, [x0, #192]",
        "stp x26, x27, [x0, #208]",
        "stp x28, x29, [x0, #224]", // regs[28]=x28, regs[29]=x29 (fp)
        "str x30, [x0, #240]",      // regs[30]=x30 (lr)
        // sp (index 31, #248) = caller's sp (no prologue ran). x9 is already
        // saved (regs[9] at #64), so it is free to reuse as scratch.
        "mov x9, sp",
        "str x9, [x0, #248]",
        // pc (index 32, #256) = return address = x30 (lr).
        "str x30, [x0, #256]",
        // pstate (index 33, #264) left as caller-zeroed; nothing to store.
        "ret",
    )
}

// --- ptrace register capture (arch-specific request shape) -------------------
//
// aarch64 has no PTRACE_GETREGS/GETFPREGS. It uses PTRACE_GETREGSET with an
// iovec and a note-type selector in the `addr` argument: NT_PRSTATUS for the
// GP register set, NT_FPREGSET for the FP/SIMD set. The kernel writes the
// actual byte count back into iov_len.

/// `PTRACE_GETREGSET` request number.
const PTRACE_GETREGSET: usize = 0x4204;
/// `NT_PRSTATUS` note type (selects the GP register set).
const NT_PRSTATUS: usize = 1;
/// `NT_FPREGSET` note type (selects the FP/SIMD register set).
const NT_FPREGSET: usize = 2;

/// Kernel `struct iovec` for `PTRACE_GETREGSET`.
#[repr(C)]
struct Iovec {
    /// Base of the output buffer.
    iov_base: *mut core::ffi::c_void,
    /// Length in bytes; the kernel writes back the count it filled.
    iov_len: usize,
}

/// Fill `out` (a `Regs`-shaped buffer of `out_len` bytes) with the stopped
/// tracee's general-purpose registers via `PTRACE_GETREGSET`+`NT_PRSTATUS`.
///
/// Unlike x86_64's `GETREGS`, `GETREGSET` needs the buffer capacity up front
/// (in the iovec), hence the explicit `out_len` - on x86_64 the analogous
/// function ignores it.
///
/// # Errors
/// Returns the kernel errno if the ptrace request fails.
///
/// # Safety
/// `out` must be valid for writes of `out_len` bytes (the caller's `Regs`).
/// The tracee must be ptrace-stopped.
#[inline]
pub unsafe fn ptrace_get_gpregs(
    pid: i32,
    out: *mut core::ffi::c_void,
    out_len: usize,
) -> Result<usize, i32> {
    unsafe { ptrace_getregset(pid, NT_PRSTATUS, out, out_len) }
}

/// Fill `out` (an `FpRegs`-shaped buffer of `out_len` bytes) with the stopped
/// tracee's FP/SIMD registers via `PTRACE_GETREGSET`+`NT_FPREGSET`.
///
/// # Errors
/// Returns the kernel errno if the ptrace request fails.
///
/// # Safety
/// `out` must be valid for writes of `out_len` bytes (the caller's `FpRegs`).
/// The tracee must be stopped.
#[inline]
pub unsafe fn ptrace_get_fpregs(
    pid: i32,
    out: *mut core::ffi::c_void,
    out_len: usize,
) -> Result<usize, i32> {
    unsafe { ptrace_getregset(pid, NT_FPREGSET, out, out_len) }
}

/// Shared `PTRACE_GETREGSET` helper: build the iovec and issue the call.
///
/// `ptrace(PTRACE_GETREGSET, pid, addr = note_type, data = &iov)`. The kernel
/// writes the filled byte count back into `iov.iov_len`; callers that need to
/// detect a short fill can compare it, but the typed wrappers treat any success
/// as sufficient (the register structs are sized from the kernel ABI).
///
/// # Safety
/// `out` must be valid for writes of `out_len` bytes; the tracee must be
/// ptrace-stopped.
#[inline]
unsafe fn ptrace_getregset(
    pid: i32,
    note_type: usize,
    out: *mut core::ffi::c_void,
    out_len: usize,
) -> Result<usize, i32> {
    let mut iov = Iovec {
        iov_base: out,
        iov_len: out_len,
    };
    crate::from_ret(unsafe {
        syscall4(
            nr::PTRACE,
            PTRACE_GETREGSET,
            pid as usize,
            note_type,
            &mut iov as *mut Iovec as usize,
        )
    })
}
