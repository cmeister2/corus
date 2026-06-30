//! x86_64 raw syscall primitives.
//!
//! Port of the `__asm__` syscall blocks in `linux_syscall_support.h` for
//! `__x86_64__`. The Linux x86_64 syscall convention:
//!   - syscall number in `rax`
//!   - args in `rdi, rsi, rdx, r10, r8, r9` (note: `r10`, not `rcx`)
//!   - the `syscall` instruction clobbers `rcx` and `r11`
//!   - return value in `rax`; errors are returned as `-errno` in `-4095..=-1`
//!
//! These are the lowest-level building blocks. Higher-level typed `sys_*`
//! wrappers build on top and convert the raw return into
//! `Result<usize, Errno>`.

use core::arch::asm;

/// Linux x86_64 base page size used by this no-libc port.
pub const PAGE_SIZE: usize = 4096;

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
            "syscall",
            inlateout("rax") n => ret,
            lateout("rcx") _,
            lateout("r11") _,
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
            "syscall",
            inlateout("rax") n => ret,
            in("rdi") a1,
            lateout("rcx") _,
            lateout("r11") _,
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
            "syscall",
            inlateout("rax") n => ret,
            in("rdi") a1,
            in("rsi") a2,
            lateout("rcx") _,
            lateout("r11") _,
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
            "syscall",
            inlateout("rax") n => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            lateout("rcx") _,
            lateout("r11") _,
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
            "syscall",
            inlateout("rax") n => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            lateout("rcx") _,
            lateout("r11") _,
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
            "syscall",
            inlateout("rax") n => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            in("r8") a5,
            lateout("rcx") _,
            lateout("r11") _,
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
            "syscall",
            inlateout("rax") n => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            in("r8") a5,
            in("r9") a6,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    ret
}

/// Syscall numbers for x86_64. Only the subset needed by the dump path
/// The dump path syscall set is enumerated for v1; more are added as wrappers land.
pub mod nr {
    /// x86_64 syscall number for `read(2)`.
    pub const READ: usize = 0;
    /// x86_64 syscall number for `write(2)`.
    pub const WRITE: usize = 1;
    /// x86_64 syscall number for `open(2)`.
    pub const OPEN: usize = 2;
    /// x86_64 syscall number for `close(2)`.
    pub const CLOSE: usize = 3;
    /// x86_64 syscall number for `stat(2)`.
    pub const STAT: usize = 4;
    /// x86_64 syscall number for `fstat(2)`.
    pub const FSTAT: usize = 5;
    /// x86_64 syscall number for `poll(2)`.
    pub const POLL: usize = 7;
    /// x86_64 syscall number for `lseek(2)`.
    pub const LSEEK: usize = 8;
    /// x86_64 syscall number for `mmap(2)`.
    pub const MMAP: usize = 9;
    /// x86_64 syscall number for `munmap(2)`.
    pub const MUNMAP: usize = 11;
    /// x86_64 syscall number for `rt_sigaction(2)`.
    pub const RT_SIGACTION: usize = 13;
    /// x86_64 syscall number for `rt_sigprocmask(2)`.
    pub const RT_SIGPROCMASK: usize = 14;
    /// x86_64 syscall number for `pipe(2)`.
    pub const PIPE: usize = 22;
    /// x86_64 syscall number for `sched_yield(2)`.
    pub const SCHED_YIELD: usize = 24;
    /// x86_64 syscall number for `nanosleep(2)`.
    pub const NANOSLEEP: usize = 35;
    /// x86_64 syscall number for `getpid(2)`.
    pub const GETPID: usize = 39;
    /// x86_64 syscall number for `socket(2)`.
    pub const SOCKET: usize = 41;
    /// x86_64 syscall number for `sendmsg(2)`.
    pub const SENDMSG: usize = 46;
    /// x86_64 syscall number for `recvmsg(2)`.
    pub const RECVMSG: usize = 47;
    /// x86_64 syscall number for `shutdown(2)`.
    pub const SHUTDOWN: usize = 48;
    /// x86_64 syscall number for `socketpair(2)`.
    pub const SOCKETPAIR: usize = 53;
    /// x86_64 syscall number for `clone(2)`.
    pub const CLONE: usize = 56;
    /// x86_64 syscall number for `fork(2)`.
    pub const FORK: usize = 57;
    /// x86_64 syscall number for `execve(2)`.
    pub const EXECVE: usize = 59;
    /// x86_64 syscall number for `exit(2)`.
    pub const EXIT: usize = 60;
    /// x86_64 syscall number for `wait4(2)`.
    pub const WAIT4: usize = 61;
    /// x86_64 syscall number for `kill(2)`.
    pub const KILL: usize = 62;
    /// x86_64 syscall number for `tkill(2)`.
    pub const TKILL: usize = 200;
    /// x86_64 syscall number for `fcntl(2)`.
    pub const FCNTL: usize = 72;
    /// x86_64 syscall number for `readlink(2)`.
    pub const READLINK: usize = 89;
    /// x86_64 syscall number for `ptrace(2)`.
    pub const PTRACE: usize = 101;
    /// x86_64 syscall number for `getppid(2)`.
    pub const GETPPID: usize = 110;
    /// x86_64 syscall number for `getpgrp(2)`.
    pub const GETPGRP: usize = 111;
    /// x86_64 syscall number for `getsid(2)`.
    pub const GETSID: usize = 124;
    /// x86_64 syscall number for `sigaltstack(2)`.
    pub const SIGALTSTACK: usize = 131;
    /// x86_64 syscall number for `getpriority(2)`.
    pub const GETPRIORITY: usize = 140;
    /// x86_64 syscall number for `prctl(2)`.
    pub const PRCTL: usize = 157;
    /// x86_64 syscall number for `arch_prctl(2)`.
    pub const ARCH_PRCTL: usize = 158;
    /// x86_64 syscall number for `gettid(2)`.
    pub const GETTID: usize = 186;
    /// x86_64 syscall number for legacy `getdents(2)`, matching `KernelDirent`.
    pub const GETDENTS: usize = 78; // legacy getdents, matches KernelDirent layout
    /// x86_64 syscall number for `getdents64(2)`.
    pub const GETDENTS64: usize = 217;
    /// x86_64 syscall number for `exit_group(2)`.
    pub const EXIT_GROUP: usize = 231;
    /// x86_64 syscall number for `dup3(2)`.
    pub const DUP3: usize = 292;
    /// x86_64 syscall number for `pipe2(2)`.
    pub const PIPE2: usize = 293;
    /// x86_64 syscall number for `geteuid(2)`.
    pub const GETEUID: usize = 107;
    /// x86_64 syscall number for `getegid(2)`.
    pub const GETEGID: usize = 108;
    /// x86_64 syscall number for `dup(2)`.
    pub const DUP: usize = 32;
}

/// Faithful port of `LSS_NAME(clone)` for x86_64
/// (`linux_syscall_support.h:2408`).
///
/// Issues the raw `clone(2)` syscall, then - *in the child* - sets up the stack
/// and calls `fn(arg)`, terminating via `exit(2)` with `fn`'s return value. The
/// child **never returns** from this function; only the parent does, receiving
/// the child tid (or `-errno`).
///
/// The two-words-pushed-onto-child-stack dance (`fn` and `arg`) and the 16-byte
/// stack alignment exactly mirror the C asm, so a child entered here meets the
/// SysV ABI expectations of a compiled `fn`.
///
/// # Safety
/// - `child_stack` must point to the *top* of a writable, suitably sized region
///   the child can use as its stack (this wrapper aligns and reserves space).
/// - `fn` must be a valid function pointer; with `CLONE_VM` it runs in the
///   caller's address space and shares memory, so it must be async-signal-safe
///   and must not touch the parent's live stack.
/// - `parent_tidptr`/`child_tidptr`/`newtls` must be null or valid per the
///   `flags` requested.
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
    let res: usize;
    // rax starts as -EINVAL so the null-guard fall-through returns -EINVAL,
    // exactly like the C wrapper's `"0"(-EINVAL)` output initializer. The clone
    // syscall number is loaded into rax only just before the `syscall`.
    let einval: usize = -(crate::linux::EINVAL as isize) as usize;
    // Bind the kernel-ABI argument registers directly (rdi/rdx/r8/r10) so the
    // compiler loads them; we only hand-manage the child-stack setup and rsi.
    unsafe {
        asm!(
            // if (fn == NULL || child_stack == NULL) return -EINVAL (in rax);
            "test  {func}, {func}",
            "jz    2f",
            "test  {stack}, {stack}",
            "jz    2f",
            // child_stack &= ~0xF; child_stack -= 16;
            "and   {stack}, -16",
            "sub   {stack}, 16",
            // push arg (at +8) and fn (at +0) onto the child stack
            "mov   [{stack} + 8], {arg}",
            "mov   [{stack}], {func}",
            // child_stack -> rsi (the kernel sets the child's rsp from it)
            "mov   rsi, {stack}",
            // rax=__NR_clone, rdi=flags, rdx=parent, r8=tls, r10=child_tid
            "mov   rax, {nr_clone}",
            "syscall",
            // parent (rax != 0) jumps to done; child falls through
            "test  rax, rax",
            "jnz   2f",
            // --- child ---
            "xor   ebp, ebp",          // terminate frame-pointer chain
            "pop   rax",               // fn
            "pop   rdi",               // arg
            "call  rax",
            // exit(fn_ret)
            "mov   rdi, rax",
            "mov   rax, {nr_exit}",
            "syscall",
            // --- done (parent) ---
            "2:",
            func = in(reg) func,
            stack = in(reg) child_stack,
            arg = in(reg) arg,
            nr_clone = const CLONE_NR,
            nr_exit = const EXIT_NR,
            inout("rax") einval => res,
            in("rdi") flags,
            in("rdx") parent_tidptr,
            in("r8") newtls,
            in("r10") child_tidptr,
            out("rsi") _,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    res
}

// `const` operands for asm! must be integer paths; alias the nr constants.
/// `clone(2)` syscall number exposed as an asm const operand.
const CLONE_NR: usize = nr::CLONE;
/// `exit(2)` syscall number exposed as an asm const operand.
const EXIT_NR: usize = nr::EXIT;

/// `SA_RESTORER` flag bit required by the x86_64 kernel for custom restorers.
pub const SA_RESTORER: u64 = 0x0400_0000;

// The x86_64 signal restorer trampoline (3rd asm trampoline, alongside
// syscall*/clone). On x86_64 the kernel does not know how to return from a
// signal handler; with SA_SIGINFO the sigaction must supply an SA_RESTORER
// pointing at a function that issues `rt_sigreturn`. glibc hides its copy, so -
// exactly like `linux_syscall_support.h`'s `restore_rt` - we ship our own.
//
// `naked`-style via global_asm!: `mov rax, __NR_rt_sigreturn; syscall`. It takes
// no args and never returns normally (the kernel restores the interrupted
// context), so a plain global symbol is correct.
core::arch::global_asm!(
    ".globl coredumper_restore_rt",
    ".align 16",
    "coredumper_restore_rt:",
    "mov rax, 15", // __NR_rt_sigreturn
    "syscall",
    // unreachable; the syscall does not return here.
);

unsafe extern "C" {
    /// The signal restorer symbol defined above. Its *address* is installed as
    /// `sa_restorer`; it is never called directly from Rust.
    pub fn coredumper_restore_rt();
}

/// Address of the [`coredumper_restore_rt`] trampoline, for `sa_restorer`.
#[inline]
pub fn restore_rt_addr() -> usize {
    coredumper_restore_rt as unsafe extern "C" fn() as usize
}

/// Snapshot the *caller's* CPU registers into a `user_regs_struct`-layout
/// buffer, so the dumping thread's core registers reflect the call site rather
/// than wherever it ends up parked (in `wait4`) during the dump. Port of the
/// x86_64 `FRAME()` macro in `elfcore.h`.
///
/// `out` is the 27-`u64` `Regs`/`i386_regs` layout (see corus-core's
/// `elf::Regs`): r15,r14,r13,r12,rbp,rbx,r11,r10,r9,r8,rax,rcx,rdx,rsi,rdi,
/// orig_rax,rip,cs,eflags,rsp,ss,fs_base,gs_base,ds,es,fs,gs (indices 0..27).
///
/// Crucially, `rip` is set to **this function's return address** (the caller's
/// next instruction) and `rsp` to the caller's stack pointer (our `rsp` after
/// popping the return address), so a debugger unwinding the dumped thread starts
/// in the *caller* (e.g. `WriteCoreDump`), exactly as the C macro arranges.
/// `fs_base`/`gs_base` are left zero (kernel-only; the caller fills them from
/// the ptrace-captured regs, as the C `SET_FRAME` does).
///
/// A naked function so there is no prologue: on entry `[rsp]` holds the return
/// address and `rsp+8` is the caller's stack pointer, letting us record the
/// caller's `rip`/`rsp` precisely. `rdi` holds `out` (SysV first arg).
///
/// # Safety
/// `out` must point to at least 27 writable `u64` slots (a `Regs`).
#[unsafe(naked)]
pub unsafe extern "C" fn capture_frame(out: *mut u64) {
    core::arch::naked_asm!(
        // rdi = out. Save GP registers (skip rdi/rax briefly as scratch).
        "mov [rdi + 0],  r15",
        "mov [rdi + 8],  r14",
        "mov [rdi + 16], r13",
        "mov [rdi + 24], r12",
        "mov [rdi + 32], rbp",
        "mov [rdi + 40], rbx",
        "mov [rdi + 48], r11",
        "mov [rdi + 56], r10",
        "mov [rdi + 64], r9",
        "mov [rdi + 72], r8",
        "mov [rdi + 80], rax",
        "mov [rdi + 88], rcx",
        "mov [rdi + 96], rdx",
        "mov [rdi + 104], rsi",
        "mov [rdi + 112], rdi",
        // rip (128) = return address at [rsp] (no prologue ran).
        "mov rax, [rsp]",
        "mov [rdi + 128], rax",
        // rsp (152) = caller's rsp = rsp + 8 (above the return address).
        "lea rax, [rsp + 8]",
        "mov [rdi + 152], rax",
        "ret",
    )
}

// --- ptrace register capture (arch-specific request shape) -------------------
//
// x86_64 fills the whole register set in one call via PTRACE_GETREGS /
// PTRACE_GETFPREGS, with `data` pointing at the output buffer and `addr`
// ignored. Other arches (e.g. aarch64) have no GETREGS and must use
// PTRACE_GETREGSET with an iovec + note-type selector, so register capture
// lives behind the arch boundary rather than in the generic `sys` layer.

/// `PTRACE_GETREGS` request number.
const PTRACE_GETREGS: usize = 12;
/// `PTRACE_GETFPREGS` request number.
const PTRACE_GETFPREGS: usize = 14;

/// Fill `out` (a `Regs`-shaped buffer) with the stopped tracee's
/// general-purpose registers.
///
/// # Errors
/// Returns the kernel errno if the ptrace request fails.
///
/// # Safety
/// `out` must point to a buffer at least the size of the kernel's
/// `user_regs_struct` (the caller's `Regs`). The tracee must be ptrace-stopped.
///
/// `out_len` is accepted for signature parity with aarch64 (whose
/// `PTRACE_GETREGSET` needs the buffer length in an iovec); x86_64's
/// `PTRACE_GETREGS` fills a fixed-size buffer and ignores it.
#[inline]
pub unsafe fn ptrace_get_gpregs(
    pid: i32,
    out: *mut core::ffi::c_void,
    _out_len: usize,
) -> Result<usize, i32> {
    // addr ignored on x86_64; data points at the output buffer.
    crate::from_ret(unsafe { syscall4(nr::PTRACE, PTRACE_GETREGS, pid as usize, 0, out as usize) })
}

/// Fill `out` (an `FpRegs`-shaped buffer) with the stopped tracee's FPU/SSE
/// registers.
///
/// # Errors
/// Returns the kernel errno if the ptrace request fails.
///
/// # Safety
/// `out` must point to a buffer at least the size of the kernel's
/// `user_fpregs_struct` (the caller's `FpRegs`). The tracee must be stopped.
#[inline]
pub unsafe fn ptrace_get_fpregs(
    pid: i32,
    out: *mut core::ffi::c_void,
    _out_len: usize,
) -> Result<usize, i32> {
    crate::from_ret(unsafe {
        syscall4(nr::PTRACE, PTRACE_GETFPREGS, pid as usize, 0, out as usize)
    })
}
