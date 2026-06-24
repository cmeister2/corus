//! Typed `sys_*` syscall wrappers - the safe-ish surface the dump engine calls.
//!
//! Each wrapper issues the raw syscall via [`crate::arch`] and converts the
//! result into `SysResult` (errno-decoded). These mirror the `sys_*` functions
//! in `linux_syscall_support.h` that the dump path actually uses (see the audit
//! in the dump path).
//!
//! Pointers are passed as raw pointers deliberately: the caller (the dump
//! engine) is itself `unsafe` by nature, and we are reproducing a libc-free
//! syscall layer, not a safe abstraction.

use core::ffi::{c_char, c_int, c_void};

use crate::arch::{nr, syscall0, syscall1, syscall2, syscall3, syscall4, syscall6};
use crate::from_ret;
use crate::kernel_types::{
    KernelMsghdr, KernelPollfd, KernelSigaction, KernelSigset, KernelStat, StackT,
};

/// Result of a syscall: `Ok(usize)` or `Err(errno)`.
pub type SysResult = Result<usize, i32>;

// --- File / IO ---------------------------------------------------------------

/// `open(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
///
/// # Safety
/// `pathname` must point to a valid NUL-terminated C string.
#[inline]
pub unsafe fn open(pathname: *const c_char, flags: c_int, mode: c_int) -> SysResult {
    from_ret(unsafe { syscall3(nr::OPEN, pathname as usize, flags as usize, mode as usize) })
}

/// `close(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
#[inline]
pub fn close(fd: c_int) -> SysResult {
    // SAFETY: close takes a plain integer fd; no memory is dereferenced.
    from_ret(unsafe { syscall1(nr::CLOSE, fd as usize) })
}

/// `read(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
///
/// # Safety
/// `buf` must be valid for writes of `count` bytes.
#[inline]
pub unsafe fn read(fd: c_int, buf: *mut c_void, count: usize) -> SysResult {
    from_ret(unsafe { syscall3(nr::READ, fd as usize, buf as usize, count) })
}

/// `write(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
///
/// # Safety
/// `buf` must be valid for reads of `count` bytes.
#[inline]
pub unsafe fn write(fd: c_int, buf: *const c_void, count: usize) -> SysResult {
    from_ret(unsafe { syscall3(nr::WRITE, fd as usize, buf as usize, count) })
}

/// `lseek(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
#[inline]
pub fn lseek(fd: c_int, offset: i64, whence: c_int) -> SysResult {
    // SAFETY: lseek dereferences no memory.
    from_ret(unsafe { syscall3(nr::LSEEK, fd as usize, offset as usize, whence as usize) })
}

/// `dup(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
#[inline]
pub fn dup(oldfd: c_int) -> SysResult {
    // SAFETY: integer-only argument.
    from_ret(unsafe { syscall1(nr::DUP, oldfd as usize) })
}

/// `fcntl(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
///
/// # Safety
/// For pointer-taking commands, `arg` must be valid for that command; for the
/// integer commands used by the dump path it is a plain value.
#[inline]
pub unsafe fn fcntl(fd: c_int, cmd: c_int, arg: usize) -> SysResult {
    from_ret(unsafe { syscall3(nr::FCNTL, fd as usize, cmd as usize, arg) })
}

/// `pipe2(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
///
/// # Safety
/// `pipefd` must point to an array of two `c_int`.
#[inline]
pub unsafe fn pipe2(pipefd: *mut c_int, flags: c_int) -> SysResult {
    from_ret(unsafe { syscall2(nr::PIPE2, pipefd as usize, flags as usize) })
}

/// `readlink(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
///
/// # Safety
/// `pathname` is a valid C string; `buf` is valid for writes of `bufsiz`.
#[inline]
pub unsafe fn readlink(pathname: *const c_char, buf: *mut c_char, bufsiz: usize) -> SysResult {
    from_ret(unsafe { syscall3(nr::READLINK, pathname as usize, buf as usize, bufsiz) })
}

/// `getdents(2)` (legacy; matches [`crate::kernel_types::KernelDirent`]).
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
///
/// # Safety
/// `dirp` must be valid for writes of `count` bytes.
#[inline]
pub unsafe fn getdents(fd: c_int, dirp: *mut c_void, count: usize) -> SysResult {
    from_ret(unsafe { syscall3(nr::GETDENTS, fd as usize, dirp as usize, count) })
}

// --- stat --------------------------------------------------------------------

/// `stat(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
///
/// # Safety
/// `pathname` is a valid C string; `statbuf` is valid for writes of a
/// [`KernelStat`].
#[inline]
pub unsafe fn stat(pathname: *const c_char, statbuf: *mut KernelStat) -> SysResult {
    from_ret(unsafe { syscall2(nr::STAT, pathname as usize, statbuf as usize) })
}

/// `fstat(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
///
/// # Safety
/// `statbuf` must be valid for writes of a [`KernelStat`].
#[inline]
pub unsafe fn fstat(fd: c_int, statbuf: *mut KernelStat) -> SysResult {
    from_ret(unsafe { syscall2(nr::FSTAT, fd as usize, statbuf as usize) })
}

// --- process / ids -----------------------------------------------------------

/// `getpid(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
#[inline]
pub fn getpid() -> SysResult {
    // SAFETY: no arguments, no memory access.
    from_ret(unsafe { syscall0(nr::GETPID) })
}

/// `gettid(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
#[inline]
pub fn gettid() -> SysResult {
    // SAFETY: no arguments, no memory access.
    from_ret(unsafe { syscall0(nr::GETTID) })
}

/// `getppid(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
#[inline]
pub fn getppid() -> SysResult {
    // SAFETY: no arguments, no memory access.
    from_ret(unsafe { syscall0(nr::GETPPID) })
}

/// `geteuid(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
#[inline]
pub fn geteuid() -> SysResult {
    // SAFETY: no arguments, no memory access.
    from_ret(unsafe { syscall0(nr::GETEUID) })
}

/// `getegid(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
#[inline]
pub fn getegid() -> SysResult {
    // SAFETY: no arguments, no memory access.
    from_ret(unsafe { syscall0(nr::GETEGID) })
}

/// `getsid(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
#[inline]
pub fn getsid(pid: c_int) -> SysResult {
    // SAFETY: integer-only argument.
    from_ret(unsafe { syscall1(nr::GETSID, pid as usize) })
}

/// `getpriority(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
#[inline]
pub fn getpriority(which: c_int, who: c_int) -> SysResult {
    // SAFETY: integer-only arguments.
    from_ret(unsafe { syscall2(nr::GETPRIORITY, which as usize, who as usize) })
}

/// `prctl(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
///
/// # Safety
/// For pointer-taking options, the pointer args must be valid; the dump path
/// uses only the integer options (`PR_GET/SET_DUMPABLE`).
#[inline]
pub unsafe fn prctl(
    option: c_int,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
) -> SysResult {
    from_ret(unsafe { syscall6(nr::PRCTL, option as usize, arg2, arg3, arg4, arg5, 0) })
}

/// `kill(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
#[inline]
pub fn kill(pid: c_int, sig: c_int) -> SysResult {
    // SAFETY: integer-only arguments.
    from_ret(unsafe { syscall2(nr::KILL, pid as usize, sig as usize) })
}

/// `sched_yield(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
#[inline]
pub fn sched_yield() -> SysResult {
    // SAFETY: no arguments, no memory access.
    from_ret(unsafe { syscall0(nr::SCHED_YIELD) })
}

/// `exit(2)` - terminates the calling thread only. Never returns.
#[inline]
pub fn exit(status: c_int) -> ! {
    // SAFETY: exit never returns and dereferences no memory.
    unsafe {
        syscall1(nr::EXIT, status as usize);
    }
    loop {
        core::hint::spin_loop();
    }
}

// --- ptrace / wait -----------------------------------------------------------

/// `ptrace(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
///
/// # Safety
/// `addr`/`data` must be valid for the given `request` (some requests treat
/// them as pointers into the tracer's memory).
#[inline]
pub unsafe fn ptrace(
    request: c_int,
    pid: c_int,
    addr: *mut c_void,
    data: *mut c_void,
) -> SysResult {
    from_ret(unsafe {
        syscall4(
            nr::PTRACE,
            request as usize,
            pid as usize,
            addr as usize,
            data as usize,
        )
    })
}

// ptrace request numbers used for register capture.
/// `PTRACE_GETREGS` request number.
const PTRACE_GETREGS: c_int = 12;
/// `PTRACE_GETFPREGS` request number.
const PTRACE_GETFPREGS: c_int = 14;

/// `ptrace(PTRACE_GETREGS, pid)` - fill `regs_out` (a `user_regs_struct`-shaped
/// buffer) with the tracee's general-purpose registers.
///
/// # Errors
/// Returns the kernel errno if the ptrace request fails.
///
/// # Safety
/// `regs_out` must point to a buffer at least the size of the kernel's
/// `user_regs_struct` (the caller's `Regs`). The tracee must be ptrace-stopped.
#[inline]
pub unsafe fn ptrace_getregs(pid: c_int, regs_out: *mut c_void) -> SysResult {
    // On x86_64 the addr arg is ignored; data points at the output buffer.
    unsafe { ptrace(PTRACE_GETREGS, pid, core::ptr::null_mut(), regs_out) }
}

/// `ptrace(PTRACE_GETFPREGS, pid)` - fill `fpregs_out` (a
/// `user_fpregs_struct`-shaped buffer) with the tracee's FPU/SSE registers.
///
/// # Errors
/// Returns the kernel errno if the ptrace request fails.
///
/// # Safety
/// `fpregs_out` must point to a buffer at least the size of the kernel's
/// `user_fpregs_struct` (the caller's `FpRegs`). The tracee must be stopped.
#[inline]
pub unsafe fn ptrace_getfpregs(pid: c_int, fpregs_out: *mut c_void) -> SysResult {
    unsafe { ptrace(PTRACE_GETFPREGS, pid, core::ptr::null_mut(), fpregs_out) }
}

/// `wait4(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
///
/// # Safety
/// `wstatus` must be null or valid for writes of a `c_int`; `rusage` null or
/// valid for a kernel rusage.
#[inline]
pub unsafe fn wait4(
    pid: c_int,
    wstatus: *mut c_int,
    options: c_int,
    rusage: *mut c_void,
) -> SysResult {
    from_ret(unsafe {
        syscall4(
            nr::WAIT4,
            pid as usize,
            wstatus as usize,
            options as usize,
            rusage as usize,
        )
    })
}

// --- signals -----------------------------------------------------------------

/// `rt_sigprocmask(2)`. `sigsetsize` must be `size_of::<KernelSigset>()`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
///
/// # Safety
/// `set`/`oldset` must be null or valid for a [`KernelSigset`] of `sigsetsize`.
#[inline]
pub unsafe fn rt_sigprocmask(
    how: c_int,
    set: *const KernelSigset,
    oldset: *mut KernelSigset,
    sigsetsize: usize,
) -> SysResult {
    from_ret(unsafe {
        syscall4(
            nr::RT_SIGPROCMASK,
            how as usize,
            set as usize,
            oldset as usize,
            sigsetsize,
        )
    })
}

// --- signal handlers ---------------------------------------------------------

/// `rt_sigaction(2)`. Installs `act` (or queries into `oldact`) for `signum`.
/// On x86_64 the kernel requires an `SA_RESTORER`; if `act` doesn't set one we
/// fill in our own [`crate::arch::restore_rt_addr`] trampoline, mirroring the C
/// `LSS_NAME(rt_sigaction)` behavior.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
///
/// # Safety
/// `act`/`oldact` must be null or valid `KernelSigaction`; `sigsetsize` must be
/// `size_of::<KernelSigset>()`.
#[inline]
pub unsafe fn rt_sigaction(
    signum: c_int,
    act: *const KernelSigaction,
    oldact: *mut KernelSigaction,
    sigsetsize: usize,
) -> SysResult {
    // If a handler is being installed without a restorer, supply ours. We copy
    // into a local so we don't mutate the caller's struct.
    let mut local;
    let act_ptr = if !act.is_null() {
        // SAFETY: caller guarantees `act` is valid.
        local = unsafe { *act };
        if local.sa_restorer.is_null() {
            local.sa_flags |= crate::arch::SA_RESTORER;
            local.sa_restorer = crate::arch::restore_rt_addr() as *mut c_void;
        }
        &local as *const KernelSigaction
    } else {
        act
    };
    from_ret(unsafe {
        syscall4(
            nr::RT_SIGACTION,
            signum as usize,
            act_ptr as usize,
            oldact as usize,
            sigsetsize,
        )
    })
}

/// `sigaltstack(2)`. Sets `ss` as the alternate signal stack (or queries the
/// current one into `old`).
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
///
/// # Safety
/// `ss`/`old` must be null or valid `StackT`.
#[inline]
pub unsafe fn sigaltstack(ss: *const StackT, old: *mut StackT) -> SysResult {
    from_ret(unsafe { syscall2(nr::SIGALTSTACK, ss as usize, old as usize) })
}

// --- memory ------------------------------------------------------------------

/// `mmap(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
///
/// # Safety
/// Standard mmap contract; `addr`/`fd`/`offset` must be consistent with `flags`.
#[inline]
pub unsafe fn mmap(
    addr: *mut c_void,
    length: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: i64,
) -> SysResult {
    from_ret(unsafe {
        syscall6(
            nr::MMAP,
            addr as usize,
            length,
            prot as usize,
            flags as usize,
            fd as usize,
            offset as usize,
        )
    })
}

/// `munmap(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
///
/// # Safety
/// `addr`/`length` must describe a mapping previously returned by `mmap`.
#[inline]
pub unsafe fn munmap(addr: *mut c_void, length: usize) -> SysResult {
    from_ret(unsafe { syscall2(nr::MUNMAP, addr as usize, length) })
}

// --- sockets (used by the compressor pipeline) -------------------------------

/// `socketpair(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
///
/// # Safety
/// `sv` must point to an array of two `c_int`.
#[inline]
pub unsafe fn socketpair(
    domain: c_int,
    type_: c_int,
    protocol: c_int,
    sv: *mut c_int,
) -> SysResult {
    from_ret(unsafe {
        syscall4(
            nr::SOCKETPAIR,
            domain as usize,
            type_ as usize,
            protocol as usize,
            sv as usize,
        )
    })
}

/// `socket(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
#[inline]
pub fn socket(domain: c_int, type_: c_int, protocol: c_int) -> SysResult {
    // SAFETY: integer-only arguments.
    from_ret(unsafe {
        syscall3(
            nr::SOCKET,
            domain as usize,
            type_ as usize,
            protocol as usize,
        )
    })
}

/// `shutdown(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
#[inline]
pub fn shutdown(sockfd: c_int, how: c_int) -> SysResult {
    // SAFETY: integer-only arguments.
    from_ret(unsafe { syscall2(nr::SHUTDOWN, sockfd as usize, how as usize) })
}

/// `fork(2)`. Returns 0 in the child, the child pid in the parent.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
#[inline]
pub fn fork() -> SysResult {
    // SAFETY: fork takes no arguments and dereferences no memory.
    from_ret(unsafe { syscall0(nr::FORK) })
}

/// `dup2(2)` - duplicate `oldfd` onto `newfd`.
///
/// # Errors
/// Returns the kernel errno if validation or duplication fails.
#[inline]
pub fn dup2(oldfd: c_int, newfd: c_int) -> SysResult {
    // dup2 isn't on x86_64 (only dup3); emulate via dup3 with flags=0 when
    // oldfd != newfd, else just validate oldfd. The kernel's dup2 semantics:
    // if oldfd==newfd, return newfd if valid.
    if oldfd == newfd {
        // Validate via fcntl(F_GETFD).
        return unsafe {
            fcntl(oldfd, 1 /* F_GETFD */, 0)
        }
        .map(|_| oldfd as usize);
    }
    from_ret(unsafe { syscall3(nr::DUP3, oldfd as usize, newfd as usize, 0) })
}

/// `execve(2)`.
///
/// # Errors
/// Returns the kernel errno if execution fails. On success, this syscall does
/// not return.
///
/// # Safety
/// `path` is a valid C string; `argv`/`envp` are NULL-terminated arrays of
/// valid C string pointers.
#[inline]
pub unsafe fn execve(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> SysResult {
    from_ret(unsafe { syscall3(nr::EXECVE, path as usize, argv as usize, envp as usize) })
}

/// `tkill(2)` - send `sig` to a single thread `tid`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
#[inline]
pub fn tkill(tid: c_int, sig: c_int) -> SysResult {
    // SAFETY: integer-only arguments.
    from_ret(unsafe { syscall2(nr::TKILL, tid as usize, sig as usize) })
}

/// `PTRACE_DETACH` request number.
const PTRACE_DETACH: c_int = 17;
/// `SIGCONT` signal number used to wake detached tracees.
const SIGCONT: c_int = 18;

/// Faithful port of `LSS_NAME(ptrace_detach)`: yield a time slice, detach, then
/// `tkill(tid, SIGCONT)` to reliably wake the tracee (PTRACE_DETACH sometimes
/// fails to). Preserves the detach result's errno semantics by returning the
/// detach result, not the wakeup's.
///
/// # Errors
/// Returns the errno from `PTRACE_DETACH` if detaching fails.
#[inline]
pub fn ptrace_detach(pid: c_int) -> SysResult {
    let _ = sched_yield();
    let rc = unsafe {
        ptrace(
            PTRACE_DETACH,
            pid,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    let _ = tkill(pid, SIGCONT);
    rc
}

/// `sendmsg(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
///
/// # Safety
/// `msg` must point to a valid [`KernelMsghdr`] with valid iov pointers.
#[inline]
pub unsafe fn sendmsg(sockfd: c_int, msg: *const KernelMsghdr, flags: c_int) -> SysResult {
    from_ret(unsafe { syscall3(nr::SENDMSG, sockfd as usize, msg as usize, flags as usize) })
}

/// `recvmsg(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
///
/// # Safety
/// `msg` must point to a valid [`KernelMsghdr`] with valid iov pointers.
#[inline]
pub unsafe fn recvmsg(sockfd: c_int, msg: *mut KernelMsghdr, flags: c_int) -> SysResult {
    from_ret(unsafe { syscall3(nr::RECVMSG, sockfd as usize, msg as usize, flags as usize) })
}

// --- poll --------------------------------------------------------------------

/// `poll(2)`.
///
/// # Errors
/// Returns the kernel errno if the syscall fails.
///
/// # Safety
/// `fds` must point to `nfds` valid [`KernelPollfd`] entries.
#[inline]
pub unsafe fn poll(fds: *mut KernelPollfd, nfds: usize, timeout: c_int) -> SysResult {
    from_ret(unsafe { syscall3(nr::POLL, fds as usize, nfds, timeout as usize) })
}

/// Convenience: number of bytes in a [`KernelSigset`], for `rt_sigprocmask`.
pub const SIGSET_SIZE: usize = core::mem::size_of::<KernelSigset>();

// --- sigset bit operations (libc-free, port of sys_sigfillset/sigdelset) -----

impl KernelSigset {
    /// Fill the set (all signals). Port of `sys_sigfillset`.
    pub fn fill(&mut self) {
        for w in self.sig.iter_mut() {
            *w = !0;
        }
    }

    /// Remove `signum` (1-based) from the set. Port of `sys_sigdelset`.
    pub fn del(&mut self, signum: c_int) {
        if signum < 1 {
            return;
        }
        let bit = (signum - 1) as usize;
        let word = bit / (u64::BITS as usize);
        let off = bit % (u64::BITS as usize);
        if word < self.sig.len() {
            self.sig[word] &= !(1u64 << off);
        }
    }
}
