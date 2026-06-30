//! Thread enumeration and suspension - port of `linuxthreads.c` +
//! `thread_lister.c`.
//!
//! [`list_all_process_threads`] clones a *lister thread* that shares this
//! process's address space but has its own pid/ppid. The lister scans
//! `/proc/<ppid>/task` for sibling threads, `PTRACE_ATTACH`es (and thereby
//! suspends) each, verifies they truly share our address space (marker-inode +
//! `PTRACE_PEEKDATA` cross-check), then invokes the caller's `callback` with the
//! suspended tids. The callback writes the core while everything is frozen, then
//! threads are resumed via
//! [`resume_all_process_threads`].
//!
//! ## Deviations from the C, with rationale
//! - **Lister stack**: the C `local_clone` runs the lister on the *caller's own
//!   stack* 4 KiB below the current frame (to avoid allocating). That aliasing
//!   is UB in Rust, so we `mmap` a dedicated stack for the lister instead. The
//!   essential design - a `CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_UNTRACED` lister
//!   sharing our VM - is preserved.
//! - **No-`Vec` thread list**: the C uses a VLA `pid_t pids[st_nlink+100]` with
//!   goto-retry on overflow. We use a fixed-capacity stack array
//!   ([`MAX_THREADS`]) and the same multi-pass loop; overflow is reported rather
//!   than silently truncating (logged via the error return).
//! - **Callback**: a C-ABI fn pointer + context pointer rather than varargs.

use core::ffi::{c_char, c_int, c_void};
use core::sync::atomic::{AtomicI32, AtomicPtr, AtomicUsize, Ordering};
use core::{mem, ptr};

use corus_syscall::arch::PAGE_SIZE;
use corus_syscall::kernel_types::{
    KernelDirent, KernelSigaction, KernelSigset, KernelStat, StackT,
};
use corus_syscall::linux::{ECHILD, EFAULT, EINTR, ENOMEM, EPERM, O_DIRECTORY, O_RDONLY};
use corus_syscall::{clone, sys};

// --- Lister crash-cleanup signal state ---------------------------------------
// If the lister thread dies (synchronous fault) while it has sibling threads
// PTRACE_ATTACHed, those threads would be left frozen forever. Mirroring the C
// `SignalHandler`/`sig_pids`/`sig_num_threads`, we install handlers for the sync
// signals on a pre-allocated alternate stack; the handler resumes (or, on
// SIGABRT, kills) the tracees before terminating. The suspend state lives in
// process-global atomics because the handler can't receive context otherwise.
//
// This is safe given the library's own contract: at most one dump (one lister)
// runs at a time (the public API is documented as non-reentrant).
/// Suspended pid list visible to the crash signal handler.
static SIG_PIDS: AtomicPtr<c_int> = AtomicPtr::new(ptr::null_mut());

/// Number of suspended pids visible to the crash signal handler.
static SIG_NUM_THREADS: AtomicUsize = AtomicUsize::new(0);

/// Pid of the fork-snapshot child the callback spawned, for the lister to reap.
///
/// The fork-snapshot dump path (see `crate::lib`) forks a copy-on-write child
/// inside the callback so the lister can resume the siblings immediately while
/// the child writes the core. The callback publishes the child pid here; after
/// resuming the siblings the lister `wait4`s it (so the child is reaped by its
/// real parent, before the lister exits) and folds the child's exit status into
/// the dump result. `0` means "no snapshot child" (in-line write / fork failed).
///
/// Lives in shared VM like the other lister statics, so the lister and the
/// original caller see the same value; the snapshot child gets a private
/// copy-on-write view it never touches. Same single-dump-at-a-time contract.
static SNAPSHOT_CHILD: AtomicI32 = AtomicI32::new(0);

/// `SIGABRT` signal number.
const SIGABRT: c_int = 6;
/// `SIGILL` signal number.
const SIGILL: c_int = 4;
/// `SIGFPE` signal number.
const SIGFPE: c_int = 8;
/// `SIGSEGV` signal number.
const SIGSEGV: c_int = 11;
/// `SIGBUS` signal number.
const SIGBUS: c_int = 7;
/// `SIGXCPU` signal number.
const SIGXCPU: c_int = 24;
/// `SIGXFSZ` signal number.
const SIGXFSZ: c_int = 25;
/// `SIGCONT` signal number used when resuming tracees.
const SIGCONT_SIG: c_int = 18;
/// `PTRACE_KILL` request number for fatal cleanup.
const PTRACE_KILL: c_int = 8;

/// Alternate signal stack size for the lister crash handler.
///
/// Do not mirror libc's `MINSIGSTKSZ`: on modern Linux/glibc it can expand to a
/// runtime `sysconf(_SC_MINSIGSTKSZ)` value, and this no-libc path needs a
/// compile-time stack buffer. The handler is tiny, but the kernel signal frame
/// can include architecture state, so use a conservative fixed buffer.
pub const ALT_STACK_SIZE: usize = 64 * 1024;

/// Synchronous signals that trigger lister crash cleanup and therefore must
/// remain unblocked in the lister.
const LISTER_CRASH_SIGNALS: [c_int; 7] =
    [SIGABRT, SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGXCPU, SIGXFSZ];

/// `SA_SIGINFO` signal-action flag.
const SA_SIGINFO: u64 = 4;
/// `SA_ONSTACK` signal-action flag.
const SA_ONSTACK: u64 = 0x0800_0000;
/// `SA_RESETHAND` signal-action flag.
const SA_RESETHAND: u64 = 0x8000_0000;
/// Default `sigaltstack` flags.
const SS_DEFAULT_FLAGS: c_int = 0;

/// Install the alternate signal stack and the sync-signal handlers. `altstack`
/// is caller-provided storage of at least [`ALT_STACK_SIZE`] bytes.
fn install_crash_handlers(altstack: &mut [u8]) {
    let mut ss = StackT::zeroed();
    ss.ss_sp = altstack.as_mut_ptr() as *mut c_void;
    ss.ss_flags = SS_DEFAULT_FLAGS;
    ss.ss_size = altstack.len();
    // SAFETY: ss points at valid, sufficiently-sized storage.
    let _ = unsafe { sys::sigaltstack(&ss, ptr::null_mut()) };

    for &sig in LISTER_CRASH_SIGNALS.iter() {
        let mut sa = KernelSigaction::zeroed();
        sa.sa_handler = sig_handler as *mut c_void;
        sa.sa_mask.fill(); // block everything while in the handler
        sa.sa_flags = SA_ONSTACK | SA_SIGINFO | SA_RESETHAND;
        // SAFETY: sa is a valid sigaction; rt_sigaction fills the restorer.
        let _ = unsafe { sys::rt_sigaction(sig, &sa, ptr::null_mut(), sys::SIGSET_SIZE) };
    }
}

/// Sync-signal handler: wake/kill any attached tracees, then exit. Async-signal
/// safe - only raw syscalls, no libc, no allocation. Port of `SignalHandler`.
extern "C" fn sig_handler(signum: c_int, _info: *mut c_void, _ctx: *mut c_void) {
    let pids = SIG_PIDS.swap(ptr::null_mut(), Ordering::SeqCst);
    if !pids.is_null() {
        let n = SIG_NUM_THREADS.load(Ordering::SeqCst);
        if signum == SIGABRT {
            // Can't safely continue the app; kill every tracee.
            for i in 0..n {
                let _ = sys::sched_yield();
                let pid = unsafe { *pids.add(i) };
                let _ = unsafe { sys::ptrace(PTRACE_KILL, pid, ptr::null_mut(), ptr::null_mut()) };
            }
        } else {
            // Resume the tracees so the application can continue.
            let slice = unsafe { core::slice::from_raw_parts(pids, n) };
            resume_all_process_threads(slice);
        }
    }
    let _ = SIGCONT_SIG;
    sys::exit(if signum == SIGABRT { 1 } else { 2 });
}

/// Maximum threads we can suspend in one pass. Fixed cap replacing the C VLA
/// (`st_nlink + 100`); generously sized for realistic processes.
pub const MAX_THREADS: usize = 4096;

/// Callback invoked with the suspended thread tids. Returns a value propagated
/// to the [`list_all_process_threads`] caller. Must be async-signal-safe and
/// must not take libc locks (threads are frozen). It should arrange for resume,
/// though the lister also force-resumes afterward.
pub type ThreadCallback =
    extern "C" fn(param: *mut c_void, pids: *const c_int, num: c_int) -> c_int;

// Linux constants used here.
/// Local/Unix socket protocol family.
const PF_LOCAL: c_int = 1;
/// Datagram socket type.
const SOCK_DGRAM: c_int = 2;
/// `fcntl(2)` command for setting descriptor flags.
const F_SETFD: c_int = 2;
/// Close-on-exec descriptor flag.
const FD_CLOEXEC: usize = 1;
/// `PTRACE_ATTACH` request number.
const PTRACE_ATTACH: c_int = 16;
/// `PTRACE_PEEKDATA` request number.
const PTRACE_PEEKDATA: c_int = 2;
/// `__WALL` wait option used for clone children.
const WALL: c_int = 0x4000_0000;
/// `prctl(2)` request for reading dumpable state.
const PR_GET_DUMPABLE: c_int = 3;
/// `prctl(2)` request for setting dumpable state.
const PR_SET_DUMPABLE: c_int = 4;
/// `prctl(2)` request for allowing a specific ptracer under YAMA.
const PR_SET_PTRACER: c_int = 0x5961_6d61;
/// `rt_sigprocmask(2)` operation for blocking signals.
const SIG_BLOCK: c_int = 0;
/// `rt_sigprocmask(2)` operation for replacing the signal mask.
const SIG_SETMASK: c_int = 2;

// clone flags for the lister (matches local_clone; note: no SIGCHLD - the
// parent reaps with __WALL).
/// Share the address space with the lister.
const CLONE_VM: usize = 0x0000_0100;
/// Share filesystem context with the lister.
const CLONE_FS: usize = 0x0000_0200;
/// Share the file descriptor table with the lister.
const CLONE_FILES: usize = 0x0000_0400;
/// Prevent tracing from following the lister clone.
const CLONE_UNTRACED: usize = 0x0080_0000;
/// Fixed buffer size for NUL-terminated `/proc` paths passed to syscalls.
const NUL_TERMINATED_PATH_LEN: usize = 80;
/// Maximum path prefix copied before reserving one byte for the trailing NUL.
const MAX_NUL_TERMINATED_PATH_PREFIX: usize = NUL_TERMINATED_PATH_LEN - 1;

/// itoa into `buf`, returning the number of bytes written (no NUL). Port of
/// `local_itoa` (libc-free).
fn local_itoa(buf: &mut [u8], value: i32) -> usize {
    let mut tmp = [0u8; 16];
    let mut n = 0usize;
    let neg = value < 0;
    // Work in i64 so i32::MIN negates safely.
    let mut v = (value as i64).unsigned_abs();
    if v == 0 {
        tmp[n] = b'0';
        n += 1;
    }
    while v > 0 {
        tmp[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    let mut out = 0;
    if neg {
        buf[out] = b'-';
        out += 1;
    }
    while n > 0 {
        n -= 1;
        buf[out] = tmp[n];
        out += 1;
    }
    out
}

/// atoi for a `&[u8]` prefix of digits. Port of `local_atoi`.
fn local_atoi(s: &[u8]) -> i32 {
    let mut n: i32 = 0;
    let mut i = 0;
    let neg = s.first() == Some(&b'-');
    if neg {
        i = 1;
    }
    while i < s.len() && s[i].is_ascii_digit() {
        n = n.wrapping_mul(10).wrapping_add((s[i] - b'0') as i32);
        i += 1;
    }
    if neg { -n } else { n }
}

/// `open(2)` that retries on EINTR. Port of `c_open`.
fn c_open(path: &[u8], flags: c_int) -> sys::SysResult {
    loop {
        match unsafe { sys::open(path.as_ptr() as *const c_char, flags, 0) } {
            Err(EINTR) => continue,
            other => return other,
        }
    }
}

/// Shared parameter block between caller and the cloned lister (CLONE_VM).
struct ListerParams {
    /// Callback result propagated to the parent.
    result: c_int,
    /// Errno-style failure code propagated to the parent.
    err: i32,
    /// Callback invoked with suspended thread ids.
    callback: ThreadCallback,
    /// Opaque user data passed to `callback`.
    parameter: *mut c_void,
}

/// Resume threads suspended by [`list_all_process_threads`]. Returns true if at
/// least one was resumed. Port of `ResumeAllProcessThreads`.
pub fn resume_all_process_threads(pids: &[c_int]) -> bool {
    let mut any = false;
    for &pid in pids {
        if sys::ptrace_detach(pid).is_ok() {
            any = true;
        }
    }
    any
}

/// Build "/proc/<n>/..." style paths into `buf`, returning the byte length.
fn build_path(buf: &mut [u8], parts: &[&[u8]], num: Option<i32>) -> usize {
    let mut len = 0;
    for p in parts {
        buf[len..len + p.len()].copy_from_slice(p);
        len += p.len();
    }
    if let Some(n) = num {
        len += local_itoa(&mut buf[len..], n);
    }
    len
}

/// The lister thread body. Runs as the clone child (its return becomes the
/// child's exit code via the clone wrapper). Writes detailed status into the
/// shared `*params`. Returns: 0 ok, 1 failure, 2 fault, 3 already-traced.
///
/// # Safety
/// `arg` must point to a live [`ListerParams`] in shared memory.
extern "C" fn lister_thread(arg: *mut c_void) -> c_int {
    // SAFETY: caller passes a valid ListerParams pointer in shared VM.
    let params = unsafe { &mut *(arg as *mut ListerParams) };

    let clone_tid = match sys::gettid() {
        Ok(t) => t as c_int,
        Err(e) => return fail(params, e),
    };
    let ppid = match sys::getppid() {
        Ok(p) => p as c_int,
        Err(e) => return fail(params, e),
    };

    // Marker socket: identifies threads sharing our fd table + VM.
    let marker = match sys::socket(PF_LOCAL, SOCK_DGRAM, 0) {
        Ok(fd) => fd as c_int,
        Err(e) => return fail(params, e),
    };
    // SAFETY: F_SETFD/FD_CLOEXEC takes an integer arg.
    if let Err(errno) = unsafe { sys::fcntl(marker, F_SETFD, FD_CLOEXEC) } {
        let _ = sys::close(marker);
        return fail(params, errno);
    }

    // Path of our own marker: /proc/<ppid>/fd/<marker>
    let mut marker_name = [0u8; 64];
    let mlen = build_path(&mut marker_name, &[b"/proc/"], Some(ppid));
    let mlen = mlen + build_path(&mut marker_name[mlen..], &[b"/fd/"], Some(marker));
    let mut marker_sb = KernelStat::zeroed();
    // SAFETY: marker_name is NUL? No - build a NUL-terminated copy.
    let marker_cstr = nul_terminate(&marker_name, mlen);
    if let Err(errno) = unsafe { sys::stat(marker_cstr.as_ptr() as *const c_char, &mut marker_sb) }
    {
        let _ = sys::close(marker);
        return fail(params, errno);
    }

    // /proc/<ppid>/task directory.
    let mut task_path = [0u8; 64];
    let tlen = build_path(&mut task_path, &[b"/proc/"], Some(ppid));
    let tlen = tlen + build_path(&mut task_path[tlen..], &[b"/task"], None);
    let task_cstr = nul_terminate(&task_path, tlen);

    // The suspended-thread list: fixed-cap stack array (no Vec).
    let mut pids = [0i32; MAX_THREADS];
    let mut num_threads = 0usize;
    let mut found_parent = false;

    // Crash-cleanup: publish the (initially empty) pid list and install sync-
    // signal handlers on an alternate stack, so a fault here wakes/kills the
    // tracees instead of leaving them frozen. Port of the sigaltstack +
    // rt_sigaction loop in `ListerThread`.
    SIG_PIDS.store(pids.as_mut_ptr(), Ordering::SeqCst);
    SIG_NUM_THREADS.store(0, Ordering::SeqCst);
    let mut altstack_mem = [0u8; ALT_STACK_SIZE];
    install_crash_handlers(&mut altstack_mem);

    let proc = match c_open(&task_cstr, O_RDONLY | O_DIRECTORY) {
        Ok(fd) => fd as c_int,
        Err(e) => {
            let _ = sys::close(marker);
            return fail(params, e);
        }
    };

    // Multi-pass scan: keep iterating until a full pass adds no new threads.
    let mut dirbuf = [0u8; PAGE_SIZE];
    loop {
        let mut added = 0usize;
        // Rewind to start of directory for this pass.
        let _ = sys::lseek(proc, 0, 0 /* SEEK_SET */);
        loop {
            let n = match unsafe {
                sys::getdents(proc, dirbuf.as_mut_ptr() as *mut c_void, dirbuf.len())
            } {
                Ok(0) => break,
                Ok(n) => n,
                Err(EINTR) => continue,
                Err(e) => {
                    let _ = sys::close(proc);
                    let _ = sys::close(marker);
                    resume_all_process_threads(&pids[..num_threads]);
                    return fail(params, e);
                }
            };
            // Walk dirents in the buffer.
            let mut off = 0usize;
            while off < n {
                // SAFETY: dirent lies within the filled portion of dirbuf.
                let dirent = unsafe { &*(dirbuf.as_ptr().add(off) as *const KernelDirent) };
                let reclen = dirent.d_reclen as usize;
                if dirent.d_ino != 0
                    && let Some(pid) = parse_tid(&dirent.d_name)
                    && pid != 0
                    && pid != clone_tid
                    && !pids[..num_threads].contains(&pid)
                    && thread_shares_address_space(pid, marker, &marker_sb)
                {
                    if num_threads >= MAX_THREADS {
                        // Overflow: report rather than truncate silently.
                        let _ = sys::close(proc);
                        let _ = sys::close(marker);
                        resume_all_process_threads(&pids[..num_threads]);
                        return fail(params, ENOMEM);
                    }
                    if attach_and_verify(pid) {
                        pids[num_threads] = pid;
                        num_threads += 1;
                        // Keep the crash-cleanup count in sync so the handler
                        // sees every tracee currently attached.
                        SIG_NUM_THREADS.store(num_threads, Ordering::SeqCst);
                        if pid == ppid {
                            found_parent = true;
                        }
                        added += 1;
                    }
                }
                if reclen == 0 {
                    break;
                }
                off += reclen;
            }
        }
        if added == 0 {
            break;
        }
    }

    let _ = sys::close(proc);
    let _ = sys::close(marker);

    if !found_parent {
        // Almost certainly being debugged; an incomplete dump is worse than an
        // error. Resume and report.
        clear_crash_state();
        resume_all_process_threads(&pids[..num_threads]);
        return 3;
    }

    // Invoke the callback with all threads frozen.
    let rc = (params.callback)(params.parameter, pids.as_ptr(), num_threads as c_int);
    params.result = rc;
    params.err = 0;

    // Past the dangerous window - stop the crash handler from touching the pid
    // list, then resume. Deviation from C: the lister always owns resume, and
    // resuming is normal, not an error. (The C flags EINVAL if its safety-net
    // resume had to do anything - a footgun we drop.)
    clear_crash_state();
    resume_all_process_threads(&pids[..num_threads]);

    // Fork-snapshot path: if the callback forked a copy-on-write child to write
    // the core (so we could resume the siblings above without waiting for the
    // whole dump), reap it now - before this lister exits, so the child is
    // collected by its real parent rather than reparenting and racing the
    // caller's `wait4`. The child reports success/failure only through its exit
    // status (its writes to the COW copy of the caller's context do not
    // propagate back), so we fold that status into `params` here.
    let child = SNAPSHOT_CHILD.swap(0, Ordering::SeqCst);
    if child > 0 {
        reap_snapshot_child(params, child);
    }
    0
}

/// Reap the fork-snapshot child and translate its exit status into the dump
/// result. Sets `params.result`/`params.err` on failure; leaves them as the
/// callback set them (result 0) on success. A clean `exit(0)` is success;
/// anything else (non-zero exit or death by signal, e.g. SIGSEGV mid-write) maps
/// to `EFAULT`, mirroring the lister's own status decode in the caller.
fn reap_snapshot_child(params: &mut ListerParams, child: c_int) {
    let mut status: c_int = 0;
    loop {
        match unsafe { sys::wait4(child, &mut status, WALL, ptr::null_mut()) } {
            Ok(_) => break,
            Err(EINTR) => continue,
            Err(errno) => {
                params.result = -1;
                params.err = errno;
                return;
            }
        }
    }
    let ok = (status & 0x7f) == 0 && ((status >> 8) & 0xff) == 0;
    if !ok {
        params.result = -1;
        params.err = EFAULT;
    }
}

/// Stop the crash handler from acting on the (about-to-be-resumed) pid list.
fn clear_crash_state() {
    SIG_PIDS.store(ptr::null_mut(), Ordering::SeqCst);
    SIG_NUM_THREADS.store(0, Ordering::SeqCst);
}

/// Publish the pid of a fork-snapshot child for the lister to reap after it
/// resumes the siblings. Called by the dump callback in the fork parent.
pub fn set_snapshot_child(pid: c_int) {
    SNAPSHOT_CHILD.store(pid, Ordering::SeqCst);
}

/// Disarm the inherited crash-cleanup state in a freshly forked snapshot child.
///
/// The child inherits the armed `SIG_PIDS`/`SIG_NUM_THREADS` list and the
/// sync-signal handlers from the lister. It does not trace those siblings, so
/// the handler's `ptrace` ops would merely fail with `ESRCH` - but they would
/// also mask the real fault status the lister needs to see. Clearing the list
/// the first thing in the child neutralizes the handler; a subsequent genuine
/// fault then produces a clean death status. Exposed for `crate::lib`.
pub fn disarm_crash_state() {
    clear_crash_state();
}

/// Store an errno-style failure in the lister parameter block.
fn fail(params: &mut ListerParams, err: i32) -> c_int {
    params.result = -1;
    params.err = err;
    1
}

/// Decode the lister's wait status into the shared parameter block.
fn decode_lister_status(status: c_int, params: &mut ListerParams) {
    // Unlike the original C, exit code 1 means fail() already stored a precise
    // errno in the shared parameter block; keep that diagnostic intact.
    if status & 0x7f == 0 {
        // WIFEXITED
        match (status >> 8) & 0xff {
            0 => {}
            1 => {
                if params.err == 0 {
                    params.err = ECHILD;
                }
                params.result = -1;
            }
            2 => {
                params.err = EFAULT;
                params.result = -1;
            }
            3 => {
                params.err = EPERM; // already traced
                params.result = -1;
            }
            _ => {
                params.err = ECHILD;
                params.result = -1;
            }
        }
    } else {
        params.err = EFAULT; // killed by signal
        params.result = -1;
    }
}

/// PTRACE_ATTACH + wait + PEEKDATA verification that the tracee truly shares our
/// address space. Returns true if the thread is now attached and verified.
fn attach_and_verify(pid: c_int) -> bool {
    // Attach (suspends the thread).
    if unsafe { sys::ptrace(PTRACE_ATTACH, pid, ptr::null_mut(), ptr::null_mut()) }.is_err() {
        return false;
    }
    // Wait for the stop.
    loop {
        match unsafe { sys::wait4(pid, ptr::null_mut(), WALL, ptr::null_mut()) } {
            Ok(_) => break,
            Err(EINTR) => continue,
            Err(_) => {
                let _ = sys::ptrace_detach(pid);
                return false;
            }
        }
    }
    // PEEKDATA cross-check: confirm the tracee really shares our address space
    // (not a forked child that coincidentally exposes the same marker inode).
    //
    // The raw `ptrace(PEEKDATA, pid, addr=&i, data=&j)` reads the tracee's word
    // at address `&i` and stores it to our `j`. Because the VM is shared, `&i`
    // denotes the same memory in both, so after the peek `j == i`. The C does
    // `i++ != j` then `i != j`: compare current i to the just-read j (equal),
    // increment i, peek again (now reads the new i into j), compare again
    // (equal). A distinct address space breaks the equality.
    let mut i: i64 = 0;
    let mut j: i64 = 0;
    let peek1 = unsafe {
        sys::ptrace(
            PTRACE_PEEKDATA,
            pid,
            &mut i as *mut i64 as *mut c_void,
            &mut j as *mut i64 as *mut c_void,
        )
    };
    if peek1.is_err() || i != j {
        let _ = sys::ptrace_detach(pid);
        return false;
    }
    i = i.wrapping_add(1);
    let peek2 = unsafe {
        sys::ptrace(
            PTRACE_PEEKDATA,
            pid,
            &mut i as *mut i64 as *mut c_void,
            &mut j as *mut i64 as *mut c_void,
        )
    };
    if peek2.is_err() || i != j {
        let _ = sys::ptrace_detach(pid);
        return false;
    }
    true
}

/// Check `/proc/<tid>/fd/<marker>` resolves to the same inode as our own marker
/// socket, i.e. the candidate thread shares our fd table (and thus our VM). Port
/// of the marker-stat check. The marker fd number is identical across threads
/// because they share the fd table, so we stat the same `marker` fd under each
/// candidate tid's `/proc` entry and compare inodes.
fn thread_shares_address_space(tid: c_int, marker: c_int, marker_sb: &KernelStat) -> bool {
    let mut path = [0u8; 64];
    let mut len = build_path(&mut path, &[b"/proc/"], Some(tid));
    len += build_path(&mut path[len..], &[b"/fd/"], Some(marker));
    let cstr = nul_terminate(&path, len);
    let mut sb = KernelStat::zeroed();
    if unsafe { sys::stat(cstr.as_ptr() as *const c_char, &mut sb) }.is_err() {
        return false;
    }
    sb.st_ino == marker_sb.st_ino
}

/// Parse a `/proc/<n>/task` entry name into a tid, skipping a leading '.' some
/// kernels prepend. Returns None if not numeric.
fn parse_tid(dname: &[u8]) -> Option<c_int> {
    let mut s = dname;
    if s.first() == Some(&b'.') {
        s = &s[1..];
    }
    // Find NUL terminator.
    let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    let s = &s[..end];
    if s.is_empty() || !s[0].is_ascii_digit() {
        return None;
    }
    Some(local_atoi(s))
}

/// NUL-terminate a path prefix into a fixed buffer for syscall use.
fn nul_terminate(src: &[u8], len: usize) -> [u8; NUL_TERMINATED_PATH_LEN] {
    let mut out = [0u8; NUL_TERMINATED_PATH_LEN];
    let n = len.min(MAX_NUL_TERMINATED_PATH_PREFIX);
    out[..n].copy_from_slice(&src[..n]);
    out[n] = 0;
    out
}

/// Enumerate and suspend all threads, invoking `callback` with the frozen tids.
/// Port of `ListAllProcessThreads`. Returns the callback's result, or -1 on
/// error (with `errno`-style code available via the returned `Err`).
///
/// `lister_stack` must be a writable region used as the lister thread's stack
/// (we pick the top and align it). Provided by the caller so this stays
/// allocation-free at the call site; see [`with_mmap_stack`] for the common
/// case.
///
/// # Safety
/// Clones a thread sharing this address space; `callback` runs with all other
/// threads ptrace-stopped and must obey the no-libc-locks rule.
///
/// # Errors
/// Returns an errno-style code if cloning, signal masking, waiting, or lister
/// setup fails.
pub unsafe fn list_all_process_threads(
    parameter: *mut c_void,
    callback: ThreadCallback,
    lister_stack: *mut c_void,
) -> Result<c_int, i32> {
    // Make the process dumpable so we can ptrace after setuid.
    let dumpable = unsafe { sys::prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) }.unwrap_or(0);
    if dumpable == 0 {
        let _ = unsafe { sys::prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) };
    }

    let mut params = ListerParams {
        result: -1,
        err: 0,
        callback,
        parameter,
    };

    // Block all async signals (keep sync signals deliverable) before cloning.
    let mut blocked = KernelSigset::empty();
    blocked.fill();
    for &s in LISTER_CRASH_SIGNALS.iter() {
        blocked.del(s);
    }
    let mut old = KernelSigset::empty();
    if let Err(errno) =
        unsafe { sys::rt_sigprocmask(SIG_BLOCK, &blocked, &mut old, sys::SIGSET_SIZE) }
    {
        restore_dumpable(dumpable);
        return Err(errno);
    }

    // Clone the lister onto its dedicated stack.
    let clone_ret = unsafe {
        clone(
            lister_thread,
            lister_stack,
            CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_UNTRACED,
            &mut params as *mut ListerParams as *mut c_void,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    let clone_pid = corus_syscall::from_ret(clone_ret);

    // Allow the lister to ptrace us under YAMA.
    if let Ok(cp) = clone_pid {
        let _ = unsafe { sys::prctl(PR_SET_PTRACER, cp, 0, 0, 0) };
    }

    // Restore the signal mask.
    let _ = unsafe { sys::rt_sigprocmask(SIG_SETMASK, &old, &mut old, sys::SIGSET_SIZE) };

    match clone_pid {
        Err(e) => {
            restore_dumpable(dumpable);
            return Err(e);
        }
        Ok(cp) => {
            // Reap the lister.
            let mut status: c_int = 0;
            loop {
                match unsafe { sys::wait4(cp as c_int, &mut status, WALL, ptr::null_mut()) } {
                    Ok(_) => break,
                    Err(EINTR) => continue,
                    Err(e) => {
                        params.err = e;
                        params.result = -1;
                        break;
                    }
                }
            }
            decode_lister_status(status, &mut params);
        }
    }

    restore_dumpable(dumpable);

    if params.result == -1 {
        Err(params.err)
    } else {
        Ok(params.result)
    }
}

/// Restore the process dumpable flag if this module changed it.
fn restore_dumpable(dumpable: usize) {
    if dumpable == 0 {
        let _ = unsafe { sys::prctl(PR_SET_DUMPABLE, dumpable, 0, 0, 0) };
    }
}

/// Single-threaded fallback - port of the default `ListAllProcessThreads` in
/// `thread_lister.c`. Used when the multi-threaded lister is unavailable or the
/// process is known single-threaded: make the process dumpable and invoke the
/// callback with just our own pid (no suspension needed - there are no siblings
/// to freeze).
///
/// # Safety
/// `callback` runs synchronously in the calling thread; the usual no-libc-locks
/// rule is relaxed here since nothing is ptrace-stopped, but the dump engine
/// should still behave as if it were.
pub unsafe fn list_self_only(parameter: *mut c_void, callback: ThreadCallback) -> c_int {
    let dumpable = unsafe { sys::prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) }.unwrap_or(0);
    if dumpable == 0 {
        let _ = unsafe { sys::prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) };
    }
    let pid = sys::getpid().map(|p| p as c_int).unwrap_or(0);
    let rc = callback(parameter, &pid as *const c_int, 1);
    restore_dumpable(dumpable);
    rc
}

/// Path-scratch bytes the lister uses (`marker_name`, `task_path`, and the
/// `nul_terminate` buffers are each at most [`NUL_TERMINATED_PATH_LEN`] bytes;
/// one page covers them comfortably).
pub const LISTER_PATH_SCRATCH: usize = PAGE_SIZE;

/// Headroom for the lister's own call frames / register spills (`getdents`
/// walk, `attach_and_verify`). Estimated; small relative to `pids[]`.
pub const LISTER_FRAME_HEADROOM: usize = 16384;

/// Extra slack added on top of the lister + callback footprint, as a guard
/// against frame-overhead underestimation. One page would do; we keep more.
pub const LISTER_STACK_SLACK: usize = 65536;

/// Stack bytes the lister thread itself needs for its own frames, beyond
/// whatever the callback consumes. Dominated by `pids: [i32; MAX_THREADS]`, plus
/// the alternate signal stack, the `dirbuf` page, path scratch, and frame
/// headroom.
pub const LISTER_OWN_STACK: usize = MAX_THREADS * mem::size_of::<c_int>() // pids[]
    + ALT_STACK_SIZE            // altstack_mem
    + PAGE_SIZE                 // dirbuf
    + LISTER_PATH_SCRATCH
    + LISTER_FRAME_HEADROOM;

/// Compute the lister stack size needed when the callback consumes
/// `callback_stack` bytes of its own. Adds the lister's own footprint
/// ([`LISTER_OWN_STACK`]) and [`LISTER_STACK_SLACK`], rounded up to a page
/// boundary. Derived from real buffer sizes so it can't silently drift when the
/// caps change.
pub const fn lister_stack_size(callback_stack: usize) -> usize {
    let raw = LISTER_OWN_STACK + callback_stack + LISTER_STACK_SLACK;
    (raw + (PAGE_SIZE - 1)) & !(PAGE_SIZE - 1)
}

/// Convenience wrapper that mmaps a lister stack sized for a callback needing
/// `callback_stack` bytes, runs [`list_all_process_threads`], and unmaps.
///
/// Pass the callback's own worst-case stack footprint (see
/// [`lister_stack_size`]); the wrapper adds the lister's own frames and slack.
/// The dump orchestrator uses [`crate::dump::DUMP_CALLBACK_STACK`].
///
/// # Safety
/// See [`list_all_process_threads`].
///
/// # Errors
/// Returns an errno-style code if stack mapping, thread listing, or stack
/// unmapping fails.
pub unsafe fn with_mmap_stack(
    parameter: *mut c_void,
    callback: ThreadCallback,
    callback_stack: usize,
) -> Result<c_int, i32> {
    let stack_size = lister_stack_size(callback_stack);
    const PROT_READ: c_int = 1;
    const PROT_WRITE: c_int = 2;
    const MAP_PRIVATE: c_int = 2;
    const MAP_ANONYMOUS: c_int = 0x20;
    const MAP_STACK: c_int = 0x20000;

    let base = unsafe {
        sys::mmap(
            ptr::null_mut(),
            stack_size,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
            -1,
            0,
        )
    }?;
    let top = (base + stack_size) as *mut c_void;
    let result = unsafe { list_all_process_threads(parameter, callback, top) };
    let _ = unsafe { sys::munmap(base as *mut c_void, stack_size) };
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    extern "C" fn unused_callback(_param: *mut c_void, _pids: *const c_int, _num: c_int) -> c_int {
        0
    }

    fn test_params(result: c_int, err: i32) -> ListerParams {
        ListerParams {
            result,
            err,
            callback: unused_callback,
            parameter: ptr::null_mut(),
        }
    }

    #[test]
    fn itoa_roundtrips() {
        let mut buf = [0u8; 16];
        let n = local_itoa(&mut buf, 12345);
        assert_eq!(&buf[..n], b"12345");
        let n = local_itoa(&mut buf, 0);
        assert_eq!(&buf[..n], b"0");
        let n = local_itoa(&mut buf, -42);
        assert_eq!(&buf[..n], b"-42");
    }

    #[test]
    fn atoi_parses() {
        assert_eq!(local_atoi(b"12345"), 12345);
        assert_eq!(local_atoi(b"0"), 0);
        assert_eq!(local_atoi(b"-42"), -42);
        assert_eq!(local_atoi(b"7abc"), 7);
    }

    #[test]
    fn parse_tid_skips_dot_and_nonnumeric() {
        assert_eq!(parse_tid(b"1234\0"), Some(1234));
        assert_eq!(parse_tid(b".5678\0"), Some(5678));
        assert_eq!(parse_tid(b"cgroup\0"), None);
        assert_eq!(parse_tid(b"\0"), None);
    }

    #[test]
    fn lister_status_exit_1_preserves_recorded_errno() {
        // Exit code 1 is the lister's fail() path: the precise errno was
        // already written into shared ListerParams and must not be replaced by
        // the parent's generic ECHILD fallback.
        let mut params = test_params(-1, corus_syscall::linux::EINVAL);

        decode_lister_status(1 << 8, &mut params);

        assert_eq!(params.result, -1);
        assert_eq!(params.err, corus_syscall::linux::EINVAL);
    }

    #[test]
    fn lister_status_exit_1_with_zero_errno_falls_back_to_echild() {
        // A zero errno on the fail() path would be malformed, but still report
        // a real failure errno rather than returning a failure with errno 0.
        let mut params = test_params(0, 0);

        decode_lister_status(1 << 8, &mut params);

        assert_eq!(params.result, -1);
        assert_eq!(params.err, ECHILD);
    }

    #[test]
    fn lister_status_keeps_existing_coarse_mappings() {
        // The errno-preservation fix is only for fail()'s exit code 1. The
        // special parent-owned mappings for fault cleanup, already-traced, and
        // signal death must stay coarse and unchanged.
        let mut fault_params = test_params(0, 0);
        decode_lister_status(2 << 8, &mut fault_params);
        assert_eq!(fault_params.result, -1);
        assert_eq!(fault_params.err, EFAULT);

        let mut traced_params = test_params(0, 0);
        decode_lister_status(3 << 8, &mut traced_params);
        assert_eq!(traced_params.result, -1);
        assert_eq!(traced_params.err, EPERM);

        let mut signal_params = test_params(0, 0);
        decode_lister_status(SIGSEGV, &mut signal_params);
        assert_eq!(signal_params.result, -1);
        assert_eq!(signal_params.err, EFAULT);
    }
}
