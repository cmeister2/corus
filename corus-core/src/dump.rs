//! Dump orchestration - port of `InternalGetCoreDump` from `elfcore.c`.
//!
//! This is the glue that runs *inside the lister thread's callback*
//! ([`crate::threads`]) with all target threads ptrace-stopped. It captures each
//! thread's registers, builds PRPSINFO, parses the memory map, and streams the
//! core via [`crate::elfcore::CoreInputs::create_elf_core`].
//!
//! Capacity is fixed (no allocation on the dump path): up to [`MAX_DUMP_THREADS`]
//! threads and [`crate::proc_parse::MAX_MAPPINGS`] mappings.
//!
//! ## Capture vs. serialize split (fork-snapshot)
//!
//! The dump is split into two phases so the caller can resume the suspended
//! siblings as early as possible:
//!
//! - [`capture_dump`] does the work that *requires* the threads frozen and the
//!   ptrace tracer relationship - per-thread registers, the FRAME() override,
//!   AUXV, and PRPSINFO (process identity). It must run before any `fork`.
//! - [`serialize_dump`] parses `/proc/self/maps` and streams the ELF core by
//!   reading this process's own memory. `dump_callback` runs it in a
//!   copy-on-write `fork` child, so the siblings can resume immediately while
//!   the child writes against a frozen-in-amber snapshot of the address space.
//!
//! `dump_callback` (this module) is the lister entry point that drives the
//! sequence: capture (frozen) -> `fork` -> serialize in the child; on `fork`
//! failure it serializes in-line with the siblings still frozen. The public
//! entry points in `crate::lib` construct the `DumpCtx` and pass `dump_callback`
//! to the lister. [`dump_core`]/[`dump_core_with`] are the standalone
//! capture-then-serialize path (no fork) for direct callers and tests.
//!
//! ### Semantic deviations of the COW snapshot
//!
//! Reading memory from a `fork` child instead of the live frozen process changes
//! the meaning of the dump in a few cases:
//!
//! - **`MAP_SHARED` segments** are no longer point-in-time consistent with the
//!   captured registers: the child shares the underlying object, so a resumed
//!   host thread can mutate it before the child reads it. (Usually fine - shared
//!   regions are typically files or IPC, not the heap/stack a backtrace needs.)
//! - **`MADV_DONTFORK` mappings vanish** from the child and **`MADV_WIPEONFORK`
//!   mappings read as zero**, so such regions drop out of or are blanked in the
//!   core. The in-line fallback still captures them.
//! - **Huge (`MAP_HUGETLB`) processes** can make the `fork` page-table copy slow
//!   or fail with `ENOMEM` - exactly the large processes this path optimizes.
//!   On `fork` failure the dump falls back to the in-line frozen write, so
//!   correctness is preserved even though the latency win is not.

use core::ffi::{c_char, c_int, c_void};
use core::mem::{self, MaybeUninit};
use core::ptr;
use core::slice;

use corus_syscall::{arch, arch::PAGE_SIZE, linux::O_RDONLY, sys};

use crate::elf::{AuxvT, CoreUser, FpRegs, Prpsinfo, Regs};
use crate::elfcore::{CoreInputs, CreateElfCoreError, ThreadState};
use crate::io::{LimitWriter, Pipe, SimpleWriter, Writer};
use crate::proc_parse::{
    MAX_MAPPINGS, Mapping, ParseMapsError, finalize_mappings, mapping_buf, parse_self_maps,
};

/// Max auxv entries captured for the NT_AUXV note.
pub const MAX_AUXV: usize = 64;

/// Max threads whose registers we capture in one dump. The register array lives
/// on the lister's stack, so this is sized for realistic processes (not the
/// 4096 mapping cap, which would blow the stack - see [`DUMP_CALLBACK_STACK`]).
pub const MAX_DUMP_THREADS: usize = 512;

/// Size of the scratch page used by the leading-zeros segment scan. Must be at
/// least one page; also the buffer size passed to `finalize_mappings`.
pub const SCRATCH_LEN: usize = PAGE_SIZE;

/// Size of the buffer holding the `/proc/self/exe` readlink result for
/// `pr_fname`.
pub const EXE_PATH_LEN: usize = 256;

/// Slack added to the buffer total to cover the call frames and register spills
/// of `dump_core` -> `CoreInputs::create_elf_core` / `build_prpsinfo`. Estimated (the
/// compiler's exact per-frame size isn't available as a `const`); generous
/// relative to the buffer terms, which dominate the footprint.
pub const FRAME_HEADROOM: usize = 8192;

/// Worst-case stack footprint of [`dump_core`] (the lister callback), derived
/// from the actual fixed buffers it places on the stack. Pass this to
/// [`crate::threads::with_mmap_stack`] so the lister stack is sized exactly,
/// not guessed. If a cap below grows, this grows with it - no magic number to
/// keep in sync.
pub const DUMP_CALLBACK_STACK: usize = MAX_DUMP_THREADS * mem::size_of::<ThreadState>() // threads[]
    + MAX_MAPPINGS * mem::size_of::<Mapping>()  // maps[]
    + MAX_AUXV * mem::size_of::<AuxvT>()        // auxv[]
    + SCRATCH_LEN
    + EXE_PATH_LEN
    + FRAME_HEADROOM;

/// `getpriority(2)` selector for process priority.
const PRIO_PROCESS: i32 = 0;

/// A user-supplied ELF note to emit in the PT_NOTE section (engine-side mirror
/// of the C `CoredumperNote`). Borrows the name/description from the caller.
#[derive(Clone, Copy)]
pub struct ExtraNote<'a> {
    /// Note owner/name bytes, without the trailing NUL.
    pub name: &'a [u8],
    /// ELF note type value.
    pub note_type: u32,
    /// Note descriptor payload bytes.
    pub description: &'a [u8],
}

/// A pre-dump callback invoked after threads are suspended and before the core
/// is built. Returning a non-zero value aborts the dump (no file written),
/// mirroring the C `callback_fn`. The pointer/userdata shape matches the C ABI
/// so both APIs lower to it identically. `unsafe` because it invokes
/// caller-provided code that runs while threads are ptrace-stopped.
pub type DumpCallback = unsafe extern "C" fn(arg: *mut c_void) -> i32;

/// How the dump freezes the process while it writes the core.
///
/// The two strategies trade pause length against fidelity and dependencies. The
/// default ([`ForkSnapshot`](DumpStrategy::ForkSnapshot)) minimizes the pause;
/// [`InProcessFrozen`](DumpStrategy::InProcessFrozen) preserves the strict
/// pre-fork semantics. They produce the same core for ordinary private,
/// anonymous and file-backed read-only mappings - they differ only for the
/// mapping kinds noted below.
#[derive(Default, Clone, Copy, Debug, Eq, PartialEq)]
pub enum DumpStrategy {
    /// Capture registers while the siblings are frozen, `fork` a copy-on-write
    /// snapshot, resume the siblings immediately, and stream the core from the
    /// snapshot child. The pause is just register capture + `fork` (proportional
    /// to thread count), not the whole write. This is the default.
    ///
    /// If `fork` fails (e.g. `ENOMEM` copying page tables for a huge process)
    /// the dump transparently falls back to
    /// [`InProcessFrozen`](DumpStrategy::InProcessFrozen), so a fork failure
    /// costs latency, not correctness.
    ///
    /// Trade-off: the snapshot is a COW child, so `MAP_SHARED` segments may be
    /// mutated by the resumed host before the child reads them, `MADV_DONTFORK`
    /// regions are absent from the snapshot, and `MADV_WIPEONFORK` regions read
    /// as zero.
    #[default]
    ForkSnapshot,
    /// Keep every sibling ptrace-stopped for the *entire* write - no `fork`,
    /// no COW snapshot. The pause scales with resident memory and output
    /// throughput (the pre-fork behavior).
    ///
    /// Choose this for: strict old semantics (`MAP_SHARED` / `MADV_DONTFORK` /
    /// `MADV_WIPEONFORK` captured from the live frozen process); deterministic
    /// "everything stayed frozen until the write completed" behavior in tests;
    /// bisecting dump bugs; and environments where `fork` is undesirable even
    /// when it would otherwise succeed.
    InProcessFrozen,
}

/// Options controlling a dump. `Default` is an unlimited, uncompressed dump with
/// no extra notes or callback, using the default [`DumpStrategy`] - equivalent
/// to `ClearCoreDumpParameters`.
#[derive(Default, Clone, Copy)]
pub struct DumpOptions<'a> {
    /// How to freeze the process while writing the core. Defaults to
    /// [`DumpStrategy::ForkSnapshot`].
    pub strategy: DumpStrategy,
    /// Truncate output at this many bytes (`COREDUMPER_FLAG_LIMITED`). `None` =
    /// unlimited.
    pub max_length: Option<usize>,
    /// Drop the largest segments first to fit `max_length`
    /// (`COREDUMPER_FLAG_LIMITED_BY_PRIORITY`). Requires `max_length`.
    pub prioritize: bool,
    /// Extra notes to append to the PT_NOTE section.
    pub notes: &'a [ExtraNote<'a>],
    /// Pre-dump callback + its userdata argument.
    pub callback: Option<(DumpCallback, *mut c_void)>,
    /// Caller's register snapshot (FRAME()): when the dumping thread is the one
    /// that called the public API, its ptrace-captured registers point into the
    /// dump machinery (parked in `wait4`). Overriding them with the snapshot
    /// taken at API entry makes the dumped thread's backtrace top out at the
    /// caller (`WriteCoreDump` -> user code), matching the C `SET_FRAME`.
    /// `(tid, regs)`: applied to the thread whose pid == `tid`.
    pub frame: Option<(i32, Regs)>,
}

/// Error returned while building a core from already-suspended threads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DumpError {
    /// Unknown dump failure after the lister callback returned failure.
    Unknown,
    /// Pre-dump callback returned non-zero and requested abort.
    CallbackAborted,
    /// `PTRACE_GETREGS` failed for this thread with the kernel errno.
    PtraceGetRegs {
        /// Thread id whose registers could not be captured.
        pid: i32,
        /// Kernel errno returned by ptrace.
        errno: i32,
    },
    /// Parsing `/proc/self/maps` failed.
    ParseMaps(ParseMapsError),
    /// Creating the loopback pipe failed with this errno.
    Pipe(i32),
    /// ELF core assembly failed at this stage.
    CreateElfCore(CreateElfCoreError),
}

/// Build a core file for the already-suspended threads in `pids`, streaming it
/// through `w`. `main_pid` is the thread to dump first (the faulting thread).
///
/// # Errors
/// Returns the dump stage that failed. The function remains allocation-free and
/// uses small `Copy` errors suitable for `no_std`.
///
/// # Safety
/// Must run while `pids` are ptrace-stopped (typically from the
/// [`crate::threads`] lister callback). Reads this process's own memory while
/// streaming segments; the address space must be stable for the duration.
pub unsafe fn dump_core(w: &mut dyn Writer, pids: &[i32], main_pid: i32) -> Result<(), DumpError> {
    unsafe { dump_core_with(w, pids, main_pid, &DumpOptions::default()) }
}

/// As [`dump_core`], honoring [`DumpOptions`] (priority limiting, extra notes,
/// pre-dump callback).
///
/// # Errors
/// Returns the dump stage that failed. The function remains allocation-free and
/// uses small `Copy` errors suitable for `no_std`.
///
/// # Safety
/// See [`dump_core`]. If `opts.callback` is set it is invoked here, with all
/// threads still suspended, so it must obey the no-libc-locks rule.
pub unsafe fn dump_core_with(
    w: &mut dyn Writer,
    pids: &[i32],
    main_pid: i32,
    opts: &DumpOptions,
) -> Result<(), DumpError> {
    // Capture (needs frozen threads + ptrace) then serialize, both in this
    // thread with the siblings frozen for the whole write. `dump_callback` (the
    // fork-snapshot path) instead calls these two halves separately so it can
    // resume the siblings between them; this wrapper is the single-shot path for
    // direct callers and tests.
    //
    // Build `CapturedDump` in place (it is large; a zeroed temporary would
    // double it on the stack - see `capture_dump`).
    let mut cap = MaybeUninit::<CapturedDump>::uninit();
    unsafe { capture_dump(cap.as_mut_ptr(), pids, main_pid, opts) }?;
    // SAFETY: capture_dump returned Ok, so every field is initialized.
    unsafe { serialize_dump(w, cap.assume_init_ref(), opts) }
}

/// State captured from the frozen, ptrace-stopped threads - everything that
/// strictly requires the suspension + tracer relationship, and nothing that
/// reads the (about-to-resume) memory image. This is the hand-off between the
/// `capture` phase (runs with siblings frozen, before any `fork`) and the
/// `serialize` phase (runs in the COW snapshot child, or in-line on fallback).
///
/// It is large - dominated by `threads` - and is meant to live on the lister
/// stack, exactly where the previous monolithic `dump_core_with` placed the same
/// arrays. It rides into the snapshot child for free via copy-on-write memory;
/// there is no allocation.
pub struct CapturedDump {
    /// Per-thread register snapshots (GP + FP) for the PRSTATUS/PRFPREG notes.
    pub threads: [ThreadState; MAX_DUMP_THREADS],
    /// Number of valid entries in `threads`.
    pub n_threads: usize,
    /// Index into `threads` of the main (faulting) thread.
    pub main_idx: usize,
    /// Captured AUXV entries for the NT_AUXV note.
    pub auxv: [AuxvT; MAX_AUXV],
    /// Number of valid entries in `auxv`.
    pub n_auxv: usize,
    /// PRPSINFO built from the dumping process's own identity (must be captured
    /// pre-fork: in the snapshot child `getpid`/`getppid`/`getsid` would report
    /// the child, not the process being dumped).
    pub prpsinfo: Prpsinfo,
    /// The main thread's pid (the dumping process's pid), captured pre-fork.
    pub main_pid: i32,
}

/// Capture per-thread registers, AUXV, and PRPSINFO while the threads in `pids`
/// are ptrace-stopped. This is the only work that requires the threads frozen
/// and the ptrace tracer relationship, so it must run before any `fork` that
/// resumes them.
///
/// # Errors
/// Returns the failing stage (pre-dump callback abort, or `PTRACE_GETREGS`).
///
/// # Safety
/// Must run while `pids` are ptrace-stopped by the calling thread (the lister),
/// since the tracer relationship is per-task and not inherited across `fork`.
/// `cap` must point to writable, properly aligned storage for one
/// `CapturedDump`; it may be uninitialized. This function fully initializes
/// `*cap` (zeroing it first, then filling it) regardless of success, so on
/// return - `Ok` or `Err` - the whole struct is initialized.
pub unsafe fn capture_dump(
    cap: *mut CapturedDump,
    pids: &[i32],
    main_pid: i32,
    opts: &DumpOptions,
) -> Result<(), DumpError> {
    // Zero the whole struct in place first, so *every* field is initialized -
    // including the unused tail of `threads` past `n_threads`, which the loop
    // below never writes. `CapturedDump` is plain data (integers and register
    // byte-arrays), so all-zero is a valid value. Doing this through the pointer
    // (rather than `*cap = mem::zeroed()`) avoids forming a reference to
    // uninitialized memory and avoids a second full-size copy on the lister's
    // fixed stack, which would overflow it.
    unsafe { ptr::write_bytes(cap as *mut u8, 0, mem::size_of::<CapturedDump>()) };
    // SAFETY: every byte is now initialized to a valid `CapturedDump`.
    let cap = unsafe { &mut *cap };

    // Pre-dump callback: abort the whole dump if it returns non-zero. Runs here,
    // with threads suspended, matching the C contract.
    if let Some((cb, arg)) = opts.callback {
        // SAFETY: caller-provided C function; invoked here per the C contract
        // with threads suspended. It must be async-signal-safe.
        if unsafe { cb(arg) } != 0 {
            return Err(DumpError::CallbackAborted);
        }
    }

    // --- Capture per-thread registers via ptrace (threads already stopped) ---
    let n_threads = pids.len().min(MAX_DUMP_THREADS);
    let mut main_idx = 0usize;

    for (i, &pid) in pids.iter().take(n_threads).enumerate() {
        let mut regs: Regs = unsafe { mem::zeroed() };
        let mut fpregs: FpRegs = unsafe { mem::zeroed() };
        if let Err(errno) = unsafe {
            arch::ptrace_get_gpregs(
                pid,
                &mut regs as *mut Regs as *mut c_void,
                mem::size_of::<Regs>(),
            )
        } {
            return Err(DumpError::PtraceGetRegs { pid, errno });
        }

        // FP registers are best-effort: a failure leaves them zeroed.
        let _ = unsafe {
            arch::ptrace_get_fpregs(
                pid,
                &mut fpregs as *mut FpRegs as *mut c_void,
                mem::size_of::<FpRegs>(),
            )
        };

        // FRAME() override: for the thread that called the public API, replace
        // the ptrace-captured regs (parked in wait4) with the caller's snapshot
        // so the backtrace tops out at WriteCoreDump -> user code. Keep the
        // kernel-only fs_base/gs_base from ptrace, as the C SET_FRAME does.
        if let Some((frame_tid, frame_regs)) = opts.frame
            && pid == frame_tid
        {
            // x86_64 keeps the kernel-only segment bases from ptrace, which
            // capture_frame() cannot read. aarch64 has no such registers, so
            // the captured frame is used as-is.
            #[cfg(target_arch = "x86_64")]
            {
                let mut fr = frame_regs;
                fr.fs_base = regs.fs_base;
                fr.gs_base = regs.gs_base;
                regs = fr;
            }
            #[cfg(target_arch = "aarch64")]
            {
                regs = frame_regs;
            }
        }

        cap.threads[i] = ThreadState { pid, regs, fpregs };
        if pid == main_pid {
            main_idx = i;
        }
    }
    cap.n_threads = n_threads;
    cap.main_idx = main_idx;

    // --- AUXV --- best-effort; failure to read auxv is not fatal.
    cap.n_auxv = read_auxv(&mut cap.auxv).unwrap_or(0);

    // --- PRPSINFO --- built from this process's own identity, pre-fork.
    cap.prpsinfo = build_prpsinfo(main_pid);
    cap.main_pid = main_pid;

    Ok(())
}

/// Parse the memory map, finalize the segment list, and stream the ELF core to
/// `w` from already-captured thread state. Reads this process's own memory for
/// segment contents.
///
/// In the fork-snapshot path this runs in the COW child, so `/proc/self/maps`
/// and the segment reads observe the child's copy-on-write address space - a
/// coherent point-in-time snapshot of the parent at fork. On fork failure it
/// runs in-line in the lister with siblings still frozen.
///
/// # Errors
/// Returns the failing stage (map parse, loopback pipe, or ELF assembly).
///
/// # Safety
/// The address space must be stable for the duration: either the siblings are
/// still frozen (fallback) or this is the COW snapshot child (siblings resumed,
/// but the child's pages are immutable w.r.t. the parent).
pub unsafe fn serialize_dump(
    w: &mut dyn Writer,
    cap: &CapturedDump,
    opts: &DumpOptions,
) -> Result<(), DumpError> {
    // The page size must be the *runtime* kernel page size. On x86_64 that is
    // always 4K, but aarch64 kernels ship 4K/16K/64K, so we cannot use the
    // compile-time `PAGE_SIZE` (its aarch64 value is only a conservative
    // fallback). Read it from AT_PAGESZ in the captured auxv; fall back to
    // `PAGE_SIZE` if the entry is missing or implausible. A wrong page size here
    // miscomputes the leading-zero skip and underflows mapping sizes.
    let pagesize = cap
        .auxv
        .iter()
        .take(cap.n_auxv)
        .find(|e| e.a_type == crate::elf::AT_PAGESZ)
        .map(|e| e.a_val as usize)
        .filter(|&p| p.is_power_of_two())
        .unwrap_or(PAGE_SIZE);

    // --- Memory mappings ---
    let mut maps = mapping_buf();
    let parsed = match parse_self_maps(&mut maps) {
        Ok(n) => n,
        Err(error) => return Err(DumpError::ParseMaps(error)),
    };
    // Loopback pipe + scratch for the leading-zeros safe page scan. Created here
    // (not pre-fork) so its fds stay private to whoever serializes.
    let loopback = match Pipe::new() {
        Ok(pipe) => pipe,
        Err(errno) => return Err(DumpError::Pipe(errno)),
    };
    let mut scratch = [0u8; SCRATCH_LEN];
    let kept = unsafe { finalize_mappings(&mut maps, parsed, pagesize, &loopback, &mut scratch) };

    // Priority limiting: shrink/drop the largest segments first so the whole
    // core fits in max_length (COREDUMPER_FLAG_LIMITED_BY_PRIORITY).
    if opts.prioritize
        && let Some(limit) = opts.max_length
    {
        let header_overhead =
            estimate_header_size(cap.n_threads, cap.n_auxv, &maps[..kept], opts.notes);
        apply_priority_limit(&mut maps[..kept], limit, header_overhead);
    }

    // NT_PRXREG (core_user) for the main thread: carries the GP + FP registers
    // as gdb's fallback. We populate `regs`/`fpregs` from the captured state and
    // leave the auxiliary fields zero (the C fills them via PTRACE_PEEKUSER; not
    // needed for gdb/readelf correctness - a documented follow-up).
    let user = if cap.n_threads > 0 {
        let mut u: CoreUser = unsafe { mem::zeroed() };
        u.regs = cap.threads[cap.main_idx].regs;
        u.fpregs = cap.threads[cap.main_idx].fpregs;
        u.fpvalid = 1;
        Some(u)
    } else {
        None
    };

    let inp = CoreInputs {
        prpsinfo: &cap.prpsinfo,
        threads: &cap.threads[..cap.n_threads],
        main_thread: cap.main_idx,
        auxv: &cap.auxv[..cap.n_auxv],
        mappings: &maps[..kept],
        pagesize,
        notes: opts.notes,
        user: user.as_ref(),
    };

    unsafe { inp.create_elf_core(w) }.map_err(DumpError::CreateElfCore)
}

/// Estimate the non-segment portion of the core (Ehdr + phdrs + note section)
/// the priority limiter must leave room for. Mirrors the C's `offset + filesz`
/// accounting in the prioritization loop, but **deliberately omits the
/// page-alignment padding** between the notes and the first PT_LOAD.
///
/// This makes the estimate a lower bound on the true header size. The
/// prioritized dump still goes through a `LimitWriter` capped at `max_length`
/// (the orchestrator sets it whenever `prioritize` is on), so under-counting
/// here means the computed segment sizes leave the total slightly *above* the
/// limit and the writer performs the exact final byte cut - landing at exactly
/// `max_length`. Over-counting, by contrast, would shrink segments too far and
/// produce a short file (< limit), which is wrong. So we bias low on purpose.
fn estimate_header_size(
    n_threads: usize,
    n_auxv: usize,
    mappings: &[Mapping],
    notes: &[ExtraNote],
) -> usize {
    use crate::elfcore::note_section_size_for;
    let ehdr = mem::size_of::<crate::elf::Ehdr>();
    let phdrs = (mappings.len() + 1) * mem::size_of::<crate::elf::Phdr>();

    // The NT_PRXREG note is emitted whenever there is a main thread.
    let notesz = note_section_size_for(n_threads, n_auxv, mappings, notes, n_threads > 0);

    ehdr + phdrs + notesz
}

/// Reduce `write_size` of the largest mappings until the total core size fits
/// `limit`. Port of the prioritization loop in `CreateElfCore`: repeatedly find
/// the largest segment and shrink it (to zero if needed). `header_overhead` is
/// the fixed Ehdr+phdr+notes cost that segments compete with.
fn apply_priority_limit(mappings: &mut [Mapping], limit: usize, header_overhead: usize) {
    loop {
        let mut total = header_overhead;
        let mut largest: Option<usize> = None;
        for (i, m) in mappings.iter().enumerate() {
            total += m.write_size;
            if largest.is_none_or(|li| mappings[li].write_size < m.write_size) {
                largest = Some(i);
            }
        }
        match largest {
            Some(li) if total > limit && mappings[li].write_size > 0 => {
                let need = total - limit;
                if need > mappings[li].write_size {
                    mappings[li].write_size = 0;
                } else {
                    mappings[li].write_size -= need;
                }
            }
            _ => break,
        }
    }
}

/// Read `/proc/self/auxv` into `out`, returning the entry count (capped).
fn read_auxv(out: &mut [AuxvT]) -> Result<usize, i32> {
    let fd = unsafe { sys::open(c"/proc/self/auxv".as_ptr(), O_RDONLY, 0) }? as i32;
    let mut n = 0usize;
    while n < out.len() {
        let mut entry = AuxvT {
            a_type: 0,
            a_val: 0,
        };
        let r = unsafe {
            sys::read(
                fd,
                &mut entry as *mut AuxvT as *mut c_void,
                mem::size_of::<AuxvT>(),
            )
        };
        match r {
            Ok(sz) if sz == mem::size_of::<AuxvT>() => {
                out[n] = entry;
                n += 1;
                if entry.a_type == 0 {
                    break; // AT_NULL
                }
            }
            _ => break,
        }
    }
    sys::close(fd).ok();
    Ok(n)
}

/// Populate a `Prpsinfo` (NT_PRPSINFO payload) from /proc and syscalls. Port of
/// the PRPSINFO-building block in `InternalGetCoreDump`.
fn build_prpsinfo(main_pid: i32) -> Prpsinfo {
    let mut info: Prpsinfo = unsafe { mem::zeroed() };
    info.pr_sname = b'R' as c_char;
    info.pr_nice = sys::getpriority(PRIO_PROCESS, 0)
        .map(|v| v as i8)
        .unwrap_or(0);
    info.pr_uid = sys::geteuid().map(|v| v as u32).unwrap_or(0);
    info.pr_gid = sys::getegid().map(|v| v as u32).unwrap_or(0);
    info.pr_pid = main_pid;
    info.pr_ppid = sys::getppid().map(|v| v as i32).unwrap_or(0);
    info.pr_sid = sys::getsid(0).map(|v| v as i32).unwrap_or(0);

    // pr_fname: basename of /proc/self/exe.
    let mut exe = [0u8; EXE_PATH_LEN];
    let size = unsafe {
        sys::readlink(
            c"/proc/self/exe".as_ptr(),
            exe.as_mut_ptr() as *mut c_char,
            exe.len(),
        )
    }
    .unwrap_or(0);
    if size > 0 {
        let path = &exe[..size];
        let base = match path.iter().rposition(|&b| b == b'/') {
            Some(i) => &path[i + 1..],
            None => path,
        };
        let cap = base.len().min(info.pr_fname.len());
        for (dst, &b) in info.pr_fname.iter_mut().zip(base.iter()).take(cap) {
            *dst = b as c_char;
        }
    }

    // pr_psargs: /proc/self/cmdline with NULs turned into spaces.
    if let Ok(fd) = unsafe { sys::open(c"/proc/self/cmdline".as_ptr(), O_RDONLY, 0) } {
        let fd = fd as i32;
        let mut buf = [0u8; 80]; // pr_psargs is 80 bytes
        if let Ok(rd) = unsafe { sys::read(fd, buf.as_mut_ptr() as *mut c_void, buf.len()) } {
            for (dst, &b) in info.pr_psargs.iter_mut().zip(buf.iter()).take(rd) {
                *dst = if b == 0 { b' ' as c_char } else { b as c_char };
            }
        }
        sys::close(fd).ok();
    }

    info
}

/// Context passed to the lister callback while threads are suspended.
///
/// Lives here beside the capture/serialize engine because [`dump_callback`] (the
/// lister entry point that drives capture -> fork -> serialize) owns it; the
/// public entry points in `crate::lib` construct it and read back its result.
pub(crate) struct DumpCtx<'a> {
    /// Output file descriptor for the core stream.
    pub(crate) out_fd: c_int,
    /// Dump options shared with the callback.
    pub(crate) opts: &'a DumpOptions<'a>,
    /// Callback result written before threads are resumed.
    pub(crate) result: c_int,
    /// Callback error detail, if available.
    pub(crate) error: Option<DumpError>,
}

impl DumpCtx<'_> {
    /// Build the writer over `out_fd` and stream the core from already-captured
    /// thread state. Returns `true` on success, including the truncation case
    /// where the writer hit `max_length` (truncation is the intended outcome -
    /// mirroring the C's `if (is_done(handle)) rc = 0;`).
    ///
    /// On failure the detail is recorded in `self.error`. That is only observable
    /// in the in-line fallback path: in the fork-snapshot child this write lands
    /// in a copy-on-write copy of the context that is discarded when the child
    /// exits, so the child reports failure through its exit status instead
    /// (decoded by the lister in `crate::threads::reap_snapshot_child`).
    fn run_serialize(&mut self, cap: &CapturedDump) -> bool {
        match self.opts.max_length {
            None => {
                let mut writer = SimpleWriter { fd: self.out_fd };
                let result = unsafe { serialize_dump(&mut writer, cap, self.opts) };
                if let Err(error) = result {
                    self.error = Some(error);
                }
                result.is_ok() || writer.done()
            }
            Some(limit) => {
                let mut writer = LimitWriter {
                    fd: self.out_fd,
                    max_length: limit,
                };
                let result = unsafe { serialize_dump(&mut writer, cap, self.opts) };
                if let Err(error) = result {
                    self.error = Some(error);
                }
                result.is_ok() || writer.done()
            }
        }
    }
}

/// Lister callback (runs with all threads suspended).
///
/// Captures the per-thread registers and process identity that *require* the
/// threads frozen, then forks a copy-on-write snapshot child to write the core.
/// The fork lets the lister resume the siblings the instant this returns, so the
/// host process is frozen only for register capture + fork - not for the whole
/// (possibly multi-GB, possibly gzip-piped) write, which the child performs
/// against its frozen-in-amber COW memory while the parent runs.
///
/// If `fork` fails, falls back to writing in-line with the siblings still frozen
/// (the original behavior), so a fork failure degrades latency, not correctness.
pub(crate) extern "C" fn dump_callback(
    param: *mut c_void,
    pids: *const c_int,
    num: c_int,
) -> c_int {
    // SAFETY: `param` is the DumpCtx we passed; `pids`/`num` come from the lister.
    let ctx = unsafe { &mut *(param as *mut DumpCtx) };
    let pid_slice = unsafe { slice::from_raw_parts(pids, num.max(0) as usize) };

    // The lister attaches to siblings including the original caller; the first
    // tid the lister recorded that equals the parent's pid is the "main" thread.
    // We use the parent pid (our process's pid) as main. This must be computed
    // here, pre-fork: in the snapshot child `getpid` would return the child.
    let main_pid = sys::getpid()
        .map(|p| p as c_int)
        .unwrap_or(pid_slice.first().copied().unwrap_or(0));

    // --- Capture phase (frozen, pre-fork): the only work that needs the threads
    // ptrace-stopped. Failure here is reported through the shared context as
    // before (this still runs in the original VM, not the COW child).
    //
    // `CapturedDump` is large (dominated by the per-thread register array); it is
    // built in place via `capture_dump` so it occupies exactly one slot on the
    // lister's fixed mmap stack (`DUMP_CALLBACK_STACK` budgets one copy). Do not
    // materialize a second temporary (e.g. `let cap = mem::zeroed()` followed by
    // a move) - that transiently doubles it and overflows the lister stack.
    let mut cap = MaybeUninit::<CapturedDump>::uninit();
    if let Err(error) = unsafe { capture_dump(cap.as_mut_ptr(), pid_slice, main_pid, ctx.opts) } {
        ctx.error = Some(error);
        ctx.result = -1;
        return 0;
    }
    // SAFETY: `capture_dump` returned Ok, so every field is initialized.
    let cap = unsafe { cap.assume_init_ref() };

    // --- Serialize: fork a COW snapshot (default) or write in-line frozen. ---
    // `InProcessFrozen` (caller opt-out) and a failed `fork` both take the
    // in-line path: keep every sibling frozen and write the core here.
    let fork_result = match ctx.opts.strategy {
        DumpStrategy::ForkSnapshot => sys::fork(),
        DumpStrategy::InProcessFrozen => Err(0),
    };
    match fork_result {
        Ok(0) => {
            // Child: neutralize the inherited crash-cleanup handler (it would
            // act on siblings this child does not trace), then write the core
            // from our private COW memory and exit. The exit status is the only
            // channel back to the lister.
            crate::threads::disarm_crash_state();
            let ok = ctx.run_serialize(cap);
            sys::exit(if ok { 0 } else { 1 });
        }
        Ok(pid) => {
            // Parent (lister): publish the child so the lister reaps it *after*
            // resuming the siblings, and folds its exit status into the result.
            // Provisionally success; the lister overrides on child failure.
            crate::threads::set_snapshot_child(pid as c_int);
            ctx.result = 0;
            0
        }
        Err(_) => {
            // InProcessFrozen, or fork failed (e.g. ENOMEM copying page tables
            // for a huge process): write in-line with siblings still frozen.
            ctx.result = if ctx.run_serialize(cap) { 0 } else { -1 };
            0
        }
    }
}
