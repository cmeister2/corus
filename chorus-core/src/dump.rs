//! Dump orchestration - port of `InternalGetCoreDump` from `elfcore.c`.
//!
//! This is the glue that runs *inside the lister thread's callback*
//! ([`crate::threads`]) with all target threads ptrace-stopped. It captures each
//! thread's registers, builds PRPSINFO, parses the memory map, and streams the
//! core via [`crate::elfcore::CoreInputs::write_core`].
//!
//! Capacity is fixed (no allocation on the dump path): up to [`MAX_THREADS`]
//! threads and [`crate::proc_parse::MAX_MAPPINGS`] mappings.

use core::ffi::c_void;
use core::mem;

use chorus_syscall::{arch::PAGE_SIZE, linux::O_RDONLY, sys};

use crate::elf::{AuxvT, CoreUser, FpRegs, Prpsinfo, Regs};
use crate::elfcore::{CoreInputs, CreateElfCoreError, ThreadState};
use crate::io::{Pipe, Writer};
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
/// of `dump_core` -> `CoreInputs::write_core` / `build_prpsinfo`. Estimated (the
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

/// Options controlling a dump. `Default` is an unlimited, uncompressed dump with
/// no extra notes or callback - equivalent to `ClearCoreDumpParameters`.
#[derive(Default, Clone, Copy)]
pub struct DumpOptions<'a> {
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
    let pagesize = PAGE_SIZE;

    // Pre-dump callback: abort the whole dump if it returns non-zero.
    if let Some((cb, arg)) = opts.callback {
        // SAFETY: caller-provided C function; invoked here per the C contract
        // with threads suspended. It must be async-signal-safe.
        if unsafe { cb(arg) } != 0 {
            return Err(DumpError::CallbackAborted);
        }
    }

    // --- Capture per-thread registers via ptrace (threads already stopped) ---
    let mut threads = [ThreadState {
        pid: 0,
        regs: unsafe { mem::zeroed() },
        fpregs: unsafe { mem::zeroed() },
    }; MAX_DUMP_THREADS];
    let n_threads = pids.len().min(MAX_DUMP_THREADS);
    let mut main_idx = 0usize;

    for (i, &pid) in pids.iter().take(n_threads).enumerate() {
        let mut regs: Regs = unsafe { mem::zeroed() };
        let mut fpregs: FpRegs = unsafe { mem::zeroed() };
        if let Err(errno) =
            unsafe { sys::ptrace_getregs(pid, &mut regs as *mut Regs as *mut c_void) }
        {
            return Err(DumpError::PtraceGetRegs { pid, errno });
        }

        // FP registers are best-effort: a failure leaves them zeroed.
        let _ = unsafe { sys::ptrace_getfpregs(pid, &mut fpregs as *mut FpRegs as *mut c_void) };

        // FRAME() override: for the thread that called the public API, replace
        // the ptrace-captured regs (parked in wait4) with the caller's snapshot
        // so the backtrace tops out at WriteCoreDump -> user code. Keep the
        // kernel-only fs_base/gs_base from ptrace, as the C SET_FRAME does.
        if let Some((frame_tid, frame_regs)) = opts.frame
            && pid == frame_tid
        {
            let mut fr = frame_regs;
            fr.fs_base = regs.fs_base;
            fr.gs_base = regs.gs_base;
            regs = fr;
        }

        threads[i] = ThreadState { pid, regs, fpregs };
        if pid == main_pid {
            main_idx = i;
        }
    }

    // --- AUXV ---
    let mut auxv = [AuxvT {
        a_type: 0,
        a_val: 0,
    }; MAX_AUXV];
    // This is best-effort; failure to read auxv is not fatal.
    let n_auxv = read_auxv(&mut auxv).unwrap_or(0);

    // --- PRPSINFO ---
    let prpsinfo = build_prpsinfo(main_pid);

    // --- Memory mappings ---
    let mut maps = mapping_buf();
    let parsed = match parse_self_maps(&mut maps) {
        Ok(n) => n,
        Err(error) => return Err(DumpError::ParseMaps(error)),
    };
    // Loopback pipe + scratch for the leading-zeros safe page scan.
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
        let header_overhead = estimate_header_size(n_threads, n_auxv, &maps[..kept], opts.notes);
        apply_priority_limit(&mut maps[..kept], limit, header_overhead);
    }

    // NT_PRXREG (core_user) for the main thread: carries the GP + FP registers
    // as gdb's fallback. We populate `regs`/`fpregs` from the captured state and
    // leave the auxiliary fields zero (the C fills them via PTRACE_PEEKUSER; not
    // needed for gdb/readelf correctness - a documented follow-up).
    let user = if n_threads > 0 {
        let mut u: CoreUser = unsafe { mem::zeroed() };
        u.regs = threads[main_idx].regs;
        u.fpregs = threads[main_idx].fpregs;
        u.fpvalid = 1;
        Some(u)
    } else {
        None
    };

    let inp = CoreInputs {
        prpsinfo: &prpsinfo,
        threads: &threads[..n_threads],
        main_thread: main_idx,
        auxv: &auxv[..n_auxv],
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
    info.pr_sname = b'R' as i8;
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
            exe.as_mut_ptr() as *mut i8,
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
            *dst = b as i8;
        }
    }

    // pr_psargs: /proc/self/cmdline with NULs turned into spaces.
    if let Ok(fd) = unsafe { sys::open(c"/proc/self/cmdline".as_ptr(), O_RDONLY, 0) } {
        let fd = fd as i32;
        let mut buf = [0u8; 80]; // pr_psargs is 80 bytes
        if let Ok(rd) = unsafe { sys::read(fd, buf.as_mut_ptr() as *mut c_void, buf.len()) } {
            for (dst, &b) in info.pr_psargs.iter_mut().zip(buf.iter()).take(rd) {
                *dst = if b == 0 { b' ' as i8 } else { b as i8 };
            }
        }
        sys::close(fd).ok();
    }

    info
}
