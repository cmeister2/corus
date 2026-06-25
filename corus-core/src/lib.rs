//! `corus-core` - the `no_std` core dump engine.
//!
//! This crate holds everything that runs on the dangerous path (after sibling
//! threads are suspended): ELF construction, thread enumeration/suspension,
//! `/proc` parsing, and core file assembly. It is strictly `no_std` with no
//! allocator reachable.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub use corus_syscall;

pub mod compress;
pub mod dump;
pub mod elf;
pub mod elfcore;
pub mod io;
pub mod notes;
pub mod proc_parse;
pub mod threads;

use core::ffi::{c_char, c_int, c_void};
use core::mem;

/// Error returned by the core dump engine entrypoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreDumpError {
    /// Thread lister setup or teardown failed with this errno-style value.
    ThreadList(i32),
    /// Core assembly failed after threads were suspended.
    Dump(dump::DumpError),
    /// Compressor process setup or completion failed with this errno-style value.
    Compressor(i32),
}

impl CoreDumpError {
    /// Convert to the legacy C-style `-1` / errno-ish surface used at FFI boundaries.
    pub const fn errno(self) -> i32 {
        match self {
            CoreDumpError::ThreadList(errno) | CoreDumpError::Compressor(errno) => errno,
            CoreDumpError::Dump(error) => dump_error_errno(error),
        }
    }
}

/// Write a core dump of the current process to file descriptor `out_fd`.
///
/// Suspends all sibling threads (via [`threads::with_mmap_stack`]), captures
/// their registers, and streams an uncompressed ELF core through `out_fd` using
/// an unbounded [`io::SimpleWriter`]. Threads are resumed before returning.
///
/// This is the orchestrator wiring `ListAllProcessThreads` ->
/// `InternalGetCoreDump` -> `CreateElfCore`. The C ABI and Rust API both build
/// on top of this.
///
/// # Safety
/// Clones a thread sharing this address space and ptrace-stops the others; see
/// [`threads::with_mmap_stack`]. `out_fd` must be a valid writable fd.
///
/// # Errors
/// Returns the failing dump stage.
pub unsafe fn write_core_dump_to_fd(out_fd: c_int) -> Result<c_int, CoreDumpError> {
    unsafe { write_core_dump_to_fd_limited(out_fd, usize::MAX) }
}

/// As [`write_core_dump_to_fd`], but truncates output at `max_length` bytes
/// (the `COREDUMPER_FLAG_LIMITED` behavior). `usize::MAX` means unlimited.
///
/// # Safety
/// See [`write_core_dump_to_fd`].
///
/// # Errors
/// See [`write_core_dump_to_fd`].
pub unsafe fn write_core_dump_to_fd_limited(
    out_fd: c_int,
    max_length: usize,
) -> Result<c_int, CoreDumpError> {
    let opts = dump::DumpOptions {
        max_length: if max_length == usize::MAX {
            None
        } else {
            Some(max_length)
        },
        ..Default::default()
    };
    unsafe { write_core_dump_to_fd_options(out_fd, &opts) }
}

/// Write a core dump to `out_fd` honoring full [`dump::DumpOptions`] (limit,
/// priority limiting, extra notes, pre-dump callback). The entry both APIs
/// lower to.
///
/// # Errors
/// Returns the failing dump stage.
///
/// # Safety
/// See [`write_core_dump_to_fd`]; `opts.callback`, if set, runs with threads
/// suspended and must obey the no-libc-locks rule.
pub unsafe fn write_core_dump_to_fd_options(
    out_fd: c_int,
    opts: &dump::DumpOptions,
) -> Result<c_int, CoreDumpError> {
    // FRAME(): snapshot the caller's registers here, at the outermost engine
    // entry, before any suspension machinery runs. Applied to the dumping
    // thread so its core backtrace reflects the call site, not `wait4`. If the
    // caller already supplied a frame, keep theirs.
    let mut opts_owned = *opts;
    if opts_owned.frame.is_none() {
        let tid = corus_syscall::sys::gettid()
            .map(|t| t as c_int)
            .unwrap_or(0);
        let mut regs: elf::Regs = unsafe { mem::zeroed() };
        unsafe { corus_syscall::arch::capture_frame(&mut regs as *mut elf::Regs as *mut u64) };
        opts_owned.frame = Some((tid, regs));
    }
    let mut ctx = dump::DumpCtx {
        out_fd,
        opts: &opts_owned,
        result: -1,
        error: None,
    };
    let rc = unsafe {
        threads::with_mmap_stack(
            &mut ctx as *mut dump::DumpCtx as *mut c_void,
            dump::dump_callback,
            dump::DUMP_CALLBACK_STACK,
        )
    };
    match rc {
        Err(errno) => Err(CoreDumpError::ThreadList(errno)),
        Ok(_) if ctx.result == 0 => Ok(0),
        Ok(_) => Err(CoreDumpError::Dump(
            ctx.error.unwrap_or(dump::DumpError::Unknown),
        )),
    }
}

/// Convert detailed dump errors to the errno-style surface used by outer APIs.
const fn dump_error_errno(error: dump::DumpError) -> i32 {
    match error {
        dump::DumpError::CallbackAborted
        | dump::DumpError::CreateElfCore(_)
        | dump::DumpError::Unknown => -1,
        dump::DumpError::PtraceGetRegs { errno, .. } | dump::DumpError::Pipe(errno) => errno,
        dump::DumpError::ParseMaps(error) => error.errno(),
    }
}

/// Write a core dump to `out_fd`, compressed on the fly by the compressor at
/// `path` (e.g. `/bin/gzip`) with arguments `argv` (NULL-terminated; `argv[0]`
/// is the program name, which may be just `gzip`). On spawn failure the caller
/// may retry with the next compressor or uncompressed.
///
/// # Safety
/// See [`write_core_dump_to_fd`]; additionally `path` and `argv` must be valid
/// C strings / a valid NULL-terminated execve vector.
///
/// # Errors
/// Returns compressor failure detail, or the failing core dump stage.
pub unsafe fn write_core_dump_compressed_to_fd(
    out_fd: c_int,
    path: *const c_char,
    argv: &[*const c_char],
) -> Result<c_int, CoreDumpError> {
    let opts = dump::DumpOptions::default();
    unsafe { write_core_dump_compressed_to_fd_with(out_fd, path, argv, &opts) }
}

/// As [`write_core_dump_compressed_to_fd`], but honors full [`dump::DumpOptions`]
/// while producing the uncompressed core stream that feeds the compressor.
///
/// # Errors
/// Returns compressor failure detail, or the failing core dump stage.
///
/// # Safety
/// See [`write_core_dump_compressed_to_fd`].
pub unsafe fn write_core_dump_compressed_to_fd_with(
    out_fd: c_int,
    path: *const c_char,
    argv: &[*const c_char],
    opts: &dump::DumpOptions,
) -> Result<c_int, CoreDumpError> {
    // Spawn the compressor: it reads our pipe and writes out_fd.
    let pipeline =
        unsafe { compress::spawn(out_fd, path, argv) }.map_err(CoreDumpError::Compressor)?;
    // Stream the uncompressed core into the compressor's stdin. With the
    // fork-snapshot path this returns once the snapshot child is forked and the
    // siblings resumed; the child (which inherited `write_fd`) keeps writing into
    // the pipe in the background, and the lister has already reaped it by the
    // time we get here. See `Pipeline` for the fd close/EOF discipline.
    let rc = unsafe { write_core_dump_to_fd_options(pipeline.write_fd, opts) };
    // Close our copy of the write end (the child closed its copy on exit, so
    // this delivers EOF to the compressor) + reap; both must succeed.
    let compressor_result = pipeline.finish();
    match rc {
        Ok(0) => compressor_result
            .map(|()| 0)
            .map_err(CoreDumpError::Compressor),
        Ok(rc) => Ok(rc),
        Err(e) => Err(e),
    }
}
