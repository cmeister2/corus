//! C ABI - `#[unsafe(no_mangle)] extern "C"` entry points matching
//! `coredumper/libcoredumper.sym` and `coredumper/google/coredumper.h`. Lowers to the
//! `corus_core` engine plus the compression pipeline.
//!
//! These are FFI boundary functions: they take raw pointers from C callers and
//! dereference them, but must be plain `extern "C"` (C cannot call an
//! `unsafe fn`). The pointer-validity contract is the caller's, exactly as in
//! the original C API. We therefore allow clippy's `not_unsafe_ptr_arg_deref`
//! for this module; each function documents its pointer expectations.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use core::ffi::{c_char, c_int, c_void};
use core::{ptr, slice};
use std::env::temp_dir;
use std::ffi::{CStr, OsStr};
use std::fs::{File, OpenOptions, remove_file};
use std::io::{Seek, SeekFrom};
use std::os::fd::{AsRawFd, IntoRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use corus_core::corus_syscall::linux::EINVAL;
use corus_core::dump::{DumpOptions, ExtraNote};
use corus_core::elf;

use crate::params::{CoreDumpParameters, CoredumperCompressor, CoredumperNote};

// --- Flags (must match google/coredumper.h) ---------------------------------
/// Limit output to `max_length` bytes.
const COREDUMPER_FLAG_LIMITED: c_int = 1;
/// Apply priority trimming before enforcing `max_length`.
const COREDUMPER_FLAG_LIMITED_BY_PRIORITY: c_int = 2;

/// Set the platform thread-local errno.
fn set_errno(e: c_int) {
    // SAFETY: __errno_location returns a valid, thread-local *mut c_int.
    unsafe {
        *libc_errno_location() = e;
    }
}

unsafe extern "C" {
    #[link_name = "__errno_location"]
    fn libc_errno_location() -> *mut c_int;
}

// --- Exported compressor tables ---------------------------------------------
// Real contents matching coredumper.c. Each table is a NUL-terminated (all-zero
// entry) array of CoredumperCompressor; an empty-name ("") entry means "fall
// back to uncompressed". Declared with C linkage and the golden names.

#[repr(transparent)]
/// Transparent wrapper that makes compressor tables `Sync` for statics.
pub struct CompressorTable<const N: usize>([CoredumperCompressor; N]);
// SAFETY: tables are immutable and contain only 'static/null pointers.
unsafe impl<const N: usize> Sync for CompressorTable<N> {}

// args arrays: { "name", NULL }. Wrapped so raw pointers can live in statics.
#[repr(transparent)]
/// Static argv pair for compressor process names.
struct Argv([*const c_char; 2]);
// SAFETY: holds only 'static string pointers; never mutated.
unsafe impl Sync for Argv {}

impl Argv {
    /// Pointer to the NUL-terminated argv array.
    const fn as_ptr(&self) -> *const *const c_char {
        self.0.as_ptr()
    }
}

/// Argv for bzip2 compressor entries.
static BZIP2_ARGS: Argv = Argv([c"bzip2".as_ptr(), ptr::null()]);
/// Argv for gzip compressor entries.
static GZIP_ARGS: Argv = Argv([c"gzip".as_ptr(), ptr::null()]);
/// Argv for compress compressor entries.
static COMPRESS_ARGS: Argv = Argv([c"compress".as_ptr(), ptr::null()]);

/// Construct one compressor table entry.
const fn comp(
    path: *const c_char,
    args: *const *const c_char,
    suffix: *const c_char,
) -> CoredumperCompressor {
    CoredumperCompressor {
        compressor: path,
        args,
        suffix,
    }
}
/// Terminal null compressor table entry.
const NULLC: CoredumperCompressor = CoredumperCompressor {
    compressor: ptr::null(),
    args: ptr::null(),
    suffix: ptr::null(),
};
/// Empty-name entry meaning uncompressed fallback.
const EMPTYC: CoredumperCompressor = CoredumperCompressor {
    // empty name => "no compression" fallback marker.
    compressor: c"".as_ptr(),
    args: ptr::null(),
    suffix: c"".as_ptr(),
};

/// bzip2 compressor table entries without fallback/terminator.
const BZIP2_COMPRESSORS: [CoredumperCompressor; 3] = [
    comp(
        c"/bin/bzip2".as_ptr(),
        BZIP2_ARGS.as_ptr(),
        c".bz2".as_ptr(),
    ),
    comp(
        c"/usr/bin/bzip2".as_ptr(),
        BZIP2_ARGS.as_ptr(),
        c".bz2".as_ptr(),
    ),
    comp(c"bzip2".as_ptr(), BZIP2_ARGS.as_ptr(), c".bz2".as_ptr()),
];
/// gzip compressor table entries without fallback/terminator.
const GZIP_COMPRESSORS: [CoredumperCompressor; 3] = [
    comp(c"/bin/gzip".as_ptr(), GZIP_ARGS.as_ptr(), c".gz".as_ptr()),
    comp(
        c"/usr/bin/gzip".as_ptr(),
        GZIP_ARGS.as_ptr(),
        c".gz".as_ptr(),
    ),
    comp(c"gzip".as_ptr(), GZIP_ARGS.as_ptr(), c".gz".as_ptr()),
];
/// compress compressor table entries without fallback/terminator.
const COMPRESS_COMPRESSORS: [CoredumperCompressor; 3] = [
    comp(
        c"/bin/compress".as_ptr(),
        COMPRESS_ARGS.as_ptr(),
        c".Z".as_ptr(),
    ),
    comp(
        c"/usr/bin/compress".as_ptr(),
        COMPRESS_ARGS.as_ptr(),
        c".Z".as_ptr(),
    ),
    comp(c"compress".as_ptr(), COMPRESS_ARGS.as_ptr(), c".Z".as_ptr()),
];

// COREDUMPER_COMPRESSED: bzip2, gzip, compress, then uncompressed fallback.
/// Try bzip2, gzip, compress, then uncompressed fallback.
#[unsafe(no_mangle)]
pub static COREDUMPER_COMPRESSED: CompressorTable<11> = {
    CompressorTable([
        BZIP2_COMPRESSORS[0],
        BZIP2_COMPRESSORS[1],
        BZIP2_COMPRESSORS[2],
        GZIP_COMPRESSORS[0],
        GZIP_COMPRESSORS[1],
        GZIP_COMPRESSORS[2],
        COMPRESS_COMPRESSORS[0],
        COMPRESS_COMPRESSORS[1],
        COMPRESS_COMPRESSORS[2],
        EMPTYC,
        NULLC,
    ])
};
/// Try only bzip2 compressor entries.
#[unsafe(no_mangle)]
pub static COREDUMPER_BZIP2_COMPRESSED: CompressorTable<4> = CompressorTable([
    BZIP2_COMPRESSORS[0],
    BZIP2_COMPRESSORS[1],
    BZIP2_COMPRESSORS[2],
    NULLC,
]);
/// Try only gzip compressor entries.
#[unsafe(no_mangle)]
pub static COREDUMPER_GZIP_COMPRESSED: CompressorTable<4> = CompressorTable([
    GZIP_COMPRESSORS[0],
    GZIP_COMPRESSORS[1],
    GZIP_COMPRESSORS[2],
    NULLC,
]);
/// Try only compress compressor entries.
#[unsafe(no_mangle)]
pub static COREDUMPER_COMPRESS_COMPRESSED: CompressorTable<4> = CompressorTable([
    COMPRESS_COMPRESSORS[0],
    COMPRESS_COMPRESSORS[1],
    COMPRESS_COMPRESSORS[2],
    NULLC,
]);
/// Try bzip2, then fall back to uncompressed output.
#[unsafe(no_mangle)]
pub static COREDUMPER_TRY_BZIP2_COMPRESSED: CompressorTable<5> = CompressorTable([
    BZIP2_COMPRESSORS[0],
    BZIP2_COMPRESSORS[1],
    BZIP2_COMPRESSORS[2],
    EMPTYC,
    NULLC,
]);
/// Try gzip, then fall back to uncompressed output.
#[unsafe(no_mangle)]
pub static COREDUMPER_TRY_GZIP_COMPRESSED: CompressorTable<5> = CompressorTable([
    GZIP_COMPRESSORS[0],
    GZIP_COMPRESSORS[1],
    GZIP_COMPRESSORS[2],
    EMPTYC,
    NULLC,
]);
/// Try compress, then fall back to uncompressed output.
#[unsafe(no_mangle)]
pub static COREDUMPER_TRY_COMPRESS_COMPRESSED: CompressorTable<5> = CompressorTable([
    COMPRESS_COMPRESSORS[0],
    COMPRESS_COMPRESSORS[1],
    COMPRESS_COMPRESSORS[2],
    EMPTYC,
    NULLC,
]);
/// Always write an uncompressed core.
#[unsafe(no_mangle)]
pub static COREDUMPER_UNCOMPRESSED: CompressorTable<2> = CompressorTable([EMPTYC, NULLC]);

// --- Core dump implementation ------------------------------------------------

/// Max extra notes converted from a C params bundle (stack buffer bound).
const MAX_EXTRA_NOTES: usize = 64;

/// Lower a parameter bundle to the engine with an explicit caller-frame override
/// (FRAME()). `frame` is `(tid, regs)` captured at the public entry so the
/// dumping thread's backtrace tops out there.
unsafe fn dump_with_params_framed(
    out_fd: c_int,
    params: *const CoreDumpParameters,
    frame: Option<(c_int, elf::Regs)>,
) -> c_int {
    unsafe {
        dump_with_params_using(out_fd, params, frame, |fd, opts| {
            corus_core::write_core_dump_to_fd_options(fd, opts).unwrap_or(-1)
        })
    }
}

/// Lower C parameters and invoke the supplied dump function.
unsafe fn dump_with_params_using(
    out_fd: c_int,
    params: *const CoreDumpParameters,
    frame: Option<(c_int, elf::Regs)>,
    dump: impl FnOnce(c_int, &DumpOptions<'_>) -> c_int,
) -> c_int {
    if params.is_null() {
        let opts = DumpOptions {
            frame,
            ..Default::default()
        };
        return dump(out_fd, &opts);
    }
    let p = unsafe { &*params };

    let limited = (p.flags & COREDUMPER_FLAG_LIMITED) != 0;
    let prioritize = (p.flags & COREDUMPER_FLAG_LIMITED_BY_PRIORITY) != 0;

    // Convert the C notes array into engine ExtraNote borrows on the stack.
    let mut notes_buf: [ExtraNote; MAX_EXTRA_NOTES] = [ExtraNote {
        name: b"",
        note_type: 0,
        description: b"",
    }; MAX_EXTRA_NOTES];

    let mut n_notes = 0usize;
    if !p.notes.is_null() && p.note_count > 0 {
        // Set the max note count to avoid overflow.
        let count = (p.note_count as usize).min(MAX_EXTRA_NOTES);

        for i in 0..count {
            let note = unsafe { &*p.notes.add(i) };
            if note.name.is_null() {
                // Ignore null names
                continue;
            }
            // name: NUL-terminated C string -> &[u8] without the NUL.
            let name = unsafe { CStr::from_ptr(note.name) }.to_bytes();

            // description: raw bytes of length description_size.
            let desc = if note.description.is_null() || note.description_size == 0 {
                &b""[..]
            } else {
                unsafe {
                    slice::from_raw_parts(
                        note.description as *const u8,
                        note.description_size as usize,
                    )
                }
            };

            // Set the note in the notes buffer.
            notes_buf[n_notes] = ExtraNote {
                name,
                note_type: note.r#type,
                description: desc,
            };
            n_notes += 1;
        }
    }

    let callback = p.callback_fn.map(|f| (f, p.callback_arg));

    let opts = DumpOptions {
        max_length: if limited || prioritize {
            Some(p.max_length)
        } else {
            None
        },
        prioritize,
        notes: &notes_buf[..n_notes],
        callback,
        // Caller-frame override captured at the public entry (or None -> the
        // engine captures its own, deeper, frame as a fallback).
        frame,
    };
    dump(out_fd, &opts)
}

/// Decode a C path string into an owned `PathBuf`.
fn file_path(file_name: *const c_char) -> Option<PathBuf> {
    if file_name.is_null() {
        return None;
    }
    // SAFETY: caller passes a valid C string.
    let cstr = unsafe { CStr::from_ptr(file_name) };
    Some(PathBuf::from(OsStr::from_bytes(cstr.to_bytes())))
}

/// Run a file-writing dump: create the file, invoke `dump` with its fd, then
/// remove the file if the dump failed or produced zero bytes - matching the C,
/// which leaves no file when the core is empty (size-0 limit) or aborted
/// (callback). Returns the dump's rc (0 = success).
fn write_to_named_file(file_name: *const c_char, dump: impl FnOnce(c_int) -> c_int) -> c_int {
    let path = match file_path(file_name) {
        Some(p) => p,
        None => {
            set_errno(EINVAL);
            return -1;
        }
    };
    let file = match OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
    {
        Ok(f) => f,
        Err(_) => return -1,
    };
    let rc = dump(file.as_raw_fd());
    // Remove the file on failure or if it ended up empty.
    let empty = file.metadata().map(|m| m.len() == 0).unwrap_or(true);
    drop(file);
    if rc != 0 || empty {
        let _ = remove_file(&path);
    }
    rc
}

// --- Entry points -----------------------------------------------------------

#[unsafe(no_mangle)]
/// Return a readable fd containing an uncompressed core dump.
pub extern "C" fn GetCoreDump() -> c_int {
    // Returns a readable fd of the core. We emulate by dumping to a temp file
    // and returning its fd positioned at 0. (The C returns a pipe fd; a file
    // fd is read-compatible and simpler/safe here.)
    let frame = capture_here!();
    get_core_dump_with(ptr::null(), frame)
}

#[unsafe(no_mangle)]
/// Return a readable fd containing a core dump configured by `params`.
pub extern "C" fn GetCoreDumpWith(params: *const CoreDumpParameters) -> c_int {
    let frame = capture_here!();
    if !params.is_null() {
        let p = unsafe { &*params };
        if (p.flags & (COREDUMPER_FLAG_LIMITED | COREDUMPER_FLAG_LIMITED_BY_PRIORITY)) != 0 {
            set_errno(EINVAL);
            return -1;
        }
    }
    get_core_dump_with(params, frame)
}

/// Shared implementation for the `Get*CoreDump` entry points.
fn get_core_dump_with(
    params: *const CoreDumpParameters,
    frame: Option<(c_int, elf::Regs)>,
) -> c_int {
    // Anonymous temp file via memfd-like tmpfile.
    let mut tmp = match tempfile() {
        Some(f) => f,
        None => return -1,
    };
    let rc = if !params.is_null() {
        let p = unsafe { &*params };
        if !p.compressors.is_null() {
            unsafe {
                dump_with_params_using(tmp.as_raw_fd(), params, frame, |fd, opts| {
                    dump_compressed(fd, p.compressors, p.selected_compressor, opts)
                })
            }
        } else {
            unsafe { dump_with_params_framed(tmp.as_raw_fd(), params, frame) }
        }
    } else {
        unsafe { dump_with_params_framed(tmp.as_raw_fd(), params, frame) }
    };
    if rc != 0 {
        return -1;
    }
    if tmp.seek(SeekFrom::Start(0)).is_err() {
        return -1;
    }
    tmp.into_raw_fd()
}

#[unsafe(no_mangle)]
/// Return a readable fd containing a compressed core dump.
pub extern "C" fn GetCompressedCoreDump(
    compressors: *const CoredumperCompressor,
    selected: *mut *mut CoredumperCompressor,
) -> c_int {
    let frame = capture_here!();
    let opts = DumpOptions {
        frame,
        ..Default::default()
    };
    let mut tmp = match tempfile() {
        Some(f) => f,
        None => return -1,
    };
    let rc = unsafe { dump_compressed(tmp.as_raw_fd(), compressors, selected, &opts) };
    if rc != 0 || tmp.seek(SeekFrom::Start(0)).is_err() {
        return -1;
    }
    tmp.into_raw_fd()
}

#[unsafe(no_mangle)]
/// Write an uncompressed core dump to `file_name`.
pub extern "C" fn WriteCoreDump(file_name: *const c_char) -> c_int {
    WriteCoreDumpWith(ptr::null(), file_name)
}

#[unsafe(no_mangle)]
/// Write a core dump to `file_name` using optional C parameters.
pub extern "C" fn WriteCoreDumpWith(
    params: *const CoreDumpParameters,
    file_name: *const c_char,
) -> c_int {
    let frame = capture_here!();
    write_to_named_file(file_name, |fd| {
        // If compressors are set, route through the pipeline.
        if !params.is_null() {
            let p = unsafe { &*params };
            if !p.compressors.is_null() {
                return unsafe {
                    dump_with_params_using(fd, params, frame, |fd, opts| {
                        dump_compressed(fd, p.compressors, p.selected_compressor, opts)
                    })
                };
            }
        }
        unsafe { dump_with_params_framed(fd, params, frame) }
    })
}

#[unsafe(no_mangle)]
/// Write an uncompressed core dump capped at `max_length` bytes.
pub extern "C" fn WriteCoreDumpLimited(file_name: *const c_char, max_length: usize) -> c_int {
    let frame = capture_here!();
    write_to_named_file(file_name, |fd| {
        let opts = DumpOptions {
            max_length: if max_length == usize::MAX {
                None
            } else {
                Some(max_length)
            },
            frame,
            ..Default::default()
        };
        unsafe { corus_core::write_core_dump_to_fd_options(fd, &opts) }.unwrap_or(-1)
    })
}

#[unsafe(no_mangle)]
/// Write a priority-limited core dump capped at `max_length` bytes.
pub extern "C" fn WriteCoreDumpLimitedByPriority(
    file_name: *const c_char,
    max_length: usize,
) -> c_int {
    let frame = capture_here!();
    write_to_named_file(file_name, |fd| {
        let opts = DumpOptions {
            max_length: Some(max_length),
            prioritize: true,
            frame,
            ..Default::default()
        };
        unsafe { corus_core::write_core_dump_to_fd_options(fd, &opts) }.unwrap_or(-1)
    })
}

#[unsafe(no_mangle)]
/// Write a compressed core dump, appending the selected compressor suffix.
pub extern "C" fn WriteCompressedCoreDump(
    file_name: *const c_char,
    max_length: usize,
    compressors: *const CoredumperCompressor,
    selected: *mut *mut CoredumperCompressor,
) -> c_int {
    let frame = capture_here!();
    let opts = DumpOptions {
        max_length: if max_length == usize::MAX {
            None
        } else {
            Some(max_length)
        },
        frame,
        ..Default::default()
    };
    // The output filename gets the selected compressor's suffix appended
    // (e.g. core-test -> core-test.gz), matching the C. Resolve which compressor
    // will run *first* so we can build the suffixed path before opening.
    let base = match file_path(file_name) {
        Some(p) => p,
        None => {
            set_errno(EINVAL);
            return -1;
        }
    };
    let idx = unsafe { resolve_compressor(compressors) };
    let suffix = idx
        .and_then(|i| {
            let entry = unsafe { &*compressors.offset(i) };
            if entry.suffix.is_null() {
                None
            } else {
                Some(unsafe { CStr::from_ptr(entry.suffix) }.to_bytes())
            }
        })
        .unwrap_or(b"");
    // Build base + suffix.
    let mut full = base.into_os_string();
    if !suffix.is_empty() {
        full.push(OsStr::from_bytes(suffix));
    }
    let full = PathBuf::from(full);

    let file = match OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&full)
    {
        Ok(f) => f,
        Err(_) => return -1,
    };
    let rc = unsafe { dump_compressed(file.as_raw_fd(), compressors, selected, &opts) };
    let empty = file.metadata().map(|m| m.len() == 0).unwrap_or(true);
    drop(file);
    if rc != 0 || empty {
        let _ = remove_file(&full);
    }
    rc
}

/// Pick the index of the first compressor whose executable is accessible (or the
/// empty-name "uncompressed" marker). Returns None if the list is exhausted with
/// nothing usable. Used to know the output suffix before opening the file.
///
/// # Safety
/// `compressors` is a valid NUL-terminated `CoredumperCompressor` array.
unsafe fn resolve_compressor(compressors: *const CoredumperCompressor) -> Option<isize> {
    if compressors.is_null() {
        return None;
    }
    let mut i = 0isize;
    loop {
        let entry = unsafe { &*compressors.offset(i) };
        if entry.compressor.is_null() {
            return None; // end of array
        }
        let name = unsafe { CStr::from_ptr(entry.compressor) }.to_bytes();
        if name.is_empty() {
            return Some(i); // empty-name => uncompressed fallback, no suffix
        }
        // Executable accessible? (absolute path check; bare names can't be
        // execve'd anyway and will be skipped by the dump path.)
        if name.starts_with(b"/") && Path::new(OsStr::from_bytes(name)).exists() {
            return Some(i);
        }
        i += 1;
    }
}

/// Try each compressor in the NUL-terminated `compressors` array until one is
/// successfully spawned; on success set `*selected`. An empty-name entry means
/// "write uncompressed". Returns 0 on success.
///
/// # Safety
/// `compressors` is a valid NUL-terminated CoredumperCompressor array; `out_fd`
/// writable; `selected` null or a valid out-pointer.
unsafe fn dump_compressed(
    out_fd: c_int,
    compressors: *const CoredumperCompressor,
    selected: *mut *mut CoredumperCompressor,
    opts: &DumpOptions<'_>,
) -> c_int {
    if compressors.is_null() {
        return unsafe { corus_core::write_core_dump_to_fd_options(out_fd, opts) }.unwrap_or(-1);
    }
    // Pre-set `*selected` to the terminal (NULL-compressor) entry, matching the
    // C: if every compressor fails, the caller sees `selected->compressor ==
    // NULL`. A successful compressor overwrites this below.
    if !selected.is_null() {
        let mut t = 0isize;
        while !unsafe { (*compressors.offset(t)).compressor }.is_null() {
            t += 1;
        }
        set_selected(selected, compressors, t);
    }
    let mut i = 0isize;
    loop {
        let entry = unsafe { &*compressors.offset(i) };
        if entry.compressor.is_null() {
            // End of array, nothing worked.
            return -1;
        }
        // Empty name => uncompressed fallback.
        let name = unsafe { CStr::from_ptr(entry.compressor) };
        if name.to_bytes().is_empty() {
            let rc =
                unsafe { corus_core::write_core_dump_to_fd_options(out_fd, opts) }.unwrap_or(-1);
            if rc == 0 {
                set_selected(selected, compressors, i);
            }
            return rc;
        }
        // `entry.compressor` is the executable path passed to execve. The argv
        // vector is separate because the C tables sometimes use an absolute
        // executable path but a short argv[0], e.g. path "/bin/gzip" with
        // argv[0] "gzip".
        let mut argv: [*const c_char; 8] = [ptr::null(); 8];
        let mut argc;
        if entry.args.is_null() {
            // No explicit argv table: use the executable path as argv[0]. The
            // trailing NULL is written below, after both branches agree on argc.
            argv[0] = entry.compressor;
            argc = 1;
        } else {
            // Copy the caller/table-provided NULL-terminated argv into our
            // fixed local buffer. Leave one slot free for our own terminator so
            // malformed or overlong tables cannot overrun the stack buffer.
            argc = 0;
            let mut j = 0isize;
            loop {
                let a = unsafe { *entry.args.offset(j) };
                if a.is_null() || argc >= argv.len() - 1 {
                    break;
                }
                argv[argc] = a;
                argc += 1;
                j += 1;
            }
        }
        // Ensure the argv slice handed to the compression pipeline is always
        // NULL-terminated, even if the source table was truncated to fit.
        argv[argc] = ptr::null();
        let rc = unsafe {
            corus_core::write_core_dump_compressed_to_fd_with(
                out_fd,
                entry.compressor,
                &argv[..=argc],
                opts,
            )
        }
        .unwrap_or_else(|error| error.errno());
        if rc == 0 {
            set_selected(selected, compressors, i);
            return 0;
        }
        // This compressor failed to spawn/run; try the next.
        i += 1;
    }
}

/// Store the selected compressor entry in the caller-provided out-pointer.
fn set_selected(
    selected: *mut *mut CoredumperCompressor,
    base: *const CoredumperCompressor,
    idx: isize,
) {
    if !selected.is_null() {
        // SAFETY: base+idx is within the array the caller provided.
        unsafe {
            *selected = base.offset(idx) as *mut CoredumperCompressor;
        }
    }
}

/// Create an anonymous temp file (unlinked) for the Get* entry points.
fn tempfile() -> Option<File> {
    static CTR: AtomicU64 = AtomicU64::new(0);
    let path = temp_dir().join(format!(
        "coredumper_{}_{}.core",
        std::process::id(),
        CTR.fetch_add(1, Ordering::Relaxed)
    ));
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .ok()?;
    let _ = remove_file(&path); // unlink; fd stays valid
    Some(f)
}

// --- Parameter helpers (port of coredumper.c) -------------------------------

#[unsafe(no_mangle)]
/// Initialize a caller-provided `CoreDumpParameters` buffer.
pub extern "C" fn ClearCoreDumpParametersInternal(params: *mut CoreDumpParameters, size: usize) {
    if params.is_null() {
        return;
    }
    // SAFETY: caller guarantees `params` points to at least `size` bytes.
    unsafe {
        ptr::write_bytes(params as *mut u8, 0, size);
        (*params).size = size;
        (*params).max_length = usize::MAX;
    }
}

#[unsafe(no_mangle)]
/// Configure a size-limited core dump.
pub extern "C" fn SetCoreDumpLimited(params: *mut CoreDumpParameters, max_length: usize) -> c_int {
    if params.is_null() {
        return -1;
    }
    let p = unsafe { &mut *params };
    if (p.flags & COREDUMPER_FLAG_LIMITED_BY_PRIORITY) != 0 {
        set_errno(EINVAL);
        return -1;
    }
    p.flags |= COREDUMPER_FLAG_LIMITED;
    p.max_length = max_length;
    0
}

#[unsafe(no_mangle)]
/// Configure compression for a core dump.
pub extern "C" fn SetCoreDumpCompressed(
    params: *mut CoreDumpParameters,
    compressors: *const CoredumperCompressor,
    selected: *mut *mut CoredumperCompressor,
) -> c_int {
    if params.is_null() {
        return -1;
    }
    let p = unsafe { &mut *params };
    if (p.flags & COREDUMPER_FLAG_LIMITED_BY_PRIORITY) != 0 {
        set_errno(EINVAL);
        return -1;
    }
    p.compressors = compressors;
    p.selected_compressor = selected;
    0
}

#[unsafe(no_mangle)]
/// Configure priority-limited dumping.
pub extern "C" fn SetCoreDumpLimitedByPriority(
    params: *mut CoreDumpParameters,
    max_length: usize,
) -> c_int {
    if params.is_null() {
        return -1;
    }
    let p = unsafe { &mut *params };
    if ((p.flags & COREDUMPER_FLAG_LIMITED) != 0
        && (p.flags & COREDUMPER_FLAG_LIMITED_BY_PRIORITY) == 0)
        || !p.compressors.is_null()
    {
        set_errno(EINVAL);
        return -1;
    }
    p.flags |= COREDUMPER_FLAG_LIMITED | COREDUMPER_FLAG_LIMITED_BY_PRIORITY;
    p.max_length = max_length;
    0
}

#[unsafe(no_mangle)]
/// Configure extra ELF notes for a core dump.
pub extern "C" fn SetCoreDumpNotes(
    params: *mut CoreDumpParameters,
    notes: *mut CoredumperNote,
    note_count: c_int,
) -> c_int {
    if params.is_null() {
        return -1;
    }
    let p = unsafe { &mut *params };
    p.notes = notes;
    p.note_count = note_count;
    0
}

#[unsafe(no_mangle)]
/// Configure a pre-dump callback.
pub extern "C" fn SetCoreDumpCallback(
    params: *mut CoreDumpParameters,
    func: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    arg: *mut c_void,
) -> c_int {
    if params.is_null() {
        return -1;
    }
    let p = unsafe { &mut *params };
    p.callback_fn = func;
    p.callback_arg = arg;
    0
}
