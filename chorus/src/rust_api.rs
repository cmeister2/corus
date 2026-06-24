//! Idiomatic Rust API.
//!
//! Builder ergonomics, `Result`, and `Option` over the same `chorus_core`
//! engine the C ABI uses. ABI-shaped features such as raw extra-note arrays and
//! pre-dump callbacks remain exposed through [`crate::capi`].

use core::ffi::c_int;
use core::ptr;

use std::ffi::CString;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use chorus_core::dump::DumpOptions;

/// Error returned by the Rust API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The dump could not be produced (engine returned failure).
    Failed,
    /// The output file could not be created.
    Io,
    /// The core dump engine failed.
    Core(chorus_core::CoreDumpError),
}

/// Which compressor family to use, mirroring the `COREDUMPER_*` tables. `None`
/// (the default) writes an uncompressed core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// Try bzip2, gzip, compress, in order; fall back to uncompressed.
    Auto,
    /// Use bzip2 compression.
    Bzip2,
    /// Use gzip compression.
    Gzip,
    /// Use traditional compress(1) compression.
    Compress,
}

/// Builder for a core dump request - the idiomatic counterpart to the C
/// `CoreDumpParameters` + `SetCoreDump*` helpers.
#[derive(Default)]
pub struct CoreDump {
    /// Optional maximum output length.
    max_length: Option<usize>,
    /// Optional compression family.
    compression: Option<Compression>,
}

impl CoreDump {
    /// Start building a core dump request.
    pub fn builder() -> Self {
        Self::default()
    }

    /// Cap the core file at `bytes`, truncating output (the
    /// `COREDUMPER_FLAG_LIMITED` behavior).
    pub fn max_length(mut self, bytes: usize) -> Self {
        self.max_length = Some(bytes);
        self
    }

    /// Compress the core on the fly with the given family.
    pub fn compression(mut self, c: Compression) -> Self {
        self.compression = Some(c);
        self
    }

    /// Write the core of the current process to `path`. Threads are suspended
    /// for the duration and resumed before returning.
    ///
    /// # Errors
    /// Returns [`Error::Io`] if the file cannot be created, or [`Error::Failed`]
    /// if the dump engine reports failure.
    ///
    /// # Safety
    /// Clones a thread sharing this address space and ptrace-stops the others
    /// (see `chorus_core::write_core_dump_to_fd`).
    pub unsafe fn write_to_path(&self, path: impl AsRef<Path>) -> Result<(), Error> {
        let file = std::fs::File::create(path).map_err(|_| Error::Io)?;
        unsafe { self.write_to_fd(file.as_raw_fd()) }
    }

    /// Write the core to an already-open file descriptor.
    ///
    /// # Errors
    /// Returns [`Error::Failed`] if compression setup or the dump engine fails.
    ///
    /// # Safety
    /// See [`write_to_path`](Self::write_to_path); `fd` must be writable.
    pub unsafe fn write_to_fd(&self, fd: c_int) -> Result<(), Error> {
        let frame = capture_here!();
        let rc = match self.compression {
            // None means uncompressed, so call the engine directly.
            None => {
                let opts = DumpOptions {
                    max_length: self.max_length,
                    frame,
                    ..Default::default()
                };
                unsafe { chorus_core::write_core_dump_to_fd_options(fd, &opts) }
            }
            // Try a compressor family.
            Some(family) => match compressor_path(family)? {
                // The compressor was found; call the engine with the compressor path and argv.
                Some(path) => {
                    let argv = [path.as_ptr(), ptr::null()];
                    let opts = DumpOptions {
                        max_length: self.max_length,
                        frame,
                        ..Default::default()
                    };
                    unsafe {
                        chorus_core::write_core_dump_compressed_to_fd_with(
                            fd,
                            path.as_ptr(),
                            &argv,
                            &opts,
                        )
                    }
                }
                // The compressor was not found; fall back to uncompressed.
                None => {
                    let opts = chorus_core::dump::DumpOptions {
                        max_length: self.max_length,
                        frame,
                        ..Default::default()
                    };
                    unsafe { chorus_core::write_core_dump_to_fd_options(fd, &opts) }
                }
            },
        };
        match rc {
            Ok(0) => Ok(()),
            Ok(_) => Err(Error::Failed),
            Err(error) => Err(Error::Core(error)),
        }
    }
}

/// Resolve a compression family's executable. `execve` does not search `PATH`,
/// so the Rust API uses `which` up front and passes an absolute path downstream.
fn compressor_path(family: Compression) -> Result<Option<CString>, Error> {
    for program in compressor_candidates(family) {
        let Ok(path) = which::which(program) else {
            continue;
        };
        return CString::new(path.as_os_str().as_bytes())
            .map(Some)
            .map_err(|_| Error::Failed);
    }
    if family == Compression::Auto {
        Ok(None)
    } else {
        Err(Error::Failed)
    }
}

/// Candidate executable names for a compression family, in preference order.
fn compressor_candidates(family: Compression) -> &'static [&'static str] {
    match family {
        Compression::Auto => &["bzip2", "gzip", "compress"],
        Compression::Bzip2 => &["bzip2"],
        Compression::Gzip => &["gzip"],
        Compression::Compress => &["compress"],
    }
}
