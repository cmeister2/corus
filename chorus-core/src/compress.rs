//! On-the-fly compression pipeline - port of `CreatePipeline`/
//! `CreatePipelineChild` from `coredumper.c`.
//!
//! [`spawn`] forks a child that `execve`s a compressor (e.g. `gzip`) with
//! stdin = the read end of a pipe and stdout = the output fd. The dump engine
//! streams the uncompressed core into the pipe's write end; the compressor
//! writes the compressed file. Closing the write end signals EOF, after which
//! the caller reaps the child.
//!
//! If the compressor can't be `execve`d, the child exits non-zero; the caller
//! detects the failed dump and can fall back to writing uncompressed.

use core::ffi::{c_char, c_int};
use core::ptr;

use chorus_syscall::linux::EINTR;
use chorus_syscall::sys;

use crate::io::Pipe;

/// A spawned compressor. Write the raw core to [`write_fd`](Self::write_fd),
/// then [`finish`](Self::finish) to close it and reap the child.
pub struct Pipeline {
    /// Write end of the pipe connected to the compressor's stdin.
    pub write_fd: c_int,
    /// Child pid of the compressor process.
    pid: c_int,
}

/// Standard input file descriptor.
const STDIN_FILENO: c_int = 0;
/// Standard output file descriptor.
const STDOUT_FILENO: c_int = 1;
/// `__WALL` wait option used to reap clone children consistently.
const WALL: c_int = 0x4000_0000;

/// Spawn a compressor child whose stdin is a fresh pipe and whose stdout is
/// `out_fd`. `path` is the executable to `execve` (no PATH search); `argv` is a
/// NULL-terminated argument vector where `argv[0]` is conventionally the program
/// name (which may differ from `path`, e.g. path `/bin/gzip`, argv[0] `gzip`).
/// Returns a [`Pipeline`] whose `write_fd` accepts the raw core bytes.
///
/// # Errors
/// Returns the kernel errno if pipe creation or fork fails.
///
/// # Safety
/// `path` and every `argv` element must be valid C strings; `argv` must be
/// NULL-terminated; `out_fd` must be a writable fd.
pub unsafe fn spawn(
    out_fd: c_int,
    path: *const c_char,
    argv: &[*const c_char],
) -> Result<Pipeline, i32> {
    debug_assert!(argv.last() == Some(&ptr::null()));

    // Create a pipe for the compressor's stdin. The compressor reads from the
    // read end, and the dump engine writes the raw core to the write end.
    let pipe = Pipe::new()?;
    let (read_fd, write_fd) = (pipe.read_fd(), pipe.write_fd());

    // Fork the compressor child. The child execve's the compressor; the parent keeps the write end of the pipe.
    match sys::fork()? {
        0 => {
            // --- Child: wire stdin<-read_fd, stdout<-out_fd, exec compressor ---
            // Close the parent's write end and the original out_fd dup target
            // handling below. On any failure we _exit(127) like a shell would.
            sys::close(write_fd).ok();
            if sys::dup2(read_fd, STDIN_FILENO).is_err()
                || sys::dup2(out_fd, STDOUT_FILENO).is_err()
            {
                sys::exit(127);
            }
            // Close now-redundant fds (best-effort).
            if read_fd != STDIN_FILENO {
                sys::close(read_fd).ok();
            }
            // Empty environment is fine for gzip/bzip2/compress.
            let envp: [*const c_char; 1] = [ptr::null()];
            unsafe { sys::execve(path, argv.as_ptr(), envp.as_ptr()) }.ok();

            // execve only returns on failure.
            sys::exit(127);
        }
        pid => {
            // --- Parent: keep write_fd, close read_fd ---
            let [read_fd, write_fd] = pipe.into_fds();
            sys::close(read_fd).ok();
            let _ = (STDOUT_FILENO, EINTR);
            Ok(Pipeline {
                write_fd,
                pid: pid as c_int,
            })
        }
    }
}

impl Pipeline {
    /// Close the write end (signaling EOF to the compressor) and reap the
    /// child.
    ///
    /// # Errors
    /// Returns the kernel errno if `wait4` fails, or `-1` if the compressor
    /// exits unsuccessfully.
    pub fn finish(self) -> Result<(), i32> {
        sys::close(self.write_fd).ok();
        let mut status: c_int = 0;
        loop {
            match unsafe { sys::wait4(self.pid, &mut status, WALL, ptr::null_mut()) } {
                Ok(_) => break,
                Err(EINTR) => continue,
                Err(errno) => return Err(errno),
            }
        }
        // WIFEXITED && WEXITSTATUS == 0
        if (status & 0x7f) == 0 && ((status >> 8) & 0xff) == 0 {
            Ok(())
        } else {
            Err(-1)
        }
    }
}
