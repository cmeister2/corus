//! `chorus` - snapshot a running process into an ELF core file.
//!
//! Two surfaces over one engine ([`chorus_core`]):
//!   - [`capi`]: the C ABI (`GetCoreDump`, `WriteCoreDump`, ...) matching
//!     `coredumper/google/coredumper.h`, for drop-in C consumers and the existing C
//!     unit test.
//!   - [`rust_api`]: an idiomatic Rust API for common dump requests (builder,
//!     `Result`, compression, and size limits).
//!
//! This crate is `std` by design: the surface layer may use `std` for caller
//! conveniences, but everything reachable after thread suspension lives in the
//! strictly-`no_std` [`chorus_core`]. Unwinding never crosses the FFI
//! boundary: the workspace sets `panic = "abort"`, so
//! a panic terminates via `std`'s abort rather than unwinding into C frames.

/// Capture the current thread's `(tid, Regs)` for the FRAME() override, so the
/// dumping thread's core backtrace tops out at the calling public entry.
///
/// `capture_frame` records *its own* return address as the snapshot `rip`. This
/// must stay a macro, not a helper function, so expansion happens directly in
/// each public API entry that wants its frame to appear in the dumped thread's
/// backtrace.
macro_rules! capture_here {
    () => {{
        let tid = ::chorus_core::chorus_syscall::sys::gettid()
            .map(|t| t as core::ffi::c_int)
            .unwrap_or(0);
        let mut regs: ::chorus_core::elf::Regs = unsafe { core::mem::zeroed() };
        unsafe {
            ::chorus_core::chorus_syscall::arch::capture_frame(
                &mut regs as *mut ::chorus_core::elf::Regs as *mut u64,
            )
        };
        Some((tid, regs))
    }};
}

pub mod capi;
pub mod params;
pub mod rust_api;

pub use rust_api::{Compression, CoreDump, Error};
