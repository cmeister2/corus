//! Raw Linux syscall support - a `no_std` port of `linux_syscall_support.h`.
//!
//! The original C header exists to issue syscalls *without libc*, so that the
//! core dumper can run after sibling threads are suspended (when taking a libc
//! lock could deadlock). This crate reproduces that: hand-written `asm!`
//! syscall primitives plus typed `sys_*` wrappers, with no allocator and no
//! libc dependency in the library itself.
//!
//! v1 targets x86_64 only. Other architectures slot in under
//! [`arch`] behind `cfg(target_arch)`.
//!
//! # Errno convention
//! The kernel returns errors as `-errno` in the range `-4095..=-1`. Raw
//! [`arch`] primitives return that value verbatim as a `usize`; the typed
//! wrappers convert it into `Result<usize, Errno>`.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg_attr(target_arch = "x86_64", path = "arch/x86_64.rs")]
pub mod arch;

pub mod kernel_types;
pub mod linux;
pub mod sys;

pub use arch::clone;

/// Largest negated errno the kernel returns in a syscall result register.
/// A raw return `r` is an error iff `r >= -4095 as usize` (wrapping).
pub const MAX_ERRNO: usize = 4095;

/// Interpret a raw syscall return value as `Result`.
///
/// Returns `Err(errno)` for values in `-4095..=-1` (as unsigned), else `Ok`.
///
/// # Errors
/// Returns the decoded positive errno when `ret` is in the kernel error range.
#[inline]
pub fn from_ret(ret: usize) -> Result<usize, i32> {
    if ret > usize::MAX - MAX_ERRNO {
        // ret is in [-4095, -1] reinterpreted as usize.
        Err(-(ret as isize) as i32)
    } else {
        Ok(ret)
    }
}

/// Terminate the whole process immediately via `exit_group(2)`.
///
/// Used by the panic handler and by fatal error paths on the dump path, where
/// unwinding is forbidden. Never returns.
#[inline]
pub fn exit_group(code: i32) -> ! {
    // SAFETY: exit_group never returns and has no memory side effects we must
    // uphold; passing the status code is always valid.
    unsafe {
        arch::syscall1(arch::nr::EXIT_GROUP, code as usize);
    }
    // exit_group does not return; satisfy the `!` type if the kernel ever did.
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errno_decoding() {
        // 0 and small positives are Ok.
        assert_eq!(from_ret(0), Ok(0));
        assert_eq!(from_ret(42), Ok(42));
        // -1 (EPERM) .. -4095 decode as Err.
        assert_eq!(from_ret((-1isize) as usize), Err(linux::EPERM));
        assert_eq!(from_ret((-2isize) as usize), Err(2));
        assert_eq!(from_ret((-4095isize) as usize), Err(4095));
        // -4096 is NOT an errno: it's a valid (huge) return value.
        assert_eq!(from_ret((-4096isize) as usize), Ok((-4096isize) as usize));
    }

    #[test]
    fn raw_write_to_stderr() {
        // Smoke test that the asm! syscall0/3 primitives actually work.
        // Differential-vs-libc tests cover the full wrapper set.
        let msg = b"[chorus-syscall] raw write OK\n";
        // SAFETY: writing a valid buffer to fd 2 (stderr) is well-defined.
        let ret = unsafe { arch::syscall3(arch::nr::WRITE, 2, msg.as_ptr() as usize, msg.len()) };
        assert_eq!(from_ret(ret), Ok(msg.len()));
    }
}
