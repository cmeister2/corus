//! Linux ABI constants shared by the no-libc syscall and core-dump layers.

/// Permission denied.
pub const EPERM: i32 = 1;
/// No child processes.
pub const ECHILD: i32 = 10;
/// Out of memory.
pub const ENOMEM: i32 = 12;
/// Bad address.
pub const EFAULT: i32 = 14;
/// Invalid argument.
pub const EINVAL: i32 = 22;

/// Interrupted system call.
pub const EINTR: i32 = 4;

/// `open(2)` read-only flag.
pub const O_RDONLY: i32 = 0;
