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

/// `open(2)` "must be a directory" flag. **Arch-specific**: x86_64 uses
/// `0o200000`, but aarch64/ARM use `0o40000` (on aarch64 the x86_64 value is
/// `O_DIRECT`, which makes `open("/proc/...", O_DIRECTORY)` fail with EINVAL).
/// Matches the per-arch definition in the original `linux_syscall_support.h`.
#[cfg(target_arch = "x86_64")]
pub const O_DIRECTORY: i32 = 0o200000;
/// `open(2)` "must be a directory" flag (aarch64 value; see x86_64 variant).
#[cfg(target_arch = "aarch64")]
pub const O_DIRECTORY: i32 = 0o40000;

/// `*at(2)` special fd: resolve relative paths against the current directory.
/// Used on arches whose only `open`/`stat`/`readlink` are the `*at` variants.
pub const AT_FDCWD: i32 = -100;

/// `*at(2)` flag: do not dereference a symbolic link (for `newfstatat` acting
/// as `lstat`/`stat` - corus passes 0 to follow links like `stat`).
pub const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
