//! Kernel ABI struct definitions (x86_64).
//!
//! These match the *kernel's* layout, not glibc's - exactly as the C
//! `linux_syscall_support.h` does. Layouts are asserted at compile time against
//! known-good C layout values. Do not reorder fields.

use core::ffi::{c_int, c_short, c_uint, c_ushort, c_void};
use core::mem;

/// `struct kernel_stat` for x86_64 (golden: size 144, align 8).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KernelStat {
    /// Device containing the file.
    pub st_dev: u64,
    /// File inode number.
    pub st_ino: u64,
    /// Number of hard links.
    pub st_nlink: u64,
    /// File mode bits.
    pub st_mode: c_uint,
    /// File owner user id.
    pub st_uid: c_uint,
    /// File owner group id.
    pub st_gid: c_uint,
    /// Kernel padding after gid.
    pub __pad0: c_uint,
    /// Device id for special files.
    pub st_rdev: u64,
    /// Total file size in bytes.
    pub st_size: i64,
    /// Preferred block size for IO.
    pub st_blksize: i64,
    /// Number of allocated 512-byte blocks.
    pub st_blocks: i64,
    /// Last access time, seconds.
    pub st_atime: u64,
    /// Last access time, nanoseconds.
    pub st_atime_nsec: u64,
    /// Last modification time, seconds.
    pub st_mtime: u64,
    /// Last modification time, nanoseconds.
    pub st_mtime_nsec: u64,
    /// Last status change time, seconds.
    pub st_ctime: u64,
    /// Last status change time, nanoseconds.
    pub st_ctime_nsec: u64,
    /// Reserved kernel padding.
    pub __unused4: [i64; 3],
}

impl KernelStat {
    /// A zeroed stat buffer suitable for passing to `fstat`/`stat`.
    pub const fn zeroed() -> Self {
        // SAFETY: KernelStat is a plain-old-data struct of integers; all-zero
        // is a valid bit pattern.
        unsafe { mem::zeroed() }
    }
}

/// `struct kernel_dirent` for x86_64 - the **legacy `getdents`** layout used by
/// the C source (golden: size 280, align 8, `d_name` at 18, no `d_type` field).
///
/// We match the original `linux_syscall_support.h` here rather than the
/// `getdents64` `linux_dirent64` layout: the C code calls `sys_getdents` (NR 78)
/// with exactly this struct, and the thread-enumeration loop only reads
/// `d_ino`/`d_reclen`/`d_name`. The faithful port follows the source's legacy
/// `getdents` usage; revisit if 64-bit `d_off` is needed.
#[repr(C)]
pub struct KernelDirent {
    /// Directory entry inode.
    pub d_ino: i64,
    /// Offset to the next directory entry.
    pub d_off: i64,
    /// Record length in bytes.
    pub d_reclen: c_ushort,
    /// NUL-terminated directory entry name.
    pub d_name: [u8; 256],
}

/// `struct kernel_sigset_t` (golden: size 8, align 8 on x86_64 - one u64 word).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KernelSigset {
    /// Raw signal mask words.
    pub sig: [u64; 1],
}

impl KernelSigset {
    /// Return an empty signal set.
    pub const fn empty() -> Self {
        Self { sig: [0] }
    }
}

/// `struct kernel_iovec` (golden: size 16, align 8).
#[repr(C)]
pub struct KernelIovec {
    /// Base address of the buffer.
    pub iov_base: *mut c_void,
    /// Buffer length in bytes.
    pub iov_len: usize,
}

/// `struct kernel_pollfd` (golden: size 8, align 4).
#[repr(C)]
pub struct KernelPollfd {
    /// File descriptor to poll.
    pub fd: c_int,
    /// Requested event mask.
    pub events: c_short,
    /// Returned event mask.
    pub revents: c_short,
}

/// `struct kernel_sigaction` for x86_64 (golden: size 32, align 8): handler at
/// 0, flags at 8, restorer at 16, mask at 24.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KernelSigaction {
    /// Either an `sa_handler` or (with `SA_SIGINFO`) an `sa_sigaction`. Stored as
    /// a raw pointer; the kernel selects the calling convention via `sa_flags`.
    pub sa_handler: *mut c_void,
    /// Signal action flags.
    pub sa_flags: u64,
    /// Restorer trampoline address used by the kernel on signal return.
    pub sa_restorer: *mut c_void,
    /// Signals masked while the handler runs.
    pub sa_mask: KernelSigset,
}

impl KernelSigaction {
    /// Return a zeroed signal action.
    pub const fn zeroed() -> Self {
        KernelSigaction {
            sa_handler: core::ptr::null_mut(),
            sa_flags: 0,
            sa_restorer: core::ptr::null_mut(),
            sa_mask: KernelSigset::empty(),
        }
    }
}

/// `stack_t` for `sigaltstack` (golden: size 24; ss_sp@0, ss_flags@8, ss_size@16).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StackT {
    /// Alternate signal stack base pointer.
    pub ss_sp: *mut c_void,
    /// Alternate signal stack flags.
    pub ss_flags: c_int,
    /// Alternate signal stack size in bytes.
    pub ss_size: usize,
}

impl StackT {
    /// Return a disabled, zeroed signal stack descriptor.
    pub const fn zeroed() -> Self {
        StackT {
            ss_sp: core::ptr::null_mut(),
            ss_flags: 0,
            ss_size: 0,
        }
    }
}

/// `struct kernel_msghdr` (golden: size 56, align 8).
#[repr(C)]
pub struct KernelMsghdr {
    /// Optional socket address pointer.
    pub msg_name: *mut c_void,
    /// Socket address length.
    pub msg_namelen: c_int,
    /// Scatter/gather buffer array.
    pub msg_iov: *mut KernelIovec,
    /// Number of entries in `msg_iov`.
    pub msg_iovlen: usize,
    /// Ancillary data buffer.
    pub msg_control: *mut c_void,
    /// Ancillary data buffer length.
    pub msg_controllen: usize,
    /// Message flags returned by the kernel.
    pub msg_flags: c_uint,
}

// --- Compile-time layout assertions against C layout values ------------------
const _: () = {
    use mem::{align_of, offset_of, size_of};

    assert!(size_of::<KernelStat>() == 144);
    assert!(align_of::<KernelStat>() == 8);
    assert!(offset_of!(KernelStat, st_dev) == 0);
    assert!(offset_of!(KernelStat, st_ino) == 8);
    assert!(offset_of!(KernelStat, st_nlink) == 16);
    assert!(offset_of!(KernelStat, st_mode) == 24);
    assert!(offset_of!(KernelStat, st_size) == 48);
    assert!(offset_of!(KernelStat, st_blocks) == 64);

    assert!(size_of::<KernelDirent>() == 280);
    assert!(align_of::<KernelDirent>() == 8);
    assert!(offset_of!(KernelDirent, d_ino) == 0);
    assert!(offset_of!(KernelDirent, d_off) == 8);
    assert!(offset_of!(KernelDirent, d_reclen) == 16);
    assert!(offset_of!(KernelDirent, d_name) == 18);

    assert!(size_of::<KernelSigset>() == 8);
    assert!(size_of::<KernelIovec>() == 16);

    assert!(size_of::<KernelPollfd>() == 8);
    assert!(align_of::<KernelPollfd>() == 4);

    assert!(size_of::<KernelMsghdr>() == 56);
    assert!(align_of::<KernelMsghdr>() == 8);
    assert!(offset_of!(KernelMsghdr, msg_iov) == 16);
    assert!(offset_of!(KernelMsghdr, msg_iovlen) == 24);
    assert!(offset_of!(KernelMsghdr, msg_control) == 32);
    assert!(offset_of!(KernelMsghdr, msg_flags) == 48);

    assert!(size_of::<KernelSigaction>() == 32 && align_of::<KernelSigaction>() == 8);
    assert!(offset_of!(KernelSigaction, sa_handler) == 0);
    assert!(offset_of!(KernelSigaction, sa_flags) == 8);
    assert!(offset_of!(KernelSigaction, sa_restorer) == 16);
    assert!(offset_of!(KernelSigaction, sa_mask) == 24);

    assert!(size_of::<StackT>() == 24 && align_of::<StackT>() == 8);
    assert!(offset_of!(StackT, ss_sp) == 0);
    assert!(offset_of!(StackT, ss_flags) == 8);
    assert!(offset_of!(StackT, ss_size) == 16);
};
