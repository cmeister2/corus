//! ELF, register, and note struct definitions for x86_64 core files.
//!
//! Faithful port of the hand-rolled definitions in `coredumper/elfcore.{c,h}` plus the
//! relevant `Elf64_*` types from `<elf.h>`. All layouts are asserted at compile
//! time against known-good C layout values. A wrong offset here silently
//! corrupts the core file, so do not reorder fields.
//!
//! This is x86_64-only; other arches should add `#[cfg(target_arch)]` variants of
//! [`Regs`]/[`FpRegs`] and the `EM_*`/wordsize constants.

#![allow(non_camel_case_types)]

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong};
use core::{mem, slice};

// --- ELF identification constants (e_ident) ---------------------------------

/// Number of bytes in `Elf64_Ehdr::e_ident`.
pub const EI_NIDENT: usize = 16;
/// ELF magic bytes.
pub const ELFMAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];
/// ELF class value for 64-bit objects.
pub const ELFCLASS64: u8 = 2;
/// ELF data encoding value for little-endian objects.
pub const ELFDATA2LSB: u8 = 1;
/// Current ELF version value.
pub const EV_CURRENT: u8 = 1;
/// System V ABI identifier.
pub const ELFOSABI_SYSV: u8 = 0;

// e_ident indices
/// Index of the first ELF magic byte in `e_ident`.
pub const EI_MAG0: usize = 0;
/// Index of the ELF class byte in `e_ident`.
pub const EI_CLASS: usize = 4;
/// Index of the ELF data encoding byte in `e_ident`.
pub const EI_DATA: usize = 5;
/// Index of the ELF version byte in `e_ident`.
pub const EI_VERSION: usize = 6;
/// Index of the ELF OS ABI byte in `e_ident`.
pub const EI_OSABI: usize = 7;

// e_type
/// ELF file type value for core files.
pub const ET_CORE: u16 = 4;
// e_machine
/// ELF machine value for x86_64.
pub const EM_X86_64: u16 = 62;
/// ELF machine value for aarch64 (ARM64).
pub const EM_AARCH64: u16 = 183;

/// The `e_machine` value for the architecture this build targets. Set into the
/// core file's ELF header so debuggers identify the dump's ISA correctly.
#[cfg(target_arch = "x86_64")]
pub const ELF_MACHINE: u16 = EM_X86_64;
/// The `e_machine` value for the architecture this build targets.
#[cfg(target_arch = "aarch64")]
pub const ELF_MACHINE: u16 = EM_AARCH64;

// Program header p_type
/// Program header type for loadable segments.
pub const PT_LOAD: u32 = 1;
/// Program header type for the notes segment.
pub const PT_NOTE: u32 = 4;
// Program header p_flags
/// Program header execute permission bit.
pub const PF_X: u32 = 1;
/// Program header write permission bit.
pub const PF_W: u32 = 2;
/// Program header read permission bit.
pub const PF_R: u32 = 4;

// Note types used in core files
/// Note type for `prstatus` thread status.
pub const NT_PRSTATUS: u32 = 1;
/// Note type for floating-point register state.
pub const NT_PRFPREG: u32 = 2;
/// Note type for process status information.
pub const NT_PRPSINFO: u32 = 3;
/// a.k.a. NT_TASKSTRUCT; payload is `core_user`.
pub const NT_PRXREG: u32 = 4;
/// Note type for AUXV entries.
pub const NT_AUXV: u32 = 6;
/// Note type for the NT_FILE mapping table.
pub const NT_FILE: u32 = 0x46494c45;

// --- ELF file structures (Elf64_*) ------------------------------------------

/// `Elf64_Ehdr` (golden: size 64, align 8).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ehdr {
    /// ELF identification bytes.
    pub e_ident: [u8; EI_NIDENT],
    /// ELF file type.
    pub e_type: u16,
    /// Target machine architecture.
    pub e_machine: u16,
    /// ELF version.
    pub e_version: u32,
    /// Entry point virtual address.
    pub e_entry: u64,
    /// Program header table file offset.
    pub e_phoff: u64,
    /// Section header table file offset.
    pub e_shoff: u64,
    /// Processor-specific flags.
    pub e_flags: u32,
    /// ELF header size in bytes.
    pub e_ehsize: u16,
    /// Program header entry size in bytes.
    pub e_phentsize: u16,
    /// Number of program header entries.
    pub e_phnum: u16,
    /// Section header entry size in bytes.
    pub e_shentsize: u16,
    /// Number of section header entries.
    pub e_shnum: u16,
    /// Section-name string table index.
    pub e_shstrndx: u16,
}

/// `Elf64_Phdr` (golden: size 56, align 8). Note x86_64 field order:
/// `p_flags` follows `p_type` (unlike Elf32).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Phdr {
    /// Program header type.
    pub p_type: u32,
    /// Segment permission flags.
    pub p_flags: u32,
    /// Segment file offset.
    pub p_offset: u64,
    /// Segment virtual address.
    pub p_vaddr: u64,
    /// Segment physical address.
    pub p_paddr: u64,
    /// Segment size in the file.
    pub p_filesz: u64,
    /// Segment size in memory.
    pub p_memsz: u64,
    /// Segment alignment.
    pub p_align: u64,
}

/// `Elf64_Shdr` (golden: size 64, align 8).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Shdr {
    /// Section name string-table offset.
    pub sh_name: u32,
    /// Section type.
    pub sh_type: u32,
    /// Section flags.
    pub sh_flags: u64,
    /// Section virtual address.
    pub sh_addr: u64,
    /// Section file offset.
    pub sh_offset: u64,
    /// Section size in bytes.
    pub sh_size: u64,
    /// Section link field.
    pub sh_link: u32,
    /// Section info field.
    pub sh_info: u32,
    /// Section alignment.
    pub sh_addralign: u64,
    /// Section entry size.
    pub sh_entsize: u64,
}

/// `Elf64_Nhdr` (golden: size 12, align 4). A note's name and descriptor
/// follow this header, each padded to 4-byte alignment.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Nhdr {
    /// Note name size including the trailing NUL.
    pub n_namesz: u32,
    /// Note descriptor size.
    pub n_descsz: u32,
    /// Note type.
    pub n_type: u32,
}

/// AUXV `a_type` for the kernel page size (`AT_PAGESZ`). Used to obtain the
/// real runtime page size, which on aarch64 is not a compile-time constant
/// (kernels ship 4K/16K/64K).
pub const AT_PAGESZ: u64 = 6;

/// `Elf64_auxv_t` (golden: size 16, align 8).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AuxvT {
    /// AUXV entry type.
    pub a_type: u64,
    /// AUXV entry value.
    pub a_val: u64,
}

// --- Register / note payload structures (from elfcore.{c,h}) ----------------

/// x86_64 general-purpose registers - `i386_regs` for `__x86_64__`
/// (golden: size 216, align 8). Matches the kernel `user_regs_struct` order
/// that `PTRACE_GETREGS` fills.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Regs {
    /// General-purpose register r15.
    pub r15: u64,
    /// General-purpose register r14.
    pub r14: u64,
    /// General-purpose register r13.
    pub r13: u64,
    /// General-purpose register r12.
    pub r12: u64,
    /// Base pointer register.
    pub rbp: u64,
    /// General-purpose register rbx.
    pub rbx: u64,
    /// General-purpose register r11.
    pub r11: u64,
    /// General-purpose register r10.
    pub r10: u64,
    /// General-purpose register r9.
    pub r9: u64,
    /// General-purpose register r8.
    pub r8: u64,
    /// Accumulator register.
    pub rax: u64,
    /// Counter register.
    pub rcx: u64,
    /// Data register.
    pub rdx: u64,
    /// Source index register.
    pub rsi: u64,
    /// Destination index register.
    pub rdi: u64,
    /// Original syscall number register value.
    pub orig_rax: u64,
    /// Instruction pointer.
    pub rip: u64,
    /// Code segment selector.
    pub cs: u64,
    /// CPU flags register.
    pub eflags: u64,
    /// Stack pointer.
    pub rsp: u64,
    /// Stack segment selector.
    pub ss: u64,
    /// FS base address.
    pub fs_base: u64,
    /// GS base address.
    pub gs_base: u64,
    /// Data segment selector.
    pub ds: u64,
    /// Extra segment selector.
    pub es: u64,
    /// FS segment selector.
    pub fs: u64,
    /// GS segment selector.
    pub gs: u64,
}

/// aarch64 general-purpose registers - the kernel `user_regs_struct`
/// (`struct user_pt_regs`, golden: size 272, align 8) that
/// `PTRACE_GETREGSET`+`NT_PRSTATUS` fills. This is also the `arm64_regs` shape
/// in the original coredumper's `elfcore.h`.
#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Regs {
    /// General-purpose registers x0..x30 (x30 is the link register).
    pub regs: [u64; 31],
    /// Stack pointer.
    pub sp: u64,
    /// Program counter.
    pub pc: u64,
    /// Processor state (NZCV flags, etc.).
    pub pstate: u64,
}

/// x86_64 FPU/SSE registers - `fpregs` (golden: size 512, align 4). This is the
/// `user_fpregs_struct` that `PTRACE_GETFPREGS` fills.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FpRegs {
    /// x87 control word.
    pub cwd: u16,
    /// x87 status word.
    pub swd: u16,
    /// x87 tag word.
    pub twd: u16,
    /// Last x87 opcode.
    pub fop: u16,
    /// FPU instruction pointer offset.
    pub fip: u32,
    /// FPU instruction pointer selector.
    pub fcs: u32,
    /// FPU operand pointer offset.
    pub foo: u32,
    /// FPU operand pointer selector.
    pub fos: u32,
    /// SSE control and status register.
    pub mxcsr: u32,
    /// Supported MXCSR mask.
    pub mxcsr_mask: u32,
    /// x87 register space.
    pub st_space: [u32; 32],
    /// XMM register space.
    pub xmm_space: [u32; 64],
    /// Reserved kernel padding.
    pub padding: [u32; 24],
}

/// aarch64 FP/SIMD registers - the kernel `user_fpsimd_state`
/// (golden: size 528, align 16) that `PTRACE_GETREGSET`+`NT_FPREGSET` fills.
#[cfg(target_arch = "aarch64")]
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct FpRegs {
    /// SIMD/FP registers v0..v31 (128-bit each).
    pub vregs: [u128; 32],
    /// Floating-point status register.
    pub fpsr: u32,
    /// Floating-point control register.
    pub fpcr: u32,
}

/// `elf_timeval` (golden: size 16, align 8).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ElfTimeval {
    /// Seconds component.
    pub tv_sec: c_long,
    /// Microseconds component.
    pub tv_usec: c_long,
}

/// `elf_siginfo` (golden: size 12, align 4).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ElfSiginfo {
    /// Signal number.
    pub si_signo: c_int,
    /// Signal code.
    pub si_code: c_int,
    /// Associated errno.
    pub si_errno: c_int,
}

/// `prstatus` - the NT_PRSTATUS note payload (golden: size 336, align 8).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Prstatus {
    /// Signal info for the thread.
    pub pr_info: ElfSiginfo,
    /// Current signal.
    pub pr_cursig: u16,
    /// Pending signal mask.
    pub pr_sigpend: c_ulong,
    /// Held signal mask.
    pub pr_sighold: c_ulong,
    /// Thread id.
    pub pr_pid: c_int,
    /// Parent process id.
    pub pr_ppid: c_int,
    /// Process group id.
    pub pr_pgrp: c_int,
    /// Session id.
    pub pr_sid: c_int,
    /// User CPU time.
    pub pr_utime: ElfTimeval,
    /// System CPU time.
    pub pr_stime: ElfTimeval,
    /// Cumulative child user CPU time.
    pub pr_cutime: ElfTimeval,
    /// Cumulative child system CPU time.
    pub pr_cstime: ElfTimeval,
    /// General-purpose register snapshot.
    pub pr_reg: Regs,
    /// Nonzero if floating-point registers are valid.
    pub pr_fpvalid: u32,
}

/// `prpsinfo` - the NT_PRPSINFO note payload (golden: size 136, align 8).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Prpsinfo {
    /// Process state code.
    pub pr_state: u8,
    /// Printable process state character.
    pub pr_sname: c_char,
    /// Nonzero if the process is a zombie.
    pub pr_zomb: u8,
    /// Process nice value.
    pub pr_nice: i8,
    /// Process flags.
    pub pr_flag: c_ulong,
    /// Real user id.
    pub pr_uid: c_uint,
    /// Real group id.
    pub pr_gid: c_uint,
    /// Process id.
    pub pr_pid: c_int,
    /// Parent process id.
    pub pr_ppid: c_int,
    /// Process group id.
    pub pr_pgrp: c_int,
    /// Session id.
    pub pr_sid: c_int,
    /// Short executable name.
    pub pr_fname: [c_char; 16],
    /// Process argument string.
    pub pr_psargs: [c_char; 80],
}

/// `core_user` - the NT_PRXREG / NT_TASKSTRUCT note payload (the kernel `user`
/// struct, golden: size 928 on x86_64). gdb reads `regs`/`fpregs` here as a
/// fallback; the C fills the rest via `PTRACE_PEEKUSER` then overwrites `regs`.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CoreUser {
    /// General-purpose register snapshot.
    pub regs: Regs,
    /// Nonzero if floating-point registers are valid.
    pub fpvalid: c_ulong,
    /// Floating-point/SSE register snapshot.
    pub fpregs: FpRegs,
    /// Text segment size.
    pub tsize: c_ulong,
    /// Data segment size.
    pub dsize: c_ulong,
    /// Stack segment size.
    pub ssize: c_ulong,
    /// Text segment start address.
    pub start_code: c_ulong,
    /// Stack start address.
    pub start_stack: c_ulong,
    /// Signal value.
    pub signal: c_ulong,
    /// Reserved word.
    pub reserved: c_ulong,
    /// Pointer to the register block.
    pub regs_ptr: *mut Regs,
    /// Pointer to the floating-point register block.
    pub fpregs_ptr: *mut FpRegs,
    /// Kernel user-struct magic value.
    pub magic: c_ulong,
    /// Command name.
    pub comm: [c_char; 32],
    /// Debug registers.
    pub debugreg: [c_ulong; 8],
    /// Last exception error code.
    pub error_code: c_ulong,
    /// Faulting address.
    pub fault_address: c_ulong,
}

/// `core_user` - the NT_PRXREG note payload on aarch64. Matches the original
/// coredumper `core_user` layout for `__aarch64__`: no `error_code`/
/// `fault_address`; instead the FP registers and an `fpregs_ptr` follow the
/// debug registers (see `elfcore.c`).
#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CoreUser {
    /// General-purpose register snapshot.
    pub regs: Regs,
    /// Nonzero if floating-point registers are valid.
    pub fpvalid: c_ulong,
    /// Text segment size.
    pub tsize: c_ulong,
    /// Data segment size.
    pub dsize: c_ulong,
    /// Stack segment size.
    pub ssize: c_ulong,
    /// Text segment start address.
    pub start_code: c_ulong,
    /// Stack start address.
    pub start_stack: c_ulong,
    /// Signal value.
    pub signal: c_ulong,
    /// Reserved word.
    pub reserved: c_ulong,
    /// Pointer to the register block.
    pub regs_ptr: *mut Regs,
    /// Kernel user-struct magic value.
    pub magic: c_ulong,
    /// Command name.
    pub comm: [c_char; 32],
    /// Debug registers.
    pub debugreg: [c_ulong; 8],
    /// Floating-point/SIMD register snapshot.
    pub fpregs: FpRegs,
    /// Pointer to the floating-point register block.
    pub fpregs_ptr: *mut FpRegs,
}

impl Ehdr {
    /// A zeroed Ehdr with the x86_64 core-file `e_ident` filled in and the
    /// fixed `e_*size`/version fields set. Caller fills `e_phoff`/`e_phnum`/etc.
    pub fn new_core() -> Self {
        // SAFETY: Ehdr is plain-old-data; all-zero is a valid starting state.
        let mut e: Ehdr = unsafe { mem::zeroed() };
        e.e_ident[EI_MAG0..EI_MAG0 + 4].copy_from_slice(&ELFMAG);
        e.e_ident[EI_CLASS] = ELFCLASS64;
        e.e_ident[EI_DATA] = ELFDATA2LSB;
        e.e_ident[EI_VERSION] = EV_CURRENT;
        e.e_ident[EI_OSABI] = ELFOSABI_SYSV;
        e.e_type = ET_CORE;
        e.e_machine = ELF_MACHINE;
        e.e_version = EV_CURRENT as u32;
        e.e_ehsize = mem::size_of::<Ehdr>() as u16;
        e.e_phentsize = mem::size_of::<Phdr>() as u16;
        e.e_shentsize = mem::size_of::<Shdr>() as u16;
        e
    }

    /// Reinterpret this header as a byte slice for writing to the core file.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: Ehdr is repr(C) POD; reading its own bytes is valid and the
        // slice borrows from &self.
        unsafe { slice::from_raw_parts(self as *const Ehdr as *const u8, mem::size_of::<Ehdr>()) }
    }
}

impl Phdr {
    /// Reinterpret this program header as a byte slice for writing to the core file.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: Phdr is repr(C) POD; reading its own bytes is valid and the
        // slice borrows from &self.
        unsafe { slice::from_raw_parts(self as *const Phdr as *const u8, mem::size_of::<Phdr>()) }
    }
}

impl Nhdr {
    /// Reinterpret this note header as a byte slice for writing to the core file.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: Nhdr is repr(C) POD; reading its own bytes is valid and the
        // slice borrows from &self.
        unsafe { slice::from_raw_parts(self as *const Nhdr as *const u8, mem::size_of::<Nhdr>()) }
    }
}

impl AuxvT {
    /// Reinterpret an AUXV slice as bytes for writing to an ELF note.
    pub fn slice_as_bytes(auxv: &[Self]) -> &[u8] {
        // SAFETY: AuxvT is repr(C) POD and `auxv` is a contiguous slice.
        unsafe { slice::from_raw_parts(auxv.as_ptr() as *const u8, mem::size_of_val(auxv)) }
    }
}

impl FpRegs {
    /// Reinterpret this floating-point register payload as bytes for a note.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: FpRegs is repr(C) POD; reading its own bytes is valid and the
        // slice borrows from &self.
        unsafe {
            slice::from_raw_parts(self as *const FpRegs as *const u8, mem::size_of::<FpRegs>())
        }
    }
}

impl Prstatus {
    /// Reinterpret this PRSTATUS payload as bytes for a note.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: Prstatus is repr(C) POD; reading its own bytes is valid and the
        // slice borrows from &self.
        unsafe {
            slice::from_raw_parts(
                self as *const Prstatus as *const u8,
                mem::size_of::<Prstatus>(),
            )
        }
    }
}

impl Prpsinfo {
    /// Reinterpret this PRPSINFO payload as bytes for a note.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: Prpsinfo is repr(C) POD; reading its own bytes is valid and the
        // slice borrows from &self.
        unsafe {
            slice::from_raw_parts(
                self as *const Prpsinfo as *const u8,
                mem::size_of::<Prpsinfo>(),
            )
        }
    }
}

impl CoreUser {
    /// Reinterpret this NT_PRXREG payload as bytes for a note.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: CoreUser is repr(C) POD; reading its own bytes is valid and the
        // slice borrows from &self.
        unsafe {
            slice::from_raw_parts(
                self as *const CoreUser as *const u8,
                mem::size_of::<CoreUser>(),
            )
        }
    }
}

// --- Compile-time layout assertions against C layout values ------------------
const _: () = {
    use mem::{align_of, offset_of, size_of};

    // ELF file structs
    assert!(size_of::<Ehdr>() == 64 && align_of::<Ehdr>() == 8);
    assert!(offset_of!(Ehdr, e_type) == 16);
    assert!(offset_of!(Ehdr, e_machine) == 18);
    assert!(offset_of!(Ehdr, e_entry) == 24);
    assert!(offset_of!(Ehdr, e_phoff) == 32);
    assert!(offset_of!(Ehdr, e_phnum) == 56);
    assert!(offset_of!(Ehdr, e_shstrndx) == 62);

    assert!(size_of::<Phdr>() == 56 && align_of::<Phdr>() == 8);
    assert!(offset_of!(Phdr, p_type) == 0);
    assert!(offset_of!(Phdr, p_flags) == 4);
    assert!(offset_of!(Phdr, p_offset) == 8);
    assert!(offset_of!(Phdr, p_vaddr) == 16);
    assert!(offset_of!(Phdr, p_filesz) == 32);
    assert!(offset_of!(Phdr, p_memsz) == 40);
    assert!(offset_of!(Phdr, p_align) == 48);

    assert!(size_of::<Shdr>() == 64 && align_of::<Shdr>() == 8);

    assert!(size_of::<Nhdr>() == 12 && align_of::<Nhdr>() == 4);
    assert!(offset_of!(Nhdr, n_namesz) == 0);
    assert!(offset_of!(Nhdr, n_descsz) == 4);
    assert!(offset_of!(Nhdr, n_type) == 8);

    assert!(size_of::<AuxvT>() == 16 && align_of::<AuxvT>() == 8);

    assert!(size_of::<ElfTimeval>() == 16 && align_of::<ElfTimeval>() == 8);
    assert!(size_of::<ElfSiginfo>() == 12 && align_of::<ElfSiginfo>() == 4);

    // Prpsinfo is arch-neutral (no register fields).
    assert!(size_of::<Prpsinfo>() == 136 && align_of::<Prpsinfo>() == 8);
    assert!(offset_of!(Prpsinfo, pr_flag) == 8);
    assert!(offset_of!(Prpsinfo, pr_uid) == 16);
    assert!(offset_of!(Prpsinfo, pr_pid) == 24);
    assert!(offset_of!(Prpsinfo, pr_fname) == 40);
    assert!(offset_of!(Prpsinfo, pr_psargs) == 56);
};

// Register/note payloads whose size depends on the target's register file.
// `Regs`/`FpRegs` (and thus `Prstatus`/`CoreUser`, which embed them) are
// arch-specific; each arch asserts its own golden layout from the C ABI.
#[cfg(target_arch = "x86_64")]
const _: () = {
    use mem::{align_of, offset_of, size_of};

    assert!(size_of::<Regs>() == 216 && align_of::<Regs>() == 8);
    assert!(offset_of!(Regs, r15) == 0);
    assert!(offset_of!(Regs, rip) == 128);
    assert!(offset_of!(Regs, rsp) == 152);
    assert!(offset_of!(Regs, gs_base) == 176);

    assert!(size_of::<FpRegs>() == 512 && align_of::<FpRegs>() == 4);
    assert!(offset_of!(FpRegs, mxcsr) == 24);
    assert!(offset_of!(FpRegs, st_space) == 32);
    assert!(offset_of!(FpRegs, xmm_space) == 160);

    assert!(size_of::<Prstatus>() == 336 && align_of::<Prstatus>() == 8);
    assert!(offset_of!(Prstatus, pr_info) == 0);
    assert!(offset_of!(Prstatus, pr_cursig) == 12);
    assert!(offset_of!(Prstatus, pr_pid) == 32);
    assert!(offset_of!(Prstatus, pr_reg) == 112);
    assert!(offset_of!(Prstatus, pr_fpvalid) == 328);

    assert!(size_of::<CoreUser>() == 928 && align_of::<CoreUser>() == 8);
    assert!(offset_of!(CoreUser, regs) == 0);
};
