//! C-ABI struct definitions matching `coredumper/google/coredumper.h`.
//!
//! Layouts are asserted at compile time against known-good C layout values.
//! (x86_64 System V ABI). Do not reorder fields.

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::mem::{align_of, offset_of, size_of};

/// Mirror of `struct CoredumperCompressor` (golden: size 24, align 8).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CoredumperCompressor {
    /// Compressor executable path, or null to terminate a table.
    pub compressor: *const c_char,
    /// Null-terminated argv array for the compressor.
    pub args: *const *const c_char,
    /// Filename suffix to append for this compressor.
    pub suffix: *const c_char,
}

/// Mirror of `struct CoredumperNote` (golden: size 24, align 8).
#[repr(C)]
pub struct CoredumperNote {
    /// Note owner/name as a NUL-terminated C string.
    pub name: *const c_char,
    /// ELF note type.
    pub r#type: c_uint,
    /// Descriptor payload size in bytes.
    pub description_size: c_uint,
    /// Descriptor payload pointer.
    pub description: *const c_void,
}

/// Mirror of `struct CoreDumpParameters` (golden: size 72, align 8).
#[repr(C)]
pub struct CoreDumpParameters {
    /// Size of this versioned struct in bytes.
    pub size: usize,
    /// Coredumper option flags.
    pub flags: c_int,
    /// Maximum output length, or `usize::MAX` for unlimited.
    pub max_length: usize,
    /// Compressor table pointer.
    pub compressors: *const CoredumperCompressor,
    /// Optional out-pointer receiving the selected compressor entry.
    pub selected_compressor: *mut *mut CoredumperCompressor,
    /// Extra ELF notes to emit.
    pub notes: *const CoredumperNote,
    /// Number of entries in `notes`.
    pub note_count: c_int,
    /// Optional callback invoked after thread suspension.
    pub callback_fn: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    /// Opaque callback argument.
    pub callback_arg: *mut c_void,
}

// --- Compile-time ABI assertions against C layout values ---------------------
// A mismatch here means the Rust layout has drifted from the C header; fix the
// struct, never the assertion.

const _: () = {
    assert!(size_of::<CoredumperCompressor>() == 24);
    assert!(align_of::<CoredumperCompressor>() == 8);
    assert!(offset_of!(CoredumperCompressor, compressor) == 0);
    assert!(offset_of!(CoredumperCompressor, args) == 8);
    assert!(offset_of!(CoredumperCompressor, suffix) == 16);

    assert!(size_of::<CoredumperNote>() == 24);
    assert!(align_of::<CoredumperNote>() == 8);
    assert!(offset_of!(CoredumperNote, name) == 0);
    assert!(offset_of!(CoredumperNote, r#type) == 8);
    assert!(offset_of!(CoredumperNote, description_size) == 12);
    assert!(offset_of!(CoredumperNote, description) == 16);

    assert!(size_of::<CoreDumpParameters>() == 72);
    assert!(align_of::<CoreDumpParameters>() == 8);
    assert!(offset_of!(CoreDumpParameters, size) == 0);
    assert!(offset_of!(CoreDumpParameters, flags) == 8);
    assert!(offset_of!(CoreDumpParameters, max_length) == 16);
    assert!(offset_of!(CoreDumpParameters, compressors) == 24);
    assert!(offset_of!(CoreDumpParameters, selected_compressor) == 32);
    assert!(offset_of!(CoreDumpParameters, notes) == 40);
    assert!(offset_of!(CoreDumpParameters, note_count) == 48);
    assert!(offset_of!(CoreDumpParameters, callback_fn) == 56);
    assert!(offset_of!(CoreDumpParameters, callback_arg) == 64);
};
