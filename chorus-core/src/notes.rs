//! ELF note construction for the PT_NOTE segment.
//!
//! Ports the note-emitting logic interleaved through `CreateElfCore` /
//! `WriteThreadRegs` in `elfcore.c`: each note is an [`Nhdr`] followed by a
//! 4-byte-aligned name and a 4-byte-aligned descriptor. These helpers compute
//! sizes for the PT_NOTE phdr and stream notes through a
//! [`Writer`].
//!
//! Note names in core files are NUL-terminated and the C pads the common
//! `"CORE"` name to 8 bytes (`"CORE\0\0\0\0"`), i.e. `n_namesz = 5` with 3 bytes
//! of padding. We reproduce that exactly.

use crate::elf::{
    AuxvT, NT_AUXV, NT_FILE, NT_PRFPREG, NT_PRPSINFO, NT_PRSTATUS, Nhdr, Prpsinfo, Prstatus,
};
use crate::io::{WriteError, Writer};
use core::{mem, slice};

/// The padded `"CORE"` note name used by Linux core notes: 5 significant bytes
/// (`n_namesz = 5`) written as 8 bytes including alignment padding.
pub const CORE_NAME: &[u8; 8] = b"CORE\0\0\0\0";
/// Significant byte length of the common `"CORE"` note name including NUL.
pub const CORE_NAMESZ: u32 = 5;

/// ELF note name/descriptor alignment.
pub const NOTE_ALIGN: usize = mem::align_of::<Nhdr>();

/// Round `n` up to the next ELF note alignment boundary.
#[inline]
pub const fn align_note(n: usize) -> usize {
    (n + (NOTE_ALIGN - 1)) & !(NOTE_ALIGN - 1)
}

/// Wrapper error for NoteWriteErrors.
pub struct NoteWriteError(WriteError);

impl core::fmt::Debug for NoteWriteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "NoteWriteError({:?})", self.0)
    }
}

impl From<WriteError> for NoteWriteError {
    fn from(e: WriteError) -> Self {
        NoteWriteError(e)
    }
}

/// Bytes a note occupies in the file: header + padded name + padded descriptor.
pub const fn note_size(namesz: usize, descsz: usize) -> usize {
    mem::size_of::<Nhdr>() + align_note(namesz) + align_note(descsz)
}

/// Write `count` zero padding bytes (count is 0..=3 for note alignment).
fn pad(w: &mut dyn Writer, count: usize) -> Result<(), NoteWriteError> {
    const ZEROS: [u8; 4] = [0; 4];
    if count == 0 {
        return Ok(());
    }
    w.write_full(&ZEROS[..count]).map_err(NoteWriteError)
}

/// Write one fixed-payload CORE note (header + "CORE" name + descriptor).
/// Used for PRSTATUS, PRFPREG, PRPSINFO, etc.
fn write_core_note(w: &mut dyn Writer, n_type: u32, desc: &[u8]) -> Result<(), NoteWriteError> {
    let descsz = desc.len();
    let nhdr = Nhdr {
        n_namesz: CORE_NAMESZ,
        n_descsz: descsz as u32,
        n_type,
    };
    w.write_full(nhdr.as_bytes())?;
    w.write_full(CORE_NAME)?;
    w.write_full(desc)?;
    pad(w, align_note(descsz) - descsz)
}

/// Write the NT_PRPSINFO note (process state/cmdline summary).
///
/// # Errors
/// Returns [`WriteError`] if the writer reports an error or short write.
pub fn write_prpsinfo(w: &mut dyn Writer, info: &Prpsinfo) -> Result<(), NoteWriteError> {
    write_core_note(w, NT_PRPSINFO, info.as_bytes())
}

/// Write a thread's NT_PRSTATUS note (signal info + integer registers). The
/// caller fills `pr_pid`/`pr_reg` before calling (port of `WriteThreadRegs`).
///
/// # Errors
/// Returns [`WriteError`] if the writer reports an error or short write.
pub fn write_prstatus(w: &mut dyn Writer, status: &Prstatus) -> Result<(), NoteWriteError> {
    write_core_note(w, NT_PRSTATUS, status.as_bytes())
}

/// Write a thread's NT_PRFPREG (FPU/SSE registers) note.
///
/// # Errors
/// Returns [`WriteError`] if the writer reports an error or short write.
pub fn write_prfpreg(
    w: &mut dyn Writer,
    fpregs: &crate::elf::FpRegs,
) -> Result<(), NoteWriteError> {
    write_core_note(w, NT_PRFPREG, fpregs.as_bytes())
}

/// Write the NT_PRXREG (a.k.a. NT_TASKSTRUCT) note carrying the `core_user`
/// payload for the main thread.
///
/// # Errors
/// Returns [`WriteError`] if the writer reports an error or short write.
pub fn write_prxreg(w: &mut dyn Writer, user: &crate::elf::CoreUser) -> Result<(), NoteWriteError> {
    write_core_note(w, crate::elf::NT_PRXREG, user.as_bytes())
}

/// Write a user-supplied extra note: the header, then the NUL-terminated `name`
/// (4-aligned), then the `description` (4-aligned). Port of the extra-notes loop
/// in `CreateElfCore`. Unlike the CORE notes, `n_namesz` includes the trailing
/// NUL and the name is the caller's, not `"CORE"`.
///
/// # Errors
/// Returns [`WriteError`] if the writer reports an error or short write.
pub fn write_extra_note(
    w: &mut dyn Writer,
    name: &[u8],
    note_type: u32,
    desc: &[u8],
) -> Result<(), NoteWriteError> {
    let namesz = name.len() + 1; // include NUL
    let descsz = desc.len();
    let nhdr = Nhdr {
        n_namesz: namesz as u32,
        n_descsz: descsz as u32,
        n_type: note_type,
    };
    w.write_full(nhdr.as_bytes())?;
    w.write_full(name)?;
    w.write_full(&[0u8])?; // name NUL
    pad(w, align_note(namesz) - namesz)?;
    w.write_full(desc)?;
    pad(w, align_note(descsz) - descsz)
}

/// Write the NT_AUXV note from a slice of auxv entries.
///
/// # Errors
/// Returns [`WriteError`] if the writer reports an error or short write.
pub fn write_auxv(w: &mut dyn Writer, auxv: &[crate::elf::AuxvT]) -> Result<(), NoteWriteError> {
    let descsz = mem::size_of_val(auxv);
    let nhdr = Nhdr {
        n_namesz: CORE_NAMESZ,
        n_descsz: descsz as u32,
        n_type: NT_AUXV,
    };
    w.write_full(nhdr.as_bytes())?;
    w.write_full(CORE_NAME)?;
    w.write_full(AuxvT::slice_as_bytes(auxv))?;
    pad(w, align_note(descsz) - descsz)
}

/// Compute the NT_FILE descriptor length for the given mappings, matching the C:
/// `2*sizeof(long)` header (count, pagesize) + per-file `3*sizeof(long)` triple
/// + each NUL-terminated name. Returns `(file_count, desc_len_unpadded)`.
pub fn nt_file_sizes(mappings: &[crate::proc_parse::Mapping]) -> (usize, usize) {
    let long = mem::size_of::<i64>();
    let mut count = 0usize;
    let mut triples_and_names = 0usize;
    for m in mappings {
        if !m.is_anon {
            count += 1;
            triples_and_names += 3 * long + m.name_len as usize + 1;
        }
    }
    if count == 0 {
        return (0, 0);
    }
    (count, 2 * long + triples_and_names)
}

/// Write the NT_FILE note (file-backed mapping table). `pagesize` is used to
/// express the file offset in pages, exactly as the C does.
///
/// # Errors
/// Returns [`WriteError`] if the writer reports an error or short write.
pub fn write_nt_file(
    w: &mut dyn Writer,
    mappings: &[crate::proc_parse::Mapping],
    pagesize: usize,
) -> Result<(), NoteWriteError> {
    let (count, desc_len) = nt_file_sizes(mappings);
    if count == 0 {
        return Ok(());
    }
    let nhdr = Nhdr {
        n_namesz: CORE_NAMESZ,
        n_descsz: desc_len as u32,
        n_type: NT_FILE,
    };
    w.write_full(nhdr.as_bytes())?;
    w.write_full(CORE_NAME)?;
    // Header: count, pagesize (as longs).
    let header = [count as i64, pagesize as i64];
    w.write_full(i64s_as_bytes(&header))?;
    // start/end/(offset/pagesize) triples.
    for m in mappings {
        if !m.is_anon {
            let triple = [m.start as i64, m.end as i64, (m.offset / pagesize) as i64];
            w.write_full(i64s_as_bytes(&triple))?;
        }
    }
    // NUL-terminated names.
    for m in mappings {
        if !m.is_anon {
            let name_with_nul = &m.name[..m.name_len as usize + 1];
            w.write_full(name_with_nul)?;
        }
    }
    // Pad the whole descriptor to 4 bytes.
    pad(w, align_note(desc_len) - desc_len)
}

/// Reinterpret native-endian i64 words as bytes for NT_FILE descriptors.
fn i64s_as_bytes(words: &[i64]) -> &[u8] {
    // SAFETY: i64 is plain integer data and `words` is a contiguous slice.
    unsafe { slice::from_raw_parts(words.as_ptr() as *const u8, mem::size_of_val(words)) }
}
