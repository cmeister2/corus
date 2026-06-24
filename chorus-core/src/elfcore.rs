//! Core file assembly - port of `CreateElfCore` from `elfcore.c`.
//!
//! Lays out and streams an ELF core file: the `Ehdr`, a `PT_NOTE` program
//! header followed by one `PT_LOAD` per dumped memory mapping, the note section
//! (PRPSINFO, per-thread PRSTATUS + PRFPREG, AUXV, NT_FILE), page alignment, and
//! finally the segment contents.
//!
//! x86_64: the `[vdso]` mapping is dumped as an ordinary segment
//! (it appears in `/proc/self/maps`), rather than the C's special vdso-phdr
//! extraction. That extra handling improves gdb unwinding *through* the vdso but
//! is not required for a loadable core.

use crate::elf::{AuxvT, Ehdr, FpRegs, PT_LOAD, PT_NOTE, Phdr, Prpsinfo, Prstatus, Regs};
use crate::io::Writer;
use crate::notes::{self, NoteWriteError, note_size};
use crate::proc_parse::Mapping;
use core::mem;

/// Error returned while assembling the ELF core file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateElfCoreError {
    /// Writing the ELF header failed.
    Ehdr,
    /// Writing a program header failed.
    Phdr,
    /// Writing the PT_NOTE section failed.
    Notes,
    /// Writing page-alignment padding failed.
    Padding,
    /// Writing a PT_LOAD segment failed.
    Segment,
}

/// Convert a NoteWriteError into the generic CreateElfCoreError::Notes.
impl From<NoteWriteError> for CreateElfCoreError {
    fn from(_: NoteWriteError) -> Self {
        Self::Notes
    }
}

/// Per-thread captured state for the core's PRSTATUS/PRFPREG notes.
#[derive(Clone, Copy)]
pub struct ThreadState {
    /// Thread id for the note payloads.
    pub pid: i32,
    /// Captured general-purpose registers.
    pub regs: Regs,
    /// Captured floating-point/SSE registers.
    pub fpregs: FpRegs,
}

/// Inputs to [`CoreInputs::write_core`], gathered by the orchestrator while threads are
/// suspended.
pub struct CoreInputs<'a> {
    /// Process-wide PRPSINFO note payload.
    pub prpsinfo: &'a Prpsinfo,
    /// Per-thread captured state.
    pub threads: &'a [ThreadState],
    /// Index in `threads` of the "main"/crashed thread, dumped first so gdb
    /// treats it as the faulting thread.
    pub main_thread: usize,
    /// AUXV entries copied into the core.
    pub auxv: &'a [AuxvT],
    /// Memory mappings selected for PT_LOAD segments and NT_FILE.
    pub mappings: &'a [Mapping],
    /// System page size used for segment alignment.
    pub pagesize: usize,
    /// User-supplied extra notes (`SetCoreDumpNotes`).
    pub notes: &'a [crate::dump::ExtraNote<'a>],
    /// The NT_PRXREG (`core_user`) payload for the main thread, if captured.
    pub user: Option<&'a crate::elf::CoreUser>,
}

impl CoreInputs<'_> {
    /// Compute the total byte size of the PT_NOTE section for these inputs.
    fn note_section_size(&self) -> usize {
        note_section_size_for(
            self.threads.len(),
            self.auxv.len(),
            self.mappings,
            self.notes,
            self.user.is_some(),
        )
    }

    /// Write the full PT_NOTE section.
    fn write_notes(&self, w: &mut dyn Writer) -> Result<(), CreateElfCoreError> {
        // PRPSINFO first.
        notes::write_prpsinfo(w, self.prpsinfo)?;
        // NT_PRXREG (core_user) for the main thread, right after PRPSINFO (matches
        // the C's note order, which gdb/readelf expect).
        if let Some(user) = self.user {
            notes::write_prxreg(w, user)?;
        }
        // Threads, crashed/main thread first (gdb assumes the first is the one that
        // faulted), then the rest - matching the C's two-pass order.
        let mut status: Prstatus = unsafe { mem::zeroed() };
        let main = self.main_thread.min(self.threads.len().saturating_sub(1));
        if !self.threads.is_empty() {
            let thread = &self.threads[main];
            status.pr_pid = thread.pid;
            status.pr_reg = thread.regs;
            notes::write_prstatus(w, &status)?;
            notes::write_prfpreg(w, &thread.fpregs)?;
        }
        for (idx, thread) in self.threads.iter().enumerate() {
            if idx == main {
                continue;
            }
            status.pr_pid = thread.pid;
            status.pr_reg = thread.regs;
            notes::write_prstatus(w, &status)?;
            notes::write_prfpreg(w, &thread.fpregs)?;
        }
        // AUXV.
        if !self.auxv.is_empty() {
            notes::write_auxv(w, self.auxv)?;
        }
        // User-supplied extra notes (matches the C: written after auxv, before
        // NT_FILE).
        for note in self.notes {
            notes::write_extra_note(w, note.name, note.note_type, note.description)?;
        }
        // NT_FILE (file-backed mapping table).
        notes::write_nt_file(w, self.mappings, self.pagesize)?;
        Ok(())
    }

    /// Assemble and stream the complete ELF core file through `w`.
    ///
    /// # Errors
    /// Returns the section of core assembly that failed to write fully.
    ///
    /// # Safety
    /// Reads the process's own mapping memory (`mapping.start..write_size`) while
    /// streaming PT_LOAD contents; the address space must be stable (threads
    /// suspended) and the mappings must reflect the current `/proc/self/maps`.
    pub unsafe fn create_elf_core(&self, w: &mut dyn Writer) -> Result<(), CreateElfCoreError> {
        let pagesize = self.pagesize;
        let num_mappings = self.mappings.len();

        // --- Ehdr ---
        let mut ehdr = Ehdr::new_core();
        ehdr.e_phoff = EHDR as u64;
        ehdr.e_phnum = (num_mappings + 1) as u16; // +1 for PT_NOTE
        w.write_full(ehdr.as_bytes())
            .map_err(|_| CreateElfCoreError::Ehdr)?;

        // --- Program headers ---
        // PT_NOTE comes first; its file offset is just past all the phdrs.
        let phdrs_end = EHDR + (num_mappings + 1) * PHDR;
        let note_filesz = self.note_section_size();

        let mut note_phdr: Phdr = unsafe { mem::zeroed() };
        note_phdr.p_type = PT_NOTE;
        note_phdr.p_offset = phdrs_end as u64;
        note_phdr.p_filesz = note_filesz as u64;
        w.write_full(note_phdr.as_bytes())
            .map_err(|_| CreateElfCoreError::Phdr)?;

        // Page-align the first PT_LOAD's file offset after the notes.
        let mut offset = phdrs_end + note_filesz;
        let note_align = (pagesize - (offset % pagesize)) % pagesize;
        offset += note_align;

        // One PT_LOAD per mapping. `p_offset` advances by each segment's write_size;
        // `p_memsz` is the full VA range, `p_filesz` is what we actually store.
        for mapping in self.mappings {
            let mut ph: Phdr = unsafe { mem::zeroed() };
            ph.p_type = PT_LOAD;
            ph.p_align = pagesize as u64;
            ph.p_offset = offset as u64;
            ph.p_vaddr = mapping.start as u64;
            ph.p_memsz = (mapping.end - mapping.start) as u64;
            ph.p_filesz = mapping.write_size as u64;
            ph.p_flags = mapping.pf_flags();
            w.write_full(ph.as_bytes())
                .map_err(|_| CreateElfCoreError::Phdr)?;
            offset += mapping.write_size;
        }

        // --- Note section ---
        self.write_notes(w)?;

        // --- Page alignment padding before segments ---
        if note_align > 0 {
            const ZEROS: [u8; 4096] = [0u8; 4096];
            let mut remaining = note_align;
            while remaining > 0 {
                let chunk = remaining.min(ZEROS.len());
                w.write_full(&ZEROS[..chunk])
                    .map_err(|_| CreateElfCoreError::Padding)?;
                remaining -= chunk;
            }
        }

        // --- Segment contents ---
        for mapping in self.mappings {
            if mapping.write_size > 0 {
                // SAFETY: caller guarantees the address space is stable and these
                // bytes are readable (non-readable mappings were filtered out in
                // finalize_mappings).
                let bytes = unsafe {
                    core::slice::from_raw_parts(mapping.start as *const u8, mapping.write_size)
                };
                w.write_full(bytes)
                    .map_err(|_| CreateElfCoreError::Segment)?;
            }
        }

        Ok(())
    }
}

/// Size of an ELF program header.
const PHDR: usize = mem::size_of::<Phdr>();
/// Size of an ELF file header.
const EHDR: usize = mem::size_of::<Ehdr>();

/// Size of one fixed-payload CORE note (header + padded "CORE" + descriptor).
const fn core_note(descsz: usize) -> usize {
    note_size(notes::CORE_NAMESZ as usize, descsz)
}

/// Total PT_NOTE section size, expressed from counts so the priority limiter
/// (which doesn't have a `CoreInputs`) can call it. Covers PRPSINFO, the
/// optional NT_PRXREG (`core_user`), per-thread PRSTATUS + PRFPREG, AUXV, NT_FILE,
/// and the user-supplied extra notes.
pub fn note_section_size_for(
    n_threads: usize,
    n_auxv: usize,
    mappings: &[Mapping],
    notes: &[crate::dump::ExtraNote],
    has_user: bool,
) -> usize {
    let mut sz = core_note(mem::size_of::<Prpsinfo>());
    if has_user {
        sz += core_note(mem::size_of::<crate::elf::CoreUser>());
    }
    sz += n_threads * (core_note(mem::size_of::<Prstatus>()) + core_note(mem::size_of::<FpRegs>()));
    if n_auxv > 0 {
        sz += core_note(n_auxv * mem::size_of::<AuxvT>());
    }
    let (count, desc_len) = notes::nt_file_sizes(mappings);
    if count > 0 {
        sz += core_note(desc_len);
    }
    for n in notes {
        sz += note_size(n.name.len() + 1, n.description.len());
    }
    sz
}
