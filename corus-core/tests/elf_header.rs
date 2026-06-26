//! A hand-built ELF core header round-trips through `readelf -h`.
//!
//! We construct an `Ehdr` via `Ehdr::new_core()`, append a single PT_NOTE
//! program header so the file is structurally a minimal core, write it to a
//! temp file, and assert `readelf` parses it as an x86-64 ELF core file.

mod common;

use corus_core::elf::{ELF_MACHINE, ELFCLASS64, ELFDATA2LSB, ELFMAG, ET_CORE, Ehdr, PT_NOTE, Phdr};
use std::io::Write;

use common::readelf_header;

#[test]
fn ehdr_fields_are_well_formed() {
    let e = Ehdr::new_core();
    assert_eq!(&e.e_ident[0..4], &ELFMAG);
    assert_eq!(e.e_ident[4], ELFCLASS64);
    assert_eq!(e.e_ident[5], ELFDATA2LSB);
    assert_eq!(e.e_type, ET_CORE);
    assert_eq!(e.e_machine, ELF_MACHINE);
    assert_eq!(e.e_ehsize as usize, core::mem::size_of::<Ehdr>());
    assert_eq!(e.e_phentsize as usize, core::mem::size_of::<Phdr>());
}

#[test]
fn minimal_core_header_parses_with_readelf() {
    // Build Ehdr + one PT_NOTE phdr right after it.
    let mut e = Ehdr::new_core();
    let ehsz = core::mem::size_of::<Ehdr>();
    let phsz = core::mem::size_of::<Phdr>();
    e.e_phoff = ehsz as u64;
    e.e_phnum = 1;

    let mut note = Phdr {
        p_type: PT_NOTE,
        p_flags: 0,
        p_offset: (ehsz + phsz) as u64,
        p_vaddr: 0,
        p_paddr: 0,
        p_filesz: 0,
        p_memsz: 0,
        p_align: 0,
    };
    // Empty note payload is fine for header parsing.
    note.p_filesz = 0;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(e.as_bytes());
    bytes.extend_from_slice(note.as_bytes());

    let dir = std::env::temp_dir();
    let path = dir.join(format!("coredumper_elf_header_{}.core", std::process::id()));
    {
        let mut f = std::fs::File::create(&path).expect("create temp core");
        f.write_all(&bytes).expect("write core");
    }

    let Some(out) = readelf_header(&path) else {
        let _ = std::fs::remove_file(&path);
        return;
    };
    let stdout = String::from_utf8_lossy(&out.stdout);

    let _ = std::fs::remove_file(&path);

    assert!(
        out.status.success(),
        "readelf failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("ELF64"),
        "not recognized as ELF64:\n{stdout}"
    );
    assert!(
        stdout.contains("Core file") || stdout.contains("CORE"),
        "not a core file:\n{stdout}"
    );
    #[cfg(target_arch = "x86_64")]
    let machine_ok =
        stdout.contains("X86-64") || stdout.contains("x86-64") || stdout.contains("Advanced Micro");
    #[cfg(target_arch = "aarch64")]
    let machine_ok = stdout.contains("AArch64") || stdout.contains("aarch64");
    assert!(machine_ok, "wrong machine:\n{stdout}");
    // Whitespace-tolerant: readelf pads the value column.
    let phnum_ok = stdout.lines().any(|l| {
        l.contains("Number of program headers:") && l.split_whitespace().last() == Some("1")
    });
    assert!(phnum_ok, "phnum not parsed as 1:\n{stdout}");
}
