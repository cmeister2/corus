//! Isolate the core-assembly path (no clone/ptrace): parse our own maps,
//! finalize them, and stream a core to a file via CoreInputs::write_core with
//! synthetic register state. This separates "does the ELF assembly work" from
//! "does the live thread-capture work".

mod common;

use core::mem;
use corus_core::elf::{AuxvT, FpRegs, Prpsinfo, Regs};
use corus_core::elfcore::{CoreInputs, ThreadState};
use corus_core::io::{Pipe, SimpleWriter};
use corus_core::proc_parse::{finalize_mappings, mapping_buf, parse_self_maps};
use std::env::temp_dir;
use std::fs::{File, remove_file};
use std::os::fd::AsRawFd;
use std::process;

use common::readelf_header;

#[test]
fn assemble_core_from_self_maps() {
    // Parse + finalize our own mappings (single-threaded, not suspended - safe
    // because this test process's map is stable enough for the assembly path).
    let mut maps = mapping_buf();
    let parsed = parse_self_maps(&mut maps).expect("parse maps");
    assert!(parsed > 0);

    // Use the real kernel page size: this test finalizes *live* /proc/self/maps,
    // so a wrong page size miscomputes the leading-zero skip and underflows
    // mapping sizes (aarch64 kernels may use 16K/64K pages, not 4K).
    let pagesize = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    assert!(
        pagesize.is_power_of_two(),
        "implausible page size {pagesize}"
    );

    let loopback = Pipe::new().expect("pipe");
    // Scratch must be at least one page; 64K covers every Linux page size.
    let mut scratch = [0u8; 64 * 1024];
    let kept = unsafe { finalize_mappings(&mut maps, parsed, pagesize, &loopback, &mut scratch) };
    assert!(kept > 0, "should keep some mappings");

    // Synthetic single-thread state.
    let threads = [ThreadState {
        pid: std::process::id() as i32,
        regs: unsafe { mem::zeroed::<Regs>() },
        fpregs: unsafe { mem::zeroed::<FpRegs>() },
    }];
    let prpsinfo: Prpsinfo = unsafe { mem::zeroed() };
    let auxv: [AuxvT; 0] = [];

    let path = temp_dir().join(format!("cd_assemble_{}.core", process::id()));
    let f = File::create(&path).unwrap();
    let mut w = SimpleWriter { fd: f.as_raw_fd() };

    let inp = CoreInputs {
        prpsinfo: &prpsinfo,
        threads: &threads,
        main_thread: 0,
        auxv: &auxv,
        mappings: &maps[..kept],
        pagesize,
        notes: &[],
        user: None,
    };
    unsafe { inp.create_elf_core(&mut w) }.expect("CoreInputs::create_elf_core should succeed");
    drop(f);

    let Some(out) = readelf_header(&path) else {
        let _ = remove_file(&path);
        return;
    };
    let s = String::from_utf8_lossy(&out.stdout);
    let _ = remove_file(&path);
    assert!(s.contains("Core file"), "should be a core file:\n{s}");
    #[cfg(target_arch = "x86_64")]
    let machine_ok = s.contains("X86-64") || s.contains("x86-64");
    #[cfg(target_arch = "aarch64")]
    let machine_ok = s.contains("AArch64") || s.contains("aarch64");
    assert!(machine_ok, "machine:\n{s}");
}

#[test]
fn assemble_core_zero_fills_unreadable_pages() -> Result<(), Box<dyn std::error::Error>> {
    let pagesize = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })?;
    let memory = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            pagesize * 3,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(memory, libc::MAP_FAILED);
    unsafe {
        core::ptr::write_bytes(memory as *mut u8, 0x11, pagesize * 3);
        core::ptr::write_bytes((memory as *mut u8).add(pagesize * 2), 0x22, pagesize);
    }
    assert_eq!(
        unsafe {
            libc::mprotect(
                (memory as *mut u8).add(pagesize).cast(),
                pagesize,
                libc::PROT_NONE,
            )
        },
        0
    );
    let mapping = corus_core::proc_parse::Mapping {
        start: memory as usize,
        end: memory as usize + pagesize * 3,
        offset: 0,
        flags: corus_core::proc_parse::Perms(
            (corus_core::elf::PF_R | corus_core::elf::PF_W) as u16,
        ),
        is_anon: true,
        write_size: pagesize * 3,
        dontdump: false,
        has_anon_pages: true,
        is_device: false,
        name_len: 0,
        name: [0; corus_core::proc_parse::FNAME_MAX],
    };
    let prpsinfo = unsafe { mem::zeroed() };
    let inputs = CoreInputs {
        prpsinfo: &prpsinfo,
        threads: &[],
        main_thread: 0,
        auxv: &[],
        mappings: &[mapping],
        pagesize,
        notes: &[],
        user: None,
    };
    let path = temp_dir().join(format!("cd_assemble_unreadable_{}.core", process::id()));
    let file = File::create(&path)?;
    let result = unsafe {
        inputs.create_elf_core(&mut SimpleWriter {
            fd: file.as_raw_fd(),
        })
    };
    assert_eq!(unsafe { libc::munmap(memory, pagesize * 3) }, 0);
    drop(file);
    let bytes = std::fs::read(&path)?;
    remove_file(&path)?;
    assert!(result.is_ok(), "assembly failed: {result:?}");
    let contents = &bytes[bytes.len() - pagesize * 3..];
    assert!(contents[..pagesize].iter().all(|&byte| byte == 0x11));
    assert!(
        contents[pagesize..pagesize * 2]
            .iter()
            .all(|&byte| byte == 0)
    );
    assert!(contents[pagesize * 2..].iter().all(|&byte| byte == 0x22));
    Ok(())
}
