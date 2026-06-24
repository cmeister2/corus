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

    let loopback = Pipe::new().expect("pipe");
    let mut scratch = [0u8; 4096];
    let kept = unsafe { finalize_mappings(&mut maps, parsed, 4096, &loopback, &mut scratch) };
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
        pagesize: 4096,
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
    assert!(
        s.contains("X86-64") || s.contains("x86-64"),
        "machine:\n{s}"
    );
}
