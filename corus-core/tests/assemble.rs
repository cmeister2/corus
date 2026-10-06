//! Isolate the core-assembly path (no clone/ptrace): parse our own maps,
//! finalize them, and stream a core to a file via CoreInputs::write_core with
//! synthetic register state. This separates "does the ELF assembly work" from
//! "does the live thread-capture work".

mod common;

use core::mem;
use corus_core::elf::{AuxvT, FpRegs, Prpsinfo, Regs};
use corus_core::elfcore::{CoreInputs, ThreadState};
use corus_core::io::{Pipe, SimpleWriter, Writer};
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
    verify_unreadable_segment(0)?;
    verify_unreadable_segment(1)
}

/// Check both aligned and unaligned sources preserve the prefix around a fault.
fn verify_unreadable_segment(source_offset: usize) -> Result<(), Box<dyn std::error::Error>> {
    let pagesize = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })?;
    let page_count = 37;
    let fault_page = 15;
    let memory = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            pagesize * page_count,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(memory, libc::MAP_FAILED);
    unsafe {
        core::ptr::write_bytes(memory as *mut u8, 0x11, pagesize * page_count);
        core::ptr::write_bytes(
            (memory as *mut u8).add(pagesize * (fault_page + 1)),
            0x22,
            pagesize * (page_count - fault_page - 1),
        );
    }
    assert_eq!(
        unsafe {
            libc::mprotect(
                (memory as *mut u8).add(pagesize * fault_page).cast(),
                pagesize,
                libc::PROT_NONE,
            )
        },
        0
    );
    let mapping = corus_core::proc_parse::Mapping {
        start: memory as usize + source_offset,
        end: memory as usize + pagesize * page_count,
        offset: 0,
        flags: corus_core::proc_parse::Perms(
            (corus_core::elf::PF_R | corus_core::elf::PF_W) as u16,
        ),
        is_anon: true,
        write_size: pagesize * page_count - source_offset,
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
    assert_eq!(unsafe { libc::munmap(memory, pagesize * page_count) }, 0);
    drop(file);
    let bytes = std::fs::read(&path)?;
    remove_file(&path)?;
    assert!(result.is_ok(), "assembly failed: {result:?}");
    let contents = &bytes[bytes.len() - (pagesize * page_count - source_offset)..];
    assert!(
        contents[..pagesize * fault_page - source_offset]
            .iter()
            .all(|&byte| byte == 0x11)
    );
    assert!(
        contents
            [pagesize * fault_page - source_offset..pagesize * (fault_page + 1) - source_offset]
            .iter()
            .all(|&byte| byte == 0)
    );
    assert!(
        contents[pagesize * (fault_page + 1) - source_offset..]
            .iter()
            .all(|&byte| byte == 0x22)
    );
    Ok(())
}

/// Resource setup must fail before output, without changing the parent's limits.
#[test]
fn assemble_resource_failure_writes_no_headers() -> Result<(), Box<dyn std::error::Error>> {
    let pagesize = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })?;
    let prpsinfo = unsafe { mem::zeroed() };
    let file = File::options().write(true).open("/dev/null")?;
    let inputs = CoreInputs {
        prpsinfo: &prpsinfo,
        threads: &[],
        main_thread: 0,
        auxv: &[],
        mappings: &[],
        pagesize,
        notes: &[],
        user: None,
    };
    let child =
        corus_core::corus_syscall::sys::fork().map_err(std::io::Error::from_raw_os_error)?;
    if child == 0 {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
            corus_core::corus_syscall::sys::exit(2);
        }
        let mut writer = CountingWriter {
            inner: SimpleWriter {
                fd: file.as_raw_fd(),
            },
            writes: 0,
        };
        let result = unsafe { inputs.create_elf_core(&mut writer) };
        corus_core::corus_syscall::sys::exit(if result.is_err() && writer.writes == 0 {
            0
        } else {
            1
        });
    }
    let mut status = 0;
    loop {
        match unsafe {
            corus_core::corus_syscall::sys::wait4(
                child as i32,
                &mut status,
                0,
                core::ptr::null_mut(),
            )
        } {
            Ok(_) => break,
            Err(corus_core::corus_syscall::linux::EINTR) => continue,
            Err(errno) => return Err(std::io::Error::from_raw_os_error(errno).into()),
        }
    }
    assert_eq!(
        status, 0,
        "resource setup must fail before writing core headers"
    );
    Ok(())
}

/// Counts output calls without changing the actual file writer.
struct CountingWriter {
    inner: SimpleWriter,
    writes: usize,
}

impl Writer for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> isize {
        self.writes += 1;
        self.inner.write(bytes)
    }

    fn done(&mut self) -> bool {
        self.inner.done()
    }
}

/// Benchmark context shared with an optional frozen-thread callback.
struct AssemblyBenchmark<'a> {
    inputs: CoreInputs<'a>,
    writer: CountingWriter,
    elapsed_ns: u64,
    succeeded: bool,
}

/// Monotonic clock using a raw syscall, safe while sibling threads hold locks.
fn monotonic_ns() -> u64 {
    let mut time = [0i64; 2];
    let _ = unsafe {
        corus_core::corus_syscall::arch::syscall2(
            libc::SYS_clock_gettime as usize,
            libc::CLOCK_MONOTONIC as usize,
            time.as_mut_ptr() as usize,
        )
    };
    time[0] as u64 * 1_000_000_000 + time[1] as u64
}

/// Time only assembly, either directly or with siblings actually suspended.
extern "C" fn benchmark_assembly(
    parameter: *mut core::ffi::c_void,
    _pids: *const i32,
    _count: i32,
) -> i32 {
    let benchmark = unsafe { &mut *parameter.cast::<AssemblyBenchmark<'_>>() };
    let begin = monotonic_ns();
    benchmark.succeeded =
        unsafe { benchmark.inputs.create_elf_core(&mut benchmark.writer) }.is_ok();
    benchmark.elapsed_ns = monotonic_ns() - begin;
    0
}

#[test]
#[ignore = "manual large-mapping syscall and freeze-duration benchmark"]
fn assemble_large_mapping_benchmark() -> Result<(), Box<dyn std::error::Error>> {
    let mib: usize = std::env::var("CORUS_BENCH_MIB")
        .unwrap_or_else(|_| "1024".into())
        .parse()?;
    let frozen = std::env::var_os("CORUS_BENCH_FREEZE").is_some();
    let pagesize = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })?;
    benchmark_large_mapping(mib, frozen, pagesize)?;
    Ok(())
}

#[test]
fn assemble_core_batches_output() -> Result<(), Box<dyn std::error::Error>> {
    for pagesize in [4096usize, 16384, 65536] {
        let writes = benchmark_large_mapping(1, false, pagesize)?;
        let segment_writes = (1024usize * 1024).div_ceil(64 * 1024);
        let max_writes = segment_writes + 6 + pagesize.div_ceil(4096);
        assert!(
            writes <= max_writes,
            "1 MiB segment must use batched output with {pagesize}-byte ELF alignment: {writes} writes exceeds {max_writes}"
        );
    }
    Ok(())
}

/// Run the shared fixture for performance measurements and the fast batching gate.
fn benchmark_large_mapping(
    mib: usize,
    frozen: bool,
    pagesize: usize,
) -> Result<usize, Box<dyn std::error::Error>> {
    let size = mib
        .checked_mul(1024 * 1024)
        .expect("benchmark size overflow");
    assert!(size > 0);
    let mapped_size = size
        .checked_add(pagesize)
        .expect("benchmark mapping size overflow");
    let memory = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            mapped_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(memory, libc::MAP_FAILED);
    unsafe { core::ptr::write_bytes(memory.cast::<u8>(), 0x5a, mapped_size) };
    let start = (memory as usize).next_multiple_of(pagesize);
    let mapping = corus_core::proc_parse::Mapping {
        start,
        end: start + size,
        offset: 0,
        flags: corus_core::proc_parse::Perms(
            (corus_core::elf::PF_R | corus_core::elf::PF_W) as u16,
        ),
        is_anon: true,
        write_size: size,
        dontdump: false,
        has_anon_pages: true,
        is_device: false,
        name_len: 0,
        name: [0; corus_core::proc_parse::FNAME_MAX],
    };
    let prpsinfo = unsafe { mem::zeroed() };
    let file = File::options().write(true).open("/dev/null")?;
    let mut benchmark = AssemblyBenchmark {
        inputs: CoreInputs {
            prpsinfo: &prpsinfo,
            threads: &[],
            main_thread: 0,
            auxv: &[],
            mappings: &[mapping],
            pagesize,
            notes: &[],
            user: None,
        },
        writer: CountingWriter {
            inner: SimpleWriter {
                fd: file.as_raw_fd(),
            },
            writes: 0,
        },
        elapsed_ns: 0,
        succeeded: false,
    };
    let parameter = (&mut benchmark as *mut AssemblyBenchmark<'_>).cast();
    let result = if frozen {
        unsafe {
            corus_core::threads::with_mmap_stack(
                parameter,
                benchmark_assembly,
                corus_core::dump::DUMP_CALLBACK_STACK,
            )
        }
    } else {
        Ok(benchmark_assembly(parameter, core::ptr::null(), 0))
    };
    assert_eq!(unsafe { libc::munmap(memory, mapped_size) }, 0);
    assert_eq!(result, Ok(0), "benchmark must not skip suspension");
    assert!(benchmark.succeeded);
    assert!(benchmark.elapsed_ns > 0);
    eprintln!(
        "assembly_benchmark mib={mib} pagesize={pagesize} output_writes={} elapsed_ms={:.3} frozen={frozen}",
        benchmark.writer.writes,
        benchmark.elapsed_ns as f64 / 1_000_000.0,
    );
    Ok(benchmark.writer.writes)
}
