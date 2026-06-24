# corus

Corus lets a Linux process write its own ELF core dump: "core us". This started as a faithful Rust translation of mad-scientist's [google-coredumper](https://github.com/madscientist/google-coredumper) fork.

## How This Works

Corus builds a core file from inside the process being dumped. The public C ABI
and Rust builder both lower to the same `corus-core` engine, which avoids libc
and allocation on the dump path so it can run while sibling threads are stopped.

When a dump starts, Corus clones a small lister thread with raw Linux syscalls.
That lister scans `/proc/<pid>/task`, attaches to sibling threads with `ptrace`,
verifies they share the same address space, and hands the frozen thread ids to
the core writer. The dumping thread also captures its caller frame so the main
thread's backtrace points at the API call site rather than the suspension
machinery.

With the process stable, the engine parses `/proc/self/maps`, `/proc/self/smaps`,
and `/proc/self/auxv`; captures register state with `PTRACE_GETREGS` and
`PTRACE_GETFPREGS`; applies the coredumper mapping rules; and streams an ELF
core containing PT_NOTE records plus one PT_LOAD segment per selected mapping.
Output goes through a small writer abstraction, which handles plain fd output,
byte limits, priority trimming, and optional fork/exec compression pipelines.

Before returning, Corus closes the writer, reaps any compressor process, and
resumes the suspended threads. Crash-cleanup signal handlers on the lister's
alternate stack make a best effort to resume or kill tracees if the lister faults
while threads are attached.

## Status

Corus is a working x86_64 Linux Rust port of google-coredumper. It builds as
three crates, exports the original C ABI from the Rust `staticlib`/`cdylib`, and
also provides an idiomatic Rust builder for common dump requests.

Current capabilities:

- Writes gdb-loadable ELF core files from inside the running process.
- Suspends and resumes sibling threads with raw syscalls and `ptrace`.
- Emits PRPSINFO, per-thread PRSTATUS/PRFPREG, AUXV, NT_FILE, and optional extra
  notes.
- Supports byte limits, priority-based trimming, pre-dump callbacks, and
  gzip/bzip2/compress pipelines.
- Keeps the core engine `no_std`, allocation-free, and libc-free on the dump
  path.

Validation covers the original C unit test linked against the Rust staticlib,
Rust API integration tests, syscall differential tests, clone/ptrace/strace
checks, gdb/readelf load checks, NT_FILE comparison against `gcore`, exported
symbol drift guards, and a no-alloc audit for `corus-core`.

Known caveats:

- Linux x86_64 only for now.
- The `[vdso]` mapping is dumped as an ordinary segment rather than using the
  original C vdso-phdr extraction path.
- When gdb selects Rust as the current frame language, one C expression in the
  original C unit harness can be rejected; the harness validates the marker with
  later unsigned prints instead.

## Layout

| Crate            | `no_std` | Role                                                                           |
|------------------|:--------:|--------------------------------------------------------------------------------|
| `corus-syscall` |   yes    | Raw Linux syscalls via hand-written `asm!` (port of `linux_syscall_support.h`) |
| `corus-core`    |   yes    | The dump engine: ELF build, thread suspend, `/proc` parse                      |
| `corus`         |    no    | `cdylib`+`staticlib`+`rlib`; C ABI (`capi`) and Rust API (`rust_api`)          |

The two surfaces are siblings over the single `corus-core` engine - neither wraps the other.

## Build & test

```sh
cargo build              # builds all three crates + libcorus.{so,a}
cargo test               # runs unit tests (incl. asm! syscall smoke tests)
make test-c-abi          # links a C smoke test against target/debug/libcorus.a
make test-original-c-unit # links and runs coredumper/coredumper_unittest.c
make tests               # Runs all tests, including Rust tests
```

Tests run serially by default: `.cargo/config.toml` sets `RUST_TEST_THREADS=1`
for Cargo/libtest, and `.config/nextest.toml` sets `test-threads = 1` for
nextest. Several tests exercise ptrace/thread suspension and are intentionally
not parallelized. The C staticlib tests live outside the Rust test harness so
they exercise the produced `.a` as ordinary C consumers would.

## Verifying the ABI

```sh
# 1. Exported symbols match coredumper/libcoredumper.sym exactly:
nm -D --defined-only ${CARGO_TARGET_DIR:-target}/debug/libcorus.so | awk '{print $3}' \
  | grep -vE '^_' | sort | diff - <(grep -v '^[[:space:]]*$' coredumper/libcoredumper.sym | sort)

# 2. Struct layouts match the C header (compile-time assertions in params.rs):
#    a mismatch fails `cargo build`; the expected values come from the C ABI.
```

## Key invariants

1. No libc, no allocator reachable from `corus-core`.
2. Raw syscalls only on the dump path (`asm!`, not libc wrappers).
3. `panic = "abort"` - unwinding must never cross the FFI boundary.
4. `libc` is a **dev-dependency only** (differential syscall tests); never linked
   into the library.
