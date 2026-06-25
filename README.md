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

With the process stable, the engine captures register state with
`PTRACE_GETREGS`/`PTRACE_GETFPREGS` and the process identity (PRPSINFO, AUXV) -
the only work that needs the siblings frozen. It then **forks a copy-on-write
snapshot child and resumes the siblings immediately**, so the host process is
paused only for register capture plus the fork - not for the whole write. The
snapshot child parses `/proc/self/maps`, `/proc/self/smaps`, and
`/proc/self/auxv`; applies the coredumper mapping rules; and streams an ELF core
(PT_NOTE records plus one PT_LOAD segment per selected mapping) against its
frozen-in-amber memory while the parent runs. Output goes through a small writer
abstraction handling plain fd output, byte limits, priority trimming, and
optional fork/exec compression pipelines.

This collapses the pause from "proportional to resident memory and output
throughput" (a multi-GB, gzip-piped dump could freeze the process for seconds)
to "proportional to thread count" - typically sub-millisecond. If the `fork`
fails (e.g. `ENOMEM` copying page tables for a very large process), the engine
falls back to writing in-line with the siblings still frozen, so a fork failure
costs latency, not correctness.

The lister reaps the snapshot child before exiting and folds its exit status into
the dump result. Crash-cleanup signal handlers on the lister's alternate stack
make a best effort to resume or kill tracees if the lister faults while threads
are attached; the snapshot child disarms this inherited state as its first act.

## Status

Corus is a working x86_64 Linux Rust port of google-coredumper. It builds as
three crates, exports the original C ABI from the Rust `staticlib`/`cdylib`, and
also provides an idiomatic Rust builder for common dump requests.

Current capabilities:

- Writes gdb-loadable ELF core files from inside the running process.
- Suspends sibling threads only long enough to capture registers, then forks a
  copy-on-write snapshot and resumes them while the snapshot writes the core -
  minimizing the pause the host process suffers. Selectable per dump: the default
  `ForkSnapshot` strategy or `InProcessFrozen` for strict stay-frozen semantics.
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
- The copy-on-write snapshot changes the meaning of the dump for a few mapping
  kinds: `MAP_SHARED` segments are no longer point-in-time consistent with the
  captured registers (a resumed thread may mutate them before the snapshot reads
  them), `MADV_DONTFORK` regions are absent from the snapshot, and
  `MADV_WIPEONFORK` regions read as zero. Callers that need the strict frozen
  semantics (or want to avoid `fork` entirely) can select the
  `InProcessFrozen` dump strategy, which keeps every thread stopped for the
  whole write at the cost of a longer pause; the default `ForkSnapshot` strategy
  also falls back to it automatically if `fork` fails.
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

`make tests` runs the Rust tests with [`cargo nextest`] (`--no-capture`, so
per-test diagnostics show in the logs) plus `cargo test --doc` for doctests,
which nextest does not run. Install nextest (`cargo install cargo-nextest
--locked`) or override with `make tests NEXTEST=0` to fall back to plain
`cargo test`.

Tests run serially by default: `.cargo/config.toml` sets `RUST_TEST_THREADS=1`
for Cargo/libtest, and `.config/nextest.toml` sets `test-threads = 1` for
nextest. Several tests exercise ptrace/thread suspension and are intentionally
not parallelized. The C staticlib tests live outside the Rust test harness so
they exercise the produced `.a` as ordinary C consumers would.

[`cargo nextest`]: https://nexte.st/

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
