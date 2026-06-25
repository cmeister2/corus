# corus-core

`no_std` ELF core-dump engine for [corus](https://crates.io/crates/corus).

This crate is the heart of corus: it builds gdb-loadable ELF core files from
inside a running process. It captures register state, suspends sibling threads
just long enough to fork a copy-on-write snapshot, parses `/proc`, applies the
coredumper mapping rules, and streams the ELF core (PT_NOTE records plus one
PT_LOAD per selected mapping). It avoids libc and allocation on the dump path so
it can run while sibling threads are stopped.

It is an internal building block of corus. You probably want the
[`corus`](https://crates.io/crates/corus) crate instead, which exposes both the
original C ABI and an idiomatic Rust builder over this engine.

- **Platform:** Linux x86_64 only.
- Built on [`corus-syscall`](https://crates.io/crates/corus-syscall) for raw
  syscalls.
- **`libc`** is a dev-dependency only (test setup and differential checks);
  never linked into the library.

See the [corus repository](https://github.com/cmeister2/corus) for the full
project, design notes, and build/test instructions.

## License

BSD-3-Clause.
