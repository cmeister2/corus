# corus-syscall

`no_std` raw Linux syscall wrappers for [corus](https://crates.io/crates/corus).

This crate provides hand-written `asm!` syscall wrappers (a Rust port of
google-coredumper's `linux_syscall_support.h`). It is allocation-free, libc-free,
and reachable from the core-dump path where libc wrappers cannot be used while
sibling threads are stopped.

It is an internal building block of corus. You probably want the
[`corus`](https://crates.io/crates/corus) crate instead.

- **Platform:** Linux x86_64 only.
- **`libc`** is a dev-dependency only, used to differentially validate the
  `asm!` wrappers in tests. It is never linked into the library.

See the [corus repository](https://github.com/cmeister2/corus) for the full
project, design notes, and build/test instructions.

## License

BSD-3-Clause.
