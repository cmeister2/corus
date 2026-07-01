# Troubleshooting

## `EPERM` / dumps fail in restricted environments

To snapshot a multi-threaded process, the thread lister `clone()`s a helper
task that `PTRACE_ATTACH`es back to the process's sibling threads to freeze them
while the core is captured. This happens for both dump strategies
(`ForkSnapshot` and `InProcessFrozen`) - the strategy only changes how the core
is serialized afterwards, not how threads are suspended. In hardened
environments - CI runners, containers, or hosts with the Yama LSM enabled - the
kernel can deny that attach with `EPERM`, and the dump fails. Corus does not
silently degrade: a denied attach fails the dump, so you see the error rather
than a subtly wrong core.

### Symptoms

A dump that works locally returns an error in the restricted environment. The
`crash_handler` example surfaces the underlying code:

```
crash_handler: dump failed variant=Core errno=1
```

`errno=1` is `EPERM`. Other consumers see the failure as a `-1` return
(`GetCoreDumpWith` and friends) or a `CoreDumpError` whose `.errno()` is `EPERM`.

### Diagnosing

Check the Yama ptrace scope:

```sh
cat /proc/sys/kernel/yama/ptrace_scope
```

A value of `1` (the common default) restricts `ptrace` to
descendants; `2` (admin-only) or `3` (no ptrace) are stricter. Any non-zero
value can block the fork-snapshot attach depending on your setup. Also check for
a container/seccomp policy that drops `CAP_SYS_PTRACE` or filters the `ptrace`
syscall.

### Fixes

Permit `ptrace` for the process:

- Relax Yama globally (needs root; this is what CI does):

  ```sh
  sudo sysctl -w kernel.yama.ptrace_scope=0
  ```

- Or grant the capability without loosening the global scope, e.g. run under
  `CAP_SYS_PTRACE` (Docker: `--cap-add=SYS_PTRACE`, and ensure the seccomp
  profile allows `ptrace`).

Permitting `ptrace` is the only remedy - because both dump strategies suspend
threads via the same cross-task attach, switching to `InProcessFrozen` does not
avoid the `EPERM`. (A single-threaded process has no siblings to attach to and
is unaffected.)
