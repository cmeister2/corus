/* Install Corus as a crash handler through the original google-coredumper C
 * ABI, and dump the process from inside a SIGSEGV handler.
 *
 * This is the C-ABI counterpart to examples/crash_handler.rs: it links the
 * Rust staticlib through google/coredumper.h and calls WriteCoreDump() from a
 * signal handler, exactly as a google-coredumper consumer would.
 *
 * WriteCoreDump() opens the output file itself, which is not strictly
 * async-signal-safe (open(2) is, but building the path is on the caller). Here
 * the path is computed once up front and only handed to WriteCoreDump() in the
 * handler, so the handler does no allocation. The handler runs on an alternate
 * stack (SA_ONSTACK) so a stack-overflow fault still has a stack.
 *
 * For CI determinism the handler writes the core and then _exit(0)s. A
 * production handler would restore SIG_DFL and re-raise so the process dies
 * with the original signal.
 */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "google/coredumper.h"

/* Output path, filled in before the handler can run. */
static char g_core_path[4096];

/* Async-signal-safe progress report: write a static string to stderr. */
static void say(const char *msg) {
  (void)write(STDERR_FILENO, msg, strlen(msg));
}

static void on_sigsegv(int sig) {
  (void)sig;
  int rc = WriteCoreDump(g_core_path);
  if (rc == 0) {
    say("crash_handler: wrote core\n");
    _exit(0);
  }
  say("crash_handler: dump failed\n");
  _exit(1);
}

static void install_handler(void) {
  /* Alternate signal stack, leaked for the process lifetime. */
  stack_t ss;
  ss.ss_size = SIGSTKSZ > 65536 ? (size_t)SIGSTKSZ : 65536;
  ss.ss_sp = malloc(ss.ss_size);
  ss.ss_flags = 0;
  if (ss.ss_sp == NULL || sigaltstack(&ss, NULL) != 0) {
    perror("sigaltstack");
    exit(1);
  }

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = on_sigsegv;
  sa.sa_flags = SA_ONSTACK | SA_NODEFER | SA_RESETHAND;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGSEGV, &sa, NULL) != 0) {
    perror("sigaction");
    exit(1);
  }
}

/* Kept non-inlined so it stays visible in the dumped backtrace. */
__attribute__((noinline)) static void trigger_fault(void) {
  volatile int *p = (volatile int *)0;
  *p = 0; /* deliberate NULL write -> SIGSEGV */
}

int main(int argc, char **argv) {
  if (argc >= 2) {
    snprintf(g_core_path, sizeof(g_core_path), "%s", argv[1]);
  } else {
    snprintf(g_core_path, sizeof(g_core_path), "/tmp/corus-crash-c-%d.core",
             (int)getpid());
  }

  install_handler();

  printf("crash_handler: process %d will fault and dump to %s\n", (int)getpid(),
         g_core_path);
  fflush(stdout);

  trigger_fault();

  fprintf(stderr, "crash_handler: fault did not trigger the handler\n");
  return 2;
}
