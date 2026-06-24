/* Link against the Rust staticlib through the original C header, call
 * WriteCoreDump, and leave debugger validation to the Makefile target.
 */
#include <stdio.h>

#include "google/coredumper.h"

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <core-path>\n", argv[0]);
    return 2;
  }

  int rc = WriteCoreDump(argv[1]);
  if (rc != 0) {
    fprintf(stderr, "WriteCoreDump failed rc=%d\n", rc);
    return 1;
  }

  printf("wrote %s\n", argv[1]);
  return 0;
}