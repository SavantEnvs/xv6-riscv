// File-input target: xv6's shell (user/sh.c) run natively as a program. The input file is the
// shell's stdin: each line is read with getcmd(), parsed with parsecmd() (gettoken/peek/
// parseline/parsepipe/parseredirs/parseblock/parseexec/nulterminate) and run with runcmd()
// using real fork/wait/pipe/dup. exec always fails (there are no programs) and open() only
// knows the console, so no files are touched. sh's own error path is exit(), so this is a
// file-input target rather than an in-process libFuzzer one.
#include "uhost.h"
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int xv6_main(void);

int main(int argc, char **argv)
{
  if (argc > 1) {
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
      perror(argv[1]);
      return 2;
    }
    dup2(fd, 0);
    close(fd);
  }
  u_real_proc = 1;
  return xv6_main();
}
