// libFuzzer target: xv6's grep (user/grep.c): grep(pattern, fd) — what `grep pattern` runs on
// stdin — with its line buffering and the ^ . * $ regex matcher (match/matchhere/matchstar).
// Input: byte 0 = read() chunk size, then the pattern up to the first NUL, then the text grep reads.
#include "uhost.h"
#include <string.h>

void xv6_grep(char *pattern, int fd);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  static int init;
  static char pat[1024];
  if (!init) {
    u_snapshot();
    init = 1;
  }
  if (size < 2)
    return -1;
  const uint8_t *nul = memchr(data + 1, 0, size - 1);
  if (!nul)
    return -1;
  size_t pl = (size_t)(nul - (data + 1));
  if (pl >= sizeof(pat)) // argv strings in xv6 are bounded by exec's MAXARG pages; keep it small
    return -1;
  memcpy(pat, data + 1, pl);
  pat[pl] = 0;

  u_reset();
  u_capture = 1;
  u_chunk = (size_t)data[0] + 1;
  u_in = nul + 1;
  u_inlen = size - (size_t)(nul + 1 - data);
  xv6_grep(pat, 0);
  u_in = 0;
  return 0;
}
