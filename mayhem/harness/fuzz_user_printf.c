// libFuzzer target: xv6's user-level printf engine (user/printf.c: vprintf, printint, printptr),
// the printf/fprintf every xv6 program links. Input = 8 little-endian 64-bit arguments followed
// by the format string. printf's contract is that the arguments match the format, so the
// harness walks the format exactly as vprintf does: each %s gets a valid string, every other
// conversion one of the fuzzed values; a format needing more than 8 arguments is rejected.
#include "uhost.h"
#include <string.h>

void xv6_fprintf(int fd, const char *fmt, ...);

static const char str[] = "xv6";

// user/ulib.c's start() calls main(); this target links no program, only the printf library.
int xv6_main(void) { return 0; }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  static int init;
  static char fmt[4096];
  if (!init) {
    u_snapshot();
    init = 1;
  }
  if (size < 64 || size - 64 >= sizeof(fmt))
    return -1;
  uint64_t v[8], a[8];
  memcpy(v, data, 64);
  memcpy(fmt, data + 64, size - 64);
  fmt[size - 64] = 0;

  // Mirror of vprintf's conversion parsing: which conversions consume an argument, and which
  // of them take a char *.
  int na = 0, state = 0;
  for (int i = 0; fmt[i]; i++) {
    int c0 = fmt[i] & 0xff, c1 = 0, c2 = 0;
    if (state == 0) {
      if (c0 == '%')
        state = '%';
      continue;
    }
    state = 0;
    c1 = fmt[i + 1] & 0xff;
    if (c1)
      c2 = fmt[i + 2] & 0xff;
    int consumes = 1, isstr = 0;
    if (c0 == 'l' && c1 == 'l' && (c2 == 'd' || c2 == 'u' || c2 == 'x'))
      i += 2;
    else if (c0 == 'l' && (c1 == 'd' || c1 == 'u' || c1 == 'x'))
      i += 1;
    else if (c0 == 's')
      isstr = 1;
    else if (!(c0 == 'd' || c0 == 'u' || c0 == 'x' || c0 == 'p' || c0 == 'c'))
      consumes = 0;
    if (!consumes)
      continue;
    if (na == 8)
      return -1;
    a[na] = isstr ? (uint64_t)(uintptr_t)str : v[na];
    na++;
  }
  for (int i = na; i < 8; i++)
    a[i] = 0;

  u_reset();
  u_capture = 1;
  xv6_fprintf(1, fmt, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);
  return 0;
}
