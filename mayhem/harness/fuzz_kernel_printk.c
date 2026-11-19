// libFuzzer target: the kernel's printk (kernel/printk.c: printk, printint, printptr), which
// formats every kernel message. Input = 8 little-endian 64-bit arguments followed by the format.
// printk's contract is that the arguments match the format, so the harness walks the format
// exactly as printk does: each %s gets a valid string, every other conversion one of the fuzzed
// values; a format needing more than 8 arguments is rejected.
#include <stdint.h>
#include <stddef.h>
#include <string.h>

int xv6k_printk(char *fmt, ...);
void xv6k_printkinit(void);

static size_t outlen;
void h_putc(int c) { (void)c; outlen++; }

static const char str[] = "xv6";

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  static int init;
  static char fmt[4096];
  if (!init) {
    xv6k_printkinit();
    init = 1;
  }
  if (size < 64 || size - 64 >= sizeof(fmt))
    return -1;
  uint64_t v[8], a[8];
  memcpy(v, data, 64);
  memcpy(fmt, data + 64, size - 64);
  fmt[size - 64] = 0;

  int na = 0;
  for (int i = 0; fmt[i]; i++) {
    if (fmt[i] != '%')
      continue;
    i++;
    int c0 = fmt[i] & 0xff, c1 = 0, c2 = 0;
    if (c0)
      c1 = fmt[i + 1] & 0xff;
    if (c1)
      c2 = fmt[i + 2] & 0xff;
    if (c0 == 0)
      break;
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

  outlen = 0;
  xv6k_printk(fmt, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);
  return 0;
}
