// Known-answer tests for xv6's user printf (user/printf.c) and grep (user/grep.c), natively
// linked exactly as the user_printf and grep fuzz targets link them. Prints PASS/FAIL per check.
#include "uhost.h"
#include <stdio.h>
#include <string.h>

void xv6_fprintf(int fd, const char *fmt, ...);
void xv6_grep(char *pattern, int fd);

static int fails;
static void expect(const char *name, const char *want)
{
  int ok = u_outlen == strlen(want) && memcmp(u_out, want, u_outlen) == 0;
  printf("%s %s\n", ok ? "PASS" : "FAIL", name);
  if (!ok) {
    printf("  want [%s]\n  got  [%.*s]\n", want, (int)u_outlen, u_out);
    fails++;
  }
  u_reset();
}

static void grep(const char *pat, const char *text, size_t chunk)
{
  static char p[256];
  snprintf(p, sizeof p, "%s", pat);
  u_in = (const uint8_t *)text;
  u_inlen = strlen(text);
  u_chunk = chunk;
  xv6_grep(p, 0);
  u_in = 0;
}

int main(void)
{
  u_snapshot();
  u_capture = 1;
  u_reset();

  xv6_fprintf(1, "%d", -42); expect("printf %d negative", "-42");
  xv6_fprintf(1, "%x", 255); expect("printf %x", "FF");
  xv6_fprintf(1, "%u", 0xffffffffu); expect("printf %u max", "4294967295");
  xv6_fprintf(1, "%lu", 18446744073709551615ull); expect("printf %lu 20 digits", "18446744073709551615");
  xv6_fprintf(1, "%lld", -9223372036854775807ll); expect("printf %lld", "-9223372036854775807");
  xv6_fprintf(1, "%llx", 0xdeadbeefcafebabeull); expect("printf %llx", "DEADBEEFCAFEBABE");
  xv6_fprintf(1, "%p", (void *)0x1234); expect("printf %p", "0x0000000000001234");
  xv6_fprintf(1, "%s|%c|%%|%q", "abc", 'Z'); expect("printf %s %c %% unknown", "abc|Z|%|%q");
  xv6_fprintf(1, "%s", (char *)0); expect("printf %s NULL", "(null)");

  const char *text = "hello\nworld\nhelp\nxyz\naaab\n";
  for (size_t chunk = 1; chunk <= 1024; chunk *= 32) {
    char name[64];
    grep("^hel", text, chunk); snprintf(name, sizeof name, "grep ^hel (chunk %zu)", chunk); expect(name, "hello\nhelp\n");
    grep("o$", text, chunk); snprintf(name, sizeof name, "grep o$ (chunk %zu)", chunk); expect(name, "hello\n");
    grep("w.r", text, chunk); snprintf(name, sizeof name, "grep w.r (chunk %zu)", chunk); expect(name, "world\n");
    grep("^a*b$", text, chunk); snprintf(name, sizeof name, "grep ^a*b$ (chunk %zu)", chunk); expect(name, "aaab\n");
    grep("q", text, chunk); snprintf(name, sizeof name, "grep no match (chunk %zu)", chunk); expect(name, "");
  }

  printf("user_selftest: %d failure(s)\n", fails);
  return fails != 0;
}
