// Known-answer tests for the kernel's printk (kernel/printk.c), linked as fuzz_kernel_printk links it.
#include <stdio.h>
#include <string.h>

int xv6k_printk(char *fmt, ...);
void xv6k_printkinit(void);

static char out[512];
static size_t outlen;
void h_putc(int c) { if (outlen < sizeof out) out[outlen++] = (char)c; }

static int fails;
static void expect(const char *name, const char *want)
{
  int ok = outlen == strlen(want) && memcmp(out, want, outlen) == 0;
  printf("%s %s\n", ok ? "PASS" : "FAIL", name);
  if (!ok) {
    printf("  want [%s]\n  got  [%.*s]\n", want, (int)outlen, out);
    fails++;
  }
  outlen = 0;
}

int main(void)
{
  xv6k_printkinit();
  xv6k_printk("%d", -42); expect("printk %d negative", "-42");
  xv6k_printk("%x", 255); expect("printk %x", "ff");
  xv6k_printk("%lu", 18446744073709551615ull); expect("printk %lu 20 digits", "18446744073709551615");
  xv6k_printk("%ld", -9223372036854775807ll); expect("printk %ld", "-9223372036854775807");
  xv6k_printk("%p", (void *)0xabc); expect("printk %p", "0x0000000000000abc");
  xv6k_printk("%s|%c|%%|%q|", "abc", 'Z'); expect("printk %s %c %% unknown", "abc|Z|%|%q|");
  xv6k_printk("%s", (char *)0); expect("printk %s NULL", "(null)");
  xv6k_printk("end%"); expect("printk trailing %", "end");
  printf("printk_selftest: %d failure(s)\n", fails);
  return fails != 0;
}
