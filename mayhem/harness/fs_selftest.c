// Known-answer tests for the natively linked xv6 file-system kernel (same code the
// fs_syscalls fuzz target drives). Prints PASS/FAIL per check; mayhem/test.sh counts them.
// Usage: fs_selftest <path to the README that mkfs put in the image>
#include "kfs_host.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct kstat { int dev; unsigned ino; short type; short nlink; uint64_t size; }; // kernel/stat.h

static int fails;
static void check(int ok, const char *name)
{
  printf("%s %s\n", ok ? "PASS" : "FAIL", name);
  if (!ok)
    fails++;
}

static int64_t sys(int num, uint64_t a0, uint64_t a1, uint64_t a2, const char *s0, const char *s1)
{
  uint64_t ia[3] = { a0, a1, a2 };
  const char *sa[2] = { s0, s1 };
  return kfs_call(num, ia, sa);
}
#define OPEN(p, m) sys(K_open, 0, (m), 0, (p), 0)

int main(int argc, char **argv)
{
  static char host[65536];
  size_t hn = 0;
  if (argc > 1) {
    FILE *f = fopen(argv[1], "rb");
    if (f) {
      hn = fread(host, 1, sizeof(host), f);
      fclose(f);
    }
  }
  kfs_init();
  kfs_reset();

  int64_t fd = OPEN("/README", KO_RDONLY);
  int64_t n = sys(K_read, fd, kfs_uaddr(0), 65536, 0, 0);
  check(fd >= 0 && hn > 0 && n == (int64_t)hn && memcmp(kfs_umem, host, hn) == 0, "read README matches the file mkfs stored");
  check(sys(K_read, fd, kfs_uaddr(0), 100, 0, 0) == 0, "read at EOF returns 0");
  sys(K_close, fd, 0, 0, 0, 0);

  fd = OPEN("/t", KO_CREATE | KO_RDWR);
  memcpy(kfs_umem, "hello xv6", 9);
  check(fd >= 0 && sys(K_write, fd, kfs_uaddr(0), 9, 0, 0) == 9, "create + write 9 bytes");
  sys(K_close, fd, 0, 0, 0, 0);
  memset(kfs_umem, 0, 64);
  fd = OPEN("/t", KO_RDONLY);
  n = sys(K_read, fd, kfs_uaddr(100), 64, 0, 0);
  check(n == 9 && memcmp(kfs_umem + 100, "hello xv6", 9) == 0, "read back written data");
  sys(K_close, fd, 0, 0, 0, 0);

  check(sys(K_link, 0, 0, 0, "/t", "/t2") == 0, "link /t /t2");
  fd = OPEN("/t2", KO_RDONLY);
  struct kstat st;
  memset(&st, 0, sizeof st);
  int64_t r = sys(K_fstat, fd, kfs_uaddr(200), 0, 0, 0);
  memcpy(&st, kfs_umem + 200, sizeof st);
  check(r == 0 && st.type == 2 && st.nlink == 2 && st.size == 9, "fstat: file, nlink 2, size 9");
  sys(K_close, fd, 0, 0, 0, 0);
  check(sys(K_unlink, 0, 0, 0, "/t", 0) == 0 && OPEN("/t", KO_RDONLY) < 0, "unlink removes the name");
  check(OPEN("/t2", KO_RDONLY) >= 0, "other link survives unlink");
  check(sys(K_link, 0, 0, 0, "/t2", "/t2") < 0, "link onto an existing name fails");

  check(sys(K_mkdir, 0, 0, 0, "/d", 0) == 0, "mkdir /d");
  check(sys(K_chdir, 0, 0, 0, "/d", 0) == 0, "chdir /d");
  fd = OPEN("f", KO_CREATE | KO_WRONLY);
  check(fd >= 0 && OPEN("/d/f", KO_RDONLY) >= 0, "relative create is visible by absolute path");
  check(OPEN("../README", KO_RDONLY) >= 0, "dot-dot resolves to the parent");
  check(sys(K_unlink, 0, 0, 0, "/d", 0) < 0, "unlink of a non-empty dir fails");
  check(sys(K_link, 0, 0, 0, "/d", "/d2") < 0, "link to a directory fails");
  check(OPEN("/nope", KO_RDONLY) < 0, "open of a missing file fails");
  check(OPEN("/d", KO_WRONLY) < 0, "open of a directory for writing fails");

  r = sys(K_pipe, kfs_uaddr(300), 0, 0, 0, 0);
  int pfd[2];
  memcpy(pfd, kfs_umem + 300, sizeof pfd);
  memcpy(kfs_umem + 400, "piped", 5);
  check(r == 0 && sys(K_write, pfd[1], kfs_uaddr(400), 5, 0, 0) == 5, "pipe write");
  check(sys(K_read, pfd[0], kfs_uaddr(500), 64, 0, 0) == 5 && memcmp(kfs_umem + 500, "piped", 5) == 0, "pipe read");
  sys(K_close, pfd[1], 0, 0, 0, 0);
  check(sys(K_read, pfd[0], kfs_uaddr(500), 64, 0, 0) == 0, "pipe read after writer closed is EOF");

  fd = OPEN("/big", KO_CREATE | KO_RDWR);
  for (int i = 0; i < 65536; i++)
    kfs_umem[i] = (uint8_t)(i * 7 + 3);
  int64_t tot = 0;
  for (int i = 0; i < 2; i++)
    tot += sys(K_write, fd, kfs_uaddr(0), 65536, 0, 0);
  sys(K_close, fd, 0, 0, 0, 0);
  memset(kfs_umem, 0, 65536);
  fd = OPEN("/big", KO_RDONLY);
  sys(K_read, fd, kfs_uaddr(0), 65536, 0, 0);
  n = sys(K_read, fd, kfs_uaddr(0), 65536, 0, 0);
  int same = 1;
  for (int i = 0; i < 65536; i++)
    same &= kfs_umem[i] == (uint8_t)(i * 7 + 3);
  check(tot == 131072 && n == 65536 && same, "128 KiB file through indirect blocks reads back");
  sys(K_close, fd, 0, 0, 0, 0);
  fd = OPEN("/big", KO_RDONLY);
  check(sys(K_read, fd, kfs_uaddr(65000), 1000, 0, 0) < 0, "read into an unmapped user address fails");

  // Console device: line editing on typed keys, a line delivered to read(), output to the UART.
  check(sys(K_mknod, 0, 1, 0, "/console", 0) == 0, "mknod console");
  fd = OPEN("/console", KO_RDWR);
  kfs_uartlen = 0;
  for (const char *k = "hix\x7fo\n"; *k; k++)
    h_console_type(*k);
  n = sys(K_read, fd, kfs_uaddr(0), 64, 0, 0);
  check(n == 4 && memcmp(kfs_umem, "hio\n", 4) == 0, "console read returns the edited line");
  int echo_ok = kfs_uartlen == 8 && memcmp(kfs_uart, "hix\b \bo\n", 8) == 0;
  if (!echo_ok) {
    printf("  uart got %zu bytes:", kfs_uartlen);
    for (size_t i = 0; i < kfs_uartlen; i++)
      printf(" %02x", (unsigned char)kfs_uart[i]);
    printf("\n");
  }
  check(echo_ok, "console echoes keys and erases on backspace");
  memcpy(kfs_umem, "out", 3);
  kfs_uartlen = 0;
  check(sys(K_write, fd, kfs_uaddr(0), 3, 0, 0) == 3 && kfs_uartlen == 3 && memcmp(kfs_uart, "out", 3) == 0, "console write reaches the UART");
  check(sys(K_read, fd, kfs_uaddr(0), 64, 0, 0) < 0, "console read with no input (process killed while waiting) fails");

  // exec: a minimal ELF (one RX segment at 0 holding a marker, entry 0x10) with two arguments.
  {
    uint8_t elf[64 + 56 + 16];
    memset(elf, 0, sizeof elf);
    memcpy(elf, "\x7f" "ELF\x02\x01\x01", 7);
    uint64_t entry = 0x10, phoff = 64, poff = 120, pfilesz = 16, pmemsz = 8192;
    uint16_t phnum = 1, phentsize = 56;
    uint32_t pt_load = 1, pflags = 5;
    memcpy(elf + 24, &entry, 8);
    memcpy(elf + 32, &phoff, 8);
    memcpy(elf + 54, &phentsize, 2);
    memcpy(elf + 56, &phnum, 2);
    memcpy(elf + 64, &pt_load, 4);
    memcpy(elf + 68, &pflags, 4);
    memcpy(elf + 72, &poff, 8);
    memcpy(elf + 96, &pfilesz, 8);
    memcpy(elf + 104, &pmemsz, 8);
    memcpy(elf + 120, "xv6-exec-marker!", 16);
    fd = OPEN("/prog", KO_CREATE | KO_WRONLY);
    memcpy(kfs_umem, elf, sizeof elf);
    sys(K_write, fd, kfs_uaddr(0), sizeof elf, 0, 0);
    sys(K_close, fd, 0, 0, 0, 0);
    memcpy(kfs_umem + 1000, "prog\0arg1", 10);
    uint64_t av[3] = { kfs_uaddr(1000), kfs_uaddr(1005), 0 };
    memcpy(kfs_umem + 2000, av, sizeof av);
    check(sys(K_exec, 0, kfs_uaddr(2000), 0, "/README", 0) < 0, "exec of a non-ELF file fails");
    check(sys(K_exec, 0, kfs_uaddr(2000), 0, "/nope", 0) < 0, "exec of a missing file fails");
    r = sys(K_exec, 0, kfs_uaddr(2000), 0, "/prog", 0);
    void *pt = h_current_pagetable();
    uint8_t *pg0 = pt ? (uint8_t *)(uintptr_t)h_vm_walk(pt, 0) : 0;
    if (getenv("FS_SELFTEST_DEBUG"))
      printf("  exec r=%lld pt=%p pg0=%p\n", (long long)r, pt, (void *)pg0);
    check(r == 2 && h_current_entry() == 0x10, "exec returns argc and sets the entry point");
    check(pg0 && memcmp(pg0, "xv6-exec-marker!", 16) == 0 && pg0[16] == 0, "exec loads the segment and zero-fills the rest");
    check(pt && h_vm_walk(pt, 8192) == 0 && h_vm_walk(pt, 12288) != 0, "exec maps a stack above an inaccessible guard page");
  }

  kfs_reset();
  check(OPEN("/t2", KO_RDONLY) < 0 && OPEN("/README", KO_RDONLY) >= 0, "reset restores the pristine image");

  // Patched images: README's inode (inode 2, block 33 offset 128) with nlink 5; a broken magic.
  static const uint8_t nlink5[] = { 33, 134, 0, 2, 5, 0 };
  static const uint8_t badmagic[] = { 1, 0, 0, 1, 0 };
  check(kfs_boot_patched(badmagic, sizeof badmagic) < 0, "image without the xv6 magic is not mounted");
  r = kfs_boot_patched(nlink5, sizeof nlink5);
  fd = OPEN("/README", KO_RDONLY);
  memset(&st, 0, sizeof st);
  sys(K_fstat, fd, kfs_uaddr(200), 0, 0, 0);
  memcpy(&st, kfs_umem + 200, sizeof st);
  check(r == 0 && st.nlink == 5 && st.size == hn, "patched image mounts and shows the patched inode");
  kfs_reset();

  printf("fs_selftest: %d failure(s)\n", fails);
  return fails != 0;
}
