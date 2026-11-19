// libFuzzer target: xv6's file-system system calls (kernel/sysfile.c over fs.c, log.c, bio.c,
// file.c, pipe.c), run natively against a RAM disk holding a fresh mkfs image. The input is a
// program: a sequence of syscalls (open/read/write/close/link/unlink/mkdir/mknod/chdir/dup/fstat/
// pipe) with fuzzer-chosen paths, keys typed at the console (kernel/console.c, reached through a
// mknod'ed console device),, fds, user addresses and lengths. A kernel panic() is an abort:
// the image is valid and every syscall argument is user-controlled, so a panic is a kernel bug.
#include "kfs_host.h"
#include <stdio.h>
#include <string.h>

struct cursor { const uint8_t *p; size_t n; };
static uint8_t next(struct cursor *c) { if (!c->n) return 0; c->n--; return *c->p++; }
static uint16_t next16(struct cursor *c) { uint16_t lo = next(c); return lo | (uint16_t)(next(c) << 8); }

static const char *const pool[] = {
  "a", "b", "c", "d", ".", "..", "README", "dir", "f", "x",
  "abcdefghijklmn", "abcdefghijklmno", "console", "", "e", "zz",
};

// Path: raw bytes (high bit set) or 1-4 components from the pool, optionally absolute.
static void path(struct cursor *c, char *out, size_t cap)
{
  uint8_t l = next(c);
  size_t k = 0;
  if (l & 0x80) {
    size_t len = l & 0x7f;
    while (len-- && k + 1 < cap)
      out[k++] = (char)next(c);
  } else {
    if (l & 0x40)
      out[k++] = '/';
    int comps = (l & 3) + 1;
    for (int i = 0; i < comps; i++) {
      const char *s = pool[next(c) & 15];
      if (i)
        out[k++] = '/';
      size_t sl = strlen(s);
      memcpy(out + k, s, sl);
      k += sl;
    }
  }
  out[k] = 0;
}

static const int modes[8] = {
  KO_RDONLY, KO_WRONLY, KO_RDWR, KO_CREATE | KO_RDWR, KO_CREATE | KO_WRONLY,
  KO_CREATE | KO_TRUNC | KO_RDWR, KO_TRUNC | KO_WRONLY, KO_CREATE,
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  static int booted;
  if (!booted) {
    kfs_init();
    booted = 1;
  }
  kfs_reset();

  struct cursor c = { data, size };
  char p0[160], p1[160];
  const char *sa[2] = { p0, p1 };
  uint64_t ia[3];
  for (int ops = 0; c.n && ops < 64; ops++) {
    uint8_t op = next(&c);
    int fd = next(&c) % 20 - 2; // a few invalid fds too
    p0[0] = p1[0] = 0;
    memset(ia, 0, sizeof(ia));
    switch (op % 14) {
    case 0:
      path(&c, p0, sizeof(p0));
      ia[1] = modes[next(&c) & 7];
      kfs_call(K_open, ia, sa);
      break;
    case 1:
      ia[0] = fd;
      kfs_call(K_close, ia, sa);
      break;
    case 2: { // read(fd, umem+off, n)
      ia[0] = fd;
      ia[1] = kfs_uaddr(next16(&c));
      ia[2] = next16(&c);
      kfs_call(K_read, ia, sa);
      break;
    }
    case 3: { // write(fd, umem+off, n) repeated, with input bytes placed at umem+off first
      size_t off = next16(&c) % KFS_UMEM_SIZE;
      uint16_t n = next16(&c);
      int rep = (next(&c) & 7) + 1;
      size_t k = next(&c);
      for (size_t i = 0; i < k && off + i < KFS_UMEM_SIZE; i++)
        kfs_umem[off + i] = next(&c);
      ia[0] = fd;
      ia[1] = kfs_uaddr(off);
      ia[2] = n;
      for (int r = 0; r < rep; r++)
        if (kfs_call(K_write, ia, sa) < 0)
          break;
      break;
    }
    case 4:
      path(&c, p0, sizeof(p0));
      path(&c, p1, sizeof(p1));
      kfs_call(K_link, ia, sa);
      break;
    case 5:
      path(&c, p0, sizeof(p0));
      kfs_call(K_unlink, ia, sa);
      break;
    case 6:
      path(&c, p0, sizeof(p0));
      kfs_call(K_mkdir, ia, sa);
      break;
    case 7:
      path(&c, p0, sizeof(p0));
      ia[1] = (int16_t)next16(&c);
      ia[2] = (int16_t)next16(&c);
      kfs_call(K_mknod, ia, sa);
      break;
    case 8:
      path(&c, p0, sizeof(p0));
      kfs_call(K_chdir, ia, sa);
      break;
    case 9:
      ia[0] = fd;
      kfs_call(K_dup, ia, sa);
      break;
    case 10:
      ia[0] = fd;
      ia[1] = kfs_uaddr(next16(&c));
      kfs_call(K_fstat, ia, sa);
      break;
    case 11:
      ia[0] = kfs_uaddr(next16(&c));
      kfs_call(K_pipe, ia, sa);
      break;
    case 12: { // many links of one file into one directory (link-count growth)
      path(&c, p0, sizeof(p0));
      int count = next16(&c) % 1024;
      for (int i = 0; i < count; i++) {
        snprintf(p1, sizeof(p1), "l%d", i);
        if (kfs_call(K_link, ia, sa) < 0)
          break;
      }
      break;
    }
    case 13: { // keys typed at the console (line editing, ^U ^H ^D, line delivery to readers)
      size_t k = next(&c) & 63;
      for (size_t i = 0; i < k && c.n; i++)
        h_console_type(next(&c));
      break;
    }
    }
  }
  return 0;
}
