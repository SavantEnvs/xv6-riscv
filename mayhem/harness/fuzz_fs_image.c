// libFuzzer target: mounting an untrusted xv6 disk image. The input is a list of patches over
// a fresh mkfs image (block, offset, bytes) — so superblock, log header and log blocks, inodes,
// bitmap and directory contents are all attacker-controlled — then the kernel boots on it
// (fsinit: readsb, log recovery, orphan reclaim) and runs a fixed walk: list the root and every
// subdirectory, read every file, then write, link, unlink and create through the syscall layer.
// A kernel panic is reported as a crash: on a crafted disk it is a kernel halt triggered by
// on-disk data (e.g. fa4789f: a file with nlink 32767, linked once more, later panics unlink).
#include "kfs_host.h"
#include <stdio.h>
#include <string.h>

static int64_t sys(int num, uint64_t a0, uint64_t a1, uint64_t a2, const char *s0, const char *s1)
{
  uint64_t ia[3] = { a0, a1, a2 };
  const char *sa[2] = { s0, s1 };
  return kfs_call(num, ia, sa);
}

struct dirent { uint16_t inum; char name[14]; }; // kernel/fs.h

// Read a directory's entries (as ls does) into names[]; returns how many.
static int list(const char *dir, char names[][64], int max)
{
  int fd = (int)sys(K_open, 0, KO_RDONLY, 0, dir, 0), k = 0;
  if (fd < 0)
    return 0;
  while (k < max && sys(K_read, fd, kfs_uaddr(0), sizeof(struct dirent), 0, 0) == sizeof(struct dirent)) {
    struct dirent de;
    memcpy(&de, kfs_umem, sizeof de);
    if (de.inum == 0)
      continue;
    char nm[15];
    memcpy(nm, de.name, 14);
    nm[14] = 0;
    if (!strcmp(nm, ".") || !strcmp(nm, ".."))
      continue;
    snprintf(names[k++], 64, "%s/%s", strcmp(dir, "/") ? dir : "", nm);
  }
  sys(K_close, fd, 0, 0, 0, 0);
  return k;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  static int booted;
  if (!booted) {
    kfs_init();
    booted = 1;
  }
  if (kfs_boot_patched(data, size) < 0)
    return -1;

  static char names[48][64];
  int n = list("/", names, 16);
  for (int i = 0, top = n; i < top && n < 48; i++)
    n += list(names[i], names + n, 48 - n);
  for (int i = 0; i < n; i++) {
    int fd = (int)sys(K_open, 0, KO_RDONLY, 0, names[i], 0);
    if (fd < 0)
      continue;
    sys(K_fstat, fd, kfs_uaddr(60000), 0, 0, 0);
    sys(K_read, fd, kfs_uaddr(0), 8192, 0, 0);
    sys(K_close, fd, 0, 0, 0, 0);
  }
  for (int i = 0; i < n && i < 8; i++) {
    sys(K_link, 0, 0, 0, names[i], "/lnk");
    sys(K_unlink, 0, 0, 0, "/lnk", 0);
    int fd = (int)sys(K_open, 0, KO_RDWR, 0, names[i], 0);
    if (fd >= 0) {
      memset(kfs_umem, 'w', 3000);
      sys(K_write, fd, kfs_uaddr(0), 3000, 0, 0);
      sys(K_close, fd, 0, 0, 0, 0);
    }
    sys(K_unlink, 0, 0, 0, names[i], 0);
  }
  sys(K_mkdir, 0, 0, 0, "/nd", 0);
  int fd = (int)sys(K_open, 0, KO_CREATE | KO_RDWR, 0, "/nd/f", 0);
  memset(kfs_umem, 'n', 20000);
  sys(K_write, fd, kfs_uaddr(0), 20000, 0, 0);
  sys(K_close, fd, 0, 0, 0, 0);
  sys(K_unlink, 0, 0, 0, "/nd/f", 0);
  sys(K_unlink, 0, 0, 0, "/nd", 0);
  return 0;
}
