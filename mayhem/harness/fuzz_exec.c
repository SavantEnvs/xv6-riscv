// libFuzzer target: exec() of an untrusted program file — sys_exec (kernel/sysfile.c) and kexec
// (kernel/exec.c): ELF header and program-header validation, segment allocation and loading,
// argument copying onto the new user stack. The file is stored as /a on a fresh mkfs image
// through the write() syscall, then exec'ed with fuzzer-chosen arguments. User page tables are
// a fake address space (mayhem/harness/kfs_host.c); everything else is xv6's own code.
// Input: byte 0 = argument count (low 3 bits), then that many NUL-terminated arguments, then
// the program file.
#include "kfs_host.h"
#include <string.h>

#define MAXPROG (128 * 1024)

static int64_t sys(int num, uint64_t a0, uint64_t a1, uint64_t a2, const char *s0)
{
  uint64_t ia[3] = { a0, a1, a2 };
  const char *sa[2] = { s0, 0 };
  return kfs_call(num, ia, sa);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  static int booted;
  if (!booted) {
    kfs_init();
    booted = 1;
  }
  if (size < 1)
    return -1;
  int argc = data[0] & 7;
  size_t pos = 1;
  size_t argoff[8];
  // Arguments go at the bottom of user memory, the argv array at 48 KiB.
  size_t strtop = 0;
  for (int i = 0; i < argc; i++) {
    const uint8_t *nul = memchr(data + pos, 0, size - pos);
    if (!nul)
      return -1;
    size_t len = (size_t)(nul - (data + pos)) + 1;
    if (strtop + len > 48 * 1024)
      return -1;
    argoff[i] = strtop;
    strtop += len;
    pos += len;
  }
  size_t proglen = size - pos;
  if (proglen > MAXPROG)
    return -1;

  kfs_reset();
  int64_t fd = sys(K_open, 0, KO_CREATE | KO_WRONLY, 0, "/a");
  for (size_t done = 0; done < proglen;) {
    size_t n = proglen - done < 32768 ? proglen - done : 32768;
    memcpy(kfs_umem, data + pos + done, n);
    if (sys(K_write, fd, kfs_uaddr(0), n, 0) != (int64_t)n)
      __builtin_trap(); // a fresh image has room for 128 KiB: a short write is a kernel bug
    done += n;
  }
  sys(K_close, fd, 0, 0, 0);

  memset(kfs_umem, 0, KFS_UMEM_SIZE);
  for (int i = 0, p = 1; i < argc; i++) {
    size_t len = strlen((const char *)data + p) + 1;
    memcpy(kfs_umem + argoff[i], data + p, len);
    p += (int)len;
  }
  uint64_t argv[9];
  for (int i = 0; i < argc; i++)
    argv[i] = kfs_uaddr(argoff[i]);
  argv[argc] = 0;
  memcpy(kfs_umem + 48 * 1024, argv, sizeof(argv));
  sys(K_exec, 0, kfs_uaddr(48 * 1024), 0, "/a");
  return 0;
}
