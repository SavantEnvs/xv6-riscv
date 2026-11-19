#include "uhost.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

int u_capture;
char u_out[1 << 16];
size_t u_outlen;
const uint8_t *u_in;
size_t u_inlen, u_chunk = 1;
int u_real_proc;

extern uint8_t __start_xv6u_data[] __attribute__((weak)), __stop_xv6u_data[] __attribute__((weak));
extern uint8_t __start_xv6u_bss[] __attribute__((weak)), __stop_xv6u_bss[] __attribute__((weak));
static uint8_t *snap_data, *snap_bss;

// Copy a whole section snapshot. The section holds ASan-instrumented globals with their redzones,
// so this copy must not be ASan-checked (it is the only code that touches the redzone bytes).
__attribute__((no_sanitize("address"))) static void raw_copy(uint8_t *dst, const uint8_t *src, size_t n)
{
  for (size_t i = 0; i < n; i++)
    ((volatile uint8_t *)dst)[i] = src[i];
}

// sbrk arena: a fixed heap that only grows, like an xv6 process's.
#define ARENA (8u << 20)
static uint8_t *arena;
static size_t brk_off;

char *h_u_sbrk(int n)
{
  if (!arena)
    arena = aligned_alloc(4096, ARENA);
  if (n < 0 || (size_t)n > ARENA - brk_off)
    return (char *)-1;
  char *p = (char *)arena + brk_off;
  brk_off += (size_t)n;
  return p;
}

int h_u_write(int fd, const void *b, int n)
{
  if (n < 0)
    return -1;
  if (!u_capture)
    return (int)write(fd, b, (size_t)n);
  size_t k = (size_t)n;
  if (k > sizeof(u_out) - u_outlen)
    k = sizeof(u_out) - u_outlen;
  memcpy(u_out + u_outlen, b, k);
  u_outlen += k;
  return n;
}

int h_u_read(int fd, void *b, int n)
{
  if (n < 0)
    return -1;
  if (!u_in)
    return (int)read(fd, b, (size_t)n);
  size_t k = (size_t)n < u_chunk ? (size_t)n : u_chunk;
  if (k > u_inlen)
    k = u_inlen;
  memcpy(b, u_in, k);
  u_in += k;
  u_inlen -= k;
  return (int)k;
}

int h_u_fork(void) { if (!u_real_proc) return -1; fflush(NULL); return fork(); }
int h_u_wait(int *s)
{
  if (!u_real_proc)
    return -1;
  int st = 0, pid = wait(&st);
  if (s)
    *s = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
  return pid;
}
int h_u_pipe(int *p) { return u_real_proc ? pipe(p) : -1; }
int h_u_close(int fd) { return u_real_proc ? close(fd) : -1; }
int h_u_dup(int fd) { return u_real_proc ? dup(fd) : -1; }
void h_u_exit(int s)
{
  if (!u_real_proc) {
    fprintf(stderr, "xv6 exit(%d) reached in an in-process target\n", s);
    abort();
  }
  exit(s);
}
// No programs to run: exec fails, as it does in xv6 for a missing binary.
int h_u_exec(const char *p, char **a) { (void)p; (void)a; return -1; }
// Only the console exists; it is the already open stdin/stdout/stderr, so hand back fd 3
// (sh's "ensure three fds are open" loop stops at the first fd >= 3). Everything else is missing.
int h_u_open(const char *p, int m) { (void)m; return strcmp(p, "console") == 0 ? 3 : -1; }

void u_snapshot(void)
{
  size_t nd = (size_t)(__stop_xv6u_data - __start_xv6u_data);
  size_t nb = (size_t)(__stop_xv6u_bss - __start_xv6u_bss);
  snap_data = malloc(nd ? nd : 1);
  snap_bss = malloc(nb ? nb : 1);
  raw_copy(snap_data, __start_xv6u_data, nd);
  raw_copy(snap_bss, __start_xv6u_bss, nb);
}

void u_reset(void)
{
  raw_copy(__start_xv6u_data, snap_data, (size_t)(__stop_xv6u_data - __start_xv6u_data));
  raw_copy(__start_xv6u_bss, snap_bss, (size_t)(__stop_xv6u_bss - __start_xv6u_bss));
  brk_off = 0;
  u_outlen = 0;
}
