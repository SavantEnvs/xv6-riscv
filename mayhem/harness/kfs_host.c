// Host side of the native xv6 FS kernel: a RAM disk holding the mkfs image, kalloc pages,
// bounds-checked "user memory", and a snapshot of every kernel global taken right after boot so
// each input starts from the same freshly mounted file system.
#include "kfs_host.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BSIZE 1024
#define FSSIZE 2000

// The mkfs image, linked in by build.sh (`ld -r -b binary fs.img`).
extern const uint8_t _binary_fs_img_start[], _binary_fs_img_end[];
// All .data/.bss of the xv6 kernel objects, renamed into these sections by build.sh.
extern uint8_t __start_xv6k_data[] __attribute__((weak)), __stop_xv6k_data[] __attribute__((weak));
extern uint8_t __start_xv6k_bss[] __attribute__((weak)), __stop_xv6k_bss[] __attribute__((weak));

uint8_t kfs_umem[KFS_UMEM_SIZE];
static uint8_t disk[FSSIZE * BSIZE];
static uint8_t dirty[FSSIZE];
static uint8_t pristine[FSSIZE * BSIZE]; // the disk right after boot
static uint8_t *snap_data, *snap_bss;
static uint8_t *pre_data, *pre_bss; // kernel globals before boot

// Copy a whole section snapshot. The section holds ASan-instrumented globals with their redzones,
// so this copy must not be ASan-checked (it is the only code that touches the redzone bytes).
__attribute__((no_sanitize("address"))) static void raw_copy(uint8_t *dst, const uint8_t *src, size_t n)
{
  for (size_t i = 0; i < n; i++)
    ((volatile uint8_t *)dst)[i] = src[i];
}
static int killed_flag;
static const uint64_t *cur_ia;
static const char **cur_sa;

#define MAXPAGES 256
static void *pages[MAXPAGES];

void h_panic(const char *s)
{
  fprintf(stderr, "xv6 kernel panic: %s\n", s);
  abort();
}

void h_disk_rw(unsigned blockno, uint8_t *data, int write)
{
  if (blockno >= FSSIZE) {
    fprintf(stderr, "xv6: disk access to block %u beyond the %d-block disk\n", blockno, FSSIZE);
    abort();
  }
  if (write) {
    memcpy(disk + (size_t)blockno * BSIZE, data, BSIZE);
    dirty[blockno] = 1;
  } else {
    memcpy(data, disk + (size_t)blockno * BSIZE, BSIZE);
  }
}

void *h_kalloc(void)
{
  for (int i = 0; i < MAXPAGES; i++)
    if (!pages[i]) {
      pages[i] = aligned_alloc(4096, 4096);
      memset(pages[i], 5, 4096); // kalloc fills with junk too
      return pages[i];
    }
  return 0; // out of memory, as kalloc reports it
}

void h_kfree(void *pa)
{
  for (int i = 0; i < MAXPAGES; i++)
    if (pages[i] == pa) {
      free(pa);
      pages[i] = 0;
      return;
    }
  h_panic("kfree");
}

// Single-threaded: the only legitimate sleeps are on a pipe (another process would have to read
// or write it) and on console input (a key would have to be typed). Model that as the process
// being killed while waiting, which makes the pipe/console code return -1. Sleeping on anything
// else (an inode/buffer lock already held, the log) can never be woken here and would hang the
// real kernel too.
void h_sleep(void *chan, int console_input)
{
  if (console_input) {
    killed_flag = 1;
    return;
  }
  for (int i = 0; i < MAXPAGES; i++)
    if (pages[i] && (uint8_t *)chan >= (uint8_t *)pages[i] && (uint8_t *)chan < (uint8_t *)pages[i] + 4096) {
      killed_flag = 1;
      return;
    }
  h_panic("sleep on a non-pipe channel in a single-process kernel (self-deadlock)");
}

int h_killed(void) { return killed_flag; }

char kfs_uart[4096];
size_t kfs_uartlen;
void h_uart_putc(int c)
{
  if (kfs_uartlen < sizeof(kfs_uart))
    kfs_uart[kfs_uartlen++] = (char)c;
}

// copyin/copyout: only kfs_umem is mapped; anything else fails like an unmapped user address.
int h_copy(int to_user, uint64_t uaddr, void *kbuf, uint64_t len)
{
  uint64_t base = (uint64_t)(uintptr_t)kfs_umem;
  if (uaddr < base || len > KFS_UMEM_SIZE || uaddr - base > KFS_UMEM_SIZE - len)
    return -1;
  if (to_user)
    memmove((void *)(uintptr_t)uaddr, kbuf, len);
  else
    memmove(kbuf, (void *)(uintptr_t)uaddr, len);
  return 0;
}

// fetchstr: a NUL-terminated string at a user address, at most max bytes including the NUL.
int h_fetchstr(uint64_t uaddr, char *buf, int max)
{
  uint64_t base = (uint64_t)(uintptr_t)kfs_umem;
  if (uaddr < base || uaddr - base >= KFS_UMEM_SIZE)
    return -1;
  size_t off = (size_t)(uaddr - base);
  for (int i = 0; i < max && off + (size_t)i < KFS_UMEM_SIZE; i++) {
    buf[i] = (char)kfs_umem[off + i];
    if (buf[i] == 0)
      return i;
  }
  return -1;
}

// Fake user address spaces for exec: up to VM_MAXPAGES zeroed pages keyed by virtual address.
// Running out of pages is what running out of physical memory is to the real uvmalloc.
#define PGSZ 4096ull
#define PTE_W_ 4
#define PTE_U_ 16
#define VM_MAXPAGES 256
#define MAXVMS 4
struct fvm { uint64_t va[VM_MAXPAGES]; uint8_t *pg[VM_MAXPAGES]; int perm[VM_MAXPAGES]; int n; };
static struct fvm *vms[MAXVMS];

void *h_vm_new(void)
{
  for (int i = 0; i < MAXVMS; i++)
    if (!vms[i])
      return vms[i] = calloc(1, sizeof(struct fvm));
  return 0;
}

static void vm_drop(int i)
{
  for (int k = 0; k < vms[i]->n; k++)
    free(vms[i]->pg[k]);
  free(vms[i]);
  vms[i] = 0;
}

void h_vm_free(void *pt)
{
  if (!pt)
    return;
  for (int i = 0; i < MAXVMS; i++)
    if (vms[i] == pt) {
      vm_drop(i);
      return;
    }
  h_panic("proc_freepagetable: unknown page table");
}

static int vm_find(struct fvm *v, uint64_t va)
{
  for (int k = 0; k < v->n; k++)
    if (v->va[k] == va)
      return k;
  return -1;
}

uint64_t h_vm_alloc(void *pt, uint64_t oldsz, uint64_t newsz, int perm)
{
  struct fvm *v = pt;
  if (newsz < oldsz)
    return oldsz;
  uint64_t start = (oldsz + PGSZ - 1) & ~(PGSZ - 1);
  for (uint64_t a = start; a < newsz; a += PGSZ) {
    if (v->n == VM_MAXPAGES || a < start) { // out of memory (or wrapped): undo this call
      while (v->n && v->va[v->n - 1] >= start)
        free(v->pg[--v->n]);
      return 0;
    }
    if (vm_find(v, a) >= 0)
      h_panic("mappages: remap");
    v->va[v->n] = a;
    v->pg[v->n] = aligned_alloc(PGSZ, PGSZ);
    memset(v->pg[v->n], 0, PGSZ);
    v->perm[v->n] = perm;
    v->n++;
  }
  return newsz;
}

uint64_t h_vm_walk(void *pt, uint64_t va)
{
  struct fvm *v = pt;
  int k = vm_find(v, va & ~(PGSZ - 1));
  if (k < 0 || !(v->perm[k] & PTE_U_))
    return 0;
  return (uint64_t)(uintptr_t)v->pg[k];
}

void h_vm_clear_user(void *pt, uint64_t va)
{
  struct fvm *v = pt;
  int k = vm_find(v, va & ~(PGSZ - 1));
  if (k < 0)
    h_panic("uvmclear");
  v->perm[k] &= ~PTE_U_;
}

// copyout/copyin over a fake address space, page by page like vm.c (no lazy allocation).
int h_vm_copy(void *pt, int to_user, uint64_t va, void *kbuf, uint64_t len)
{
  struct fvm *v = pt;
  uint8_t *kb = kbuf;
  while (len > 0) {
    uint64_t va0 = va & ~(PGSZ - 1);
    int k = vm_find(v, va0);
    if (k < 0 || !(v->perm[k] & PTE_U_) || (to_user && !(v->perm[k] & PTE_W_)))
      return -1;
    uint64_t n = PGSZ - (va - va0);
    if (n > len)
      n = len;
    if (to_user)
      memmove(v->pg[k] + (va - va0), kb, n);
    else
      memmove(kb, v->pg[k] + (va - va0), n);
    len -= n;
    kb += n;
    va = va0 + PGSZ;
  }
  return 0;
}

int h_arg_int(int n) { return (int)cur_ia[n]; }
uint64_t h_arg_addr(int n) { return cur_ia[n]; }
const char *h_arg_str(int n) { return n < 2 ? cur_sa[n] : 0; }

void h_kernel_boot(void);
uint64_t h_syscall(int num);

void kfs_init(void)
{
  size_t n = (size_t)(_binary_fs_img_end - _binary_fs_img_start);
  if (n != sizeof(disk)) {
    fprintf(stderr, "kfs: fs.img is %zu bytes, expected %zu\n", n, sizeof(disk));
    abort();
  }
  memcpy(disk, _binary_fs_img_start, n);
  size_t pd = (size_t)(__stop_xv6k_data - __start_xv6k_data);
  size_t pb = (size_t)(__stop_xv6k_bss - __start_xv6k_bss);
  pre_data = malloc(pd ? pd : 1);
  pre_bss = malloc(pb ? pb : 1);
  raw_copy(pre_data, __start_xv6k_data, pd);
  raw_copy(pre_bss, __start_xv6k_bss, pb);
  h_kernel_boot();
  size_t nd = (size_t)(__stop_xv6k_data - __start_xv6k_data);
  size_t nb = (size_t)(__stop_xv6k_bss - __start_xv6k_bss);
  snap_data = malloc(nd ? nd : 1);
  snap_bss = malloc(nb ? nb : 1);
  raw_copy(snap_data, __start_xv6k_data, nd);
  raw_copy(snap_bss, __start_xv6k_bss, nb);
  // Boot may have written (log recovery); the post-boot disk is the pristine one.
  memcpy(pristine, disk, sizeof(disk));
  memset(dirty, 0, sizeof(dirty));
}

void kfs_reset(void)
{
  for (int b = 0; b < FSSIZE; b++)
    if (dirty[b]) {
      memcpy(disk + (size_t)b * BSIZE, pristine + (size_t)b * BSIZE, BSIZE);
      dirty[b] = 0;
    }
  raw_copy(__start_xv6k_data, snap_data, (size_t)(__stop_xv6k_data - __start_xv6k_data));
  raw_copy(__start_xv6k_bss, snap_bss, (size_t)(__stop_xv6k_bss - __start_xv6k_bss));
  for (int i = 0; i < MAXPAGES; i++)
    if (pages[i]) {
      free(pages[i]);
      pages[i] = 0;
    }
  for (int i = 0; i < MAXVMS; i++)
    if (vms[i])
      vm_drop(i);
  killed_flag = 0;
  kfs_uartlen = 0;
  memset(kfs_umem, 0, sizeof(kfs_umem));
}

int kfs_boot_patched(const uint8_t *p, size_t n)
{
  kfs_reset();
  memcpy(disk, _binary_fs_img_start, sizeof(disk));
  memset(dirty, 1, sizeof(dirty)); // the next kfs_reset restores every block
  // Patch records: block selector, 16-bit offset, length (0-63), bytes.
  // A short record (header 4 bytes, 6 for an extended 0xf0+ selector) ends the patch list.
  while (n >= 4 && n >= (p[0] < 0xf0 ? 4u : 6u)) {
    unsigned blk = p[0] < 0xf0 ? p[0] : (unsigned)(p[1] | p[2] << 8) % FSSIZE;
    if (p[0] >= 0xf0) {
      p += 2;
      n -= 2;
    }
    size_t off = (size_t)(p[1] | p[2] << 8) % BSIZE;
    size_t len = p[3] & 63;
    p += 4;
    n -= 4;
    if (len > n)
      len = n;
    if (len > BSIZE - off)
      len = BSIZE - off;
    memcpy(disk + (size_t)blk * BSIZE + off, p, len);
    p += len;
    n -= len;
  }
  // fsinit() panics "invalid file system" unless the superblock carries FSMAGIC: that is its
  // definition of an xv6 file system, not a bug, so such an image is not one this target mounts.
  uint32_t magic;
  memcpy(&magic, disk + BSIZE, sizeof(magic));
  if (magic != 0x10203040)
    return -1;
  raw_copy(__start_xv6k_data, pre_data, (size_t)(__stop_xv6k_data - __start_xv6k_data));
  raw_copy(__start_xv6k_bss, pre_bss, (size_t)(__stop_xv6k_bss - __start_xv6k_bss));
  killed_flag = 0;
  h_kernel_boot();
  return 0;
}

int64_t kfs_call(int num, const uint64_t ia[3], const char *sa[2])
{
  cur_ia = ia;
  cur_sa = sa;
  killed_flag = 0;
  int64_t r = (int64_t)h_syscall(num);
  cur_ia = 0;
  cur_sa = 0;
  return r;
}
