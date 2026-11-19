// Kernel-side glue for running xv6's file-system code (fs.c, log.c, bio.c, file.c, sysfile.c,
// pipe.c, sleeplock.c, string.c, console.c, exec.c) natively, without QEMU. Compiled like a kernel file (xv6 headers,
// xv6 names); build.sh then prefixes every xv6 symbol with xv6k_ so nothing clashes with libc.
// Symbols named h_* are left alone: they are the interface to the host side (kfs_host.c).
#include "kernel/types.h"
#include "kernel/riscv.h"
#include "kernel/param.h"
#include "kernel/spinlock.h"
#include "kernel/sleeplock.h"
#include "kernel/fs.h"
#include "kernel/buf.h"
#include "kernel/proc.h"
#include "kernel/defs.h"

// Host side (kfs_host.c).
void h_panic(const char *) __attribute__((noreturn));
void h_disk_rw(uint blockno, uchar *data, int write);
void *h_kalloc(void);
void h_kfree(void *);
void h_sleep(void *chan, int console_input);
void h_uart_putc(int c);
int h_killed(void);
int h_copy(int to_user, uint64 uaddr, void *kbuf, uint64 len);
int h_arg_int(int n);
uint64 h_arg_addr(int n);
const char *h_arg_str(int n);
int h_fetchstr(uint64 uaddr, char *buf, int max);
// A fake user address space for exec (kfs_host.c): pages keyed by virtual address.
void *h_vm_new(void);
void h_vm_free(void *pt);
uint64 h_vm_alloc(void *pt, uint64 oldsz, uint64 newsz, int perm);
uint64 h_vm_walk(void *pt, uint64 va);
void h_vm_clear_user(void *pt, uint64 va);
int h_vm_copy(void *pt, int to_user, uint64 va, void *kbuf, uint64 len);

// The one process every syscall runs as. Lives in this object's .bss, so it is part of the
// kernel state the host snapshots after boot and restores before every input.
static struct proc h_theproc;
static void *h_chan;
static struct trapframe h_trapframe;

void initlock(struct spinlock *lk, char *name) { lk->name = name; lk->locked = 0; lk->cpu = 0; }
void acquire(struct spinlock *lk) { lk->locked = 1; }
void release(struct spinlock *lk) { lk->locked = 0; }
int holding(struct spinlock *lk) { return lk->locked; }
void push_off(void) {}
void pop_off(void) {}

void sleep_prepare(void *chan) { h_chan = chan; }
// console.c's input buffer (same layout as its anonymous struct) — consoleread() sleeps on cons.r.
struct h_cons { struct spinlock lock; char buf[128]; uint r, w, e; };
extern struct h_cons cons;
void sleep(void) { h_sleep(h_chan, h_chan == (void *)&cons.r); }
void wakeup(void *chan) { (void)chan; }
struct proc *myproc(void) { return &h_theproc; }
int killed(struct proc *p) { (void)p; return h_killed(); }
void setkilled(struct proc *p) { (void)p; }

void *kalloc(void) { return h_kalloc(); }
void kfree(void *pa) { h_kfree(pa); }

// The process starts with no page table: its user memory is the host's kfs_umem. A page table
// made by exec (proc_pagetable/uvmalloc) is a fake address space in kfs_host.c.
int copyout(pagetable_t pt, uint64 psz, uint64 dstva, char *src, uint64 len)
{ (void)psz; return pt ? h_vm_copy(pt, 1, dstva, src, len) : h_copy(1, dstva, src, len); }
int copyin(pagetable_t pt, uint64 psz, char *dst, uint64 srcva, uint64 len)
{ (void)psz; return pt ? h_vm_copy(pt, 0, srcva, dst, len) : h_copy(0, srcva, dst, len); }
pagetable_t proc_pagetable(struct proc *p) { (void)p; return (pagetable_t)h_vm_new(); }
void proc_freepagetable(pagetable_t pt, uint64 sz) { (void)sz; h_vm_free(pt); }
uint64 uvmalloc(pagetable_t pt, uint64 oldsz, uint64 newsz, int xperm)
{ return h_vm_alloc(pt, oldsz, newsz, PTE_R | PTE_U | xperm); }
uint64 walkaddr(pagetable_t pt, uint64 va) { return h_vm_walk(pt, va); }
void uvmclear(pagetable_t pt, uint64 va) { h_vm_clear_user(pt, va); }
int either_copyout(int user_dst, uint64 dst, void *src, uint64 len)
{
  if (user_dst)
    return h_copy(1, dst, src, len);
  memmove((void *)dst, src, len);
  return 0;
}
int either_copyin(void *dst, int user_src, uint64 src, uint64 len)
{
  if (user_src)
    return h_copy(0, src, dst, len);
  memmove(dst, (void *)src, len);
  return 0;
}

void argint(int n, int *ip) { *ip = h_arg_int(n); }
void argaddr(int n, uint64 *ap) { *ap = h_arg_addr(n); }
int argstr(int n, char *buf, int max)
{
  const char *s = h_arg_str(n);
  int i;
  if (s == 0)
    return -1;
  for (i = 0; i < max; i++) {
    buf[i] = s[i];
    if (s[i] == 0)
      return i;
  }
  return -1; // like copyinstr: no NUL within max
}
int fetchaddr(uint64 addr, uint64 *ip) { return h_copy(0, addr, ip, sizeof(*ip)); }
int fetchstr(uint64 addr, char *buf, int max) { return h_fetchstr(addr, buf, max); }

void virtio_disk_rw(struct buf *b, int write) { h_disk_rw(b->blockno, b->data, write); }
void panic(char *s) { h_panic(s); }
void uartinit(void) {}
void uartputc_sync(int c) { h_uart_putc(c); }
void uartwrite(char buf[], int n) { for (int i = 0; i < n; i++) h_uart_putc(buf[i]); }
void procdump(void) {}

// Keyboard input: what uartintr() does for each received character.
void h_console_type(int c) { consoleintr(c); }
int printk(char *fmt, ...) { (void)fmt; return 0; }

// Boot the file-system half of the kernel the way main.c/proc.c do.
void h_kernel_boot(void)
{
  binit();
  iinit();
  fileinit();
  consoleinit();
  h_theproc.pid = 1;
  h_theproc.trapframe = &h_trapframe;
  fsinit(ROOTDEV);
  h_theproc.cwd = namei("/");
}

uint64 sys_dup(void), sys_read(void), sys_write(void), sys_close(void), sys_fstat(void),
    sys_link(void), sys_unlink(void), sys_open(void), sys_mkdir(void), sys_mknod(void),
    sys_chdir(void), sys_pipe(void), sys_exec(void);

// Syscall numbers as in kernel/syscall.h.
// The current process's page table (0 until an exec succeeds) and its entry point.
void *h_current_pagetable(void) { return h_theproc.pagetable; }
uint64 h_current_entry(void) { return h_theproc.trapframe->epc; }

uint64 h_syscall(int num)
{
  switch (num) {
  case 4: return sys_pipe();
  case 5: return sys_read();
  case 7: return sys_exec();
  case 9: return sys_chdir();
  case 10: return sys_dup();
  case 8: return sys_fstat();
  case 15: return sys_open();
  case 16: return sys_write();
  case 17: return sys_mknod();
  case 18: return sys_unlink();
  case 19: return sys_link();
  case 20: return sys_mkdir();
  case 21: return sys_close();
  }
  return (uint64)-1;
}
