// Kernel-side glue for kernel/printk.c run natively: the console output it drives goes to the
// host (h_putc), and its spinlock is single-threaded. build.sh prefixes xv6 symbols with xv6k_.
#include "kernel/types.h"
#include "kernel/param.h"
#include "kernel/spinlock.h"
#include "kernel/riscv.h"
#include "kernel/defs.h"

void h_putc(int c);

void consputc(int c) { h_putc(c); }
void initlock(struct spinlock *lk, char *name) { lk->name = name; lk->locked = 0; lk->cpu = 0; }
void acquire(struct spinlock *lk) { lk->locked = 1; }
void release(struct spinlock *lk) { lk->locked = 0; }
