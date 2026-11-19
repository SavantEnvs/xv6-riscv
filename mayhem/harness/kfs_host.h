// Host-side API over the natively linked xv6 file-system kernel (see kstubs.c, kfs_host.c).
#pragma once
#include <stdint.h>
#include <stddef.h>

#define KFS_UMEM_SIZE 65536
extern uint8_t kfs_umem[KFS_UMEM_SIZE]; // the calling process's "user memory"

void kfs_init(void);   // load the mkfs image, boot the FS kernel, snapshot its state (once)
void kfs_reset(void);  // restore disk + kernel state to the post-boot snapshot
// Run syscall `num` (kernel/syscall.h numbering) with integer/address args `ia` and string args `sa`.
// Mount a modified image: the mkfs image with patch records applied (see kfs_host.c), booted
// from scratch (log recovery included). Returns -1, without booting, if it is not an xv6 fs.
// kfs_reset() afterwards returns to the normal post-boot state.
int kfs_boot_patched(const uint8_t *patch, size_t n);
int64_t kfs_call(int num, const uint64_t ia[3], const char *sa[2]);
// Console: type a key (what the UART interrupt does), and what the kernel has sent to the UART.
void h_console_type(int c);
extern char kfs_uart[4096];
extern size_t kfs_uartlen;
// exec: the process's page table after a successful exec, its entry point, and the host page
// holding virtual address `va` in it (0 if unmapped or not user-accessible).
void *h_current_pagetable(void);
uint64_t h_current_entry(void);
uint64_t h_vm_walk(void *pt, uint64_t va);
static inline uint64_t kfs_uaddr(size_t off) { return (uint64_t)(uintptr_t)(kfs_umem + off); }

// kernel/fcntl.h, kernel/syscall.h
#define KO_RDONLY 0x000
#define KO_WRONLY 0x001
#define KO_RDWR 0x002
#define KO_CREATE 0x200
#define KO_TRUNC 0x400
enum { K_pipe = 4, K_read = 5, K_exec = 7, K_fstat = 8, K_chdir = 9, K_dup = 10, K_open = 15, K_write = 16,
       K_mknod = 17, K_unlink = 18, K_link = 19, K_mkdir = 20, K_close = 21 };
