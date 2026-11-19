// User-side glue: xv6's user-level system calls (user/user.h), forwarded to the host (uhost.c).
// Compiled like an xv6 user file; build.sh prefixes every xv6 symbol with xv6_ (h_* are kept).
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int h_u_fork(void);
void h_u_exit(int) __attribute__((noreturn));
int h_u_wait(int *);
int h_u_pipe(int *);
int h_u_write(int, const void *, int);
int h_u_read(int, void *, int);
int h_u_close(int);
int h_u_exec(const char *, char **);
int h_u_open(const char *, int);
int h_u_dup(int);
char *h_u_sbrk(int);

int fork(void) { return h_u_fork(); }
int exit(int s) { h_u_exit(s); }
int wait(int *s) { return h_u_wait(s); }
int pipe(int *p) { return h_u_pipe(p); }
int write(int fd, const void *b, int n) { return h_u_write(fd, b, n); }
int read(int fd, void *b, int n) { return h_u_read(fd, b, n); }
int close(int fd) { return h_u_close(fd); }
int kill(int pid) { (void)pid; return -1; }
int exec(const char *p, char **a) { return h_u_exec(p, a); }
int open(const char *p, int m) { return h_u_open(p, m); }
int mknod(const char *p, short a, short b) { (void)p; (void)a; (void)b; return -1; }
int unlink(const char *p) { (void)p; return -1; }
int fstat(int fd, struct stat *st) { (void)fd; (void)st; return -1; }
int link(const char *a, const char *b) { (void)a; (void)b; return -1; }
int mkdir(const char *p) { (void)p; return -1; }
int chdir(const char *p) { (void)p; return -1; }
int dup(int fd) { return h_u_dup(fd); }
int getpid(void) { return 1; }
char *sys_sbrk(int n, int t) { (void)t; return h_u_sbrk(n); }
int pause(int n) { (void)n; return 0; }
int uptime(void) { return 0; }
int sync(void) { return 0; }
