// Host side of the natively linked xv6 user programs/libraries (see ustubs.c, uhost.c).
#pragma once
#include <stddef.h>
#include <stdint.h>

// Where xv6 write() goes: 0 = the real fd, 1 = the capture buffer (u_out/u_outlen).
extern int u_capture;
extern char u_out[1 << 16];
extern size_t u_outlen;
// Where xv6 read() comes from: real fds when u_in is NULL, else this buffer in u_chunk pieces.
extern const uint8_t *u_in;
extern size_t u_inlen, u_chunk;
// Process-level calls (fork/wait/pipe/close/dup/exit) are real when u_real_proc is set,
// else they fail (-1) and exit aborts (it must not be reachable from a libFuzzer target).
extern int u_real_proc;

void u_snapshot(void); // record the xv6 user objects' globals (call once, before first use)
void u_reset(void);    // restore them, reset the sbrk arena and the capture buffer
