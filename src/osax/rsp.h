#ifndef YABAI_RSP_H
#define YABAI_RSP_H

#include <stddef.h>
#include <stdint.h>

// Upper bound for one RSP read or write. A debugserver that stops answering
// must not leave the loader (and the `yabai --load-sa` waiting on it) stuck.
#define RSP_IO_TIMEOUT_SEC 3

int rsp_send(int fd, const char *data);
char *rsp_recv(int fd, char *buf, size_t bufsz);
void rsp_encode_u64(uint64_t val, char *out);
uint64_t rsp_decode_u64(const char *hex);
int rsp_connect(int port);
int rsp_set_reg(int sock, int regnum, uint64_t val, char *buf, size_t bufsz);
int rsp_get_reg(int sock, int regnum, uint64_t *val, char *buf, size_t bufsz);

#endif
