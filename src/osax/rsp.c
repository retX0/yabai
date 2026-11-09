#ifdef __arm64__

/*
 * RSP transport and register helpers are adapted from retX0/amfree:
 * https://github.com/retX0/amfree
 */

#include "rsp.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static uint8_t rsp_checksum(const char *data, size_t len)
{
    uint8_t sum = 0;
    for (size_t i = 0; i < len; i++) sum += (uint8_t)data[i];
    return sum;
}

int rsp_send(int fd, const char *data)
{
    size_t len = strlen(data);
    char pkt[len + 5];
    snprintf(pkt, sizeof(pkt), "$%s#%02x", data, rsp_checksum(data, len));
    return write(fd, pkt, len + 4) == (ssize_t)(len + 4) ? 0 : -1;
}

char *rsp_recv(int fd, char *buf, size_t bufsz)
{
    size_t pos = 0;
    int in_packet = 0;
    size_t start = 0;
    while (pos < bufsz - 1) {
        ssize_t n = read(fd, buf + pos, 1);
        if (n <= 0) return NULL;
        char c = buf[pos];
        if (c == '$') {
            in_packet = 1;
            start = pos + 1;
        } else if (c == '#' && in_packet) {
            buf[pos] = '\0';
            char cs[3] = {0};
            if (read(fd, cs, 2) != 2) return NULL;
            write(fd, "+", 1);
            return buf + start;
        }
        pos++;
    }
    return NULL;
}

void rsp_encode_u64(uint64_t val, char *out)
{
    for (int i = 0; i < 8; i++) {
        sprintf(out + i * 2, "%02x", (unsigned)(val & 0xFF));
        val >>= 8;
    }
}

uint64_t rsp_decode_u64(const char *hex)
{
    uint64_t val = 0;
    for (int i = 7; i >= 0; i--) {
        unsigned byte = 0;
        sscanf(hex + i * 2, "%2x", &byte);
        val = (val << 8) | byte;
    }
    return val;
}

int rsp_connect(int port)
{
    for (int attempt = 0; attempt < 30; attempt++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_port = htons((uint16_t)port),
            .sin_addr.s_addr = inet_addr("127.0.0.1"),
        };
        if (fd == -1) return -1;
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            // Bound every later read/write: rsp_recv() returns NULL on timeout
            // instead of blocking forever. Never die from SIGPIPE if
            // debugserver goes away mid-session.
            struct timeval timeout = { .tv_sec = RSP_IO_TIMEOUT_SEC };
            int on = 1;
            if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1 ||
                setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == -1 ||
                setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on)) == -1) {
                close(fd);
                return -1;
            }
            return fd;
        }
        close(fd);
        usleep(100000);
    }
    return -1;
}

int rsp_set_reg(int sock, int regnum, uint64_t val, char *buf, size_t bufsz)
{
    char hexval[17], cmd[64];
    rsp_encode_u64(val, hexval);
    snprintf(cmd, sizeof(cmd), "P%x=%s", regnum, hexval);
    rsp_send(sock, cmd);
    char *r = rsp_recv(sock, buf, bufsz);
    return (r && strcmp(r, "OK") == 0) ? 0 : -1;
}

int rsp_get_reg(int sock, int regnum, uint64_t *val, char *buf, size_t bufsz)
{
    char cmd[16];
    snprintf(cmd, sizeof(cmd), "p%x", regnum);
    rsp_send(sock, cmd);
    char *r = rsp_recv(sock, buf, bufsz);
    if (!r || !*r) return -1;
    *val = rsp_decode_u64(r);
    return 0;
}

#endif
