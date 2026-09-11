#ifndef YABAI_SA_DATA_H
#define YABAI_SA_DATA_H

#include <stdint.h>

#define SA_DP_MAGIC 0x59414241495341ull /* YABAISA */

#define SA_ST_RUNNING 0
#define SA_ST_OK      1
#define SA_ST_FAIL    2

struct sa_dp {
    uint64_t magic;
    uint64_t dlsym;
    uint64_t status;      /* also carries progress markers (0xA1/0x11/...) */
    char socket_path[108];
};

#endif
