/*
 * sa_payload.c — scripting-addition payload as a standalone arm64e image.
 *
 * Compiled separately (see makefile):
 *   clang -arch arm64e -c  →  ld -arch arm64e -e _blob_entry -lSystem
 *
 * Hard requirements:
 *   - ZERO undefined symbols: every external call goes through a function
 *     pointer resolved by dlsym at runtime.
 *   - The image is mapped into Dock with its layout preserved (page-aligned
 *     slide), so ADRP works normally — no INLINE_STR tricks needed.
 *   - arm64e codegen auto-signs local function pointers (paciza) and
 *     authenticated branches (braaz/blraaz/retab) pair up automatically.
 *   - The only manual PAC step: pointers that crossed the process boundary
 *     (loader stripped them) must be re-signed before an authenticated
 *     call — see sign_raw().
 *
 * Entry contract: x0 = struct sa_dp * (see sa_data.h). noreturn.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>

#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>

#include "sa_data.h"
#include "common.h"

#define RTLD_DEFAULT ((void *)-2)
#define unpack(v) p_memcpy(&v, message, sizeof(v)); message += sizeof(v)
#define lerp(a, t, b) (((1.0f-(t))*(a)) + ((t)*(b)))

typedef void *id;
typedef void *SELv;
typedef void *Classv;

/* ------------------------------------------------------------------ */
/* function-pointer layer: p_xxx resolved at runtime, #define lets the */
/* do_* bodies stay close to the original payload.m sources            */
/* ------------------------------------------------------------------ */

typedef void *(*dlsym_fn)(void *, const char *);
typedef void *(*msgsend_fn)(id, SELv, ...);

/* dyld */
static dlsym_fn p_dlsym;
/* ObjC runtime */
static msgsend_fn p_objc_msgSend;
static Classv (*p_objc_getClass)(const char *);
static id (*p_objc_retain)(id);
static SELv (*p_sel_registerName)(const char *);
static void *(*p_object_getInstanceVariable)(id, const char *, void **);
static void (*p_object_setInstanceVariable)(id, const char *, void *);
/* CF */
static CFArrayRef (*p_CFArrayCreate)(CFAllocatorRef, const void **, CFIndex, const void *);
static CFNumberRef (*p_CFNumberCreate)(CFAllocatorRef, CFNumberType, const void *);
static void (*p_CFRelease)(CFTypeRef);
static Boolean (*p_CFEqual)(CFTypeRef, CFTypeRef);
static CFIndex (*p_CFArrayGetCount)(CFArrayRef);
static const void *(*p_CFArrayGetValueAtIndex)(CFArrayRef, CFIndex);
static CFUUIDRef (*p_CFUUIDCreateFromString)(CFAllocatorRef, CFStringRef);
static uint32_t (*p_CGDisplayGetDisplayIDFromUUID)(CFUUIDRef);
static const CFArrayCallBacks *p_kCFTypeArrayCallBacks;
/* GCD — dispatch_get_main_queue is a macro over the _dispatch_main_q
 * data symbol and returns NULL from dlsym; resolve the queue directly. */
static void *p_dispatch_main_q;
static void (*p_dispatch_sync_f)(void *, void *, void (*)(void *));
/* pthread / libc */
static int (*p_pthread_create)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
static int (*p_pthread_detach)(pthread_t);
static int (*p_pthread_mutex_init)(pthread_mutex_t *, const pthread_mutexattr_t *);
static int (*p_pthread_mutex_lock)(pthread_mutex_t *);
static int (*p_pthread_mutex_unlock)(pthread_mutex_t *);
static void *(*p_malloc)(size_t);
static void (*p_free)(void *);
static void *(*p_memcpy)(void *, const void *, size_t);
static size_t (*p_strlen)(const char *);
static void *(*p_memset)(void *, int, size_t);
static int (*p_socket)(int, int, int);
static int (*p_bind)(int, const void *, unsigned);
static int (*p_listen)(int, int);
static int (*p_accept)(int, void *, void *);
static int (*p_read)(int, void *, size_t);
static ssize_t (*p_write)(int, const void *, size_t);
static int (*p_shutdown)(int, int);
static int (*p_close)(int);
static int (*p_unlink)(const char *);
static int (*p_usleep)(unsigned);
static kern_return_t (*p_vm_protect)(mach_port_t, uint64_t, uint64_t, boolean_t, int);
static mach_port_t *p_mach_task_self_;
/* pthread/libc extras */
static int (*p_chmod)(const char *, unsigned);
static int (*p_sysctlbyname)(const char *, void *, size_t *, void *, size_t);

/* SkyLight */
static int (*p_SLSMainConnectionID)(void);
static CGError (*p_SLSGetConnectionPSN)(int, ProcessSerialNumber *);
static CGError (*p_SLSGetWindowAlpha)(int, uint32_t, float *);
static CGError (*p_SLSSetWindowAlpha)(int, uint32_t, float);
static OSStatus (*p_SLSMoveWindowWithGroup)(int, uint32_t, CGPoint *);
static CGError (*p_SLSReassociateWindowsSpacesByGeometry)(int, CFArrayRef);
static CGError (*p_SLSGetWindowOwner)(int, uint32_t, int *);
static void (*p_swift_release)(void *);
static void (*p_swift_errorRelease)(void *);
static void *(*p_wm_metadata)(uint64_t);
static uint64_t p_wm_shared;
static uint64_t p_wm_request_control;
static uint64_t p_wm_activate_window;
static CGError (*p_SLSSetWindowTags)(int, uint32_t, uint64_t *, size_t);
static CGError (*p_SLSClearWindowTags)(int, uint32_t, uint64_t *, size_t);
static CGError (*p_SLSGetWindowBounds)(int, uint32_t, CGRect *);
static CGError (*p_SLSGetWindowTransform)(int, uint32_t, CGAffineTransform *);
static CGError (*p_SLSSetWindowTransform)(int, uint32_t, CGAffineTransform);
static CGError (*p_SLSOrderWindow)(int, uint32_t, int, uint32_t);
static void (*p_SLSManagedDisplaySetCurrentSpace)(int, CFStringRef, uint64_t);
static uint64_t (*p_SLSManagedDisplayGetCurrentSpace)(int, CFStringRef);
static CFStringRef (*p_SLSCopyManagedDisplayForSpace)(int, uint64_t);
static void (*p_SLSMoveWindowsToManagedSpace)(int, CFArrayRef, uint64_t);
static void (*p_SLSShowSpaces)(int, CFArrayRef);
static void (*p_SLSHideSpaces)(int, CFArrayRef);
static CFTypeRef (*p_SLSTransactionCreate)(int);
static CGError (*p_SLSTransactionCommit)(CFTypeRef, int);
static CGError (*p_SLSTransactionOrderWindowGroup)(CFTypeRef, uint32_t, int, uint32_t);
static CGError (*p_SLSTransactionSetWindowSystemAlpha)(CFTypeRef, uint32_t, float);
static CGError (*p_SLSSetWindowSubLevel)(int, uint32_t, int);
static int (*p_CGWindowLevelForKey)(int);

#define malloc p_malloc
#define free p_free
#ifdef memcpy
#undef memcpy
#endif
#ifdef memset
#undef memset
#endif
#define memcpy p_memcpy
#define memset p_memset
#define HASHTABLE_IMPLEMENTATION
#include "../misc/hashtable.h"
#undef HASHTABLE_IMPLEMENTATION
#undef memset
#undef memcpy
#undef free
#undef malloc

#define objc_msgSend      p_objc_msgSend
#define objc_getClass     p_objc_getClass
#define sel               p_sel_registerName
#define CFArrayCreate     p_CFArrayCreate
#define CFNumberCreate    p_CFNumberCreate
#define CFRelease         p_CFRelease
#define CFEqual           p_CFEqual
#define CFArrayGetCount   p_CFArrayGetCount
#define CFArrayGetValueAtIndex p_CFArrayGetValueAtIndex
#define dispatch_sync_f   p_dispatch_sync_f
#define SLSMainConnectionID p_SLSMainConnectionID
#define SLSGetConnectionPSN p_SLSGetConnectionPSN
#define SLSGetWindowAlpha p_SLSGetWindowAlpha
#define SLSSetWindowAlpha p_SLSSetWindowAlpha
#define SLSMoveWindowWithGroup p_SLSMoveWindowWithGroup
#define SLSReassociateWindowsSpacesByGeometry p_SLSReassociateWindowsSpacesByGeometry
#define SLSGetWindowOwner p_SLSGetWindowOwner
#define SLSSetWindowTags  p_SLSSetWindowTags
#define SLSClearWindowTags p_SLSClearWindowTags
#define SLSGetWindowBounds p_SLSGetWindowBounds
#define SLSGetWindowTransform p_SLSGetWindowTransform
#define SLSSetWindowTransform p_SLSSetWindowTransform
#define SLSOrderWindow   p_SLSOrderWindow
#define SLSManagedDisplaySetCurrentSpace p_SLSManagedDisplaySetCurrentSpace
#define SLSManagedDisplayGetCurrentSpace p_SLSManagedDisplayGetCurrentSpace
#define SLSCopyManagedDisplayForSpace p_SLSCopyManagedDisplayForSpace
#define SLSMoveWindowsToManagedSpace p_SLSMoveWindowsToManagedSpace
#define SLSShowSpaces    p_SLSShowSpaces
#define SLSHideSpaces    p_SLSHideSpaces
#define SLSTransactionCreate p_SLSTransactionCreate
#define SLSTransactionCommit p_SLSTransactionCommit
#define SLSTransactionOrderWindowGroup p_SLSTransactionOrderWindowGroup
#define SLSTransactionSetWindowSystemAlpha p_SLSTransactionSetWindowSystemAlpha
#define SLSSetWindowSubLevel p_SLSSetWindowSubLevel
#define CGWindowLevelForKey p_CGWindowLevelForKey

/* ------------------------------------------------------------------ */
/* state                                                              */
/* ------------------------------------------------------------------ */

struct window_fade_context {
    pthread_t thread;
    uint32_t wid;
    volatile float alpha;
    volatile float duration;
    volatile bool skip;
};

static pthread_mutex_t window_fade_lock;
static struct table window_fade_table;

struct sa_state {
    id dock_spaces;
    id dppm;
    uint64_t add_space_fp;
    uint64_t remove_space_fp;
    uint64_t move_space_fp;
    uint64_t set_front_window_fp;
    uint64_t animation_time_addr;
    bool sequoia;
    bool tahoe;
};

static struct sa_state S;

/* arm64e: pointer that crossed the process boundary (stripped by the
 * loader) has no valid signature — re-sign (IA key, disc 0) before any
 * authenticated indirect call. */
static inline void *sign_raw(void *p)
{
    return __builtin_ptrauth_sign_unauthenticated(p, 0, 0);
}

/* ------------------------------------------------------------------ */
/* dock binary pattern scanning (ported from payload.m / arm64_payload.m) */
/* ------------------------------------------------------------------ */

struct osver { int major, minor, patch; };

static struct osver os_version(void)
{
    struct osver v = {0, 0, 0};
    char buf[32] = {0};
    size_t len = sizeof(buf) - 1;
    if (p_sysctlbyname && p_sysctlbyname("kern.osproductversion", buf, &len, NULL, 0) == 0) {
        /* parse "major.minor.patch" without sscanf */
        int *out[3] = {&v.major, &v.minor, &v.patch};
        int fi = 0;
        for (const char *p = buf; *p && fi < 3; p++) {
            if (*p >= '0' && *p <= '9') {
                *out[fi] = *out[fi] * 10 + (*p - '0');
            } else if (*p == '.') {
                fi++;
            } else {
                break;
            }
        }
    }
    return v;
}

static uint64_t hex_find_seq_range(uint64_t addr, uint64_t end, const char *c_pattern)
{
    if (!addr || addr >= end || !c_pattern) return 0;

    uint64_t pattern_length = (p_strlen(c_pattern) + 1) / 3;
    if (!pattern_length || pattern_length > end - addr) return 0;

    char buffer_a[pattern_length];
    char buffer_b[pattern_length];
    p_memset(buffer_a, 0, sizeof(buffer_a));
    p_memset(buffer_b, 0, sizeof(buffer_b));

    const char *pattern = c_pattern + 1;
    for (uint64_t i = 0; i < pattern_length; ++i) {
        char c = pattern[-1];
        if (c == '?') {
            buffer_b[i] = 1;
        } else {
            int temp = c <= '9' ? 0 : 9;
            temp = (temp + c) << 0x4;
            c = pattern[0];
            int temp2 = c <= '9' ? 0xd0 : 0xc9;
            buffer_a[i] = temp2 + c + temp;
        }
        pattern += 3;
    }

    uint64_t last = end - pattern_length;
    while (addr <= last) {
        uint64_t counter = 0;
        while (counter < pattern_length &&
               (buffer_b[counter] || ((char *)addr)[counter] == buffer_a[counter])) {
            counter++;
        }
        if (counter == pattern_length) return addr;
        addr++;
    }

    return 0;
}

static uint64_t hex_find_seq(uint64_t baddr, const char *c_pattern)
{
    return hex_find_seq_range(baddr, baddr + 0x1286a0, c_pattern);
}

static uint64_t decode_adrp_add(uint64_t addr, uint64_t offset)
{
    uint32_t adrp_instr = *(uint32_t *)addr;

    uint32_t immlo = (0x60000000 & adrp_instr) >> 29;
    uint32_t immhi = (0xffffe0 & adrp_instr) >> 3;

    int32_t value = (immhi | immlo) << 12;
    int64_t value_64 = value;

    uint32_t add_instr = *(uint32_t *)(addr + 4);
    uint64_t imm12 = (add_instr & 0x3ffc00) >> 10;

    if (add_instr & 0xc00000) {
        imm12 <<= 12;
    }

    return (offset & 0xfffffffffffff000) + value_64 + imm12;
}

/* dock base = image header of the host process (Dock itself) scanned via
 * mach_vm_region in the loader? No — inside Dock, find its own __TEXT. */
static uint64_t dock_base(void)
{
    /* Dock's own executable image: iterate dyld's image list — but we have
     * no dyld bindings; instead use _dyld API via dlsym. */
    static uint32_t (*dyld_image_count)(void);
    static const void *(*dyld_get_image_header)(uint32_t);
    if (!dyld_image_count) {
        dyld_image_count = p_dlsym(RTLD_DEFAULT, "_dyld_image_count");
        dyld_get_image_header = p_dlsym(RTLD_DEFAULT, "_dyld_get_image_header");
        if (!dyld_image_count || !dyld_get_image_header) return 0;
    }
    /* image 0 is the main executable (Dock) */
    return (uint64_t)dyld_get_image_header(0);
}

static bool verify_os(struct osver v)
{
    if (v.major == 26) { S.sequoia = true; S.tahoe = true; return true; }
    if (v.major == 15) { S.sequoia = true; return true; }
    if (v.major == 14) return true;
    if (v.major == 13) return true;
    if (v.major == 12) return true;
    return false;
}

/* macOS-version offsets/patterns for Dock's __TEXT (from arm64_payload.m) */
struct vpat {
    uint64_t off;
    const char *pat;
};

static struct vpat pat_dock_spaces(struct osver v)
{
    if (v.major == 26)  return (struct vpat){0x30000,  "?8 ?? ?? ?? 08 ?? ?? 91 00 01 40 F9 E2 03 13 AA ?? ?? ?? 94 ?? ?? ?? ?? 08"};
    if (v.major == 15)  return (struct vpat){v.minor >= 4 ? 0x1f0000 : 0x200000, "BF 6B 0A A9 ?? ?? ?? 94 ?? ?? ?? 94 ?? ?? ?? 94"};
    if (v.major == 14)  return (struct vpat){0x114000, "BF 6B 0A A9 ?? ?? ?? 94 ?? ?? ?? 94 ?? ?? ?? 94"};
    if (v.major == 13)  return (struct vpat){0x118000, "F4 57 0B A9 ?? ?? ?? 94 ?? ?? ?? 94 ?? ?? ?? 94"};
    if (v.major == 12)  return (struct vpat){0x8000,   "F4 57 0B A9 ?? ?? ?? 94 ?? ?? ?? 94 ?? ?? ?? 94"};
    return (struct vpat){0, NULL};
}

static struct vpat pat_dppm(struct osver v)
{
    if (v.major == 26)  return (struct vpat){0x70000,  "?? ?? 00 ?? 08 ?? ?? 91 00 01 40 F9 E2 03 16 AA E3 03 19 AA ?? ?? ?? 94"};
    if (v.major == 15)  return (struct vpat){0x250000, "B1 8C 0E 94 ?? ?? ?? 94 ?? ?? ?? 94"};
    if (v.major == 14)  return (struct vpat){v.minor > 0 ? 0x1d2000 : 0x9000, "B1 8C 0E 94 ?? ?? ?? 94 ?? ?? ?? 94"};
    if (v.major == 13)  return (struct vpat){0x9000,   "B1 8C 0E 94 ?? ?? ?? 94 ?? ?? ?? 94"};
    if (v.major == 12)  return (struct vpat){0x7000,   "A9 8C 0E 94 ?? ?? ?? 94 ?? ?? ?? 94"};
    return (struct vpat){0, NULL};
}

static struct vpat pat_add_space(struct osver v)
{
    if (v.major == 26)  return (struct vpat){0x250000, "7F 23 03 D5 E1 03 1E AA ?? ?? ?? 97 FE 03 01 AA FD 7B 05 A9 FD 43 01 91 F3 03"};
    if (v.major == 15)  return (struct vpat){0x250000, "C8 6C 0A 94 ?? ?? ?? 94 C9 8C 0A 94"};
    if (v.major == 14)  return (struct vpat){0x1D0000, "C8 6C 0A 94 ?? ?? ?? 94 C9 8C 0A 94"};
    if (v.major == 13)  return (struct vpat){0x1E0000, "C8 6C 0A 94 ?? ?? ?? 94 C9 8C 0A 94"};
    if (v.major == 12)  return (struct vpat){0x220000, "C8 6C 0A 94 ?? ?? ?? 94 C9 8C 0A 94"};
    return (struct vpat){0, NULL};
}

static struct vpat pat_remove_space(struct osver v)
{
    if (v.major == 26)  return (struct vpat){0x1e0000, "7F 23 03 D5 FF ?? ?? D1 FC ?? ?? A9 FA ?? ?? A9 F8 ?? ?? A9 F6 ?? ?? A9 F4 ?? ?? A9 FD ?? ?? A9 FD ?? ?? 91 ?? 03 03 AA F5 03 02 AA F4 03 01 AA"};
    if (v.major == 15)  return (struct vpat){0x1c0000, "CA 8C 0A 94 ?? ?? ?? 94 ?? ?? ?? 94"};
    if (v.major == 14)  return (struct vpat){0x280000, "CA 8C 0A 94 ?? ?? ?? 94 ?? ?? ?? 94"};
    if (v.major == 13)  return (struct vpat){0x2A0000, "CA 8C 0A 94 ?? ?? ?? 94 ?? ?? ?? 94"};
    if (v.major == 12)  return (struct vpat){0x260000, "CA 8C 0A 94 ?? ?? ?? 94 ?? ?? ?? 94"};
    return (struct vpat){0, NULL};
}

static struct vpat pat_move_space(struct osver v)
{
    if (v.major == 26)  return (struct vpat){0x1c0000, "7F 23 03 D5 E3 03 1E AA ?? ?? ?? 97 FE 03 03 AA FD 7B ?? A9 FD ?? ?? 91 F6 03 14 AA"};
    if (v.major == 15)  return (struct vpat){0x210000, "C7 6C 0A 94 C8 6C 0A 94"};
    if (v.major == 14)  return (struct vpat){0x1C0000, "C7 6C 0A 94 C8 6C 0A 94"};
    if (v.major == 13)  return (struct vpat){0x1F0000, "C7 6C 0A 94 C8 6C 0A 94"};
    if (v.major == 12)  return (struct vpat){0x260000, "C7 6C 0A 94 C8 6C 0A 94"};
    return (struct vpat){0, NULL};
}

static struct vpat pat_set_front_window(struct osver v)
{
    /* macOS 26 uses WindowManagerLayoutControl instead; this old signature
     * resolves to a ShowFront transition helper and cannot focus by itself. */
    if (v.major == 26)  return (struct vpat){0, NULL};
    if (v.major == 15)  return (struct vpat){0x200000, "1F 29 00 F9 ?? ?? ?? 94 ?? ?? ?? 94 ?? ?? ?? 94 ?? ?? ?? 94"};
    if (v.major == 14)  return (struct vpat){0x1E0000, "1F 29 00 F9 ?? ?? ?? 94 ?? ?? ?? 94 ?? ?? ?? 94 ?? ?? ?? 94"};
    if (v.major == 13)  return (struct vpat){0x200000, "1F 29 00 F9 ?? ?? ?? 94 ?? ?? ?? 94 ?? ?? ?? 94 ?? ?? ?? 94"};
    if (v.major == 12)  return (struct vpat){0x240000, "1F 29 00 F9 ?? ?? ?? 94 ?? ?? ?? 94 ?? ?? ?? 94 ?? ?? ?? 94"};
    return (struct vpat){0, NULL};
}

static struct vpat pat_fix_animation(struct osver v)
{
    if (v.major == 26)  return (struct vpat){0x250000, "00 10 6A 1E A8 ?? ?? D1 ?? 01 ?? F8"};
    if (v.major == 15)  return (struct vpat){0x250000, "E4 71 0A 94 E2 03 1F AA ?? ?? ?? 94"};
    if (v.major == 14)  return (struct vpat){0x1D0000, "E4 71 0A 94 E2 03 1F AA ?? ?? ?? 94"};
    if (v.major == 13)  return (struct vpat){0x1E0000, "E4 71 0A 94 E2 03 1F AA ?? ?? ?? 94"};
    if (v.major == 12)  return (struct vpat){0x230000, "E4 71 0A 94 E2 03 1F AA ?? ?? ?? 94"};
    return (struct vpat){0, NULL};
}

static void init_instances(void)
{
    struct osver v = os_version();
    if (!verify_os(v)) return;

    uint64_t baseaddr = dock_base();
    if (!baseaddr) return;

    struct vpat p;

    p = pat_dock_spaces(v);
    if (p.pat) {
        uint64_t a = hex_find_seq(baseaddr + p.off, p.pat);
        if (a) {
            uint64_t off = decode_adrp_add(a, a - baseaddr);
            id obj = *(id *)(baseaddr + off);
            if (obj) S.dock_spaces = p_objc_retain(obj);
        }
    }

    p = pat_dppm(v);
    if (p.pat) {
        uint64_t a = hex_find_seq(baseaddr + p.off, p.pat);
        if (a) {
            uint64_t off = decode_adrp_add(a, a - baseaddr);
            id obj = *(id *)(baseaddr + off);
            if (!obj) obj = *(id *)(baseaddr + off - 8); /* Sonoma hack */
            if (obj) S.dppm = p_objc_retain(obj);
        }
    }

    p = pat_add_space(v);
    if (p.pat) {
        uint64_t a = hex_find_seq(baseaddr + p.off, p.pat);
        if (a) S.add_space_fp = (uint64_t)__builtin_ptrauth_sign_unauthenticated((void *)a, 0, 0);
    }

    p = pat_remove_space(v);
    if (p.pat) {
        uint64_t a = hex_find_seq(baseaddr + p.off, p.pat);
        if (a) S.remove_space_fp = (uint64_t)__builtin_ptrauth_sign_unauthenticated((void *)a, 0, 0);
    }

    p = pat_move_space(v);
    if (p.pat) {
        uint64_t a = hex_find_seq(baseaddr + p.off, p.pat);
        if (a) S.move_space_fp = (uint64_t)__builtin_ptrauth_sign_unauthenticated((void *)a, 0, 0);
    }

    p = pat_set_front_window(v);
    if (p.pat) {
        uint64_t a = hex_find_seq(baseaddr + p.off, p.pat);
        if (a) S.set_front_window_fp = (uint64_t)__builtin_ptrauth_sign_unauthenticated((void *)a, 0, 0);
    }

    p = pat_fix_animation(v);
    if (p.pat) {
        uint64_t a = hex_find_seq(baseaddr + p.off, p.pat);
        if (a) {
            uint64_t page = a & ~0x3fffull;
            if (p_vm_protect(*p_mach_task_self_, page, 0x4000, 0,
                             VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) == KERN_SUCCESS) {
                *(uint32_t *)a = 0x2f00e400; /* movi d0, #0: zero animation duration */
                if (p_vm_protect(*p_mach_task_self_, page, 0x4000, 0,
                                 VM_PROT_READ | VM_PROT_EXECUTE) == KERN_SUCCESS) {
                    S.animation_time_addr = a;
                }
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* ObjC helpers (C flavor of payload.m's inline helpers)              */
/* ------------------------------------------------------------------ */

static id get_ivar_value(id instance, const char *name)
{
    id result = NULL;
    if (p_object_getInstanceVariable) p_object_getInstanceVariable(instance, name, (void **)&result);
    return result;
}

static void set_ivar_value(id instance, const char *name, id value)
{
    if (p_object_setInstanceVariable) p_object_setInstanceVariable(instance, name, value);
}

static uint64_t get_space_id(id space)
{
    return ((uint64_t (*)(id, SELv))objc_msgSend)(space, sel("spid"));
}

static id space_for_display_with_id(CFStringRef display_uuid, uint64_t space_id)
{
    id spaces = ((id (*)(id, SELv, CFStringRef))objc_msgSend)(S.dock_spaces, sel("spacesForDisplay:"), display_uuid);
    if (!spaces) return NULL;
    CFIndex count = CFArrayGetCount((CFArrayRef)spaces);
    for (CFIndex i = 0; i < count; i++) {
        id sp = (id)CFArrayGetValueAtIndex((CFArrayRef)spaces, i);
        if (get_space_id(sp) == space_id) return sp;
    }
    return NULL;
}

static id display_space_for_display_uuid(CFStringRef display_uuid)
{
    id display_spaces = get_ivar_value(S.dock_spaces, "_displaySpaces");
    if (!display_spaces) return NULL;
    CFIndex count = CFArrayGetCount((CFArrayRef)display_spaces);
    for (CFIndex i = 0; i < count; i++) {
        id ds = (id)CFArrayGetValueAtIndex((CFArrayRef)display_spaces, i);
        id cur = get_ivar_value(ds, "_currentSpace");
        uint64_t sid = get_space_id(cur);
        CFStringRef uuid = SLSCopyManagedDisplayForSpace(SLSMainConnectionID(), sid);
        bool match = uuid && CFEqual(uuid, display_uuid);
        if (uuid) CFRelease(uuid);
        if (match) return ds;
    }
    return NULL;
}

static id display_space_for_space_with_id(uint64_t space_id)
{
    id display_spaces = get_ivar_value(S.dock_spaces, "_displaySpaces");
    if (!display_spaces) return NULL;
    CFIndex count = CFArrayGetCount((CFArrayRef)display_spaces);
    for (CFIndex i = 0; i < count; i++) {
        id ds = (id)CFArrayGetValueAtIndex((CFArrayRef)display_spaces, i);
        id cur = get_ivar_value(ds, "_currentSpace");
        if (get_space_id(cur) == space_id) return ds;
    }
    return NULL;
}

/* CFArray of CFNumber from uint64 sid / uint32 wid values */
static CFArrayRef array_of_numbers(const void *values, size_t size, int count)
{
    CFNumberRef temp[64];
    if (count > 64) count = 64;
    for (int i = 0; i < count; i++)
        temp[i] = CFNumberCreate(NULL, size == 8 ? 4 : 3 /* SInt64:SInt32 */,
                                 (const char *)values + size * i);
    CFArrayRef arr = CFArrayCreate(NULL, (const void **)temp, count,
                                   p_kCFTypeArrayCallBacks);
    for (int i = 0; i < count; i++) CFRelease(temp[i]);
    return arr;
}

/* Dock's private add/move routines take one argument in x20. Keep the
 * register setup and authenticated call in one asm block: splitting them
 * lets the C epilogue restore callee-saved x20 before a tail call. */
__attribute__((noinline))
static void call_add_space(id v0, id v1, uint64_t func)
{
    __asm__ volatile(
        "mov x0, %0\n"
        "mov x20, %1\n"
        "blraaz %2\n"
        :
        : "r"(v0), "r"(v1), "r"(func)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
          "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16",
          "x17", "x20", "x30", "cc", "memory");
}

__attribute__((noinline))
static void call_move_space(id v0, id v1, const void *v2, id v3, uint64_t func)
{
    __asm__ volatile(
        "mov x0, %0\n"
        "mov x1, %1\n"
        "mov x2, %2\n"
        "mov x20, %3\n"
        "blraaz %4\n"
        :
        : "r"(v0), "r"(v1), "r"(v2), "r"(v3), "r"(func)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
          "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16",
          "x17", "x20", "x30", "cc", "memory");
}

__attribute__((noinline))
static void *call_wm_shared(void *metadata, uint64_t func)
{
    void *result;
    __asm__ volatile(
        "mov x20, %1\n"
        "blraaz %2\n"
        "mov %0, x0\n"
        : "=&r"(result)
        : "r"(metadata), "r"(func)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
          "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16",
          "x17", "x20", "x30", "cc", "memory");
    return result;
}

__attribute__((noinline))
static void *call_wm_request_control(void *manager, uint64_t func, void **error)
{
    void *result;
    void *swift_error;
    __asm__ volatile(
        "mov x20, %2\n"
        "mov x21, xzr\n"
        "blraaz %3\n"
        "mov %0, x0\n"
        "mov %1, x21\n"
        : "=&r"(result), "=&r"(swift_error)
        : "r"(manager), "r"(func)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
          "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16",
          "x17", "x20", "x21", "x30", "cc", "memory");
    *error = swift_error;
    return result;
}

__attribute__((noinline))
static void *call_wm_activate_window(uint32_t wid, void *control, uint64_t func)
{
    void *swift_error;
    __asm__ volatile(
        "mov w0, %w1\n"
        "mov x20, %2\n"
        "mov x21, xzr\n"
        "blraaz %3\n"
        "mov %0, x21\n"
        : "=&r"(swift_error)
        : "r"(wid), "r"(control), "r"(func)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
          "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16",
          "x17", "x20", "x21", "x30", "cc", "memory");
    return swift_error;
}

#define asm__call_add_space(v0, v1, func) call_add_space((v0), (v1), (func))
#define asm__call_move_space(v0, v1, v2, v3, func) \
    call_move_space((v0), (v1), (v2), (v3), (func))

/* dispatch_sync(^{...}) → dispatch_sync_f(main_q, ctx, fn) */
struct main_ctx {
    uint64_t space_id;
    CFStringRef display_uuid;
    id space, dest_space, display_space, dock_spaces;
    uint64_t fp;
    unsigned dest_display_id;
    CFStringRef dest_display_uuid;
    uint32_t wid;
};

static void on_main_space_create(void *arg)
{
    struct main_ctx *c = arg;
    const char *class_name = S.sequoia ? "ManagedSpace" : "Dock.ManagedSpace";
    id new_space = ((id (*)(id, SELv))objc_msgSend)(
        ((id (*)(id, SELv))objc_msgSend)(objc_getClass(class_name), sel("alloc")), sel("init"));
    id display_space = display_space_for_display_uuid(c->display_uuid);
    asm__call_add_space(new_space, display_space, c->fp);
}

typedef void (*remove_space_call)(id, id, id, uint64_t, uint64_t);
static void on_main_space_destroy(void *arg)
{
    struct main_ctx *c = arg;
    ((remove_space_call)c->fp)(c->space, c->display_space, c->dock_spaces, c->space_id, c->space_id);
}

static void on_main_space_move(void *arg)
{
    struct main_ctx *c = arg;
    asm__call_move_space(c->space, c->dest_space, c->dest_display_uuid, c->dock_spaces, c->fp);
}

static void on_main_dppm_move(void *arg)
{
    struct main_ctx *c = arg;
    ((void (*)(id, SELv, id, unsigned, CFStringRef))objc_msgSend)(
        S.dppm, sel("moveSpace:toDisplay:displayUUID:"), c->space, c->dest_display_id, c->dest_display_uuid);
}

static void on_main_window_focus(void *arg)
{
    struct main_ctx *c = arg;
    void *metadata = p_wm_metadata(0);
    if (!metadata) return;

    void *manager = call_wm_shared(metadata, p_wm_shared);
    if (!manager) return;

    void *error = NULL;
    void *control = call_wm_request_control(manager, p_wm_request_control, &error);
    if (error) {
        p_swift_errorRelease(error);
        p_swift_release(manager);
        return;
    }
    if (!control) {
        p_swift_release(manager);
        return;
    }

    error = call_wm_activate_window(c->wid, control, p_wm_activate_window);
    if (error) p_swift_errorRelease(error);
    p_swift_release(control);
    p_swift_release(manager);
}

/* ------------------------------------------------------------------ */
/* opcode handlers (ported from payload.m)                            */
/* ------------------------------------------------------------------ */

static void do_space_focus(char *message)
{
    if (!S.dock_spaces) return;

    uint64_t dest_space_id;
    unpack(dest_space_id);
    if (!dest_space_id) return;

    CFStringRef dest_display = SLSCopyManagedDisplayForSpace(SLSMainConnectionID(), dest_space_id);
    if (!dest_display) return;

    id source_space = ((id (*)(id, SELv, CFStringRef))objc_msgSend)(
        S.dock_spaces, sel(S.sequoia ? "currentSpaceForDisplayUUID:" : "currentSpaceforDisplayUUID:"), dest_display);
    uint64_t source_space_id = source_space ? get_space_id(source_space) : 0;

    if (source_space_id != dest_space_id) {
        id dest_space = space_for_display_with_id(dest_display, dest_space_id);
        if (dest_space) {
            id display_space = display_space_for_space_with_id(source_space_id);
            if (display_space) {
                uint64_t src_arr[1] = {source_space_id};
                uint64_t dst_arr[1] = {dest_space_id};
                CFArrayRef ns_dest = array_of_numbers(dst_arr, 8, 1);
                CFArrayRef ns_src = array_of_numbers(src_arr, 8, 1);
                SLSShowSpaces(SLSMainConnectionID(), ns_dest);
                SLSHideSpaces(SLSMainConnectionID(), ns_src);
                SLSManagedDisplaySetCurrentSpace(SLSMainConnectionID(), dest_display, dest_space_id);
                set_ivar_value(display_space, "_currentSpace", p_objc_retain(dest_space));
                CFRelease(ns_dest);
                CFRelease(ns_src);
            }
        }
    }

    CFRelease(dest_display);
}

static void do_space_create(char *message)
{
    if (!S.dock_spaces || !S.add_space_fp) return;

    uint64_t space_id;
    unpack(space_id);

    CFStringRef display_uuid = SLSCopyManagedDisplayForSpace(SLSMainConnectionID(), space_id);
    if (!display_uuid) return;

    struct main_ctx c = {.space_id = space_id, .display_uuid = display_uuid, .fp = S.add_space_fp};
    dispatch_sync_f(p_dispatch_main_q, &c, on_main_space_create);
    CFRelease(display_uuid);
}

static void do_space_destroy(char *message)
{
    if (!S.dock_spaces || !S.remove_space_fp) return;

    uint64_t space_id;
    unpack(space_id);

    CFStringRef display_uuid = SLSCopyManagedDisplayForSpace(SLSMainConnectionID(), space_id);
    if (!display_uuid) return;

    uint64_t active_space_id = SLSManagedDisplayGetCurrentSpace(SLSMainConnectionID(), display_uuid);
    id space = space_for_display_with_id(display_uuid, space_id);
    id display_space = display_space_for_display_uuid(display_uuid);

    struct main_ctx c = {.space_id = space_id, .space = space, .display_space = display_space,
                         .dock_spaces = S.dock_spaces, .fp = S.remove_space_fp};
    dispatch_sync_f(p_dispatch_main_q, &c, on_main_space_destroy);

    if (active_space_id == space_id) {
        uint64_t dest_space_id = SLSManagedDisplayGetCurrentSpace(SLSMainConnectionID(), display_uuid);
        id dest_space = space_for_display_with_id(display_uuid, dest_space_id);
        if (dest_space) set_ivar_value(display_space, "_currentSpace", p_objc_retain(dest_space));
    }

    CFRelease(display_uuid);
}

static void do_space_move(char *message)
{
    if (!S.dock_spaces || !S.dppm || !S.move_space_fp) return;

    uint64_t source_space_id, dest_space_id, source_prev_space_id;
    unpack(source_space_id);
    unpack(dest_space_id);
    unpack(source_prev_space_id);

    bool focus_dest_space;
    unpack(focus_dest_space);

    CFStringRef source_display_uuid = SLSCopyManagedDisplayForSpace(SLSMainConnectionID(), source_space_id);
    if (!source_display_uuid) return;
    id source_space = space_for_display_with_id(source_display_uuid, source_space_id);
    id source_display_space = display_space_for_display_uuid(source_display_uuid);

    CFStringRef dest_display_uuid = SLSCopyManagedDisplayForSpace(SLSMainConnectionID(), dest_space_id);
    if (!dest_display_uuid) { CFRelease(source_display_uuid); return; }
    id dest_space = space_for_display_with_id(dest_display_uuid, dest_space_id);
    id dest_display_space = display_space_for_display_uuid(dest_display_uuid);
    if (!source_space || !source_display_space || !dest_space || !dest_display_space) {
        CFRelease(source_display_uuid);
        CFRelease(dest_display_uuid);
        return;
    }

    CFUUIDRef dest_display_uuid_ref = p_CFUUIDCreateFromString(NULL, dest_display_uuid);
    unsigned dest_display_id = dest_display_uuid_ref
        ? p_CGDisplayGetDisplayIDFromUUID(dest_display_uuid_ref) : 0;
    if (dest_display_uuid_ref) CFRelease(dest_display_uuid_ref);
    if (!dest_display_id) {
        CFRelease(source_display_uuid);
        CFRelease(dest_display_uuid);
        return;
    }

    if (source_prev_space_id) {
        uint64_t show_arr[1] = {source_prev_space_id};
        uint64_t hide_arr[1] = {source_space_id};
        CFArrayRef ns_dest = array_of_numbers(show_arr, 8, 1);
        CFArrayRef ns_src = array_of_numbers(hide_arr, 8, 1);
        id new_source_space = space_for_display_with_id(source_display_uuid, source_prev_space_id);

        SLSShowSpaces(SLSMainConnectionID(), ns_dest);
        SLSHideSpaces(SLSMainConnectionID(), ns_src);
        SLSManagedDisplaySetCurrentSpace(SLSMainConnectionID(), source_display_uuid, source_prev_space_id);
        if (source_display_space && new_source_space)
            set_ivar_value(source_display_space, "_currentSpace", p_objc_retain(new_source_space));
        CFRelease(ns_dest);
        CFRelease(ns_src);
    }

    struct main_ctx c = {.space = source_space, .dest_space = dest_space,
                         .display_space = dest_display_space,
                         .dest_display_uuid = dest_display_uuid, .dock_spaces = S.dock_spaces,
                         .fp = S.move_space_fp};
    dispatch_sync_f(p_dispatch_main_q, &c, on_main_space_move);

    struct main_ctx d = {.space = source_space, .dest_display_id = dest_display_id,
                         .dest_display_uuid = dest_display_uuid};
    dispatch_sync_f(p_dispatch_main_q, &d, on_main_dppm_move);

    if (focus_dest_space) {
        uint64_t new_source_space_id = SLSManagedDisplayGetCurrentSpace(SLSMainConnectionID(), source_display_uuid);
        id new_source_space = space_for_display_with_id(source_display_uuid, new_source_space_id);
        if (source_display_space && new_source_space)
            set_ivar_value(source_display_space, "_currentSpace", p_objc_retain(new_source_space));

        uint64_t hide_arr[1] = {dest_space_id};
        CFArrayRef ns_dest_monitor = array_of_numbers(hide_arr, 8, 1);
        SLSHideSpaces(SLSMainConnectionID(), ns_dest_monitor);
        SLSManagedDisplaySetCurrentSpace(SLSMainConnectionID(), dest_display_uuid, source_space_id);
        if (dest_display_space && source_space)
            set_ivar_value(dest_display_space, "_currentSpace", p_objc_retain(source_space));
        CFRelease(ns_dest_monitor);
    }

    CFRelease(source_display_uuid);
    CFRelease(dest_display_uuid);
}

static void do_window_move(char *message)
{
    uint32_t wid;
    unpack(wid);
    if (!wid) return;

    int x, y;
    unpack(x);
    unpack(y);

    CGPoint point = {x, y};
    SLSMoveWindowWithGroup(SLSMainConnectionID(), wid, &point);

    uint32_t arr[1] = {wid};
    CFArrayRef window_list = array_of_numbers(arr, 4, 1);
    SLSReassociateWindowsSpacesByGeometry(SLSMainConnectionID(), window_list);
    CFRelease(window_list);
}

static void do_window_opacity(char *message)
{
    uint32_t wid;
    unpack(wid);
    if (!wid) return;

    float alpha;
    unpack(alpha);

    p_pthread_mutex_lock(&window_fade_lock);
    struct window_fade_context *context = table_find(&window_fade_table, &wid);

    if (context) {
        context->alpha = alpha;
        context->duration = 0.0f;
        __asm__ __volatile__ ("" ::: "memory");

        context->skip = true;
        p_pthread_mutex_unlock(&window_fade_lock);
    } else {
        SLSSetWindowAlpha(SLSMainConnectionID(), wid, alpha);
        p_pthread_mutex_unlock(&window_fade_lock);
    }
}

static void *window_fade_thread_proc(void *data)
{
entry:;
    struct window_fade_context *context = (struct window_fade_context *)data;
    context->skip = false;

    float start_alpha;
    float end_alpha = context->alpha;
    SLSGetWindowAlpha(SLSMainConnectionID(), context->wid, &start_alpha);

    int frame_duration = 8;
    int total_duration = (int)(context->duration * 1000.0f);
    int frame_count = (int)(((float)total_duration / (float)frame_duration) + 1.0f);

    for (int frame_index = 1; frame_index <= frame_count; ++frame_index) {
        if (context->skip) goto entry;

        float t = (float)frame_index / (float)frame_count;
        if (t < 0.0f) t = 0.0f;
        if (t > 1.0f) t = 1.0f;

        float alpha = lerp(start_alpha, t, end_alpha);
        SLSSetWindowAlpha(SLSMainConnectionID(), context->wid, alpha);

        p_usleep((unsigned)(frame_duration * 1000));
    }

    p_pthread_mutex_lock(&window_fade_lock);
    if (!context->skip) {
        table_remove(&window_fade_table, &context->wid);
        p_pthread_mutex_unlock(&window_fade_lock);
        p_free(context);
        return NULL;
    }
    p_pthread_mutex_unlock(&window_fade_lock);

    goto entry;
}

static void do_window_opacity_fade(char *message)
{
    uint32_t wid;
    unpack(wid);
    if (!wid) return;

    float alpha, duration;
    unpack(alpha);
    unpack(duration);

    p_pthread_mutex_lock(&window_fade_lock);
    struct window_fade_context *context = table_find(&window_fade_table, &wid);

    if (context) {
        context->alpha = alpha;
        context->duration = duration;
        __asm__ __volatile__ ("" ::: "memory");

        context->skip = true;
        p_pthread_mutex_unlock(&window_fade_lock);
    } else {
        context = p_malloc(sizeof(struct window_fade_context));
        context->wid = wid;
        context->alpha = alpha;
        context->duration = duration;
        context->skip = false;
        __asm__ __volatile__ ("" ::: "memory");

        table_add(&window_fade_table, &wid, context);
        p_pthread_mutex_unlock(&window_fade_lock);
        p_pthread_create(&context->thread, NULL, window_fade_thread_proc, context);
        p_pthread_detach(context->thread);
    }
}

static void do_window_layer(char *message)
{
    uint32_t wid;
    unpack(wid);
    if (!wid) return;

    int layer;
    unpack(layer);

    SLSSetWindowSubLevel(SLSMainConnectionID(), wid, CGWindowLevelForKey(layer));
}

static void do_window_sticky(char *message)
{
    uint32_t wid;
    unpack(wid);
    if (!wid) return;

    bool value;
    unpack(value);

    uint64_t tags = (1 << 11);
    if (value == 1) {
        SLSSetWindowTags(SLSMainConnectionID(), wid, &tags, 64);
    } else {
        SLSClearWindowTags(SLSMainConnectionID(), wid, &tags, 64);
    }
}

typedef void (*focus_window_call)(ProcessSerialNumber, uint32_t);
static void do_window_focus(char *message)
{
    bool use_tahoe_focus = S.tahoe && p_wm_metadata && p_wm_shared &&
                           p_wm_request_control && p_wm_activate_window &&
                           p_swift_release && p_swift_errorRelease;
    if (!use_tahoe_focus && !S.set_front_window_fp) return;

    uint32_t wid;
    unpack(wid);

    if (use_tahoe_focus) {
        struct main_ctx c = {.wid = wid};
        dispatch_sync_f(p_dispatch_main_q, &c, on_main_window_focus);
        return;
    }

    if (!p_SLSGetWindowOwner || !p_SLSGetConnectionPSN) return;
    int window_connection = 0;
    ProcessSerialNumber window_psn = {0, 0};
    SLSGetWindowOwner(SLSMainConnectionID(), wid, &window_connection);
    SLSGetConnectionPSN(window_connection, &window_psn);
    ((focus_window_call)S.set_front_window_fp)(window_psn, wid);
}

static void do_window_shadow(char *message)
{
    uint32_t wid;
    unpack(wid);
    if (!wid) return;

    bool value;
    unpack(value);

    uint64_t tags = (1 << 3);
    if (value == 1) {
        SLSClearWindowTags(SLSMainConnectionID(), wid, &tags, 64);
    } else {
        SLSSetWindowTags(SLSMainConnectionID(), wid, &tags, 64);
    }
}

static void do_window_scale(char *message)
{
    uint32_t wid;
    unpack(wid);
    if (!wid) return;

    CGRect frame = {{0, 0}, {0, 0}};
    SLSGetWindowBounds(SLSMainConnectionID(), wid, &frame);

    CGAffineTransform current = {0, 0, 0, 0, 0, 0};
    SLSGetWindowTransform(SLSMainConnectionID(), wid, &current);

    CGAffineTransform original = {1, 0, 0, 1,
                                  -frame.origin.x, -frame.origin.y};
    bool is_original = current.a == original.a && current.d == original.d &&
                       current.tx == original.tx && current.ty == original.ty;

    if (is_original) {
        float dx, dy, dw, dh;
        unpack(dx);
        unpack(dy);
        unpack(dw);
        unpack(dh);

        int target_width = dw / 4;
        int target_height = target_width / (frame.size.width / frame.size.height);

        float x_scale = frame.size.width / target_width;
        float y_scale = frame.size.height / target_height;

        float transformed_x = -(dx + dw) + (frame.size.width * (1 / x_scale));
        float transformed_y = -dy;

        /* transform = translate(tx,ty) ∘ scale(sx,sy) */
        CGAffineTransform t = {x_scale, 0, 0, y_scale,
                               transformed_x * x_scale,
                               transformed_y * y_scale};
        SLSSetWindowTransform(SLSMainConnectionID(), wid, t);
    } else {
        SLSSetWindowTransform(SLSMainConnectionID(), wid, original);
    }
}

static void do_window_swap_proxy_in(char *message)
{
    int count = 0;
    unpack(count);
    if (!count) return;

    CFTypeRef transaction = SLSTransactionCreate(SLSMainConnectionID());
    for (int i = 0; i < count; ++i) {
        uint32_t wid;
        unpack(wid);
        if (!wid) continue;
        uint32_t proxy_wid;
        unpack(proxy_wid);

        SLSTransactionOrderWindowGroup(transaction, proxy_wid, 1, wid);
        SLSTransactionSetWindowSystemAlpha(transaction, wid, 0);
    }
    SLSTransactionCommit(transaction, 0);
    CFRelease(transaction);
}

static void do_window_swap_proxy_out(char *message)
{
    int count = 0;
    unpack(count);
    if (!count) return;

    CFTypeRef transaction = SLSTransactionCreate(SLSMainConnectionID());
    for (int i = 0; i < count; ++i) {
        uint32_t wid;
        unpack(wid);
        if (!wid) continue;
        uint32_t proxy_wid;
        unpack(proxy_wid);

        SLSTransactionSetWindowSystemAlpha(transaction, wid, 1.0f);
        SLSTransactionOrderWindowGroup(transaction, proxy_wid, 0, wid);
    }
    SLSTransactionCommit(transaction, 0);
    CFRelease(transaction);
}

static void do_window_order(char *message)
{
    uint32_t a_wid;
    unpack(a_wid);
    if (!a_wid) return;

    int order;
    unpack(order);

    uint32_t b_wid;
    unpack(b_wid);

    SLSOrderWindow(SLSMainConnectionID(), a_wid, order, b_wid);
}

static void do_window_order_in(char *message)
{
    int count = 0;
    unpack(count);
    if (!count) return;

    CFTypeRef transaction = SLSTransactionCreate(SLSMainConnectionID());
    for (int i = 0; i < count; ++i) {
        uint32_t wid;
        unpack(wid);
        if (!wid) continue;
        SLSTransactionOrderWindowGroup(transaction, wid, 1, 0);
    }
    SLSTransactionCommit(transaction, 0);
    CFRelease(transaction);
}

static void do_window_list_move_to_space(char *message)
{
    uint64_t sid;
    unpack(sid);

    int count = 0;
    unpack(count);
    if (count <= 0 || count > 64) return;

    CFArrayRef window_list = array_of_numbers(message, sizeof(uint32_t), count);
    SLSMoveWindowsToManagedSpace(SLSMainConnectionID(), window_list, sid);
    CFRelease(window_list);
}

static void do_window_move_to_space(char *message)
{
    uint64_t sid;
    unpack(sid);

    uint32_t wid;
    unpack(wid);

    CFArrayRef window_list = array_of_numbers(&wid, sizeof(uint32_t), 1);
    SLSMoveWindowsToManagedSpace(SLSMainConnectionID(), window_list, sid);
    CFRelease(window_list);
}

static void do_handshake(int fd)
{
    uint32_t attrib = 0;
    if (S.dock_spaces)          attrib |= OSAX_ATTRIB_DOCK_SPACES;
    if (S.dppm)                 attrib |= OSAX_ATTRIB_DPPM;
    if (S.add_space_fp)         attrib |= OSAX_ATTRIB_ADD_SPACE;
    if (S.remove_space_fp)      attrib |= OSAX_ATTRIB_REM_SPACE;
    if (S.move_space_fp)        attrib |= OSAX_ATTRIB_MOV_SPACE;
    if ((S.tahoe && p_wm_metadata && p_wm_shared && p_wm_request_control &&
         p_wm_activate_window && p_swift_release && p_swift_errorRelease) ||
        S.set_front_window_fp) attrib |= OSAX_ATTRIB_SET_WINDOW;
    if (S.animation_time_addr) attrib |= OSAX_ATTRIB_ANIM_TIME;

    char bytes[64];
    int n = 0;
    const char *ver = OSAX_VERSION;
    while (ver[n]) { bytes[n] = ver[n]; n++; }
    bytes[n++] = 0;
    p_memcpy(bytes + n, &attrib, 4);
    n += 4;
    bytes[n++] = '\n';
    p_write(fd, bytes, n);
}

static void handle_message(int fd, char *message)
{
    unsigned char op = (unsigned char)*message++;
    if (op == SA_OPCODE_HANDSHAKE) {
        do_handshake(fd);          /* writes its own response */
        return;
    }

    switch (op) {
    case SA_OPCODE_SPACE_FOCUS:          do_space_focus(message); break;
    case SA_OPCODE_SPACE_CREATE:         do_space_create(message); break;
    case SA_OPCODE_SPACE_DESTROY:        do_space_destroy(message); break;
    case SA_OPCODE_SPACE_MOVE:           do_space_move(message); break;
    case SA_OPCODE_WINDOW_MOVE:          do_window_move(message); break;
    case SA_OPCODE_WINDOW_OPACITY:       do_window_opacity(message); break;
    case SA_OPCODE_WINDOW_OPACITY_FADE:  do_window_opacity_fade(message); break;
    case SA_OPCODE_WINDOW_LAYER:         do_window_layer(message); break;
    case SA_OPCODE_WINDOW_STICKY:        do_window_sticky(message); break;
    case SA_OPCODE_WINDOW_SHADOW:        do_window_shadow(message); break;
    case SA_OPCODE_WINDOW_FOCUS:         do_window_focus(message); break;
    case SA_OPCODE_WINDOW_SCALE:         do_window_scale(message); break;
    case SA_OPCODE_WINDOW_SWAP_PROXY_IN: do_window_swap_proxy_in(message); break;
    case SA_OPCODE_WINDOW_SWAP_PROXY_OUT:do_window_swap_proxy_out(message); break;
    case SA_OPCODE_WINDOW_ORDER:         do_window_order(message); break;
    case SA_OPCODE_WINDOW_ORDER_IN:      do_window_order_in(message); break;
    case SA_OPCODE_WINDOW_LIST_TO_SPACE: do_window_list_move_to_space(message); break;
    case SA_OPCODE_WINDOW_TO_SPACE:      do_window_move_to_space(message); break;
    default: break;
    }

    char ok = 0;
    p_write(fd, &ok, 1);
}

/* ------------------------------------------------------------------ */
/* daemon (pthread): resolve, scan, socket, accept loop               */
/* ------------------------------------------------------------------ */

static TABLE_HASH_FUNC(hash_wid)
{
    return *(uint32_t *)key;
}

static TABLE_COMPARE_FUNC(compare_wid)
{
    return *(uint32_t *)key_a == *(uint32_t *)key_b;
}

static bool resolve_all(dlsym_fn d)
{
#define RS(var, sym) do { var = (__typeof__(var))d(RTLD_DEFAULT, sym); } while (0)
    RS(p_objc_msgSend,      "objc_msgSend");
    RS(p_objc_getClass,     "objc_getClass");
    RS(p_objc_retain,       "objc_retain");
    RS(p_sel_registerName,  "sel_registerName");
    RS(p_object_getInstanceVariable, "object_getInstanceVariable");
    RS(p_object_setInstanceVariable, "object_setInstanceVariable");
    RS(p_CFArrayCreate,     "CFArrayCreate");
    RS(p_CFNumberCreate,    "CFNumberCreate");
    RS(p_CFRelease,         "CFRelease");
    RS(p_CFEqual,           "CFEqual");
    RS(p_CFArrayGetCount,   "CFArrayGetCount");
    RS(p_CFArrayGetValueAtIndex, "CFArrayGetValueAtIndex");
    RS(p_CFUUIDCreateFromString, "CFUUIDCreateFromString");
    RS(p_CGDisplayGetDisplayIDFromUUID, "CGDisplayGetDisplayIDFromUUID");
    RS(p_kCFTypeArrayCallBacks, "kCFTypeArrayCallBacks");
    RS(p_dispatch_main_q,    "_dispatch_main_q");
    RS(p_dispatch_sync_f,   "dispatch_sync_f");
    RS(p_pthread_create,    "pthread_create");
    RS(p_pthread_detach,    "pthread_detach");
    RS(p_pthread_mutex_init, "pthread_mutex_init");
    RS(p_pthread_mutex_lock, "pthread_mutex_lock");
    RS(p_pthread_mutex_unlock, "pthread_mutex_unlock");
    RS(p_malloc,            "malloc");
    RS(p_free,              "free");
    RS(p_memcpy,            "memcpy");
    RS(p_strlen,            "strlen");
    RS(p_memset,            "memset");
    RS(p_socket,            "socket");
    RS(p_bind,              "bind");
    RS(p_listen,            "listen");
    RS(p_accept,            "accept");
    RS(p_read,              "read");
    RS(p_write,             "write");
    RS(p_shutdown,          "shutdown");
    RS(p_close,             "close");
    RS(p_unlink,            "unlink");
    RS(p_usleep,            "usleep");
    RS(p_vm_protect,        "vm_protect");
    RS(p_mach_task_self_,   "mach_task_self_");
    RS(p_chmod,             "chmod");
    RS(p_sysctlbyname,      "sysctlbyname");
    RS(p_SLSMainConnectionID,                  "SLSMainConnectionID");
    RS(p_SLSGetConnectionPSN,                  "SLSGetConnectionPSN");
    RS(p_SLSGetWindowAlpha,                    "SLSGetWindowAlpha");
    RS(p_SLSSetWindowAlpha,                    "SLSSetWindowAlpha");
    RS(p_SLSMoveWindowWithGroup,               "SLSMoveWindowWithGroup");
    RS(p_SLSReassociateWindowsSpacesByGeometry,"SLSReassociateWindowsSpacesByGeometry");
    RS(p_SLSGetWindowOwner,                    "SLSGetWindowOwner");
    RS(p_swift_release,                         "swift_release");
    RS(p_swift_errorRelease,                    "swift_errorRelease");
    RS(p_wm_metadata,                           "$s13WindowManagerAACMa");
    RS(p_wm_shared,                             "$s13WindowManagerAAC6sharedABvgZ");
    RS(p_wm_request_control,                    "$s13WindowManagerAAC33synchronouslyRequestLayoutControlAA0abeF0CyKF");
    RS(p_wm_activate_window,                    "$s13WindowManager0aB13LayoutControlC021synchronouslyActivateA0yys6UInt32VKFTj");
    RS(p_SLSSetWindowTags,                     "SLSSetWindowTags");
    RS(p_SLSClearWindowTags,                   "SLSClearWindowTags");
    RS(p_SLSGetWindowBounds,                   "SLSGetWindowBounds");
    RS(p_SLSGetWindowTransform,                "SLSGetWindowTransform");
    RS(p_SLSSetWindowTransform,                "SLSSetWindowTransform");
    RS(p_SLSOrderWindow,                       "SLSOrderWindow");
    RS(p_SLSManagedDisplaySetCurrentSpace,     "SLSManagedDisplaySetCurrentSpace");
    RS(p_SLSManagedDisplayGetCurrentSpace,     "SLSManagedDisplayGetCurrentSpace");
    RS(p_SLSCopyManagedDisplayForSpace,        "SLSCopyManagedDisplayForSpace");
    RS(p_SLSMoveWindowsToManagedSpace,         "SLSMoveWindowsToManagedSpace");
    RS(p_SLSShowSpaces,                        "SLSShowSpaces");
    RS(p_SLSHideSpaces,                        "SLSHideSpaces");
    RS(p_SLSTransactionCreate,                 "SLSTransactionCreate");
    RS(p_SLSTransactionCommit,                 "SLSTransactionCommit");
    RS(p_SLSTransactionOrderWindowGroup,       "SLSTransactionOrderWindowGroup");
    RS(p_SLSTransactionSetWindowSystemAlpha,   "SLSTransactionSetWindowSystemAlpha");
    RS(p_SLSSetWindowSubLevel,                 "SLSSetWindowSubLevel");
    RS(p_CGWindowLevelForKey,                  "CGWindowLevelForKey");
#undef RS

    if (!p_objc_msgSend || !p_sel_registerName ||
        !p_CFArrayCreate || !p_CFArrayGetCount ||
        !p_CFArrayGetValueAtIndex || !p_CFUUIDCreateFromString ||
        !p_CGDisplayGetDisplayIDFromUUID || !p_kCFTypeArrayCallBacks ||
        !p_SLSMainConnectionID || !p_socket || !p_memcpy ||
        !p_dispatch_main_q || !p_dispatch_sync_f ||
        !p_pthread_create || !p_pthread_detach ||
        !p_pthread_mutex_init || !p_pthread_mutex_lock ||
        !p_pthread_mutex_unlock || !p_malloc || !p_free ||
        !p_memset || !p_usleep || !p_SLSGetWindowAlpha ||
        !p_SLSSetWindowAlpha)
        return false;
    return true;
}

static void *daemon_main(void *arg)
{
    struct sa_dp *dp = arg;
    dp->status = 0x11; /* progress: entered daemon (status stays RUNNING) */

    if (!resolve_all(p_dlsym)) {
        dp->status = SA_ST_FAIL;
        for (;;) ;
    }
    dp->status = 0x22;

    init_instances();
    p_pthread_mutex_init(&window_fade_lock, NULL);
    table_init(&window_fade_table, 150, hash_wid, compare_wid);
    dp->status = 0x33;

    struct sockaddr_un {
        uint8_t sun_len;
        uint8_t sun_family;
        char sun_path[104];
    } un;
    p_memset(&un, 0, sizeof(un));
    un.sun_family = 1 /* AF_UNIX */;
    int i = 0;
    while (dp->socket_path[i] && i < (int)sizeof(un.sun_path) - 1) {
        un.sun_path[i] = dp->socket_path[i];
        i++;
    }
    un.sun_len = (uint8_t)(2 + i + 1);

    p_unlink(un.sun_path);

    int fd = p_socket(1 /* AF_UNIX */, 1 /* SOCK_STREAM */, 0);
    if (fd < 0) { dp->status = SA_ST_FAIL; for (;;) ; }
    if (p_bind(fd, &un, sizeof(un)) != 0) { dp->status = SA_ST_FAIL; for (;;) ; }
    p_chmod(dp->socket_path, 0600);
    if (p_listen(fd, 128) != 0) { dp->status = SA_ST_FAIL; for (;;) ; }

    dp->status = SA_ST_OK;

    for (;;) {
        int conn = p_accept(fd, 0, 0);
        if (conn < 0) continue;

        int16_t nread = 0;
        if (p_read(conn, &nread, 2) == 2 && nread > 0 && nread < SA_SOCKET_BUFF_LEN) {
            char buf[SA_SOCKET_BUFF_LEN];
            int got = 0;
            while (got < nread) {
                int r = (int)p_read(conn, buf + got, (size_t)(nread - got));
                if (r <= 0) break;
                got += r;
            }
            if (got == nread) handle_message(conn, buf);
        }
        p_shutdown(conn, 2 /* SHUT_RDWR */);
        p_close(conn);
    }
}

/* ------------------------------------------------------------------ */
/* entry: runs on the hijacked Dock thread                            */
/* x0 = struct sa_dp *                                                */
/* ------------------------------------------------------------------ */

__attribute__((noreturn, used))
void blob_entry(struct sa_dp *dp)
{
    if (!dp || dp->magic != SA_DP_MAGIC || !dp->dlsym) {
        if (dp) dp->status = SA_ST_FAIL;
        for (;;) ;
    }
    dp->status = 0xA1; /* entered blob_entry */

    /* cross-process pointer: loader stripped it; re-sign (IA, disc 0).
     * dlsym results afterwards are already signed by dyld — never
     * re-sign those, double-signing corrupts the pointer. */
    p_dlsym = (dlsym_fn)sign_raw((void *)dp->dlsym);
    dp->status = 0xA2;

    void *(*ptc)(void *, const void *, void *(*)(void *), void *) =
        (void *(*)(void *, const void *, void *(*)(void *), void *))
        p_dlsym(RTLD_DEFAULT, "pthread_create");
    if (!ptc) {
        dp->status = SA_ST_FAIL;
        for (;;) ;
    }
    dp->status = 0xA3;

    /* &daemon_main is a local address: arm64e codegen signs it (paciza)
     * and pthread's _pthread_start authenticates via blraaz. */
    void *tid = 0;
    if (ptc(&tid, 0, daemon_main, dp) != 0) {
        dp->status = SA_ST_FAIL;
        for (;;) ;
    }
    dp->status = 0xA4; /* pthread spawned */

    /* pthread owns the work; hijacked thread spins until the injector
     * restores its saved registers and releases it. */
    for (;;) ;
}

__attribute__((noreturn, used))
void blob_spin(void)
{
    for (;;) ;
}
