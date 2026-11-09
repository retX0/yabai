#ifdef __arm64__

/*
 * The debugserver thread-hijack flow is adapted from retX0/amfree:
 * https://github.com/retX0/amfree
 */

#include "dock_hijack.h"
#include "rsp.h"
#include "sa_data.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <fcntl.h>
#include <stddef.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define RSP_PORT 23482

// Relative to a developer dir (what `xcode-select -p` prints).
#define DEBUGSERVER_XCODE_SUFFIX \
    "/../SharedFrameworks/LLDB.framework/Versions/A/Resources/debugserver"
#define DEBUGSERVER_CLT_SUFFIX \
    "/Library/PrivateFrameworks/LLDB.framework/Versions/A/Resources/debugserver"

#define XCODE_SELECT_LINK   "/var/db/xcode_select_link"
#define XCODE_DEVELOPER_DIR "/Applications/Xcode.app/Contents/Developer"
#define CLT_DEVELOPER_DIR   "/Library/Developer/CommandLineTools"

typedef struct {
    int num;
    uint64_t val;
} saved_reg_t;

/*
 * The loader is setuid-root and runs debugserver as root, so only accept
 * Apple's debugserver. "anchor apple" alone is not enough: any Apple binary
 * (e.g. /bin/sh) would pass, and Xcode.app is often user-writable.
 */
#define DEBUGSERVER_REQUIREMENT "identifier \"com.apple.debugserver\" and anchor apple"

static int debugserver_is_trusted(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode) || access(path, X_OK) != 0)
        return 0;

    int trusted = 0;
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        kCFAllocatorDefault, (const UInt8 *)path, (CFIndex)strlen(path), false);
    SecStaticCodeRef code = NULL;
    SecRequirementRef requirement = NULL;

    if (url &&
        SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code) == errSecSuccess &&
        SecRequirementCreateWithString(CFSTR(DEBUGSERVER_REQUIREMENT), kSecCSDefaultFlags, &requirement) == errSecSuccess &&
        SecStaticCodeCheckValidity(code, kSecCSStrictValidate, requirement) == errSecSuccess) {
        trusted = 1;
    }

    if (requirement) CFRelease(requirement);
    if (code) CFRelease(code);
    if (url) CFRelease(url);
    return trusted;
}

static int try_debugserver(char *path, size_t path_sz, const char *developer_dir, const char *suffix)
{
    int wrote = snprintf(path, path_sz, "%s%s", developer_dir, suffix);
    if (wrote < 0 || (size_t)wrote >= path_sz) return 0;
    return debugserver_is_trusted(path);
}

/*
 * Find debugserver in the active developer dir first, then in the default
 * Xcode and Command Line Tools locations. Both layouts are tried for each dir:
 * Xcode keeps it in SharedFrameworks, Command Line Tools in PrivateFrameworks.
 *
 * The active dir is read from the root-owned xcode-select link instead of
 * running `xcode-select -p`, which honours DEVELOPER_DIR from the caller.
 */
static int resolve_debugserver(char *path, size_t path_sz)
{
    const char *dirs[3];
    size_t dir_count = 0;

    char selected[1024];
    ssize_t len = readlink(XCODE_SELECT_LINK, selected, sizeof(selected) - 1);
    if (len > 0) {
        selected[len] = '\0';
        dirs[dir_count++] = selected;
    }
    dirs[dir_count++] = XCODE_DEVELOPER_DIR;
    dirs[dir_count++] = CLT_DEVELOPER_DIR;

    for (size_t i = 0; i < dir_count; i++) {
        if (try_debugserver(path, path_sz, dirs[i], DEBUGSERVER_XCODE_SUFFIX)) return 0;
        if (try_debugserver(path, path_sz, dirs[i], DEBUGSERVER_CLT_SUFFIX))   return 0;
    }

    return -1;
}

static pid_t dock_spawn_debugserver(pid_t target)
{
    char ds_path[1024];
    char pid_arg[32], port_arg[32];
    if (resolve_debugserver(ds_path, sizeof(ds_path)) < 0) {
        fprintf(stderr, "could not locate an Apple-signed debugserver "
                        "(install Xcode or the Command Line Tools: xcode-select --install)\n");
        return -1;
    }

    snprintf(pid_arg, sizeof(pid_arg), "--attach=%d", target);
    snprintf(port_arg, sizeof(port_arg), "localhost:%d", RSP_PORT);

    pid_t ds_pid = fork();
    if (ds_pid == 0) {
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execl(ds_path, "debugserver", port_arg, pid_arg, NULL);
        _exit(127);
    }
    return ds_pid;
}

static void abort_threads(mach_port_t task)
{
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t tcount = 0;
    if (task_threads(task, &threads, &tcount) != KERN_SUCCESS) return;
    for (mach_msg_type_number_t i = 0; i < tcount; i++) {
        thread_abort_safely(threads[i]);
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads, tcount * sizeof(thread_t));
}

/* Extract thread ID from a T-stop reply like "T11thread:2365fa4;...". */
static void parse_stop_thread(const char *reply, char *out, size_t outsz)
{
    const char *p = strstr(reply, "thread:");
    if (!p) return;
    p += 7;
    size_t i = 0;
    while (p[i] && p[i] != ';' && i < outsz - 1) {
        out[i] = p[i];
        i++;
    }
    out[i] = '\0';
}

int dock_hijack_exec(pid_t pid, mach_port_t task,
                     mach_vm_address_t code, mach_vm_address_t spin_pc,
                     mach_vm_address_t stack_top, uint64_t x0)
{
    char rsp_buf[65536];
    saved_reg_t saved_regs[0x22];
    size_t saved_count = 0;
    int saved_regs_ok = 0;
    int killed_dock = 0;
    int ret = -1;
    char hijack_tid[32] = {0};

    pid_t ds_pid = dock_spawn_debugserver(pid);
    if (ds_pid < 0) return -1;

    int sock = rsp_connect(RSP_PORT);
    if (sock < 0) {
        fprintf(stderr, "debugserver rsp connect failed\n");
        kill(ds_pid, SIGKILL);
        waitpid(ds_pid, NULL, 0);
        return -1;
    }

    usleep(200000);
    rsp_send(sock, "QStartNoAckMode");
    rsp_recv(sock, rsp_buf, sizeof(rsp_buf));

    rsp_send(sock, "?");
    char *reply = rsp_recv(sock, rsp_buf, sizeof(rsp_buf));
    if (!reply || reply[0] != 'T') {
        fprintf(stderr, "dock stop query failed\n");
        goto cleanup;
    }

    /* Remember which thread the "?" stop-reply refers to.
     * This is the thread whose registers we save/restore. */
    parse_stop_thread(reply, hijack_tid, sizeof(hijack_tid));

    /* Select this thread for register operations (Hg). */
    if (hijack_tid[0]) {
        char cmd[40];
        snprintf(cmd, sizeof(cmd), "Hg%s", hijack_tid);
        rsp_send(sock, cmd);
        rsp_recv(sock, rsp_buf, sizeof(rsp_buf));
    }

    abort_threads(task);

    /* Save all general-purpose registers, cpsr, and pc. */
    for (int reg = 0; reg <= 0x1f; reg++)
        saved_regs[saved_count++].num = reg;
    saved_regs[saved_count++].num = 0x21; /* cpsr — optional */
    saved_regs[saved_count++].num = 0x20; /* pc */

    for (size_t i = 0; i < saved_count;) {
        if (rsp_get_reg(sock, saved_regs[i].num, &saved_regs[i].val,
                        rsp_buf, sizeof(rsp_buf)) == 0) {
            i++;
            continue;
        }
        if (saved_regs[i].num == 0x21) {
            saved_regs[i] = saved_regs[--saved_count];
            continue;
        }
        fprintf(stderr, "read reg %x failed\n", saved_regs[i].num);
        goto cleanup;
    }
    saved_regs_ok = 1;

    /* Set x0=data_page, pc=code_entry, sp=stack, lr=spin. */
    if (rsp_set_reg(sock, 0x00, x0,                 rsp_buf, sizeof(rsp_buf)) < 0 ||
        rsp_set_reg(sock, 0x20, (uint64_t)code,     rsp_buf, sizeof(rsp_buf)) < 0 ||
        rsp_set_reg(sock, 0x1e, (uint64_t)spin_pc,  rsp_buf, sizeof(rsp_buf)) < 0 ||
        rsp_set_reg(sock, 0x1f, (uint64_t)stack_top, rsp_buf, sizeof(rsp_buf)) < 0) {
        fprintf(stderr, "set pc/sp/x0/lr failed\n");
        goto cleanup;
    }

    /* Resume ALL threads — no Hc thread selection so pthread_create can work. */
    rsp_send(sock, "c");

    /* Poll dp->status via mach_vm_read (whole process keeps running). */
    {
        uint64_t status = SA_ST_RUNNING;
        for (int i = 0; i < 80; i++) {
            usleep(50000);
            mach_vm_size_t outsz = 0;
            if (mach_vm_read_overwrite(task, x0 + offsetof(struct sa_dp, status),
                                       8, (mach_vm_address_t)&status, &outsz) == KERN_SUCCESS) {
                if (status == SA_ST_OK) { ret = 0; break; }
                if (status == SA_ST_FAIL) break;
            }
        }
    }

    /* Stop so we can restore regs. */
    {
        char ctrl_c = 0x03;
        write(sock, &ctrl_c, 1);
        rsp_recv(sock, rsp_buf, sizeof(rsp_buf));
    }

    /* Re-select our hijacked thread for register restore.
     * After ctrl+C, debugserver's current thread is whichever thread
     * happened to be running — in a multi-threaded Dock that's NOT
     * necessarily ours. Without Hg we'd restore our saved regs into
     * a random Dock thread → PAC mismatch → crash. */
    if (hijack_tid[0]) {
        char cmd[40];
        snprintf(cmd, sizeof(cmd), "Hg%s", hijack_tid);
        rsp_send(sock, cmd);
        rsp_recv(sock, rsp_buf, sizeof(rsp_buf));
    }

cleanup:
    /* ALWAYS restore registers to the correct thread. */
    if (saved_regs_ok) {
        int restore_ok = 1;
        for (size_t i = 0; i < saved_count; i++) {
            if (rsp_set_reg(sock, saved_regs[i].num, saved_regs[i].val,
                            rsp_buf, sizeof(rsp_buf)) < 0) {
                restore_ok = 0;
                break;
            }
        }
        if (!restore_ok) {
            /* The hijacked thread now has partly restored registers and would
             * crash Dock at some random later point. Kill it now instead;
             * launchd restarts Dock and yabai can re-inject on dock_did_restart. */
            fprintf(stderr, "could not restore Dock registers; killing Dock\n");
            kill(pid, SIGKILL);
            killed_dock = 1;
            ret = -1;
        }
    }
    if (!killed_dock) {
        rsp_send(sock, "D");
        rsp_recv(sock, rsp_buf, sizeof(rsp_buf));
    }
    kill(ds_pid, SIGKILL);
    waitpid(ds_pid, NULL, 0);
    close(sock);
    return ret;
}

#endif
