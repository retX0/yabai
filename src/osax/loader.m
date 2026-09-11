#include <Cocoa/Cocoa.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

#ifdef __arm64__
#include <ptrauth.h>
#include <stdlib.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include "dock_hijack.h"
#include "sa_data.h"

/* embedded arm64e blob image (see makefile: blob_bin.c) */
extern unsigned char sa_blob_image[];
extern unsigned int sa_blob_image_len;
#else
static const char payload_path[] = "/Library/ScriptingAdditions/yabai.osax/Contents/Resources/payload.bundle/Contents/MacOS/payload";

static char shell_code[] =
"\x55"                             // push       rbp
"\x48\x89\xE5"                     // mov        rbp, rsp
"\x48\x83\xEC\x10"                 // sub        rsp, 0x10
"\x48\x8D\x7D\xF8"                 // lea        rdi, qword [rbp+var_8]
"\x31\xC0"                         // xor        eax, eax
"\x89\xC1"                         // mov        ecx, eax
"\x48\x8D\x15\x1E\x00\x00\x00"     // lea        rdx, qword ptr [rip+0x1E]
"\x48\x89\xCE"                     // mov        rsi, rcx
"\x48\xB8"                         // movabs     rax, pthread_create_from_mach_thread
"\x00\x00\x00\x00\x00\x00\x00\x00" //
"\xFF\xD0"                         // call       rax
"\x48\x83\xC4\x10"                 // add        rsp, 0x10
"\x5D"                             // pop        rbp
"\x48\xC7\xC0\x65\x62\x61\x79"     // mov        rax, 0x79616265
"\xEB\xFE"                         // jmp        0x0
"\xC3"                             // ret
"\x55"                             // push       rbp
"\x48\x89\xE5"                     // mov        rbp, rsp
"\xBE\x01\x00\x00\x00"             // mov        esi, 0x1
"\x48\x8D\x3D\x16\x00\x00\x00"     // lea        rdi, qword ptr [rip+0x16]
"\x48\xB8"                         // movabs     rax, dlopen
"\x00\x00\x00\x00\x00\x00\x00\x00" //
"\xFF\xD0"                         // call       rax
"\x31\xF6"                         // xor        esi, esi
"\x89\xF7"                         // mov        edi, esi
"\x48\x89\xF8"                     // mov        rax, rdi
"\x5D"                             // pop        rbp
"\xC3"                             // ret
"\x00\x00\x00\x00\x00\x00\x00\x00" // empty space for payload_path
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00";
#endif

static pid_t get_dock_pid(void)
{
    NSArray *list = [NSRunningApplication runningApplicationsWithBundleIdentifier:@"com.apple.dock"];

    if (list.count == 1) {
        NSRunningApplication *dock = list[0];
        if ([dock isFinishedLaunching] == YES) {
            return [dock processIdentifier];
        }
    }

    return 0;
}

#ifdef __arm64__

/* Parse the embedded blob image and map it into the target with its
 * layout preserved (page-aligned slide) — ADRP stays valid.
 * Returns 0 and fills entry/spin (target addresses) on success. */
static int map_blob_image(mach_port_t task,
                          mach_vm_address_t *entry_out,
                          mach_vm_address_t *spin_out)
{
    const struct mach_header_64 *mh = (const struct mach_header_64 *)sa_blob_image;
    if (sa_blob_image_len < sizeof(*mh) || mh->magic != MH_MAGIC_64 || mh->filetype != MH_EXECUTE) {
        fprintf(stderr, "sa_blob_image: not a mach-o executable\n");
        return 1;
    }

    const struct load_command *lc = (const struct load_command *)(mh + 1);
    const struct symtab_command *st = NULL;
    uint64_t min_vm = ~0ull, max_vm = 0;

    for (uint32_t i = 0; i < mh->ncmds;
         i++, lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize)) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
            if (!strcmp(sg->segname, "__PAGEZERO") || !strcmp(sg->segname, "__LINKEDIT") || !sg->vmsize)
                continue;
            if (sg->vmaddr + sg->vmsize < sg->vmaddr ||
                sg->fileoff + sg->filesize < sg->fileoff ||
                sg->fileoff + sg->filesize > sa_blob_image_len) {
                fprintf(stderr, "sa_blob_image: invalid segment %s\n", sg->segname);
                return 1;
            }
            /* Include zero-fill segments in the reservation. In particular,
             * __DATA,__bss has filesize == 0 but contains all payload globals. */
            if (sg->vmaddr < min_vm) min_vm = sg->vmaddr;
            if (sg->vmaddr + sg->vmsize > max_vm) max_vm = sg->vmaddr + sg->vmsize;
        } else if (lc->cmd == LC_SYMTAB) {
            st = (const struct symtab_command *)lc;
        }
    }
    if (!st || min_vm > max_vm) {
        fprintf(stderr, "sa_blob_image: bad segments/symtab\n");
        return 1;
    }

    uint64_t entry = 0, spin = 0;
    const struct nlist_64 *syms = (const struct nlist_64 *)(sa_blob_image + st->symoff);
    const char *strs = (const char *)(sa_blob_image + st->stroff);
    for (uint32_t i = 0; i < st->nsyms; i++) {
        if ((syms[i].n_type & N_TYPE) != N_SECT || !syms[i].n_value) continue;
        const char *name = strs + syms[i].n_un.n_strx;
        if (!strcmp(name, "_blob_entry")) entry = syms[i].n_value;
        else if (!strcmp(name, "_blob_spin")) spin = syms[i].n_value;
    }
    if (!entry || !spin) {
        fprintf(stderr, "sa_blob_image: entry/spin symbols missing\n");
        return 1;
    }

    uint64_t span = (max_vm - min_vm + 0xfff) & ~0xfffull;
    mach_vm_address_t remote = 0;
    if (mach_vm_allocate(task, &remote, span, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
        fprintf(stderr, "sa_blob_image: remote alloc failed\n");
        return 1;
    }

    lc = (const struct load_command *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds;
         i++, lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize)) {
        if (lc->cmd != LC_SEGMENT_64) continue;
        const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
        if (!strcmp(sg->segname, "__PAGEZERO") || !strcmp(sg->segname, "__LINKEDIT") || !sg->vmsize)
            continue;
        mach_vm_address_t dst = remote + (sg->vmaddr - min_vm);
        if ((sg->filesize &&
             mach_vm_write(task, dst, (vm_address_t)(sa_blob_image + sg->fileoff),
                           sg->filesize) != KERN_SUCCESS) ||
            vm_protect(task, dst, sg->vmsize, 0,
                       strcmp(sg->segname, "__TEXT") == 0
                           ? (VM_PROT_EXECUTE | VM_PROT_READ)
                           : (VM_PROT_READ | VM_PROT_WRITE)) != KERN_SUCCESS) {
            fprintf(stderr, "sa_blob_image: map seg %s failed\n", sg->segname);
            mach_vm_deallocate(task, remote, span);
            return 1;
        }
    }

    *entry_out = remote + (entry - min_vm);
    *spin_out = remote + (spin - min_vm);
    return 0;
}

static int inject_via_hijack(pid_t pid, mach_port_t task)
{
    const char *user = getenv("SUDO_USER");
    if (!user) user = getenv("USER");
    if (!user) {
        fprintf(stderr, "no SUDO_USER/USER for sa socket\n");
        return 1;
    }

    struct sa_dp dp = {0};
    dp.magic = SA_DP_MAGIC;
    dp.dlsym = (uint64_t)ptrauth_strip(dlsym(RTLD_DEFAULT, "dlsym"), ptrauth_key_function_pointer);
    snprintf(dp.socket_path, sizeof(dp.socket_path), "/tmp/yabai-sa_%s.socket", user);

    mach_vm_address_t data = 0, stack = 0;
    vm_size_t stack_size = 64 * 1024;
    if (mach_vm_allocate(task, &data, sizeof(dp), VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
        fprintf(stderr, "remote data alloc failed\n");
        return 1;
    }
    if (mach_vm_allocate(task, &stack, stack_size, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
        fprintf(stderr, "remote stack alloc failed\n");
        mach_vm_deallocate(task, data, sizeof(dp));
        return 1;
    }
    if (mach_vm_write(task, data, (vm_address_t)&dp, sizeof(dp)) != KERN_SUCCESS) {
        fprintf(stderr, "remote data write failed\n");
        mach_vm_deallocate(task, stack, stack_size);
        mach_vm_deallocate(task, data, sizeof(dp));
        return 1;
    }

    mach_vm_address_t entry = 0, spin = 0;
    if (map_blob_image(task, &entry, &spin) != 0) {
        mach_vm_deallocate(task, stack, stack_size);
        mach_vm_deallocate(task, data, sizeof(dp));
        return 1;
    }

    int rc = dock_hijack_exec(pid, task, entry, spin, stack + stack_size / 2, data);
    mach_vm_deallocate(task, stack, stack_size);
    if (rc == 0) {
        /* daemon_main no longer references the startup data after SA_ST_OK. */
        mach_vm_deallocate(task, data, sizeof(dp));
    } else {
        uint64_t status = 0;
        mach_vm_size_t out = 0;
        mach_vm_read_overwrite(task, data + offsetof(struct sa_dp, status),
                               sizeof(status), (mach_vm_address_t)&status, &out);
        fprintf(stderr, "loader: final status=0x%llx\n", (unsigned long long)status);
    }
    return rc;
}
#endif

int main(void)
{
    mach_port_t task = 0;
    pid_t pid = get_dock_pid();

    if (!pid) {
        fprintf(stderr, "could not locate Dock.app pid\n");
        return 1;
    }

    if (task_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS) {
        fprintf(stderr, "could not retrieve task port for pid: %d\n", pid);
        return 1;
    }

#ifdef __arm64__
    return inject_via_hijack(pid, task);
#else
    int result = 0;
    thread_act_t thread = 0;
    mach_vm_address_t code = 0;
    mach_vm_address_t stack = 0;
    vm_size_t stack_size = 16 * 1024;
    uint64_t stack_contents = 0x00000000CAFEBABE;

    if (mach_vm_allocate(task, &stack, stack_size, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
        fprintf(stderr, "could not allocate stack segment\n");
        return 1;
    }

    if (mach_vm_write(task, stack, (vm_address_t) &stack_contents, sizeof(uint64_t)) != KERN_SUCCESS) {
        fprintf(stderr, "could not copy dummy return address into stack segment\n");
        return 1;
    }

    if (vm_protect(task, stack, stack_size, 1, VM_PROT_READ | VM_PROT_WRITE) != KERN_SUCCESS) {
        fprintf(stderr, "could not change protection for stack segment\n");
        return 1;
    }

    if (mach_vm_allocate(task, &code, sizeof(shell_code), VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
        fprintf(stderr, "could not allocate code segment\n");
        return 1;
    }

    uint64_t pcfmt_address = (uint64_t) dlsym(RTLD_DEFAULT, "pthread_create_from_mach_thread");
    uint64_t dlopen_address = (uint64_t) dlsym(RTLD_DEFAULT, "dlopen");

    memcpy(shell_code + 28, &pcfmt_address, sizeof(uint64_t));
    memcpy(shell_code + 71, &dlopen_address, sizeof(uint64_t));
    memcpy(shell_code + 90, payload_path, strlen(payload_path));

    if (mach_vm_write(task, code, (vm_address_t) shell_code, sizeof(shell_code)) != KERN_SUCCESS) {
        fprintf(stderr, "could not copy shellcode into code segment\n");
        return 1;
    }

    if (vm_protect(task, code, sizeof(shell_code), 0, VM_PROT_EXECUTE | VM_PROT_READ) != KERN_SUCCESS) {
        fprintf(stderr, "could not change protection for code segment\n");
        return 1;
    }

    x86_thread_state64_t thread_state = {};
    thread_state_flavor_t thread_flavor = x86_THREAD_STATE64;
    mach_msg_type_number_t thread_flavor_count = x86_THREAD_STATE64_COUNT;

    thread_state.__rip = (uint64_t) code;
    thread_state.__rsp = (uint64_t) stack + (stack_size / 2);

    kern_return_t error = thread_create_running(task, thread_flavor, (thread_state_t)&thread_state, thread_flavor_count, &thread);
    if (error != KERN_SUCCESS) {
        fprintf(stderr, "could not spawn remote thread: %s\n", mach_error_string(error));
        return 1;
    }

    usleep(10000);

    for (int i = 0; i < 10; ++i) {
        kern_return_t error = thread_get_state(thread, thread_flavor, (thread_state_t)&thread_state, &thread_flavor_count);

        if (error != KERN_SUCCESS) {
            result = 1;
            goto terminate;
        }

        if (thread_state.__rax == 0x79616265) {
            result = 0;
            goto terminate;
        }

        usleep(20000);
    }

terminate:
    error = thread_terminate(thread);
    if (error != KERN_SUCCESS) {
        fprintf(stderr, "failed to terminate remote thread: %s\n", mach_error_string(error));
    }

    return result;
#endif
}
