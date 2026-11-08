#ifndef YABAI_DOCK_HIJACK_H
#define YABAI_DOCK_HIJACK_H

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <sys/types.h>
#include <stdint.h>

#ifdef __arm64__
int dock_hijack_exec(pid_t pid, mach_port_t task,
                     mach_vm_address_t code, mach_vm_address_t spin_pc,
                     mach_vm_address_t stack_top, uint64_t x0);
#endif

#endif
