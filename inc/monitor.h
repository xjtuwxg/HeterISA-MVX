#ifndef _MONITOR_H
#define _MONITOR_H

#include <sys/ptrace.h>		// ptrace()
#include <sys/user.h>		// struct user_regs_struct
#include <stdio.h>		// pid_t
#include <sys/types.h>		// pid_t
#include <syscall.h>		// SYS_read, SYS_getpid
#include <errno.h>		// errno
#include <string.h>		// memcpy()
#include <assert.h>		// assert()

#ifdef __x86_64__
#include <sys/reg.h>		// ORIG_RAX
#endif

typedef struct _args {
    char *arg0;
    char *arg1;
    char *arg2;
    char *arg3;
    char *arg4;
    char *arg5;
} args_t;

typedef struct _syscall_entry {
    int nargs;
    const char *name;
    union {
	args_t args;
	char* arg[6];
    } sc_arg;
} syscall_entry_t;

/* Define the "sensitive" syscall number, params that we want to intercept */
static const syscall_entry_t syscalls[] = {
/* syscall entries are from "strace/linux/x86_64/syscallent.h" */
#ifdef __x86_64__
#include <x86/syscallent.h>
#endif
/* syscall entries are from "strace/linux/64/syscallent.h" */
#ifdef __aarch64__
#include <arm64/syscallent.h>
#endif
};

/* All syscall names and number, converted from musl. */
static const char* syscall_name[] = {
#ifdef __x86_64__
#include <x86/syscall.h>
#endif
#ifdef __aarch64__
#include <arm64/syscall.h>
#endif
};

/* The dir whitelist. */
static const char* dir_whitelist[] = {
#include "whitelist.h"
};

/* Syscall convert table (arm64 => x86_64). */
static const int syscall_tbl[512] = {
#include "syscall_tbl.h"
};

/* Store the "real fd" with the "virtual fd" as the index. */
static int fd_vtab[128];
static int vtab_index = 3; // point to next available fd.
static int open_close_idx = 0;

void pre_syscall(long syscall, long long args[]);
void post_syscall(long syscall, long result);

/* Follower syscall handling code. */
void follower_wait_pre_syscall(pid_t pid, long syscall_num, long long args[],
			       int *skip_post_handling);
//void follower_wait_post_syscall(pid_t pid, long syscall_num);
void follower_wait_post_syscall(pid_t pid, long syscall_num,
				long long syscall_retval);
void follower_wait_post_syscall_sel(pid_t pid, long syscall_num,
				      long long args[]);

/* Master sync code. */
void master_syncpoint(pid_t pid, int fd, long syscall_num, long long args[],
		      long long retval);

#endif
