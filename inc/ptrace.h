#ifndef _PTRACE_H
#define _PTRACE_H

#include <sys/ptrace.h>		// ptrace
#include <sys/wait.h>		// waitpid
#include <linux/ptrace.h>
#include <sys/user.h>		// struct user_regs_struct
#include <sys/uio.h>		// struct iovec for arm64
#include <errno.h>		// errno
#include <elf.h>		// NT_PRSTATUS
#include <string.h>		// strerror

union u {
    long val;
    char str[8];
} input;

static inline int ptrace_syscall(pid_t pid)
{
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
		return -1;
        if (waitpid(pid, 0, 0) == -1)
		return -2;
	return 0;
}

long get_regs_args(pid_t pid, struct user_regs_struct *regs, long long args[]);
long long get_retval(pid_t pid, struct user_regs_struct *regs, int *term);

int update_child_data(pid_t pid, long long dst, char *src, size_t len);
int get_child_data(pid_t pid, char *dst, long long src, size_t len);

#endif
