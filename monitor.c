#define _POSIX_C_SOURCE 200112L

/* C standard library */
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* POSIX */
#include <unistd.h>
#include <sys/user.h>	// struct user_regs_struct
#include <sys/wait.h>

/* Linux */
#include <syscall.h>
#include <sys/ptrace.h>

#define PTR	0
#define INT	1
#define UINT	2

typedef struct args {
    char *arg0;
    char *arg1;
    char *arg2;
    char *arg3;
    char *arg4;
    char *arg5;
} args_t;

typedef struct syscall_entry {
    int nargs;
    const char *name;
    union {
	args_t args;
	char* arg[6];
    } sc_arg;
} syscall_entry_t;

#define FATAL(...) \
    do { \
        fprintf(stderr, "strace: " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)

static const syscall_entry_t syscalls[] = {
#include "syscallent.h"
};

void pre_syscall(long syscall, struct user_regs_struct regs)
{
    //long syscall = regs.orig_rax;
    syscall_entry_t ent = syscalls[syscall];

    if (ent.name != 0) {
	int nargs = ent.nargs;
	int cnt = 0;
	fprintf(stderr, "[%3ld] %s (", syscall, ent.name);
	if (cnt++ < nargs) fprintf(stderr, "%s: 0x%llx", ent.sc_arg.arg[0], regs.rdi);
	else goto out;
	if (cnt++ < nargs) fprintf(stderr, ", %s: 0x%llx", ent.sc_arg.arg[1], regs.rsi);
	else goto out;
	if (cnt++ < nargs) fprintf(stderr, ", %s: 0x%llx", ent.sc_arg.arg[2], regs.rdx);
	else goto out;
	if (cnt++ < nargs) fprintf(stderr, ", %s: 0x%llx", ent.sc_arg.arg[3], regs.r10);
	else goto out;
	if (cnt++ < nargs) fprintf(stderr, ", %s: 0x%llx", ent.sc_arg.arg[4], regs.r8);
	else goto out;
	if (cnt++ < nargs) fprintf(stderr, ", %s: 0x%llx", ent.sc_arg.arg[5], regs.r9);
	else goto out;
out:
	fprintf(stderr, ")");
    }
#if 0
    /* Print a representation of the system call */
    fprintf(stderr, "[%3ld] (%ld, %ld, %ld, %ld, %ld, %ld)",
            syscall,
            (long)regs.rdi, (long)regs.rsi, (long)regs.rdx,
            (long)regs.r10, (long)regs.r8,  (long)regs.r9);
#endif
}

void post_syscall(long syscall, long result)
{
    syscall_entry_t ent = syscalls[syscall];

    if (ent.name != 0) {
        /* Print system call result */
        fprintf(stderr, " = 0x%lx\n", result);
    }
}

int main(int argc, char **argv)
{
    if (argc <= 1)
        FATAL("too few arguments: %d", argc);

#if 1
    int syscall_num = sizeof(syscalls) / sizeof(syscall_entry_t);
    printf("%lu, %lu\n", sizeof(syscalls), sizeof(syscall_entry_t));
    for (int i = 0; i < syscall_num; i++) {
	if (syscalls[i].nargs == 0) continue;
	printf("[%3d] syscall %s # params: %d\n",
	       i, syscalls[i].name, syscalls[i].nargs);
	for (int j = 0; j < syscalls[i].nargs; j++)
	    printf("%s, ", syscalls[i].sc_arg.arg[j]);
	printf("\n");
    }
#endif

    pid_t pid = fork();
    switch (pid) {
        case -1: /* error */
            FATAL("%s", strerror(errno));
        case 0:  /* child */
            ptrace(PTRACE_TRACEME, 0, 0, 0);
            execvp(argv[1], argv + 1);
            FATAL("%s", strerror(errno));
    }

    /* parent */
    waitpid(pid, 0, 0); // sync with PTRACE_TRACEME
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

    for (;;) {
        /* Enter next system call */
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));
        if (waitpid(pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));

        /* Get system call arguments */
        struct user_regs_struct regs;
	long syscall_num = regs.orig_rax;
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
            FATAL("%s", strerror(errno));

	pre_syscall(syscall_num, regs);
#if 0
        long syscall = regs.orig_rax;

        /* Print a representation of the system call */
        fprintf(stderr, "[%3ld] (%ld, %ld, %ld, %ld, %ld, %ld)",
                syscall,
                (long)regs.rdi, (long)regs.rsi, (long)regs.rdx,
                (long)regs.r10, (long)regs.r8,  (long)regs.r9);
#endif

        /* Run system call and stop on exit */
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));
        if (waitpid(pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));

        /* Get system call result */
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
            fputs(" = ?\n", stderr);
            if (errno == ESRCH)
                exit(regs.rdi); // system call was _exit(2) or similar
            FATAL("%s", strerror(errno));
        }

	post_syscall(syscall_num, regs.rax);
    }
}
