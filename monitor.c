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

#include <linux/ptrace.h>
#include <sys/uio.h>
#include <elf.h>

#define FATAL(...) \
    do { \
        fprintf(stderr, "strace: " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)

#define PTR	0
#define INT	1
#define UINT	2

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

/* define the "sensitive" syscall number, params that we want to intercept */
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

void sync_syscall(long syscall, struct user_regs_struct *regs, pid_t pid)
{
    char read_param[20] = "Hello World!";
    char *args = (char *)(regs->regs[1]);
    fprintf(stderr, "%p --> %s", args, read_param);
    if (ptrace(PTRACE_POKEDATA, pid, 0, &regs) == -1)
        FATAL("%s", strerror(errno));
}

/* @param: syscall num & arguments */
void pre_syscall(long syscall, long long args[], struct user_regs_struct *regs, pid_t pid)
{
    syscall_entry_t ent = syscalls[syscall];

    /* current, we want to print the syscall params */
    //fprintf(stderr, "[%3ld]\n", syscall);
    if (ent.name != 0) {
	int nargs = ent.nargs;
	int i;
	fprintf(stderr, "[%3ld] %s (", syscall, ent.name);
	if (nargs != 0)
	    fprintf(stderr, "%s: 0x%llx", ent.sc_arg.arg[0], args[0]);
	for (i = 1; i < nargs; i++) {
	    fprintf(stderr, ", %s: 0x%llx", ent.sc_arg.arg[i], args[i]);
	}
	fprintf(stderr, ")");
	// if the syscall is read, we modify the input
	if (syscall == 63) {
	    sync_syscall(syscall, regs, pid);
	}
    }
}

/* @param: syscall num & return value */
void post_syscall(long syscall, long result)
{
    syscall_entry_t ent = syscalls[syscall];

    if (ent.name != 0) {
        /* Print system call result */
        fprintf(stderr, " = 0x%lx\n", result);
    }
}

#ifdef __x86_64__
static inline int x86_get_sc_args(struct user_regs_struct regs,
				  long long args[])
{
    args[0] = regs.rdi;  args[1] = regs.rsi;  args[2] = regs.rdx;
    args[3] = regs.r10;  args[4] = regs.r8;   args[5] = regs.r9;
    return regs.orig_rax;
}
#endif

#ifdef __aarch64__
//static inline int arm64_get_sc_args(struct user_pt_regs regs,
static inline int arm64_get_sc_args(struct user_regs_struct regs,
				    long long args[])
{
    args[0] = regs.regs[0];  args[1] = regs.regs[1];  args[2] = regs.regs[2];
    args[3] = regs.regs[3];  args[4] = regs.regs[4];  args[5] = regs.regs[5];
    return regs.regs[8];
}
#endif

int main(int argc, char **argv)
{
    if (argc <= 1)
        FATAL("too few arguments: %d", argc);

#if 0
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
            FATAL("%s. pid -1", strerror(errno));
        case 0:  /* child */
            fprintf(stderr, "pid: %d\n", pid);
            ptrace(PTRACE_TRACEME, 0, 0, 0);
            execvp(argv[1], argv + 1);
            FATAL("%s. child", strerror(errno));
    }

    /* parent */
    waitpid(pid, 0, 0); // sync with PTRACE_TRACEME
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

    //fprintf(stderr, "pid: %d. getpid: %d\n", pid, getpid());
    for (;;) {
        /* Enter next system call */
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            FATAL("ptrace_syscall error %s.", strerror(errno));
        if (waitpid(pid, 0, 0) == -1)
            FATAL("waitpid error %s.", strerror(errno));

        /* Get system call arguments */
        struct user_regs_struct regs;
        long syscall_num;
        long long args[6];

#ifdef __x86_64__
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
            FATAL("%s", strerror(errno));
        syscall_num = x86_get_sc_args(regs, args);
#endif
#ifdef __aarch64__
	struct iovec iov;
	//struct user_pt_regs arm64_regs;
	iov.iov_base = &regs;
	iov.iov_len = sizeof(regs);
        //if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1)
        if (ptrace(PTRACE_PEEKUSER, pid, 8, 0) == -1)
            FATAL("ptrace_getregset error %s.", strerror(errno));
        syscall_num = arm64_get_sc_args(regs, args);
#endif
	pre_syscall(syscall_num, args, &regs, pid);


        /* Run system call and stop on exit */
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            FATAL("ptrace_syscall error (retval) %s", strerror(errno));
        if (waitpid(pid, 0, 0) == -1)
            FATAL("waitpid error (retval) %s", strerror(errno));


        /* Get system call result, and print it */
#ifdef __x86_64__
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
            fputs(" = ?\n", stderr);
            if (errno == ESRCH)
                exit(regs.rdi); // system call was _exit(2) or similar
            FATAL("%s", strerror(errno));
        }

	post_syscall(syscall_num, regs.rax);
#endif
#ifdef __aarch64__
        if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
            fputs(" = ?\n", stderr);
            if (errno == ESRCH)
                exit(regs.regs[0]); // system call was _exit(2) or similar
            FATAL("%s. 3", strerror(errno));
	}
	post_syscall(syscall_num, regs.regs[8]);
#endif
    }
}
