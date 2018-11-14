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

#ifdef __x86_64__
#include <sys/reg.h>	// ORIG_RAX
#endif

#include "msg_socket.h"

//#define _DEBUG
#ifdef _DEBUG
#define FATAL(...) \
    do { \
        fprintf(stderr, "[mvx error]: " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)

#define PRINT(...) \
    do { \
	fprintf(stdout, "[mvx]: " __VA_ARGS__); \
	fflush(stdout); \
    } while (0);
#else
#define FATAL(...) \
    do {} while(0);
#define PRINT(...) \
    do {} while(0);
#endif

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

union u {
    long val;
    char str[8];
} input;

void sync_syscall(long syscall, struct user_regs_struct *regs, pid_t pid)
{
    //char read_param[20] = "Hello World!";
    unsigned long mem_loc, reg_loc = 0;
    long ret;
#ifdef __x86_64__
    mem_loc = regs->rsi;
    reg_loc = 8*ORIG_RAX;
#endif
#ifdef __aarch64__
    mem_loc = regs->regs[1];
#endif
    //fprintf(stderr, "[%3ld] %p --> %s\n", syscall, args, read_param);
    //input.val = ptrace(PTRACE_PEEKDATA, pid, regs->rsi, 0);
    //PRINT("%s\n", input.str);
    //PRINT("0x%lx", input.val);
    /* Inject input string. */
    memcpy(input.str, "hello", sizeof("hello"));
    ret = ptrace(PTRACE_POKEDATA, pid, mem_loc, input.val);
    PRINT("ret: %ld\n", ret);
    //ret = ptrace(PTRACE_PEEKTEXT, pid, regs->pc, 0);
    //PRINT("ret: 0x%lx\n", ret);
    /* Inject getpid syscall */
    ret = ptrace(PTRACE_POKEUSER, pid, reg_loc, SYS_getpid);
    PRINT("ret: %ld\n", ret);
}

/* @param: syscall num & arguments */
void pre_syscall(long syscall, long long args[], struct user_regs_struct *regs,
		 pid_t pid)
{
    syscall_entry_t ent = syscalls[syscall];

    /* current, we want to print the syscall params */
    //fprintf(stderr, "[%3ld]\n", syscall);
    if (ent.name != 0) {
	int nargs = ent.nargs;
	int i;
	PRINT("[%3ld] %s (", syscall, ent.name);
	if (nargs != 0)
	    PRINT("%s: 0x%llx", ent.sc_arg.arg[0], args[0]);
	for (i = 1; i < nargs; i++) {
	    PRINT(", %s: 0x%llx", ent.sc_arg.arg[i], args[i]);
	}
	PRINT(")\n");
	// if the syscall is read, we modify the input
    }
}

/* @param: syscall num & return value */
void post_syscall(long syscall, long result)
{
    syscall_entry_t ent = syscalls[syscall];

    if (ent.name != 0 && 0) {
        /* Print system call result */
        PRINT(" = 0x%lx\n", result);
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

static int sockfd, clientfd;

int main(int argc, char **argv)
{
    int connfd;
    SA in_addr;
    socklen_t in_len = sizeof(in_addr);

    if (argc <= 1)
        FATAL("too few arguments: %d", argc);

    pid_t pid = fork();
    switch (pid) {
        case -1: /* error */
            FATAL("%s. pid -1", strerror(errno));
        case 0:  /* child */
            PRINT("pid: %d\n", pid);
            ptrace(PTRACE_TRACEME, 0, 0, 0);
            execvp(argv[1], argv + 1);
            FATAL("%s. child", strerror(errno));
    }

    /* parent */
    sockfd = create_server_socket();

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
            FATAL("ptrace_getregs %s", strerror(errno));
        syscall_num = x86_get_sc_args(regs, args);
#endif
#ifdef __aarch64__
	struct iovec iov;
	iov.iov_base = &regs;
	iov.iov_len = sizeof(regs);
        if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1)
            FATAL("ptrace_getregset error %s.", strerror(errno));
        syscall_num = arm64_get_sc_args(regs, args);
#endif
	if (syscall_num == -1) break;
	pre_syscall(syscall_num, args, &regs, pid);

#ifdef __x86_64__
	/* MVX: Sync the syscall (e.g., SYS_read) params for inputs.
	 * MVX slave node */
	if ((syscall_num == SYS_read) && (args[0] == 0)) {
            long ret;
	    char buf[128];
            if (listen(sockfd, SOMAXCONN) < 0)
		FATAL("listen error");
	    PRINT("sockfd: %d\n", sockfd);
	    if ((connfd = accept(sockfd, &in_addr, &in_len)) == -1) {
		PRINT("error connfd: %d. err: %d\n", connfd, errno);
	    }
	    PRINT("connfd: %d\n", connfd);

	    memset(&input, 0, sizeof(input));
	    if (read(connfd, input.str, 8) == -1)
	        PRINT("read error\n");
	    PRINT("input: 0x%lx, %s\n", input.val, input.str);
            //PRINT("input: 0x%lx, %s\n", input.val, input.str);
            ret = ptrace(PTRACE_POKEDATA, pid, args[1], input.val);
            PRINT("ret: %ld\n", ret);
            ret = ptrace(PTRACE_POKEUSER, pid, 8*ORIG_RAX, SYS_getpid);
            PRINT("ret: %ld\n", ret);
	    //sync_syscall(syscall_num, &regs, pid);
	}
#endif
#ifdef __aarch64__
#endif


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
	if ((syscall_num == SYS_read) && (args[0] == 0)) {
	    /* MVX: Send the syscall (e.g., SYS_read) params to slaves.
	     * MVX master node */
	    memset(&input, 0, sizeof(input));
            input.val = ptrace(PTRACE_PEEKDATA, pid, args[1], 0);
            PRINT("input: 0x%lx. %s\n", input.val, input.str);
	    clientfd = create_client_socket("10.4.4.16");
	    if (write(clientfd, input.str, sizeof(input.str)) == -1)
		PRINT("write error\n");
	}
#endif
    }
}
