#define _POSIX_C_SOURCE 200112L

/* C standard library */
#include <errno.h>
#include <stdio.h>	// pid_t
#include <stddef.h>
#include <stdlib.h>	// EXIT_FAILURE
#include <string.h>

/* POSIX */
#include <unistd.h>
#include <sys/user.h>	// struct user_regs_struct
#include <sys/wait.h>

/* Linux */
#include <syscall.h>
#include <sys/ptrace.h>

#include <linux/ptrace.h>

#ifdef __x86_64__
#include <sys/reg.h>	// ORIG_RAX
#endif

#include "msg_socket.h"
#include "debug.h"	// FATAL & PRINT
#include "ptrace.h"

#define PTR	0
#define INT	1
#define UINT	2

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
		//PRINT("pid: %d\n", pid);
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		execvp(argv[1], argv + 1);
		FATAL("%s. child", strerror(errno));
	}

	/* parent */
	sockfd = create_server_socket();

	waitpid(pid, 0, 0); // sync with PTRACE_TRACEME
	ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

	int terminate = 0;
	while (!terminate) {
		/* Enter next system call */
		if (ptrace_syscall(pid) < 0)
		    FATAL("PTRACE_SYSCALL error: %s,", strerror(errno));

		/* Get system call arguments */
		struct user_regs_struct regs;
		long long args[6];
		long syscall_num;
		long long syscall_retval;

		syscall_num = get_regs_args(pid, &regs, args);
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
		if (ptrace_syscall(pid) < 0)
			FATAL("PTRACE_SYSCALL error: %s,", strerror(errno));

		/* Get system call result, and print it */
		syscall_retval = get_retval(pid, &regs, &terminate);
		if (terminate) break;

		post_syscall(syscall_num, syscall_retval);
    }
}
