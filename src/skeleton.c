#define _POSIX_C_SOURCE 200112L

/* C standard library */
#include <errno.h>		// errno
#include <stdio.h>		// pid_t
#include <stddef.h>
#include <stdlib.h>		// EXIT_FAILURE
#include <string.h>

/* POSIX */
#include <unistd.h>
#include <sys/user.h>		// struct user_regs_struct
#include <sys/wait.h>

/* Linux */
#include <syscall.h>
#include <sys/ptrace.h>

#include <linux/ptrace.h>

#ifdef __x86_64__
#include <sys/reg.h>		// ORIG_RAX
#endif

#include "debug.h"		// FATAL & PRINT
#include "ptrace.h"
#include "monitor.h"

/**
 * Main function for multi-ISA MVX
 * Use: ./mvx_monitor <executable> <args>
 * */
int main(int argc, char **argv)
{
	int clientfd;

	if (argc <= 1)
	    FATAL("too few arguments: %d", argc);

	pid_t pid = fork();
	switch (pid) {
	    case -1: /* error */
		FATAL("%s. pid -1", strerror(errno));
	    case 0:  /* child, executing the tracee */
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		execvp(argv[1], argv + 1);
		FATAL("%s. child", strerror(errno));
	}

	/* parent, also the monitor (tracer) */

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
		if (syscall_num == -1) {
			PRINT("syscall #%ld, terminate\n",
			      syscall_num);
			PRINT("regs rax 0x%llx 0x%llx\n", regs.orig_rax, regs.rax);;
			//PRINT("0x%lx 0x%lx 0x%lx");
			break;
		}

		PRINT("[before syscall] [ip] 0x%llx\n", regs.rip);
		pre_syscall(syscall_num, args);

		/* Run system call and stop on exit */
		if (ptrace_syscall(pid) < 0)
			FATAL("PTRACE_SYSCALL error: %s,", strerror(errno));

		/* Get system call result, and print it */
		syscall_retval = get_retval(pid, &regs, &terminate);
		if (terminate) {
			PRINT("syscall #%ld, ret %lld. terminate\n",
			      syscall_num, syscall_retval);
			break;
		}

		post_syscall(syscall_num, syscall_retval);
		RAW_PRINT("\n");
	}
	PRINT("Finish main loop!\n");
}
