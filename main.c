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

#include "msg_socket.h"
#include "debug.h"		// FATAL & PRINT
#include "ptrace.h"
#include "monitor.h"

#if 0
#define PTR	0
#define INT	1
#define UINT	2
#endif

#define IP_CLIENT	"10.4.4.16"

int main(int argc, char **argv)
{
	int clientfd;

	if (argc <= 1)
	    FATAL("too few arguments: %d", argc);

	pid_t pid = fork();
	switch (pid) {
	    case -1: /* error */
		FATAL("%s. pid -1", strerror(errno));
	    case 0:  /* child */
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		execvp(argv[1], argv + 1);
		FATAL("%s. child", strerror(errno));
	}

	/* parent */
	//sockfd = create_server_socket();
	msg_thread_init();
	clientfd = create_client_socket(IP_CLIENT);

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
			break;
		}

		//pre_syscall(syscall_num, args);

#ifdef __x86_64__
		/* Slave variant has to wait the master variant' input */
		wait_master_syncpoint(pid, syscall_num, args);
#endif
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

		//post_syscall(syscall_num, syscall_retval);
#ifdef __aarch64__
		/* Master gets the user input, and syncs the value to slave
		 * variant. */
		master_syncpoint(pid, clientfd, syscall_num, args,
				 syscall_retval);
#endif
	}
	PRINT("Finish main loop!\n");
}
