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

#define IP_CLIENT	"10.4.4.16"

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

	initVDT();
	PRINT("vdt 1 real %d, vdt 2 real %d\n", fd_vtab[1].real,
	      fd_vtab[2].real);

	/* parent, also the monitor (tracer) */
	/* Initiate the message thread (both server and client). */
	msg_thread_init();
	clientfd = create_client_socket(IP_CLIENT);

	waitpid(pid, 0, 0); // sync with PTRACE_TRACEME
	ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

	int terminate = 0;
	int skip_post_handling = 0;
	int status = 0;
	while (!terminate) {
		/* Enter next system call (before entering) */
		status = 0;
		skip_post_handling = 0;
		if (ptrace_syscall_status(pid, &status) < 0)
			FATAL("PTRACE_SYSCALL error 1: %s.", strerror(errno));
		if (WSTOPSIG(status) != SIGTRAP) {
			PRINT("Not a sigtrap (%d). See \"man 7 signal\".\n",
			      WSTOPSIG(status));
			break;
		}

		/* (1) The following code handles syscall params, before tracee
		 *     entering the kernel. */
		struct user_regs_struct regs;
		int64_t args[6];
		int64_t syscall_retval;
		uint64_t syscall_num;

		/* Get system call arguments */
		syscall_num = get_regs_args(pid, &regs, args);
		pre_syscall(syscall_num, args);
		PRINT("0) vdt 1 real %d, vdt 2 real %d. 0x%p\n",
		      fd_vtab[1].real, fd_vtab[2].real, fd_vtab);
#ifdef __x86_64__
		/* Follower wants to wait the leader's "input" */
		follower_wait_pre_syscall(pid, syscall_num, args,
					  &skip_post_handling);
#endif
		/* Run system call and stop on exit (after syscall return) */
		if (ptrace_syscall(pid) < 0)
			FATAL("PTRACE_SYSCALL error 2: %s.", strerror(errno));

		/* (2) The following code handles syscall retval, after tracee
		 *     leaving the kernel. */
		/* Get system call result, and print it */
		syscall_retval = get_retval(pid, &regs, &terminate);
		if (terminate) {
			PRINT("syscall #%ld, ret %ld. terminate\n",
			      syscall_num, syscall_retval);
			break;
		}
		post_syscall(syscall_num, syscall_retval);
#ifdef __x86_64__
		/* Follower wants to wait leader's "syscall retval" */
		if (skip_post_handling) continue;
		follower_wait_post_syscall(pid, syscall_num, syscall_retval,
					   args);
#endif

#ifdef __aarch64__
		/* Master syncs the "user input" value to follower. */
		master_syncpoint(pid, clientfd, syscall_num, args,
				 syscall_retval);
#endif

		RAW_PRINT("\n");
	}
	PRINT("Finish main loop!\n");
}
