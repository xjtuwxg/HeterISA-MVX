#include "monitor.h"
#include "debug.h"
#include "msg_socket.h"
#include "ptrace.h"

/* @param: syscall num & arguments */
void pre_syscall(long syscall, long long args[])
{
    syscall_entry_t ent = syscalls[syscall];

    /* current, we want to print the syscall params */
    //fprintf(stderr, "[%3ld]\n", syscall);
    if (ent.name != 0) {
	int nargs = ent.nargs;
	int i;
	PRINT("[%3ld] %s (", syscall, ent.name);
	if (nargs != 0)
	    RAW_PRINT("%s: 0x%llx", ent.sc_arg.arg[0], args[0]);
	for (i = 1; i < nargs; i++) {
	    RAW_PRINT(", %s: 0x%llx", ent.sc_arg.arg[i], args[i]);
	}
	RAW_PRINT(")\n");
	// if the syscall is read, we modify the input
    }
}

/* @param: syscall num & return value */
void post_syscall(long syscall, long result)
{
    syscall_entry_t ent = syscalls[syscall];

    if (ent.name != 0) {
        /* Print system call result */
        PRINT(" = 0x%lx\n", result);
    }
}

#if 0
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
#endif

/* MVX: Sync the syscall (e.g., SYS_read) params for inputs.
 * MVX slave node */
void wait_master_syncpoint(pid_t pid, long syscall_num, long long args[])
{
	int val;
	switch (syscall_num) {
	case SYS_read:	// Wait and get stdin from master variant.
		if (args[0] == 0) {
			sem_getvalue(&msg.lock, &val);
			PRINT("before sem_wait. %d\n", val);
			sem_wait(&msg.lock);
			sem_getvalue(&msg.lock, &val);
			PRINT("after sem_wait. %d\n", val);
			PRINT("pid %u, args[1] 0x%llx, buf: %s, len: %u\n",
			      pid, args[1], msg.buf, msg.len);
			update_child_data(pid, args[1], msg.buf, msg.len);
			syscall_getpid(pid);
		}
		break;
	}
#if 0
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
#ifdef __x86_64__
		ret = ptrace(PTRACE_POKEDATA, pid, args[1], input.val);
		PRINT("ret: %ld\n", ret);
		ret = ptrace(PTRACE_POKEUSER, pid, 8*ORIG_RAX, SYS_getpid);
		PRINT("ret: %ld\n", ret);
#endif
		//sync_syscall(syscall_num, &regs, pid);
	}
#endif
}

void master_syncpoint(pid_t pid, long syscall_num, long long args[],
		      long long retval, int fd)
{
	char buf[1024];
	switch (syscall_num) {
	case SYS_read:	// Sync the input to slave variant.
		if (args[0] == 0) {	// arg[1]: buf, arg[2]: count
			get_child_data(pid, buf, args[1], args[2]);
			PRINT("%s. cnt %lld\n", buf, retval);
			write(fd, buf, retval);
		}
		break;
	}

}
