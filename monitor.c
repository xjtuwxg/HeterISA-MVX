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

/* MVX: Sync the syscall (e.g., SYS_read) params for inputs.
 * MVX slave node */
void wait_master_syncpoint(pid_t pid, long syscall_num, long long args[])
{
	int val;
	switch (syscall_num) {
	case SYS_read:	// Wait and get stdin from master variant.
		if (args[0] == 5) {
		//if (args[0] == 0) {
			sem_getvalue(&msg.lock, &val);
			PRINT("before sem_wait. %d\n", val);
			sem_wait(&msg.lock);
			sem_getvalue(&msg.lock, &val);
			PRINT("after sem_wait. %d\n", val);
			PRINT("pid %d, args[1] 0x%llx, buf: %s, len: %lu\n",
			      pid, args[1], msg.buf, msg.len);
			update_child_data(pid, args[1], msg.buf, msg.len);
			syscall_getpid(pid);
		}
		break;
	}
}

/**
 * Inline funtion to handle SYS_read on master node.
 * */
static inline void master_sys_read(pid_t pid, int fd, long long args[],
		      long long retval)
{
	int child_fd = args[0];
	long long child_buf = args[1];
	size_t child_cnt = args[2];
	char *monitor_buf = NULL;

	assert(child_cnt > 0);
	monitor_buf = malloc(child_cnt+8);
	if (child_fd == 7) {
	//if (child_fd == 0) {
		get_child_data(pid, monitor_buf, child_buf, child_cnt);
		PRINT("%s. cnt %lld. child_cnt %lu\n", monitor_buf, retval,
		      child_cnt);
		write(fd, monitor_buf, retval);
	}
	free(monitor_buf);
}

/**
 * The synchronization function on master node, executing syscall and forward
 * the result to slaves.
 * */
void master_syncpoint(pid_t pid, int fd, long syscall_num, long long args[],
		      long long retval)
{
	switch (syscall_num) {
	case SYS_read:	// Sync the input to slave variant.
		master_sys_read(pid, fd, args, retval);
		break;
	}

}
