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
void follower_wait_pre_syscall(pid_t pid, long syscall_num, long long args[])
{
	int val;
	switch (syscall_num) {
	case SYS_read:	// Wait and get stdin from master variant.
		if (args[0] == 5) {
		//if (args[0] == 0) {
			sem_getvalue(&msg.lock, &val);
			PRINT("sys_read before sem_wait. %d\n", val);
			sem_wait(&msg.lock);
			sem_getvalue(&msg.lock, &val);
			PRINT("after sem_wait. %d\n", val);
			PRINT("pid %d, args[1] 0x%llx, buf: %s, len: %lu\n",
			      pid, args[1], msg.buf, msg.len);
			update_child_data(pid, args[1], msg.buf, msg.len);
			syscall_getpid(pid);
		}
		break;
	case SYS_epoll_pwait:
#if __x86_64__
		{
			msg_epoll_t epmsg;
			struct epoll_event events[16];

			sem_getvalue(&msg.lock, &val);
			PRINT("sys_epoll_wait before sem_wait. %d\n", val);
			sem_wait(&msg.lock);
			sem_getvalue(&msg.lock, &val);
			PRINT("after sem_wait. %d\n", val);
			PRINT("pid %d, args[1] 0x%llx, buf: %s, len: %lu\n",
			      pid, args[1], msg.buf, msg.len);
			//memcpy(&epmsg, msg.buf, msg.len);
			memcpy(events, msg.buf, msg.len);
			//PRINT("epfd: %d, e #: %d, to: %d\n",
			//      epmsg.epfd, epmsg.event_num,
			//      epmsg.timeout);
			/* updating the epoll_pwait syscall parameters */
			//ptrace(PTRACE_POKEUSER, pid, 8*RDI, epmsg.epfd);
			//ptrace(PTRACE_POKEUSER, pid, 8*RDX, 64);
			//ptrace(PTRACE_POKEUSER, pid, 8*R10, epmsg.timeout);
			update_child_data(pid, args[1], (char*)events,
				msg.len);
			//update_child_data(pid, args[1], (char*)(epmsg.events),
			//	epmsg.event_num * sizeof(struct epoll_event));
			syscall_getpid(pid);
		}
#endif
		break;
	}
}

void follower_wait_post_syscall(pid_t pid, long syscall_num)
{
	int val;
	long long master_retval;
	switch (syscall_num) {
	case SYS_accept:
#if __x86_64__
		sem_wait(&msg.lock);
		sscanf(msg.buf, "%llx", &master_retval);
		PRINT("%s: msg.buf: 0x%s, msg.len: %d. master_retval %lld\n",
		      __func__, msg.buf, msg.len, master_retval);
		ptrace(PTRACE_POKEUSER, pid, 8*RAX, master_retval);
#endif
		break;
	}
}

/**
 * Inline funtion to handle SYS_read on master node.
 *    ssize_t read(int fd, void *buf, size_t count)
 * */
static inline void master_sys_read(pid_t pid, int fd, long long args[],
		      long long retval)
{
	int child_fd = args[0];
	long long child_buf = args[1];
	size_t child_cnt = args[2];
	//size_t child_cnt = retval;
	char *monitor_buf = NULL;
	int ret = 0;

	assert(child_cnt > 0);
	monitor_buf = malloc(child_cnt+8);
	if (child_fd == 5) {
	//if (child_fd == 0) {
		get_child_data(pid, monitor_buf, child_buf, child_cnt);
		PRINT("%s. cnt %lld. child_cnt %lu\n", monitor_buf, retval,
		      child_cnt);
		ret = write(fd, monitor_buf, retval);
		PRINT("!!!! write ret: %d. retval: %lld. errno %d\n",
		      ret, retval, errno);
	}
	free(monitor_buf);
}

/**
 * Inline function for SYS_epoll_pwait on master node.
 *    int epoll_pwait(int epfd, struct epoll_event *events,
 *			int maxevents, int timeout,
 *                      const sigset_t *sigmask);
 * */
static inline void master_sys_epoll_pwait(pid_t pid, int fd, long long args[],
		      long long retval)
{
	msg_epoll_t epoll_msg;		// contains arch specific code for universal epoll_event.
	struct epoll_event *events;	// 12 bytes on x86, 16 bytes on arm
	struct epoll_event_x86 *x86_events;
	size_t events_len, x86_epoll_len;
	int ret = 0, i;

	epoll_msg.epfd = args[0];
	epoll_msg.event_num = retval;
	epoll_msg.maxevents = args[2];
	epoll_msg.timeout = args[3];
	events_len = sizeof(struct epoll_event) * retval;
	x86_epoll_len = sizeof(struct epoll_event_x86) * retval;
	events = malloc(events_len);
	x86_events = malloc(events_len);


	//get_child_data(pid, (char*)(epoll_msg.events), args[1], events_len);
	// Get the child epoll_event data on arm.
	get_child_data(pid, (char*)events, args[1], events_len);
	PRINT("epoll_pwait: %lld, 0x%llx, %lld, %lld, %lld, %lld | %lld\n",
	      args[0], args[1], args[2], args[3], args[4], args[5], retval);
	PRINT("epoll: events 0x%x, data u64 0x%lx\n",
	      epoll_msg.events[0].events, epoll_msg.events[0].data.u64);
	// Convert epoll_data to x86 format.
	for (i = 0; i < retval; i++) {
		x86_events[i].events = events[i].events;
		x86_events[i].data = events[i].data;
	}
	//ret = write(fd, (void*)&epoll_msg, sizeof(int)*4+events_len);
	ret = write(fd, (void*)x86_events, x86_epoll_len);
	PRINT("!!!! epoll_pwait write ret: %d. errno %d\n",
	      ret, errno);
	free(events);
	free(x86_events);
}

static inline void master_sys_accept(pid_t pid, int fd, long long args[],
		      long long retval)
{
	int ret = 0;
	char buf[8];
	sprintf(buf, "%llx", retval);
	ret = write(fd, buf, 8);
	PRINT("%s: buf %s, ret %d.\n", __func__, buf, ret);
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
	case SYS_epoll_pwait:
		master_sys_epoll_pwait(pid, fd, args, retval);
		break;
	case SYS_accept:
		master_sys_accept(pid, fd, args, retval);
		break;
	}

}
