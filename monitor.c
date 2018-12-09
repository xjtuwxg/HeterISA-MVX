#include "monitor.h"
#include "debug.h"
#include "msg_socket.h"
#include "ptrace.h"

/* @param: syscall num & arguments */
void pre_syscall(long syscall, long long args[])
{
    syscall_entry_t ent = syscalls[syscall];

    /* current, we want to print the syscall params */
    fprintf(stderr, "[%3ld] %s\n", syscall, syscall_name[syscall]);
#if 1
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
#endif
}

/* @param: syscall num & return value */
void post_syscall(long syscall, long result)
{
    syscall_entry_t ent = syscalls[syscall];

    PRINT(" = 0x%lx\n", result);
#if 0
    if (ent.name != 0) {
        /* Print system call result */
        PRINT(" = 0x%lx\n", result);
    }
#endif
}

/* MVX: Sync the syscall (e.g., SYS_read) params for inputs.
 * MVX slave node */
void follower_wait_pre_syscall(pid_t pid, long syscall_num, long long args[])
{
	int val;
	msg_t rmsg;
	switch (syscall_num) {
	case SYS_read:	// Wait read buffer sent from master variant.
		//if (args[0] == 0) {
		{
			// Wait for the non-empty ringbuf.
			msg_t *tmsg = NULL;
			sem_wait(&ringbuf->sem);
			tmsg = ringbuf_gettop(ringbuf);
			if (tmsg) {
				PRINT("syscall %d, len %u\n", tmsg->syscall, tmsg->len);
			}
			else {
				PRINT("top empty, should not be here.\n");
				break;
			}

			// If it's a normal read syscall, use the top msg_t and
			// delete it in post syscall handler.
			if (tmsg->retval >= 0) {
				update_child_data(pid, args[1], tmsg->buf,
						  tmsg->len);
			}

			// If read returns negative number, nothing to handle
			// here, just jmp to the post syscall handler.
			syscall_getpid(pid);
		}
		break;
	case SYS_epoll_pwait:
#if __x86_64__
		{
			struct epoll_event events[16];

			sem_getvalue(&ringbuf->sem, &val);
			PRINT(">>>>> sys_epoll_wait before sem_wait. %d\n", val);
			sem_wait(&ringbuf->sem);
			sem_getvalue(&ringbuf->sem, &val);
			PRINT("after sem_wait. %d\n", val);

			ringbuf_pop(ringbuf, &rmsg);
			PRINT("pid %d, args[1] 0x%llx, buf: %s, len: %u, syscall %d\n",
			      pid, args[1], rmsg.buf, rmsg.len, rmsg.syscall);
			memcpy(events, rmsg.buf, rmsg.len);
			update_child_data(pid, args[1], (char*)events,
				rmsg.len);
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
	msg_t rmsg;

	switch (syscall_num) {
	/* The following syscalls are only handled here for the retval. */
	case SYS_accept:
	case SYS_fcntl:
	case SYS_epoll_ctl:
#if __x86_64__
		sem_getvalue(&ringbuf->sem, &val);
		PRINT(">>>>> follower is handling [%3ld] before sem_wait. %d\n",
		      syscall_num, val);
		sem_wait(&ringbuf->sem);
		sem_getvalue(&ringbuf->sem, &val);
		PRINT("after sem_wait. %d\n", val);

		ringbuf_pop(ringbuf, &rmsg);
		sscanf(rmsg.buf, "%llx", &master_retval);
		PRINT("%s: msg.buf: 0x%s, msg.len: %u. master_retval %lld\n",
		      __func__, rmsg.buf, rmsg.len, master_retval);
		ptrace(PTRACE_POKEUSER, pid, 8*RAX, master_retval);
#endif
		break;
	/* The following syscalls were handled before for the params, and they
	 * are handled again here for the retval. */
	case SYS_read:
		PRINT("Update retval of syscall %d\n", syscall_num);
		ringbuf_pop(ringbuf, &rmsg);
		master_retval = rmsg.retval;
		ptrace(PTRACE_POKEUSER, pid, 8*RAX, master_retval);
		break;
	}
}


/* ===== Those master syscall handlers only care about the params. ===== */
/**
 * Inline funtion to handle SYS_read on master node.
 *    ssize_t read(int fd, void *buf, size_t count)
 *    "retval" is actually the length of the string write to buffer.
 * */
static inline void master_sys_read(pid_t pid, int fd, long long args[],
		      long long retval)
{
	int child_fd = args[0];
	long long child_buf = args[1];
	size_t child_cnt = args[2];
	char *monitor_buf = NULL;
	int ret = 0;
	msg_t rmsg;
	char buf[20];

	assert(child_cnt > 0);
	monitor_buf = malloc(child_cnt+8);
	if (child_fd == 0) {
		get_child_data(pid, monitor_buf, child_buf, child_cnt);
		PRINT("%s: child actual read %lld bytes, child cnt %lu\n",
		      __func__, retval, child_cnt);

		msg.syscall = 0;	// SYS_read x86
		if (retval > 0) {	// read something correct
			msg.len = retval;
			msg.retval = retval;
			memcpy(msg.buf, monitor_buf, retval);
			ret = write(fd, (void*)&msg, retval+16);
			PRINT("write ret: %d. retval: %lld. errno %d\n",
				ret, retval, errno);
		} else {		// read unsuccessful, ret negative
			msg.len = 0;
			msg.retval = retval;
			ret = write(fd, (void*)&msg, 16);
			PRINT("write ret: %d. retval: %lld. msg len 16\n",
				ret, retval);
		}
	}
	free(monitor_buf);
}

/**
 * Inline function for SYS_epoll_pwait on master node.
 *    int epoll_pwait(int epfd, struct epoll_event *events,
 *			int maxevents, int timeout,
 *                      const sigset_t *sigmask);
 * Cares only about the 2nd parameter (args[1]).
 * The retval is the number of epoll_event
 * */
static inline void master_sys_epoll_pwait(pid_t pid, int fd, long long args[],
		      long long retval)
{
	struct epoll_event *events;	// 12 bytes on x86, 16 bytes on arm
	struct epoll_event_x86 *x86_events;
	size_t events_len, x86_epoll_len;
	int ret = 0, i;

	PRINT("epoll_pwait: %lld, 0x%llx, %lld, %lld, %lld, %lld | %lld\n",
	      args[0], args[1], args[2], args[3], args[4], args[5], retval);

	events_len = sizeof(struct epoll_event) * retval;
	x86_epoll_len = sizeof(struct epoll_event_x86) * retval;
	events = malloc(events_len);
	x86_events = malloc(events_len);

	// Get the child epoll_event data on arm.
	get_child_data(pid, (char*)events, args[1], events_len);
	// Convert epoll events to x86 data format.
	for (i = 0; i < retval; i++) {
		x86_events[i].events = events[i].events;
		x86_events[i].data = events[i].data;
	}

	// Send epoll_event through msg_t variable
	msg.syscall = 281;	// SYS_epoll_pwait x86
	msg.len = x86_epoll_len;
	msg.retval = retval;
	memcpy(msg.buf, x86_events, x86_epoll_len);
	ret = write(fd, (void*)&msg, x86_epoll_len+16);
	//fsync(fd);
	PRINT("epoll_pwait write ret: %d. errno %d. len %lu, %lu\n",
	      ret, errno, x86_epoll_len, events_len);
	free(events);
	free(x86_events);
}

/* ===== Those master syscall handlers only care about the retval. ===== */
/**
 * Inline funtion to handle ret only syscalls on master node.
 * */
static inline void master_syscall_return(int fd, long syscall, long long retval)
{
	int ret = 0;
	char buf[20];
	PRINT("** master syscall [%3ld], retval: 0x%llx\n", syscall, retval);

	/* Convert retval of 'long long' into 'char[]', prepare the msg_t and
	 * send it */
	sprintf(buf, "%llx", retval);
	msg.syscall = syscall;	// syscall number on x86 platform
	msg.len = strlen(buf);
	memcpy(msg.buf, buf, msg.len);
	ret = write(fd, &msg, msg.len+16);
	fsync(fd);

	PRINT("** %s: buf %s, write %d bytes. len %lu.\n",
	      __func__, buf, ret, strlen(buf));
}

/**
 * The synchronization function on master node, executing syscall and forward
 * the result to slaves.
 * Data will be sent with a msg_t data structure (containing syscall,len,buf)
 * */
static int cnt = 0;
void master_syncpoint(pid_t pid, int fd, long syscall_num, long long args[],
		      long long retval)
{
	switch (syscall_num) {
	case SYS_read:	// Sync the input to slave variant.
		master_sys_read(pid, fd, args, retval);
		PRINT("master cnt: %d >>>>>\n", ++cnt);
		break;
	case SYS_epoll_pwait:
		master_sys_epoll_pwait(pid, fd, args, retval);
		PRINT("master cnt: %d >>>>>\n", ++cnt);
		break;
	/* The following syscalls only have to send the retval. */
	case SYS_accept:
	case SYS_fcntl:
	case SYS_epoll_ctl:
		master_syscall_return(fd, syscall_num, retval);
		PRINT("master cnt: %d >>>>>\n", ++cnt);
		break;
	}

}
