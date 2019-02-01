#include "monitor.h"
#include "debug.h"
#include "msg_socket.h"
#include "ptrace.h"

static int count = 0;
/* @param: syscall num & arguments */
void pre_syscall(long syscall, int64_t args[])
{
    syscall_entry_t ent = syscalls[syscall];

    /* current, we want to print the syscall params */
    fprintf(stderr, "(%3d) [%3ld] %s\n", count++, syscall, syscall_name[syscall]);
#if 1
    if (ent.name != 0) {
	int nargs = ent.nargs;
	int i;
	PRINT("[%3ld] %s (", syscall, ent.name);
	if (nargs != 0)
	    RAW_PRINT("%s: 0x%lx", ent.sc_arg.arg[0], args[0]);
	for (i = 1; i < nargs; i++) {
	    RAW_PRINT(", %s: 0x%lx", ent.sc_arg.arg[i], args[i]);
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

    //PRINT(" = 0x%lx (origin)\n", result);
    fprintf(stderr, " = %ld (0x%lx) (local syscall exec)\n", result, result);
#if 0
    if (ent.name != 0) {
        /* Print system call result */
        PRINT(" = 0x%lx\n", result);
    }
#endif
}

/**
 * The pre syscall handler mainly handles the syscall params.
 * */
void follower_wait_pre_syscall(pid_t pid, long syscall_num, int64_t args[],
			       int *skip_post_handling)
{
	int val;
	msg_t *rmsg = NULL;

	switch (syscall_num) {
	case SYS_read:	// Wait read buffer sent from master variant.
		if (args[0] != 3) {
			// Wait for the non-empty ringbuf.
			rmsg = ringbuf_wait(ringbuf);
			assert(SYS_read == rmsg->syscall);
			// If it's a normal read syscall, use the top msg_t to
			// update the param, and delete it in post syscall handler.
			if (rmsg->retval >= 0) {
				update_child_data(pid, args[1], rmsg->buf,
						  rmsg->len);
			}
			// If read returns negative number, nothing to handle
			// here, just jmp to the post syscall handler.
			syscall_getpid(pid);
		} else {
			*skip_post_handling = 1;
		}
		break;
	case SYS_epoll_pwait:
#if __x86_64__
		{
			struct epoll_event events[16];

			rmsg = ringbuf_wait(ringbuf);
			assert(SYS_epoll_pwait == rmsg->syscall);
			//PRINT("pid %d, args[1] 0x%lx, buf: %s, len: %u, syscall %d\n",
			//      pid, args[1], rmsg.buf, rmsg.len, rmsg.syscall);
			memcpy(events, rmsg->buf, rmsg->len);
			update_child_data(pid, args[1], (char*)events,
				rmsg->len);
			syscall_getpid(pid);
		}
#endif
		break;
	case SYS_getsockopt:
		{
			rmsg = ringbuf_wait(ringbuf);
			assert(SYS_getsockopt == rmsg->syscall);
			//PRINT("pid %d, args[1] 0x%lx, buf: %s, len: %u, syscall %d\n",
			//    pid, args[1], rmsg->buf, rmsg->len, rmsg->syscall);
			update_child_data(pid, args[3], (char*)rmsg->buf,
				rmsg->len);
			syscall_getpid(pid);
		}
		break;
	case SYS_sendfile:
		{
			rmsg = ringbuf_wait(ringbuf);
			assert(SYS_sendfile == rmsg->syscall);
			update_child_data(pid, args[2], (char*)rmsg->buf,
				rmsg->len);
			PRINT("len %u\n", rmsg->len);
			syscall_getpid(pid);
		}
		break;
#if __x86_64__
	case SYS_open:
		{
			rmsg = ringbuf_wait(ringbuf);
			PRINT("syscall %u. tail %lu\n", rmsg->syscall,
			      ringbuf->tail);
			//VFD_PRINT("open fd %ld\n", args[0]);
			assert(SYS_open == rmsg->syscall);
			/* "flag=1": open file in whitelist */
			if (!rmsg->flag) syscall_getpid(pid);
		}
		break;
#endif
	case SYS_close:
		{
			rmsg = ringbuf_wait(ringbuf);
			PRINT("SYS_close %d\n", rmsg->syscall);
			VFD_PRINT("** close fd %ld, syscall %d\n",
				  args[0], rmsg->syscall);
			assert(SYS_close == rmsg->syscall);
		}
		break;
	//case SYS_accept:
	case SYS_accept4:
		{
			rmsg = ringbuf_wait(ringbuf);
			PRINT("SYS_accept4 %d\n", rmsg->syscall);
			VFD_PRINT("** accept4 fd %ld, syscall %d\n",
				  args[0], rmsg->syscall);
			syscall_dup(pid);
			assert(SYS_accept4 == rmsg->syscall);
		}
		break;
	case SYS_writev:
		{
			rmsg = ringbuf_wait(ringbuf);
			VFD_PRINT("** write fd %ld, syscall %d\n",
				  args[0], rmsg->syscall);
			if (!isRealDesc(args[0])) syscall_getpid(pid);
		}
		break;
	}
}

/**
 * The post syscall handler in follower mainly handles the syscall retval.
 * e.g., setup the retval of the simulated syscalls.
 * */
void follower_wait_post_syscall(pid_t pid, long syscall_num,
				int64_t syscall_retval, int64_t args[])
{
	int64_t master_retval;
	msg_t rmsg;

#if __x86_64__
	switch (syscall_num) {
	/* (1) The following syscalls are ONLY handled here for the retval. */
	case SYS_fcntl:
	case SYS_epoll_ctl:
	case SYS_setsockopt:
		PRINT(">>>>> follower is handling [%3ld].\n", syscall_num);
		sem_wait(&ringbuf->sem);
		ringbuf_pop(ringbuf, &rmsg);
		assert(syscall_num == rmsg.syscall);
		master_retval = rmsg.retval;
		update_retval(pid, master_retval);
		//PRINT("%s: msg.buf: 0x%s, msg.len: %u. =master_retval %ld\n",
		//      __func__, rmsg.buf, rmsg.len, master_retval);
		break;
	// write to a local file should not take effect??
//	case SYS_writev:
//		if (args[0] != 5) break;
/*		sem_wait(&ringbuf->sem);
		ringbuf_pop(ringbuf, &rmsg);
		assert(syscall_num == rmsg.syscall);
		master_retval = rmsg.retval;
		update_retval(pid, master_retval);
		PRINT("=%ld\n", master_retval);*/
		break;

	/* This two syscalls are only used to intercept fd operations. */
	case SYS_epoll_create1:
	case SYS_socket:
		VFD_PRINT("socket/epoll_create1 index [%3d]\n",
			  open_close_idx++);
		if (syscall_retval >= 0)
			fd_vtab[vtab_index++].id = syscall_retval;
			fd_vtab[vtab_index++].real = 0;
		break;

	/* (2) Handle separately and fill the fd_vtab. The following syscalls were
	 * handled before. */
	case SYS_open:
		ringbuf_pop(ringbuf, &rmsg);
		VFD_PRINT("open index[%d]\n", open_close_idx++);
		if (rmsg.flag) { // if load local file, update vtab and continue
			fd_vtab[vtab_index++].id = syscall_retval;
			fd_vtab[vtab_index++].real = 1;
			VFD_PRINT("** open fd master %ld. vtab_index %d <--> open fd %ld\n",
				  rmsg.retval, vtab_index-1, syscall_retval);
			break;
		}
		master_retval = rmsg.retval;
		update_retval(pid, master_retval);
		VFD_PRINT("=%ld\n", master_retval);
		break;
	case SYS_close:
		ringbuf_pop(ringbuf, &rmsg);
		master_retval = rmsg.retval;
		VFD_PRINT("** SYS_close, retval %ld, master retval %ld. close fd %d\n",
			  syscall_retval, master_retval, vtab_index-1);
		if (vtab_index > 0) vtab_index--;
		VFD_PRINT("close index [%3d]\n", open_close_idx++);
		update_retval(pid, master_retval);
		VFD_PRINT("=%ld\n", master_retval);
		break;

	/* (2') The following syscalls were handled before the params, and they
	 * are handled again here for the retval. */
	//case SYS_accept:
	case SYS_writev:
	case SYS_accept4:
	case SYS_read:
	case SYS_epoll_pwait:
	case SYS_getsockopt:
	case SYS_sendfile:
		//PRINT("Update retval of syscall %ld\n", syscall_num);
		ringbuf_pop(ringbuf, &rmsg);
		master_retval = rmsg.retval;
		update_retval(pid, master_retval);
		VFD_PRINT("=%ld\n", master_retval);

		if (syscall_num == SYS_accept4) {
			VFD_PRINT("accept4 index[%d]. = %ld\n = %ld (master)\n",
			    open_close_idx++, syscall_retval, master_retval);
			fd_vtab[vtab_index++].id = master_retval;
			fd_vtab[vtab_index++].real = 0;
			VFD_PRINT("vtab idx %d\n", vtab_index-1);
		}
		break;
	}
#endif
}


/* ===== Those master syscall handlers only care about the params. ===== */
/**
 * Inline funtion to handle SYS_read on master node.
 *    ssize_t read(int fd, void *buf, size_t count)
 *    "retval" is the actual length of the string writen to the buffer.
 * */
static inline void master_sys_read(pid_t pid, int fd, int64_t args[],
		      int64_t retval)
{
	int child_fd = args[0];
	int64_t child_buf = args[1];
	size_t child_count = args[2];
	char *monitor_buf = NULL;
	int ret = 0;
	msg_t rmsg;
	char buf[20];

	assert(child_count > 0);
	monitor_buf = malloc(child_count+8);

	if (child_fd != 3) {	// TODO: Selectively fd handling rules.
		// We first want to retrieve child memory with params.
		get_child_data(pid, monitor_buf, child_buf, child_count);
		// We then want to send syscall info to Followers.
		msg.syscall = 0;	// SYS_read x86
		if (retval > 0) {	// read something correct
			msg.len = retval;
			msg.retval = retval;
			memcpy(msg.buf, monitor_buf, retval);
			ret = write(fd, (void*)&msg, retval+16);
		} else {		// read unsuccessful, ret negative
			msg.len = 0;
			msg.retval = retval;
			ret = write(fd, (void*)&msg, 16);
		}
	}
	free(monitor_buf);
	assert(ret != -1);
}

/**
 * Inline function for SYS_epoll_pwait on master node.
 *    int epoll_pwait(int epfd, struct epoll_event *events,
 *			int maxevents, int timeout,
 *                      const sigset_t *sigmask);
 * Cares only about the 2nd parameter (args[1]).
 * The retval is the number of epoll_event
 * */
static inline void master_sys_epoll_pwait(pid_t pid, int fd, int64_t args[],
		      int64_t retval)
{
	struct epoll_event *events;	// 12 bytes on x86, 16 bytes on arm
	struct epoll_event_x86 *x86_events;
	size_t events_len, x86_epoll_len;
	int ret = 0, i;

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
	//PRINT("epoll_pwait write ret: %d. errno %d. len %lu, %lu\n",
	//      ret, errno, x86_epoll_len, events_len);
	free(events);
	free(x86_events);
	assert(ret != -1);
}

/**
 * Inline function for SYS_getsockopt on master node.
 *    int getsockopt(int sockfd, int level, int optname,
 *                     void *optval, socklen_t *optlen);
 * Only cares about the args[3],args[4] and retval.
 * */
static inline void master_sys_getsockopt(pid_t pid, int fd, int64_t args[],
					 int64_t retval)
{
	int ret = 0;
	char *optval;
	unsigned int optlen = 0; //args[4];

	PRINT("getsockopt: %ld, %ld, %ld, 0x%lx, 0x%lx | %ld\n",
	      args[0], args[1], args[2], args[3], args[4], retval);
	get_child_data(pid, (char*)&optlen, args[4], 4);
	optval = malloc(optlen);
	get_child_data(pid, (char*)&optlen, args[3], optlen);
	PRINT("optlen 0x%x, optval %s\n", optlen, optval);
	msg.syscall = 55;	// SYS_getsockopt x86
	msg.len = optlen;
	msg.retval = retval;
	memcpy(msg.buf, optval, optlen);
	ret = write(fd, (void*)&msg, optlen+16);
	free(optval);
	assert(ret != -1);
}

/**
 * Inline hanlder for SYS_sendfile on master. See 'man sendfile'.
 *   ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
 * Cares about the 'offset + retval'
 * */
static inline void master_sys_sendfile(pid_t pid, int fd, int64_t args[],
					 int64_t retval)
{
	int ret = 0;
	off_t offset = 0;
	//size_t len = sizeof(offset);
	PRINT("sendfile: %ld, %ld, 0x%lx, 0x%lx | %ld\n",
	      args[0], args[1], args[2], args[3], retval);
	get_child_data(pid, (char*)&offset, args[2], sizeof(off_t));
	PRINT("off 0x%lx, count %ld. %lu\n", offset, args[3], sizeof(off_t));
	msg.syscall = 40;	// SYS_sendfile x86
	msg.len = sizeof(off_t);
	msg.retval = retval;
	memcpy(msg.buf, (char*)&offset, sizeof(off_t));
	ret = write(fd, (void*)&msg, sizeof(off_t)+16);
	assert(ret != -1);
}

static inline void master_syscall_return(int fd, long syscall, int64_t retval);

static inline void master_sys_openat_sel(pid_t pid, int fd, int64_t args[],
					 int64_t retval)
{
	char prefix[8];
	size_t wl_len = sizeof(dir_whitelist)/sizeof(char*);
	size_t i, size;
	int ret = 0, in_list_flag = 0;

	get_child_data(pid, prefix, args[1], 8);
	prefix[7] = 0;
	for (i = 0; i < wl_len; i++) {
		size = strlen(dir_whitelist[i]);
		// TODO: maybe buggy, if the file path read by child < 8 bytes
		ret = strncmp(dir_whitelist[i], prefix, (size > 7) ? 7 : size);
		if (!ret) {
			in_list_flag = 1;	// ret=0: found in white list.
			PRINT("** Found in white list. prefix %s\n", prefix);
			break;
		}
	}
	if (!in_list_flag) {
		PRINT("** Not found in whitelist\n");
	}
	VFD_PRINT("open index[%d]. fd %ld. prefix %s. in wl %d\n",
		  open_close_idx++, retval, prefix, in_list_flag);
	msg.flag = in_list_flag;	// flag=1: found file in the white list.
	msg.syscall = 2;	// SYS_open x86
	msg.len = 0;
	msg.retval = retval;
	ret = write(fd, (void*)&msg, 16);
	//PRINT("** master send message of sys_open\n");
	print_msg(msg);
	assert(ret != -1);
}

/* ===== Those master syscall handlers only care about the retval. ===== */
/**
 * Inline funtion to handle ret only syscalls on master node.
 * */
static inline void master_syscall_return(int fd, long syscall, int64_t retval)
{
	int ret = 0;
	//PRINT("** master syscall [%3ld], retval: 0x%lx\n", syscall, retval);
	/* Prepare the msg_t and send. */
	msg.syscall = syscall;	// syscall number on x86 platform
	msg.len = 0;
	msg.retval = retval;
	ret = write(fd, &msg, 16);
	//PRINT("** %s: write %d bytes.\n", __func__, ret);
	print_msg(msg);
	assert(ret != -1);
}

/**
 * The synchronization function on master node, executing the syscalls and
 * forward the result to slaves. Data will be sent with a msg_t data
 * structure (containing syscall num + message len + memory content buf)
 * */
void master_syncpoint(pid_t pid, int fd, long syscall_num, int64_t args[],
		      int64_t retval)
{
	//long follower_syscall_num = 0;
	switch (syscall_num) {
	/** (1) The following syscalls will send both param and retval. **/
	case SYS_read:	// Sync the input to slave variant.
		master_sys_read(pid, fd, args, retval);
		break;
	case SYS_epoll_pwait:
		master_sys_epoll_pwait(pid, fd, args, retval);
		break;
	case SYS_getsockopt:
		master_sys_getsockopt(pid, fd, args, retval);
		break;
	case SYS_sendfile:
		master_sys_sendfile(pid, fd, args, retval);
		break;

	/** (2) The following syscalls only have to send the retval. **/
	case SYS_openat:
		master_sys_openat_sel(pid, fd, args, retval);
		break;
	/* This guy delete fd. */
	case SYS_close:
		if (syscall_num == SYS_close)
			VFD_PRINT("close index[%d]. fd %ld. ret %ld\n",
				  open_close_idx++, args[0], retval);
	/* The following syscalls will create new fd.
	 * "open, socket, accept4, epoll_create1" */
	//case SYS_accept:// ret a descriptor of acceted socket
	case SYS_accept4:
		if (syscall_num == SYS_accept4)
			VFD_PRINT("accept4 index[%d]. fd %ld\n",
				  open_close_idx++, retval);
	/* The following syscalls manipulate fd, and the return value affects
	 * code after that. */
	case SYS_writev:
//		if (args[0] != 5) break;
	case SYS_fcntl:	// manipulate fd, ret depends on the operation
	case SYS_epoll_ctl:
	case SYS_setsockopt:
		assert(syscall_tbl[syscall_num]);
		master_syscall_return(fd, syscall_tbl[syscall_num], retval);
		break;
	case SYS_socket:
	case SYS_epoll_create1:
		VFD_PRINT("%s index[%d]. fd %ld\n",
			  syscall_num == SYS_socket?"socket":"epoll_create1",
			  open_close_idx++, retval);
	}

}
