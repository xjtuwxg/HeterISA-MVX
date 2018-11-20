#include "ptrace.h"
#include "debug.h"
//#include <linux/ptrace.h>

/**
 * Get syscall arguments from user_regs_struct
 * Arch-dependent part
 * */
#ifdef __x86_64__
/**
 * x86_64 useds rsi, rdi, rdx, r10, r8, r9 for syscall params,
 *       rax for syscall num, and rax for the retval.
 * See "man 2 syscall"
 * */
static inline int x86_get_sc_args(struct user_regs_struct regs,
				  long long args[])
{
    args[0] = regs.rdi;  args[1] = regs.rsi;  args[2] = regs.rdx;
    args[3] = regs.r10;  args[4] = regs.r8;   args[5] = regs.r9;
    return regs.orig_rax;
}
#endif
#ifdef __aarch64__
/**
 * arm64 uses x0 - x5 for the syscall params,
 *     x8 for the syscall num, and x0 for the retval.
 * See "man 2 syscall"
 * */
static inline int arm64_get_sc_args(struct user_regs_struct regs,
				    long long args[])
{
    args[0] = regs.regs[0];  args[1] = regs.regs[1];  args[2] = regs.regs[2];
    args[3] = regs.regs[3];  args[4] = regs.regs[4];  args[5] = regs.regs[5];
    return regs.regs[8];
}
#endif

/**
 * Get the current register value from user_regs_struct, parse the register
 * value into a 6 element syscall param array.
 * */
long get_regs_args(pid_t pid, struct user_regs_struct *regs, long long args[])
{
        long syscall_num;
#ifdef __x86_64__
	if (ptrace(PTRACE_GETREGS, pid, 0, regs) == -1)
		ERROR("PTRACE_GETREGS %s", strerror(errno));
        syscall_num = x86_get_sc_args(*regs, args);
#endif
#ifdef __aarch64__
	struct iovec iov;
	iov.iov_base = regs;
	iov.iov_len = sizeof(*regs);
        //if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1)
        if (ptrace(PTRACE_GETREGSET, pid, 1, &iov) == -1)
		FATAL("ptrace_getregset error %s.", strerror(errno));
        syscall_num = arm64_get_sc_args(*regs, args);
#endif
	return syscall_num;
}

/**
 * Get the register value again on syscall exits. Return the syscall retval.
 * */
long long get_retval(pid_t pid, struct user_regs_struct *regs, int *term)
{
#ifdef __x86_64__
        if (ptrace(PTRACE_GETREGS, pid, 0, regs) == -1) {
		fputs(" = ?\n", stderr);
		if (errno == ESRCH) {	// No such process
			*term = 1;
			PRINT("%s: rdi: %lld.\n", strerror(errno), regs->rdi);
			return 0;
			//exit(regs->rdi); // system call was _exit(2) or similar
		}
		FATAL("%s", strerror(errno));
        }
	return regs->rax;
#endif
#ifdef __aarch64__
	struct iovec iov;
	iov.iov_base = regs;
	iov.iov_len = sizeof(*regs);
        if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
		fputs(" = ?\n", stderr);
		if (errno == ESRCH) {	// No such process
			*term = 1;
			//PRINT("x0: %lld.\n", regs->regs[0]);
			return 0;
		}
		FATAL("%s.", strerror(errno));	// strerror may have segfault
	}
	return regs->regs[0];
	//post_syscall(syscall_num, regs.regs[8]);
#if 0
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
#endif

}

/**
 * Copy data from parent address space (src, len) to child process (pid, dst).
 * */
int update_child_data(pid_t pid, long long dst, char *src, size_t len)
{
	long ret;
	int cnt = len / sizeof(long long);
	long long dst_loc = dst;
	int i;

	memset(&input, 0, sizeof(input));
	for (i = 0; i < cnt; i++) {
		memcpy(input.str, src+i*8, 8);
		ret = ptrace(PTRACE_POKEDATA, pid, dst_loc+i*8, input.val);
		if (ret) FATAL("%s error", __func__);
	}
	/// TODO: finish str cpy

	return 0;
}

/**
 * Copy data from child process.
 * */
int get_child_data(pid_t pid, char *dst, long long src, size_t len)
{
	size_t cnt = len / sizeof(long long);
	size_t i;
	memset(&input, 0, sizeof(input));

	if (cnt*8 < len) cnt++;
	for (i = 0; i < cnt; i++) {
		input.val = ptrace(PTRACE_PEEKDATA, pid, src+8*i, 0);
		memcpy(dst+8*i, input.str, 8);
	}
	dst[len] = 0;
	return 0;
}
