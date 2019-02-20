# popcorn-mvx

A multi-version execution project

So far, we supported Lighttpd webserver to be executed with multiple variants on two ISAs (i.e., arm64 and x86\_64).
The current version of popcorn-mvx uses Ptrace interface to fully control the (variant) process execution. It limits
the performance, for example, with our early prototype, it would bring *10x* performance overhead on the Lighttpd 
webserver.

In our current design, we run the master variant on arm64, and the follower variant on x86\_64. We selectively
synchronize the syscalls from the master to the follower. Different from the existing approaches, popcorn-mvx replies 
on the follower to verify whether there is an inconsistent syscall execution. Therefore, the alert could be a little
bit late from the inconsistent point.

Popcorn-mvx sent the following syscalls from the master to the follower:

1. The following syscalls send both parameters and retval:
```
epoll_pwait, getsockopt, sendfile, read, recvfrom.
```
2. The following syscalls only send retval:
```
accept, accept4, writev, fcntl, epoll_ctl, setsockopt, openat, close.
```
3. A few syscalls affect the descriptor table:
```
socket, epoll_create1, openat, close.
```
For socket, epoll\_create1 we would like the follower execute them locally.
4. Others
`exit_group` might want to be taken care of, since it will exit the current process execution.
