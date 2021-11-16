HeterISA-MVX (ptrace-based)
===

## Background

This project implements a user-space multi-ISA multi-version execution (MVX) engine. The idea is to run two program variants with the same semantic concurrently. Any execution divergence between the two variants potentially indicates an exploit. In our case, we use **programs built from different architectures** as variants.

So far, we supported Lighttpd webserver to be executed with multiple variants on two nodes of different ISAs (i.e., arm64 and x86\_64).
The current version of HeterISA-MVX uses [ptrace](https://en.wikipedia.org/wiki/Ptrace) interface to fully control the variant execution. However, ptrace-based MVX systems have larger performance overhead, for example, there is about *10x* performance overhead on the Lighttpd webserver running on top of our MVX prototpye.

In our current design, we run the **leader variant on arm64**, and the **follower variant on x86\_64**. We selectively
synchronize the syscalls from the leader to the follower. Different from the existing approaches, HeterISA-MVX replies 
on the follower to verify whether there is an inconsistent syscall execution. Therefore, the alert could be a little
bit late from the inconsistent point.

HeterISA-MVX sent the following syscalls from the leader to the follower:

1) The following syscalls send both parameters and retval:
```
epoll_pwait, getsockopt, sendfile, read, recvfrom.
```

2) The following syscalls only send retval:
```
accept, accept4, writev, fcntl, epoll_ctl, setsockopt, openat, close.
```

3) A few syscalls affect the descriptor table:
```
socket, epoll_create1, openat, close.
```
For `socket, epoll_create1` we would like the follower execute them locally.

4) Others
`exit_group` might want to be taken care of, since it will exit the current process execution.

## How to use HeterISA-MVX

To use ptrace-based HeterISA-MVX, you have to **run the leader variant first**. Currently, we use aarch64 as the leader node, and x86_64 as the follower node.

1) Config the IPs of two servers

Edit the configuration file: `inc/config.h` and set the IPs correctly:
```
❯ cat inc/config.h
... ...
#ifdef __aarch64__
#define IP_SERVER	"10.4.4.13"	// The IP address of the x86 machine.
#else
#define IP_SERVER	"10.4.4.33"	// The IP address of the arm64 machine.
```

2) The simple network server (testing epoll related events)

Start the leader variant (from the ARM node) first:
```
popcorn@arm:~/works/mvx/HeterISA-MVX$ ./mvx_monitor ./test/epoll
```

Next, start the follower variant (from the x86 node):
```
popcorn@x86:~/works/mvx/HeterISA-MVX$ ./mvx_monitor ./test/epoll
```

Access the leader variant via network:
```
popcorn@arm:~$ nc localhost 5000
Hi, how are you.
```

3) Lighttpd web server

Start the leader variant:
```
popcorn@arm:~/works/mvx/HeterISA-MVX$ ./mvx_monitor test/lighttpd-1.4.50/src/lighttpd -f test/lighttpd.conf -D
```

Start the follower variant:
```
popcorn@x86:~/works/mvx/HeterISA-MVX$ ./mvx_monitor test/lighttpd-1.4.50/src/lighttpd -f test/lighttpd.conf -D
```

Access the web server:
```
popcorn@arm:~$ curl localhost:8889
<html>
<head>
... ...
```

### Compile lighttpd
```
-> % sudo apt-get install automake autoconf libtool pkg-config
popcorn@arm [02:01:49 AM] [~/mvx/HeterISA-MVX/test/lighttpd-1.4.50] [master *]
-> % ./config-xiaoguang.sh
-> % make & sudo make install
```