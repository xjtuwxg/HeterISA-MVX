#ifndef _MSG_SOCKET_H
#define _MSG_SOCKET_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

#define MAXEVENTS 64

typedef struct sockaddr SA;
struct epoll_event event;
struct epoll_event events[MAXEVENTS];
int listenfd, efd;

int create_client_socket(char *ip);
int create_server_socket(void);
int init(void);

#endif
