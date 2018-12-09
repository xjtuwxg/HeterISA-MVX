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
#include <semaphore.h>
#include <pthread.h>		// pthread_t
#include <sys/types.h>
#include <arpa/inet.h>		// inet_pton

#define MAXEVENTS	64
#define MSG_SIZE	4032

#ifndef NI_MAXHOST
#define NI_MAXHOST	1025
#endif
#ifndef NI_MAXSERV
#define NI_MAXSERV	32
#endif
#ifndef NI_NUMERICHOST
#define NI_NUMERICHOST	1
#endif

/* Definations for ring buffer. */
#define MAX_RINGBUF_SIZE	256

typedef struct sockaddr SA;

/**
 * The message data structure, also the entry of ringbuf_t.
 * The msg_t header has 16 bytes, then follows the variant length buf.
 * */
typedef struct _message_t {
	short syscall;		// 2 bytes
	short flag;		// 2 bytes, not used so far
	unsigned int len;	// 4 bytes
	long retval;		// 8 bytes
	char buf[MSG_SIZE];
} msg_t;


/**
 * head: index indicate the index of the next available msg slot for
 * the ring buffer message
 * */
struct ringbuf_t {
	msg_t *msg[MAX_RINGBUF_SIZE];
	size_t head, tail;
	size_t size;
	sem_t sem;
};
typedef struct ringbuf_t *ringbuf_t;

/* Epoll event in x86 format */
struct epoll_event_x86 {
	uint32_t events;
	epoll_data_t data;
} __attribute__ ((__packed__));

/**
 * Global variables for msg_socket.c (the message layer)
 * */
int listenfd, efd;
struct epoll_event event;
struct epoll_event events[MAXEVENTS];
ringbuf_t ringbuf;	// server/receiver side ring buffer
msg_t msg;		// client/sender side msg data struct


/* Socket related interfaces */
int create_client_socket(char *ip);
int create_server_socket(void);

void msg_thread_init(void);

/* Ring buffer related interfaces */
ringbuf_t ringbuf_new(void);
int ringbuf_add(ringbuf_t rb, msg_t *msg);
int ringbuf_pop(ringbuf_t rb, msg_t *msg);

static inline size_t ringbuf_size(ringbuf_t rb)
{
	return rb->size;
}

static inline int isEmpty(ringbuf_t rb)
{
	if (rb->size == 0) return 1;
	else return 0;
}

static inline msg_t* ringbuf_gettop(ringbuf_t rb)
{
	if (isEmpty(rb)) {
		return 0;
	}
	if (rb->head == 0) return rb->msg[MAX_RINGBUF_SIZE-1];
	else return rb->msg[rb->head-1];
}

#endif
