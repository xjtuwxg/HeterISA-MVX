#ifndef _RINGBUF_H
#define _RINGBUF_H

#include <stddef.h>
#include <sys/types.h>
#include "msg_socket.h"

typedef struct ringbuf_t *ringbuf_t;

ringbuf_t ringbuf_new(void);

int ringbuf_add(ringbuf_t rb, msg_t *msg);
int ringbuf_del(ringbuf_t rb, msg_t *msg);
//void ringbuf_reset(ringbuf_t rb);
//int ringbuf_get_head(ringbuf_t rb, msg_t *msg);

#endif
