#include "inc/ringbuf.h"

#define MAX_RINGBUF_SIZE	256

/**
 * head: index indicate the index of the next available msg slot for
 * the ring buffer message
 * */
struct ringbuf_t
{
	msg_t *msg[MAX_RINGBUF_SIZE];
	//msg_t *head, *tail;
	size_t head, tail;	// index of head and tail
	size_t size;
};

//struct ringbuf_t ringbuf;

//ringbuf_t ringbuf_new(size_t capacity)
ringbuf_t ringbuf_new(void)
{
	ringbuf_t rb = malloc(sizeof(struct ringbuf_t));
	if (rb) {
		memset(rb->msg, 0, sizeof(msg_t)*MAX_RINGBUF_SIZE);
		rb->head = rb->tail = 0;
		rb->size = 0;
		return rb;
	}
	return 0;
}

//void ringbuf_reset(ringbuf_t rb)
//{
//	rb->head = rb->tail = rb->buf;
//}

/**
 * Add msg to the ringbuf rb.
 * */
int ringbuf_add(ringbuf_t rb, msg_t *msg)
{
	if (rb->size >= MAX_RINGBUF_SIZE) return -1;
	// fill the ringbuf
	rb->msg[rb->head] = msg;
	// advance the head index
	if (rb->head == MAX_RINGBUF_SIZE-1) rb->head = 0;
	else rb->head++;
	// increase the size
	rb->size++;

	return 0;
}

/**
 * Del msg from the ringbuf rb.
 * */
int ringbuf_del(ringbuf_t rb, msg_t *msg)
{
	if (rb->size == 0) return -1;
	// retrive the msg value from ringbuf
	msg = rb->msg[rb->tail];
	// advance the tail index
	if (rb->tail == MAX_RINGBUF_SIZE-1) rb->tail = 0;
	else rb->tail++;
	// decrease the size
	rb->size--;

	return 0;
}

//int ringbuf_get_head(ringbuf_t rb, msg_t *msg)
//{
//}
