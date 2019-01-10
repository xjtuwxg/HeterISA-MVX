#ifndef _DEBUG_H
#define _DEBUG_H

#include <stdio.h>	// stderr
#include <stdlib.h>	// EXIT_FAILURE

/**
 * The DEBUG mode print functions.
 * */
//#define _DEBUG

#ifdef _DEBUG
#define FATAL(...) \
    do { \
        fprintf(stderr, "[mvx fatal]: " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)

#define ERROR(...) \
	do { \
		fprintf(stderr, "[mvx error]: "__VA_ARGS__); \
		fputc('\n', stderr); \
	} while(0)

#define PRINT(...) \
    do { \
	fprintf(stdout, "[mvx]: " __VA_ARGS__); \
	fflush(stdout); \
    } while (0);

#define RAW_PRINT(...) \
    do { \
	fprintf(stdout, __VA_ARGS__); \
	fflush(stdout); \
    } while (0);
#else	// ifdef _DEBUG
#define FATAL(...)	do {} while(0)
#define ERROR(...)	do {} while(0)
#define PRINT(...)	do {} while(0)
#define RAW_PRINT(...)	do {} while(0)
#endif	// end _DEBUG


//#define _MSG_DEBUG

#ifdef _MSG_DEBUG
#define MSG_PRINT(...) \
    do { \
	fprintf(stdout, "[mvx msg]: " __VA_ARGS__); \
	fflush(stdout); \
    } while (0);
#else	// ifdef _MSG_DEBUG
#define MSG_PRINT(...)	do {} while(0)
#endif	// end	_MSG_DEBUG

#include "msg_socket.h"
static void print_msg(msg_t msg)
{
	PRINT("** syscall [%d], flag %d, len %d, retval %ld.\n",
	      msg.syscall, msg.flag, msg.len, msg.retval);
}

#endif	// _DEBUG_H
