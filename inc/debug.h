#ifndef _DEBUG_H
#define _DEBUG_H

#include <stdio.h>	// stderr
#include <stdlib.h>	// EXIT_FAILURE

/**
 * The DEBUG mode print functions.
 * */
#define _DEBUG
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

/**
 * Debug mode print message for message layer.
 * */
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

/**
 * Debug mode print message for virtual fd.
 * */
#define _VFD_DEBUG
#ifdef _VFD_DEBUG
#define VFD_PRINT(...) \
    do { \
	fprintf(stdout, "[mvx vfd]: " __VA_ARGS__); \
	fflush(stdout); \
    } while (0);
#else	// ifdef _VFD_DEBUG
#define VFD_PRINT(...)	do {} while(0)
#endif	// end	_VFD_DEBUG

#endif	// _DEBUG_H
