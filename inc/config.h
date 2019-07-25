#ifndef _CONFIG_H
#define _CONFIG_H

#define _DEBUG

#ifdef __aarch64__
#define IP_SERVER	"10.4.4.13"	// The IP address of the x86 machine.
#else
#define IP_SERVER	"10.4.4.33"	// The IP address of the arm64 machine.
#endif

#endif
