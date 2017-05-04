/* (c)2017 ZeroTier, Inc. (Adam Ierymenko) -- MIT LICENSE */

#ifndef TOSS_H__
#define TOSS_H__

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#include <Windows.h>
#include <tchar.h>
#include <wchar.h>
#include <ShlObj.h>
#include <netioapi.h>
#include <iphlpapi.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <ifaddrs.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#endif

#include "ipscope.h"
#include "speck_hash.h"
#include "base32.h"

/* Do not change, must be a multiple of 5 */
#define TOSS_MAX_TOKEN_BYTES 500

/* Max IP hops (IP TTL) for catch */
/* #define TOSS_CATCH_MAX_HOPS 2 */

/* Size indicating the "file" is a pipe */
#define TOSS_PIPE_FILE_SIZE 0xffffffffffffffffULL

#endif
