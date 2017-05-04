#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <ifaddrs.h>

#include "ipscope.h"

/* Uncomment to print some tracing info to stderr for debugging */
#define TOSS_VERBOSE 1

#define TOSS_MAX_TOKEN_BYTES 1024

int main(int argc,char **argv)
{
	uint8_t token[TOSS_MAX_TOKEN_BYTES];
	unsigned int tokenlen = 0;

	if (argc != 2) {
		printf("Usage: %s <file>\n",argv[0]);
		return 1;
	}

	uint8_t ip4s[TOSS_MAX_TOKEN_BYTES],ip6s[TOSS_MAX_TOKEN_BYTES];
	unsigned int ip4ptr = 0,ip6ptr = 0;
	struct ifaddrs *ifa = (struct ifaddrs *)0;
	if (getifaddrs(&ifa)) {
		fprintf(stderr,"%s: FATAL: getifaddrs() failed (call failed).\n",argv[0]);
		return 1;
	}
	if (!ifa) {
		fprintf(stderr,"%s: FATAL: getifaddrs() failed (null result).\n",argv[0]);
		return 1;
	}
	while (ifa) {
		if (ifa->ifa_addr) {
			enum toss_ip_scope ipscope = IP_SCOPE_NONE;
			switch(ifa->ifa_addr->sa_family) {
				case AF_INET:
					if ((ip4ptr + 4) <= TOSS_MAX_TOKEN_BYTES) {
						ipscope = classify_ip4((struct sockaddr_in *)ifa->ifa_addr);
						if ((ipscope == IP_SCOPE_PRIVATE)||(ipscope == IP_SCOPE_GLOBAL)||(ipscope == IP_SCOPE_SHARED)) {
							memcpy(ip4s + ip4ptr,&(((const struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr),4);
#ifdef TOSS_VERBOSE
							fprintf(stderr,"%s: found IPv4: ",argv[0]);
							for(int i=0;i<4;++i)
								fprintf(stderr,"%s%u",((i > 0) ? "." : ""),(unsigned int)ip4s[ip4ptr + i]);
							fprintf(stderr,"\n");
#endif
							ip4ptr += 4;
						}
					}
					break;
				case AF_INET6:
					if ((ip6ptr + 16) <= TOSS_MAX_TOKEN_BYTES) {
						ipscope = classify_ip6((struct sockaddr_in6 *)ifa->ifa_addr);
						if ((ipscope == IP_SCOPE_PRIVATE)||(ipscope == IP_SCOPE_GLOBAL)||(ipscope == IP_SCOPE_SHARED)) {
							memcpy(ip6s + ip6ptr,((const struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr.s6_addr,16);
#ifdef TOSS_VERBOSE
							fprintf(stderr,"%s: found IPv6: ",argv[0]);
							for(int i=0;i<16;++i)
								fprintf(stderr,"%.2x",(unsigned int)ip6s[ip6ptr + i]);
							fprintf(stderr,"\n");
#endif
							ip6ptr += 16;
						}
					}
					break;
			}
		}
		ifa = ifa->ifa_next;
	}
}
