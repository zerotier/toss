/* (c)2017 ZeroTier, Inc. (Adam Ierymenko) -- MIT LICENSE */

#ifndef TOSS_IPSCOPE_H
#define TOSS_IPSCOPE_H

#include <stdint.h>

enum toss_ip_scope
{
	IP_SCOPE_NONE,          /* NULL or not an IP address */
	IP_SCOPE_MULTICAST,     /* 224.0.0.0 and other V4/V6 multicast IPs */
	IP_SCOPE_LOOPBACK,      /* 127.0.0.1, ::1, etc. */
	IP_SCOPE_GLOBAL,        /* globally routable IP address (all others) */
	IP_SCOPE_LINK_LOCAL,    /* 169.254.x.x, IPv6 LL */
	IP_SCOPE_SHARED,        /* 100.64.0.0/10, shared space for e.g. carrier-grade NAT */
	IP_SCOPE_PRIVATE        /* 10.x.x.x, 192.168.x.x, etc. */
};

static enum toss_ip_scope classify_ip4(const struct sockaddr_in *in)
{
	const uint32_t ip = (uint32_t)ntohl(in->sin_addr.s_addr);
	switch(ip >> 24) {
		case 0x00: return IP_SCOPE_NONE;                                      // 0.0.0.0/8 (reserved, never used)
		case 0x0a: return IP_SCOPE_PRIVATE;                                   // 10.0.0.0/8
		case 0x64:
			if ((ip & 0xffc00000) == 0x64400000) return IP_SCOPE_SHARED;        // 100.64.0.0/10
			break;
		case 0x7f: return IP_SCOPE_LOOPBACK;                                  // 127.0.0.0/8
		case 0xa9:
			if ((ip & 0xffff0000) == 0xa9fe0000) return IP_SCOPE_LINK_LOCAL;    // 169.254.0.0/16
			break;
		case 0xac:
			if ((ip & 0xfff00000) == 0xac100000) return IP_SCOPE_PRIVATE;       // 172.16.0.0/12
			break;
		case 0xc0:
			if ((ip & 0xffff0000) == 0xc0a80000) return IP_SCOPE_PRIVATE;				// 192.168.0.0/16
			break;
		case 0xff: return IP_SCOPE_NONE;                                      // 255.0.0.0/8 (broadcast, or unused/unusable)
	}
	switch(ip >> 28) {
		case 0xe: return IP_SCOPE_MULTICAST;                              // 224.0.0.0/4
	}
	return IP_SCOPE_GLOBAL;
}

static enum toss_ip_scope classify_ip6(const struct sockaddr_in6 *in)
{
	const uint8_t *ip = (const uint8_t *)in->sin6_addr.s6_addr;
	if ((ip[0] & 0xf0) == 0xf0) {
		if (ip[0] == 0xff) return IP_SCOPE_MULTICAST;                              // ff00::/8
		if ((ip[0] == 0xfe)&&((ip[1] & 0xc0) == 0x80)) {
			unsigned int k = 2;
			while ((!ip[k])&&(k < 15)) ++k;
			if ((k == 15)&&(ip[15] == 0x01))
				return IP_SCOPE_LOOPBACK;                                              // fe80::1/128
			else return IP_SCOPE_LINK_LOCAL;                                         // fe80::/10
		}
		if ((ip[0] & 0xfe) == 0xfc) return IP_SCOPE_PRIVATE;                       // fc00::/7
	}
	unsigned int k = 0;
	while ((!ip[k])&&(k < 15)) ++k;
	if (k == 15) { // all 0's except last byte
		if (ip[15] == 0x01) return IP_SCOPE_LOOPBACK;                              // ::1/128
		if (ip[15] == 0x00) return IP_SCOPE_NONE;                                  // ::/128
	}
	return IP_SCOPE_GLOBAL;
}

#endif
