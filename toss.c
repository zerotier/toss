#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <ifaddrs.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

#include "ipscope.h"
#include "speck_hash.h"
#include "base32.h"

/* Do not change, must be a multiple of 5 */
#define TOSS_MAX_TOKEN_BYTES 500

int main(int argc,char **argv)
{
	uint8_t buf[16384];
	char frombuf[128];
	long n;
	struct speck_hash sh;

	srand((unsigned int)time(0));

	if (argc != 2) {
		printf("Usage: %s <file>\n",argv[0]);
		return 1;
	}

	const char *start_of_fn = strrchr(argv[1],'/');
	const char *plainname = (start_of_fn) ? (start_of_fn + 1) : argv[1];
	if (strchr(plainname,'\\')) {
		fprintf(stderr,"%s: FATAL: \\ is not allowed in a file name.\n",argv[0]);
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
							/*
							fprintf(stderr,"%s: found IPv4: ",argv[0]);
							for(int i=0;i<4;++i)
								fprintf(stderr,"%s%u",((i > 0) ? "." : ""),(unsigned int)ip4s[ip4ptr + i]);
							fprintf(stderr,"\n");
							*/
							ip4ptr += 4;
						}
					}
					break;
				case AF_INET6:
					if ((ip6ptr + 16) <= TOSS_MAX_TOKEN_BYTES) {
						ipscope = classify_ip6((struct sockaddr_in6 *)ifa->ifa_addr);
						if ((ipscope == IP_SCOPE_PRIVATE)||(ipscope == IP_SCOPE_GLOBAL)||(ipscope == IP_SCOPE_SHARED)) {
							memcpy(ip6s + ip6ptr,((const struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr.s6_addr,16);
							/*
							fprintf(stderr,"%s: found IPv6: ",argv[0]);
							for(int i=0;i<16;++i)
								fprintf(stderr,"%.2x",(unsigned int)ip6s[ip6ptr + i]);
							fprintf(stderr,"\n");
							*/
							ip6ptr += 16;
						}
					}
					break;
			}
		}
		ifa = ifa->ifa_next;
	}

	int filefd = open(argv[1],O_RDONLY);
	if (filefd < 0) {
		fprintf(stderr,"%s: FATAL: unable to open for reading: %s\n",argv[0],argv[1]);
		return 1;
	}
	uint8_t filedigest[16];
	speck_hash_reset(&sh);
	uint64_t filelen = 0;
	while ((n = (long)read(filefd,buf,sizeof(buf))) > 0) {
		filelen += (uint64_t)n;
		speck_hash_update(&sh,buf,(unsigned long)n);
	}
	speck_hash_finalize(&sh,filedigest);

	int lsock = -1;
	unsigned int port = 0;
	for(int k=0;k<16384;++k) {
		lsock = (int)socket(AF_INET6,SOCK_STREAM,0);
		if (lsock < 0) {
			close(filefd);
			fprintf(stderr,"%s: FATAL: socket(AF_INET6,SOCK_STREAM,0) failed.\n",argv[0]);
			return 1;
		}
		int tmpi = 0;
		setsockopt(lsock,IPPROTO_IPV6,IPV6_V6ONLY,(void *)&tmpi,sizeof(tmpi));
		tmpi = 1;
		setsockopt(lsock,SOL_SOCKET,SO_REUSEADDR,(void *)&tmpi,sizeof(tmpi));

		port = 30000 + ((unsigned int)rand() % 35535);
		struct sockaddr_in6 in6any;
		memset(&in6any,0,sizeof(struct sockaddr_in6));
		in6any.sin6_family = AF_INET6;
		in6any.sin6_port = htons((uint16_t)port);
		in6any.sin6_addr = in6addr_any;

		if (bind(lsock,(struct sockaddr *)&in6any,sizeof(struct sockaddr_in6))) {
			close(lsock);
			lsock = -1;
		} else {
			break;
		}
	}
	if (lsock < 0) {
		close(filefd);
		fprintf(stderr,"%s: FATAL: unable to bind any port (tried 16384 times)\n",argv[0]);
		return 1;
	}

	uint8_t token[TOSS_MAX_TOKEN_BYTES + 8];
	token[0] = (uint8_t)((port >> 8) & 0xff);
	token[1] = (uint8_t)(port & 0xff);
	token[2] = (uint8_t)((filelen >> 56) & 0xff);
	token[3] = (uint8_t)((filelen >> 48) & 0xff);
	token[4] = (uint8_t)((filelen >> 40) & 0xff);
	token[5] = (uint8_t)((filelen >> 32) & 0xff);
	token[6] = (uint8_t)((filelen >> 24) & 0xff);
	token[7] = (uint8_t)((filelen >> 16) & 0xff);
	token[8] = (uint8_t)((filelen >> 8) & 0xff);
	token[9] = (uint8_t)(filelen & 0xff);
	unsigned int tokenlen = 10;
	for(int i=0;i<8;++i) /* use first 8 bytes of file digest */
		token[tokenlen++] = filedigest[i];
	unsigned int ip4ptr2 = 0,ip6ptr2 = 0;
	n = 0;
	while ((ip4ptr2 < ip4ptr)&&(ip6ptr2 < ip6ptr)&&((tokenlen + 17 + 5) <= TOSS_MAX_TOKEN_BYTES)) {
		if (n) {
			token[tokenlen++] = 16;
			for(int i=0;i<16;++i)
				token[tokenlen++] = ip6s[ip6ptr2++];
		} else {
			token[tokenlen++] = 4;
			for(int i=0;i<4;++i)
				token[tokenlen++] = ip4s[ip4ptr2++];
		}
		n ^= 1;
	}
	while ((tokenlen % 5) != 0)
		++tokenlen;

	char hrtok[TOSS_MAX_TOKEN_BYTES * 2];
	n = 0;
	for(int i=0;i<tokenlen;i+=5) {
		base32_5_to_8(token + i,hrtok + n);
		i += 5;
		n += 8;
	}
	hrtok[n] = (char)0;

	uint8_t claim[16];
	speck_hash_reset(&sh);
	speck_hash_update(&sh,"claim",5);
	speck_hash_update(&sh,token,tokenlen);
	speck_hash_update(&sh,"claim",5);
	speck_hash_finalize(&sh,claim);
	uint8_t hello[16];
	speck_hash_reset(&sh);
	speck_hash_update(&sh,"hello",5);
	speck_hash_update(&sh,token,tokenlen);
	speck_hash_update(&sh,"hello",5);
	speck_hash_finalize(&sh,hello);

	printf("%s/%s\n",plainname,hrtok);

	int ok = 1;
	for(int k=0;k<16;++k) {
		if (listen(lsock,4)) {
			close(filefd);
			close(lsock);
			fprintf(stderr,"%s: FATAL: listen() failed.\n",argv[0]);
			return 1;
		}
		struct sockaddr_storage fromaddr;
		memset(&fromaddr,0,sizeof(struct sockaddr_storage));
		socklen_t addrlen = sizeof(struct sockaddr_storage);
		int csock = accept(lsock,(struct sockaddr *)&fromaddr,&addrlen);
		if (csock < 0)
			continue;

		const char *fromasc = "(unknown)";
		switch(fromaddr.ss_family) {
			case AF_INET:
				fromasc = inet_ntop(AF_INET,&(((struct sockaddr_in *)&fromaddr)->sin_addr.s_addr),frombuf,sizeof(frombuf));
				break;
			case AF_INET6:
				fromasc = inet_ntop(AF_INET6,((struct sockaddr_in6 *)&fromaddr)->sin6_addr.s6_addr,frombuf,sizeof(frombuf));
				break;
		}
		if (!fromasc)
			fromasc = "(unknown)";

		printf("%s: %s ",argv[0],fromasc); fflush(stdout);

		send(csock,hello,16,0);

		long claimptr = 0;
		while ((n = recv(csock,(void *)(buf + claimptr),16 - claimptr,0)) > 0)
			claimptr += n;
		if (claimptr < 16) {
			close(csock);
			printf("empty or invalid claim code, waiting again...\n");
			continue;
		}
		if (memcmp(buf,claim,16)) {
			printf("invalid claim code, waiting again...\n");
			close(csock);
			continue;
		}

		printf("got claim, sending... "); fflush(stdout);
		lseek(filefd,0,SEEK_SET);
		off_t flen = (off_t)filelen;
		if (sendfile(filefd,csock,0,&flen,(struct sf_hdtr *)0,0)) {
			printf("sendfile() failed, waiting again...\n");
			close(csock);
			continue;
		} else if (flen != (off_t)filelen) {
			printf("sendfile() incomplete (wrote %lu bytes), waiting again...\n",(unsigned long)flen);
			close(csock);
			continue;
		} else {
			ok = 0;
			printf("sent %llu bytes. done!\n",(unsigned long long)filelen);
			shutdown(csock,SHUT_WR);
			close(csock);
			break;
		}
	}

	close(filefd);
	close(lsock);

	if (ok)
		fprintf(stderr,"%s: FATAL: tried 16 times, failed to send.\n",argv[0]);

	return ok;
}
