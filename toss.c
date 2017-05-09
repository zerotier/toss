/* (c)2017 ZeroTier, Inc. (Adam Ierymenko) -- MIT LICENSE */

#include "toss.h"

#if defined(_WIN32) || defined(_WIN64)
int __cdecl _tmain(int argc, _TCHAR* argv[])
#else
int main(int argc,char **argv)
#endif
{
	uint8_t buf[16384];
	char frombuf[128];
	long n;
	struct speck_hash sh;

#if defined(_WIN32) || defined(_WIN64)
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2,2),&wsaData);
#endif

	srand((unsigned int)time(0));

	if (argc != 2) {
		fprintf(stderr,"Usage: %s <file>\n",argv[0]);
		return 1;
	}

#if defined(_WIN32) || defined(_WIN64)
	const char *plainname = strrchr(argv[1],'\\');
	if (plainname)
		++plainname;
	else plainname = argv[1];
	if (strchr(plainname,'/')) {
		fprintf(stderr,"%s: FATAL: / is not allowed in a file name.\n",argv[0]);
		return 1;
	}
#else
	const char *plainname = strrchr(argv[1],'/');
	if (plainname)
		++plainname;
	else plainname = argv[1];
	if (strchr(plainname,'\\')) {
		fprintf(stderr,"%s: FATAL: \\ is not allowed in a file name.\n",argv[0]);
		return 1;
	}
#endif

	uint8_t ip4s[TOSS_MAX_TOKEN_BYTES],ip6s[TOSS_MAX_TOKEN_BYTES];
	unsigned int ip4ptr = 0,ip6ptr = 0;

#if defined(_WIN32) || defined(_WIN64)
#error Windows interface address enumeration not implemented yet.
#else
	/* We do this in four passes. The first grabs interfaces that start with
	 * 'z' (zt#), the second 't' (tun#/tap#), the third 'i' (ipsec#), and the
	 * final pass grabs anything else (eth#, etc.). This makes us prioritize
	 * encapsulated encrypted interaces like ZeroTier and OpenVPN over others.
	 * Catch has its own priority, trying private IPs first and then globally
	 * scoped ones. These two priorities work together to prefer secure and
	 * possibly virtual routes. */
	struct ifaddrs *ifalist = (struct ifaddrs *)0;
	if (getifaddrs(&ifalist)) {
		fprintf(stderr,"%s: FATAL: getifaddrs() failed (call failed).\n",argv[0]);
		return 1;
	}
	if (!ifalist) {
		fprintf(stderr,"%s: FATAL: getifaddrs() failed (null result).\n",argv[0]);
		return 1;
	}
	for(int pass=0;pass<4;++pass) {
		struct ifaddrs *ifa = ifalist;
		while (ifa) {
			if ( (ifa->ifa_addr) && ( (pass == 3) || ( (ifa->ifa_name) && (ifa->ifa_name[0] == "zti"[pass]) ) ) ) {
				enum toss_ip_scope ipscope = IP_SCOPE_NONE;
				switch(ifa->ifa_addr->sa_family) {
					case AF_INET:
						if ((ip4ptr + 4) <= TOSS_MAX_TOKEN_BYTES) {
							ipscope = classify_ip4((struct sockaddr_in *)ifa->ifa_addr);
							if ((ipscope == IP_SCOPE_PRIVATE)||(ipscope == IP_SCOPE_GLOBAL)||(ipscope == IP_SCOPE_SHARED)) {
								memcpy(ip4s + ip4ptr,&(((const struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr),4);
								ip4ptr += 4;
							}
						}
						break;
					case AF_INET6:
						if ((ip6ptr + 16) <= TOSS_MAX_TOKEN_BYTES) {
							ipscope = classify_ip6((struct sockaddr_in6 *)ifa->ifa_addr);
							if ((ipscope == IP_SCOPE_PRIVATE)||(ipscope == IP_SCOPE_GLOBAL)||(ipscope == IP_SCOPE_SHARED)) {
								memcpy(ip6s + ip6ptr,((const struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr.s6_addr,16);
								ip6ptr += 16;
							}
						}
						break;
				}
			}
			ifa = ifa->ifa_next;
		}
	}
	freeifaddrs(ifalist);
#endif

	int filefd;
	uint8_t filedigest[16];
	uint64_t filelen = 0;
	if (!strcmp(plainname,"-")) {
		filefd = STDIN_FILENO;
		plainname = (char *)0; /* will be filled in later */
		for(int i=0;i<16;++i)
			filedigest[i] = (uint8_t)rand(); /* digest is unused with pipes, so randomize it to randomize the token */
		filelen = TOSS_PIPE_FILE_SIZE;
	} else {
		filefd = open(argv[1],O_RDONLY);
		if (filefd < 0) {
			fprintf(stderr,"%s: FATAL: unable to open for reading: %s\n",argv[0],argv[1]);
			return 1;
		}
		speck_hash_reset(&sh);
		while ((n = (long)read(filefd,buf,sizeof(buf))) > 0) {
			filelen += (uint64_t)n;
			speck_hash_update(&sh,buf,(unsigned long)n);
		}
		speck_hash_finalize(&sh,filedigest);
		if (!filelen) {
			close(filefd);
			fprintf(stderr,"%s: FATAL: zero byte file: %s\n",argv[0],argv[1]);
			return 1;
		}
	}

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
		n += 8;
	}
	hrtok[n] = (char)0;

	uint8_t claim[16];
	speck_hash_reset(&sh);
	speck_hash_update(&sh,"toss1",5);
	speck_hash_update(&sh,token,tokenlen);
	speck_hash_update(&sh,"claim",5);
	speck_hash_finalize(&sh,claim);

	uint8_t hello[16];
	speck_hash_reset(&sh);
	speck_hash_update(&sh,"toss1",5);
	speck_hash_update(&sh,token,tokenlen);
	speck_hash_update(&sh,"hello",5);
	speck_hash_finalize(&sh,hello);

	fprintf(stderr,"%s%s%s\n",(plainname) ? plainname : "",(plainname) ? "/" : "",hrtok);

	for(;;) {
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

		fprintf(stderr,"%s: %s ",argv[0],fromasc); fflush(stderr);

		send(csock,hello,16,0);

		long claimptr = 0;
		while ((claimptr < 16)&&((n = recv(csock,(void *)(buf + claimptr),16 - claimptr,0)) > 0))
			claimptr += n;
		if ((claimptr != 16)||(memcmp(buf,claim,16))) {
			close(csock);
			fprintf(stderr,"invalid claim code.\n");
			continue;
		}

		fprintf(stderr,"claim OK... "); fflush(stderr);
		if (filefd == STDIN_FILENO) {
			n = 0;
			uint64_t wrote = 0;
			while ((n = read(filefd,buf,sizeof(buf))) > 0) {
				if ((long)send(csock,buf,n,0) != n) {
					fprintf(stderr,"send incomplete, wrote %llu bytes.\n",(unsigned long long)wrote);
					break;
				}
				wrote += n;
			}
			fprintf(stderr,"tossed %llu bytes.\n",(unsigned long long)wrote);
			shutdown(csock,SHUT_WR);
			close(csock);
			break;
		} else {
			lseek(filefd,0,SEEK_SET);
			off_t flen = (off_t)filelen;
#if defined(__linux__) || defined(linux) || defined(__LINUX__) || defined(__linux)
			if (sendfile(csock,filefd,(off_t *)0,(size_t)filelen) < 0) {
#else
			if (sendfile(filefd,csock,0,&flen,(struct sf_hdtr *)0,0)) {
#endif
				fprintf(stderr,"sendfile() failed.\n");
			} else if (flen != (off_t)filelen) {
				fprintf(stderr,"sendfile() incomplete, wrote %llu bytes.\n",(unsigned long long)flen);
			} else {
				fprintf(stderr,"tossed %llu bytes.\n",(unsigned long long)filelen);
				shutdown(csock,SHUT_WR);
			}
			close(csock);
		}
	}

	close(filefd);
	close(lsock);

	return 0;
}
