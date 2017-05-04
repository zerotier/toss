/* (c)2017 ZeroTier, Inc. (Adam Ierymenko) -- MIT LICENSE */

#include "toss.h"

#define TRY_SCOPE_COUNT 3
static const enum toss_ip_scope TRY_SCOPE_ORDER[TRY_SCOPE_COUNT] = { IP_SCOPE_PRIVATE,IP_SCOPE_SHARED,IP_SCOPE_GLOBAL };
static const unsigned int TRY_SCOPE_TIMEOUT[TRY_SCOPE_COUNT] = { 2,2,8 };

static void catch_sigalrm(int sig) {}

#if defined(_WIN32) || defined(_WIN64)
int __cdecl _tmain(int argc, _TCHAR* argv[])
#else
int main(int argc,char **argv)
#endif
{
	static uint8_t buf[1048576]; /* WARNING: can't use in multithreaded programs without making non-static */
	char frombuf[128];
	long n;
	struct speck_hash sh;

#if defined(_WIN32) || defined(_WIN64)
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2,2),&wsaData);
#else
	signal(SIGALRM,catch_sigalrm);
#endif

	if ((argc < 2)||(argc > 3)) {
		printf("Usage: %s <claim> [<output file>]\n",argv[0]);
		return 1;
	}

	char plainname[TOSS_MAX_TOKEN_BYTES];
	uint8_t token[TOSS_MAX_TOKEN_BYTES + 8];
	unsigned int tokenlen = 0;
	const char *hrtok = strchr(argv[1],'/');
	if (hrtok) {
		unsigned int i = (unsigned int)(hrtok - argv[1]);
		memcpy(plainname,argv[1],i);
		plainname[i] = (char)0;
		++hrtok;
	} else {
		plainname[0] = (char)0;
		hrtok = argv[1];
	}
	while (strlen(hrtok) >= 8) {
		if (tokenlen >= TOSS_MAX_TOKEN_BYTES) {
			fprintf(stderr,"%s: FATAL: invalid token (too long)\n",argv[0]);
			return 1;
		}
		base32_8_to_5(hrtok,token + tokenlen);
		tokenlen += 5;
		hrtok += 8;
	}
	if ((tokenlen <= 18)||((tokenlen % 5) != 0)) {
		fprintf(stderr,"%s: FATAL: invalid or incomplete token (make sure you get both lines if it wraps in terminal)\n",argv[0]);
		return 1;
	}

	unsigned int port = (((unsigned int)token[0] & 0xff) << 8) | (token[1] & 0xff);
	if ((!port)||(port > 0xffff)) {
		fprintf(stderr,"%s: FATAL: invalid token (bad port %u)\n",argv[0],port);
		return 1;
	}
	uint64_t filelen = 0;
	filelen |= ((uint64_t)token[2] & 0xff) << 56;
	filelen |= ((uint64_t)token[3] & 0xff) << 48;
	filelen |= ((uint64_t)token[4] & 0xff) << 40;
	filelen |= ((uint64_t)token[5] & 0xff) << 32;
	filelen |= ((uint64_t)token[6] & 0xff) << 24;
	filelen |= ((uint64_t)token[7] & 0xff) << 16;
	filelen |= ((uint64_t)token[8] & 0xff) << 8;
	filelen |= (uint64_t)token[9] & 0xff;
	if (!filelen) {
		fprintf(stderr,"%s: FATAL: invalid token (file length is 0)\n",argv[0]);
		return 1;
	}

	if (!plainname[0]) { /* If no plainname, use file digest */
		for(int i=0;i<8;++i)
			snprintf(plainname+(i*2),3,"%.2x",(unsigned int)token[i+10]);
	}
	const char *destpath = (argc >= 3) ? argv[2] : plainname;

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

	if (filelen == TOSS_PIPE_FILE_SIZE) {
		printf("%s: catching %s (size unknown)\n",argv[0],destpath);
	} else {
		printf("%s: catching %s (%llu bytes)\n",argv[0],destpath,(unsigned long long)filelen);
	}

	int ok = 1;
	for(int k=0;k<TRY_SCOPE_COUNT;++k) {
		for(unsigned int i=18;i<tokenlen;) {
			unsigned int iplen = token[i++];
			if (i >= tokenlen) break;

			struct sockaddr_storage sa;
			const char *fromaddr = (char *)0;
			memset(&sa,0,sizeof(struct sockaddr_storage));
			enum toss_ip_scope ipsc = IP_SCOPE_NONE;
			switch(iplen) {
				case 4:
					sa.ss_family = AF_INET;
					((struct sockaddr_in *)&sa)->sin_port = htons((uint16_t)port);
					memcpy(&(((struct sockaddr_in *)&sa)->sin_addr.s_addr),token + i,4);
					fromaddr = inet_ntop(AF_INET,token + i,frombuf,sizeof(frombuf));
					ipsc = classify_ip4((struct sockaddr_in *)&sa);
					break;
				case 16:
					sa.ss_family = AF_INET6;
					((struct sockaddr_in6 *)&sa)->sin6_port = htons((uint16_t)port);
					memcpy(((struct sockaddr_in6 *)&sa)->sin6_addr.s6_addr,token + i,16);
					fromaddr = inet_ntop(AF_INET6,token + i,frombuf,sizeof(frombuf));
					ipsc = classify_ip6((struct sockaddr_in6 *)&sa);
					break;
			}
			i += iplen;

			if ((fromaddr)&&(ipsc == TRY_SCOPE_ORDER[k])) {
				fprintf(stderr,"%s: %s/%u ",argv[0],fromaddr,port); fflush(stderr);

				int csock = socket(sa.ss_family,SOCK_STREAM,0);
				if (csock < 0) {
					fprintf(stderr,"%s: FATAL: socket() failed\n",argv[0]);
					return 1;
				}

#ifdef TOSS_CATCH_MAX_HOPS
				if (sa.ss_family == AF_INET) {
					int opt = TOSS_CATCH_MAX_HOPS;
					setsockopt(csock,IPPROTO_IP,IP_TTL,(void *)&opt,sizeof(opt));
				} else if (sa.ss_family == AF_INET6) {
					int opt = TOSS_CATCH_MAX_HOPS;
					setsockopt(csock,IPPROTO_IPV6,IPV6_UNICAST_HOPS,(void *)&opt,sizeof(opt));
				}
#endif

				alarm(TRY_SCOPE_TIMEOUT[k]);
				if (connect(csock,(struct sockaddr *)&sa,(sa.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))) {
					alarm(0);
					close(csock);
					fprintf(stderr,"connect failed.\n");
					continue;
				}
				alarm(0);

				long helloptr = 0;
				while ((helloptr < 16)&&((n = recv(csock,(void *)(buf + helloptr),16 - helloptr,0)) > 0))
					helloptr += n;
				if (helloptr != 16) {
					close(csock);
					fprintf(stderr,"bad greeting (incomplete).\n");
					continue;
				}
				if (memcmp(buf,hello,16)) {
					close(csock);
					fprintf(stderr,"bad greeting (invalid).\n");
					continue;
				}

				send(csock,claim,16,0);

				int filefd;
				if (!strcmp(destpath,"-")) {
					filefd = STDOUT_FILENO;
				} else {
					filefd = open(destpath,O_WRONLY|O_CREAT|O_TRUNC,0644);
					if (filefd < 0) {
						close(csock);
						fprintf(stderr,"cannot open file for writing.\n%s: FATAL: cannot open destination for writing: %s",argv[0],destpath);
						return 1;
					}
				}

				uint64_t filegot = 0;
				speck_hash_reset(&sh);

				while ((n = recv(csock,buf,sizeof(buf),0)) > 0) {
					fprintf(stderr,"."); fflush(stderr);
					speck_hash_update(&sh,buf,(unsigned long)n);
					if ((long)write(filefd,buf,n) != n) {
						close(csock);
						close(filefd);
						fprintf(stderr,"write error.\n%s: FATAL: write error: %s",argv[0],destpath);
						return 1;
					}
					filegot += (uint64_t)n;
				}
				close(csock);
				close(filefd);

				speck_hash_finalize(&sh,buf);
				if ((filelen != TOSS_PIPE_FILE_SIZE)&&((memcmp(token + 10,buf,8))||(filelen != filegot))) {
					fprintf(stderr,"got %llu bytes, VERIFICATION FAILED! file may be corrupt!\n",(unsigned long long)filegot);
				} else {
					ok = 0;
					fprintf(stderr,"wrote %llu bytes to: %s\n",(unsigned long long)filegot,(filefd == STDOUT_FILENO) ? "(stdout)" : destpath);
				}

				k = TRY_SCOPE_COUNT + 1; /* break outer loop */
				break;
			}
		}
	}

	if (ok)
		printf("%s: no addresses worked! bad token or no network path?\n",argv[0]);

	return ok;
}
