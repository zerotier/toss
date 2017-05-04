#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "speck_hash.h"

int main(int argc,char **argv)
{
	static uint8_t tmp[1000001];
	uint8_t digest[16];
	struct speck_hash sh;

	for(long i=0;i<sizeof(tmp);++i)
		tmp[i] = (uint8_t)i;

	speck_hash_reset(&sh);
	speck_hash_update(&sh,tmp,sizeof(tmp));
	speck_hash_finalize(&sh,digest);

	for(int i=0;i<16;++i)
		printf("%.2x",(unsigned int)digest[i]);
	printf("\n");

	return 0;
}
