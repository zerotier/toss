#ifndef TOSS_SPECK_HASH_H
#define TOSS_SPECK_HASH_H

/* This is used for payload verification and generating a claim code.
 * At only 128 bits and built from a "weird" block cipher, it's should
 * not be considered a strong hash. Toss is not a crypto tool, so
 * use something like GPG to encrypt your content prior to transferring
 * it if you need better security. */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define SPECK_ROR(x, r) ((x >> r) | (x << (64 - r)))
#define SPECK_ROL(x, r) ((x << r) | (x >> (64 - r)))
#define SPECK_R(x, y, k) (x = SPECK_ROR(x, 8), x += y, x ^= k, y = SPECK_ROL(y, 3), y ^= x)
#define SPECK_ROUNDS 32

/* Speck: a super-tiny ARX block cipher (128-bit variant) */
/* https://en.wikipedia.org/wiki/Speck_%28cipher%29 */
static void speck_encrypt(uint64_t pt[2],uint64_t ct[2],uint64_t K[2])
{
	uint64_t y = pt[0], x = pt[1], b = K[0], a = K[1];
	SPECK_R(x, y, b);
	for (int i = 0; i < SPECK_ROUNDS - 1; i++) {
		SPECK_R(a, b, i);
		SPECK_R(x, y, b);
	}
	ct[0] = y;
	ct[1] = x;
}

/* Simple 128-bit Merkle–Damgård hash function built from Speck */
/* https://en.wikipedia.org/wiki/Merkle–Damgård_construction */

struct speck_hash
{
	uint64_t digest[2];
	uint64_t nextblk[2];
	unsigned long nextblkptr;
	unsigned long totallen;
};

static void speck_hash_reset(struct speck_hash *h)
{
	/* Silly arbitrary IV */
	h->digest[0] = 0xfeeddeadbabef00dULL;
	h->digest[1] = 0xfeeddeadd00df00dULL;
	h->nextblk[0] = 0;
	h->nextblk[1] = 0;
	h->nextblkptr = 0;
	h->totallen = 0;
}

static void speck_hash_update(struct speck_hash *h,const void *d,unsigned long l)
{
	uint64_t tmp[2];
	for(unsigned long i=0;i<l;++i) {
		h->nextblk[h->nextblkptr >> 3] |= ( ((uint64_t)((const uint8_t *)d)[i] & (uint64_t)0xff) << (8 * (h->nextblkptr & 7)) );
		if (++h->nextblkptr == 16) {
			speck_encrypt(h->digest,tmp,h->nextblk);
			h->digest[0] ^= tmp[0];
			h->digest[1] ^= tmp[1];
			h->nextblkptr = 0;
			h->nextblk[0] = 0;
			h->nextblk[1] = 0;
		}
	}
	h->totallen += l;
}

static void speck_hash_finalize(struct speck_hash *h,uint8_t digest[16])
{
	uint64_t pad[2],tmp[2];

	/* Hash any remaining input */
	if (h->nextblkptr)
		speck_encrypt(h->digest,tmp,h->nextblk);

	/* Merkle–Damgård length padding */
	pad[0] = h->totallen;
	pad[1] = ~h->totallen;
	speck_encrypt(h->digest,tmp,pad);
	h->digest[0] ^= tmp[0];
	h->digest[1] ^= tmp[1];

	/* Output digest in big-endian byte order */
	digest[0] = (uint8_t)((h->digest[0] >> 56) & 0xff);
	digest[1] = (uint8_t)((h->digest[0] >> 48) & 0xff);
	digest[2] = (uint8_t)((h->digest[0] >> 40) & 0xff);
	digest[3] = (uint8_t)((h->digest[0] >> 32) & 0xff);
	digest[4] = (uint8_t)((h->digest[0] >> 24) & 0xff);
	digest[5] = (uint8_t)((h->digest[0] >> 16) & 0xff);
	digest[6] = (uint8_t)((h->digest[0] >> 8) & 0xff);
	digest[7] = (uint8_t)(h->digest[0] & 0xff);
	digest[8] = (uint8_t)((h->digest[1] >> 56) & 0xff);
	digest[9] = (uint8_t)((h->digest[1] >> 48) & 0xff);
	digest[10] = (uint8_t)((h->digest[1] >> 40) & 0xff);
	digest[11] = (uint8_t)((h->digest[1] >> 32) & 0xff);
	digest[12] = (uint8_t)((h->digest[1] >> 24) & 0xff);
	digest[13] = (uint8_t)((h->digest[1] >> 16) & 0xff);
	digest[14] = (uint8_t)((h->digest[1] >> 8) & 0xff);
	digest[15] = (uint8_t)(h->digest[1] & 0xff);
}

#endif
