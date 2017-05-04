/* (c)2017 ZeroTier, Inc. (Adam Ierymenko) -- MIT LICENSE */

#ifndef TOSS_BASE32_H
#define TOSS_BASE32_H

#include <stdint.h>

static const char base32_chars[32] = { 'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','2','3','4','5','6','7' };
static const uint8_t base32_bits[256] = {
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,26,27,28,29,30,31,0,0,0,0,0,0,0,0,0,0,1,2,3,4,5,
	6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,0,0,0,0,0,0,0,1,2,
	3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

static void base32_5_to_8(const uint8_t *in,char *out)
{
	out[0] = base32_chars[(in[0]) >> 3];
	out[1] = base32_chars[(in[0] & 0x07) << 2 | (in[1] & 0xc0) >> 6];
	out[2] = base32_chars[(in[1] & 0x3e) >> 1];
	out[3] = base32_chars[(in[1] & 0x01) << 4 | (in[2] & 0xf0) >> 4];
	out[4] = base32_chars[(in[2] & 0x0f) << 1 | (in[3] & 0x80) >> 7];
	out[5] = base32_chars[(in[3] & 0x7c) >> 2];
	out[6] = base32_chars[(in[3] & 0x03) << 3 | (in[4] & 0xe0) >> 5];
	out[7] = base32_chars[(in[4] & 0x1f)];
}

static void base32_8_to_5(const char *in,uint8_t *out)
{
	out[0] = ((base32_bits[(unsigned int)in[0]]) << 3) | (base32_bits[(unsigned int)in[1]] & 0x1C) >> 2;
	out[1] = ((base32_bits[(unsigned int)in[1]] & 0x03) << 6) | (base32_bits[(unsigned int)in[2]]) << 1 | (base32_bits[(unsigned int)in[3]] & 0x10) >> 4;
	out[2] = ((base32_bits[(unsigned int)in[3]] & 0x0F) << 4) | (base32_bits[(unsigned int)in[4]] & 0x1E) >> 1;
	out[3] = ((base32_bits[(unsigned int)in[4]] & 0x01) << 7) | (base32_bits[(unsigned int)in[5]]) << 2 | (base32_bits[(unsigned int)in[6]] & 0x18) >> 3;
	out[4] = ((base32_bits[(unsigned int)in[6]] & 0x07) << 5) | (base32_bits[(unsigned int)in[7]]);
}

#endif
