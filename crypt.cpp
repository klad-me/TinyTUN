#include "crypt.h"

#include <string.h>
#include <stdlib.h>


uint8_t key128[16];


// https://en.wikipedia.org/wiki/XTEA
static void xtea_encipher(unsigned int num_rounds, uint32_t *v, uint32_t const *k) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], sum=0, delta=0x9E3779B9;
    for (i=0; i < num_rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum>>11) & 3]);
    }
    v[0]=v0; v[1]=v1;
}

static void xtea_decipher(unsigned int num_rounds, uint32_t *v, uint32_t const *k) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], delta=0x9E3779B9, sum=delta*num_rounds;
    for (i=0; i < num_rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum>>11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
    }
    v[0]=v0; v[1]=v1;
}


void makeKey128(const char *key_str)
{
    uint8_t tmp[16];
    
    // Making 16-byte string
    uint8_t l=0;
    while (l < 16)
    {
	uint8_t n=strlen(key_str);
	if (n > 16-l) n=16-l;
	memcpy(tmp+l, key_str, n);
	l+=n;
    }
    
    // Making left side
    memcpy(key128, tmp, 8);
    xtea_encipher(32, (uint32_t*)(key128+0), (const uint32_t*)tmp);
    
    // Making right side
    memcpy(tmp, key128, 8);
    xtea_encipher(32, (uint32_t*)(key128+8), (const uint32_t*)tmp);
}


void rand128(uint8_t *buf)
{
    for (uint8_t i=0; i<16; i++)
	buf[i]=rand() & 0xff;
}


void encrypt128(uint8_t *buf, const uint8_t *key)
{
#ifdef UNALIGNED_32BIT
    xtea_encipher(32, (uint32_t*)(buf+0), (const uint32_t*)key);
    xtea_encipher(32, (uint32_t*)(buf+8), (const uint32_t*)key);
#else
    // Checking buffer alignment
    if (! (((uint64_t)buf) & 3))
    {
	// Well-aligned
	xtea_encipher(32, (uint32_t*)(buf+0), (const uint32_t*)key);
	xtea_encipher(32, (uint32_t*)(buf+8), (const uint32_t*)key);
    } else
    {
	// Use temp buffer
	uint32_t tmp[4];
	memcpy(tmp, buf, 16);
	xtea_encipher(32, tmp+0, (const uint32_t*)key);
	xtea_encipher(32, tmp+2, (const uint32_t*)key);
	memcpy(buf, tmp, 16);
    }
#endif
}


void decrypt128(uint8_t *buf, const uint8_t *key)
{
#ifdef UNALIGNED_32BIT
    xtea_decipher(32, (uint32_t*)(buf+0), (const uint32_t*)key);
    xtea_decipher(32, (uint32_t*)(buf+8), (const uint32_t*)key);
#else
    // Checking buffer alignment
    if (! (((uint64_t)buf) & 3))
    {
	// Well-aligned
	xtea_decipher(32, (uint32_t*)(buf+0), (const uint32_t*)key);
	xtea_decipher(32, (uint32_t*)(buf+8), (const uint32_t*)key);
    } else
    {
	// Use temp buffer
	uint32_t tmp[4];
	memcpy(tmp, buf, 16);
	xtea_decipher(32, tmp+0, (const uint32_t*)key);
	xtea_decipher(32, tmp+2, (const uint32_t*)key);
	memcpy(buf, tmp, 16);
    }
#endif
}


uint16_t crc16(uint16_t crc, const uint8_t *data, uint16_t size)
{
    uint16_t i;
    uint8_t x,cnt;
    
    for (i=0; i<size; i++)
    {
        x=data[i];
        for (cnt=0; cnt<8; cnt++)
        {
            if ((x^crc)&1) crc=((crc^0x4002)>>1)|0x8000; else
                           crc=crc>>1;
            x>>=1;
        }
    }
    
    return crc;
}
