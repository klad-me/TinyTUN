#ifndef CRYPT_H
#define CRYPT_H


#include <stdint.h>


// 128-bit key
extern uint8_t key128[16];


// Hash-function to make 128-bit key from password
void makeKey128(const char *key_str);

// Get 128-bit random
void rand128(uint8_t *buf);

// Encrypt 128-bit data with 128-bit key
void encrypt128(uint8_t *buf, const uint8_t *key);

// Decrypt 128-bit data using 128-bit key
void decrypt128(uint8_t *buf, const uint8_t *key);

// Calc CRC16 for data
uint16_t crc16(uint16_t crc, const uint8_t *data, uint16_t size);



#endif
