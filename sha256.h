#pragma once


#include <stdint.h>

void sha256_parallel8(uint8_t s[8][32], uint32_t size, uint8_t result[8][32]);