#include <stdio.h>
#include <immintrin.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <openssl/sha.h>
#include "libbase58.h"
#include "sha256.h"


struct mask {
	uint8_t add_data[32];
	uint8_t sub_data[32];
};

struct mask masks[63];
int masks_cnt;


static const int8_t b58digits_map[] = {
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
	-1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
	22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
	-1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
	47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
};
char b58alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";


void reverse24(uint8_t* p) {
	for(int i = 0; i < 12; i++) {
		uint8_t tmp = p[i];
		p[i] = p[23 - i];
		p[23 - i] = tmp;
	}
}


struct bucket {
	uint8_t content[21];
	int cnt_suffixes;
	uint32_t suffixes[64];
	uint64_t bitmasks[64];
};
struct bucket active_buckets[8];
int cnt_active_buckets;
int c;

void flush_buckets() {
	if(cnt_active_buckets == 8) {
		c += 8;

		uint8_t content[8][32];
		for(int i = 0; i < 8; i++) {
			memcpy(content[i], active_buckets[i].content, sizeof(active_buckets[i].content));
		}
		struct bucket* bucket1 = &active_buckets[0];

		uint8_t sha256_digest1[8][32];
		sha256_parallel8(content, sizeof(bucket1->content), sha256_digest1);

		uint8_t sha256_digest2[8][32];
		sha256_parallel8(sha256_digest1, sizeof(sha256_digest1[0]), sha256_digest2);

		uint32_t sha[8];
		for(int i = 0; i < 8; i++) {
			sha[i] = *(uint32_t*)sha256_digest2[i];
		}

		for(int i = 0; i < 8; i++) {
			struct bucket* bucket = &active_buckets[i];
			for(int j = 0; j < bucket->cnt_suffixes; j++) {
				if(bucket->suffixes[j] == sha[i]) {
					printf("%lx\n", bucket->bitmasks[j]);
				}
			}
		}
	} else {
		for(int i = 0; i < cnt_active_buckets; i++) {
			c++;

			struct bucket* bucket = &active_buckets[i];

			uint8_t sha256_digest1[32];
			SHA256(bucket->content, sizeof(bucket->content), sha256_digest1);
			uint8_t sha256_digest2[32];
			SHA256(sha256_digest1, sizeof(sha256_digest1), sha256_digest2);

			uint32_t sha = *(uint32_t*)sha256_digest2;

			for(int i = 0; i < bucket->cnt_suffixes; i++) {
				if(bucket->suffixes[i] == sha) {
					printf("%lx\n", bucket->bitmasks[i]);
				}
			}
		}
	}

	cnt_active_buckets = 0;
}

void new_bucket(__m256i data) {
	if(cnt_active_buckets == sizeof(active_buckets) / sizeof(active_buckets[0])) {
		flush_buckets();
	}
	struct bucket* bucket = &active_buckets[cnt_active_buckets];
	bucket->cnt_suffixes = 0;
	bucket->content[0] = 0;
	uint8_t tmp[32];
	_mm256_storeu_si256((__m256i*)tmp, data);
	for(int i = 0; i < 20; i++) {
		bucket->content[1 + i] = tmp[23 - i];
	}
	cnt_active_buckets++;
}

void add_to_bucket(uint32_t suffix, uint32_t bitmask) {
	assert(cnt_active_buckets > 0);
	struct bucket* bucket = &active_buckets[cnt_active_buckets - 1];
	assert(bucket->cnt_suffixes < sizeof(bucket->suffixes) / sizeof(bucket->suffixes[0]));
	bucket->suffixes[bucket->cnt_suffixes] = suffix;
	bucket->bitmasks[bucket->cnt_suffixes] = bitmask;
	bucket->cnt_suffixes++;
}


int main(int argc, char** argv) {
	if(argc <= 1 || strlen(argv[1]) > 40) {
		printf("Usage: %s <lowercase_of_bitcoin_address>\n", argv[0]);
		return 0;
	}

	char* s = argv[1];

	for(char* p = s; *p; p++) {
		*p = toupper((int)*p);

		switch(*p) {
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
			case 'L':
				break;

			case 'I':
				*p = 'i';
				break;

			case 'O':
				*p = 'o';
				break;

			case 'A':
			case 'B':
			case 'C':
			case 'D':
			case 'E':
			case 'F':
			case 'G':
			case 'H':
			case 'J':
			case 'K':
			case 'M':
			case 'N':
			case 'P':
			case 'Q':
			case 'R':
			case 'S':
			case 'T':
			case 'U':
			case 'V':
			case 'W':
			case 'X':
			case 'Y':
			case 'Z': {
				int power58 = strlen(s) - 1 - (p - s);
				assert(b58digits_map[*p] != -1 && b58digits_map[tolower((int)*p)] != -1);

				char diff_str[128];
				diff_str[0] = b58alphabet[b58digits_map[tolower((int)*p)] - b58digits_map[*p]];
				memset(diff_str + 1, '1', power58);
				diff_str[1 + power58] = '\0';

				uint8_t diff_data[24];
				size_t binsz = sizeof(diff_data);
				if(!b58tobin(diff_data, &binsz, diff_str, 0)) {
					break;
				}

				if(masks_cnt == sizeof(masks) / sizeof(masks[0])) {
					fprintf(stderr, "Too many letters.\n");
					return 1;
				}
				reverse24(diff_data);

				memcpy(masks[masks_cnt].add_data, diff_data, sizeof(diff_data));

				for(int i = 0; i < 24; i++) {
					masks[masks_cnt].sub_data[i] = diff_data[i] ^ 255;
				}
				uint8_t carry = 1;
				for(int i = 0; i < 24; i++) {
					if((uint8_t)(masks[masks_cnt].sub_data[i] + carry) < masks[masks_cnt].sub_data[i]) {
						masks[masks_cnt].sub_data[i] += carry;
						carry = 1;
					} else {
						masks[masks_cnt].sub_data[i] += carry;
						carry = 0;
					}
				}

				masks_cnt++;
				break;
			}

			default:
				fprintf(stderr, "Invalid base58 data.\n");
				return 1;
		}
	}

	uint64_t iter_data[4];
	iter_data[3] = 0;
	size_t binsz = 24;
	if(!b58tobin(iter_data, &binsz, s, 0)) {
		fprintf(stderr, "Could not decode base58 data.\n");
		return 1;
	}
	reverse24((uint8_t*)iter_data);


	struct mask* base_mask = masks + masks_cnt - 1;
	uint64_t prev_bitmask = 0;

	// bitmask == 0
	__m256i prev_iter_data = _mm256_lddqu_si256((__m256i*)iter_data);
	new_bucket(prev_iter_data);
	add_to_bucket(0, 0);

	uint64_t tightloop_iter_data[4];
	memcpy(tightloop_iter_data, iter_data, sizeof(iter_data));

	for(uint64_t bitmask_generator = 1; bitmask_generator != (1ULL << masks_cnt); bitmask_generator++) {
		uint64_t bitmask = bitmask_generator ^ (bitmask_generator >> 1);
		struct mask* mask = base_mask;
		uint64_t tmp1;
		uint64_t* diff_data;
		asm volatile(
			"xorq %1, %2;"
			"tzcntq %2, %0;"
			"shlq $6, %0;"
			"subq %0, %4;"
			"movq %4, %3;"
			"movq %4, %0;"
			"add $32, %0;"
			"testq %1, %2;"
			"cmove %0, %3;"
			"movq (%3), %0;"
			"addq %0, %5;"
			"movq 0x8(%3), %0;"
			"adcq %0, %6;"
			"movq 0x10(%3), %0;"
			"adcq %0, %7;"
			"movq %1, %2;"
			: "=&r"(tmp1), "+r"(bitmask), "+r"(prev_bitmask), "=&r"(diff_data), "+r"(mask), "+r"(tightloop_iter_data[0]), "+r"(tightloop_iter_data[1]), "+r"(tightloop_iter_data[2])
			:
			: "memory", "flags"
		);

		prev_iter_data = _mm256_insert_epi32(prev_iter_data, ((uint32_t*)tightloop_iter_data)[0], 0);
		if(
			tightloop_iter_data[0] != prev_iter_data[0] ||
			tightloop_iter_data[1] != prev_iter_data[1] ||
			tightloop_iter_data[2] != prev_iter_data[2]
		) {
			prev_iter_data = _mm256_lddqu_si256((__m256i*)tightloop_iter_data);
			new_bucket(prev_iter_data);
		}

		add_to_bucket(htonl(*(uint32_t*)tightloop_iter_data), bitmask);
	}

	flush_buckets();

	printf("SHA was called %d times\n", 2 * c);

	exit(0);
}