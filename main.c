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
	uint8_t add_data[24];
	uint8_t sub_data[24];
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
	uint64_t bitmasks[32]; // 4 checksum bytes are encoded to at most 6 characters, but the first is always a digit, hence 2**5
	uint32_t suffixes[32];
	int cnt_suffixes;
	uint8_t content[21];
} __attribute__((aligned(1024)));
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

			int j = 0;
			__m256i mask = _mm256_set1_epi32(sha[i]);
			while(j + 8 <= bucket->cnt_suffixes) {
				uint32_t cmp = _mm256_movemask_epi8(_mm256_cmpeq_epi32(_mm256_lddqu_si256(bucket->suffixes + j), mask));
				cmp &= 0x11111111;
				while(__builtin_expect(cmp, 0)) {
					int j1 = j + (__builtin_ffs(cmp) - 1) / 4;
					cmp &= cmp - 1;

					printf("# %lx (bucket %d, sha %x, suffix %x, content ", bucket->bitmasks[j1], i, sha[i], bucket->suffixes[j1]);
					for(int k = 0; k < 21; k++) {
						printf("%02x", bucket->content[k]);
					}
					printf(")\n");
				}
				j += 8;
			}

			/*
			for(; j < bucket->cnt_suffixes; j++) {
				if(bucket->suffixes[j] == sha[i]) {
					printf("@ %lx (bucket %d, sha %x, suffix %x, content ", bucket->bitmasks[j], i, sha[i], bucket->suffixes[j]);
					for(int k = 0; k < 21; k++) {
						printf("%02x", bucket->content[k]);
					}
					printf(")\n");
				}
			}
			*/
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

struct bucket* new_bucket(uint8_t* data) {
	if(cnt_active_buckets == sizeof(active_buckets) / sizeof(active_buckets[0])) {
		flush_buckets();
	}
	struct bucket* bucket = &active_buckets[cnt_active_buckets];
	bucket->cnt_suffixes = 0;
	memset(bucket->suffixes, 0, sizeof(bucket->suffixes));
	bucket->content[0] = 0;
	for(int i = 0; i < 20; i++) {
		bucket->content[1 + i] = data[23 - i];
	}
	cnt_active_buckets++;
	return bucket;
}

void add_to_bucket(uint32_t suffix, uint32_t bitmask, struct bucket* bucket) {
	int suf = bucket->cnt_suffixes;
	assert(suf < sizeof(bucket->bitmasks) / sizeof(bucket->bitmasks[0]));
	bucket->suffixes[suf] = suffix;
	bucket->bitmasks[suf] = bitmask;
	bucket->cnt_suffixes++;
}


#define ADD24BYTES(dst, src) { \
	int carry = 0; \
	for(int j = 0; j < 3; j++) { \
		uint64_t next_value = ((uint64_t*)src)[j] + ((uint64_t*)dst)[j]; \
		int next_carry = next_value < ((uint64_t*)src)[j] || next_value + carry < next_value; \
		next_value += carry; \
		carry = next_carry; \
		((uint64_t*)dst)[j] = next_value; \
	} \
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


	uint64_t limit = masks_cnt < 2 ? 1 : (1ULL << (masks_cnt - 2));
	uint64_t shift = masks_cnt < 2 ? 0 : masks_cnt - 2;

	uint64_t iter_data[3][4]; // the array index order is swapped for optimization
	uint8_t prev_iter_data[4][24];
	memset(prev_iter_data, 0, sizeof(prev_iter_data));

	for(int high = 0; high < 4; high++) {
		uint8_t tmp_iter_data[24];
		size_t binsz = sizeof(tmp_iter_data);
		if(!b58tobin(tmp_iter_data, &binsz, s, 0)) {
			fprintf(stderr, "Could not decode base58 data.\n");
			return 1;
		}
		reverse24(tmp_iter_data);

		for(int i = 0; i < 2; i++) {
			if(((high >> i) & 1) && i < masks_cnt) {
				ADD24BYTES(tmp_iter_data, masks[i].add_data)
			}
		}

		for(int i = 0; i < 3; i++) {
			iter_data[i][high] = ((uint64_t*)tmp_iter_data)[i];
		}
	}

	struct bucket* active_bucket[4];

	uint64_t prev_bitmask_low = 0;
	for(uint64_t bitmask_generator = 0; bitmask_generator < limit; bitmask_generator++) {
		uint64_t bitmask_low = (bitmask_generator ^ (bitmask_generator >> 1));

		if(bitmask_generator != 0) {
			int i = __builtin_ffsll(bitmask_low ^ prev_bitmask_low) - 1;
			assert(i >= 0 && i < masks_cnt - 2);
			struct mask* mask = &masks[masks_cnt - 1 - i];
			uint8_t* diff_data = ((bitmask_low >> i) & 1) ? mask->add_data : mask->sub_data;

			uint64_t* src = diff_data;
			__m256i carry256 = _mm256_setzero_si256();

			for(int j = 0; j < 3; j++) {
				__m256i src256 = _mm256_set1_epi64x(src[j]);
				__m256i dst256 = _mm256_lddqu_si256((__m256i*)iter_data[j]);
				__m256i next_value256 = _mm256_add_epi64(src256, dst256);

				__m256i topbit = _mm256_set1_epi64x(1ULL << 63);
				__m256i next_value256sat = _mm256_add_epi64(topbit, next_value256);
				__m256i src256sat = _mm256_add_epi64(topbit, src256);

				__m256i next_carry256 = _mm256_or_si256(
					_mm256_cmpgt_epi64(src256sat, next_value256sat),
					_mm256_cmpgt_epi64(next_value256sat, _mm256_add_epi64(next_value256sat, carry256))
				);

				next_value256 = _mm256_add_epi64(next_value256, carry256);
				carry256 = _mm256_and_si256(next_carry256, _mm256_set1_epi64x(1));
				dst256 = next_value256;

				_mm256_storeu_si256((__m256i*)iter_data[j], dst256);
			}
		}

		for(int high = 0; high < 4; high++) {
			if(
				bitmask_generator == 0 ||
				(iter_data[0][high] >> 32) != (((uint64_t*)prev_iter_data[high])[0] >> 32) ||
				iter_data[1][high] != ((uint64_t*)prev_iter_data[high])[1] ||
				iter_data[2][high] != ((uint64_t*)prev_iter_data[high])[2]
			) {
				for(int i = 0; i < 3; i++) {
					((uint64_t*)prev_iter_data[high])[i] = iter_data[i][high];
				}
				active_bucket[high] = new_bucket(prev_iter_data[high]);
			}

			uint64_t bitmask = bitmask_low | (high << shift);
			add_to_bucket(htonl((uint32_t)iter_data[0][high]), bitmask, active_bucket[high]);
		}

		prev_bitmask_low = bitmask_low;
	}

	flush_buckets();

	printf("SHA was called %d times\n", 2 * c);

	exit(0);
}

// 33s -- with SHA
// 16s -- without SHA
// 10s -- without bucketing