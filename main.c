#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <openssl/sha.h>
#include "libbase58.h"


struct mask {
	uint8_t add_data[24];
	uint8_t sub_data[24];
};

struct mask masks[31];
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

	uint8_t iter_data[24];
	size_t binsz = sizeof(iter_data);
	if(!b58tobin(iter_data, &binsz, s, 0)) {
		fprintf(stderr, "Could not decode base58 data.\n");
		return 1;
	}
	reverse24(iter_data);


	uint8_t prev_iter_data[24];
	memset(prev_iter_data, 0, sizeof(prev_iter_data));

	int c = 0;

	uint32_t active_sha = 0;
	uint32_t active_bitmask = 0;
	for(uint32_t bitmask_generator = 0; bitmask_generator < (1 << masks_cnt); bitmask_generator++) {
		if(bitmask_generator != 0) {
			uint32_t bitmask = bitmask_generator ^ (bitmask_generator >> 1);

			int i = __builtin_ffs(bitmask ^ active_bitmask) - 1;
			assert(i >= 0 && i < masks_cnt);

			struct mask mask = masks[masks_cnt - 1 - i];
			int carry = 0;
			uint8_t* diff_data = ((bitmask >> i) & 1) ? mask.add_data : mask.sub_data;
			for(int j = 0; j < 3; j++) {
				uint64_t next_value = ((uint64_t*)iter_data)[j] + ((uint64_t*)diff_data)[j];
				int next_carry = next_value < ((uint64_t*)iter_data)[j] || next_value + carry < next_value;
				next_value += carry;
				carry = next_carry;
				((uint64_t*)iter_data)[j] = next_value;
			}

			active_bitmask = bitmask;
		}

		if(
			active_bitmask == 0 ||
			((uint32_t*)iter_data)[1] != ((uint32_t*)prev_iter_data)[1] ||
			((uint64_t*)iter_data)[1] != ((uint64_t*)prev_iter_data)[1] ||
			((uint64_t*)iter_data)[2] != ((uint64_t*)prev_iter_data)[2]
		) {
			uint8_t tmp[21];
			tmp[0] = 0;
			for(int i = 0; i < 20; i++) {
				tmp[1 + i] = iter_data[23 - i];
			}
			uint8_t sha256_digest1[32];
			SHA256(tmp, sizeof(tmp), sha256_digest1);
			uint8_t sha256_digest2[32];
			SHA256(sha256_digest1, sizeof(sha256_digest1), sha256_digest2);
			c++;
			active_sha = *(uint32_t*)sha256_digest2;
			memcpy(prev_iter_data, iter_data, sizeof(iter_data));
		}

		if(htonl(*(uint32_t*)iter_data) == active_sha) {
			printf("%d\n", active_bitmask);
		}
	}

	printf("SHA was called %d times\n", 2 * c);

	exit(0);
}