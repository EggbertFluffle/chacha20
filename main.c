#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <sys/types.h>

// Chachat format
// 4 x 4 grid, every cell is 32 bits => 512 bits total
// First 4 are constants
// Next 8 are keys
// 1 is block number (sometimes 2)
// 3 is nonce (sometimes 2)

// We do 20 rounds of mixing. Each round consisting of 
//  - 4 mixes in columns
//  - 4 mixes in diagonals (gives good diffusion)

// During a quarter round, you have the A, B, C, and D blocks:
// 1. A = A + B

const char* constant_phrase = "expand 32-byte k";

typedef struct {
	uint32_t data[16];
} chacha20;

const size_t columns[4][4] = {
	{0, 4, 8, 12},
	{1, 5, 9, 13},
	{2, 6, 10, 14},
	{3, 7, 11, 15}
};

const size_t diagonals[4][4] = {
	{0, 5, 10, 15},
	{1, 6, 11, 12},
	{2, 7, 8, 13},
	{3, 4, 9, 14}
};

chacha20 chacha20_create(const char* key, uint32_t counter) {
	// Key must be 256 bits
	assert(strlen(key) == 32);

	chacha20 out;
	memset((void*)out.data, 0, 64);

	// Insert the contant phrase
	for (int i = 0; i < 4; i++) {
		out.data[i] = *((uint32_t*) &constant_phrase[i*4]);
	}

	for (int i = 0; i < 8; i++) {
		out.data[i + 4] = *((uint32_t*) &key[i*4]);
	}

	out.data[13] = counter;

	for(int i = 0; i < 3; i++) {
		out.data[14 + i] = 0;
	}

	return out;
}

uint32_t rotate(uint32_t num, size_t rots) {
	return (num << rots) | (num >> (32 - rots));
}

void chacha20_quarter_round(chacha20* cha, const size_t* idx) {
	uint32_t A = cha->data[idx[0]];
	uint32_t B = cha->data[idx[1]];
	uint32_t C = cha->data[idx[2]];
	uint32_t D = cha->data[idx[3]];

	A = A + B;
	D = D ^ A;
	D = rotate(D, 16);
	C = D + C;
	B = B ^ C;
	B = rotate(B, 12);
	A = A + B;
	cha->data[idx[0]] = A; // A done
	D = D ^ A;
	D = rotate(D, 8);
	cha->data[idx[3]] = D; // D done
	C = C + D;
	cha->data[idx[2]] = C; // C done
	B = B ^ C;
	B = rotate(B, 7);
	cha->data[idx[1]] = B; // B done
}

// Gives a uint8_t[64]
char* chacha20_get_chunk(chacha20* cha1) {
	chacha20* cha2 = (chacha20*)malloc(sizeof(chacha20));
	*cha2 = *cha1;

	for(int i = 0; i < 10; i++) {
		for(int j = 0; j < 4; j++) {
			chacha20_quarter_round(cha2, columns[j]);
		}

		for(int j = 0; j < 4; j++) {
			chacha20_quarter_round(cha2, diagonals[j]);
		}
	}

	for(int i = 0; i < 16; i++) {
		cha2->data[i] += cha1->data[i];
	}

	cha1->data[15] += 1;

	return (char*) cha2->data;
}

char* chacha20_encrypt(chacha20 cha, const char* msg, size_t len) {
	char* out = (char*)malloc(sizeof(char) * len);

	char* key_chunk = NULL;
	for(size_t i = 0; i < len; i++) {
		if(i % 64 == 0) {
			if(key_chunk != NULL) free(key_chunk);
			key_chunk = chacha20_get_chunk(&cha);
		}

		out[i] = msg[i] ^ key_chunk[i % 64];
	}

	free(key_chunk);
	return out;
}

char* chacha20_decrypt(chacha20 cha, const char* d_msg, size_t len) {
	return chacha20_encrypt(cha, d_msg, len);
}

void chacha20_print(chacha20 cha) {
	for(int i = 0; i < 16; i++) {
		printf("%d ", cha.data[i]);
		if(i % 4 == 3) {
			printf("\n");
		}
	}
}

int main() {
	chacha20 cha = chacha20_create("helloworhelloworhelloworhellowor", 0);
	chacha20_print(cha);

	FILE *file = fopen("macbeth.txt", "r");
	fseek(file, 0L, SEEK_END);
	size_t file_size = ftell(file);
	fseek(file, 0L, SEEK_SET);
	char* text = (char*)malloc(sizeof(char) * file_size);
	fgets(text, file_size, file);

	printf("text size: %d\n", strlen(text));

	char* e_msg = chacha20_encrypt(cha, text, file_size);
	printf("%s", e_msg);

	char* d_msg = chacha20_decrypt(cha, e_msg, file_size);
	printf("d_msg size: %d", strlen(d_msg));
	printf("%s", d_msg);
}
