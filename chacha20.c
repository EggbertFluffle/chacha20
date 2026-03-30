#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <sys/types.h>

// Possibilities for improvements
// 		1. SIMD parallelism: not a real modification
// 		2. ChachaX: variable rounds trading speed for security
// 		3. Increase the amount of state 6x6 grid, 8x8 grid
// 		4. Change the rotation constatnts and test avalanche effect (16, 12, 8, 7)

//		5. Change cells in "columns" and "diagonals"
//		6. Shrink the constants to include MORE key

// Constant phrase that takes up blocks 0, 1, 2, 3
const char* constant_phrase = "expand 32-byte k";

typedef struct {
	uint32_t data[16];
} chacha20;

// Print chacha matrix contents
void chacha20_print(chacha20* cha) {
	for(int i = 0; i < 16; i++) {
		printf("%zd\t", cha->data[i]);
		if(i % 4 == 3) {
			printf("\n");
		}
	}
}

// Indecies for quarter-rounds over columns and diagonals
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

chacha20 chacha20_create(const char* key, const char* nonce) {
	// Key must be 256 bits
	assert(strlen(key) == 32);
	assert(strlen(nonce) == 12);

	chacha20 out;
	memset((void*)out.data, 0, 64);

	// Insert the contant phrase
	for (int i = 0; i < 4; i++) {
		out.data[i] = *((uint32_t*) &constant_phrase[i * 4]);
	}

	// Insert the key
	for (int i = 0; i < 8; i++) {
		out.data[i + 4] = *((uint32_t*) &key[i*4]);
	}

	// Insert the counter
	out.data[12] = 0;

	for (int i = 0; i < 3; i++) {
		out.data[13 + i] = *((uint32_t*) &nonce[i*4]);;
	}

	return out;
}

// Rotate a 32bit integer with wrapping
uint32_t rotate(uint32_t num, size_t rots) {
	return (num << rots) | (num >> (32 - rots));
}

// Make 1 quarter round on the matrix
void chacha20_quarter_round(chacha20* cha, const size_t* idx) {
	uint32_t A = cha->data[idx[0]];
	uint32_t B = cha->data[idx[1]];
	uint32_t C = cha->data[idx[2]];
	uint32_t D = cha->data[idx[3]];

	// A B C D

	// printf("[%zd] [%zd] [%zd] [%zd]\n", A, B, C, D);

	// printf("16 (%zd) (%zd) (%zd)\n", A, B, D);
	A += B; D ^= A; D = rotate(D, 16);
	// printf("12 (%zd) (%zd) (%zd)\n", C, D, B);
	C += D; B ^= C; B = rotate(B, 12);
	// printf("8  (%zd) (%zd) (%zd)\n", A, B, D);
	A += B; D ^= A; D = rotate(D, 8);
	// printf("7  (%zd) (%zd) (%zd)\n", C, D, B);
	C += D; B ^= C; B = rotate(B, 7);

	cha->data[idx[0]] = A;
	cha->data[idx[1]] = B;
	cha->data[idx[2]] = C;
	cha->data[idx[3]] = D;
}

void chacha20_get_chunk(chacha20* cha1, uint8_t out[64]) {
    chacha20 cha2;
    memcpy(cha2.data, cha1->data, 64);

    for(int i = 0; i < 10; i++) {
        for(int j = 0; j < 4; j++) {
			chacha20_quarter_round(&cha2, columns[j]);
		}

        for(int j = 0; j < 4; j++) {
			chacha20_quarter_round(&cha2, diagonals[j]);
		}
    }

    for(int i = 0; i < 16; i++) {
        cha2.data[i] += cha1->data[i];
	}

    cha1->data[12] += 1;
    memcpy(out, cha2.data, 64);
}

void chacha20_encrypt(chacha20 cha, char* msg, size_t len) {
    uint8_t chunk[64];

    for(size_t i = 0; i < len; i++) {
        if(i % 64 == 0) {
			chacha20_get_chunk(&cha, chunk);
		}

        msg[i] ^= chunk[i % 64];
    }
}

// Same thing as encrypt
void chacha20_decrypt(chacha20 cha, char* d_msg, size_t len) {
	chacha20_encrypt(cha, d_msg, len);
}

int main(int argc, char** argv) {
	if(argc != 5) {
		printf("Usage: chacha20 <KEY> <NOUCE> <INPUT_FILE> <OUTPUT_FILE>\n");
		exit(-1);
	}

	chacha20 cha = chacha20_create(argv[1], argv[2]);

	FILE* read_file = fopen(argv[3], "r");
	fseek(read_file, 0L, SEEK_END);
	size_t msg_len = ftell(read_file);
	fseek(read_file, 0L, SEEK_SET);

	char msg_buffer[msg_len];
	fread(msg_buffer, sizeof(char), msg_len, read_file);
	fclose(read_file);

	chacha20_encrypt(cha, msg_buffer, msg_len);

	FILE* write_file = fopen(argv[4], "w+");
	fwrite(msg_buffer, sizeof(char), msg_len, write_file);
	fclose(write_file);

	return 0;
}
