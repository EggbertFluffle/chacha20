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

chacha20 chacha20_create(const char* key, uint32_t counter) {
	// Key must be 256 bits
	assert(strlen(key) == 32);

	chacha20 out;
	memset((void*)out.data, 0, 64);

	// Insert the contant phrase
	for (int i = 0; i < 4; i++) {
		out.data[i] = *((uint32_t*) &constant_phrase[i*4]);
	}

	// Insert the key
	for (int i = 0; i < 8; i++) {
		out.data[i + 4] = *((uint32_t*) &key[i*4]);
	}

	// Insert the counter
	out.data[12] = counter;

	// Set the nonce to 0? (THIS MIGHT BE WRONG)
	for(int i = 0; i < 3; i++) {
		out.data[13 + i] = 0;
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

	A += B; D ^= A; D = rotate(D, 16);
	C += D; B ^= C; B = rotate(B, 12);
	A += B; D ^= A; D = rotate(D, 8);
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

char* chacha20_encrypt(chacha20 cha, const char* msg, size_t len) {
    char* out = (char*)malloc(sizeof(char) * len);
    uint8_t chunk[64];

    for(size_t i = 0; i < len; i++) {
        if(i % 64 == 0) {
			chacha20_get_chunk(&cha, chunk);
		}

        out[i] = msg[i] ^ chunk[i % 64];
    }

    return out;
}

// Same thing as encrypt
char* chacha20_decrypt(chacha20 cha, const char* d_msg, size_t len) {
	return chacha20_encrypt(cha, d_msg, len);
}

// Print chacha matrix contents
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
	// chacha20_print(cha);

	FILE *file = fopen("macbeth.txt", "r");

	// Get the length of the file
	fseek(file, 0L, SEEK_END);
	size_t file_size = ftell(file);
	fseek(file, 0L, SEEK_SET);

	// Read the file into memory
	char* text = (char*)malloc(sizeof(char) * file_size);
	fgets(text, file_size, file);

	printf("text size: %d\n", strlen(text));

	// Encrypt the message
	char* e_msg = chacha20_encrypt(cha, text, file_size);
	// printf("%s", e_msg);

	// Decrypt the message
	char* d_msg = chacha20_decrypt(cha, e_msg, file_size);
	printf("d_msg size: %d", strlen(d_msg));
	// printf("%s", d_msg);
}
