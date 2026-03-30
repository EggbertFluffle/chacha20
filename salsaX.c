#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <memory.h>
#include <sys/types.h>

const size_t BLOCK_ALLOCATIONS[15][4] = {
/* 	CONST  KEY      BLK NONCE */
	{ 1, 	1,		 1,	 1 },	
	{ 2, 	4,		 1,	 2 },
	{ 4, 	8,		 1,	 3 },
	{ 7, 	12,		 2,	 4 },
	{ 9, 	20,		 2,	 5 },
	{ 12, 	28,		 3,	 6 },
	{ 18, 	36,		 3,	 7 },
	{ 21, 	48,		 4,	 8 },
	{ 27, 	60,		 4,	 9 },
	{ 34, 	72,		 5,	 10 },
	{ 40, 	88,		 5,	 11 },
	{ 51, 	100,	 6,	 12 },
	{ 57, 	120,	 6,	 13 },
	{ 68, 	136,	 7,	 14 },
	{ 78, 	156,	 7,	 15 }
};

#define get_block_allocation(n) BLOCK_ALLOCATIONS[n - 2]

#define const_size(n) get_block_allocation(n)[0]
#define key_size(n) get_block_allocation(n)[1]
#define block_size(n) get_block_allocation(n)[2]
#define nonce_size(n) get_block_allocation(n)[3]

#define const_start(n) (0)
#define key_start(n) (const_size(n))
#define block_start(n) (const_size(n) + key_size(n))
#define nonce_start(n) (const_size(n) + key_size(n) + block_size(n))

#define rotate(num, rots) ((num << rots) | (num >> (32 - rots)))

#define MSG_BUFFER 65536

const int ROUNDS = 20;
const int ITERATIONS = 10;

uint64_t total_rounds = 0;
uint64_t matrices_allocated = 0;

uint64_t rounding_time = 0;
uint64_t encrypting_time = 0;
uint64_t decrypting_time = 0;

const char* constant_phrase = "expand 32-byte k";

typedef struct {
	size_t size;
	uint32_t* data;
} salsax;

void salsax_print(salsax* salsa) {
	for (int i = 0; i < salsa->size; i++) {
		for(int j = 0; j < salsa->size; j++) {
			printf("%zd\t", salsa->data[salsa->size * i + j]);
		}
		printf("\n");
	}
}


salsax create_salsax(size_t size, const char* key, const char* nonce) {
	const size_t key_len = strlen(key);
	if (key_size(size) * 4 != key_len) {
		printf("Invalid key size %zd for salsa%zd", key_len, size);
		exit(-1);
	}

	const size_t nonce_len = strlen(nonce);
	if (nonce_size(size) * 4 != nonce_len) {
		printf("Invalid nonce size %zd for salsa%zd", nonce_len, size);
		exit(-1);
	}

	salsax salsa = {
		.size = size,
		.data = (uint32_t*)malloc(sizeof(uint32_t) * size * size)
	};
	
	// Copy the constant
	memcpy(salsa.data, constant_phrase, const_size(size) * 4);

	// Copy the key
	memcpy(salsa.data + key_start(size), key, key_size(size) * 4);
	
	// 0 out the block
	memset(salsa.data + block_start(size), 0, block_size(size) * 4);

	// Copy the nonce
	memcpy(salsa.data + nonce_start(size), nonce, nonce_size(size) * 4);

	return salsa;
}

void get_group_idx(size_t size, int iteration, bool diagonal, size_t* idx) {
	int i = 0;
	for(size_t j = 0; j < size; j++) {
		idx[i] = (j * size) + iteration + (diagonal ? ((iteration + j) % size) - iteration : 0);
		i++;
	}
}

void salsax_fractional_round(salsax* salsa, const size_t* idx) {
	size_t size = salsa->size;
	uint32_t elements[salsa->size];

	for(size_t i = 0; i < size; i++) {
		elements[i] = salsa->data[idx[i]];
	}

	size_t pair_count = size / 2;

	size_t triplets[pair_count][3];

	for (size_t i = 0; i < pair_count; i++) {
		triplets[i][0] = i * 2;
		triplets[i][1] = triplets[i][0] + 1;
		triplets[i][2] = (triplets[i][1] + 2) % size;
	}

	for (size_t i = 0; i < pair_count; i++) {
		if(i % 2 == 0) {
			elements[triplets[i][0]] += elements[triplets[i][1]];
			elements[triplets[i][2]] ^= elements[triplets[i][0]];
			elements[triplets[i][2]] = rotate(elements[triplets[i][2]], 16);
		} else {
			elements[triplets[i][0]] += elements[triplets[i][1]];
			elements[triplets[i][2]] ^= elements[triplets[i][0]];
			elements[triplets[i][2]] = rotate(elements[triplets[i][2]], 12);
		}
	}

	for (size_t i = 0; i < pair_count; i++) {
		if(i % 2 == 0) {
			elements[triplets[i][0]] += elements[triplets[i][1]];
			elements[triplets[i][2]] ^= elements[triplets[i][0]];
			elements[triplets[i][2]] = rotate(elements[triplets[i][2]], 8);
		} else {
			elements[triplets[i][0]] += elements[triplets[i][1]];
			elements[triplets[i][2]] ^= elements[triplets[i][0]];
			elements[triplets[i][2]] = rotate(elements[triplets[i][2]], 7);
		}
	}

	for(size_t i = 0; i < salsa->size; i++) {
		salsa->data[idx[i]] = elements[i];
	}
}

void salsax_get_chunk(salsax* salsa1, char* dest) {
	size_t size = salsa1->size;
	salsax salsa2 = {
		.data = (uint32_t*)dest,
		.size = size
	};
	memcpy(salsa2.data, salsa1->data, sizeof(uint32_t) * size * size);

	size_t columns[size][size];
	size_t diagonals[size][size];
	for(size_t i = 0; i < size; i++) {
		get_group_idx(size, i, false, columns[i]);
		get_group_idx(size, i, true, diagonals[i]);
	}

	for(int i = 0; i < 10; i++) {
		for(int j = 0; j < size; j++) {
			salsax_fractional_round(&salsa2, columns[j % size]);
		}

		for(int j = 0; j < size; j++) {
			salsax_fractional_round(&salsa2, diagonals[j % size]);
		}
	}

	for(int i = 0; i < salsa1->size * salsa1->size; i++) {
		salsa2.data[i] += salsa1->data[i];
	}

    salsa1->data[block_start(salsa1->size) + block_size(salsa1->size) - 1] += 1;
    memcpy(dest, salsa2.data, sizeof(uint32_t) * salsa1->size * salsa1->size);
}

void salsax_encrypt(salsax* salsa, char* msg, size_t len) {
	size_t salsa_length = salsa->size * salsa->size * 4;
	char chunk[salsa_length];

    for(size_t i = 0; i < len; i++) {
        if(i % salsa_length == 0) {
			salsax_get_chunk(salsa, chunk);
		}

        msg[i] = msg[i] ^ chunk[i % salsa_length];
    }
}

int main(int argc, char** argv) {
	if(argc != 6) {
		printf("Usage: salsax <SIZE> <KEY> <NOUCE> <INPUT_FILE> <OUTPUT_FILE>\n");
		exit(-1);
	}

	char* key = argv[2];
	char* nonce = argv[3];
	size_t size = atoi(argv[1]);

	salsax salsa = create_salsax(size, key, nonce);

	FILE* read_file = fopen(argv[4], "r");

	// Get size of input file
	fseek(read_file, 0L, SEEK_END);
	size_t msg_len = ftell(read_file);
	fseek(read_file, 0L, SEEK_SET);

	char msg_buffer[msg_len];
	fread(msg_buffer, sizeof(char), msg_len, read_file);
	fclose(read_file);
	
	salsax_encrypt(&salsa, msg_buffer, msg_len);

	FILE* write_file = fopen(argv[5], "w+");
	fwrite(msg_buffer, sizeof(char), msg_len, write_file);
	fclose(write_file);

	return 0;
}
