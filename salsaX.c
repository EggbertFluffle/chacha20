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

const int ROUNDS = 20;
const int ITERATIONS = 10;

// Telemetry and testing
uint64_t total_rounds = 0;
uint64_t matrices_allocated = 0;

uint64_t rounding_time = 0;
uint64_t encrypting_time = 0;
uint64_t decrypting_time = 0;

// Constant phrase that takes up blocks 0, 1, 2, 3
// New constant phrase must be able to handle the maximum of 312 bytes
const char* constant_phrase = "expand 32-byte k";

typedef struct {
	size_t size;
	uint32_t* data;
} salsax;

salsax create_salsax(size_t size, const char* key) {
	const size_t key_size = strlen(key);
	if (key_size(size) * 4 <= key_size) {
		printf("Invalid key size %zd for salsa%zd", key_size, size);
		exit(-1);
	}

	salsax salsa = {
		.size = size,
		.data = (uint32_t*)malloc(sizeof(uint32_t) * size * size)
	};
	
	// Insert the constant phrase
	memcpy(salsa.data, constant_phrase, const_size(size) * 4);

	// Insert user key
	memcpy(salsa.data + key_start(size), key, key_size(size) * 4);
	
	// TODO: Determine if we should set block and nonce to zero
	memset(salsa.data + block_start(size), 0, block_size(size));
	memset(salsa.data + nonce_start(size), 0, nonce_size(size));

	return salsa;
}

// Get the indicies of the group for the next fractional round
void get_group_idx(size_t size, int iteration, bool diagonal, size_t* idx) {
	bool odd = size % 2 == 1;

	for(size_t i = 0; i < size; i++) {

	}

	if(odd) {
		idx[size - 1] = 
	}
}

// TODO: When picking the elements from a row, put the id of the
// the left out element, equal to m, where m is the group we are
// fractional rounding. Basically, if the size of the salsa is 5
// and we are doing a fractional_round on column 3, put C at the
// end of the list of elements, bringing all other elements down
void salsax_fractional_round(salsax* salsa, const size_t* idx) {
	uint32_t elements[salsa->size];
	for(size_t i = 0; i < salsa->size; i++) {
		elements[i] = salsa->data[idx[i]];
	}

	bool odd_salsa = salsa->size % 2 == 1;
	size_t ess_count = odd_salsa ? salsa->size - 1 : salsa->size;
	size_t pair_count = ess_count / 2;

	size_t triplets[3][pair_count];

	// We include the first pass here for efficiency
	for (size_t i = 0; i < pair_count; i++) {
		if(i % 2 == 0) {
			triplets[i][0] = ess_count - i;
			triplets[i][1] = ess_count - i - 1;
			triplets[i][2] = i - 1;

			elements[triplets[i][0]] += elements[triplets[i][1]];
			elements[triplets[i][2]] ^= elements[triplets[i][0]];
			elements[triplets[i][2]] = rotate(elements[triplets[i][2]], 16);
		} else {
			triplets[i][0] = i - 1;
			triplets[i][1] = i;
			triplets[i][2] = ess_count - i;

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

	// Now we take the left out element and mix it in
	if(odd_salsa) {
		for (size_t i = 0; i < salsa->size - 1; i++) {
			elements[salsa->size - 1] ^= elements[i];
		}

		for (size_t i = 0; i < salsa->size - 1; i++) {
			elements[salsa->size - 1] ^= elements[i];
		}
	}

	for(size_t i = 0; i < salsa->size; i++) {
		salsa->data[idx[i]] = elements[i];
	}
}

int main(int argc, char** argv) {
	// chacha20 cha = chacha20_create("helloworhelloworhelloworhellowor", 0);
	// chacha20_print(cha);

	FILE *file = fopen("macbeth.txt", "r");

	// Get the length of the file
	fseek(file, 0L, SEEK_END);
	size_t file_size = ftell(file);
	fseek(file, 0L, SEEK_SET);

	// Read the file into memory
	char* text = (char*)malloc(sizeof(char) * file_size);
	fgets(text, file_size, file);
	printf("text size: %zd\n", strlen(text));
}
