/*
The software is provided by the Institute of Commercial Cryptography Standards
(ICCS), and is used for algorithm submissions in the Next-generation Commercial
Cryptographic Algorithms Program (NGCC).

ICCS doesn't represent or warrant that the operation of the software will be
uninterrupted or error-free in all cases. ICCS will take no responsibility for
the use of the software or the results thereof, if the software is used for any
other purposes.
*/

#include "CryptHash_AlgorithmInstance.h"
// #include "megascon_f.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define ULL unsigned long long

typedef struct __attribute__((aligned(64))) {
    uint64_t w[8][4];
} State2048;

static const unsigned BIT_PERM[8] = {1, 7, 5, 2, 4, 6, 0, 3};

static const unsigned A[8] = { 1,  2,  4,  7, 26, 49, 55, 58 };
static const unsigned B[8] = { 3,  5, 15,  9, 46,  6, 19, 47 };
static const unsigned C[8] = {14, 23, 17, 12, 13, 50, 56, 61 };
static const unsigned D[8] = {36, 60, 24, 40, 37, 25, 57, 28 };

static inline uint64_t rotl64(uint64_t x, unsigned r)
{
    r &= 63;
    return r ? ((x << r) | (x >> (64 - r))) : x;
}

static inline uint64_t round_constant(unsigned round)
{
    uint64_t x = 0x9e3779b97f4a7c15ULL ^ (uint64_t)round;
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

static void chichi_scalar(State2048 *s)
{
    uint64_t x[8][4];
    memcpy(x, s->w, sizeof(x));

    for (int j = 0; j < 4; j++) {
        s->w[0][j] = x[0][j] ^ (~x[1][j] & x[2][j]);
        s->w[1][j] = x[4][j] ^ (~x[2][j] & x[0][j]);
        s->w[2][j] = x[3][j] ^ (~x[0][j] & x[1][j]);
        s->w[3][j] = ~x[1][j] ^ (~x[4][j] & ~x[5][j]);
        s->w[4][j] = x[2][j] ^ (~x[5][j] & x[6][j]);
        s->w[5][j] = x[5][j] ^ (~x[6][j] & x[7][j]);
        s->w[6][j] = x[6][j] ^ (~x[7][j] & x[3][j]);
        s->w[7][j] = x[7][j] ^ (~x[3][j] & x[4][j]);
    }
}

static void bitperm_scalar(State2048 *s)
{
    uint64_t t[8][4];

    for (int old = 0; old < 8; old++) {
        int nw = (int)BIT_PERM[old];
        for (int j = 0; j < 4; j++) {
            t[nw][j] = s->w[old][j];
        }
    }

    for (int r = 0; r < 8; r++) {
        for (int j = 0; j < 4; j++) {
            s->w[r][j] = t[r][j];
        }
    }
}

static void row_mix_one_scalar(uint64_t x[4], unsigned a, unsigned b,
                               unsigned c, unsigned d)
{
    uint64_t t[4] = {x[0], x[1], x[2], x[3]};

    x[0] = t[0] ^ rotl64(t[1], a) ^ rotl64(t[2], b) ^
           rotl64(t[3], c) ^ rotl64(t[0], d);
    x[1] = t[1] ^ rotl64(t[2], a) ^ rotl64(t[3], b) ^
           rotl64(t[0], c) ^ rotl64(t[1], d);
    x[2] = t[2] ^ rotl64(t[3], a) ^ rotl64(t[0], b) ^
           rotl64(t[1], c) ^ rotl64(t[2], d);
    x[3] = t[3] ^ rotl64(t[0], a) ^ rotl64(t[1], b) ^
           rotl64(t[2], c) ^ rotl64(t[3], d);
}

static void row_mix_scalar(State2048 *s)
{
    for (int i = 0; i < 8; i++) {
        row_mix_one_scalar(s->w[i], A[i], B[i], C[i], D[i]);
    }
}

static void add_constant_scalar(State2048 *s, unsigned round)
{
    s->w[0][0] ^= round_constant(round);
}

void permute2048_scalar(State2048 *s, unsigned rounds)
{
    for (unsigned r = 0; r < rounds; r++) {
        chichi_scalar(s);
        bitperm_scalar(s);
        row_mix_scalar(s);
        add_constant_scalar(s, r);
    }
}
void permutation(unsigned char *state, unsigned rounds)
{
    State2048 s;
    memcpy(s.w, state, sizeof(s.w));
    permute2048_scalar(&s, rounds);
    memcpy(state, s.w, sizeof(s.w));
}

/// @brief The hash function based on sponge construction
/// @param[in] hash The hash length in BYTES (should be equal to 48)
/// @param[in] rate The rate in BYTES (should be equal to 160)
/// @param[in] input The base address of message
/// @param[in] input_len_bits The length of message in BITS
/// @param[in] output_len_bits The length of digest in BITS (should be equal to hash)
/// @param[out] output The base address of digest
/// @return 0 for success, 1 for error
int hash_sponge(int hash, int rate, const unsigned char *input, ULL input_len_bits, int output_len_bits, unsigned char *output){
    if (rate != 160 || hash != 48){
        printf("Invalid rate or hash length\n");
        return 1;
    }
    unsigned char state[256];
    unsigned char IV[256];
    memset(IV, 0, sizeof(IV));
    memcpy(state, IV, sizeof(IV));
    // padding
    ULL padded_input_len_bits = ((input_len_bits + rate*8) / (rate*8)) * rate*8;
    ULL padded_input_len = padded_input_len_bits / 8;
    unsigned char *padded_input = (unsigned char *)malloc(padded_input_len);
    memset(padded_input, 0, padded_input_len);
    ULL full_bytes = input_len_bits / 8;
    int remaining_bits = input_len_bits % 8;
    memcpy(padded_input, input, full_bytes);
    if (remaining_bits > 0) {
        unsigned char mask = 0xFF << (8 - remaining_bits);
        padded_input[full_bytes] = input[full_bytes] & mask;
        padded_input[full_bytes] |= 0x80 >> remaining_bits; // padding with 0x80
    } else {
        padded_input[full_bytes] = 0x80; // padding with 0x80
    }

    // absorbing phase
    ULL blocks = padded_input_len / rate;
    for (ULL i = 0; i < blocks; i++) {
        for (int j = 0; j < rate; j++) {
            state[j] ^= padded_input[i * rate + j];
        }
        permutation(state, 15);
    }
    // squeezing phase
    for (int i = 0; i < hash; i ++){
        output[i] = state[i];
    }
    return 0;
}


int CryptHash(int digest_len_bits, const unsigned char *msg, unsigned long long msg_len_bits, unsigned char *digest)
{
    return hash_sponge(digest_len_bits / 8, 160, msg, msg_len_bits, digest_len_bits, digest);
}