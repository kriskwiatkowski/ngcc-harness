/*
The software is provided by the Institute of Commercial Cryptography Standards
(ICCS), and is used for algorithm submissions in the Next-generation Commercial
Cryptographic Algorithms Program (NGCC).

ICCS doesn't represent or warrant that the operation of the software will be
uninterrupted or error-free in all cases. ICCS will take no responsibility for
the use of the software or the results thereof, if the software is used for any
other purposes.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "CryptHash_AlgorithmInstance.h"

#define ULL unsigned long long

/// @brief The rotation offsets for ShiftRow
static const int rhoY[4][4] = {
    {0, 14, 20, 22},
    {0, 13, 68, 91},
    {0, 27, 42, 106},
    {0, 32, 48, 80}
};

/// @brief The round constants for AddRoundConstant
static const ULL RCON[24] = {
    0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3, 0x13, 0x19, 0x8a, 0x2e,
    0x03, 0x70, 0x73, 0x44, 0xa4, 0x09, 0x38, 0x22, 0x29, 0x9f, 0x31, 0xd0
};

/// @brief The multiplication function for bit-sliced operations
static inline void MUL(ULL *x0, ULL *x1, ULL *x2, ULL *x3){
    ULL tmp = *x3; 
    *x3 = *x2; *x2 = *x1; *x1 = *x0; *x0 = tmp; // rotation
    *x1 ^= *x0; // XOR
}

/// @brief The bit-sliced MDS matrix multiplication
static inline void bitSliceMDS(ULL *x0, ULL *x1, ULL *x2, ULL *x3,
                        ULL *x4, ULL *x5, ULL *x6, ULL *x7,
                        ULL *x8, ULL *x9, ULL *xa, ULL *xb, 
                        ULL *xc, ULL *xd, ULL *xe, ULL *xf){
    *x8 ^= *xc; *x9 ^= *xd; *xa ^= *xe; *xb ^= *xf; // C ^= D
    *x0 ^= *x4; *x1 ^= *x5; *x2 ^= *x6; *x3 ^= *x7; // A ^= B
    MUL(x4, x5, x6, x7); // B = MUL(B)
    MUL(xc, xd, xe, xf); // D = MUL(D)
    *x4 ^= *x8; *x5 ^= *x9; *x6 ^= *xa; *x7 ^= *xb; // B ^= C
    *xc ^= *x0; *xd ^= *x1; *xe ^= *x2; *xf ^= *x3; // D ^= A
    MUL(x0, x1, x2, x3); // A = MUL(A)
    MUL(x0, x1, x2, x3); // A = MUL(A)
    MUL(x8, x9, xa, xb); // C = MUL(C)
    MUL(x8, x9, xa, xb); // C = MUL(C)
    *x8 ^= *xc; *x9 ^= *xd; *xa ^= *xe; *xb ^= *xf; // C ^= D
    *x0 ^= *x4; *x1 ^= *x5; *x2 ^= *x6; *x3 ^= *x7; // A ^= B
    *x4 ^= *x8; *x5 ^= *x9; *x6 ^= *xa; *x7 ^= *xb; // B ^= C
    *xc ^= *x0; *xd ^= *x1; *xe ^= *x2; *xf ^= *x3; // D ^= A
}

/// @brief The permutation function of MOZI-512
/// @param[in] state The base address of the internal state
/// @param[in] roundNum The number of rounds to execute (should be equal to 20)
void permutation(unsigned char *state, int roundNum){
    ULL A[4][4][2], B[4][4][2], C[4][4][2], D[4][4][2];
    // load state into S
    for (int i = 0; i < 4; i ++){
        for (int j = 0; j < 4; j ++){
            A[i][j][0] = 0;
            A[i][j][1] = 0;
            for (int k = 7; k >= 0; k --){
                A[i][j][0] <<= 8;
                A[i][j][0] |= state[(i * 4 + j) * 16 + k];
                
                A[i][j][1] <<= 8;
                A[i][j][1] |= state[(i * 4 + j) * 16 + k + 8];
            }
        }
    }

    for (int r = 0; r < roundNum; r++) {
        // s-box
        for (int y = 0; y < 4; y ++){
            for (int k = 0; k < 2; k ++){
                B[3][y][k] = (A[3][y][k] & A[2][y][k]) ^ A[1][y][k];
                B[1][y][k] = (A[2][y][k] | A[1][y][k]) ^ A[0][y][k];
                B[0][y][k] = (B[3][y][k] & A[0][y][k]) ^ A[3][y][k];
                B[2][y][k] = (B[1][y][k] & A[3][y][k]) ^ A[2][y][k];
            }
        }

        // MC (bit-sliced MDS)
        memcpy(C, B, sizeof(B));
        bitSliceMDS(&C[0][0][0], &C[1][0][0], &C[2][0][0], &C[3][0][0],
                    &C[0][1][0], &C[1][1][0], &C[2][1][0], &C[3][1][0],
                    &C[0][2][0], &C[1][2][0], &C[2][2][0], &C[3][2][0],
                    &C[0][3][0], &C[1][3][0], &C[2][3][0], &C[3][3][0]);
        bitSliceMDS(&C[0][0][1], &C[1][0][1], &C[2][0][1], &C[3][0][1],
                    &C[0][1][1], &C[1][1][1], &C[2][1][1], &C[3][1][1],
                    &C[0][2][1], &C[1][2][1], &C[2][2][1], &C[3][2][1],
                    &C[0][3][1], &C[1][3][1], &C[2][3][1], &C[3][3][1]);

        // ShiftRow
        for (int x = 0; x < 4; x ++){
            for (int y = 0; y < 4; y ++){
                if (rhoY[r%4][y] == 0) {
                    D[x][y][0] = C[x][y][0];
                    D[x][y][1] = C[x][y][1];
                }
                else if (rhoY[r%4][y] < 64){
                    D[x][y][0] = (C[x][y][0] >> rhoY[r%4][y]) | (C[x][y][1] << (64 - rhoY[r%4][y]));
                    D[x][y][1] = (C[x][y][1] >> rhoY[r%4][y]) | (C[x][y][0] << (64 - rhoY[r%4][y]));
                }
                else if (rhoY[r%4][y] > 64){
                    D[x][y][0] = (C[x][y][1] >> (rhoY[r%4][y] - 64)) | (C[x][y][0] << (128 - rhoY[r%4][y]));
                    D[x][y][1] = (C[x][y][0] >> (rhoY[r%4][y] - 64)) | (C[x][y][1] << (128 - rhoY[r%4][y]));
                }
                else {
                    D[x][y][0] = C[x][y][1];
                    D[x][y][1] = C[x][y][0];
                }
            }
        }

        // add constants
        D[3][3][0] ^= RCON[r];
        memcpy(A, D, sizeof(D));
    }

    // store state back to output
    for (int i = 0; i < 4; i ++){
        for (int j = 0; j < 4; j ++){
            for (int k = 0; k < 8; k ++){
                state[(i * 4 + j) * 16 + k] = (A[i][j][0] >> (8 * k)) & 0xFF;
                state[(i * 4 + j) * 16 + k + 8] = (A[i][j][1] >> (8 * k)) & 0xFF;
            }
        }
    }
}

/// @brief The hash function based on sponge construction
/// @param[in] hash The hash length in BYTES (should be equal to 0 in XOF mode)
/// @param[in] rate The rate in BYTES (should be equal to 128)
/// @param[in] input The base address of message
/// @param[in] input_len_bits The length of message in BITS
/// @param[in] output_len_bits The length of digest in BITS (arbitrary in XOF mode)
/// @param[out] output The base address of digest
/// @return 0 for success, 1 for error
int hash_sponge(int hash, int rate, const unsigned char *input, ULL input_len_bits, int output_len_bits, unsigned char *output){
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
        permutation(state, 20);
    }
    // squeezing phase
    int output_blocks = (output_len_bits + rate*8 - 1) / (rate*8);
    int output_len_bytes = (output_len_bits + 7) / 8;
    for (int i = 0; i < output_blocks; i++) {
        if (i != 0) {
            permutation(state, 20);
        }
        for (int j = 0; j < rate && i * rate + j < output_len_bytes; j++) {
            if (i * rate + j == output_len_bytes - 1){
                int remaining_bits = output_len_bits % 8;
                if (remaining_bits == 0) remaining_bits = 8;
                unsigned char mask = 0xFF << (8 - remaining_bits);
                output[i * rate + j] = state[j] & mask;
            }
            else {
                output[i * rate + j] = state[j];
            }
        }
    }
    return 0;
}

int CryptHash(int digest_len_bits, const unsigned char *msg, unsigned long long msg_len_bits, unsigned char *digest)
{
    return hash_sponge(0, 128, msg, msg_len_bits, digest_len_bits, digest);
}