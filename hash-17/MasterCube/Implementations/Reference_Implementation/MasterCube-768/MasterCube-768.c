#include <stdint.h>
#include <stdint.h>
#include <string.h>

#include "mastercube.h"
#if (!defined (__AVX512F__) || !defined (__AVX512BW__) || !defined (__AVX512VL__)) && !defined(__AVX2__) && !defined(__SSE4_2__)

static const int N_ROUNDS = 18;

/*
 * row-major matrices
 */
struct xy_slice {
    union xy_slice_data {
        uint16_t slice[6][8];
        uint16_t row[6][8];
        uint16_t raw_data[48];
    } data;
};
struct mc_state {
    union mc_state_data {
        struct mc_state_halves {
            struct xy_slice left;
            struct xy_slice right;
        } halves;

        uint16_t row[12][8];
        uint16_t raw_data[96];
        uint32_t pair32[6][8];
        uint64_t pair64[6][4];
    } data;
};

static inline uint16_t ror16(const uint16_t x, const int n_ror)
{
    if (n_ror == 0) return x;
    return (x >> n_ror) | (x << (16 - n_ror));
}

static inline void MAndRXs(struct xy_slice *state_l, struct xy_slice *state_r, const int alpha, const int beta, const int gamma)
{
    for (int i = 0; i < 6; ++i)
        for (int j = 0; j < 8; ++j) {
            const uint16_t x = state_l->data.slice[i][j];
            const uint16_t y = state_r->data.slice[i][j];
            const uint16_t a = ror16(x, alpha);
            const uint16_t b = ror16(x, beta);
            const uint16_t c = ror16(x, gamma);
            state_r->data.slice[i][j] = (a & b) ^ c ^ y;
        }

    return;
}

static inline void ShiftRows(struct xy_slice *state_l, struct xy_slice *state_r)
{
    //#pragma GCC unroll 6
    for (int i = 0; i < 6; ++i) {
        uint16_t v[8];
        memcpy(v, state_l->data.slice[i], 16);

        state_l->data.slice[i][0] = v[(0 + i) % 8];
        state_l->data.slice[i][1] = v[(1 + i) % 8];
        state_l->data.slice[i][2] = v[(2 + i) % 8];
        state_l->data.slice[i][3] = v[(3 + i) % 8];
        state_l->data.slice[i][4] = v[(4 + i) % 8];
        state_l->data.slice[i][5] = v[(5 + i) % 8];
        state_l->data.slice[i][6] = v[(6 + i) % 8];
        state_l->data.slice[i][7] = v[(7 + i) % 8];
    }

    //#pragma GCC unroll 6
    for (int i = 0; i < 6; ++i) {
        uint16_t v[8];
        memcpy(v, state_r->data.slice[i], 16);

        state_r->data.slice[i][0] = v[(0 - i + 8) % 8];
        state_r->data.slice[i][1] = v[(1 - i + 8) % 8];
        state_r->data.slice[i][2] = v[(2 - i + 8) % 8];
        state_r->data.slice[i][3] = v[(3 - i + 8) % 8];
        state_r->data.slice[i][4] = v[(4 - i + 8) % 8];
        state_r->data.slice[i][5] = v[(5 - i + 8) % 8];
        state_r->data.slice[i][6] = v[(6 - i + 8) % 8];
        state_r->data.slice[i][7] = v[(7 - i + 8) % 8];
    }

    return;
}

static inline void mix_row_32x4(uint16_t x[8])
{
    uint16_t tmp[8];
    memcpy(tmp, x, 16);

    for (int i = 0; i < 4; ++i) {
        const int i0 = 2 * i;
        const int i1 = 2 * i + 1;
        x[i0] = tmp[(i0 - 2 + 8) % 8] ^ tmp[i0] ^ tmp[(i0 + 2) % 8];
        x[i1] = tmp[(i1 - 2 + 8) % 8] ^ tmp[i1] ^ tmp[(i1 + 2) % 8];
    }

    return;
}

static inline void MixRows(struct mc_state *state)
{
    for (int i = 0; i < 6; ++i) {
        mix_row_32x4(state->data.halves.left.data.slice[i]);
        mix_row_32x4(state->data.halves.right.data.slice[i]);
    }

    return;
}

static inline void SwapRows(struct mc_state *state)
{
    struct xy_slice tmp;
    memcpy(tmp.data.raw_data, state->data.halves.right.data.raw_data, sizeof(struct xy_slice));

    memcpy(state->data.halves.right.data.slice[0], tmp.data.slice[1], 16);
    memcpy(state->data.halves.right.data.slice[1], tmp.data.slice[0], 16);

    memcpy(state->data.halves.right.data.slice[2], tmp.data.slice[3], 16);
    memcpy(state->data.halves.right.data.slice[3], tmp.data.slice[2], 16);

    memcpy(state->data.halves.right.data.slice[4], tmp.data.slice[5], 16);
    memcpy(state->data.halves.right.data.slice[5], tmp.data.slice[4], 16);

    return;
}

static inline void CrossMixs(struct mc_state *state)
{
#if defined(__ARM_ARCH_7EM__) || defined(__ARM_ARCH_7M__)
    for (int j = 0; j < 8; ++j) {
        const uint32_t x0 = state->data.pair32[0][j];
        const uint32_t x1 = state->data.pair32[1][j];
        const uint32_t x2 = state->data.pair32[2][j];
        const uint32_t x3 = state->data.pair32[3][j];
        const uint32_t x4 = state->data.pair32[4][j];
        const uint32_t x5 = state->data.pair32[5][j];

        state->data.pair32[0][j] = x0 ^ x1 ^ x4;
        state->data.pair32[1][j] = x1 ^ x2 ^ x5;
        state->data.pair32[2][j] = x2 ^ x3 ^ x0;
        state->data.pair32[3][j] = x3 ^ x4 ^ x1;
        state->data.pair32[4][j] = x4 ^ x5 ^ x2;
        state->data.pair32[5][j] = x5 ^ x0 ^ x3;
    }
#else
    for (int j = 0; j < 4; ++j) {
        const uint64_t x0 = state->data.pair64[0][j];
        const uint64_t x1 = state->data.pair64[1][j];
        const uint64_t x2 = state->data.pair64[2][j];
        const uint64_t x3 = state->data.pair64[3][j];
        const uint64_t x4 = state->data.pair64[4][j];
        const uint64_t x5 = state->data.pair64[5][j];

        state->data.pair64[0][j] = x0 ^ x1 ^ x4;
        state->data.pair64[1][j] = x1 ^ x2 ^ x5;
        state->data.pair64[2][j] = x2 ^ x3 ^ x0;
        state->data.pair64[3][j] = x3 ^ x4 ^ x1;
        state->data.pair64[4][j] = x4 ^ x5 ^ x2;
        state->data.pair64[5][j] = x5 ^ x0 ^ x3;
    }
#endif


    return;
}

static inline void MixColumns(struct mc_state *state)
{
    struct mc_state tmp;
    memcpy(tmp.data.raw_data, state->data.raw_data, sizeof(struct mc_state));

    for (int i = 0; i < 2; ++i) {
        for (int j = 0; j < 8; ++j) {
            uint16_t tmp0 = tmp.data.row[2 + i][j] ^ tmp.data.row[4 + i][j];
            uint16_t tmp1 = tmp.data.row[0 + i][j] ^ tmp.data.row[4 + i][j];
            uint16_t tmp2 = tmp.data.row[0 + i][j] ^ tmp0;
            state->data.row[0 + i][j] = tmp0;
            state->data.row[2 + i][j] = tmp1;
            state->data.row[4 + i][j] = tmp2;
        }
    }

    for (int i = 0; i < 2; ++i) {
        for (int j = 0; j < 8; ++j) {
            uint16_t tmp0 = tmp.data.row[6 + i][j] ^ tmp.data.row[10 + i][j];
            uint16_t tmp1 = tmp.data.row[8 + i][j] ^ tmp.data.row[10 + i][j];
            uint16_t tmp2 = tmp.data.row[8 + i][j] ^ tmp0;
            state->data.row[6 + i][j] = tmp0;
            state->data.row[8 + i][j] = tmp1;
            state->data.row[10 + i][j] = tmp2;
        }
    }

    return;
}

static inline void AddConstant(struct mc_state *state, const int rn)
{
    uint8_t c[16] = {
        0x44, 0x73, 0x70, 0x03,
        0x2E, 0x8A, 0x19, 0x13,
        0xD3, 0x08, 0xA3, 0x85,
        0x88, 0x6A, 0x3F, 0x24
    };

    uint16_t *c_16 = (uint16_t *)c;
    for (int j = 0; j < 8; ++j)
        state->data.row[0][j] ^= c_16[j] ^ rn;

    return;
}

static inline void _core(struct mc_state *state, const int n_rounds)
{
    //#pragma GCC unroll 20
    for (int i = 0; i < n_rounds; ++i) {
        CrossMixs(state);
        SwapRows(state);

        MAndRXs(&state->data.halves.left, &state->data.halves.right,  0, 1, 8);
        MAndRXs(&state->data.halves.right, &state->data.halves.left, 14, 5, 0);
        MAndRXs(&state->data.halves.left, &state->data.halves.right, 9, 12, 8);
        MAndRXs(&state->data.halves.right, &state->data.halves.left, 14, 5, 0);
        MAndRXs(&state->data.halves.left, &state->data.halves.right, 0, 1, 8);
        MAndRXs(&state->data.halves.right, &state->data.halves.left, 8, 9, 0);

        CrossMixs(state);
        SwapRows(state);

        MixColumns(state);
        ShiftRows(&state->data.halves.left, &state->data.halves.right);
        MixRows(state);

        AddConstant(state, i);
    }

    return;
}

static inline void _core_inverse(struct mc_state *state, const int n_rounds)
{

    for (int i = n_rounds - 1; i >= 0; --i) {
        AddConstant(state, i + 9); // for 18 rounds mcube

        MixRows(state);

        ShiftRows(&state->data.halves.right, &state->data.halves.left);

        MixColumns(state);

        SwapRows(state);
        CrossMixs(state);

        MAndRXs(&state->data.halves.right, &state->data.halves.left, 8, 9, 0);
        MAndRXs(&state->data.halves.left, &state->data.halves.right, 0, 1, 8);
        MAndRXs(&state->data.halves.right, &state->data.halves.left, 14, 5, 0);
        MAndRXs(&state->data.halves.left, &state->data.halves.right, 9, 12, 8);
        MAndRXs(&state->data.halves.right, &state->data.halves.left, 14, 5, 0);
        MAndRXs(&state->data.halves.left, &state->data.halves.right,  0, 1, 8);

        struct xy_slice tmp;
        memcpy(tmp.data.raw_data, state->data.halves.left.data.raw_data, sizeof(struct xy_slice));
        memcpy(state->data.halves.left.data.raw_data, state->data.halves.right.data.raw_data, sizeof(struct xy_slice));
        memcpy(state->data.halves.right.data.raw_data, tmp.data.raw_data, sizeof(struct xy_slice));

        SwapRows(state);
        CrossMixs(state);
    }

    return;
}

static inline void zip_prf(struct mc_state *state)
{
    struct mc_state state_copy;
    memcpy(state_copy.data.raw_data, state->data.raw_data, sizeof(struct mc_state));

    _core(state, N_ROUNDS / 2);

    _core_inverse(&state_copy, N_ROUNDS / 2);

    for (int i = 0; i < 12; ++i)
        for (int j = 0; j < 8; ++j)
            state->data.row[i][j] ^= state_copy.data.row[i][j];

    return;
}

static void mc_transform(struct mc_state *state)
{
    zip_prf(state);
    return;
}


static inline void _sponge_absorb_helper(void (*transform)(struct mc_state *), struct mc_state *state, const int block_bits, const unsigned char *message, const uint64_t message_bits)
{
    for (int i = 0; i < 12; ++i)
        for (int j = 0; j < 8; ++j)
            state->data.row[i][j] = 0x0000;

    const int block_bytes = block_bits / 8;
    const int n_m128_per_block = block_bits / 128; // _m128i reg
    const uint64_t message_bytes = (message_bits + 7) / 8;
    const uint64_t n_block = message_bits / block_bits; // number of full blocks
    uint8_t last_block[136] = {0x00}; // the last and unaligned block, allocate the largest potential needed size, and pad with 0x00

    // copy and turn the last unaligned block to a padded full block
    const uint64_t last_index = n_block * block_bytes;
    memcpy(last_block, message + last_index, message_bytes - last_index);
    pad10star1(last_block, message_bits % block_bits, block_bits);

    for (uint64_t i = 0; i < n_block; ++i) {
        for (int j = 0; j < n_m128_per_block; ++j) {
            for (int k = 0; k < 8; ++k)
                state->data.row[j][k] ^= ((uint16_t *)(message + block_bytes * i + 16 * j))[k];
        }
        for (int k = 0; k < 4; ++k)
            state->data.row[n_m128_per_block][k] ^= ((uint16_t *)(message + block_bytes * i + 16 * n_m128_per_block))[k];

        transform(state);
    }
    {
        for (int j = 0; j < n_m128_per_block; ++j) {
            for (int k = 0; k < 8; ++k)
                state->data.row[j][k] ^= ((uint16_t *)(last_block + 16 * j))[k];
        }
        for (int k = 0; k < 4; ++k)
            state->data.row[n_m128_per_block][k] ^= ((uint16_t *)(last_block + 16 * n_m128_per_block))[k];

        transform(state);
    }

    return;
}

static inline void _sponge_squeeze_helper(void (*transform)(struct mc_state *), struct mc_state *state, const int block_bits, unsigned char *digest, const int digest_bits)
{
    const int digest_bytes = digest_bits / 8;
    const int block_bytes = block_bits / 8;
    const int n_block = (digest_bytes + block_bytes - 1) / block_bytes;

    const int n_m128_per_block  = (block_bits  + 128 - 1) / 128; // _m128i reg
    const int n_m128_per_digest = (digest_bits + 128 - 1) / 128; // _m128i reg
    const int n_m128_per_iter   = n_m128_per_block < n_m128_per_digest ? n_m128_per_block : n_m128_per_digest;

    uint8_t buffer[3][768 / 8];

    for (int i = 0; i < n_block; ++i) { // max: 3 (the 1024 case)
        for (int j = 0; j < n_m128_per_iter; ++j) // max: 6 (the 768 case)
            memcpy(buffer[i] + 16 * j, state->data.row[j], 16);

        transform(state);
    }

    if (digest_bytes <= block_bytes) {
        memcpy(digest, buffer[0], digest_bytes);
    } else if (digest_bytes <= 2 * block_bytes) {
        memcpy(digest, buffer[0], block_bytes);
        memcpy(digest + block_bytes, buffer[1], digest_bytes - block_bytes);
    } else if (digest_bytes <= 3 * block_bytes) {
        memcpy(digest, buffer[0], block_bytes);
        memcpy(digest + block_bytes, buffer[1], block_bytes);
        memcpy(digest + 2 * block_bytes, buffer[2], digest_bytes - 2 * block_bytes);
    }

    return;
}


int MasterCube768_plain(const unsigned char *message, unsigned long long message_bit_len, unsigned char *digest)
{
    struct mc_state state = {0};

    enum {
        digest_bits = 768, // bits
        block_bits = 704 // bits
    };

    _sponge_absorb_helper(mc_transform, &state, block_bits, message, message_bit_len);
    _sponge_squeeze_helper(mc_transform, &state, block_bits, digest, digest_bits);

    return 0;
}

#else

int MasterCube768_plain(const unsigned char *message, unsigned long long message_bit_len, unsigned char *digest)
{
    UNUSED(message);
    UNUSED(message_bit_len);
    UNUSED(digest);
    return 1;
}

#endif



