#ifndef MASTERCUBE_H
#define MASTERCUBE_H

/* Merged from common.h. */
#include <stdint.h>

/*
 * pad10*1 on a zero-initialized last_block.
 *
 * last_block: zeroed buffer that may be larger than the real block
 * msg_bits:   number of valid message bits already stored in last_block
 * block_bits: real logical block size in bits, always a multiple of 8
 *
 * Bit order inside each byte: MSB-first.
 */
static inline void pad10star1(uint8_t last_block[136], const int message_bits, const int block_bits)
{
    const int partial_bits = message_bits % 8;
    if (partial_bits != 0)
    {
        last_block[message_bits / 8] &= (uint8_t)(0xFFu << (8 - partial_bits));
    }

    /* append the first '1' bit immediately after the message */
    last_block[message_bits / 8] |= (uint8_t)(0x80u >> partial_bits);

    /* set the last bit of the real block to 1 */
    last_block[(block_bits / 8) - 1] |= 0x01u;

    return;
}

/* Merged from macros.h. */
#define UNUSED(x) (void)(x)

#if defined(__SSE4_2__) || defined(__AVX2__)

#define _MM_SHUFFLE_R(w, x, y, z) _MM_SHUFFLE(z, y, x, w)

#endif

/* Public MasterCube API declarations. */
#ifdef __cplusplus
extern "C"
{
#endif

    /// @brief Input message to get message digests of specified lengths
    /// @param message The base address of message
    /// @param messagebitlen The total BITS of message
    /// @param digest The base address of digest
    /// @return 0 for success, others for error

    #if defined (__AVX512F__) || defined (__AVX512BW__)
        #define  MasterCube512  MasterCube512_avx512_256
        #define  MasterCube768  MasterCube768_avx512_256
        #define MasterCube1024 MasterCube1024_avx512_256
    #elif defined (__AVX2__)
        #define  MasterCube512  MasterCube512_avx2
        #define  MasterCube768  MasterCube768_avx2
        #define MasterCube1024 MasterCube1024_avx2
    #elif defined (__SSE4_2__)
        #define  MasterCube512  MasterCube512_sse
        #define  MasterCube768  MasterCube768_sse
        #define MasterCube1024 MasterCube1024_sse
    #else
        #define  MasterCube512  MasterCube512_plain
        #define  MasterCube768  MasterCube768_plain
        #define MasterCube1024 MasterCube1024_plain
    #endif

    int  MasterCube512(const unsigned char *message, unsigned long long message_bit_len, unsigned char *digest);
    int  MasterCube768(const unsigned char *message, unsigned long long message_bit_len, unsigned char *digest);
    int MasterCube1024(const unsigned char *message, unsigned long long message_bit_len, unsigned char *digest);

#ifdef __cplusplus
}
#endif

#endif /* MASTERCUBE_H */

