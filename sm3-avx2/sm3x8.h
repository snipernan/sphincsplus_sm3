#ifndef SPX_SM3X8_H
#define SPX_SM3X8_H

#include "params.h"

#define SPX_SM3_BLOCK_BYTES 64
#define SPX_SM3_OUTPUT_BYTES 32  /* This does not necessarily equal SPX_N */

#if SPX_SM3_OUTPUT_BYTES < SPX_N
    #error Linking against SM3 with N larger than 32 bytes is not supported
#endif

#define sm3x8_seeded SPX_NAMESPACE(sm3x8_seeded)
void sm3x8_seeded(
              unsigned char *out0,
              unsigned char *out1,
              unsigned char *out2,
              unsigned char *out3,
              unsigned char *out4,
              unsigned char *out5,
              unsigned char *out6,
              unsigned char *out7,
              const unsigned char *seed,
              unsigned long long seedlen,
              const unsigned char *in0,
              const unsigned char *in1,
              const unsigned char *in2,
              const unsigned char *in3,
              const unsigned char *in4,
              const unsigned char *in5,
              const unsigned char *in6,
              const unsigned char *in7, unsigned long long inlen);

/* This provides a wrapper around the internals of 8x parallel SM3 */
#define sm3x8 SPX_NAMESPACE(sm3x8)
void sm3x8(unsigned char *out0,
              unsigned char *out1,
              unsigned char *out2,
              unsigned char *out3,
              unsigned char *out4,
              unsigned char *out5,
              unsigned char *out6,
              unsigned char *out7,
              const unsigned char *in0,
              const unsigned char *in1,
              const unsigned char *in2,
              const unsigned char *in3,
              const unsigned char *in4,
              const unsigned char *in5,
              const unsigned char *in6,
              const unsigned char *in7, unsigned long long inlen);

/**
 * Note that inlen should be sufficiently small that it still allows for
 * an array to be allocated on the stack. Typically 'in' is merely a seed.
 * Outputs outlen number of bytes
 */
#define mgf1x8 SPX_NAMESPACE(mgf1x8)
void mgf1x8(unsigned char *outx8, unsigned long outlen,
            const unsigned char *in0,
            const unsigned char *in1,
            const unsigned char *in2,
            const unsigned char *in3,
            const unsigned char *in4,
            const unsigned char *in5,
            const unsigned char *in6,
            const unsigned char *in7,
            unsigned long inlen);
#endif
