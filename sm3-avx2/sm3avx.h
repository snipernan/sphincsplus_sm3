
#ifndef XYSSL_SM3_H
#define XYSSL_SM3_H

#include "immintrin.h"

#define u32 uint32_t
#define u256 __m256i

#define XOR _mm256_xor_si256
#define OR _mm256_or_si256
#define AND _mm256_and_si256
#define ADD32 _mm256_add_epi32
#define NOT(x) _mm256_xor_si256(x, _mm256_set_epi32(-1, -1, -1, -1, -1, -1, -1, -1))

#define LOAD(src) _mm256_loadu_si256((__m256i *)(src))
#define STORE(dest,src) _mm256_storeu_si256((__m256i *)(dest),src)

#define BYTESWAP(x) _mm256_shuffle_epi8(x, _mm256_set_epi8(0xc,0xd,0xe,0xf,0x8,0x9,0xa,0xb,0x4,0x5,0x6,0x7,0x0,0x1,0x2,0x3,0xc,0xd,0xe,0xf,0x8,0x9,0xa,0xb,0x4,0x5,0x6,0x7,0x0,0x1,0x2,0x3))

#define SHIFTR32(x, y) _mm256_srli_epi32(x, y)
#define SHIFTL32(x, y) _mm256_slli_epi32(x, y)

#define ROTR32(x, y) OR(SHIFTR32(x, y), SHIFTL32(x, 32 - y))
#define ROTL32(x, y) OR(SHIFTL32(x, y), SHIFTR32(x, 32 - y))

#define XOR3(a, b, c) XOR(XOR(a, b), c)

#define ADD3_32(a, b, c) ADD32(ADD32(a, b), c)
#define ADD4_32(a, b, c, d) ADD32(ADD32(ADD32(a, b), c), d)
#define ADD5_32(a, b, c, d, e) ADD32(ADD32(ADD32(ADD32(a, b), c), d), e)

#define MAJ_AVX(a, b, c) XOR3(AND(a, b), AND(a, c), AND(b, c))
#define CH_AVX(a, b, c) XOR(AND(a, b), AND(NOT(a), c))

#define SIGMA1_AVX(x) XOR3(ROTR32(x, 6), ROTR32(x, 11), ROTR32(x, 25))
#define SIGMA0_AVX(x) XOR3(ROTR32(x, 2), ROTR32(x, 13), ROTR32(x, 22))

#define WSIGMA1_AVX(x) XOR3(ROTR32(x, 17), ROTR32(x, 19), SHIFTR32(x, 10))
#define WSIGMA0_AVX(x) XOR3(ROTR32(x, 7), ROTR32(x, 18), SHIFTR32(x, 3))

#define FF0(x,y,z)  _mm256_xor_si256(_mm256_xor_si256(x, y ), z) 
#define FF1(x,y,z) _mm256_or_si256(_mm256_or_si256(_mm256_and_si256(x, y ), _mm256_and_si256(x, z)), _mm256_and_si256(y, z))

#define GG0(x,y,z)  _mm256_xor_si256(_mm256_xor_si256(x, y ), z)
#define GG1(x,y,z) _mm256_or_si256(_mm256_and_si256(x, y ), _mm256_andnot_si256(x, z))


#define P0(x) _mm256_xor_si256(_mm256_xor_si256(x, ROTL32(x,9)), ROTL32(x,17)) 
#define P1(x) _mm256_xor_si256(_mm256_xor_si256(x, ROTL32(x,15)), ROTL32(x,23))



/**
 * \brief          SM3 context structure
 */
typedef struct
{
    u256 s[8];
    unsigned char msgblocks[8 * 64];
    int datalen;
    unsigned long long msglen;

}
sm3ctx;
void store(__m256i v, unsigned char* out0, unsigned char* out1, unsigned char* out2, unsigned char* out3, unsigned char* out4, unsigned char* out5, unsigned char* out6, unsigned char* out7);
void transpose(u256 s[8]);
void sm3_init8x(sm3ctx* ctx);
void sm3_final8x(sm3ctx* ctx,
    unsigned char* out0,
    unsigned char* out1,
    unsigned char* out2,
    unsigned char* out3,
    unsigned char* out4,
    unsigned char* out5,
    unsigned char* out6,
    unsigned char* out7);

void sm3_transform8x(sm3ctx* ctx,
    const unsigned char* data0,
    const unsigned char* data1,
    const unsigned char* data2,
    const unsigned char* data3,
    const unsigned char* data4,
    const unsigned char* data5,
    const unsigned char* data6,
    const unsigned char* data7);

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * \brief          SM3 context setup
     *
     * \param ctx      context to be initialized
     */
    void sm3_init8x(sm3ctx* ctx);



    /**
     * \brief          Output = SM3( input buffer )
     *
     * \param input    buffer holding the  data
     * \param ilen     length of the input data
     * \param output   SM3 checksum result
     */

    /**
     * \brief          Output = SM3( file contents )
     *
     * \param path     input file name
     * \param output   SM3 checksum result
     *
     * \return         0 if successful, 1 if fopen failed,
     *                 or 2 if fread failed
     */


#ifdef __cplusplus
}
#endif

#endif /* sm3.h */
