#include "sm3avx.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "immintrin.h"

#define u32 uint32_t
#define u256 __m256i

#define SM3ROUND_AVX0(A, B, C, D, E, F, G, H, j, w,w1) \
    SS1 =ROTL32(ADD3_32(ROTL32(A,12),E,ROTL32(T[j],(j%32))), 7);\
    SS2=_mm256_xor_si256(SS1,ROTL32(A,12));\
    TT1=ADD4_32(FF0(A,B,C),D,SS2,w1);\
    TT2=ADD4_32(GG0(E,F,G),H,SS1,w);\
    B=ROTL32(B,9);\
    H=TT1;\
    F=ROTL32(F,19);\
    D=P0(TT2);

#define SM3ROUND_AVX(A, B, C, D, E, F, G, H, j, w,w1) \
    SS1 = ROTL32(ADD3_32(ROTL32(A,12),E,ROTL32(T[j],(j%32))), 7);\
    SS2=_mm256_xor_si256(SS1,ROTL32(A,12));\
    TT1=ADD4_32(FF1(A,B,C),D,SS2,w1);\
    TT2=ADD4_32(GG1(E,F,G),H,SS1,w);\
    B=ROTL32(B,9);\
    H=TT1;\
    F=ROTL32(F,19);\
    D=P0(TT2);



void store(__m256i v, unsigned char* out0, unsigned char* out1, unsigned char* out2, unsigned char* out3, unsigned char* out4, unsigned char* out5, unsigned char* out6, unsigned char* out7) {
    unsigned char buffer[32];
    _mm256_storeu_si256((__m256i*)buffer, v);

    for (int i = 0; i < 4; ++i) {
        out0[i] = buffer[i];
        out1[i] = buffer[i + 4];
        out2[i] = buffer[i + 8];
        out3[i] = buffer[i + 12];
        out4[i] = buffer[i + 16];
        out5[i] = buffer[i + 20];
        out6[i] = buffer[i + 24];
        out7[i] = buffer[i + 28];
    }
}

void transpose(u256 s[8]) {
    u256 tmp0[8];
    u256 tmp1[8];
    tmp0[0] = _mm256_unpacklo_epi32(s[0], s[1]);
    tmp0[1] = _mm256_unpackhi_epi32(s[0], s[1]);
    tmp0[2] = _mm256_unpacklo_epi32(s[2], s[3]);
    tmp0[3] = _mm256_unpackhi_epi32(s[2], s[3]);
    tmp0[4] = _mm256_unpacklo_epi32(s[4], s[5]);
    tmp0[5] = _mm256_unpackhi_epi32(s[4], s[5]);
    tmp0[6] = _mm256_unpacklo_epi32(s[6], s[7]);
    tmp0[7] = _mm256_unpackhi_epi32(s[6], s[7]);
    tmp1[0] = _mm256_unpacklo_epi64(tmp0[0], tmp0[2]);
    tmp1[1] = _mm256_unpackhi_epi64(tmp0[0], tmp0[2]);
    tmp1[2] = _mm256_unpacklo_epi64(tmp0[1], tmp0[3]);
    tmp1[3] = _mm256_unpackhi_epi64(tmp0[1], tmp0[3]);
    tmp1[4] = _mm256_unpacklo_epi64(tmp0[4], tmp0[6]);
    tmp1[5] = _mm256_unpackhi_epi64(tmp0[4], tmp0[6]);
    tmp1[6] = _mm256_unpacklo_epi64(tmp0[5], tmp0[7]);
    tmp1[7] = _mm256_unpackhi_epi64(tmp0[5], tmp0[7]);
    s[0] = _mm256_permute2x128_si256(tmp1[0], tmp1[4], 0x20);
    s[1] = _mm256_permute2x128_si256(tmp1[1], tmp1[5], 0x20);
    s[2] = _mm256_permute2x128_si256(tmp1[2], tmp1[6], 0x20);
    s[3] = _mm256_permute2x128_si256(tmp1[3], tmp1[7], 0x20);
    s[4] = _mm256_permute2x128_si256(tmp1[0], tmp1[4], 0x31);
    s[5] = _mm256_permute2x128_si256(tmp1[1], tmp1[5], 0x31);
    s[6] = _mm256_permute2x128_si256(tmp1[2], tmp1[6], 0x31);
    s[7] = _mm256_permute2x128_si256(tmp1[3], tmp1[7], 0x31);
}

/*
 * SM3 context setup
 */
void sm3_init8x(sm3ctx* ctx)
{

    ctx->s[0] = _mm256_set_epi32(0x7380166F, 0x7380166F, 0x7380166F, 0x7380166F, 0x7380166F, 0x7380166F, 0x7380166F, 0x7380166F);
    ctx->s[1] = _mm256_set_epi32(0x4914B2B9, 0x4914B2B9, 0x4914B2B9, 0x4914B2B9, 0x4914B2B9, 0x4914B2B9, 0x4914B2B9, 0x4914B2B9);
    ctx->s[2] = _mm256_set_epi32(0x172442D7, 0x172442D7, 0x172442D7, 0x172442D7, 0x172442D7, 0x172442D7, 0x172442D7, 0x172442D7);
    ctx->s[3] = _mm256_set_epi32(0xDA8A0600, 0xDA8A0600, 0xDA8A0600, 0xDA8A0600, 0xDA8A0600, 0xDA8A0600, 0xDA8A0600, 0xDA8A0600);
    ctx->s[4] = _mm256_set_epi32(0xA96F30BC, 0xA96F30BC, 0xA96F30BC, 0xA96F30BC, 0xA96F30BC, 0xA96F30BC, 0xA96F30BC, 0xA96F30BC);
    ctx->s[5] = _mm256_set_epi32(0x163138AA, 0x163138AA, 0x163138AA, 0x163138AA, 0x163138AA, 0x163138AA, 0x163138AA, 0x163138AA);
    ctx->s[6] = _mm256_set_epi32(0xE38DEE4D, 0xE38DEE4D, 0xE38DEE4D, 0xE38DEE4D, 0xE38DEE4D, 0xE38DEE4D, 0xE38DEE4D, 0xE38DEE4D);
    ctx->s[7] = _mm256_set_epi32(0xB0FB0E4E, 0xB0FB0E4E, 0xB0FB0E4E, 0xB0FB0E4E, 0xB0FB0E4E, 0xB0FB0E4E, 0xB0FB0E4E, 0xB0FB0E4E);
    ctx->datalen = 0;
    ctx->msglen = 0;

}


void sm3_final8x(sm3ctx* ctx,
    unsigned char* out0,
    unsigned char* out1,
    unsigned char* out2,
    unsigned char* out3,
    unsigned char* out4,
    unsigned char* out5,
    unsigned char* out6,
    unsigned char* out7)
{
    unsigned int i, curlen;

    // Padding
    if (ctx->datalen < 56) {
        for (i = 0; i < 8; ++i) {
            curlen = ctx->datalen;
            ctx->msgblocks[64 * i + curlen++] = 0x80;
            while (curlen < 64) {
                ctx->msgblocks[64 * i + curlen++] = 0x00;
            }
        }
    }
    else {
        for (i = 0; i < 8; ++i) {
            curlen = ctx->datalen;
            ctx->msgblocks[64 * i + curlen++] = 0x80;
            while (curlen < 64) {
                ctx->msgblocks[64 * i + curlen++] = 0x00;
            }
        }
        sm3_transform8x(ctx,
            &ctx->msgblocks[64 * 0],
            &ctx->msgblocks[64 * 1],
            &ctx->msgblocks[64 * 2],
            &ctx->msgblocks[64 * 3],
            &ctx->msgblocks[64 * 4],
            &ctx->msgblocks[64 * 5],
            &ctx->msgblocks[64 * 6],
            &ctx->msgblocks[64 * 7]
        );
        memset(ctx->msgblocks, 0, 8 * 64);
    }
    // Add length of the message to each block
    ctx->msglen += ctx->datalen * 8;
    for (i = 0; i < 8; i++) {
        ctx->msgblocks[64 * i + 63] = ctx->msglen;
        ctx->msgblocks[64 * i + 62] = ctx->msglen >> 8;
        ctx->msgblocks[64 * i + 61] = ctx->msglen >> 16;
        ctx->msgblocks[64 * i + 60] = ctx->msglen >> 24;
        ctx->msgblocks[64 * i + 59] = ctx->msglen >> 32;
        ctx->msgblocks[64 * i + 58] = ctx->msglen >> 40;
        ctx->msgblocks[64 * i + 57] = ctx->msglen >> 48;
        ctx->msgblocks[64 * i + 56] = ctx->msglen >> 56;
    }
    sm3_transform8x(ctx,
        &ctx->msgblocks[64 * 0],
        &ctx->msgblocks[64 * 1],
        &ctx->msgblocks[64 * 2],
        &ctx->msgblocks[64 * 3],
        &ctx->msgblocks[64 * 4],
        &ctx->msgblocks[64 * 5],
        &ctx->msgblocks[64 * 6],
        &ctx->msgblocks[64 * 7]
    );

    // Compute final hash output
    transpose(ctx->s);

    store(BYTESWAP(ctx->s[0]), out0, out1, out2, out3, out4, out5, out6, out7);
    // Store Hash value
    //STORE(out0, BYTESWAP(ctx->s[0]));
    //STORE(out1, BYTESWAP(ctx->s[1]));
    //STORE(out2, BYTESWAP(ctx->s[2]));
    //STORE(out3, BYTESWAP(ctx->s[3]));
    //STORE(out4, BYTESWAP(ctx->s[4]));
    //STORE(out5, BYTESWAP(ctx->s[5]));
    //STORE(out6, BYTESWAP(ctx->s[6]));
    //STORE(out7, BYTESWAP(ctx->s[7]));
}

void sm3_transform8x(sm3ctx* ctx,
    const unsigned char* data0,
    const unsigned char* data1,
    const unsigned char* data2,
    const unsigned char* data3,
    const unsigned char* data4,
    const unsigned char* data5,
    const unsigned char* data6,
    const unsigned char* data7) {
    u256 s[8], w[68];
    u256 SS1, SS2, TT1, TT2, w1[64];
    u256 T[64];
    int j;


    for (j = 0; j < 16; j++)
        T[j] = _mm256_set1_epi32(0x79CC4519);
    for (j = 16; j < 64; j++)
        T[j] = _mm256_set1_epi32(0x7A879D8A);

    // Load words and transform data correctly
    w[0] = BYTESWAP(LOAD(data0));
    w[0 + 8] = BYTESWAP(LOAD(data0 + 32));
    w[1] = BYTESWAP(LOAD(data1));
    w[1 + 8] = BYTESWAP(LOAD(data1 + 32));
    w[2] = BYTESWAP(LOAD(data2));
    w[2 + 8] = BYTESWAP(LOAD(data2 + 32));
    w[3] = BYTESWAP(LOAD(data3));
    w[3 + 8] = BYTESWAP(LOAD(data3 + 32));
    w[4] = BYTESWAP(LOAD(data4));
    w[4 + 8] = BYTESWAP(LOAD(data4 + 32));
    w[5] = BYTESWAP(LOAD(data5));
    w[5 + 8] = BYTESWAP(LOAD(data5 + 32));
    w[6] = BYTESWAP(LOAD(data6));
    w[6 + 8] = BYTESWAP(LOAD(data6 + 32));
    w[7] = BYTESWAP(LOAD(data7));
    w[7 + 8] = BYTESWAP(LOAD(data7 + 32));
    

    transpose(w);
    transpose(w + 8);

    //w[0] = copy_first_32_bits(w[0]);
    // Initial State
    s[0] = ctx->s[0];
    s[1] = ctx->s[1];
    s[2] = ctx->s[2];
    s[3] = ctx->s[3];
    s[4] = ctx->s[4];
    s[5] = ctx->s[5];
    s[6] = ctx->s[6];
    s[7] = ctx->s[7];





    w1[0] = _mm256_xor_si256(w[0], w[4]);
    w1[1] = _mm256_xor_si256(w[1], w[5]);
    w1[2] = _mm256_xor_si256(w[2], w[6]);
    w1[3] = _mm256_xor_si256(w[3], w[7]);
    w1[4] = _mm256_xor_si256(w[4], w[8]);
    w1[5] = _mm256_xor_si256(w[5], w[9]);
    w1[6] = _mm256_xor_si256(w[6], w[10]);
    w1[7] = _mm256_xor_si256(w[7], w[11]);
    w1[8] = _mm256_xor_si256(w[8], w[12]);
    w1[9] = _mm256_xor_si256(w[9], w[13]);
    w1[10] = _mm256_xor_si256(w[10], w[14]);
    w1[11] = _mm256_xor_si256(w[11], w[15]);
    SM3ROUND_AVX0(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], 0, w[0], w1[0]);
    SM3ROUND_AVX0(s[7], s[0], s[1], s[2], s[3], s[4], s[5], s[6], 1, w[1], w1[1]);
    SM3ROUND_AVX0(s[6], s[7], s[0], s[1], s[2], s[3], s[4], s[5], 2, w[2], w1[2]);
    SM3ROUND_AVX0(s[5], s[6], s[7], s[0], s[1], s[2], s[3], s[4], 3, w[3], w1[3]);
    SM3ROUND_AVX0(s[4], s[5], s[6], s[7], s[0], s[1], s[2], s[3], 4, w[4], w1[4]);
    SM3ROUND_AVX0(s[3], s[4], s[5], s[6], s[7], s[0], s[1], s[2], 5, w[5], w1[5]);
    SM3ROUND_AVX0(s[2], s[3], s[4], s[5], s[6], s[7], s[0], s[1], 6, w[6], w1[6]);
    SM3ROUND_AVX0(s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[0], 7, w[7], w1[7]);
    SM3ROUND_AVX0(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], 8, w[8], w1[8]);
    SM3ROUND_AVX0(s[7], s[0], s[1], s[2], s[3], s[4], s[5], s[6], 9, w[9], w1[9]);
    SM3ROUND_AVX0(s[6], s[7], s[0], s[1], s[2], s[3], s[4], s[5], 10, w[10], w1[10]);
    SM3ROUND_AVX0(s[5], s[6], s[7], s[0], s[1], s[2], s[3], s[4], 11, w[11], w1[11]);
    w[16] = XOR3(P1(XOR3(w[0], w[7], ROTL32(w[13], 15))), ROTL32(w[3], 7), w[10]);
    w1[12] = XOR(w[12], w[16]);
    SM3ROUND_AVX0(s[4], s[5], s[6], s[7], s[0], s[1], s[2], s[3], 12, w[12], w1[12]);
    w[17] = XOR3(P1(XOR3(w[1], w[8], ROTL32(w[14], 15))), ROTL32(w[4], 7), w[11]);
    w1[13] = XOR(w[13], w[17]);
    SM3ROUND_AVX0(s[3], s[4], s[5], s[6], s[7], s[0], s[1], s[2], 13, w[13], w1[13]);
    w[18] = XOR3(P1(XOR3(w[2], w[9], ROTL32(w[15], 15))), ROTL32(w[5], 7), w[12]);
    w1[14] = XOR(w[14], w[18]);
    SM3ROUND_AVX0(s[2], s[3], s[4], s[5], s[6], s[7], s[0], s[1], 14, w[14], w1[14]);
    w[19] = XOR3(P1(XOR3(w[3], w[10], ROTL32(w[16], 15))), ROTL32(w[6], 7), w[13]);
    w1[15] = XOR(w[15], w[19]);
    SM3ROUND_AVX0(s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[0], 15, w[15], w1[15]);
    w[20] = XOR3(P1(XOR3(w[4], w[11], ROTL32(w[17], 15))), ROTL32(w[7], 7), w[14]);
    w1[16] = XOR(w[16], w[20]);
    SM3ROUND_AVX(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], 16, w[16], w1[16]);
    w[21] = XOR3(P1(XOR3(w[5], w[12], ROTL32(w[18], 15))), ROTL32(w[8], 7), w[15]);
    w1[17] = XOR(w[17], w[21]);
    SM3ROUND_AVX(s[7], s[0], s[1], s[2], s[3], s[4], s[5], s[6], 17, w[17], w1[17]);
    w[22] = XOR3(P1(XOR3(w[6], w[13], ROTL32(w[19], 15))), ROTL32(w[9], 7), w[16]);
    w1[18] = XOR(w[18], w[22]);
    SM3ROUND_AVX(s[6], s[7], s[0], s[1], s[2], s[3], s[4], s[5], 18, w[18], w1[18]);
    w[23] = XOR3(P1(XOR3(w[7], w[14], ROTL32(w[20], 15))), ROTL32(w[10], 7), w[17]);
    w1[19] = XOR(w[19], w[23]);
    SM3ROUND_AVX(s[5], s[6], s[7], s[0], s[1], s[2], s[3], s[4], 19, w[19], w1[19]);
    w[24] = XOR3(P1(XOR3(w[8], w[15], ROTL32(w[21], 15))), ROTL32(w[11], 7), w[18]);
    w1[20] = XOR(w[20], w[24]);
    SM3ROUND_AVX(s[4], s[5], s[6], s[7], s[0], s[1], s[2], s[3], 20, w[20], w1[20]);
    w[25] = XOR3(P1(XOR3(w[9], w[16], ROTL32(w[22], 15))), ROTL32(w[12], 7), w[19]);
    w1[21] = XOR(w[21], w[25]);
    SM3ROUND_AVX(s[3], s[4], s[5], s[6], s[7], s[0], s[1], s[2], 21, w[21], w1[21]);
    w[26] = XOR3(P1(XOR3(w[10], w[17], ROTL32(w[23], 15))), ROTL32(w[13], 7), w[20]);
    w1[22] = XOR(w[22], w[26]);
    SM3ROUND_AVX(s[2], s[3], s[4], s[5], s[6], s[7], s[0], s[1], 22, w[22], w1[22]);
    w[27] = XOR3(P1(XOR3(w[11], w[18], ROTL32(w[24], 15))), ROTL32(w[14], 7), w[21]);
    w1[23] = XOR(w[23], w[27]);
    SM3ROUND_AVX(s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[0], 23, w[23], w1[23]);
    w[28] = XOR3(P1(XOR3(w[12], w[19], ROTL32(w[25], 15))), ROTL32(w[15], 7), w[22]);
    w1[24] = XOR(w[24], w[28]);
    SM3ROUND_AVX(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], 24, w[24], w1[24]);
    w[29] = XOR3(P1(XOR3(w[13], w[20], ROTL32(w[26], 15))), ROTL32(w[16], 7), w[23]);
    w1[25] = XOR(w[25], w[29]);
    SM3ROUND_AVX(s[7], s[0], s[1], s[2], s[3], s[4], s[5], s[6], 25, w[25], w1[25]);
    w[30] = XOR3(P1(XOR3(w[14], w[21], ROTL32(w[27], 15))), ROTL32(w[17], 7), w[24]);
    w1[26] = XOR(w[26], w[30]);
    SM3ROUND_AVX(s[6], s[7], s[0], s[1], s[2], s[3], s[4], s[5], 26, w[26], w1[26]);
    w[31] = XOR3(P1(XOR3(w[15], w[22], ROTL32(w[28], 15))), ROTL32(w[18], 7), w[25]);
    w1[27] = XOR(w[27], w[31]);
    SM3ROUND_AVX(s[5], s[6], s[7], s[0], s[1], s[2], s[3], s[4], 27, w[27], w1[27]);
    w[32] = XOR3(P1(XOR3(w[16], w[23], ROTL32(w[29], 15))), ROTL32(w[19], 7), w[26]);
    w1[28] = XOR(w[28], w[32]);
    SM3ROUND_AVX(s[4], s[5], s[6], s[7], s[0], s[1], s[2], s[3], 28, w[28], w1[28]);
    w[33] = XOR3(P1(XOR3(w[17], w[24], ROTL32(w[30], 15))), ROTL32(w[20], 7), w[27]);
    w1[29] = XOR(w[29], w[33]);
    SM3ROUND_AVX(s[3], s[4], s[5], s[6], s[7], s[0], s[1], s[2], 29, w[29], w1[29]);
    w[34] = XOR3(P1(XOR3(w[18], w[25], ROTL32(w[31], 15))), ROTL32(w[21], 7), w[28]);
    w1[30] = XOR(w[30], w[34]);
    SM3ROUND_AVX(s[2], s[3], s[4], s[5], s[6], s[7], s[0], s[1], 30, w[30], w1[30]);
    w[35] = XOR3(P1(XOR3(w[19], w[26], ROTL32(w[32], 15))), ROTL32(w[22], 7), w[29]);
    w1[31] = XOR(w[31], w[35]);
    SM3ROUND_AVX(s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[0], 31, w[31], w1[31]);
    w[36] = XOR3(P1(XOR3(w[20], w[27], ROTL32(w[33], 15))), ROTL32(w[23], 7), w[30]);
    w1[32] = XOR(w[32], w[36]);
    SM3ROUND_AVX(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], 32, w[32], w1[32]);
    w[37] = XOR3(P1(XOR3(w[21], w[28], ROTL32(w[34], 15))), ROTL32(w[24], 7), w[31]);
    w1[33] = XOR(w[33], w[37]);
    SM3ROUND_AVX(s[7], s[0], s[1], s[2], s[3], s[4], s[5], s[6], 33, w[33], w1[33]);
    w[38] = XOR3(P1(XOR3(w[22], w[29], ROTL32(w[35], 15))), ROTL32(w[25], 7), w[32]);
    w1[34] = XOR(w[34], w[38]);
    SM3ROUND_AVX(s[6], s[7], s[0], s[1], s[2], s[3], s[4], s[5], 34, w[34], w1[34]);
    w[39] = XOR3(P1(XOR3(w[23], w[30], ROTL32(w[36], 15))), ROTL32(w[26], 7), w[33]);
    w1[35] = XOR(w[35], w[39]);
    SM3ROUND_AVX(s[5], s[6], s[7], s[0], s[1], s[2], s[3], s[4], 35, w[35], w1[35]);
    w[40] = XOR3(P1(XOR3(w[24], w[31], ROTL32(w[37], 15))), ROTL32(w[27], 7), w[34]);
    w1[36] = XOR(w[36], w[40]);
    SM3ROUND_AVX(s[4], s[5], s[6], s[7], s[0], s[1], s[2], s[3], 36, w[36], w1[36]);
    w[41] = XOR3(P1(XOR3(w[25], w[32], ROTL32(w[38], 15))), ROTL32(w[28], 7), w[35]);
    w1[37] = XOR(w[37], w[41]);
    SM3ROUND_AVX(s[3], s[4], s[5], s[6], s[7], s[0], s[1], s[2], 37, w[37], w1[37]);
    w[42] = XOR3(P1(XOR3(w[26], w[33], ROTL32(w[39], 15))), ROTL32(w[29], 7), w[36]);
    w1[38] = XOR(w[38], w[42]);
    SM3ROUND_AVX(s[2], s[3], s[4], s[5], s[6], s[7], s[0], s[1], 38, w[38], w1[38]);
    w[43] = XOR3(P1(XOR3(w[27], w[34], ROTL32(w[40], 15))), ROTL32(w[30], 7), w[37]);
    w1[39] = XOR(w[39], w[43]);
    SM3ROUND_AVX(s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[0], 39, w[39], w1[39]);
    w[44] = XOR3(P1(XOR3(w[28], w[35], ROTL32(w[41], 15))), ROTL32(w[31], 7), w[38]);
    w1[40] = XOR(w[40], w[44]);
    SM3ROUND_AVX(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], 40, w[40], w1[40]);
    w[45] = XOR3(P1(XOR3(w[29], w[36], ROTL32(w[42], 15))), ROTL32(w[32], 7), w[39]);
    w1[41] = XOR(w[41], w[45]);
    SM3ROUND_AVX(s[7], s[0], s[1], s[2], s[3], s[4], s[5], s[6], 41, w[41], w1[41]);
    w[46] = XOR3(P1(XOR3(w[30], w[37], ROTL32(w[43], 15))), ROTL32(w[33], 7), w[40]);
    w1[42] = XOR(w[42], w[46]);
    SM3ROUND_AVX(s[6], s[7], s[0], s[1], s[2], s[3], s[4], s[5], 42, w[42], w1[42]);
    w[47] = XOR3(P1(XOR3(w[31], w[38], ROTL32(w[44], 15))), ROTL32(w[34], 7), w[41]);
    w1[43] = XOR(w[43], w[47]);
    SM3ROUND_AVX(s[5], s[6], s[7], s[0], s[1], s[2], s[3], s[4], 43, w[43], w1[43]);
    w[48] = XOR3(P1(XOR3(w[32], w[39], ROTL32(w[45], 15))), ROTL32(w[35], 7), w[42]);
    w1[44] = XOR(w[44], w[48]);
    SM3ROUND_AVX(s[4], s[5], s[6], s[7], s[0], s[1], s[2], s[3], 44, w[44], w1[44]);
    w[49] = XOR3(P1(XOR3(w[33], w[40], ROTL32(w[46], 15))), ROTL32(w[36], 7), w[43]);
    w1[45] = XOR(w[45], w[49]);
    SM3ROUND_AVX(s[3], s[4], s[5], s[6], s[7], s[0], s[1], s[2], 45, w[45], w1[45]);
    w[50] = XOR3(P1(XOR3(w[34], w[41], ROTL32(w[47], 15))), ROTL32(w[37], 7), w[44]);
    w1[46] = XOR(w[46], w[50]);
    SM3ROUND_AVX(s[2], s[3], s[4], s[5], s[6], s[7], s[0], s[1], 46, w[46], w1[46]);
    w[51] = XOR3(P1(XOR3(w[35], w[42], ROTL32(w[48], 15))), ROTL32(w[38], 7), w[45]);
    w1[47] = XOR(w[47], w[51]);
    SM3ROUND_AVX(s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[0], 47, w[47], w1[47]);
    w[52] = XOR3(P1(XOR3(w[36], w[43], ROTL32(w[49], 15))), ROTL32(w[39], 7), w[46]);
    w1[48] = XOR(w[48], w[52]);
    SM3ROUND_AVX(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], 48, w[48], w1[48]);
    w[53] = XOR3(P1(XOR3(w[37], w[44], ROTL32(w[50], 15))), ROTL32(w[40], 7), w[47]);
    w1[49] = XOR(w[49], w[53]);
    SM3ROUND_AVX(s[7], s[0], s[1], s[2], s[3], s[4], s[5], s[6], 49, w[49], w1[49]);
    w[54] = XOR3(P1(XOR3(w[38], w[45], ROTL32(w[51], 15))), ROTL32(w[41], 7), w[48]);
    w1[50] = XOR(w[50], w[54]);
    SM3ROUND_AVX(s[6], s[7], s[0], s[1], s[2], s[3], s[4], s[5], 50, w[50], w1[50]);
    w[55] = XOR3(P1(XOR3(w[39], w[46], ROTL32(w[52], 15))), ROTL32(w[42], 7), w[49]);
    w1[51] = XOR(w[51], w[55]);
    SM3ROUND_AVX(s[5], s[6], s[7], s[0], s[1], s[2], s[3], s[4], 51, w[51], w1[51]);
    w[56] = XOR3(P1(XOR3(w[40], w[47], ROTL32(w[53], 15))), ROTL32(w[43], 7), w[50]);
    w1[52] = XOR(w[52], w[56]);
    SM3ROUND_AVX(s[4], s[5], s[6], s[7], s[0], s[1], s[2], s[3], 52, w[52], w1[52]);
    w[57] = XOR3(P1(XOR3(w[41], w[48], ROTL32(w[54], 15))), ROTL32(w[44], 7), w[51]);
    w1[53] = XOR(w[53], w[57]);
    SM3ROUND_AVX(s[3], s[4], s[5], s[6], s[7], s[0], s[1], s[2], 53, w[53], w1[53]);
    w[58] = XOR3(P1(XOR3(w[42], w[49], ROTL32(w[55], 15))), ROTL32(w[45], 7), w[52]);
    w1[54] = XOR(w[54], w[58]);
    SM3ROUND_AVX(s[2], s[3], s[4], s[5], s[6], s[7], s[0], s[1], 54, w[54], w1[54]);
    w[59] = XOR3(P1(XOR3(w[43], w[50], ROTL32(w[56], 15))), ROTL32(w[46], 7), w[53]);
    w1[55] = XOR(w[55], w[59]);
    SM3ROUND_AVX(s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[0], 55, w[55], w1[55]);
    w[60] = XOR3(P1(XOR3(w[44], w[51], ROTL32(w[57], 15))), ROTL32(w[47], 7), w[54]);
    w1[56] = XOR(w[56], w[60]);
    SM3ROUND_AVX(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], 56, w[56], w1[56]);
    w[61] = XOR3(P1(XOR3(w[45], w[52], ROTL32(w[58], 15))), ROTL32(w[48], 7), w[55]);
    w1[57] = XOR(w[57], w[61]);
    SM3ROUND_AVX(s[7], s[0], s[1], s[2], s[3], s[4], s[5], s[6], 57, w[57], w1[57]);
    w[62] = XOR3(P1(XOR3(w[46], w[53], ROTL32(w[59], 15))), ROTL32(w[49], 7), w[56]);
    w1[58] = XOR(w[58], w[62]);
    SM3ROUND_AVX(s[6], s[7], s[0], s[1], s[2], s[3], s[4], s[5], 58, w[58], w1[58]);
    w[63] = XOR3(P1(XOR3(w[47], w[54], ROTL32(w[60], 15))), ROTL32(w[50], 7), w[57]);
    w1[59] = XOR(w[59], w[63]);
    SM3ROUND_AVX(s[5], s[6], s[7], s[0], s[1], s[2], s[3], s[4], 59, w[59], w1[59]);
    w[64] = XOR3(P1(XOR3(w[48], w[55], ROTL32(w[61], 15))), ROTL32(w[51], 7), w[58]);
    w1[60] = XOR(w[60], w[64]);
    SM3ROUND_AVX(s[4], s[5], s[6], s[7], s[0], s[1], s[2], s[3], 60, w[60], w1[60]);
    w[65] = XOR3(P1(XOR3(w[49], w[56], ROTL32(w[62], 15))), ROTL32(w[52], 7), w[59]);
    w1[61] = XOR(w[61], w[65]);
    SM3ROUND_AVX(s[3], s[4], s[5], s[6], s[7], s[0], s[1], s[2], 61, w[61], w1[61]);
    w[66] = XOR3(P1(XOR3(w[50], w[57], ROTL32(w[63], 15))), ROTL32(w[53], 7), w[60]);
    w1[62] = XOR(w[62], w[66]);
    SM3ROUND_AVX(s[2], s[3], s[4], s[5], s[6], s[7], s[0], s[1], 62, w[62], w1[62]);
    w[67] = XOR3(P1(XOR3(w[51], w[58], ROTL32(w[64], 15))), ROTL32(w[54], 7), w[61]);
    w1[63] = XOR(w[63], w[67]);
    SM3ROUND_AVX(s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[0], 63, w[63], w1[63]);

    // Feed Forward
    ctx->s[0] = XOR(s[0], ctx->s[0]);
    ctx->s[1] = XOR(s[1], ctx->s[1]);
    ctx->s[2] = XOR(s[2], ctx->s[2]);
    ctx->s[3] = XOR(s[3], ctx->s[3]);
    ctx->s[4] = XOR(s[4], ctx->s[4]);
    ctx->s[5] = XOR(s[5], ctx->s[5]);
    ctx->s[6] = XOR(s[6], ctx->s[6]);
    ctx->s[7] = XOR(s[7], ctx->s[7]);
}




