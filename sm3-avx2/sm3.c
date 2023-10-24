/*
 * SM3 Hash alogrith
 * thanks to Xyssl
 * author:goldboar
 * email:goldboar@163.com
 * 2011-10-26
 */

 //Testing data from SM3 Standards
 //http://www.oscca.gov.cn/News/201012/News_1199.htm 
 // Sample 1
 // Input:"abc"  
 // Output:66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0

 // Sample 2 
 // Input:"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
 // Outpuf:debe9ff9 2275b8a1 38604889 c18e5a4d 6fdb70e5 387e5765 293dcba3 9c0c5732


#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "utils.h"
#include "sm3.h"
/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                             \
{                                                       \
    (n) = ( (unsigned int) (b)[(i)    ] << 24 )        \
        | ( (unsigned int) (b)[(i) + 1] << 16 )        \
        | ( (unsigned int) (b)[(i) + 2] <<  8 )        \
        | ( (unsigned int) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                             \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

 /*
  * SM3 context setup
  */

static uint64_t load_bigendian_64(const uint8_t *x) {
    return (uint64_t)(x[7]) | (((uint64_t)(x[6])) << 8) |
           (((uint64_t)(x[5])) << 16) | (((uint64_t)(x[4])) << 24) |
           (((uint64_t)(x[3])) << 32) | (((uint64_t)(x[2])) << 40) |
           (((uint64_t)(x[1])) << 48) | (((uint64_t)(x[0])) << 56);
}

static void store_bigendian_64(uint8_t *x, uint64_t u) {
    x[7] = (uint8_t) u;
    u >>= 8;
    x[6] = (uint8_t) u;
    u >>= 8;
    x[5] = (uint8_t) u;
    u >>= 8;
    x[4] = (uint8_t) u;
    u >>= 8;
    x[3] = (uint8_t) u;
    u >>= 8;
    x[2] = (uint8_t) u;
    u >>= 8;
    x[1] = (uint8_t) u;
    u >>= 8;
    x[0] = (uint8_t) u;
}

void sm3_process_block(unsigned int state[8],const unsigned char data[64])
{
    unsigned int SS1, SS2, TT1, TT2, W[68], W1[64];
    unsigned int A, B, C, D, E, F, G, H;
    unsigned int T[64];
    unsigned int Temp1, Temp2, Temp3, Temp4, Temp5;
    int j;
#ifdef _DEBUG
    int i;
#endif

    // 	for(j=0; j < 68; j++)
    // 		W[j] = 0;
    // 	for(j=0; j < 64; j++)
    // 		W1[j] = 0;

    for (j = 0; j < 16; j++)
        T[j] = 0x79CC4519;
    for (j = 16; j < 64; j++)
        T[j] = 0x7A879D8A;

    GET_ULONG_BE(W[0], data, 0);
    GET_ULONG_BE(W[1], data, 4);
    GET_ULONG_BE(W[2], data, 8);
    GET_ULONG_BE(W[3], data, 12);
    GET_ULONG_BE(W[4], data, 16);
    GET_ULONG_BE(W[5], data, 20);
    GET_ULONG_BE(W[6], data, 24);
    GET_ULONG_BE(W[7], data, 28);
    GET_ULONG_BE(W[8], data, 32);
    GET_ULONG_BE(W[9], data, 36);
    GET_ULONG_BE(W[10], data, 40);
    GET_ULONG_BE(W[11], data, 44);
    GET_ULONG_BE(W[12], data, 48);
    GET_ULONG_BE(W[13], data, 52);
    GET_ULONG_BE(W[14], data, 56);
    GET_ULONG_BE(W[15], data, 60);

#ifdef _DEBUG 
    printf("Message with padding:\n");
    for (i = 0; i < 8; i++)
        printf("%08x ", W[i]);
    printf("\n");
    for (i = 8; i < 16; i++)
        printf("%08x ", W[i]);
    printf("\n");
#endif

#define FF0(x,y,z) ( (x) ^ (y) ^ (z)) 
#define FF1(x,y,z) (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))

#define GG0(x,y,z) ( (x) ^ (y) ^ (z)) 
#define GG1(x,y,z) (((x) & (y)) | ( (~(x)) & (z)) )


#define  SHL(x,n) (((x) & 0xFFFFFFFF) << n)
#define ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n)))

#define P0(x) ((x) ^  ROTL((x),9) ^ ROTL((x),17)) 
#define P1(x) ((x) ^  ROTL((x),15) ^ ROTL((x),23)) 

    for (j = 16; j < 68; j++)
    {
        //W[j] = P1( W[j-16] ^ W[j-9] ^ ROTL(W[j-3],15)) ^ ROTL(W[j - 13],7 ) ^ W[j-6];
        //Why thd release's result is different with the debug's ?
        //Below is okay. Interesting, Perhaps VC6 has a bug of Optimizaiton.

        Temp1 = W[j - 16] ^ W[j - 9];
        Temp2 = ROTL(W[j - 3], 15);
        Temp3 = Temp1 ^ Temp2;
        Temp4 = P1(Temp3);
        Temp5 = ROTL(W[j - 13], 7) ^ W[j - 6];
        W[j] = Temp4 ^ Temp5;
    }

#ifdef _DEBUG 
    printf("Expanding message W0-67:\n");
    for (i = 0; i < 68; i++)
    {
        printf("%08x ", W[i]);
        if (((i + 1) % 8) == 0) printf("\n");
    }
    printf("\n");
#endif

    for (j = 0; j < 64; j++)
    {
        W1[j] = W[j] ^ W[j + 4];
    }

#ifdef _DEBUG 
    printf("Expanding message W'0-63:\n");
    for (i = 0; i < 64; i++)
    {
        printf("%08x ", W1[i]);
        if (((i + 1) % 8) == 0) printf("\n");
    }
    printf("\n");
#endif

    A = state[0];
    B = state[1];
    C = state[2];
    D = state[3];
    E = state[4];
    F = state[5];
    G = state[6];
    H = state[7];
#ifdef _DEBUG       
    printf("j     A       B        C         D         E        F        G       H\n");
    printf("   %08x %08x %08x %08x %08x %08x %08x %08x\n", A, B, C, D, E, F, G, H);
#endif

    for (j = 0; j < 16; j++)
    {
        SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = FF0(A, B, C) + D + SS2 + W1[j];
        TT2 = GG0(E, F, G) + H + SS1 + W[j];
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
#ifdef _DEBUG 
        printf("%02d %08x %08x %08x %08x %08x %08x %08x %08x\n", j, A, B, C, D, E, F, G, H);
#endif
    }

    for (j = 16; j < 64; j++)
    {
        SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = FF1(A, B, C) + D + SS2 + W1[j];
        TT2 = GG1(E, F, G) + H + SS1 + W[j];
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
#ifdef _DEBUG 
        printf("%02d %08x %08x %08x %08x %08x %08x %08x %08x\n", j, A, B, C, D, E, F, G, H);
#endif	
    }

    state[0] ^= A;
    state[1] ^= B;
    state[2] ^= C;
    state[3] ^= D;
    state[4] ^= E;
    state[5] ^= F;
    state[6] ^= G;
    state[7] ^= H;
#ifdef _DEBUG 
    printf("   %08x %08x %08x %08x %08x %08x %08x %08x\n", ctx->state[0], ctx->state[1], ctx->state[2],
        ctx->state[3], ctx->state[4], ctx->state[5], ctx->state[6], ctx->state[7]);
#endif
}

void sm3_inc_blocks(uint8_t *state, const uint8_t *in, size_t inblocks) {
    uint64_t bytes = load_bigendian_64(state + 32);

    crypto_hashblocks_sm3(state, in, 64 * inblocks);
    bytes += 64 * inblocks;

    store_bigendian_64(state + 32, bytes);
}

void uint8_to_uint32(const uint8_t* in, unsigned int* out) {
    for (size_t i = 0; i < 8; i++) {
        out[i] = ((unsigned int)in[i * 4] << 24) | ((unsigned int)in[i * 4 + 1] << 16) | ((unsigned int)in[i * 4 + 2] << 8) | (unsigned int)in[i * 4 + 3];
    }
}

size_t crypto_hashblocks_sm3(uint8_t *statebytes, const uint8_t *input, size_t inlen) {
    unsigned int state[8];
    uint8_to_uint32(statebytes, state);
    unsigned int fill;
    unsigned int left;
    unsigned int total[2];
    unsigned char buffer[64];

    total[0] = 0;
    total[1] = 0;

    left = total[0] & 0x3F;
    fill = 64 - left; 

    total[0] += inlen;
    total[0] &= 0xFFFFFFFF;

    if (total[0] < (unsigned int)inlen)
        total[1]++;

    if (left && (unsigned int)inlen >= fill)
    {
        memcpy((void*)(buffer + left),
            (void*)input, fill);
        sm3_process_block(state, buffer);
        input += fill;
        inlen -= fill;
        left = 0;
    }

    while (inlen >= 64)
    {
        sm3_process_block(state, input);
        input += 64;
        inlen -= 64;
    }

    if (inlen > 0)
    {
        memcpy((void*)(buffer + left),
            (void*)input, inlen);
    }
    return inlen;
}

void sm3_starts(sm3_context* ctx ,uint8_t* state_t)
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;
    uint8_to_uint32(state_t, ctx->state);
}
/*
 * SM3 process buffer
 */
void sm3_update(sm3_context* ctx,const unsigned char* input, size_t ilen)
{
    unsigned int fill;
    unsigned int left;

    if (ilen <= 0)
        return;

    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

    ctx->total[0] += ilen;
    ctx->total[0] &= 0xFFFFFFFF;

    if (ctx->total[0] < (unsigned int)ilen)
        ctx->total[1]++;

    if (left && ilen >= fill)
    {
        memcpy((void*)(ctx->buffer + left),
            (void*)input, fill);
        sm3_process(ctx, ctx->buffer);
        input += fill;
        ilen -= fill;
        left = 0;
    }

    while (ilen >= 64)
    {
        sm3_process(ctx, (unsigned char*)input);
        input += 64;
        ilen -= 64;
    }

    if (ilen > 0)
    {
        memcpy((void*)(ctx->buffer + left),
            (void*)input, ilen);
    }
}

static const unsigned char sm3_padding[64] =
{
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void sm3_process(sm3_context* ctx, unsigned char data[64])
{
    unsigned int SS1, SS2, TT1, TT2, W[68], W1[64];
    unsigned int A, B, C, D, E, F, G, H;
    unsigned int T[64];
    unsigned int Temp1, Temp2, Temp3, Temp4, Temp5;
    int j;
#ifdef _DEBUG
    int i;
#endif

    // 	for(j=0; j < 68; j++)
    // 		W[j] = 0;
    // 	for(j=0; j < 64; j++)
    // 		W1[j] = 0;

    for (j = 0; j < 16; j++)
        T[j] = 0x79CC4519;
    for (j = 16; j < 64; j++)
        T[j] = 0x7A879D8A;

    GET_ULONG_BE(W[0], data, 0);
    GET_ULONG_BE(W[1], data, 4);
    GET_ULONG_BE(W[2], data, 8);
    GET_ULONG_BE(W[3], data, 12);
    GET_ULONG_BE(W[4], data, 16);
    GET_ULONG_BE(W[5], data, 20);
    GET_ULONG_BE(W[6], data, 24);
    GET_ULONG_BE(W[7], data, 28);
    GET_ULONG_BE(W[8], data, 32);
    GET_ULONG_BE(W[9], data, 36);
    GET_ULONG_BE(W[10], data, 40);
    GET_ULONG_BE(W[11], data, 44);
    GET_ULONG_BE(W[12], data, 48);
    GET_ULONG_BE(W[13], data, 52);
    GET_ULONG_BE(W[14], data, 56);
    GET_ULONG_BE(W[15], data, 60);

#ifdef _DEBUG 
    printf("Message with padding:\n");
    for (i = 0; i < 8; i++)
        printf("%08x ", W[i]);
    printf("\n");
    for (i = 8; i < 16; i++)
        printf("%08x ", W[i]);
    printf("\n");
#endif

#define FF0(x,y,z) ( (x) ^ (y) ^ (z)) 
#define FF1(x,y,z) (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))

#define GG0(x,y,z) ( (x) ^ (y) ^ (z)) 
#define GG1(x,y,z) (((x) & (y)) | ( (~(x)) & (z)) )


#define  SHL(x,n) (((x) & 0xFFFFFFFF) << n)
#define ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n)))

#define P0(x) ((x) ^  ROTL((x),9) ^ ROTL((x),17)) 
#define P1(x) ((x) ^  ROTL((x),15) ^ ROTL((x),23)) 

    for (j = 16; j < 68; j++)
    {
        //W[j] = P1( W[j-16] ^ W[j-9] ^ ROTL(W[j-3],15)) ^ ROTL(W[j - 13],7 ) ^ W[j-6];
        //Why thd release's result is different with the debug's ?
        //Below is okay. Interesting, Perhaps VC6 has a bug of Optimizaiton.

        Temp1 = W[j - 16] ^ W[j - 9];
        Temp2 = ROTL(W[j - 3], 15);
        Temp3 = Temp1 ^ Temp2;
        Temp4 = P1(Temp3);
        Temp5 = ROTL(W[j - 13], 7) ^ W[j - 6];
        W[j] = Temp4 ^ Temp5;
    }

#ifdef _DEBUG 
    printf("Expanding message W0-67:\n");
    for (i = 0; i < 68; i++)
    {
        printf("%08x ", W[i]);
        if (((i + 1) % 8) == 0) printf("\n");
    }
    printf("\n");
#endif

    for (j = 0; j < 64; j++)
    {
        W1[j] = W[j] ^ W[j + 4];
    }

#ifdef _DEBUG 
    printf("Expanding message W'0-63:\n");
    for (i = 0; i < 64; i++)
    {
        printf("%08x ", W1[i]);
        if (((i + 1) % 8) == 0) printf("\n");
    }
    printf("\n");
#endif

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];
#ifdef _DEBUG       
    printf("j     A       B        C         D         E        F        G       H\n");
    printf("   %08x %08x %08x %08x %08x %08x %08x %08x\n", A, B, C, D, E, F, G, H);
#endif

    for (j = 0; j < 16; j++)
    {
        SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = FF0(A, B, C) + D + SS2 + W1[j];
        TT2 = GG0(E, F, G) + H + SS1 + W[j];
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
#ifdef _DEBUG 
        printf("%02d %08x %08x %08x %08x %08x %08x %08x %08x\n", j, A, B, C, D, E, F, G, H);
#endif
    }

    for (j = 16; j < 64; j++)
    {
        SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = FF1(A, B, C) + D + SS2 + W1[j];
        TT2 = GG1(E, F, G) + H + SS1 + W[j];
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
#ifdef _DEBUG 
        printf("%02d %08x %08x %08x %08x %08x %08x %08x %08x\n", j, A, B, C, D, E, F, G, H);
#endif	
    }

    ctx->state[0] ^= A;
    ctx->state[1] ^= B;
    ctx->state[2] ^= C;
    ctx->state[3] ^= D;
    ctx->state[4] ^= E;
    ctx->state[5] ^= F;
    ctx->state[6] ^= G;
    ctx->state[7] ^= H;
#ifdef _DEBUG 
    printf("   %08x %08x %08x %08x %08x %08x %08x %08x\n", ctx->state[0], ctx->state[1], ctx->state[2],
        ctx->state[3], ctx->state[4], ctx->state[5], ctx->state[6], ctx->state[7]);
#endif
}

/*
 * SM3 final digest
 */
void sm3_finish(sm3_context* ctx, unsigned char output[32])
{
    unsigned long last, padn;
    unsigned long high, low;
    unsigned char msglen[8];

    high = (ctx->total[0] >> 29)
        | (ctx->total[1] << 3);
    low = (ctx->total[0] << 3);

    PUT_ULONG_BE(high, msglen, 0);
    PUT_ULONG_BE(low, msglen, 4);

    last = ctx->total[0] & 0x3F;
    padn = (last < 56) ? (56 - last) : (120 - last);

    sm3_update(ctx, (unsigned char*)sm3_padding, padn);
    sm3_update(ctx, msglen, 8);

    PUT_ULONG_BE(ctx->state[0], output, 0);
    PUT_ULONG_BE(ctx->state[1], output, 4);
    PUT_ULONG_BE(ctx->state[2], output, 8);
    PUT_ULONG_BE(ctx->state[3], output, 12);
    PUT_ULONG_BE(ctx->state[4], output, 16);
    PUT_ULONG_BE(ctx->state[5], output, 20);
    PUT_ULONG_BE(ctx->state[6], output, 24);
    PUT_ULONG_BE(ctx->state[7], output, 28);
}

/*
 * output = SM3( input buffer )
 */

static const uint8_t iv_256[32] = {
    0x73, 0x80, 0x16, 0x6F, 0x49, 0x14, 0xB2, 0xB9,
    0x17, 0x24, 0x42, 0xD7, 0xDA, 0x8A, 0x06, 0x00,
    0xA9, 0x6F, 0x30, 0xBC, 0x16, 0x31, 0x38, 0xAA,
    0xE3, 0x8D, 0xEE, 0x4D, 0xB0, 0xFB, 0x0E, 0x4E
};

void sm3_inc_init(uint8_t *state) {
    for (size_t i = 0; i < 32; ++i) {
        state[i] = iv_256[i];
    }
    for (size_t i = 32; i < 40; ++i) {
        state[i] = 0;
    }
}                              

void sm3_inc_finalize(uint8_t *out, uint8_t *state_t, const uint8_t *in, size_t inlen) {
    sm3_context ctx;
    sm3_starts(&ctx,state_t);
    sm3_update(&ctx, in, inlen);
    sm3_finish(&ctx, out);
    memset(&ctx, 0, sizeof(sm3_context));
}

void sm3(uint8_t *out, const uint8_t *in, size_t inlen) {
    uint8_t state[40];
    sm3_inc_init(state);
    sm3_inc_finalize(out, state, in, inlen);
}

void mgf1_256(unsigned char *out, unsigned long outlen,
          const unsigned char *in, unsigned long inlen)
{
    SPX_VLA(uint8_t, inbuf, inlen+4);
    unsigned char outbuf[SPX_SM3_OUTPUT_BYTES];
    unsigned long i;

    memcpy(inbuf, in, inlen);

    /* While we can fit in at least another full block of SM3 output.. */
    for (i = 0; (i+1)*SPX_SM3_OUTPUT_BYTES <= outlen; i++) {
        u32_to_bytes(inbuf + inlen, (uint32_t)i);
        sm3(out, inbuf, inlen + 4);
        out += SPX_SM3_OUTPUT_BYTES;
    }
    /* Until we cannot anymore, and we fill the remainder. */
    if (outlen > i*SPX_SM3_OUTPUT_BYTES) {
        u32_to_bytes(inbuf + inlen, (uint32_t)i);
        sm3(outbuf, inbuf, inlen + 4);
        memcpy(out, outbuf, outlen - i*SPX_SM3_OUTPUT_BYTES);
    }
}

void seed_state(spx_ctx *ctx) {
    uint8_t block[128];
    size_t i;

    for (i = 0; i < SPX_N; ++i) {
        block[i] = ctx->pub_seed[i];
    }
    for (i = SPX_N; i < 128; ++i) {
        block[i] = 0;
    }

    sm3_inc_init(ctx->state_seeded);
    sm3_inc_blocks(ctx->state_seeded, block, 1);
}


