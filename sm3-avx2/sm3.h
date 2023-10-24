#ifndef SPX_SM3_H
#define SPX_SM3_H
#define uint8_t unsigned char
#include "params.h"

#define SPX_SM3_BLOCK_BYTES 64
#define SPX_SM3_OUTPUT_BYTES 32  /* This does not necessarily equal SPX_N */


#if SPX_SM3_OUTPUT_BYTES < SPX_N
    #error Linking against SM3 with N larger than 32 bytes is not supported
#endif

#define SPX_SM3_ADDR_BYTES 22

/**
 * \brief          SM3 context structure
 */
typedef struct
{
    unsigned int total[2];     /*!< number of bytes processed  */
    unsigned int state[8];     /*!< intermediate digest state  */
    unsigned char buffer[64];   /*!< data block being processed */

    unsigned char ipad[64];     /*!< HMAC: inner padding        */
    unsigned char opad[64];     /*!< HMAC: outer padding        */

}
sm3_context;

void uint8_to_uint32(const uint8_t *in, unsigned int *out);
void sm3_process_block(unsigned int state[8], const unsigned char data[64]);
size_t crypto_hashblocks_sm3(uint8_t *statebytes, const uint8_t *input, size_t inlen);
void sm3_inc_blocks(uint8_t *state, const uint8_t *in, size_t inblocks);
void sm3_inc_init(uint8_t *state);
void sm3_inc_finalize(uint8_t *out, uint8_t *state_t, const uint8_t *in, size_t inlen);
void sm3(uint8_t *out, const uint8_t *in, size_t inlen);
void mgf1_256(unsigned char *out, unsigned long outlen,
          const unsigned char *in, unsigned long inlen);
void seed_state(spx_ctx *ctx);
void sm3_process(sm3_context* ctx, unsigned char data[64]);

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * \brief          SM3 context setup
     *
     * \param ctx      context to be initialized
     */
    void sm3_starts(sm3_context* ctx ,uint8_t* state_t);

    /**
     * \brief          SM3 process buffer
     *
     * \param ctx      SM3 context
     * \param input    buffer holding the  data
     * \param ilen     length of the input data
     */
    void sm3_update(sm3_context* ctx,const unsigned char* input, size_t ilen);

    /**
     * \brief          SM3 final digest
     *
     * \param ctx      SM3 context
     */
    void sm3_finish(sm3_context* ctx, unsigned char output[32]);

    /**
     * \brief          Output = SM3( input buffer )
     *
     * \param input    buffer holding the  data
     * \param ilen     length of the input data
     * \param output   SM3 checksum result
     */
    void sm3(uint8_t *out, const uint8_t *in, size_t ilen);

    /**
     * \brief          Output = SM3( file contents )
     *
     * \param path     input file name
     * \param output   SM3 checksum result
     *
     * \return         0 if successful, 1 if fopen failed,
     *                 or 2 if fread failed
     */
    int sm3_file(char* path, unsigned char output[32]);

    /**
     * \brief          SM3 HMAC context setup
     *
     * \param ctx      HMAC context to be initialized
     * \param key      HMAC secret key
     * \param keylen   length of the HMAC key
     */
    void sm3_hmac_starts(sm3_context* ctx, unsigned char* key, int keylen);

    /**
     * \brief          SM3 HMAC process buffer
     *
     * \param ctx      HMAC context
     * \param input    buffer holding the  data
     * \param ilen     length of the input data
     */
    void sm3_hmac_update(sm3_context* ctx, unsigned char* input, int ilen);

    /**
     * \brief          SM3 HMAC final digest
     *
     * \param ctx      HMAC context
     * \param output   SM3 HMAC checksum result
     */
    void sm3_hmac_finish(sm3_context* ctx, unsigned char output[32]);

    /**
     * \brief          Output = HMAC-SM3( hmac key, input buffer )
     *
     * \param key      HMAC secret key
     * \param keylen   length of the HMAC key
     * \param input    buffer holding the  data
     * \param ilen     length of the input data
     * \param output   HMAC-SM3 result
     */
    void sm3_hmac(unsigned char* key, int keylen,
        unsigned char* input, int ilen,
        unsigned char output[32]);


#ifdef __cplusplus
}
#endif

#endif /* sm3.h */