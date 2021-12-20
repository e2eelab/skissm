
#include "config.h"
#include "cipher_internal.h"
#include "aes.h"
#include "gcm.h"
#include "platform.h"

#if defined(MBEDTLS_GCM_C)
/* shared by all GCM ciphers */
static void *gcm_ctx_alloc( void )
{
    void *ctx = mbedtls_calloc( 1, sizeof( mbedtls_gcm_context ) );

    if( ctx != NULL )
        mbedtls_gcm_init( (mbedtls_gcm_context *) ctx );

    return( ctx );
}

static void gcm_ctx_free( void *ctx )
{
    mbedtls_gcm_free( ctx );
    mbedtls_free( ctx );
}
#endif /* MBEDTLS_GCM_C */

#if defined(MBEDTLS_AES_C)

static int aes_crypt_ecb_wrap( void *ctx, mbedtls_operation_t operation,
        const unsigned char *input, unsigned char *output )
{
    return mbedtls_aes_crypt_ecb( (mbedtls_aes_context *) ctx, operation, input, output );
}

#if defined(MBEDTLS_CIPHER_MODE_CBC)
static int aes_crypt_cbc_wrap( void *ctx, mbedtls_operation_t operation, size_t length,
        unsigned char *iv, const unsigned char *input, unsigned char *output )
{
    return mbedtls_aes_crypt_cbc( (mbedtls_aes_context *) ctx, operation, length, iv, input,
                          output );
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_CFB)
static int aes_crypt_cfb128_wrap( void *ctx, mbedtls_operation_t operation,
        size_t length, size_t *iv_off, unsigned char *iv,
        const unsigned char *input, unsigned char *output )
{
    return mbedtls_aes_crypt_cfb128( (mbedtls_aes_context *) ctx, operation, length, iv_off, iv,
                             input, output );
}
#endif /* MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_OFB)
static int aes_crypt_ofb_wrap( void *ctx, size_t length, size_t *iv_off,
        unsigned char *iv, const unsigned char *input, unsigned char *output )
{
    return mbedtls_aes_crypt_ofb( (mbedtls_aes_context *) ctx, length, iv_off,
                                    iv, input, output );
}
#endif /* MBEDTLS_CIPHER_MODE_OFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
static int aes_crypt_ctr_wrap( void *ctx, size_t length, size_t *nc_off,
        unsigned char *nonce_counter, unsigned char *stream_block,
        const unsigned char *input, unsigned char *output )
{
    return mbedtls_aes_crypt_ctr( (mbedtls_aes_context *) ctx, length, nc_off, nonce_counter,
                          stream_block, input, output );
}
#endif /* MBEDTLS_CIPHER_MODE_CTR */

#if defined(MBEDTLS_CIPHER_MODE_XTS)
static int aes_crypt_xts_wrap( void *ctx, mbedtls_operation_t operation,
                               size_t length,
                               const unsigned char data_unit[16],
                               const unsigned char *input,
                               unsigned char *output )
{
    mbedtls_aes_xts_context *xts_ctx = ctx;
    int mode;

    switch( operation )
    {
        case MBEDTLS_ENCRYPT:
            mode = MBEDTLS_AES_ENCRYPT;
            break;
        case MBEDTLS_DECRYPT:
            mode = MBEDTLS_AES_DECRYPT;
            break;
        default:
            return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    return mbedtls_aes_crypt_xts( xts_ctx, mode, length,
                                  data_unit, input, output );
}
#endif /* MBEDTLS_CIPHER_MODE_XTS */

static int aes_setkey_dec_wrap( void *ctx, const unsigned char *key,
                                unsigned int key_bitlen )
{
    return mbedtls_aes_setkey_dec( (mbedtls_aes_context *) ctx, key, key_bitlen );
}

static int aes_setkey_enc_wrap( void *ctx, const unsigned char *key,
                                unsigned int key_bitlen )
{
    return mbedtls_aes_setkey_enc( (mbedtls_aes_context *) ctx, key, key_bitlen );
}

static void * aes_ctx_alloc( void )
{
    mbedtls_aes_context *aes = mbedtls_calloc( 1, sizeof( mbedtls_aes_context ) );

    if( aes == NULL )
        return( NULL );

    mbedtls_aes_init( aes );

    return( aes );
}

static void aes_ctx_free( void *ctx )
{
    mbedtls_aes_free( (mbedtls_aes_context *) ctx );
    mbedtls_free( ctx );
}

static const mbedtls_cipher_base_t aes_info = {
    MBEDTLS_CIPHER_ID_AES,
    aes_crypt_ecb_wrap,
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    aes_crypt_cbc_wrap,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    aes_crypt_cfb128_wrap,
#endif
#if defined(MBEDTLS_CIPHER_MODE_OFB)
    aes_crypt_ofb_wrap,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    aes_crypt_ctr_wrap,
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_STREAM)
    NULL,
#endif
    aes_setkey_enc_wrap,
    aes_setkey_dec_wrap,
    aes_ctx_alloc,
    aes_ctx_free
};

static const mbedtls_cipher_info_t aes_128_ecb_info = {
    MBEDTLS_CIPHER_AES_128_ECB,
    MBEDTLS_MODE_ECB,
    128,
    "AES-128-ECB",
    0,
    0,
    16,
    &aes_info
};

static const mbedtls_cipher_info_t aes_192_ecb_info = {
    MBEDTLS_CIPHER_AES_192_ECB,
    MBEDTLS_MODE_ECB,
    192,
    "AES-192-ECB",
    0,
    0,
    16,
    &aes_info
};

static const mbedtls_cipher_info_t aes_256_ecb_info = {
    MBEDTLS_CIPHER_AES_256_ECB,
    MBEDTLS_MODE_ECB,
    256,
    "AES-256-ECB",
    0,
    0,
    16,
    &aes_info
};

#if defined(MBEDTLS_CIPHER_MODE_CBC)
static const mbedtls_cipher_info_t aes_128_cbc_info = {
    MBEDTLS_CIPHER_AES_128_CBC,
    MBEDTLS_MODE_CBC,
    128,
    "AES-128-CBC",
    16,
    0,
    16,
    &aes_info
};

static const mbedtls_cipher_info_t aes_192_cbc_info = {
    MBEDTLS_CIPHER_AES_192_CBC,
    MBEDTLS_MODE_CBC,
    192,
    "AES-192-CBC",
    16,
    0,
    16,
    &aes_info
};

static const mbedtls_cipher_info_t aes_256_cbc_info = {
    MBEDTLS_CIPHER_AES_256_CBC,
    MBEDTLS_MODE_CBC,
    256,
    "AES-256-CBC",
    16,
    0,
    16,
    &aes_info
};
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_CFB)
static const mbedtls_cipher_info_t aes_128_cfb128_info = {
    MBEDTLS_CIPHER_AES_128_CFB128,
    MBEDTLS_MODE_CFB,
    128,
    "AES-128-CFB128",
    16,
    0,
    16,
    &aes_info
};

static const mbedtls_cipher_info_t aes_192_cfb128_info = {
    MBEDTLS_CIPHER_AES_192_CFB128,
    MBEDTLS_MODE_CFB,
    192,
    "AES-192-CFB128",
    16,
    0,
    16,
    &aes_info
};

static const mbedtls_cipher_info_t aes_256_cfb128_info = {
    MBEDTLS_CIPHER_AES_256_CFB128,
    MBEDTLS_MODE_CFB,
    256,
    "AES-256-CFB128",
    16,
    0,
    16,
    &aes_info
};
#endif /* MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_OFB)
static const mbedtls_cipher_info_t aes_128_ofb_info = {
    MBEDTLS_CIPHER_AES_128_OFB,
    MBEDTLS_MODE_OFB,
    128,
    "AES-128-OFB",
    16,
    0,
    16,
    &aes_info
};

static const mbedtls_cipher_info_t aes_192_ofb_info = {
    MBEDTLS_CIPHER_AES_192_OFB,
    MBEDTLS_MODE_OFB,
    192,
    "AES-192-OFB",
    16,
    0,
    16,
    &aes_info
};

static const mbedtls_cipher_info_t aes_256_ofb_info = {
    MBEDTLS_CIPHER_AES_256_OFB,
    MBEDTLS_MODE_OFB,
    256,
    "AES-256-OFB",
    16,
    0,
    16,
    &aes_info
};
#endif /* MBEDTLS_CIPHER_MODE_OFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
static const mbedtls_cipher_info_t aes_128_ctr_info = {
    MBEDTLS_CIPHER_AES_128_CTR,
    MBEDTLS_MODE_CTR,
    128,
    "AES-128-CTR",
    16,
    0,
    16,
    &aes_info
};

static const mbedtls_cipher_info_t aes_192_ctr_info = {
    MBEDTLS_CIPHER_AES_192_CTR,
    MBEDTLS_MODE_CTR,
    192,
    "AES-192-CTR",
    16,
    0,
    16,
    &aes_info
};

static const mbedtls_cipher_info_t aes_256_ctr_info = {
    MBEDTLS_CIPHER_AES_256_CTR,
    MBEDTLS_MODE_CTR,
    256,
    "AES-256-CTR",
    16,
    0,
    16,
    &aes_info
};
#endif /* MBEDTLS_CIPHER_MODE_CTR */

#if defined(MBEDTLS_CIPHER_MODE_XTS)
static int xts_aes_setkey_enc_wrap( void *ctx, const unsigned char *key,
                                    unsigned int key_bitlen )
{
    mbedtls_aes_xts_context *xts_ctx = ctx;
    return( mbedtls_aes_xts_setkey_enc( xts_ctx, key, key_bitlen ) );
}

static int xts_aes_setkey_dec_wrap( void *ctx, const unsigned char *key,
                                    unsigned int key_bitlen )
{
    mbedtls_aes_xts_context *xts_ctx = ctx;
    return( mbedtls_aes_xts_setkey_dec( xts_ctx, key, key_bitlen ) );
}

static void *xts_aes_ctx_alloc( void )
{
    mbedtls_aes_xts_context *xts_ctx = mbedtls_calloc( 1, sizeof( *xts_ctx ) );

    if( xts_ctx != NULL )
        mbedtls_aes_xts_init( xts_ctx );

    return( xts_ctx );
}

static void xts_aes_ctx_free( void *ctx )
{
    mbedtls_aes_xts_context *xts_ctx = ctx;

    if( xts_ctx == NULL )
        return;

    mbedtls_aes_xts_free( xts_ctx );
    mbedtls_free( xts_ctx );
}

static const mbedtls_cipher_base_t xts_aes_info = {
    MBEDTLS_CIPHER_ID_AES,
    NULL,
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    aes_crypt_xts_wrap,
#endif
#if defined(MBEDTLS_CIPHER_MODE_STREAM)
    NULL,
#endif
    xts_aes_setkey_enc_wrap,
    xts_aes_setkey_dec_wrap,
    xts_aes_ctx_alloc,
    xts_aes_ctx_free
};

static const mbedtls_cipher_info_t aes_128_xts_info = {
    MBEDTLS_CIPHER_AES_128_XTS,
    MBEDTLS_MODE_XTS,
    256,
    "AES-128-XTS",
    16,
    0,
    16,
    &xts_aes_info
};

static const mbedtls_cipher_info_t aes_256_xts_info = {
    MBEDTLS_CIPHER_AES_256_XTS,
    MBEDTLS_MODE_XTS,
    512,
    "AES-256-XTS",
    16,
    0,
    16,
    &xts_aes_info
};
#endif /* MBEDTLS_CIPHER_MODE_XTS */

#if defined(MBEDTLS_GCM_C)
static int gcm_aes_setkey_wrap( void *ctx, const unsigned char *key,
                                unsigned int key_bitlen )
{
    return mbedtls_gcm_setkey( (mbedtls_gcm_context *) ctx, MBEDTLS_CIPHER_ID_AES,
                     key, key_bitlen );
}

static const mbedtls_cipher_base_t gcm_aes_info = {
    MBEDTLS_CIPHER_ID_AES,
    NULL,
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_STREAM)
    NULL,
#endif
    gcm_aes_setkey_wrap,
    gcm_aes_setkey_wrap,
    gcm_ctx_alloc,
    gcm_ctx_free,
};

static const mbedtls_cipher_info_t aes_128_gcm_info = {
    MBEDTLS_CIPHER_AES_128_GCM,
    MBEDTLS_MODE_GCM,
    128,
    "AES-128-GCM",
    12,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    16,
    &gcm_aes_info
};

static const mbedtls_cipher_info_t aes_192_gcm_info = {
    MBEDTLS_CIPHER_AES_192_GCM,
    MBEDTLS_MODE_GCM,
    192,
    "AES-192-GCM",
    12,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    16,
    &gcm_aes_info
};

static const mbedtls_cipher_info_t aes_256_gcm_info = {
    MBEDTLS_CIPHER_AES_256_GCM,
    MBEDTLS_MODE_GCM,
    256,
    "AES-256-GCM",
    12,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    16,
    &gcm_aes_info
};
#endif /* MBEDTLS_GCM_C */

#if defined(MBEDTLS_CCM_C)
static int ccm_aes_setkey_wrap( void *ctx, const unsigned char *key,
                                unsigned int key_bitlen )
{
    return mbedtls_ccm_setkey( (mbedtls_ccm_context *) ctx, MBEDTLS_CIPHER_ID_AES,
                     key, key_bitlen );
}

static const mbedtls_cipher_base_t ccm_aes_info = {
    MBEDTLS_CIPHER_ID_AES,
    NULL,
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_STREAM)
    NULL,
#endif
    ccm_aes_setkey_wrap,
    ccm_aes_setkey_wrap,
    ccm_ctx_alloc,
    ccm_ctx_free,
};

static const mbedtls_cipher_info_t aes_128_ccm_info = {
    MBEDTLS_CIPHER_AES_128_CCM,
    MBEDTLS_MODE_CCM,
    128,
    "AES-128-CCM",
    12,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    16,
    &ccm_aes_info
};

static const mbedtls_cipher_info_t aes_192_ccm_info = {
    MBEDTLS_CIPHER_AES_192_CCM,
    MBEDTLS_MODE_CCM,
    192,
    "AES-192-CCM",
    12,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    16,
    &ccm_aes_info
};

static const mbedtls_cipher_info_t aes_256_ccm_info = {
    MBEDTLS_CIPHER_AES_256_CCM,
    MBEDTLS_MODE_CCM,
    256,
    "AES-256-CCM",
    12,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    16,
    &ccm_aes_info
};
#endif /* MBEDTLS_CCM_C */

#endif /* MBEDTLS_AES_C */

const mbedtls_cipher_definition_t mbedtls_cipher_definitions[] =
{
#if defined(MBEDTLS_AES_C)
    { MBEDTLS_CIPHER_AES_128_ECB,          &aes_128_ecb_info },
    { MBEDTLS_CIPHER_AES_192_ECB,          &aes_192_ecb_info },
    { MBEDTLS_CIPHER_AES_256_ECB,          &aes_256_ecb_info },
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    { MBEDTLS_CIPHER_AES_128_CBC,          &aes_128_cbc_info },
    { MBEDTLS_CIPHER_AES_192_CBC,          &aes_192_cbc_info },
    { MBEDTLS_CIPHER_AES_256_CBC,          &aes_256_cbc_info },
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    { MBEDTLS_CIPHER_AES_128_CFB128,       &aes_128_cfb128_info },
    { MBEDTLS_CIPHER_AES_192_CFB128,       &aes_192_cfb128_info },
    { MBEDTLS_CIPHER_AES_256_CFB128,       &aes_256_cfb128_info },
#endif
#if defined(MBEDTLS_CIPHER_MODE_OFB)
    { MBEDTLS_CIPHER_AES_128_OFB,          &aes_128_ofb_info },
    { MBEDTLS_CIPHER_AES_192_OFB,          &aes_192_ofb_info },
    { MBEDTLS_CIPHER_AES_256_OFB,          &aes_256_ofb_info },
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    { MBEDTLS_CIPHER_AES_128_CTR,          &aes_128_ctr_info },
    { MBEDTLS_CIPHER_AES_192_CTR,          &aes_192_ctr_info },
    { MBEDTLS_CIPHER_AES_256_CTR,          &aes_256_ctr_info },
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    { MBEDTLS_CIPHER_AES_128_XTS,          &aes_128_xts_info },
    { MBEDTLS_CIPHER_AES_256_XTS,          &aes_256_xts_info },
#endif
#if defined(MBEDTLS_GCM_C)
    { MBEDTLS_CIPHER_AES_128_GCM,          &aes_128_gcm_info },
    { MBEDTLS_CIPHER_AES_192_GCM,          &aes_192_gcm_info },
    { MBEDTLS_CIPHER_AES_256_GCM,          &aes_256_gcm_info },
#endif
#if defined(MBEDTLS_CCM_C)
    { MBEDTLS_CIPHER_AES_128_CCM,          &aes_128_ccm_info },
    { MBEDTLS_CIPHER_AES_192_CCM,          &aes_192_ccm_info },
    { MBEDTLS_CIPHER_AES_256_CCM,          &aes_256_ccm_info },
#endif
#endif /* MBEDTLS_AES_C */

    { MBEDTLS_CIPHER_NONE, NULL }
};
