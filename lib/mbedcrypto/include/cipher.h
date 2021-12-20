#ifndef MBEDTLS_CIPHER_H
#define MBEDTLS_CIPHER_H

#include <stddef.h>

#include "config.h"
#include "platform_util.h"

#if defined(MBEDTLS_CIPHER_MODE_CBC)
#define MBEDTLS_CIPHER_MODE_WITH_PADDING
#endif

#define MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE  -0x6080  /**< The selected feature is not available. */
#define MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA       -0x6100  /**< Bad input parameters. */
#define MBEDTLS_ERR_CIPHER_ALLOC_FAILED         -0x6180  /**< Failed to allocate memory. */
#define MBEDTLS_ERR_CIPHER_INVALID_PADDING      -0x6200  /**< Input data contains invalid padding and is rejected. */
#define MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED  -0x6280  /**< Decryption of block requires a full block. */
#define MBEDTLS_ERR_CIPHER_INVALID_CONTEXT      -0x6380  /**< The context is invalid. For example, because it was freed. */

#define MBEDTLS_CIPHER_VARIABLE_IV_LEN     0x01    /**< Cipher accepts IVs of variable length. */
#define MBEDTLS_CIPHER_VARIABLE_KEY_LEN    0x02    /**< Cipher accepts keys of variable length. */

/**
 * \brief     Supported cipher types.
 *
 * \warning   RC4 and DES are considered weak ciphers and their use
 *            constitutes a security risk. Arm recommends considering stronger
 *            ciphers instead.
 */
typedef enum {
    MBEDTLS_CIPHER_ID_NONE = 0,  /**< Placeholder to mark the end of cipher ID lists. */
    MBEDTLS_CIPHER_ID_NULL,      /**< The identity cipher, treated as a stream cipher. */
    MBEDTLS_CIPHER_ID_AES,       /**< The AES cipher. */
    MBEDTLS_CIPHER_ID_DES,       /**< The DES cipher. */
    MBEDTLS_CIPHER_ID_3DES,      /**< The Triple DES cipher. */
    MBEDTLS_CIPHER_ID_CAMELLIA,  /**< The Camellia cipher. */
    MBEDTLS_CIPHER_ID_BLOWFISH,  /**< The Blowfish cipher. */
    MBEDTLS_CIPHER_ID_ARC4,      /**< The RC4 cipher. */
    MBEDTLS_CIPHER_ID_ARIA,      /**< The Aria cipher. */
    MBEDTLS_CIPHER_ID_CHACHA20,  /**< The ChaCha20 cipher. */
} mbedtls_cipher_id_t;

/**
 * \brief     Supported {cipher type, cipher mode} pairs.
 *
 * \warning   RC4 and DES are considered weak ciphers and their use
 *            constitutes a security risk. Arm recommends considering stronger
 *            ciphers instead.
 */
typedef enum {
    MBEDTLS_CIPHER_NONE = 0,             /**< Placeholder to mark the end of cipher-pair lists. */
    MBEDTLS_CIPHER_NULL,                 /**< The identity stream cipher. */
    MBEDTLS_CIPHER_AES_128_ECB,          /**< AES cipher with 128-bit ECB mode. */
    MBEDTLS_CIPHER_AES_192_ECB,          /**< AES cipher with 192-bit ECB mode. */
    MBEDTLS_CIPHER_AES_256_ECB,          /**< AES cipher with 256-bit ECB mode. */
    MBEDTLS_CIPHER_AES_128_CBC,          /**< AES cipher with 128-bit CBC mode. */
    MBEDTLS_CIPHER_AES_192_CBC,          /**< AES cipher with 192-bit CBC mode. */
    MBEDTLS_CIPHER_AES_256_CBC,          /**< AES cipher with 256-bit CBC mode. */
    MBEDTLS_CIPHER_AES_128_CFB128,       /**< AES cipher with 128-bit CFB128 mode. */
    MBEDTLS_CIPHER_AES_192_CFB128,       /**< AES cipher with 192-bit CFB128 mode. */
    MBEDTLS_CIPHER_AES_256_CFB128,       /**< AES cipher with 256-bit CFB128 mode. */
    MBEDTLS_CIPHER_AES_128_CTR,          /**< AES cipher with 128-bit CTR mode. */
    MBEDTLS_CIPHER_AES_192_CTR,          /**< AES cipher with 192-bit CTR mode. */
    MBEDTLS_CIPHER_AES_256_CTR,          /**< AES cipher with 256-bit CTR mode. */
    MBEDTLS_CIPHER_AES_128_GCM,          /**< AES cipher with 128-bit GCM mode. */
    MBEDTLS_CIPHER_AES_192_GCM,          /**< AES cipher with 192-bit GCM mode. */
    MBEDTLS_CIPHER_AES_256_GCM,          /**< AES cipher with 256-bit GCM mode. */
    MBEDTLS_CIPHER_CAMELLIA_128_ECB,     /**< Camellia cipher with 128-bit ECB mode. */
    MBEDTLS_CIPHER_CAMELLIA_192_ECB,     /**< Camellia cipher with 192-bit ECB mode. */
    MBEDTLS_CIPHER_CAMELLIA_256_ECB,     /**< Camellia cipher with 256-bit ECB mode. */
    MBEDTLS_CIPHER_CAMELLIA_128_CBC,     /**< Camellia cipher with 128-bit CBC mode. */
    MBEDTLS_CIPHER_CAMELLIA_192_CBC,     /**< Camellia cipher with 192-bit CBC mode. */
    MBEDTLS_CIPHER_CAMELLIA_256_CBC,     /**< Camellia cipher with 256-bit CBC mode. */
    MBEDTLS_CIPHER_CAMELLIA_128_CFB128,  /**< Camellia cipher with 128-bit CFB128 mode. */
    MBEDTLS_CIPHER_CAMELLIA_192_CFB128,  /**< Camellia cipher with 192-bit CFB128 mode. */
    MBEDTLS_CIPHER_CAMELLIA_256_CFB128,  /**< Camellia cipher with 256-bit CFB128 mode. */
    MBEDTLS_CIPHER_CAMELLIA_128_CTR,     /**< Camellia cipher with 128-bit CTR mode. */
    MBEDTLS_CIPHER_CAMELLIA_192_CTR,     /**< Camellia cipher with 192-bit CTR mode. */
    MBEDTLS_CIPHER_CAMELLIA_256_CTR,     /**< Camellia cipher with 256-bit CTR mode. */
    MBEDTLS_CIPHER_CAMELLIA_128_GCM,     /**< Camellia cipher with 128-bit GCM mode. */
    MBEDTLS_CIPHER_CAMELLIA_192_GCM,     /**< Camellia cipher with 192-bit GCM mode. */
    MBEDTLS_CIPHER_CAMELLIA_256_GCM,     /**< Camellia cipher with 256-bit GCM mode. */
    MBEDTLS_CIPHER_DES_ECB,              /**< DES cipher with ECB mode. */
    MBEDTLS_CIPHER_DES_CBC,              /**< DES cipher with CBC mode. */
    MBEDTLS_CIPHER_DES_EDE_ECB,          /**< DES cipher with EDE ECB mode. */
    MBEDTLS_CIPHER_DES_EDE_CBC,          /**< DES cipher with EDE CBC mode. */
    MBEDTLS_CIPHER_DES_EDE3_ECB,         /**< DES cipher with EDE3 ECB mode. */
    MBEDTLS_CIPHER_DES_EDE3_CBC,         /**< DES cipher with EDE3 CBC mode. */
    MBEDTLS_CIPHER_BLOWFISH_ECB,         /**< Blowfish cipher with ECB mode. */
    MBEDTLS_CIPHER_BLOWFISH_CBC,         /**< Blowfish cipher with CBC mode. */
    MBEDTLS_CIPHER_BLOWFISH_CFB64,       /**< Blowfish cipher with CFB64 mode. */
    MBEDTLS_CIPHER_BLOWFISH_CTR,         /**< Blowfish cipher with CTR mode. */
    MBEDTLS_CIPHER_ARC4_128,             /**< RC4 cipher with 128-bit mode. */
    MBEDTLS_CIPHER_AES_128_CCM,          /**< AES cipher with 128-bit CCM mode. */
    MBEDTLS_CIPHER_AES_192_CCM,          /**< AES cipher with 192-bit CCM mode. */
    MBEDTLS_CIPHER_AES_256_CCM,          /**< AES cipher with 256-bit CCM mode. */
    MBEDTLS_CIPHER_CAMELLIA_128_CCM,     /**< Camellia cipher with 128-bit CCM mode. */
    MBEDTLS_CIPHER_CAMELLIA_192_CCM,     /**< Camellia cipher with 192-bit CCM mode. */
    MBEDTLS_CIPHER_CAMELLIA_256_CCM,     /**< Camellia cipher with 256-bit CCM mode. */
    MBEDTLS_CIPHER_ARIA_128_ECB,         /**< Aria cipher with 128-bit key and ECB mode. */
    MBEDTLS_CIPHER_ARIA_192_ECB,         /**< Aria cipher with 192-bit key and ECB mode. */
    MBEDTLS_CIPHER_ARIA_256_ECB,         /**< Aria cipher with 256-bit key and ECB mode. */
    MBEDTLS_CIPHER_ARIA_128_CBC,         /**< Aria cipher with 128-bit key and CBC mode. */
    MBEDTLS_CIPHER_ARIA_192_CBC,         /**< Aria cipher with 192-bit key and CBC mode. */
    MBEDTLS_CIPHER_ARIA_256_CBC,         /**< Aria cipher with 256-bit key and CBC mode. */
    MBEDTLS_CIPHER_ARIA_128_CFB128,      /**< Aria cipher with 128-bit key and CFB-128 mode. */
    MBEDTLS_CIPHER_ARIA_192_CFB128,      /**< Aria cipher with 192-bit key and CFB-128 mode. */
    MBEDTLS_CIPHER_ARIA_256_CFB128,      /**< Aria cipher with 256-bit key and CFB-128 mode. */
    MBEDTLS_CIPHER_ARIA_128_CTR,         /**< Aria cipher with 128-bit key and CTR mode. */
    MBEDTLS_CIPHER_ARIA_192_CTR,         /**< Aria cipher with 192-bit key and CTR mode. */
    MBEDTLS_CIPHER_ARIA_256_CTR,         /**< Aria cipher with 256-bit key and CTR mode. */
    MBEDTLS_CIPHER_ARIA_128_GCM,         /**< Aria cipher with 128-bit key and GCM mode. */
    MBEDTLS_CIPHER_ARIA_192_GCM,         /**< Aria cipher with 192-bit key and GCM mode. */
    MBEDTLS_CIPHER_ARIA_256_GCM,         /**< Aria cipher with 256-bit key and GCM mode. */
    MBEDTLS_CIPHER_ARIA_128_CCM,         /**< Aria cipher with 128-bit key and CCM mode. */
    MBEDTLS_CIPHER_ARIA_192_CCM,         /**< Aria cipher with 192-bit key and CCM mode. */
    MBEDTLS_CIPHER_ARIA_256_CCM,         /**< Aria cipher with 256-bit key and CCM mode. */
    MBEDTLS_CIPHER_AES_128_OFB,          /**< AES 128-bit cipher in OFB mode. */
    MBEDTLS_CIPHER_AES_192_OFB,          /**< AES 192-bit cipher in OFB mode. */
    MBEDTLS_CIPHER_AES_256_OFB,          /**< AES 256-bit cipher in OFB mode. */
    MBEDTLS_CIPHER_AES_128_XTS,          /**< AES 128-bit cipher in XTS block mode. */
    MBEDTLS_CIPHER_AES_256_XTS,          /**< AES 256-bit cipher in XTS block mode. */
    MBEDTLS_CIPHER_CHACHA20,             /**< ChaCha20 stream cipher. */
    MBEDTLS_CIPHER_CHACHA20_POLY1305,    /**< ChaCha20-Poly1305 AEAD cipher. */
    MBEDTLS_CIPHER_AES_128_KW,           /**< AES cipher with 128-bit NIST KW mode. */
    MBEDTLS_CIPHER_AES_192_KW,           /**< AES cipher with 192-bit NIST KW mode. */
    MBEDTLS_CIPHER_AES_256_KW,           /**< AES cipher with 256-bit NIST KW mode. */
    MBEDTLS_CIPHER_AES_128_KWP,          /**< AES cipher with 128-bit NIST KWP mode. */
    MBEDTLS_CIPHER_AES_192_KWP,          /**< AES cipher with 192-bit NIST KWP mode. */
    MBEDTLS_CIPHER_AES_256_KWP,          /**< AES cipher with 256-bit NIST KWP mode. */
} mbedtls_cipher_type_t;

/** Supported cipher modes. */
typedef enum {
    MBEDTLS_MODE_NONE = 0,               /**< None.                        */
    MBEDTLS_MODE_ECB,                    /**< The ECB cipher mode.         */
    MBEDTLS_MODE_CBC,                    /**< The CBC cipher mode.         */
    MBEDTLS_MODE_CFB,                    /**< The CFB cipher mode.         */
    MBEDTLS_MODE_OFB,                    /**< The OFB cipher mode.         */
    MBEDTLS_MODE_CTR,                    /**< The CTR cipher mode.         */
    MBEDTLS_MODE_GCM,                    /**< The GCM cipher mode.         */
    MBEDTLS_MODE_STREAM,                 /**< The stream cipher mode.      */
    MBEDTLS_MODE_CCM,                    /**< The CCM cipher mode.         */
    MBEDTLS_MODE_XTS,                    /**< The XTS cipher mode.         */
    MBEDTLS_MODE_CHACHAPOLY,             /**< The ChaCha-Poly cipher mode. */
    MBEDTLS_MODE_KW,                     /**< The SP800-38F KW mode */
    MBEDTLS_MODE_KWP,                    /**< The SP800-38F KWP mode */
} mbedtls_cipher_mode_t;

/** Supported cipher padding types. */
typedef enum {
    MBEDTLS_PADDING_PKCS7 = 0,     /**< PKCS7 padding (default).        */
    MBEDTLS_PADDING_ONE_AND_ZEROS, /**< ISO/IEC 7816-4 padding.         */
    MBEDTLS_PADDING_ZEROS_AND_LEN, /**< ANSI X.923 padding.             */
    MBEDTLS_PADDING_ZEROS,         /**< Zero padding (not reversible). */
    MBEDTLS_PADDING_NONE,          /**< Never pad (full blocks only).   */
} mbedtls_cipher_padding_t;

/** Type of operation. */
typedef enum {
    MBEDTLS_OPERATION_NONE = -1,
    MBEDTLS_DECRYPT = 0,
    MBEDTLS_ENCRYPT,
} mbedtls_operation_t;

/** Maximum length of any IV, in Bytes. */
/* This should ideally be derived automatically from list of ciphers.
 * This should be kept in sync with MBEDTLS_SSL_MAX_IV_LENGTH defined
 * in ssl_internal.h. */
#define MBEDTLS_MAX_IV_LENGTH      16

/** Maximum block size of any cipher, in Bytes. */
/* This should ideally be derived automatically from list of ciphers.
 * This should be kept in sync with MBEDTLS_SSL_MAX_BLOCK_LENGTH defined
 * in ssl_internal.h. */
#define MBEDTLS_MAX_BLOCK_LENGTH   16

/**
 * Base cipher information (opaque struct).
 */
typedef struct mbedtls_cipher_base_t mbedtls_cipher_base_t;

/**
 * Cipher information. Allows calling cipher functions
 * in a generic way.
 */
typedef struct mbedtls_cipher_info_t
{
    /** Full cipher identifier. For example,
     * MBEDTLS_CIPHER_AES_256_CBC.
     */
    mbedtls_cipher_type_t type;

    /** The cipher mode. For example, MBEDTLS_MODE_CBC. */
    mbedtls_cipher_mode_t mode;

    /** The cipher key length, in bits. This is the
     * default length for variable sized ciphers.
     * Includes parity bits for ciphers like DES.
     */
    unsigned int key_bitlen;

    /** Name of the cipher. */
    const char * name;

    /** IV or nonce size, in Bytes.
     * For ciphers that accept variable IV sizes,
     * this is the recommended size.
     */
    unsigned int iv_size;

    /** Bitflag comprised of MBEDTLS_CIPHER_VARIABLE_IV_LEN and
     *  MBEDTLS_CIPHER_VARIABLE_KEY_LEN indicating whether the
     *  cipher supports variable IV or variable key sizes, respectively.
     */
    int flags;

    /** The block size, in Bytes. */
    unsigned int block_size;

    /** Struct for base cipher information and functions. */
    const mbedtls_cipher_base_t *base;

} mbedtls_cipher_info_t;

/**
 * Generic cipher context.
 */
typedef struct mbedtls_cipher_context_t
{
    /** Information about the associated cipher. */
    const mbedtls_cipher_info_t *cipher_info;

    /** Key length to use. */
    int key_bitlen;

    /** Operation that the key of the context has been
     * initialized for.
     */
    mbedtls_operation_t operation;

#if defined(MBEDTLS_CIPHER_MODE_WITH_PADDING)
    /** Padding functions to use, if relevant for
     * the specific cipher mode.
     */
    void (*add_padding)( unsigned char *output, size_t olen, size_t data_len );
    int (*get_padding)( unsigned char *input, size_t ilen, size_t *data_len );
#endif

    /** Buffer for input that has not been processed yet. */
    unsigned char unprocessed_data[MBEDTLS_MAX_BLOCK_LENGTH];

    /** Number of Bytes that have not been processed yet. */
    size_t unprocessed_len;

    /** Current IV or NONCE_COUNTER for CTR-mode, data unit (or sector) number
     * for XTS-mode. */
    unsigned char iv[MBEDTLS_MAX_IV_LENGTH];

    /** IV size in Bytes, for ciphers with variable-length IVs. */
    size_t iv_size;

    /** The cipher-specific context. */
    void *cipher_ctx;

#if defined(MBEDTLS_CMAC_C)
    /** CMAC-specific context. */
    mbedtls_cmac_context_t *cmac_ctx;
#endif

#if defined(MBEDTLS_USE_PSA_CRYPTO)
    /** Indicates whether the cipher operations should be performed
     *  by Mbed TLS' own crypto library or an external implementation
     *  of the PSA Crypto API.
     *  This is unset if the cipher context was established through
     *  mbedtls_cipher_setup(), and set if it was established through
     *  mbedtls_cipher_setup_psa().
     */
    unsigned char psa_enabled;
#endif /* MBEDTLS_USE_PSA_CRYPTO */

} mbedtls_cipher_context_t;

/**
 * \brief               This function retrieves the cipher-information
 *                      structure associated with the given cipher ID,
 *                      key size and mode.
 *
 * \param cipher_id     The ID of the cipher to search for. For example,
 *                      #MBEDTLS_CIPHER_ID_AES.
 * \param key_bitlen    The length of the key in bits.
 * \param mode          The cipher mode. For example, #MBEDTLS_MODE_CBC.
 *
 * \return              The cipher information structure associated with the
 *                      given \p cipher_id.
 * \return              \c NULL if the associated cipher information is not found.
 */
const mbedtls_cipher_info_t *mbedtls_cipher_info_from_values( const mbedtls_cipher_id_t cipher_id,
                                              int key_bitlen,
                                              const mbedtls_cipher_mode_t mode );

/**
 * \brief               This function frees and clears the cipher-specific
 *                      context of \p ctx. Freeing \p ctx itself remains the
 *                      responsibility of the caller.
 *
 * \param ctx           The context to be freed. If this is \c NULL, the
 *                      function has no effect, otherwise this must point to an
 *                      initialized context.
 */
void mbedtls_cipher_free( mbedtls_cipher_context_t *ctx );

/**
 * \brief               This function initializes a cipher context for
 *                      use with the given cipher primitive.
 *
 * \param ctx           The context to initialize. This must be initialized.
 * \param cipher_info   The cipher to use.
 *
 * \return              \c 0 on success.
 * \return              #MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA on
 *                      parameter-verification failure.
 * \return              #MBEDTLS_ERR_CIPHER_ALLOC_FAILED if allocation of the
 *                      cipher-specific context fails.
 *
 * \internal Currently, the function also clears the structure.
 * In future versions, the caller will be required to call
 * mbedtls_cipher_init() on the structure first.
 */
int mbedtls_cipher_setup( mbedtls_cipher_context_t *ctx,
                          const mbedtls_cipher_info_t *cipher_info );

/**
 * \brief        This function returns the block size of the given cipher.
 *
 * \param ctx    The context of the cipher. This must be initialized.
 *
 * \return       The block size of the underlying cipher.
 * \return       \c 0 if \p ctx has not been initialized.
 */
static inline unsigned int mbedtls_cipher_get_block_size(
    const mbedtls_cipher_context_t *ctx )
{
    MBEDTLS_INTERNAL_VALIDATE_RET( ctx != NULL, 0 );
    if( ctx->cipher_info == NULL )
        return 0;

    return ctx->cipher_info->block_size;
}

/**
 * \brief               This function sets the key to use with the given context.
 *
 * \param ctx           The generic cipher context. This must be initialized and
 *                      bound to a cipher information structure.
 * \param key           The key to use. This must be a readable buffer of at
 *                      least \p key_bitlen Bits.
 * \param key_bitlen    The key length to use, in Bits.
 * \param operation     The operation that the key will be used for:
 *                      #MBEDTLS_ENCRYPT or #MBEDTLS_DECRYPT.
 *
 * \return              \c 0 on success.
 * \return              #MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA on
 *                      parameter-verification failure.
 * \return              A cipher-specific error code on failure.
 */
int mbedtls_cipher_setkey( mbedtls_cipher_context_t *ctx,
                           const unsigned char *key,
                           int key_bitlen,
                           const mbedtls_operation_t operation );

#if defined(MBEDTLS_CIPHER_MODE_WITH_PADDING)
/**
 * \brief               This function sets the padding mode, for cipher modes
 *                      that use padding.
 *
 *                      The default passing mode is PKCS7 padding.
 *
 * \param ctx           The generic cipher context. This must be initialized and
 *                      bound to a cipher information structure.
 * \param mode          The padding mode.
 *
 * \return              \c 0 on success.
 * \return              #MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE
 *                      if the selected padding mode is not supported.
 * \return              #MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA if the cipher mode
 *                      does not support padding.
 */
int mbedtls_cipher_set_padding_mode( mbedtls_cipher_context_t *ctx,
                                     mbedtls_cipher_padding_t mode );
#endif /* MBEDTLS_CIPHER_MODE_WITH_PADDING */

/**
 * \brief               The generic cipher update function. It encrypts or
 *                      decrypts using the given cipher context. Writes as
 *                      many block-sized blocks of data as possible to output.
 *                      Any data that cannot be written immediately is either
 *                      added to the next block, or flushed when
 *                      mbedtls_cipher_finish() is called.
 *                      Exception: For MBEDTLS_MODE_ECB, expects a single block
 *                      in size. For example, 16 Bytes for AES.
 *
 * \note                If the underlying cipher is used in GCM mode, all calls
 *                      to this function, except for the last one before
 *                      mbedtls_cipher_finish(), must have \p ilen as a
 *                      multiple of the block size of the cipher.
 *
 * \param ctx           The generic cipher context. This must be initialized and
 *                      bound to a key.
 * \param input         The buffer holding the input data. This must be a
 *                      readable buffer of at least \p ilen Bytes.
 * \param ilen          The length of the input data.
 * \param output        The buffer for the output data. This must be able to
 *                      hold at least `ilen + block_size`. This must not be the
 *                      same buffer as \p input.
 * \param olen          The length of the output data, to be updated with the
 *                      actual number of Bytes written. This must not be
 *                      \c NULL.
 *
 * \return              \c 0 on success.
 * \return              #MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA on
 *                      parameter-verification failure.
 * \return              #MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE on an
 *                      unsupported mode for a cipher.
 * \return              A cipher-specific error code on failure.
 */
int mbedtls_cipher_update( mbedtls_cipher_context_t *ctx,
                           const unsigned char *input,
                           size_t ilen, unsigned char *output,
                           size_t *olen );

#endif /* MBEDTLS_CIPHER_H */
