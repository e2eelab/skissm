
#include "hkdf.h"

#include <string.h>

#include "md.h"
#include "error.h"
#include "platform_util.h"

int mbedtls_hkdf( const mbedtls_md_info_t *md, const unsigned char *salt,
                  size_t salt_len, const unsigned char *ikm, size_t ikm_len,
                  const unsigned char *info, size_t info_len,
                  unsigned char *okm, size_t okm_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char prk[MBEDTLS_MD_MAX_SIZE];

    ret = mbedtls_hkdf_extract( md, salt, salt_len, ikm, ikm_len, prk );

    if( ret == 0 )
    {
        ret = mbedtls_hkdf_expand( md, prk, mbedtls_md_get_size( md ),
                                   info, info_len, okm, okm_len );
    }

    mbedtls_platform_zeroize( prk, sizeof( prk ) );

    return( ret );
}

int mbedtls_hkdf_extract( const mbedtls_md_info_t *md,
                          const unsigned char *salt, size_t salt_len,
                          const unsigned char *ikm, size_t ikm_len,
                          unsigned char *prk )
{
    unsigned char null_salt[MBEDTLS_MD_MAX_SIZE] = { '\0' };

    if( salt == NULL )
    {
        size_t hf_len;

        if( salt_len != 0 )
        {
            return MBEDTLS_ERR_HKDF_BAD_INPUT_DATA;
        }

        hf_len = mbedtls_md_get_size( md );

        if( hf_len == 0 )
        {
            return MBEDTLS_ERR_HKDF_BAD_INPUT_DATA;
        }

        salt = null_salt;
        salt_len = hf_len;
    }

    return( mbedtls_md_hmac( md, salt, salt_len, ikm, ikm_len, prk ) );
}

int mbedtls_hkdf_expand( const mbedtls_md_info_t *md, const unsigned char *prk,
                         size_t prk_len, const unsigned char *info,
                         size_t info_len, unsigned char *okm, size_t okm_len )
{
    size_t hf_len;
    size_t where = 0;
    size_t n;
    size_t t_len = 0;
    size_t i;
    int ret = 0;
    mbedtls_md_context_t ctx;
    unsigned char t[MBEDTLS_MD_MAX_SIZE];

    if( okm == NULL )
    {
        return( MBEDTLS_ERR_HKDF_BAD_INPUT_DATA );
    }

    hf_len = mbedtls_md_get_size( md );

    if( prk_len < hf_len || hf_len == 0 )
    {
        return( MBEDTLS_ERR_HKDF_BAD_INPUT_DATA );
    }

    if( info == NULL )
    {
        info = (const unsigned char *) "";
        info_len = 0;
    }

    n = okm_len / hf_len;

    if( okm_len % hf_len != 0 )
    {
        n++;
    }

    /*
     * Per RFC 5869 Section 2.3, okm_len must not exceed
     * 255 times the hash length
     */
    if( n > 255 )
    {
        return( MBEDTLS_ERR_HKDF_BAD_INPUT_DATA );
    }

    mbedtls_md_init( &ctx );

    if( ( ret = mbedtls_md_setup( &ctx, md, 1 ) ) != 0 )
    {
        goto exit;
    }

    memset( t, 0, hf_len );

    /*
     * Compute T = T(1) | T(2) | T(3) | ... | T(N)
     * Where T(N) is defined in RFC 5869 Section 2.3
     */
    for( i = 1; i <= n; i++ )
    {
        size_t num_to_copy;
        unsigned char c = i & 0xff;

        ret = mbedtls_md_hmac_starts( &ctx, prk, prk_len );
        if( ret != 0 )
        {
            goto exit;
        }

        ret = mbedtls_md_hmac_update( &ctx, t, t_len );
        if( ret != 0 )
        {
            goto exit;
        }

        ret = mbedtls_md_hmac_update( &ctx, info, info_len );
        if( ret != 0 )
        {
            goto exit;
        }

        /* The constant concatenated to the end of each T(n) is a single octet.
         * */
        ret = mbedtls_md_hmac_update( &ctx, &c, 1 );
        if( ret != 0 )
        {
            goto exit;
        }

        ret = mbedtls_md_hmac_finish( &ctx, t );
        if( ret != 0 )
        {
            goto exit;
        }

        num_to_copy = i != n ? hf_len : okm_len - where;
        memcpy( okm + where, t, num_to_copy );
        where += hf_len;
        t_len = hf_len;
    }

exit:
    mbedtls_md_free( &ctx );
    mbedtls_platform_zeroize( t, sizeof( t ) );

    return( ret );
}
