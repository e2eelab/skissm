#include "aes.h"

#include <string.h>

#include "aesni.h"
#include "platform_util.h"
#include "error.h"

/* Parameter validation macros based on platform_util.h */
#define AES_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_AES_BAD_INPUT_DATA )
#define AES_VALIDATE( cond )        \
    MBEDTLS_INTERNAL_VALIDATE( cond )

/*
 * 32-bit integer manipulation macros (little endian)
 */
#ifndef GET_UINT32_LE
#define GET_UINT32_LE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ]       )             \
        | ( (uint32_t) (b)[(i) + 1] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 2] << 16 )             \
        | ( (uint32_t) (b)[(i) + 3] << 24 );            \
}
#endif

#ifndef PUT_UINT32_LE
#define PUT_UINT32_LE(n,b,i)                                    \
{                                                               \
    (b)[(i)    ] = (unsigned char) ( ( (n)       ) & 0xFF );    \
    (b)[(i) + 1] = (unsigned char) ( ( (n) >>  8 ) & 0xFF );    \
    (b)[(i) + 2] = (unsigned char) ( ( (n) >> 16 ) & 0xFF );    \
    (b)[(i) + 3] = (unsigned char) ( ( (n) >> 24 ) & 0xFF );    \
}
#endif

/*
 * Forward S-box & tables
 */
static unsigned char FSb[256];
static uint32_t FT0[256];
#if !defined(MBEDTLS_AES_FEWER_TABLES)
static uint32_t FT1[256];
static uint32_t FT2[256];
static uint32_t FT3[256];
#endif /* !MBEDTLS_AES_FEWER_TABLES */

/*
 * Reverse S-box & tables
 */
static unsigned char RSb[256];
static uint32_t RT0[256];
#if !defined(MBEDTLS_AES_FEWER_TABLES)
static uint32_t RT1[256];
static uint32_t RT2[256];
static uint32_t RT3[256];
#endif /* !MBEDTLS_AES_FEWER_TABLES */

/*
 * Round constants
 */
static uint32_t RCON[10];

/*
 * Tables generation code
 */
#define ROTL8(x) ( ( (x) << 8 ) & 0xFFFFFFFF ) | ( (x) >> 24 )
#define XTIME(x) ( ( (x) << 1 ) ^ ( ( (x) & 0x80 ) ? 0x1B : 0x00 ) )
#define MUL(x,y) ( ( (x) && (y) ) ? pow[(log[(x)]+log[(y)]) % 255] : 0 )

static int aes_init_done = 0;

static void aes_gen_tables( void )
{
    int i, x, y, z;
    int pow[256];
    int log[256];

    /*
     * compute pow and log tables over GF(2^8)
     */
    for( i = 0, x = 1; i < 256; i++ )
    {
        pow[i] = x;
        log[x] = i;
        x = ( x ^ XTIME( x ) ) & 0xFF;
    }

    /*
     * calculate the round constants
     */
    for( i = 0, x = 1; i < 10; i++ )
    {
        RCON[i] = (uint32_t) x;
        x = XTIME( x ) & 0xFF;
    }

    /*
     * generate the forward and reverse S-boxes
     */
    FSb[0x00] = 0x63;
    RSb[0x63] = 0x00;

    for( i = 1; i < 256; i++ )
    {
        x = pow[255 - log[i]];

        y  = x; y = ( ( y << 1 ) | ( y >> 7 ) ) & 0xFF;
        x ^= y; y = ( ( y << 1 ) | ( y >> 7 ) ) & 0xFF;
        x ^= y; y = ( ( y << 1 ) | ( y >> 7 ) ) & 0xFF;
        x ^= y; y = ( ( y << 1 ) | ( y >> 7 ) ) & 0xFF;
        x ^= y ^ 0x63;

        FSb[i] = (unsigned char) x;
        RSb[x] = (unsigned char) i;
    }

    /*
     * generate the forward and reverse tables
     */
    for( i = 0; i < 256; i++ )
    {
        x = FSb[i];
        y = XTIME( x ) & 0xFF;
        z =  ( y ^ x ) & 0xFF;

        FT0[i] = ( (uint32_t) y       ) ^
                 ( (uint32_t) x <<  8 ) ^
                 ( (uint32_t) x << 16 ) ^
                 ( (uint32_t) z << 24 );

#if !defined(MBEDTLS_AES_FEWER_TABLES)
        FT1[i] = ROTL8( FT0[i] );
        FT2[i] = ROTL8( FT1[i] );
        FT3[i] = ROTL8( FT2[i] );
#endif /* !MBEDTLS_AES_FEWER_TABLES */

        x = RSb[i];

        RT0[i] = ( (uint32_t) MUL( 0x0E, x )       ) ^
                 ( (uint32_t) MUL( 0x09, x ) <<  8 ) ^
                 ( (uint32_t) MUL( 0x0D, x ) << 16 ) ^
                 ( (uint32_t) MUL( 0x0B, x ) << 24 );

#if !defined(MBEDTLS_AES_FEWER_TABLES)
        RT1[i] = ROTL8( RT0[i] );
        RT2[i] = ROTL8( RT1[i] );
        RT3[i] = ROTL8( RT2[i] );
#endif /* !MBEDTLS_AES_FEWER_TABLES */
    }
}

#define AES_RT0(idx) RT0[idx]
#define AES_RT1(idx) RT1[idx]
#define AES_RT2(idx) RT2[idx]
#define AES_RT3(idx) RT3[idx]

#define AES_FT0(idx) FT0[idx]
#define AES_FT1(idx) FT1[idx]
#define AES_FT2(idx) FT2[idx]
#define AES_FT3(idx) FT3[idx]

void mbedtls_aes_init( mbedtls_aes_context *ctx )
{
    AES_VALIDATE( ctx != NULL );

    memset( ctx, 0, sizeof( mbedtls_aes_context ) );
}

void mbedtls_aes_free( mbedtls_aes_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_aes_context ) );
}

#if defined(MBEDTLS_CIPHER_MODE_XTS)
void mbedtls_aes_xts_init( mbedtls_aes_xts_context *ctx )
{
    AES_VALIDATE( ctx != NULL );

    mbedtls_aes_init( &ctx->crypt );
    mbedtls_aes_init( &ctx->tweak );
}

void mbedtls_aes_xts_free( mbedtls_aes_xts_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_aes_free( &ctx->crypt );
    mbedtls_aes_free( &ctx->tweak );
}
#endif /* MBEDTLS_CIPHER_MODE_XTS */

/*
 * AES key schedule (encryption)
 */
#if !defined(MBEDTLS_AES_SETKEY_ENC_ALT)
int mbedtls_aes_setkey_enc( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits )
{
    unsigned int i;
    uint32_t *RK;

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( key != NULL );

    switch( keybits )
    {
        case 128: ctx->nr = 10; break;
        case 192: ctx->nr = 12; break;
        case 256: ctx->nr = 14; break;
        default : return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }

#if !defined(MBEDTLS_AES_ROM_TABLES)
    if( aes_init_done == 0 )
    {
        aes_gen_tables();
        aes_init_done = 1;
    }
#endif

    ctx->rk = RK = ctx->buf;

#if defined(MBEDTLS_AESNI_C) && defined(MBEDTLS_HAVE_X86_64)
    if( mbedtls_aesni_has_support( MBEDTLS_AESNI_AES ) )
        return( mbedtls_aesni_setkey_enc( (unsigned char *) ctx->rk, key, keybits ) );
#endif

    for( i = 0; i < ( keybits >> 5 ); i++ )
    {
        GET_UINT32_LE( RK[i], key, i << 2 );
    }

    switch( ctx->nr )
    {
        case 10:

            for( i = 0; i < 10; i++, RK += 4 )
            {
                RK[4]  = RK[0] ^ RCON[i] ^
                ( (uint32_t) FSb[ ( RK[3] >>  8 ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( RK[3] >> 16 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( RK[3] >> 24 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( RK[3]       ) & 0xFF ] << 24 );

                RK[5]  = RK[1] ^ RK[4];
                RK[6]  = RK[2] ^ RK[5];
                RK[7]  = RK[3] ^ RK[6];
            }
            break;

        case 12:

            for( i = 0; i < 8; i++, RK += 6 )
            {
                RK[6]  = RK[0] ^ RCON[i] ^
                ( (uint32_t) FSb[ ( RK[5] >>  8 ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( RK[5] >> 16 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( RK[5] >> 24 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( RK[5]       ) & 0xFF ] << 24 );

                RK[7]  = RK[1] ^ RK[6];
                RK[8]  = RK[2] ^ RK[7];
                RK[9]  = RK[3] ^ RK[8];
                RK[10] = RK[4] ^ RK[9];
                RK[11] = RK[5] ^ RK[10];
            }
            break;

        case 14:

            for( i = 0; i < 7; i++, RK += 8 )
            {
                RK[8]  = RK[0] ^ RCON[i] ^
                ( (uint32_t) FSb[ ( RK[7] >>  8 ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( RK[7] >> 16 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( RK[7] >> 24 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( RK[7]       ) & 0xFF ] << 24 );

                RK[9]  = RK[1] ^ RK[8];
                RK[10] = RK[2] ^ RK[9];
                RK[11] = RK[3] ^ RK[10];

                RK[12] = RK[4] ^
                ( (uint32_t) FSb[ ( RK[11]       ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( RK[11] >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( RK[11] >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( RK[11] >> 24 ) & 0xFF ] << 24 );

                RK[13] = RK[5] ^ RK[12];
                RK[14] = RK[6] ^ RK[13];
                RK[15] = RK[7] ^ RK[14];
            }
            break;
    }

    return( 0 );
}
#endif /* !MBEDTLS_AES_SETKEY_ENC_ALT */

/*
 * AES key schedule (decryption)
 */
#if !defined(MBEDTLS_AES_SETKEY_DEC_ALT)
int mbedtls_aes_setkey_dec( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits )
{
    int i, j, ret;
    mbedtls_aes_context cty;
    uint32_t *RK;
    uint32_t *SK;

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( key != NULL );

    mbedtls_aes_init( &cty );

    ctx->rk = RK = ctx->buf;

    /* Also checks keybits */
    if( ( ret = mbedtls_aes_setkey_enc( &cty, key, keybits ) ) != 0 )
        goto exit;

    ctx->nr = cty.nr;

#if defined(MBEDTLS_AESNI_C) && defined(MBEDTLS_HAVE_X86_64)
    if( mbedtls_aesni_has_support( MBEDTLS_AESNI_AES ) )
    {
        mbedtls_aesni_inverse_key( (unsigned char *) ctx->rk,
                           (const unsigned char *) cty.rk, ctx->nr );
        goto exit;
    }
#endif

    SK = cty.rk + cty.nr * 4;

    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;

    for( i = ctx->nr - 1, SK -= 8; i > 0; i--, SK -= 8 )
    {
        for( j = 0; j < 4; j++, SK++ )
        {
            *RK++ = AES_RT0( FSb[ ( *SK       ) & 0xFF ] ) ^
                    AES_RT1( FSb[ ( *SK >>  8 ) & 0xFF ] ) ^
                    AES_RT2( FSb[ ( *SK >> 16 ) & 0xFF ] ) ^
                    AES_RT3( FSb[ ( *SK >> 24 ) & 0xFF ] );
        }
    }

    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;

exit:
    mbedtls_aes_free( &cty );

    return( ret );
}
#endif /* !MBEDTLS_AES_SETKEY_DEC_ALT */

#if defined(MBEDTLS_CIPHER_MODE_XTS)
static int mbedtls_aes_xts_decode_keys( const unsigned char *key,
                                        unsigned int keybits,
                                        const unsigned char **key1,
                                        unsigned int *key1bits,
                                        const unsigned char **key2,
                                        unsigned int *key2bits )
{
    const unsigned int half_keybits = keybits / 2;
    const unsigned int half_keybytes = half_keybits / 8;

    switch( keybits )
    {
        case 256: break;
        case 512: break;
        default : return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }

    *key1bits = half_keybits;
    *key2bits = half_keybits;
    *key1 = &key[0];
    *key2 = &key[half_keybytes];

    return 0;
}

int mbedtls_aes_xts_setkey_enc( mbedtls_aes_xts_context *ctx,
                                const unsigned char *key,
                                unsigned int keybits)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const unsigned char *key1, *key2;
    unsigned int key1bits, key2bits;

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( key != NULL );

    ret = mbedtls_aes_xts_decode_keys( key, keybits, &key1, &key1bits,
                                       &key2, &key2bits );
    if( ret != 0 )
        return( ret );

    /* Set the tweak key. Always set tweak key for the encryption mode. */
    ret = mbedtls_aes_setkey_enc( &ctx->tweak, key2, key2bits );
    if( ret != 0 )
        return( ret );

    /* Set crypt key for encryption. */
    return mbedtls_aes_setkey_enc( &ctx->crypt, key1, key1bits );
}

int mbedtls_aes_xts_setkey_dec( mbedtls_aes_xts_context *ctx,
                                const unsigned char *key,
                                unsigned int keybits)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const unsigned char *key1, *key2;
    unsigned int key1bits, key2bits;

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( key != NULL );

    ret = mbedtls_aes_xts_decode_keys( key, keybits, &key1, &key1bits,
                                       &key2, &key2bits );
    if( ret != 0 )
        return( ret );

    /* Set the tweak key. Always set tweak key for encryption. */
    ret = mbedtls_aes_setkey_enc( &ctx->tweak, key2, key2bits );
    if( ret != 0 )
        return( ret );

    /* Set crypt key for decryption. */
    return mbedtls_aes_setkey_dec( &ctx->crypt, key1, key1bits );
}
#endif /* MBEDTLS_CIPHER_MODE_XTS */

#define AES_FROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3)                     \
    do                                                          \
    {                                                           \
        (X0) = *RK++ ^ AES_FT0( ( (Y0)       ) & 0xFF ) ^       \
                       AES_FT1( ( (Y1) >>  8 ) & 0xFF ) ^       \
                       AES_FT2( ( (Y2) >> 16 ) & 0xFF ) ^       \
                       AES_FT3( ( (Y3) >> 24 ) & 0xFF );        \
                                                                \
        (X1) = *RK++ ^ AES_FT0( ( (Y1)       ) & 0xFF ) ^       \
                       AES_FT1( ( (Y2) >>  8 ) & 0xFF ) ^       \
                       AES_FT2( ( (Y3) >> 16 ) & 0xFF ) ^       \
                       AES_FT3( ( (Y0) >> 24 ) & 0xFF );        \
                                                                \
        (X2) = *RK++ ^ AES_FT0( ( (Y2)       ) & 0xFF ) ^       \
                       AES_FT1( ( (Y3) >>  8 ) & 0xFF ) ^       \
                       AES_FT2( ( (Y0) >> 16 ) & 0xFF ) ^       \
                       AES_FT3( ( (Y1) >> 24 ) & 0xFF );        \
                                                                \
        (X3) = *RK++ ^ AES_FT0( ( (Y3)       ) & 0xFF ) ^       \
                       AES_FT1( ( (Y0) >>  8 ) & 0xFF ) ^       \
                       AES_FT2( ( (Y1) >> 16 ) & 0xFF ) ^       \
                       AES_FT3( ( (Y2) >> 24 ) & 0xFF );        \
    } while( 0 )

#define AES_RROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3)                 \
    do                                                      \
    {                                                       \
        (X0) = *RK++ ^ AES_RT0( ( (Y0)       ) & 0xFF ) ^   \
                       AES_RT1( ( (Y3) >>  8 ) & 0xFF ) ^   \
                       AES_RT2( ( (Y2) >> 16 ) & 0xFF ) ^   \
                       AES_RT3( ( (Y1) >> 24 ) & 0xFF );    \
                                                            \
        (X1) = *RK++ ^ AES_RT0( ( (Y1)       ) & 0xFF ) ^   \
                       AES_RT1( ( (Y0) >>  8 ) & 0xFF ) ^   \
                       AES_RT2( ( (Y3) >> 16 ) & 0xFF ) ^   \
                       AES_RT3( ( (Y2) >> 24 ) & 0xFF );    \
                                                            \
        (X2) = *RK++ ^ AES_RT0( ( (Y2)       ) & 0xFF ) ^   \
                       AES_RT1( ( (Y1) >>  8 ) & 0xFF ) ^   \
                       AES_RT2( ( (Y0) >> 16 ) & 0xFF ) ^   \
                       AES_RT3( ( (Y3) >> 24 ) & 0xFF );    \
                                                            \
        (X3) = *RK++ ^ AES_RT0( ( (Y3)       ) & 0xFF ) ^   \
                       AES_RT1( ( (Y2) >>  8 ) & 0xFF ) ^   \
                       AES_RT2( ( (Y1) >> 16 ) & 0xFF ) ^   \
                       AES_RT3( ( (Y0) >> 24 ) & 0xFF );    \
    } while( 0 )

/*
 * AES-ECB block encryption
 */
#if !defined(MBEDTLS_AES_ENCRYPT_ALT)
int mbedtls_internal_aes_encrypt( mbedtls_aes_context *ctx,
                                  const unsigned char input[16],
                                  unsigned char output[16] )
{
    int i;
    uint32_t *RK = ctx->rk;
    struct
    {
        uint32_t X[4];
        uint32_t Y[4];
    } t;

    GET_UINT32_LE( t.X[0], input,  0 ); t.X[0] ^= *RK++;
    GET_UINT32_LE( t.X[1], input,  4 ); t.X[1] ^= *RK++;
    GET_UINT32_LE( t.X[2], input,  8 ); t.X[2] ^= *RK++;
    GET_UINT32_LE( t.X[3], input, 12 ); t.X[3] ^= *RK++;

    for( i = ( ctx->nr >> 1 ) - 1; i > 0; i-- )
    {
        AES_FROUND( t.Y[0], t.Y[1], t.Y[2], t.Y[3], t.X[0], t.X[1], t.X[2], t.X[3] );
        AES_FROUND( t.X[0], t.X[1], t.X[2], t.X[3], t.Y[0], t.Y[1], t.Y[2], t.Y[3] );
    }

    AES_FROUND( t.Y[0], t.Y[1], t.Y[2], t.Y[3], t.X[0], t.X[1], t.X[2], t.X[3] );

    t.X[0] = *RK++ ^ \
            ( (uint32_t) FSb[ ( t.Y[0]       ) & 0xFF ]       ) ^
            ( (uint32_t) FSb[ ( t.Y[1] >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) FSb[ ( t.Y[2] >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) FSb[ ( t.Y[3] >> 24 ) & 0xFF ] << 24 );

    t.X[1] = *RK++ ^ \
            ( (uint32_t) FSb[ ( t.Y[1]       ) & 0xFF ]       ) ^
            ( (uint32_t) FSb[ ( t.Y[2] >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) FSb[ ( t.Y[3] >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) FSb[ ( t.Y[0] >> 24 ) & 0xFF ] << 24 );

    t.X[2] = *RK++ ^ \
            ( (uint32_t) FSb[ ( t.Y[2]       ) & 0xFF ]       ) ^
            ( (uint32_t) FSb[ ( t.Y[3] >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) FSb[ ( t.Y[0] >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) FSb[ ( t.Y[1] >> 24 ) & 0xFF ] << 24 );

    t.X[3] = *RK++ ^ \
            ( (uint32_t) FSb[ ( t.Y[3]       ) & 0xFF ]       ) ^
            ( (uint32_t) FSb[ ( t.Y[0] >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) FSb[ ( t.Y[1] >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) FSb[ ( t.Y[2] >> 24 ) & 0xFF ] << 24 );

    PUT_UINT32_LE( t.X[0], output,  0 );
    PUT_UINT32_LE( t.X[1], output,  4 );
    PUT_UINT32_LE( t.X[2], output,  8 );
    PUT_UINT32_LE( t.X[3], output, 12 );

    mbedtls_platform_zeroize( &t, sizeof( t ) );

    return( 0 );
}
#endif /* !MBEDTLS_AES_ENCRYPT_ALT */

/*
 * AES-ECB block decryption
 */
#if !defined(MBEDTLS_AES_DECRYPT_ALT)
int mbedtls_internal_aes_decrypt( mbedtls_aes_context *ctx,
                                  const unsigned char input[16],
                                  unsigned char output[16] )
{
    int i;
    uint32_t *RK = ctx->rk;
    struct
    {
        uint32_t X[4];
        uint32_t Y[4];
    } t;

    GET_UINT32_LE( t.X[0], input,  0 ); t.X[0] ^= *RK++;
    GET_UINT32_LE( t.X[1], input,  4 ); t.X[1] ^= *RK++;
    GET_UINT32_LE( t.X[2], input,  8 ); t.X[2] ^= *RK++;
    GET_UINT32_LE( t.X[3], input, 12 ); t.X[3] ^= *RK++;

    for( i = ( ctx->nr >> 1 ) - 1; i > 0; i-- )
    {
        AES_RROUND( t.Y[0], t.Y[1], t.Y[2], t.Y[3], t.X[0], t.X[1], t.X[2], t.X[3] );
        AES_RROUND( t.X[0], t.X[1], t.X[2], t.X[3], t.Y[0], t.Y[1], t.Y[2], t.Y[3] );
    }

    AES_RROUND( t.Y[0], t.Y[1], t.Y[2], t.Y[3], t.X[0], t.X[1], t.X[2], t.X[3] );

    t.X[0] = *RK++ ^ \
            ( (uint32_t) RSb[ ( t.Y[0]       ) & 0xFF ]       ) ^
            ( (uint32_t) RSb[ ( t.Y[3] >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) RSb[ ( t.Y[2] >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) RSb[ ( t.Y[1] >> 24 ) & 0xFF ] << 24 );

    t.X[1] = *RK++ ^ \
            ( (uint32_t) RSb[ ( t.Y[1]       ) & 0xFF ]       ) ^
            ( (uint32_t) RSb[ ( t.Y[0] >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) RSb[ ( t.Y[3] >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) RSb[ ( t.Y[2] >> 24 ) & 0xFF ] << 24 );

    t.X[2] = *RK++ ^ \
            ( (uint32_t) RSb[ ( t.Y[2]       ) & 0xFF ]       ) ^
            ( (uint32_t) RSb[ ( t.Y[1] >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) RSb[ ( t.Y[0] >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) RSb[ ( t.Y[3] >> 24 ) & 0xFF ] << 24 );

    t.X[3] = *RK++ ^ \
            ( (uint32_t) RSb[ ( t.Y[3]       ) & 0xFF ]       ) ^
            ( (uint32_t) RSb[ ( t.Y[2] >>  8 ) & 0xFF ] <<  8 ) ^
            ( (uint32_t) RSb[ ( t.Y[1] >> 16 ) & 0xFF ] << 16 ) ^
            ( (uint32_t) RSb[ ( t.Y[0] >> 24 ) & 0xFF ] << 24 );

    PUT_UINT32_LE( t.X[0], output,  0 );
    PUT_UINT32_LE( t.X[1], output,  4 );
    PUT_UINT32_LE( t.X[2], output,  8 );
    PUT_UINT32_LE( t.X[3], output, 12 );

    mbedtls_platform_zeroize( &t, sizeof( t ) );

    return( 0 );
}
#endif /* !MBEDTLS_AES_DECRYPT_ALT */

/*
 * AES-ECB block encryption/decryption
 */
int mbedtls_aes_crypt_ecb( mbedtls_aes_context *ctx,
                           int mode,
                           const unsigned char input[16],
                           unsigned char output[16] )
{
    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( input != NULL );
    AES_VALIDATE_RET( output != NULL );
    AES_VALIDATE_RET( mode == MBEDTLS_AES_ENCRYPT ||
                      mode == MBEDTLS_AES_DECRYPT );

#if defined(MBEDTLS_AESNI_C) && defined(MBEDTLS_HAVE_X86_64)
    if( mbedtls_aesni_has_support( MBEDTLS_AESNI_AES ) )
        return( mbedtls_aesni_crypt_ecb( ctx, mode, input, output ) );
#endif

    if( mode == MBEDTLS_AES_ENCRYPT )
        return( mbedtls_internal_aes_encrypt( ctx, input, output ) );
    else
        return( mbedtls_internal_aes_decrypt( ctx, input, output ) );
}

#if defined(MBEDTLS_CIPHER_MODE_CBC)
/*
 * AES-CBC buffer encryption/decryption
 */
int mbedtls_aes_crypt_cbc( mbedtls_aes_context *ctx,
                    int mode,
                    size_t length,
                    unsigned char iv[16],
                    const unsigned char *input,
                    unsigned char *output )
{
    int i;
    unsigned char temp[16];

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( mode == MBEDTLS_AES_ENCRYPT ||
                      mode == MBEDTLS_AES_DECRYPT );
    AES_VALIDATE_RET( iv != NULL );
    AES_VALIDATE_RET( input != NULL );
    AES_VALIDATE_RET( output != NULL );

    if( length % 16 )
        return( MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH );

    if( mode == MBEDTLS_AES_DECRYPT )
    {
        while( length > 0 )
        {
            memcpy( temp, input, 16 );
            mbedtls_aes_crypt_ecb( ctx, mode, input, output );

            for( i = 0; i < 16; i++ )
                output[i] = (unsigned char)( output[i] ^ iv[i] );

            memcpy( iv, temp, 16 );

            input  += 16;
            output += 16;
            length -= 16;
        }
    }
    else
    {
        while( length > 0 )
        {
            for( i = 0; i < 16; i++ )
                output[i] = (unsigned char)( input[i] ^ iv[i] );

            mbedtls_aes_crypt_ecb( ctx, mode, output, output );
            memcpy( iv, output, 16 );

            input  += 16;
            output += 16;
            length -= 16;
        }
    }

    return( 0 );
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_XTS)

/* Endianess with 64 bits values */
#ifndef GET_UINT64_LE
#define GET_UINT64_LE(n,b,i)                            \
{                                                       \
    (n) = ( (uint64_t) (b)[(i) + 7] << 56 )             \
        | ( (uint64_t) (b)[(i) + 6] << 48 )             \
        | ( (uint64_t) (b)[(i) + 5] << 40 )             \
        | ( (uint64_t) (b)[(i) + 4] << 32 )             \
        | ( (uint64_t) (b)[(i) + 3] << 24 )             \
        | ( (uint64_t) (b)[(i) + 2] << 16 )             \
        | ( (uint64_t) (b)[(i) + 1] <<  8 )             \
        | ( (uint64_t) (b)[(i)    ]       );            \
}
#endif

#ifndef PUT_UINT64_LE
#define PUT_UINT64_LE(n,b,i)                            \
{                                                       \
    (b)[(i) + 7] = (unsigned char) ( (n) >> 56 );       \
    (b)[(i) + 6] = (unsigned char) ( (n) >> 48 );       \
    (b)[(i) + 5] = (unsigned char) ( (n) >> 40 );       \
    (b)[(i) + 4] = (unsigned char) ( (n) >> 32 );       \
    (b)[(i) + 3] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i)    ] = (unsigned char) ( (n)       );       \
}
#endif

typedef unsigned char mbedtls_be128[16];

/*
 * GF(2^128) multiplication function
 *
 * This function multiplies a field element by x in the polynomial field
 * representation. It uses 64-bit word operations to gain speed but compensates
 * for machine endianess and hence works correctly on both big and little
 * endian machines.
 */
static void mbedtls_gf128mul_x_ble( unsigned char r[16],
                                    const unsigned char x[16] )
{
    uint64_t a, b, ra, rb;

    GET_UINT64_LE( a, x, 0 );
    GET_UINT64_LE( b, x, 8 );

    ra = ( a << 1 )  ^ 0x0087 >> ( 8 - ( ( b >> 63 ) << 3 ) );
    rb = ( a >> 63 ) | ( b << 1 );

    PUT_UINT64_LE( ra, r, 0 );
    PUT_UINT64_LE( rb, r, 8 );
}

/*
 * AES-XTS buffer encryption/decryption
 */
int mbedtls_aes_crypt_xts( mbedtls_aes_xts_context *ctx,
                           int mode,
                           size_t length,
                           const unsigned char data_unit[16],
                           const unsigned char *input,
                           unsigned char *output )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t blocks = length / 16;
    size_t leftover = length % 16;
    unsigned char tweak[16];
    unsigned char prev_tweak[16];
    unsigned char tmp[16];

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( mode == MBEDTLS_AES_ENCRYPT ||
                      mode == MBEDTLS_AES_DECRYPT );
    AES_VALIDATE_RET( data_unit != NULL );
    AES_VALIDATE_RET( input != NULL );
    AES_VALIDATE_RET( output != NULL );

    /* Data units must be at least 16 bytes long. */
    if( length < 16 )
        return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;

    /* NIST SP 800-38E disallows data units larger than 2**20 blocks. */
    if( length > ( 1 << 20 ) * 16 )
        return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;

    /* Compute the tweak. */
    ret = mbedtls_aes_crypt_ecb( &ctx->tweak, MBEDTLS_AES_ENCRYPT,
                                 data_unit, tweak );
    if( ret != 0 )
        return( ret );

    while( blocks-- )
    {
        size_t i;

        if( leftover && ( mode == MBEDTLS_AES_DECRYPT ) && blocks == 0 )
        {
            /* We are on the last block in a decrypt operation that has
             * leftover bytes, so we need to use the next tweak for this block,
             * and this tweak for the lefover bytes. Save the current tweak for
             * the leftovers and then update the current tweak for use on this,
             * the last full block. */
            memcpy( prev_tweak, tweak, sizeof( tweak ) );
            mbedtls_gf128mul_x_ble( tweak, tweak );
        }

        for( i = 0; i < 16; i++ )
            tmp[i] = input[i] ^ tweak[i];

        ret = mbedtls_aes_crypt_ecb( &ctx->crypt, mode, tmp, tmp );
        if( ret != 0 )
            return( ret );

        for( i = 0; i < 16; i++ )
            output[i] = tmp[i] ^ tweak[i];

        /* Update the tweak for the next block. */
        mbedtls_gf128mul_x_ble( tweak, tweak );

        output += 16;
        input += 16;
    }

    if( leftover )
    {
        /* If we are on the leftover bytes in a decrypt operation, we need to
         * use the previous tweak for these bytes (as saved in prev_tweak). */
        unsigned char *t = mode == MBEDTLS_AES_DECRYPT ? prev_tweak : tweak;

        /* We are now on the final part of the data unit, which doesn't divide
         * evenly by 16. It's time for ciphertext stealing. */
        size_t i;
        unsigned char *prev_output = output - 16;

        /* Copy ciphertext bytes from the previous block to our output for each
         * byte of cyphertext we won't steal. At the same time, copy the
         * remainder of the input for this final round (since the loop bounds
         * are the same). */
        for( i = 0; i < leftover; i++ )
        {
            output[i] = prev_output[i];
            tmp[i] = input[i] ^ t[i];
        }

        /* Copy ciphertext bytes from the previous block for input in this
         * round. */
        for( ; i < 16; i++ )
            tmp[i] = prev_output[i] ^ t[i];

        ret = mbedtls_aes_crypt_ecb( &ctx->crypt, mode, tmp, tmp );
        if( ret != 0 )
            return ret;

        /* Write the result back to the previous block, overriding the previous
         * output we copied. */
        for( i = 0; i < 16; i++ )
            prev_output[i] = tmp[i] ^ t[i];
    }

    return( 0 );
}
#endif /* MBEDTLS_CIPHER_MODE_XTS */

#if defined(MBEDTLS_CIPHER_MODE_CFB)
/*
 * AES-CFB128 buffer encryption/decryption
 */
int mbedtls_aes_crypt_cfb128( mbedtls_aes_context *ctx,
                       int mode,
                       size_t length,
                       size_t *iv_off,
                       unsigned char iv[16],
                       const unsigned char *input,
                       unsigned char *output )
{
    int c;
    size_t n;

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( mode == MBEDTLS_AES_ENCRYPT ||
                      mode == MBEDTLS_AES_DECRYPT );
    AES_VALIDATE_RET( iv_off != NULL );
    AES_VALIDATE_RET( iv != NULL );
    AES_VALIDATE_RET( input != NULL );
    AES_VALIDATE_RET( output != NULL );

    n = *iv_off;

    if( n > 15 )
        return( MBEDTLS_ERR_AES_BAD_INPUT_DATA );

    if( mode == MBEDTLS_AES_DECRYPT )
    {
        while( length-- )
        {
            if( n == 0 )
                mbedtls_aes_crypt_ecb( ctx, MBEDTLS_AES_ENCRYPT, iv, iv );

            c = *input++;
            *output++ = (unsigned char)( c ^ iv[n] );
            iv[n] = (unsigned char) c;

            n = ( n + 1 ) & 0x0F;
        }
    }
    else
    {
        while( length-- )
        {
            if( n == 0 )
                mbedtls_aes_crypt_ecb( ctx, MBEDTLS_AES_ENCRYPT, iv, iv );

            iv[n] = *output++ = (unsigned char)( iv[n] ^ *input++ );

            n = ( n + 1 ) & 0x0F;
        }
    }

    *iv_off = n;

    return( 0 );
}
#endif /* MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_OFB)
/*
 * AES-OFB (Output Feedback Mode) buffer encryption/decryption
 */
int mbedtls_aes_crypt_ofb( mbedtls_aes_context *ctx,
                           size_t length,
                           size_t *iv_off,
                           unsigned char iv[16],
                           const unsigned char *input,
                           unsigned char *output )
{
    int ret = 0;
    size_t n;

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( iv_off != NULL );
    AES_VALIDATE_RET( iv != NULL );
    AES_VALIDATE_RET( input != NULL );
    AES_VALIDATE_RET( output != NULL );

    n = *iv_off;

    if( n > 15 )
        return( MBEDTLS_ERR_AES_BAD_INPUT_DATA );

    while( length-- )
    {
        if( n == 0 )
        {
            ret = mbedtls_aes_crypt_ecb( ctx, MBEDTLS_AES_ENCRYPT, iv, iv );
            if( ret != 0 )
                goto exit;
        }
        *output++ =  *input++ ^ iv[n];

        n = ( n + 1 ) & 0x0F;
    }

    *iv_off = n;

exit:
    return( ret );
}
#endif /* MBEDTLS_CIPHER_MODE_OFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
/*
 * AES-CTR buffer encryption/decryption
 */
int mbedtls_aes_crypt_ctr( mbedtls_aes_context *ctx,
                       size_t length,
                       size_t *nc_off,
                       unsigned char nonce_counter[16],
                       unsigned char stream_block[16],
                       const unsigned char *input,
                       unsigned char *output )
{
    int c, i;
    size_t n;

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( nc_off != NULL );
    AES_VALIDATE_RET( nonce_counter != NULL );
    AES_VALIDATE_RET( stream_block != NULL );
    AES_VALIDATE_RET( input != NULL );
    AES_VALIDATE_RET( output != NULL );

    n = *nc_off;

    if ( n > 0x0F )
        return( MBEDTLS_ERR_AES_BAD_INPUT_DATA );

    while( length-- )
    {
        if( n == 0 ) {
            mbedtls_aes_crypt_ecb( ctx, MBEDTLS_AES_ENCRYPT, nonce_counter, stream_block );

            for( i = 16; i > 0; i-- )
                if( ++nonce_counter[i - 1] != 0 )
                    break;
        }
        c = *input++;
        *output++ = (unsigned char)( c ^ stream_block[n] );

        n = ( n + 1 ) & 0x0F;
    }

    *nc_off = n;

    return( 0 );
}
#endif /* MBEDTLS_CIPHER_MODE_CTR */
