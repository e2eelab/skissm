#ifndef MBEDTLS_MD_INTERNAL_H
#define MBEDTLS_MD_INTERNAL_H

#include "md.h"

/**
 * Message digest information.
 * Allows message digest functions to be called in a generic way.
 */
struct mbedtls_md_info_t
{
    /** Name of the message digest */
    const char *name;

    /** Digest identifier */
    mbedtls_md_type_t type;

    /** Output length of the digest function in bytes */
    unsigned char size;

    /** Block length of the digest function in bytes */
    unsigned char block_size;
};

#endif /* MBEDTLS_MD_INTERNAL_H */
