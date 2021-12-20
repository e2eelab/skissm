#ifndef MBEDTLS_PLATFORM_H
#define MBEDTLS_PLATFORM_H

#include <stdlib.h>

#define MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED -0x0072 /**< The requested feature is not supported by the platform */

#define mbedtls_free       free
#define mbedtls_calloc     calloc

#define mbedtls_printf     printf

#endif /* MBEDTLS_PLATFORM_H */
