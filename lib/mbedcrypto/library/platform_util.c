
#include "platform_util.h"

#include <string.h>

static void * (* const volatile memset_func)( void *, int, size_t ) = memset;

void mbedtls_platform_zeroize( void *buf, size_t len )
{
    MBEDTLS_INTERNAL_VALIDATE( len == 0 || buf != NULL );

    if( len > 0 )
        memset_func( buf, 0, len );
}
