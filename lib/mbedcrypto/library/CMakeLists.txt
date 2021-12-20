option(USE_STATIC_MBEDTLS_LIBRARY "Build mbed TLS static library." ON)
option(USE_SHARED_MBEDTLS_LIBRARY "Build mbed TLS shared library." OFF)
option(LINK_WITH_PTHREAD "Explicitly link mbed TLS library to pthread." OFF)
option(LINK_WITH_TRUSTED_STORAGE "Explicitly link mbed TLS library to trusted_storage." OFF)

# Set the project root directory if it's not already defined, as may happen if
# the library folder is included directly by a parent project, without
# including the top level CMakeLists.txt.
if(NOT DEFINED MBEDTLS_DIR)
    set(MBEDTLS_DIR ${CMAKE_SOURCE_DIR})
endif()

set(src_crypto
    aes.c
    aesni.c
    cipher.c
    cipher_wrap.c
    gcm.c
    hkdf.c
    md.c
    platform_util.c
    sha256.c
    sha512.c
)

set(mbedcrypto_target "${MBEDTLS_TARGET_PREFIX}mbedcrypto")

set(mbedcrypto_target ${mbedcrypto_target} PARENT_SCOPE)

if (USE_STATIC_MBEDTLS_LIBRARY)
    set(mbedcrypto_static_target ${mbedcrypto_target})
endif()

set(target_libraries ${mbedcrypto_target})

if(USE_STATIC_MBEDTLS_LIBRARY AND USE_SHARED_MBEDTLS_LIBRARY)
    string(APPEND mbedcrypto_static_target "_static")

    list(APPEND target_libraries
        ${mbedcrypto_static_target}
        )
endif()

if(USE_STATIC_MBEDTLS_LIBRARY)
    add_library(${mbedcrypto_static_target} STATIC ${src_crypto})
    set_target_properties(${mbedcrypto_static_target} PROPERTIES OUTPUT_NAME mbedcrypto)
    target_link_libraries(${mbedcrypto_static_target} PUBLIC ${libs})
endif(USE_STATIC_MBEDTLS_LIBRARY)

if(USE_SHARED_MBEDTLS_LIBRARY)
    add_library(${mbedcrypto_target} SHARED ${src_crypto})
    set_target_properties(${mbedcrypto_target} PROPERTIES VERSION 2.26.0 SOVERSION 6)
    target_link_libraries(${mbedcrypto_target} PUBLIC ${libs})
endif(USE_SHARED_MBEDTLS_LIBRARY)

foreach(target IN LISTS target_libraries)
    # Include public header files from /include and other directories
    # declared by /3rdparty/**/CMakeLists.txt. Include private header files
    # from /library and others declared by /3rdparty/**/CMakeLists.txt.
    # /library needs to be listed explicitly when building .c files outside
    # of /library (which currently means: under /3rdparty).
    target_include_directories(${target}
        PUBLIC ${MBEDTLS_DIR}/include/
        PRIVATE ${MBEDTLS_DIR}/library/)
    install(TARGETS ${target}
            DESTINATION ${LIB_INSTALL_DIR}
            PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
endforeach(target)

set(lib_target "${MBEDTLS_TARGET_PREFIX}lib")

add_custom_target(${lib_target} DEPENDS ${mbedcrypto_target})
if(USE_STATIC_MBEDTLS_LIBRARY AND USE_SHARED_MBEDTLS_LIBRARY)
    add_dependencies(${lib_target} ${mbedcrypto_static_target})
endif()

