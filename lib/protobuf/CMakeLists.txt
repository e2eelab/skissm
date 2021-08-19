IF(CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID MATCHES "Clang")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-variable -Wno-unused-function -Wno-shadow")
ENDIF(CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID MATCHES "Clang")

IF(CMAKE_COMPILER_IS_GNUCC)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-sign-compare")
    IF(GCC_WARN_SIGN_CONVERSION)
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-sign-conversion")
    ENDIF(GCC_WARN_SIGN_CONVERSION)
ENDIF(CMAKE_COMPILER_IS_GNUCC)

IF(CMAKE_C_COMPILER_ID MATCHES "Clang")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-shorten-64-to-32")
ENDIF(CMAKE_C_COMPILER_ID MATCHES "Clang")

include_directories(
    exports/c
    exports/c/lib
)

set(protobuf_SRCS
    exports/c/lib/protobuf-c/protobuf-c.c
    exports/c/e2ee_account.pb-c.c
    exports/c/e2ee_address.pb-c.c
    exports/c/e2ee_commands.pb-c.c
    exports/c/e2ee_message.pb-c.c
    exports/c/e2ee_pre_key_bundle.pb-c.c
    exports/c/e2ee_session.pb-c.c
)

# Add -fPIC flag
if(BUILD_SHARED_LIBS)
    add_library(protobuf OBJECT ${protobuf_SRCS})
    set_property(TARGET protobuf PROPERTY POSITION_INDEPENDENT_CODE ON)
else()
    add_library(protobuf STATIC ${protobuf_SRCS})
    set_property(TARGET protobuf PROPERTY POSITION_INDEPENDENT_CODE OFF)
endif()
