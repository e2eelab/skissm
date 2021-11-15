################################################################################
#
#  Copyright © 2020-2021 by Academia Sinica
#
#  This file is part of SKISSM.
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  SKISSM is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with SKISSM.  If not, see <http://www.gnu.org/licenses/>.
#
################################################################################

cmake_minimum_required(VERSION 3.14)
project(skissm VERSION 1.0.1 LANGUAGES CXX C)

include(FetchContent)
include(GNUInstallDirs)

option(SKISSM_TESTS "Build tests" OFF)
option(BUILD_SHARED_LIBS "Build as a shared library" ON)

set(PROJECT_VERSION_SO 1.0.1)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
set(curve25519_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib")
set(protos_DIR "${CMAKE_CURRENT_SOURCE_DIR}/protos")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

FetchContent_Declare(
    mbedtls
    GIT_REPOSITORY https://github.com/ARMmbed/mbedtls.git
    GIT_TAG v3.0.0
)
message(STATUS "Fetching mbedtls")
FetchContent_MakeAvailable(mbedtls)

find_package(Protobuf REQUIRED)
find_package(gRPC REQUIRED)
add_subdirectory(${curve25519_DIR}/curve25519)

set(skissm_src
    src/account_manager.c
    src/account.c
    src/cipher.c
    src/crypto.c
    src/group_session_manager.c
    src/group_session.c
    src/mem_util.c
    src/ratchet.c
    src/session.c
    src/e2ee_protocol.c
    src/skissm.c
    src/error.c
)


FILE(GLOB_RECURSE PROTOS "${protos_DIR}" *.proto)
set(PROTO_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/protos)
set(PROTO_DIS_DIR ${CMAKE_CURRENT_BINARY_DIR}/proto-src)
file(MAKE_DIRECTORY ${PROTO_DIS_DIR})

FOREACH(proto ${PROTOS})
    get_filename_component(proto_name ${proto} NAME_WE)
    message(STATUS "Converting ${proto}")
    if(EXISTS ${PROTO_SRC_DIR}/skissm/${proto_name}.proto)
        EXECUTE_PROCESS(COMMAND ${PROTOBUF_PROTOC_EXECUTABLE} --proto_path=${protos_DIR} --c_out=${PROTO_DIS_DIR} --plugin=protoc-gen-grpc=grpc_cpp_plugin skissm/${proto_name}.proto RESULT_VARIABLE rv)
        list(APPEND skissm_src ${PROTO_DIS_DIR}/skissm/${proto_name}.pb-c.c)
    elseif(EXISTS ${PROTO_SRC_DIR}/skissm/service/${proto_name}.proto)
        EXECUTE_PROCESS(COMMAND ${PROTOBUF_PROTOC_EXECUTABLE} --proto_path=${protos_DIR} --c_out=${PROTO_DIS_DIR} --plugin=protoc-gen-grpc=grpc_cpp_plugin skissm/service/${proto_name}.proto RESULT_VARIABLE rv)
        list(APPEND skissm_src ${PROTO_DIS_DIR}/skissm/service/${proto_name}.pb-c.c)
    else()
        EXECUTE_PROCESS(COMMAND ${PROTOBUF_PROTOC_EXECUTABLE} --proto_path=${protos_DIR} --c_out=${PROTO_DIS_DIR} --plugin=protoc-gen-grpc=grpc_cpp_plugin skissm/service/dto/${proto_name}.proto RESULT_VARIABLE rv)
        list(APPEND skissm_src ${PROTO_DIS_DIR}/skissm/service/dto/${proto_name}.pb-c.c)
    endif()
    
    # Optional, but that can show the user if something have gone wrong with the proto generation 
    IF(${rv})
        MESSAGE("Generation of data model returned ${rv} for dir:${proto_dir} name:{proto_name}")
    ENDIF()
ENDFOREACH(proto)

set(skissm_include
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/skissm>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${Protobuf_INCLUDE_DIRS}
        ${PROTO_DIS_DIR}
        ${PROTO_DIS_DIR}/service
        ${PROTO_DIS_DIR}/service/dto
        ${curve25519_DIR}
        ${curve25519_DIR}/curve25519/ed25519
        ${mbedtls_BINARY_DIR}/include
)

if (CMAKE_GENERATOR MATCHES "Xcode")
    set_xcode_property(skissm 
        PRODUCT_BUNDLE_IDENTIFIER "org.e2eelab.skissm" All
    )
    set_xcode_property(skissm 
        CODE_SIGN_IDENTITY "iPhone Developer" All
    )
    set_xcode_property(skissm 
        DEVELOPMENT_TEAM FCU7D4F89K All
    )
endif()

# skissm_static
add_library(skissm_static STATIC
    ${skissm_src}
)

target_include_directories(skissm_static
    ${skissm_include}
)

target_compile_features(skissm_static PRIVATE 
    c_std_99
    cxx_std_14
)

set_target_properties(skissm_static PROPERTIES
    POSITION_INDEPENDENT_CODE OFF
    WINDOWS_EXPORT_ALL_SYMBOLS ON
    SOVERSION "${PROJECT_VERSION_SO}"
    VERSION "${CMAKE_PROJECT_VERSION}"
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_BINDIR}
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}
)

target_link_options(skissm_static PUBLIC "LINKER:-undefined,dynamic_lookup")
add_dependencies(skissm_static mbedtls curve25519)

target_link_libraries(skissm_static
    PUBLIC 
        mbedtls 
        mbedx509 
        mbedcrypto
        curve25519
        gRPC::grpc
        Protobuf
)

# skissm_shared
add_library(skissm_shared SHARED
    ${skissm_src}
)

target_include_directories(skissm_shared
    ${skissm_include}
)

target_compile_features(skissm_shared PRIVATE 
    c_std_99
    cxx_std_14
)

set_target_properties(skissm_shared PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    WINDOWS_EXPORT_ALL_SYMBOLS ON
    SOVERSION "${PROJECT_VERSION_SO}"
    VERSION "${CMAKE_PROJECT_VERSION}"
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_BINDIR}
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}
)

target_link_options(skissm_shared PUBLIC "LINKER:-undefined,dynamic_lookup")
add_dependencies(skissm_shared mbedtls curve25519)
target_link_libraries(skissm_static
    PUBLIC 
    mbedtls 
    mbedx509 
    mbedcrypto
    curve25519
    gRPC::grpc
    Protobuf
)


#
# Installation
#
set(INSTALL_CONFIGDIR ${CMAKE_INSTALL_LIBDIR}/cmake/skissm)
install(TARGETS skissm_static EXPORT skissm-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/include/skissm/e2ee_protocol.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/skissm/account.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/skissm
)

if (SKISSM_TESTS)
   add_subdirectory(tests)
endif()
