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

cmake_policy(SET CMP0009 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0079 NEW)

include(FetchContent)
include(GNUInstallDirs)

option(SKISSM_TESTS "Build tests" ON)
option(BUILD_SHARED_LIBS "Build as a shared library" ON)

set(PROJECT_VERSION_SO 1.0.1)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(ENABLE_TESTING ON)
set(BENCHMARK_ENABLE_TESTING OFF)
set(ENABLE_PROGRAMS OFF)
set(USE_SHARED_MBEDTLS_LIBRARY ON)
set(protobuf_BUILD_TESTS OFF)
set(BUILD_PROTOC OFF)

set(lib_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib")
set(curve25519_DIR "${lib_DIR}/curve25519")
set(mbedtls_DIR "${lib_DIR}/mbedtls")
set(protobuf-c_DIR "${lib_DIR}/protobuf-c")
set(sqlite3_DIR "${lib_DIR}/sqlite3")

list(APPEND CMAKE_MODULE_PATH
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake"
)

add_subdirectory(${curve25519_DIR})
add_subdirectory(${mbedtls_DIR})

if(NOT TARGET grpc)
    find_package(gRPC REQUIRED)
endif()

if(NOT TARGET libprotobuf)
    find_package(Protobuf REQUIRED)
endif()

# Patch Protobuf-c bug https://github.com/protobuf-c/protobuf-c/pull/482
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/protobuf-c.cmake 
    ${protobuf-c_DIR}/CMakeLists.txt
    COPYONLY
)
add_subdirectory(${protobuf-c_DIR})

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

set(PROTO_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/protos)
set(PROTO_DIS_DIR ${CMAKE_CURRENT_BINARY_DIR}/proto-src)
file(MAKE_DIRECTORY ${PROTO_DIS_DIR})

FILE(GLOB skissm_PROTOS
    ${PROTO_SRC_DIR}/skissm/*.proto
    ${PROTO_SRC_DIR}/skissm/service/*.proto
    ${PROTO_SRC_DIR}/skissm/service/dto/*.proto
)

FOREACH(proto ${skissm_PROTOS})
    get_filename_component(proto_name ${proto} NAME_WE)
    message(STATUS "Converting ${proto}")
    if(EXISTS ${PROTO_SRC_DIR}/skissm/${proto_name}.proto)
        EXECUTE_PROCESS(COMMAND ${PROTOBUF_PROTOC_EXECUTABLE} --proto_path=${PROTO_SRC_DIR} --c_out=${PROTO_DIS_DIR} --plugin=protoc-gen-grpc=grpc_cpp_plugin skissm/${proto_name}.proto RESULT_VARIABLE rv)
        list(APPEND skissm_src ${PROTO_DIS_DIR}/skissm/${proto_name}.pb-c.c)
    elseif(EXISTS ${PROTO_SRC_DIR}/skissm/service/${proto_name}.proto)
        EXECUTE_PROCESS(COMMAND ${PROTOBUF_PROTOC_EXECUTABLE} --proto_path=${PROTO_SRC_DIR} --c_out=${PROTO_DIS_DIR} --plugin=protoc-gen-grpc=grpc_cpp_plugin skissm/service/${proto_name}.proto RESULT_VARIABLE rv)
        list(APPEND skissm_src ${PROTO_DIS_DIR}/skissm/service/${proto_name}.pb-c.c)
    else()
        EXECUTE_PROCESS(COMMAND ${PROTOBUF_PROTOC_EXECUTABLE} --proto_path=${PROTO_SRC_DIR} --c_out=${PROTO_DIS_DIR} --plugin=protoc-gen-grpc=grpc_cpp_plugin skissm/service/dto/${proto_name}.proto RESULT_VARIABLE rv)
        list(APPEND skissm_src ${PROTO_DIS_DIR}/skissm/service/dto/${proto_name}.pb-c.c)
    endif()

    # Optional, but that can show the user if something have gone wrong with the proto generation 
    IF(${rv})
        MESSAGE("Generation of data model returned ${rv}")
    ENDIF()
ENDFOREACH(proto)

file(GLOB_RECURSE skissm_headers "${CMAKE_CURRENT_SOURCE_DIR}/include/skissm/*.h")

set(skissm_private_include
    ${libprotobuf_includes}
    ${protobuf-c_DIR}
    ${gRPC_INCLUDE_DIRS}
    ${lib_DIR}
    ${curve25519_DIR}/ed25519
    ${mbedtls_DIR}/include
)

# message(STATUS "skissm_headers: ${skissm_headers}")

if (CMAKE_GENERATOR MATCHES "Xcode")
    set(CMAKE_XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "iPhone Developer")
    set(CMAKE_XCODE_ATTRIBUTE_DEVELOPMENT_TEAM FCU7D4F89K)
    set(CMAKE_XCODE_ATTRIBUTE_DEBUG_INFORMATION_FORMAT "dwarf-with-dsym")

    add_library(skissm_framework SHARED
        ${skissm_src}
        ${skissm_headers}
    )
    add_dependencies(skissm_framework curve25519 mbedtls protobuf::libprotobuf protobuf-c)

    target_include_directories(skissm_framework
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/skissm>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
            ${PROTO_DIS_DIR}
        PRIVATE
            ${skissm_private_include}
    )

    target_compile_features(skissm_framework PRIVATE
        c_std_99
        cxx_std_14
    )

    set_target_properties(
        skissm_framework
        PROPERTIES
        OUTPUT_NAME ${CMAKE_PROJECT_NAME}
        FRAMEWORK TRUE
        FRAMEWORK_VERSION C
        POSITION_INDEPENDENT_CODE ON
        MACOSX_FRAMEWORK_IDENTIFIER org.e2eelab.ski.skissm
        MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION_SO}"
        MACOSX_BUNDLE_BUNDLE_VERSION ${CMAKE_CACHE_MAJOR_VERSION}.${CMAKE_CACHE_MINOR_VERSION}
        MACOSX_RPATH ON
    )

    foreach(file_path ${skissm_headers})
        get_filename_component(file_name file_path NAME)
        set_property(SOURCE ${file_path} PROPERTY MACOSX_PACKAGE_LOCATION Headers)
    endforeach(file_path)

    target_link_libraries(skissm_framework
        PUBLIC
            mbedtls
            curve25519
            protobuf::libprotobuf
            protobuf-c
    )

else()
    # skissm_static
    add_library(skissm_static STATIC
        ${skissm_src} ${skissm_headers}
    )
    add_dependencies(skissm_static curve25519 mbedtls protobuf::libprotobuf protobuf-c)

    target_include_directories(skissm_static
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/skissm>
            $<BUILD_INTERFACE:${protobuf-c_DIR}>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
            ${PROTO_DIS_DIR}
        PRIVATE
            $<BUILD_INTERFACE:${PROTO_DIS_DIR}>
            ${skissm_private_include}
    )

    target_compile_features(skissm_static PRIVATE
        c_std_99
        cxx_std_14
    )

    set_target_properties(skissm_static PROPERTIES
        WINDOWS_EXPORT_ALL_SYMBOLS ON
        SOVERSION "${PROJECT_VERSION_SO}"
        VERSION "${CMAKE_PROJECT_VERSION}"
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_BINDIR}
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}
    )

    target_link_options(skissm_static PUBLIC "LINKER:-undefined,dynamic_lookup")
    target_link_libraries(skissm_static
        PUBLIC
            mbedtls
            curve25519
            protobuf::libprotobuf
            protobuf-c
    )

    install(TARGETS skissm_static EXPORT skissm-targets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )

    # skissm_shared
    add_library(skissm_shared SHARED
        ${skissm_src} ${skissm_headers}
    )
    add_dependencies(skissm_shared curve25519 mbedtls protobuf::libprotobuf protobuf-c)
    target_include_directories(skissm_shared
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/skissm>
            $<BUILD_INTERFACE:${protobuf-c_DIR}>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
            ${PROTO_DIS_DIR}
        PRIVATE
            $<BUILD_INTERFACE:${PROTO_DIS_DIR}>
            ${skissm_private_include}
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
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_BINDIR}
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}
    )

    target_link_options(skissm_shared PUBLIC "LINKER:-undefined,dynamic_lookup")
    target_link_libraries(skissm_shared
        PUBLIC
            mbedtls
            curve25519
            protobuf::libprotobuf
            protobuf-c
    )

    #
    # Installation
    #
    install(TARGETS skissm_shared EXPORT skissm-targets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )

    if (SKISSM_TESTS)
        add_subdirectory(tests)
    endif()
endif()

# message(STATUS "CMAKE_INSTALL_INCLUDEDIR: ${CMAKE_INSTALL_INCLUDEDIR}")

# install(FILES
#     ${CMAKE_CURRENT_SOURCE_DIR}/include/skissm/e2ee_protocol.h
#     ${CMAKE_CURRENT_SOURCE_DIR}/include/skissm/account.h
#     DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/skissm
# )

