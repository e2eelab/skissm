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
cmake_policy(SET CMP0077 NEW)


include(FetchContent)
include(GNUInstallDirs)

option(SKISSM_TESTS "Build tests" OFF)
option(BUILD_SHARED_LIBS "Build as a shared library" ON)

set(PROJECT_VERSION_SO 1.0.1)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" "/opt/homebrew/opt/mbedtls/cmake")
list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew" "/opt/homebrew/opt")

set(curve25519_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

FetchContent_Declare(
    mbedtls
    GIT_REPOSITORY https://github.com/ARMmbed/mbedtls.git
    GIT_TAG v3.0.0
)

FetchContent_Declare(
    Protobuf
    GIT_REPOSITORY https://github.com/protocolbuffers/protobuf.git
    GIT_TAG v3.19.1
    SOURCE_SUBDIR cmake
)

FetchContent_Declare(
    Protobuf-c
    GIT_REPOSITORY https://github.com/protobuf-c/protobuf-c.git
    GIT_TAG v1.4.0
)

set(ENABLE_TESTING OFF)
set(BENCHMARK_ENABLE_TESTING OFF)
set(ENABLE_PROGRAMS OFF)
set(USE_SHARED_MBEDTLS_LIBRARY ON)
set(protobuf_BUILD_TESTS OFF)
set(BUILD_PROTOC OFF)

message(STATUS "Fetching mbedtls Protobuf")
FetchContent_MakeAvailable(mbedtls Protobuf Protobuf-c)

# Patch Protobuf-c bug https://github.com/protobuf-c/protobuf-c/pull/482
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/protobuf-c.cmake ${protobuf-c_SOURCE_DIR}/CMakeLists.txt)

# find_package(Protobuf REQUIRED)
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


set(PROTO_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/protos")
set(PROTO_DIS_DIR ${CMAKE_CURRENT_BINARY_DIR}/proto-src)
file(MAKE_DIRECTORY ${PROTO_DIS_DIR})

FILE(GLOB skissm_PROTOS 
    ${PROTO_SRC_DIR}/skissm/*.proto
    ${PROTO_SRC_DIR}/skissm/service/*.proto
    ${PROTO_SRC_DIR}/skissm/service/dto/*.proto
)

message(STATUS "skissm_PROTOS: ${skissm_PROTOS}")
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

set(skissm_include
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/skissm>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${Protobuf_INCLUDE_DIRS}
        ${Protobuf-c_INCLUDE_DIRS}
        ${gRPC_INCLUDE_DIRS}
        ${PROTO_DIS_DIR}
        ${PROTO_DIS_DIR}/service
        ${PROTO_DIS_DIR}/service/dto
        ${curve25519_DIR}
        ${curve25519_DIR}/curve25519/ed25519
        ${mbedtls_BINARY_DIR}/include
)

function(get_all_targets var)
    set(targets)
    get_all_targets_recursive(targets ${CMAKE_CURRENT_SOURCE_DIR})
    set(${var} ${targets} PARENT_SCOPE)
endfunction()

macro(get_all_targets_recursive targets dir)
    get_property(subdirectories DIRECTORY ${dir} PROPERTY SUBDIRECTORIES)
    foreach(subdir ${subdirectories})
        get_all_targets_recursive(${targets} ${subdir})
    endforeach()

    get_property(current_targets DIRECTORY ${dir} PROPERTY BUILDSYSTEM_TARGETS)
    list(APPEND ${targets} ${current_targets})
endmacro()

if (CMAKE_GENERATOR MATCHES "Xcode")
    get_all_targets(all_targets)
    message("All targets: ${all_targets}")

    add_library(skissm_framework SHARED
        ${skissm_src}
    )

    target_include_directories(skissm_framework
        ${skissm_include}
    )

    target_compile_features(skissm_framework PRIVATE 
        c_std_99
        cxx_std_14
    )

    foreach(target ${all_targets})
        message(STATUS "Signing ${target}")
        set_xcode_property(${target} 
            PRODUCT_BUNDLE_IDENTIFIER "org.e2eelab.${target}"
            CODE_SIGN_IDENTITY "iPhone Developer"
            DEVELOPMENT_TEAM FCU7D4F89K 
            DEBUG_INFORMATION_FORMAT "dwarf-with-dsym" All
        )
    endforeach(target in all_targets)

    set_target_properties(skissm_framework PROPERTIES
        OUTPUT_NAME skissm
        FRAMEWORK TRUE
        FRAMEWORK_VERSION C
        POSITION_INDEPENDENT_CODE ON
        MACOSX_FRAMEWORK_IDENTIFIER org.e2eelab.skissm.skissm
        MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION_SO}"
        MACOSX_BUNDLE_BUNDLE_VERSION 1.0
        MACOSX_RPATH TRUE
        SOVERSION "${PROJECT_VERSION_SO}"
        PUBLIC_HEADER ${skissm_include}
    )

    add_dependencies(skissm_framework curve25519 Protobuf gRPC::grpc Protobuf-c mbedtls mbedx509 mbedcrypto)
    target_link_libraries(skissm_framework
        PUBLIC 
            mbedtls 
            mbedx509 
            mbedcrypto
            curve25519
            gRPC::grpc
            Protobuf
            Protobuf-c
    )
else()
    # skissm_static
    add_library(skissm_static STATIC
        ${skissm_src}
    )
    add_dependencies(skissm_static curve25519 gRPC::grpc mbedtls mbedx509 mbedcrypto)

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
    target_link_libraries(skissm_static
        PUBLIC 
            mbedtls 
            mbedx509 
            mbedcrypto
            curve25519
            gRPC::grpc
            Protobuf
            Protobuf-c
    )

    set(INSTALL_CONFIGDIR ${CMAKE_INSTALL_LIBDIR}/cmake/skissm)
    install(TARGETS skissm_static EXPORT skissm-targets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )

    # skissm_shared
    add_library(skissm_shared SHARED
        ${skissm_src}
    )
    add_dependencies(skissm_shared curve25519 gRPC::grpc mbedtls mbedx509 mbedcrypto)
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
    target_link_libraries(skissm_static
        PUBLIC 
            mbedtls 
            mbedx509 
            mbedcrypto
            curve25519
            gRPC::grpc
            Protobuf
            Protobuf-c
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

    if (SKISSM_TESTS)
        add_subdirectory(tests)
    endif()
endif()

install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/include/skissm/e2ee_protocol.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/skissm/account.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/skissm
)

