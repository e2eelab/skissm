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

cmake_minimum_required(VERSION 3.4)

project(skissm VERSION 3.2.1 LANGUAGES CXX C)

option(SKISSM_TESTS "Build tests" ON)
option(BUILD_SHARED_LIBS "Build as a shared library" ON)

set(PROJECT_VERSION_MAJOR 1)
set(PROJECT_VERSION_MINOR 0)
set(PROJECT_VERSION_PATCH 0)
set(PROJECT_VERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}")
set(PROJECT_VERSION_SO 1)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

set(curve25519_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib/curve25519")
set(mbedtls_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib/mbedtls")
set(protobuf_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib/protobuf/exports/c")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_library(skissm
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

    src/error.c)

add_subdirectory(lib)

target_include_directories(skissm
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/skissm>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${protobuf_DIR}
        ${protobuf_DIR}/lib
        ${curve25519_DIR}
        ${curve25519_DIR}/ed25519
        ${curve25519_DIR}/ed25519/additions
        ${curve25519_DIR}/ed25519/additions/generalized
        ${curve25519_DIR}/ed25519/nacl_includes
        ${mbedtls_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/lib)

set_target_properties(skissm PROPERTIES
    SOVERSION "${PROJECT_VERSION_SO}"
    VERSION "${PROJECT_VERSION}"
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_BINDIR}
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})

# add_link_options(skissm "LINKER:-z,nodefs")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-undefined,dynamic_lookup")

target_link_libraries(skissm
    curve25519
    protobuf
    mbedtls)

#
# Installation
#
include(GNUInstallDirs)
set(INSTALL_CONFIGDIR ${CMAKE_INSTALL_LIBDIR}/cmake/skissm)
install(TARGETS skissm
    EXPORT skissm-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# The exported target will be named skissm.
set_target_properties(skissm PROPERTIES EXPORT_NAME skissm)
install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/include/skissm/e2ee_protocol.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/skissm/account.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/skissm)


if (SKISSM_TESTS)
   add_subdirectory(tests)
endif()