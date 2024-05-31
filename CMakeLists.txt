# ##############################################################################
#
# Copyright © 2020-2021 by Academia Sinica
#
# This file is part of SKISSM.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# SKISSM is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# SKISSM.  If not, see <http://www.gnu.org/licenses/>.
#
# ##############################################################################

cmake_minimum_required(VERSION 3.21)
project(
  skissm
  LANGUAGES CXX C)

cmake_policy(SET CMP0009 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0079 NEW)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 17)

include(GNUInstallDirs)

option(SKISSM_BUILD_PROTOBUF "Build protobuf" ON)
option(SKISSM_TESTS "Build skissm tests" ON)

set(EXTERNAL_LIB_DIR "${CMAKE_CURRENT_BINARY_DIR}/lib")

# library path
set(lib_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib")
set(curve25519_DIR "${lib_DIR}/curve25519")
set(mbedcrypto_DIR "${lib_DIR}/mbedcrypto")
set(protobuf_DIR "${lib_DIR}/protobuf")
set(protobuf-c_DIR "${lib_DIR}/protobuf-c")
set(pqclean_DIR "${lib_DIR}/PQClean")

# protobuf flags
set(protobuf_BUILD_SHARED_LIBS OFF)
set(protobuf_BUILD_PROTOC_BINARIES OFF)
set(protobuf_BUILD_LIBPROTOC OFF)
set(protobuf_BUILD_TESTS OFF)

# set protoc tool path, ex: "/usr/local/bin/protoc"
find_program(PROTOC_EXECUTABLE protoc REQUIRED)
if(NOT PROTOC_EXECUTABLE)
  message(FATAL_ERROR "protoc excutable not found! Please install protoc")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

add_subdirectory(${curve25519_DIR} ${EXTERNAL_LIB_DIR}/curve25519)
add_subdirectory(${mbedcrypto_DIR} ${EXTERNAL_LIB_DIR}/mbedcrypto)
add_subdirectory(${pqclean_DIR} ${EXTERNAL_LIB_DIR}/PQClean)
if(SKISSM_BUILD_PROTOBUF)
  add_subdirectory(${protobuf_DIR})
endif()

# Patch Protobuf-c bug https://github.com/protobuf-c/protobuf-c/pull/482
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/protobuf-c.cmake
               ${protobuf-c_DIR}/CMakeLists.txt COPYONLY)
add_subdirectory(${protobuf-c_DIR} ${EXTERNAL_LIB_DIR}/protobuf-c)

file(GLOB skissm_src ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)
file(GLOB src_headers ${CMAKE_CURRENT_SOURCE_DIR}/include/skissm/*.h)

set(PROTO_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/protos/src)
set(PROTO_DIS_DIR ${CMAKE_CURRENT_BINARY_DIR}/proto-gen)
file(MAKE_DIRECTORY ${PROTO_DIS_DIR}/skissm)

file(GLOB skissm_PROTOS ${PROTO_SRC_DIR}/skissm/*.proto)

set(PROTOBUF_PROTOC_EXECUTABLE
    "/usr/local/bin/protoc"
    CACHE STRING "Protoc binary on host")

set(proto_gen_src "")
set(proto_gen_header "")

foreach(proto ${skissm_PROTOS})
  get_filename_component(proto_name ${proto} NAME_WE)
  message(STATUS "  convert => ${proto}")
  execute_process(
    COMMAND
      ${PROTOC_EXECUTABLE} -I=skissm --proto_path=${PROTO_SRC_DIR}
      --c_out=${PROTO_DIS_DIR}/skissm ${proto_name}.proto
    RESULT_VARIABLE rv
    OUTPUT_VARIABLE protoc_output
    WORKING_DIRECTORY ${PROTO_SRC_DIR})
  list(APPEND proto_gen_src ${PROTO_DIS_DIR}/skissm/${proto_name}.pb-c.c)
  list(APPEND proto_gen_header ${PROTO_DIS_DIR}/skissm/${proto_name}.pb-c.h)

  # Optional, but that can show the user if something have gone wrong with the
  # proto generation
  if(${rv})
    message("Generation of data model returned ${rv}")
  endif()
endforeach(proto)

# Target: skissm_static
add_library(skissm_static STATIC ${skissm_src} ${src_headers}
                                  ${proto_gen_src} ${proto_gen_header})

add_dependencies(skissm_static curve25519 mbedcrypto protobuf::libprotobuf
                  protobuf-c)

target_include_directories(
  skissm_static
  PUBLIC $<BUILD_INTERFACE:${PROTO_DIS_DIR}>
          $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
          $<BUILD_INTERFACE:${protobuf-c_DIR}>
          $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE ${lib_DIR} ${lib_DIR}/curve25519 ${lib_DIR}/curve25519/ed25519
          ${lib_DIR}/curve25519/ed25519/additions
          ${lib_DIR}/curve25519/ed25519/nacl_includes)

set_target_properties(
  skissm_static
  PROPERTIES OUTPUT_NAME "skissm"
              WINDOWS_EXPORT_ALL_SYMBOLS ON
              ARCHIVE_OUTPUT_DIRECTORY
              ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_BINDIR}
              LIBRARY_OUTPUT_DIRECTORY
              ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}
              RUNTIME_OUTPUT_DIRECTORY
              ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_BINDIR})

target_link_libraries(skissm_static PUBLIC mbedcrypto curve25519 pqclean
                                            protobuf::libprotobuf protobuf-c)

# Install
install(TARGETS skissm_static
  EXPORT skissm-targets
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  #INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  #PRIVATE_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(
    DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/.
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING
    PATTERN "*.h")

install(
    DIRECTORY ${PROTO_DIS_DIR}/.
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING
    PATTERN "*.h")

if(SKISSM_TESTS)
  add_subdirectory(tests)
endif()
