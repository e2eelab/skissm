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

cmake_minimum_required(VERSION 3.15.0)
project(
  skissm
  VERSION 1.0.1
  LANGUAGES CXX C)

cmake_policy(SET CMP0009 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0079 NEW)

include(GNUInstallDirs)

option(SKISSM_BUILD_PROTOBUF "Build protobuf" ON)
option(SKISSM_TESTS "Build tests" ON)
option(BUILD_SHARED_LIBS "Build as a shared library" ON)

set(PROJECT_VERSION_SO ${PROJECT_VERSION_MAJOR})

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# library path
set(lib_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib")
set(curve25519_DIR "${lib_DIR}/curve25519")
set(mbedtls_DIR "${lib_DIR}/mbedtls")
set(sqlite3_DIR "${lib_DIR}/sqlite3")
set(protobuf_DIR "${lib_DIR}/protobuf")
set(protobuf-c_DIR "${lib_DIR}/protobuf-c")

# mbedtls flags
set(ENABLE_TESTING OFF)
set(ENABLE_PROGRAMS OFF)
set(USE_SHARED_MBEDTLS_LIBRARY ON)

# protobuf flags
set(protobuf_BUILD_PROTOC_BINARIES OFF)
set(protobuf_BUILD_LIBPROTOC OFF)
set(protobuf_BUILD_TESTS OFF)

# set protoc tool path, ex: "/usr/local/bin/protoc"
find_program(PROTOC_EXECUTABLE protoc REQUIRED)
if(NOT PROTOC_EXECUTABLE)
  message(FATAL_ERROR "protoc excutable not found! Please install protoc")
endif()

if(NOT GRPC_CPP_PLUGIN)
  find_program(GRPC_CPP_PLUGIN grpc_cpp_plugin)
endif()

add_compile_options(-Wno-shorten-64-to-32)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

add_subdirectory(${curve25519_DIR})
add_subdirectory(${mbedtls_DIR})
if(SKISSM_BUILD_PROTOBUF)
  add_subdirectory(${protobuf_DIR}/cmake)
endif()

# Patch Protobuf-c bug https://github.com/protobuf-c/protobuf-c/pull/482
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/protobuf-c.cmake
               ${protobuf-c_DIR}/CMakeLists.txt COPYONLY)
add_subdirectory(${protobuf-c_DIR})

set(skissm_src
    src/account_manager.c
    src/account.c
    src/cipher.c
    src/crypto.c
    src/e2ee_protocol.c
    src/error.c
    src/group_session.c
    src/group_session_manager.c
    src/mem_util.c
    src/ratchet.c
    src/session.c
    src/session_manager.c
    src/skissm.c)

set(src_headers
    include/skissm/account_manager.h
    include/skissm/account.h
    include/skissm/cipher.h
    include/skissm/crypto.h
    include/skissm/e2ee_protocol.h
    include/skissm/error.h
    include/skissm/group_session.h
    include/skissm/group_session_manager.h
    include/skissm/mem_util.h
    include/skissm/ratchet.h
    include/skissm/session.h
    include/skissm/session_manager.h
    include/skissm/skissm.h)

set(PROTO_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/protos)
set(PROTO_DIS_DIR ${CMAKE_CURRENT_BINARY_DIR}/proto-src)
file(MAKE_DIRECTORY ${PROTO_DIS_DIR}/skissm/)

file(GLOB skissm_PROTOS ${PROTO_SRC_DIR}/skissm/*.proto)

set(PROTOBUF_PROTOC_EXECUTABLE
    "/usr/local/bin/protoc"
    CACHE STRING "Protoc binary on host")
set(GRPC_CPP_PLUGIN_EXECUTABLE
    "/usr/local/bin/grpc_cpp_plugin"
    CACHE STRING "gRPC CPP plugin binary on host")

set(proto_gen_src "")
set(proto_gen_header "")

foreach(proto ${skissm_PROTOS})
  get_filename_component(proto_name ${proto} NAME_WE)
  message(STATUS "  convert => ${proto}")
  execute_process(
    COMMAND
      ${PROTOC_EXECUTABLE} -I${PROTO_SRC_DIR}/skissm
      --c_out=${PROTO_DIS_DIR}/skissm --grpc_out=${PROTO_DIS_DIR}/skissm
      --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN} ${proto_name}.proto
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

set(skissm_private_include
    ${libprotobuf_includes} ${protobuf-c_DIR} ${gRPC_INCLUDE_DIRS} ${lib_DIR}
    ${curve25519_DIR}/ed25519 ${mbedtls_DIR}/include)

if(CMAKE_SYSTEM_NAME MATCHES iOS)
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")
  set(CMAKE_XCODE_GENERATE_SCHEME ON)

  add_library(skissm_framework SHARED ${skissm_src} ${src_headers}
                                      ${proto_gen_src} ${proto_gen_header})

  add_dependencies(skissm_framework curve25519 mbedtls protobuf::libprotobuf
                   protobuf-c)

  set_source_files_properties(${proto_gen_header}
                              PROPERTIES MACOSX_PACKAGE_LOCATION Headers/skissm)
  set_source_files_properties(${src_headers} PROPERTIES MACOSX_PACKAGE_LOCATION
                                                        Headers)

  target_compile_features(skissm_framework PRIVATE c_std_99 cxx_std_14)
  set_xcode_property(skissm_framework GCC_C_LANGUAGE_STANDARD c99 All)
  set_xcode_property(skissm_framework CLANG_CXX_LANGUAGE_STANDARD c++14 All)
  set_xcode_property(skissm_framework DEBUG_INFORMATION_FORMAT
                     "dwarf-with-dsym" All)
  set_xcode_property(skissm_framework CLANG_ENABLE_MODULES ON All)
  set_xcode_property(skissm_framework PRODUCT_BUNDLE_IDENTIFIER
                     "org.e2ee.ski.SKISSM" All)

  set_target_properties(
    skissm_framework
    PROPERTIES OUTPUT_NAME skissm
               FRAMEWORK TRUE
               FRAMEWORK_VERSION C
               VERSION "${CMAKE_PROJECT_VERSION}"
               SOVERSION "${PROJECT_VERSION_SO}"
               XCODE_GENERATE_SCHEME ON
               MACOSX_RPATH ON
               MACOSX_FRAMEWORK_IDENTIFIER "org.e2ee.ski.SKISSM"
               POSITION_INDEPENDENT_CODE ON)

  target_include_directories(
    skissm_framework
    PUBLIC $<BUILD_INTERFACE:${PROTO_DIS_DIR}>
           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
           $<BUILD_INTERFACE:${protobuf-c_DIR}>
           $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE ${SQLITE3_SRC_DIR}
            ${lib_DIR}
            ${lib_DIR}/curve25519
            ${lib_DIR}/curve25519/ed25519
            ${lib_DIR}/curve25519/ed25519/additions
            ${lib_DIR}/curve25519/ed25519/nacl_includes)

  target_link_libraries(skissm_framework mbedtls curve25519
                        protobuf::libprotobuf protobuf-c)

  install(
    TARGETS skissm_framework
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    FRAMEWORK DESTINATION ${CMAKE_INSTALL_LIBDIR}/Frameworks)

else()
  add_library(skissm_static STATIC ${skissm_src} ${src_headers}
                                   ${proto_gen_src} ${proto_gen_header})

  add_dependencies(skissm_static curve25519 mbedtls protobuf::libprotobuf
                   protobuf-c)

  target_include_directories(
    skissm_static
    PUBLIC $<BUILD_INTERFACE:${PROTO_DIS_DIR}>
           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
           $<BUILD_INTERFACE:${protobuf-c_DIR}>
           $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE ${SQLITE3_SRC_DIR}
            ${lib_DIR}
            ${lib_DIR}/curve25519
            ${lib_DIR}/curve25519/ed25519
            ${lib_DIR}/curve25519/ed25519/additions
            ${lib_DIR}/curve25519/ed25519/nacl_includes)

  target_compile_features(skissm_static PRIVATE c_std_99 cxx_std_14)

  set_target_properties(
    skissm_static
    PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON
               SOVERSION "${PROJECT_VERSION_SO}"
               VERSION "${CMAKE_PROJECT_VERSION}"
               ARCHIVE_OUTPUT_DIRECTORY
               ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_BINDIR}
               LIBRARY_OUTPUT_DIRECTORY
               ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}
               RUNTIME_OUTPUT_DIRECTORY
               ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_BINDIR})

  target_link_options(skissm_static PUBLIC "LINKER:-undefined,dynamic_lookup")
  target_link_libraries(skissm_static PUBLIC mbedtls curve25519
                                             protobuf::libprotobuf protobuf-c)

  install(
    TARGETS skissm_static
    EXPORT skissm-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    PRIVATE_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

  # skissm_shared
  add_library(skissm_shared SHARED ${skissm_src} ${proto_gen_src})

  add_dependencies(skissm_shared curve25519 mbedtls protobuf::libprotobuf
                   protobuf-c)

  target_include_directories(
    skissm_shared
    PUBLIC $<BUILD_INTERFACE:${PROTO_DIS_DIR}>
           $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
           $<BUILD_INTERFACE:${protobuf-c_DIR}>
           $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE ${SQLITE3_SRC_DIR}
            ${lib_DIR}
            ${lib_DIR}/curve25519
            ${lib_DIR}/curve25519/ed25519
            ${lib_DIR}/curve25519/ed25519/additions
            ${lib_DIR}/curve25519/ed25519/nacl_includes)

  target_compile_features(skissm_shared PRIVATE c_std_99 cxx_std_14)

  set_target_properties(
    skissm_shared
    PROPERTIES POSITION_INDEPENDENT_CODE ON
               WINDOWS_EXPORT_ALL_SYMBOLS ON
               SOVERSION "${PROJECT_VERSION_SO}"
               VERSION "${CMAKE_PROJECT_VERSION}"
               ARCHIVE_OUTPUT_DIRECTORY
               ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_BINDIR}
               LIBRARY_OUTPUT_DIRECTORY
               ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}
               RUNTIME_OUTPUT_DIRECTORY
               ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_BINDIR})

  target_link_options(skissm_shared PUBLIC "LINKER:-undefined,dynamic_lookup")
  target_link_libraries(skissm_shared PUBLIC mbedtls curve25519
                                             protobuf::libprotobuf protobuf-c)

  #
  # Installation
  #
  install(
    TARGETS skissm_shared
    EXPORT skissm-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    PRIVATE_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

  if(SKISSM_TESTS)
    add_subdirectory(tests)
  endif()

  # include(CMakePackageConfigHelpers)
  # write_basic_package_version_file(SkissmConfigVersion.cmake COMPATIBILITY
  # SameMajorVersion)

  # install( EXPORT SkissmTargets FILE SkissmTargets.cmake NAMESPACE skissm::
  # DESTINATION lib/cmake/skissm)

  # install(FILES "${CMAKE_CURRENT_BINARY_DIR}/SkissmConfig.cmake"
  # "${CMAKE_CURRENT_BINARY_DIR}/SkissmConfigVersion.cmake" DESTINATION
  # lib/cmake/MyLib)
endif()
