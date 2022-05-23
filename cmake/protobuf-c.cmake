set(PACKAGE protobuf-c)
set(PACKAGE_NAME protobuf-c)
set(PACKAGE_VERSION 1.4.0)
set(PACKAGE_URL https://github.com/protobuf-c/protobuf-c)
set(PACKAGE_DESCRIPTION "Protocol Buffers implementation in C")

cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

project(protobuf-c)
include(GNUInstallDirs)

# options
option(BUILD_PROTO3 "BUILD_PROTO3" ON)
option(BUILD_PROTOC "Build protoc-gen-c" OFF)
if(CMAKE_BUILD_TYPE MATCHES Debug)
  option(BUILD_TESTS "Build tests" ON)
else()
  option(BUILD_TESTS "Build tests" OFF)
endif()

include(TestBigEndian)
test_big_endian(WORDS_BIGENDIAN)

set(PACKAGE_STRING "${PACKAGE_NAME} ${PACKAGE_VERSION}")
add_definitions(-DPACKAGE_VERSION="${PACKAGE_VERSION}")
add_definitions(-DPACKAGE_STRING="${PACKAGE_STRING}")
if(${WORDS_BIGENDIAN})
  add_definitions(-DWORDS_BIGENDIAN)
endif()

if(MSVC AND BUILD_SHARED_LIBS)
  add_definitions(-DPROTOBUF_C_USE_SHARED_LIB)
endif(MSVC AND BUILD_SHARED_LIBS)

if(MSVC)
  # using Visual Studio C++
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4267 /wd4244")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4267 /wd4244")
endif()

set(TEST_DIR ${MAIN_DIR}/t)

add_library(protobuf-c STATIC)
target_sources(protobuf-c
               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/protobuf-c/protobuf-c.c)
target_sources(protobuf-c
               PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/protobuf-c/protobuf-c.h)

if(MSVC)
  set_target_properties(protobuf-c PROPERTIES COMPILE_PDB_NAME protobuf-c)
  if(BUILD_SHARED_LIBS)
    target_compile_definitions(protobuf-c PRIVATE -DPROTOBUF_C_EXPORT)
  else()
    # In case we are building static libraries, link also the runtime library
    # statically so that MSVCR*.DLL is not required at runtime.
    # https://msdn.microsoft.com/en-us/library/2kzt1wy3.aspx This is achieved by
    # replacing msvc option /MD with /MT and /MDd with /MTd
    # http://www.cmake.org/Wiki/CMake_FAQ#How_can_I_build_my_MSVC_application_with_a_static_runtime.3F
    foreach(
      flag_var
      CMAKE_CXX_FLAGS
      CMAKE_CXX_FLAGS_DEBUG
      CMAKE_CXX_FLAGS_RELEASE
      CMAKE_CXX_FLAGS_MINSIZEREL
      CMAKE_CXX_FLAGS_RELWITHDEBINFO
      CMAKE_C_FLAGS
      CMAKE_C_FLAGS_DEBUG
      CMAKE_C_FLAGS_RELEASE
      CMAKE_C_FLAGS_MINSIZEREL
      CMAKE_FLAGS_RELWITHDEBINFO)
      if(${flag_var} MATCHES "/MD")
        string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
      endif(${flag_var} MATCHES "/MD")
    endforeach(flag_var)
  endif(BUILD_SHARED_LIBS)
endif(MSVC)

target_include_directories(
  protobuf-c
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  PRIVATE ${PROTOBUF_INCLUDE_DIR})

if(BUILD_PROTOC)
  include_directories(${CMAKE_BINARY_DIR}) # for generated files

  if(MSVC AND NOT BUILD_SHARED_LIBS)
    set(Protobuf_USE_STATIC_LIBS ON)
  endif(MSVC AND NOT BUILD_SHARED_LIBS)

  find_package(Protobuf REQUIRED)

  if(BUILD_PROTO3)
    add_definitions(-DHAVE_PROTO3)
  endif(BUILD_PROTO3)

  set(CMAKE_CXX_STANDARD 11)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
  set(CMAKE_CXX_EXTENSIONS OFF)
  add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/protobuf-c/protobuf-c.pb.cc
           ${CMAKE_CURRENT_BINARY_DIR}/protobuf-c/protobuf-c.pb.h
    COMMAND
      ${PROTOBUF_PROTOC_EXECUTABLE} ARGS --cpp_out ${CMAKE_CURRENT_BINARY_DIR}
      -I${CMAKE_CURRENT_SOURCE_DIR}
      ${CMAKE_CURRENT_SOURCE_DIR}/protobuf-c/protobuf-c.proto)
  file(GLOB PROTOC_GEN_C_SRC ${CMAKE_CURRENT_SOURCE_DIR}/protoc-c/*.h
       ${CMAKE_CURRENT_SOURCE_DIR}/protoc-c/*.cc)
  add_executable(protoc-gen-c ${PROTOC_GEN_C_SRC} protobuf-c/protobuf-c.pb.cc
                              protobuf-c/protobuf-c.pb.h)

  target_include_directories(
    protoc-gen-c
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    PRIVATE ${PROTOBUF_INCLUDE_DIR})

  target_link_libraries(protoc-gen-c ${PROTOBUF_PROTOC_LIBRARY}
                        ${PROTOBUF_LIBRARY})

  if(MSVC AND BUILD_SHARED_LIBS)
    target_compile_definitions(protoc-gen-c PRIVATE -DPROTOBUF_USE_DLLS)
    get_filename_component(PROTOBUF_DLL_DIR ${PROTOBUF_PROTOC_EXECUTABLE}
                           DIRECTORY)
    file(GLOB PROTOBUF_DLLS ${PROTOBUF_DLL_DIR}/*.dll)
    file(COPY ${PROTOBUF_DLLS} DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
  endif(MSVC AND BUILD_SHARED_LIBS)

  if(CMAKE_HOST_UNIX)
    add_custom_command(
      TARGET ${PROJECT_NAME}
      POST_BUILD
      COMMAND ln -sf protoc-gen-c protoc-c DEPENDS protoc-gen-c)
  endif(CMAKE_HOST_UNIX)

  function(GENERATE_TEST_SOURCES PROTO_FILE SRC HDR)
    add_custom_command(
      OUTPUT ${SRC} ${HDR}
      COMMAND
        ${PROTOBUF_PROTOC_EXECUTABLE} ARGS --plugin=$<TARGET_FILE:protoc-gen-c>
        -I${MAIN_DIR} ${PROTO_FILE} --c_out=${CMAKE_CURRENT_BINARY_DIR}
      DEPENDS protoc-gen-c)
  endfunction()

  if(BUILD_TESTS)
    enable_testing()

    generate_test_sources(${TEST_DIR}/test.proto t/test.pb-c.c t/test.pb-c.h)

    add_executable(
      test-generated-code ${TEST_DIR}/generated-code/test-generated-code.c
                          t/test.pb-c.c t/test.pb-c.h)
    target_link_libraries(test-generated-code protobuf-c)

    add_custom_command(
      OUTPUT t/test-full.pb.cc t/test-full.pb.h
      COMMAND ${PROTOBUF_PROTOC_EXECUTABLE} ARGS --cpp_out ${CMAKE_BINARY_DIR}
              -I${MAIN_DIR} ${TEST_DIR}/test-full.proto)

    generate_test_sources(${TEST_DIR}/test-full.proto t/test-full.pb-c.c
                          t/test-full.pb-c.h)

    add_executable(
      cxx-generate-packed-data
      ${TEST_DIR}/generated-code2/cxx-generate-packed-data.cc t/test-full.pb.h
      t/test-full.pb.cc protobuf-c/protobuf-c.pb.cc protobuf-c/protobuf-c.pb.h)
    target_link_libraries(cxx-generate-packed-data ${PROTOBUF_LIBRARY})
    if(MSVC AND BUILD_SHARED_LIBS)
      target_compile_definitions(cxx-generate-packed-data
                                 PRIVATE -DPROTOBUF_USE_DLLS)
    endif(MSVC AND BUILD_SHARED_LIBS)

    file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/t/generated-code2)
    add_custom_command(
      OUTPUT t/generated-code2/test-full-cxx-output.inc
      COMMAND ${CMAKE_BINARY_DIR}/cxx-generate-packed-data
              ">t/generated-code2/test-full-cxx-output.inc"
      DEPENDS cxx-generate-packed-data)

    generate_test_sources(${TEST_DIR}/test-optimized.proto
                          t/test-optimized.pb-c.c t/test-optimized.pb-c.h)

    add_executable(
      test-generated-code2
      ${TEST_DIR}/generated-code2/test-generated-code2.c
      t/generated-code2/test-full-cxx-output.inc t/test-full.pb-c.h
      t/test-full.pb-c.c t/test-optimized.pb-c.h t/test-optimized.pb-c.c)
    target_link_libraries(test-generated-code2 protobuf-c)

    generate_test_sources(${TEST_DIR}/issue220/issue220.proto
                          t/issue220/issue220.pb-c.c t/issue220/issue220.pb-c.h)
    add_executable(
      test-issue220 ${TEST_DIR}/issue220/issue220.c t/issue220/issue220.pb-c.c
                    t/issue220/issue220.pb-c.h)
    target_link_libraries(test-issue220 protobuf-c)

    generate_test_sources(${TEST_DIR}/issue251/issue251.proto
                          t/issue251/issue251.pb-c.c t/issue251/issue251.pb-c.h)
    add_executable(
      test-issue251 ${TEST_DIR}/issue251/issue251.c t/issue251/issue251.pb-c.c
                    t/issue251/issue251.pb-c.h)
    target_link_libraries(test-issue251 protobuf-c)

    add_executable(test-version ${TEST_DIR}/version/version.c)
    target_link_libraries(test-version protobuf-c)

    generate_test_sources(${TEST_DIR}/test-proto3.proto t/test-proto3.pb-c.c
                          t/test-proto3.pb-c.h)
    add_executable(
      test-generated-code3 ${TEST_DIR}/generated-code/test-generated-code.c
                           t/test-proto3.pb-c.c t/test-proto3.pb-c.h)
    target_compile_definitions(test-generated-code3 PUBLIC -DPROTO3)
    target_link_libraries(test-generated-code3 protobuf-c)

  endif() # BUILD_TESTS

  # https://github.com/protocolbuffers/protobuf/issues/5107
  if(CMAKE_HOST_UNIX)
    find_package(Threads REQUIRED)
    target_link_libraries(protoc-gen-c ${CMAKE_THREAD_LIBS_INIT})
    if(BUILD_TESTS)
      target_link_libraries(cxx-generate-packed-data ${CMAKE_THREAD_LIBS_INIT})
    endif(BUILD_TESTS)
  endif(CMAKE_HOST_UNIX)

  install(TARGETS protoc-gen-c RUNTIME DESTINATION bin)
endif(BUILD_PROTOC) # BUILD_PROTOC

install(
  TARGETS protobuf-c
  EXPORT protobuf-c-targets
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  INCLUDES
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/protobuf-c/protobuf-c.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/protobuf-c)

if(CMAKE_HOST_UNIX)
  install(
    CODE "EXECUTE_PROCESS (COMMAND ln -sf protoc-gen-c protoc-c WORKING_DIRECTORY ${CMAKE_INSTALL_PREFIX}/bin)"
  )
endif(CMAKE_HOST_UNIX)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/protobuf-c/libprotobuf-c.pc.in
               ${CMAKE_CURRENT_BINARY_DIR}/libprotobuf-c.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libprotobuf-c.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

if(BUILD_TESTS)
  include(Dart)

  set(DART_TESTING_TIMEOUT 5)
  add_test(test-generated-code test-generated-code)
  add_test(test-generated-code2 test-generated-code2)
  add_test(test-generated-code3 test-generated-code3)
  add_test(test-issue220 test-issue220)
  add_test(test-issue251 test-issue251)
  add_test(test-version test-version)
endif()

include(CPack)
