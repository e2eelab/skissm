enable_testing()

set(websocketpp_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib/websocketpp")
set(asio_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib/asio")
set(sqlite3_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib/sqlite3")

add_subdirectory(lib)

add_library(db STATIC
    db.c)

target_include_directories(db
    PRIVATE
        ${sqlite3_DIR}
        ${protobuf_DIR}
        ${protobuf_DIR}/lib
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include/skissm>)

add_library(test_env STATIC
    e2ee_protocol_simulator.c
    test_env.c)

target_include_directories(test_env
    PRIVATE
        ${sqlite3_DIR}
        ${protobuf_DIR}
        ${protobuf_DIR}/lib
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include/skissm>)

add_library(test_util STATIC 
    test_util.c)

target_include_directories(test_util
    PRIVATE
        ${protobuf_DIR}
        ${protobuf_DIR}/lib
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include/skissm>)

set(TEST_SKISSM
    test_account
    test_ratchet
    test_session
    test_group_session
    # test_gcm
    test_account_db
    test_session_db
  )

set(TEST_WS
    test_utf8
    # test_utf8_crypto
)

if(NOT (${CMAKE_SYSTEM_NAME} MATCHES "Windows" AND BUILD_SHARED_LIBS))
  # test_ratchet doesn't work on Windows when building a DLL, because it tries
  # to use internal symbols, so only enable it if we're not on Windows, or if
  # we're building statically

  # set(TEST_SKISSM ${TEST_SKISSM} test_ratchet)
  # add_test(Ratchet test_ratchet)
endif()

foreach(test IN ITEMS ${TEST_SKISSM})
  add_executable(${test} ${test}.c)
  target_include_directories(${test}
      PRIVATE
          $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include/skissm>
          ${sqlite3_DIR}
          ${protobuf_DIR}
          ${protobuf_DIR}/lib
          ${mbedtls_DIR})
  target_link_libraries(${test} db test_util test_env sqlite3 skissm)
endforeach(test)

foreach(test IN ITEMS ${TEST_WS})
  add_executable(${test} ${test}.cpp)
  target_include_directories(${test}
      PRIVATE
          $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include/skissm>
          ${sqlite3_DIR}
          ${protobuf_DIR}
          ${protobuf_DIR}/lib
          ${mbedtls_DIR}
          ${websocketpp_DIR}
          ${asio_DIR})
  target_link_libraries(${test} db test_util test_env sqlite3 skissm)
endforeach(test)

file(COPY data DESTINATION .)

add_test(Account test_account)
add_test(Ratchet test_ratchet)
add_test(Session test_session)
add_test(GroupSession test_group_session)
add_test(Account_db test_account_db)
add_test(Session_db test_session_db)
# add_test(GCM test_gcm)
# add_test(UTF8 test_utf8 9000)
# add_test(UTF8_crypto test_utf8_crypto 9001)