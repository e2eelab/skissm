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
enable_testing()

set(sqlite3_DIR "${lib_DIR}/sqlite3")

if(NOT sqlite3)
  add_subdirectory(${sqlite3_DIR} "${CMAKE_CURRENT_BINARY_DIR}/lib/sqlite3")
endif()

add_library(db STATIC
    test_db.c)

target_include_directories(db
    PRIVATE
        ${sqlite3_DIR}
        $<BUILD_INTERFACE:${protobuf-c_DIR}>
        $<BUILD_INTERFACE:${PROTO_DIS_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>)

add_library(test_env STATIC
    test_server.c
    test_plugin.c
    test_db.c
    test_util.c)

target_include_directories(test_env
    PRIVATE
        ${sqlite3_DIR}
        $<BUILD_INTERFACE:${protobuf-c_DIR}>
        $<BUILD_INTERFACE:${PROTO_DIS_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>)

add_library(test_util STATIC
    test_util.c)

target_include_directories(test_util
    PRIVATE
        $<BUILD_INTERFACE:${protobuf-c_DIR}>
        $<BUILD_INTERFACE:${PROTO_DIS_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>)

set(TEST_SKISSM
    test_aes
    test_gcm
    test_sha
    test_account
    # test_ratchet
    # test_session
    # test_group_session
    # test_account_db
    # test_session_db
    # test_group_pre_key
    # test_unload
    # test_spk_db
    # test_opk_db
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
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
        ${sqlite3_DIR}
        $<BUILD_INTERFACE:${protobuf-c_DIR}>
        $<BUILD_INTERFACE:${PROTO_DIS_DIR}>
        ${mbedtls_DIR})
  if(CMAKE_SYSTEM_NAME MATCHES iOS)
    target_link_libraries(${test} db test_util test_env sqlite3 skissm_static)
  else()
    target_link_libraries(${test} db test_util test_env sqlite3 skissm_static ${CMAKE_DL_LIBS})
  endif()
endforeach(test)

file(COPY data DESTINATION .)

add_test(AES test_aes)
add_test(GCM test_gcm)
add_test(SHA test_sha)
add_test(Account test_account)
# add_test(Ratchet test_ratchet)
# add_test(Session test_session)
# add_test(GroupSession test_group_session)
# add_test(Account_db test_account_db)
# add_test(Session_db test_session_db)
# add_test(Group_pre_key test_group_pre_key)
# add_test(Unload test_unload)
# add_test(SPK_db test_spk_db)
# add_test(OPK_db test_opk_db)
