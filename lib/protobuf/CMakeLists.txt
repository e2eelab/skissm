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
    exports/c/skissm/service/e2ee_service.pb-c.c
    exports/c/skissm/service/dto/connect_request.pb-c.c
    exports/c/skissm/service/dto/event_data_request.pb-c.c
    exports/c/skissm/service/dto/login_request.pb-c.c
    exports/c/skissm/service/dto/logout_request.pb-c.c
    exports/c/skissm/service/dto/response_data.pb-c.c
    exports/c/skissm/add_group_members_request_payload.pb-c.c
    exports/c/skissm/chain_key.pb-c.c
    exports/c/skissm/create_group_request_payload.pb-c.c
    exports/c/skissm/create_group_response_payload.pb-c.c
    exports/c/skissm/delete_user_request_payload.pb-c.c
    exports/c/skissm/e2ee_account.pb-c.c
    exports/c/skissm/e2ee_address.pb-c.c
    exports/c/skissm/e2ee_commands.pb-c.c
    exports/c/skissm/e2ee_group_msg_payload.pb-c.c
    exports/c/skissm/e2ee_group_pre_key_payload.pb-c.c
    exports/c/skissm/e2ee_group_session.pb-c.c
    exports/c/skissm/e2ee_message.pb-c.c
    exports/c/skissm/e2ee_message_type.pb-c.c
    exports/c/skissm/e2ee_msg_payload.pb-c.c
    exports/c/skissm/e2ee_plaintext.pb-c.c
    exports/c/skissm/e2ee_plaintext_type.pb-c.c
    exports/c/skissm/e2ee_pre_key_bundle.pb-c.c
    exports/c/skissm/e2ee_pre_key_payload.pb-c.c
    exports/c/skissm/e2ee_protocol_msg.pb-c.c
    exports/c/skissm/e2ee_ratchet.pb-c.c
    exports/c/skissm/e2ee_session.pb-c.c
    exports/c/skissm/get_group_request_payload.pb-c.c
    exports/c/skissm/get_group_response_payload.pb-c.c
    exports/c/skissm/get_pre_key_bundle_request_payload.pb-c.c
    exports/c/skissm/get_pre_key_bundle_response_payload.pb-c.c
    exports/c/skissm/key_pair.pb-c.c
    exports/c/skissm/message_key.pb-c.c
    exports/c/skissm/one_time_pre_key_pair.pb-c.c
    exports/c/skissm/one_time_pre_key_public.pb-c.c
    exports/c/skissm/publish_spk_request_payload.pb-c.c
    exports/c/skissm/receiver_chain_node.pb-c.c
    exports/c/skissm/register_user_request_payload.pb-c.c
    exports/c/skissm/register_user_response_payload.pb-c.c
    exports/c/skissm/remove_group_members_request_payload.pb-c.c
    exports/c/skissm/sender_chain_node.pb-c.c
    exports/c/skissm/signed_pre_key_pair.pb-c.c
    exports/c/skissm/signed_pre_key_public.pb-c.c
    exports/c/skissm/skipped_message_key_node.pb-c.c
    exports/c/skissm/supply_opks_request_payload.pb-c.c
    exports/c/skissm/supply_opks_response_payload.pb-c.c
)

# Add -fPIC flag
if(BUILD_SHARED_LIBS)
    add_library(protobuf OBJECT ${protobuf_SRCS})
    set_property(TARGET protobuf PROPERTY POSITION_INDEPENDENT_CODE ON)
else()
    add_library(protobuf STATIC ${protobuf_SRCS})
    set_property(TARGET protobuf PROPERTY POSITION_INDEPENDENT_CODE OFF)
endif()
