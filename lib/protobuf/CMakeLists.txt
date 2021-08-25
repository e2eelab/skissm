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
    exports/c/add_group_members_request_payload.pb-c.c
    exports/c/add_group_members_response_payload.pb-c.c
    exports/c/chain_key.pb-c.c
    exports/c/create_group_request_payload.pb-c.c
    exports/c/create_group_response_payload.pb-c.c
    exports/c/delete_user_request_payload.pb-c.c
    exports/c/delete_user_response_payload.pb-c.c
    exports/c/e2ee_account.pb-c.c
    exports/c/e2ee_address.pb-c.c
    exports/c/e2ee_commands.pb-c.c
    exports/c/e2ee_group_msg_payload.pb-c.c
    exports/c/e2ee_group_msg_response_payload.pb-c.c
    exports/c/e2ee_group_pre_key_payload.pb-c.c
    exports/c/e2ee_group_session.pb-c.c
    exports/c/e2ee_message.pb-c.c
    exports/c/e2ee_message_type.pb-c.c
    exports/c/e2ee_msg_payload.pb-c.c
    exports/c/e2ee_msg_response_payload.pb-c.c
    exports/c/e2ee_plaintext.pb-c.c
    exports/c/e2ee_plaintext_type.pb-c.c
    exports/c/e2ee_pre_key_bundle.pb-c.c
    exports/c/e2ee_pre_key_payload.pb-c.c
    exports/c/e2ee_protocol_msg.pb-c.c
    exports/c/e2ee_ratchet.pb-c.c
    exports/c/e2ee_session.pb-c.c
    exports/c/get_group_request_payload.pb-c.c
    exports/c/get_group_response_payload.pb-c.c
    exports/c/get_pre_key_bundle_request_payload.pb-c.c
    exports/c/get_pre_key_bundle_response_payload.pb-c.c
    exports/c/key_pair.pb-c.c
    exports/c/message_key.pb-c.c
    exports/c/one_time_pre_key_pair.pb-c.c
    exports/c/one_time_pre_key_public.pb-c.c
    exports/c/publish_spk_request_payload.pb-c.c
    exports/c/publish_spk_response_payload.pb-c.c
    exports/c/receiver_chain_node.pb-c.c
    exports/c/register_user_request_payload.pb-c.c
    exports/c/register_user_response_payload.pb-c.c
    exports/c/remove_group_members_request_payload.pb-c.c
    exports/c/remove_group_members_response_payload.pb-c.c
    exports/c/sender_chain_node.pb-c.c
    exports/c/signed_pre_key_pair.pb-c.c
    exports/c/signed_pre_key_public.pb-c.c
    exports/c/skipped_message_key_node.pb-c.c
    exports/c/supply_opks_request_payload.pb-c.c
    exports/c/supply_opks_response_payload.pb-c.c
)

# Add -fPIC flag
if(BUILD_SHARED_LIBS)
    add_library(protobuf OBJECT ${protobuf_SRCS})
    set_property(TARGET protobuf PROPERTY POSITION_INDEPENDENT_CODE ON)
else()
    add_library(protobuf STATIC ${protobuf_SRCS})
    set_property(TARGET protobuf PROPERTY POSITION_INDEPENDENT_CODE OFF)
endif()
