/*
 * Copyright © 2020-2021 by Academia Sinica
 *
 * This file is part of SKISSM.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * SKISSM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with SKISSM.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef GROUP_SESSION_H_
#define GROUP_SESSION_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "skissm/skissm.h"

/**
 * @brief Advance the chain key of group session.
 *
 * @param cipher_suite
 * @param chain_key
 */
void advance_group_chain_key(
    const cipher_suite_t *cipher_suite,
    ProtobufCBinaryData *chain_key
);

/**
 * @brief Create group message key.
 *
 * @param cipher_suite
 * @param chain_key
 * @param message_key
 */
void create_group_message_key(
    const cipher_suite_t *cipher_suite,
    const ProtobufCBinaryData *chain_key,
    Skissm__MsgKey *message_key
);

/**
 * @brief Pack the group pre-keys.
 *
 * @param outbound_group_session
 * @param group_pre_key_plaintext_data
 * @param old_session_id
 */
size_t pack_group_pre_key_plaintext(
    Skissm__GroupSession *outbound_group_session,
    uint8_t **group_pre_key_plaintext_data,
    char *old_session_id
);

/**
 * @brief Create an outbound group session by a group creator.
 *
 * @param n_member_info_list
 * @param member_info_list
 * @param e2ee_pack_id
 * @param user_address
 * @param group_name
 * @param group_address
 * @param group_members
 * @param group_members_num
 * @param old_session_id
 */
void new_outbound_group_session_by_sender(
    size_t n_member_info_list,
    Skissm__GroupMemberInfo **member_info_list,
    const char *e2ee_pack_id,
    Skissm__E2eeAddress *user_address,
    const char *group_name,
    Skissm__E2eeAddress *group_address,
    Skissm__GroupMember **group_members,
    size_t group_members_num,
    char *old_session_id
);

/**
 * @brief Create an outbound group session by a group receiver.
 *
 * @param group_seed
 * @param e2ee_pack_id
 * @param user_address
 * @param group_name
 * @param group_address
 * @param session_id
 * @param group_members
 * @param group_members_num
 */
void new_outbound_group_session_by_receiver(
    const ProtobufCBinaryData *group_seed,
    const char *e2ee_pack_id,
    Skissm__E2eeAddress *user_address,
    const char *group_name,
    Skissm__E2eeAddress *group_address,
    const char *session_id,
    Skissm__GroupMember **group_members,
    size_t group_members_num
);

/**
 * @brief Create an outbound group session when receiving other group member's invitation.
 *
 * @param group_update_key_bundle
 * @param user_address
 */
void new_outbound_group_session_invited(
    Skissm__GroupUpdateKeyBundle *group_update_key_bundle,
    Skissm__E2eeAddress *user_address
);

/**
 * @brief Create an inbound group session with group pre-key bundle.
 *
 * @param e2ee_pack_id
 * @param user_address
 * @param group_pre_key_bundle
 */
void new_inbound_group_session_by_pre_key_bundle(
    const char *e2ee_pack_id,
    Skissm__E2eeAddress *user_address,
    Skissm__GroupPreKeyBundle *group_pre_key_bundle
);

/**
 * @brief Create an inbound group session with other member's id.
 *
 * @param e2ee_pack_id
 * @param user_address
 * @param group_member_id
 * @param group_info
 */
void new_inbound_group_session_by_member_id(
    const char *e2ee_pack_id,
    Skissm__E2eeAddress *user_address,
    Skissm__GroupMemberInfo *group_member_id,
    Skissm__GroupInfo *group_info
);

/**
 * @brief Complete an inbound group session with group pre-key bundle.
 *
 * @param inbound_group_session
 * @param group_pre_key_bundle
 */
void complete_inbound_group_session_by_pre_key_bundle(
    Skissm__GroupSession *inbound_group_session,
    Skissm__GroupPreKeyBundle *group_pre_key_bundle
);

/**
 * @brief Complete an inbound group session with other member's id.
 *
 * @param inbound_group_session
 * @param group_member_id
 * @param group_info
 */
void complete_inbound_group_session_by_member_id(
    Skissm__GroupSession *inbound_group_session,
    Skissm__GroupMemberInfo *group_member_id,
    Skissm__E2eeAddress *group_address
);

/**
 * @brief Create and complete an inbound group session.
 *
 * @param group_member_id
 * @param other_inbound_group_session
 */
void new_and_complete_inbound_group_session(
    Skissm__GroupMemberInfo *group_member_id,
    Skissm__GroupSession *other_inbound_group_session
);

/**
 * @brief Create and complete an inbound group session with other's chain key.
 *
 * @param group_member_id
 * @param other_group_session
 * @param their_chain_key
 */
void new_and_complete_inbound_group_session_with_chain_key(
    Skissm__GroupMemberInfo *group_member_id,
    Skissm__GroupSession *other_group_session,
    ProtobufCBinaryData *their_chain_key
);

/**
 * @brief Create and complete an inbound group session with other's ratchet state.
 *
 * @param group_update_key_bundle
 * @param user_address
 */
void new_and_complete_inbound_group_session_with_ratchet_state(
    Skissm__GroupUpdateKeyBundle *group_update_key_bundle,
    Skissm__E2eeAddress *user_address
);

/**
 * @brief Renew the outbound group session when someone joins the group.
 *
 * @param outbound_group_session
 * @param sender_chain_key
 * @param sender_address
 * @param n_adding_member_info_list
 * @param adding_member_info_list
 * @param adding_group_members_num
 * @param adding_group_members
 */
void renew_outbound_group_session_by_welcome_and_add(
    Skissm__GroupSession *outbound_group_session,
    ProtobufCBinaryData *sender_chain_key,
    Skissm__E2eeAddress *sender_address,
    size_t n_adding_member_info_list,
    Skissm__GroupMemberInfo **adding_member_info_list,
    size_t adding_group_members_num,
    Skissm__GroupMember **adding_group_members
);

/**
 * @brief Renew the inbound group session when someone joins the group.
 *
 * @param sender_chain_key
 * @param inbound_group_session
 * @param new_group_info
 */
void renew_inbound_group_session_by_welcome_and_add(
    ProtobufCBinaryData *sender_chain_key,
    Skissm__GroupSession *inbound_group_session,
    Skissm__GroupInfo *new_group_info
);

void renew_group_sessions_with_new_device(
    Skissm__GroupSession *outbound_group_session,
    ProtobufCBinaryData *sender_chain_key,
    Skissm__E2eeAddress *sender_address,
    Skissm__E2eeAddress *new_device_address,
    Skissm__GroupMemberInfo *adding_member_device_info
);

#ifdef __cplusplus
}
#endif

#endif /* GROUP_SESSION_H_ */
