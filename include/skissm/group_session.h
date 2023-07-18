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
 * @brief Create an outbound group session.
 *
 * @param sender
 * @param seed_secret
 * @param n_member_ids
 * @param member_ids
 * @param e2ee_pack_id
 * @param user_address
 * @param group_name,
 * @param group_address
 * @param group_members
 * @param group_members_num
 * @param old_session_id
 */
void new_outbound_group_session(
    bool sender,
    const ProtobufCBinaryData *seed_secret,
    size_t n_member_ids,
    Skissm__GroupMemberID **member_ids,
    const char *e2ee_pack_id,
    Skissm__E2eeAddress *user_address,
    const char *group_name,
    Skissm__E2eeAddress *group_address,
    Skissm__GroupMember **group_members,
    size_t group_members_num,
    char *old_session_id
);

/**
 * @brief Create an inbound group session.
 *
 * @param e2ee_pack_id
 * @param user_address
 * @param group_pre_key_bundle
 * @param group_member_id
 * @param group_info
 */
void new_inbound_group_session(
    const char *e2ee_pack_id,
    Skissm__E2eeAddress *user_address,
    Skissm__GroupPreKeyBundle *group_pre_key_bundle,
    Skissm__GroupMemberID *group_member_id,
    Skissm__GroupInfo *group_info
);

void complete_inbound_group_session(
    Skissm__GroupSession *inbound_group_session,
    Skissm__GroupPreKeyBundle *group_pre_key_bundle,
    Skissm__GroupMemberID *group_member_id,
    Skissm__E2eeAddress *group_address
);

void new_and_complete_inbound_group_session(
    Skissm__GroupMemberID *group_member_id,
    Skissm__GroupSession *other_inbound_group_session
);

#ifdef __cplusplus
}
#endif

#endif /* GROUP_SESSION_H_ */
