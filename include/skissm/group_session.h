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
 * @brief Create an outbound group session.
 *
 * @param e2ee_pack_id
 * @param user_address
 * @param group_address
 * @param group_members
 * @param group_members_num
 * @param old_session_id
 * @param old_session_id_num
 */
void create_outbound_group_session(
    const char *e2ee_pack_id,
    Skissm__E2eeAddress *user_address,
    Skissm__E2eeAddress *group_address,
    Skissm__GroupMember **group_members,
    size_t group_members_num,
    char **old_session_id,
    size_t old_session_id_num
);

/**
 * @brief Create an inbound group session.
 *
 * @param e2ee_pack_id
 * @param group_pre_key_bundle
 * @param user_address
 */
void create_inbound_group_session(
    const char *e2ee_pack_id,
    Skissm__GroupPreKeyBundle *group_pre_key_bundle,
    Skissm__E2eeAddress *user_address
);

/**
 * @brief Advance the chain key of group session.
 *
 * @param cipher_suite
 * @param chain_key
 * @param iteration
 */
void advance_group_chain_key(const cipher_suite_t *cipher_suite, ProtobufCBinaryData *chain_key, uint32_t iteration);


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
 * @brief Encrypt a group message with engaged group session.
 *
 * @param user_address
 * @param group_address
 * @param plaintext
 * @param plaintext_len
 */
void encrypt_group_session(
    Skissm__E2eeAddress *user_address,
    Skissm__E2eeAddress *group_address,
    const uint8_t *plaintext, size_t plaintext_len
);

#ifdef __cplusplus
}
#endif

#endif /* GROUP_SESSION_H_ */
