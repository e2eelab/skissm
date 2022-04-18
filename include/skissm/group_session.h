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
 * @param member_addresses
 * @param member_num
 * @param old_session_id
 */
void create_outbound_group_session(
    uint32_t e2ee_pack_id,
    Skissm__E2eeAddress *user_address,
    Skissm__E2eeAddress *group_address,
    Skissm__E2eeAddress **member_addresses,
    size_t member_num,
    char *old_session_id
);

/**
 * @brief Create an inbound group session.
 *
 * @param e2ee_pack_id
 * @param group_pre_key_payload
 * @param user_address
 */
void create_inbound_group_session(
    uint32_t e2ee_pack_id,
    Skissm__E2eeGroupPreKeyPayload *group_pre_key_payload,
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
 * @brief Create group message keys.
 *
 * @param cipher_suite
 * @param chain_key
 * @param message_key
 */
void create_group_message_keys(
    const cipher_suite_t *cipher_suite,
    const ProtobufCBinaryData *chain_key,
    Skissm__MessageKey *message_key
);

/**
 * @brief Pack group pre-keys.
 *
 * @param outbound_group_session
 * @param group_pre_key_plaintext
 * @param old_session_id
 */
size_t pack_group_pre_key_plaintext(
    Skissm__E2eeGroupSession *outbound_group_session,
    uint8_t **group_pre_key_plaintext,
    char *old_session_id
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

/**
 * @brief Close a group session.
 *
 * @param group_session
 */
void close_group_session(Skissm__E2eeGroupSession *group_session);

#ifdef __cplusplus
}
#endif

#endif /* GROUP_SESSION_H_ */
