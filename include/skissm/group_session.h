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

#include "skissm.h"

/**
 * @brief Create an outbound group session
 *
 * @param user_address
 * @param group_address
 * @param member_addresses
 * @param member_num
 * @param old_session_id
 */
void create_outbound_group_session(
    Org__E2eelab__Skissm__Proto__E2eeAddress *user_address,
    Org__E2eelab__Skissm__Proto__E2eeAddress *group_address,
    Org__E2eelab__Skissm__Proto__E2eeAddress **member_addresses,
    size_t member_num,
    ProtobufCBinaryData *old_session_id
);

/**
 * @brief Create an inbound group session object
 * 
 * @param group_pre_key_payload
 * @param user_address
 */
void create_inbound_group_session(
    Org__E2eelab__Skissm__Proto__E2eeGroupPreKeyPayload *group_pre_key_payload,
    Org__E2eelab__Skissm__Proto__E2eeAddress *user_address
);

/**
 * @brief  Encrypt group message
 *
 * @param user_address
 * @param group_address
 * @param plaintext
 * @param plaintext_len
 */
void encrypt_group_session(
    Org__E2eelab__Skissm__Proto__E2eeAddress *user_address,
    Org__E2eelab__Skissm__Proto__E2eeAddress *group_address,
    const uint8_t *plaintext, size_t plaintext_len
);


/**
 * @brief Decrypt group message
 *
 * @param user_address
 * @param group_msg
 */
void decrypt_group_session(
    Org__E2eelab__Skissm__Proto__E2eeAddress *user_address,
    Org__E2eelab__Skissm__Proto__E2eeMessage *group_msg
);

#endif /* GROUP_SESSION_H_ */
