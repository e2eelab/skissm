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
#include "skissm/session.h"

#include <stdio.h>
#include <string.h>

#include "skissm/account.h"
#include "skissm/cipher.h"
#include "skissm/e2ee_client.h"
#include "skissm/group_session.h"
#include "skissm/mem_util.h"
#include "skissm/ratchet.h"

/** length of the shared secret created by a Curve25519 ECDH operation */
#define CURVE25519_SHARED_SECRET_LENGTH 32

void initialise_session(
    Skissm__Session *session, uint32_t e2ee_pack_id,
    Skissm__E2eeAddress *our_address, Skissm__E2eeAddress *their_address
) {
    skissm__session__init(session);
    session->e2ee_pack_id = e2ee_pack_id;
    copy_address_from_address(&(session->our_address), our_address);
    copy_address_from_address(&(session->their_address), their_address);
}

void pack_common_plaintext(
    const uint8_t *plaintext_data, size_t plaintext_data_len,
    int plaintext_type,
    uint8_t **common_plaintext_data, size_t *common_plaintext_data_len
) {
    Skissm__Plaintext *plaintext = (Skissm__Plaintext *)malloc(sizeof(Skissm__Plaintext));
    skissm__plaintext__init(plaintext);
    plaintext->version = strdup(E2EE_PLAINTEXT_VERSION);
    plaintext->payload_case = plaintext_type;
    switch(plaintext_type) {
        case SKISSM__PLAINTEXT__PAYLOAD_COMMON_MSG:
            plaintext->common_msg.len = plaintext_data_len;
            plaintext->common_msg.data = (uint8_t *)malloc(sizeof(uint8_t) * plaintext_data_len);
            memcpy(plaintext->common_msg.data, plaintext_data, plaintext_data_len);
            break;
        case SKISSM__PLAINTEXT__PAYLOAD_COMMON_SYNC_MSG:
            plaintext->common_sync_msg.len = plaintext_data_len;
            plaintext->common_sync_msg.data = (uint8_t *)malloc(sizeof(uint8_t) * plaintext_data_len);
            memcpy(plaintext->common_sync_msg.data, plaintext_data, plaintext_data_len);
            break;
        default:
            // error
            break;
    };

    size_t len = skissm__plaintext__get_packed_size(plaintext);
    *common_plaintext_data_len = len;
    *common_plaintext_data = (uint8_t *)malloc(sizeof(uint8_t) * len);
    skissm__plaintext__pack(plaintext, *common_plaintext_data);

    // release
    skissm__plaintext__free_unpacked(plaintext, NULL);
}
