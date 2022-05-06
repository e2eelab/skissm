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
#include "skissm/error.h"
#include "skissm/group_session.h"
#include "skissm/mem_util.h"
#include "skissm/ratchet.h"

/** length of the shared secret created by a Curve25519 ECDH operation */
#define CURVE25519_SHARED_SECRET_LENGTH 32

void initialise_session(Skissm__Session *session, const char *e2ee_pack_id, Skissm__E2eeAddress *from, Skissm__E2eeAddress *to) {
    skissm__session__init(session);
    session->e2ee_pack_id = strdup(e2ee_pack_id);
    copy_address_from_address(&(session->from), from);
    copy_address_from_address(&(session->to), to);
    initialise_ratchet(&(session->ratchet));
}

void pack_common_plaintext(const uint8_t *plaintext_data, size_t plaintext_data_len, uint8_t **common_plaintext_data, size_t *common_plaintext_data_len) {
    Skissm__Plaintext *plaintext = (Skissm__Plaintext *)malloc(sizeof(Skissm__Plaintext));
    skissm__plaintext__init(plaintext);
    plaintext->version = strdup(E2EE_PLAINTEXT_VERSION);
    plaintext->payload_case = SKISSM__PLAINTEXT__PAYLOAD_COMMON_MSG;
    plaintext->common_msg.len = plaintext_data_len;
    plaintext->common_msg.data = (uint8_t *)malloc(sizeof(uint8_t) * plaintext_data_len);
    memcpy(plaintext->common_msg.data, plaintext_data, plaintext_data_len);

    size_t len = skissm__plaintext__get_packed_size(plaintext);
    *common_plaintext_data_len = len;
    *common_plaintext_data = (uint8_t *)malloc(sizeof(uint8_t) * len);
    skissm__plaintext__pack(plaintext, *common_plaintext_data);

    // release
    skissm__plaintext__free_unpacked(plaintext, NULL);
}

Skissm__Session *get_outbound_session(Skissm__E2eeAddress *from, Skissm__E2eeAddress *to) {
    Skissm__Session *outbound_session = NULL;
    get_skissm_plugin()->db_handler.load_outbound_session(from, to, &outbound_session);
    if (outbound_session == NULL) {
        return NULL;
    } else {
        if (outbound_session->responded)
            return outbound_session;
        else {
            // outbound_session can't be used if is is not responded
            skissm__session__free_unpacked(outbound_session, NULL);
            return NULL;
        }
    }
}