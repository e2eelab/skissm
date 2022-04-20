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
#include "skissm/e2ee_protocol.h"
#include "skissm/error.h"
#include "skissm/group_session.h"
#include "skissm/mem_util.h"
#include "skissm/ratchet.h"

/** length of the shared secret created by a Curve25519 ECDH operation */
#define CURVE25519_SHARED_SECRET_LENGTH 32

void initialise_session(Skissm__Session *session, uint32_t e2ee_pack_id, Skissm__E2eeAddress *from, Skissm__E2eeAddress *to) {
    skissm__session__init(session);
    session->e2ee_pack_id = e2ee_pack_id;
    copy_address_from_address(&(session->from), from);
    copy_address_from_address(&(session->to), to);
    initialise_ratchet(&(session->ratchet));
}

void close_session(Skissm__Session *session) {
    if (session != NULL) {
        skissm__session__free_unpacked(session, NULL);
        session = NULL;
    }
}

void pack_e2ee_plaintext(const uint8_t *plaintext_data, size_t plaintext_data_len, Skissm__PlaintextType plaintext_type, uint8_t **e2ee_plaintext_data, size_t *e2ee_plaintext_data_len) {
    Skissm__Plaintext *ssm_e2ee_plaintext = (Skissm__Plaintext *)malloc(sizeof(Skissm__Plaintext));
    skissm__plaintext__init(ssm_e2ee_plaintext);
    ssm_e2ee_plaintext->version = PLAINTEXT_VERSION;
    ssm_e2ee_plaintext->type = plaintext_type;
    ssm_e2ee_plaintext->payload.len = plaintext_data_len;
    ssm_e2ee_plaintext->payload.data = (uint8_t *)malloc(sizeof(uint8_t) * plaintext_data_len);
    memcpy(ssm_e2ee_plaintext->payload.data, plaintext_data, plaintext_data_len);

    size_t len = skissm__plaintext__get_packed_size(ssm_e2ee_plaintext);
    *e2ee_plaintext_data_len = len;
    *e2ee_plaintext_data = (uint8_t *)malloc(sizeof(uint8_t) * len);
    skissm__plaintext__pack(ssm_e2ee_plaintext, *e2ee_plaintext_data);

    // release
    skissm__plaintext__free_unpacked(ssm_e2ee_plaintext, NULL);
}
