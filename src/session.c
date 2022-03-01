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

const struct session_cipher SESSION_CIPHER = SESSION_CIPHER_INIT;

/** length of the shared secret created by a Curve25519 ECDH operation */
#define CURVE25519_SHARED_SECRET_LENGTH 32

/** length of the shared secret created by a PQC operation */
#define CRYPTO_BYTES_KEY 32

/** length of the ciphertext created by a PQC operation */
#define CRYPTO_CIPHERTEXTBYTES 1039

void initialise_session(Skissm__E2eeSession *session, Skissm__E2eeAddress *from, Skissm__E2eeAddress *to) {
    skissm__e2ee_session__init(session);
    copy_address_from_address(&(session->from), from);
    copy_address_from_address(&(session->to), to);
    initialise_ratchet(&(session->ratchet));
}

void close_session(Skissm__E2eeSession *session) {
    if (session != NULL) {
        skissm__e2ee_session__free_unpacked(session, NULL);
        session = NULL;
    }
}

void pack_e2ee_plaintext(const uint8_t *plaintext, size_t plaintext_len, Skissm__E2eePlaintextType plaintext_type, uint8_t **e2ee_plaintext, size_t *e2ee_plaintext_len) {
    Skissm__E2eePlaintext *ssm_e2ee_plaintext = (Skissm__E2eePlaintext *)malloc(sizeof(Skissm__E2eePlaintext));
    skissm__e2ee_plaintext__init(ssm_e2ee_plaintext);
    ssm_e2ee_plaintext->version = PLAINTEXT_VERSION;
    ssm_e2ee_plaintext->plaintext_type = plaintext_type;
    ssm_e2ee_plaintext->payload.len = plaintext_len;
    ssm_e2ee_plaintext->payload.data = (uint8_t *)malloc(sizeof(uint8_t) * plaintext_len);
    memcpy(ssm_e2ee_plaintext->payload.data, plaintext, plaintext_len);

    size_t len = skissm__e2ee_plaintext__get_packed_size(ssm_e2ee_plaintext);
    *e2ee_plaintext_len = len;
    *e2ee_plaintext = (uint8_t *)malloc(sizeof(uint8_t) * len);
    skissm__e2ee_plaintext__pack(ssm_e2ee_plaintext, *e2ee_plaintext);

    // release
    skissm__e2ee_plaintext__free_unpacked(ssm_e2ee_plaintext, NULL);
}

const session_suite *get_session_suite(uint32_t cipher_suite_id) {
    // cipher_suite_id = 0 for testing
    if (cipher_suite_id == 1 || cipher_suite_id == 0){
        return SESSION_CIPHER.suite1;
    } else if (cipher_suite_id == 2){
        return SESSION_CIPHER.suite2;
    } else{
        return NULL;
    }
}
