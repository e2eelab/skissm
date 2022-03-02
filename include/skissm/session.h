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
#ifndef SESSION_H_
#define SESSION_H_

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "skissm/skissm.h"

typedef struct session_suite{
    /**
     * @brief Create a new outbound session.
     *
     * @param session The outbound session
     * @param local_account Our account
     * @param their_pre_key_bundle Their pre-key bundle
     * @return Success or not
     */
    size_t (*new_outbound_session)(
        Skissm__E2eeSession *session,
        const Skissm__E2eeAccount *local_account,
        Skissm__E2eePreKeyBundle *their_pre_key_bundle
    );

    /**
     * @brief Create a new inbound session.
     *
     * @param session The inbound session
     * @param local_account Our account
     * @param inbound_message The inbound message
     * @return Success or not
     */
    size_t (*new_inbound_session)(
        Skissm__E2eeSession *session,
        Skissm__E2eeAccount *local_account,
        Skissm__E2eeMessage *inbound_message
    );
} session_suite;

struct session_cipher {
    const struct session_suite *suite1;
    const struct session_suite *suite2;
};

extern const struct session_suite ECDH_X25519_AES256_GCM_SHA256;

extern const struct session_suite PQC_AES256_GCM_SHA256;

#define SESSION_CIPHER_INIT                                                            \
    { &ECDH_X25519_AES256_GCM_SHA256, &PQC_AES256_GCM_SHA256 }

extern const struct session_cipher SESSION_CIPHER;

/* common */
void initialise_session(
    Skissm__E2eeSession *session,
    Skissm__E2eeAddress *from,
    Skissm__E2eeAddress *to
);

void pack_e2ee_plaintext(
    const uint8_t *plaintext, size_t plaintext_len,
    Skissm__E2eePlaintextType plaintext_type,
    uint8_t **context, size_t *context_len
);

const session_suite *get_session_suite(uint32_t cipher_suite_id);

/* ECC-related */
size_t crypto_curve25519_new_outbound_session(
    Skissm__E2eeSession *session,
    const Skissm__E2eeAccount *local_account,
    Skissm__E2eePreKeyBundle *their_pre_key_bundle
);

size_t crypto_curve25519_new_inbound_session(
    Skissm__E2eeSession *session,
    Skissm__E2eeAccount *local_account,
    Skissm__E2eeMessage *inbound_prekey_message
);

/* PQC-related */
size_t pqc_new_outbound_session(
    Skissm__E2eeSession *session,
    const Skissm__E2eeAccount *local_account,
    Skissm__E2eePreKeyBundle *their_pre_key_bundle
);

size_t pqc_new_inbound_session(
    Skissm__E2eeSession *session,
    Skissm__E2eeAccount *local_account,
    Skissm__E2eeMessage *inbound_message
);

size_t pqc_complete_outbound_session(
    Skissm__E2eeSession *outbound_session,
    Skissm__E2eeAcceptPayload *e2ee_accept_payload
);

/**
 * @brief Close a session
 *
 * @param session
 */
void close_session(Skissm__E2eeSession *session);

#ifdef __cplusplus
}
#endif

#endif /* SESSION_H_ */
