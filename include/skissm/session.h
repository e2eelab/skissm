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

/**
 * @brief Handler for message encryption
 *
 */
typedef struct encryption_handler {
    /**
     * @param msg
     * @param msg_len
     */
    void (*on_encrypted)(uint8_t **, size_t);
} encryption_handler;

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

size_t new_outbound_session(
    Skissm__E2eeSession *session,
    const Skissm__E2eeAccount *local_account,
    Skissm__E2eePreKeyBundle *their_pre_key_bundle
);

size_t new_inbound_session(
    Skissm__E2eeSession *session,
    Skissm__E2eeAccount *local_account,
    Skissm__E2eeMessage *inbound_prekey_message
);

/**
 * @brief Encrypt a given plaintext with an initialized outbound session
 *
 * @param outbound_session initialized outbound session
 * @param plaintext plaintext to be encrypted
 * @param plaintext_len plaintext length
 * @return size_t encrypted message length
 */
size_t perform_encrypt_session(Skissm__E2eeSession *outbound_session, const uint8_t *plaintext, size_t plaintext_len);

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
