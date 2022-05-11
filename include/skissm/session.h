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

typedef struct session_suite_t {
    /**
     * @brief Create a new outbound session.
     *
     * @param session The outbound session
     * @param local_account Our account
     * @param their_pre_key_bundle Their pre-key bundle
     * @return Skissm__InviteResponse *
     */
    Skissm__InviteResponse * (*new_outbound_session)(
        Skissm__Session *,
        const Skissm__Account *,
        Skissm__PreKeyBundle *
    );

    /**
     * @brief Create a new inbound session.
     *
     * @param session The inbound session
     * @param local_account Our account
     * @param request The invite message
     * @return Success or not
     */
    size_t (*new_inbound_session)(
        Skissm__Session *,
        Skissm__Account *,
        Skissm__InviteMsg *
    );

    /**
     * @brief Complete an outbound session.
     *
     * @param outbound_session The inbound session
     * @param msg The accept message
     * @return Success or not
     */
    size_t (*complete_outbound_session)(
        Skissm__Session *,
        Skissm__AcceptMsg *
    );
} session_suite_t;

/* common */
void initialise_session(
    Skissm__Session *session,
    const char *e2ee_pack_id,
    Skissm__E2eeAddress *from,
    Skissm__E2eeAddress *to
);

/**
 * @brief Packaging a common plaintext to common_plaintext_data.
 *
 * @param plaintext_data
 * @param plaintext_data_len
 * @param common_plaintext_data
 * @param common_plaintext_data_len
 */
void pack_common_plaintext(const uint8_t *plaintext_data, size_t plaintext_data_len, uint8_t **common_plaintext_data, size_t *common_plaintext_data_len);

/* ECC-related */
Skissm__InviteResponse *crypto_curve25519_new_outbound_session(
    Skissm__Session *session,
    const Skissm__Account *local_account,
    Skissm__PreKeyBundle *their_pre_key_bundle
);

size_t crypto_curve25519_new_inbound_session(
    Skissm__Session *session,
    Skissm__Account *local_account,
    Skissm__InviteMsg *msg
);

size_t crypto_curve25519_complete_outbound_session(
    Skissm__Session *outbound_session,
    Skissm__AcceptMsg *msg
);

/* PQC-related */
Skissm__InviteResponse *pqc_new_outbound_session(
    Skissm__Session *session,
    const Skissm__Account *local_account,
    Skissm__PreKeyBundle *their_pre_key_bundle
);

size_t pqc_new_inbound_session(
    Skissm__Session *session,
    Skissm__Account *local_account,
    Skissm__InviteMsg *msg
);

size_t pqc_complete_outbound_session(
    Skissm__Session *outbound_session,
    Skissm__AcceptMsg *msg
);

#ifdef __cplusplus
}
#endif

#endif /* SESSION_H_ */
