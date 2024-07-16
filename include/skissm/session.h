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
     * @param response_out The output invite response
     * @param from The sender's address
     * @param their_pre_key_bundle Their pre-key bundle
     * @return 0 if success
     */
    int (*new_outbound_session)(
        Skissm__InviteResponse **,
        Skissm__E2eeAddress *,
        Skissm__PreKeyBundle *
    );

    /**
     * @brief Create a new inbound session.
     *
     * @param inbound_session_out The inbound session
     * @param local_account Our account
     * @param request The invite message
     * @return value < 0 for error
     */
    int (*new_inbound_session)(
        Skissm__Session **,
        Skissm__Account *,
        Skissm__InviteMsg *
    );

    /**
     * @brief Complete an outbound session.
     *
     * @param outbound_session_out The outbound session
     * @param msg The accept message
     * @return value < 0 for error
     */
    int (*complete_outbound_session)(
        Skissm__Session **,
        Skissm__AcceptMsg *
    );
} session_suite_t;

/* common */
void initialise_session(
    Skissm__Session *session,
    uint32_t e2ee_pack_id,
    Skissm__E2eeAddress *our_address,
    Skissm__E2eeAddress *their_address
);

/**
 * @brief Packaging a common plaintext to common_plaintext_data.
 *
 * @param plaintext_data
 * @param plaintext_data_len
 * @param plaintext_type
 * @param common_plaintext_data
 * @param common_plaintext_data_len
 */
void pack_common_plaintext(
    const uint8_t *plaintext_data, size_t plaintext_data_len,
    int plaintext_type,
    uint8_t **common_plaintext_data, size_t *common_plaintext_data_len
);

/* ECC-related */
Skissm__InviteResponse *crypto_curve25519_new_outbound_session(
    Skissm__Session *session,
    const Skissm__Account *local_account,
    Skissm__PreKeyBundle *their_pre_key_bundle
);

int crypto_curve25519_new_inbound_session(
    Skissm__Session *session,
    Skissm__Account *local_account,
    Skissm__InviteMsg *msg
);

int crypto_curve25519_complete_outbound_session(
    Skissm__Session *outbound_session,
    Skissm__AcceptMsg *msg
);

/* PQC-related */
int pqc_new_outbound_session_v2(
    Skissm__InviteResponse **response_out,
    Skissm__E2eeAddress *from,
    Skissm__PreKeyBundle *their_pre_key_bundle
);

int pqc_new_inbound_session(
    Skissm__Session **inbound_session_out,
    Skissm__Account *local_account,
    Skissm__InviteMsg *msg
);

int pqc_complete_outbound_session(
    Skissm__Session **outbound_session_out,
    Skissm__AcceptMsg *msg
);

#ifdef __cplusplus
}
#endif

#endif /* SESSION_H_ */
