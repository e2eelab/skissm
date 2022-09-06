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
#ifndef E2EE_CLIENT_INTERNAL_H_
#define E2EE_CLIENT_INTERNAL_H_

#include "skissm/skissm.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Get the pre-key bundle internal object.
 *
 * @param from
 * @param to_user_id
 * @param to_domain
 * @param group_pre_key_plaintext_data
 * @param group_pre_key_plaintext_data_len
 * @return Skissm__InviteResponse *
 */
Skissm__InviteResponse *get_pre_key_bundle_internal(
    Skissm__E2eeAddress *from,
    const char *to_user_id,
    const char *to_domain,
    uint8_t *group_pre_key_plaintext_data,
    size_t group_pre_key_plaintext_data_len
);

/**
 * @brief Send invite request to server.
 *
 * @param outbound_session
 * @param pre_shared_keys
 * @param pre_shared_keys_num
 * @return Skissm__InviteResponse *
 */
Skissm__InviteResponse *invite_internal(
    Skissm__Session *outbound_session,
    ProtobufCBinaryData **pre_shared_keys, size_t pre_shared_keys_num
);

/**
 * @brief Send accept request to server.
 *
 * @param e2ee_pack_id
 * @param from
 * @param to
 * @param ciphertext_1
 * @return Skissm__AcceptResponse *
 */
Skissm__AcceptResponse *accept_internal(
    const char *e2ee_pack_id,
    Skissm__E2eeAddress *from, Skissm__E2eeAddress *to,
    ProtobufCBinaryData *ciphertext_1
);

/**
 * @brief Send face-to-face invite request to server.
 *
 * @param from
 * @param to
 * @param e2ee_pack_id
 * @param secret
 * @param secret_len
 * @return Skissm__F2fInviteResponse *
 */
Skissm__F2fInviteResponse *f2f_invite_internal(
    Skissm__E2eeAddress *from, Skissm__E2eeAddress *to,
    char *e2ee_pack_id,
    uint8_t *secret, size_t secret_len
);

/**
 * @brief Send face-to-face accept request to server.
 *
 * @param e2ee_pack_id
 * @param from
 * @param to
 * @param local_account
 * @return Skissm__F2fAcceptResponse *
 */
Skissm__F2fAcceptResponse *f2f_accept_internal(
    const char *e2ee_pack_id,
    Skissm__E2eeAddress *from, Skissm__E2eeAddress *to,
    Skissm__Account *local_account
);

/**
 * @brief Send publish_spk request to server.
 *
 * @param account The account to be processed
 * @return Skissm__PublishSpkResponse *
 */
Skissm__PublishSpkResponse *publish_spk_internal(Skissm__Account *account);

/**
 * @brief Send supply_opks request to server.
 *
 * @param account
 * @param opks_num
 * @return Skissm__SupplyOpksResponse *
 */
Skissm__SupplyOpksResponse *supply_opks_internal(Skissm__Account *account, uint32_t opks_num);

/**
 * @brief Send one2one_msg request to server.
 *
 * @param outbound_session
 * @param plaintext_data
 * @param plaintext_data_len
 * @return Skissm__SendOne2oneMsgResponse *
 */
Skissm__SendOne2oneMsgResponse *send_one2one_msg_internal(
    Skissm__Session *outbound_session,
    const uint8_t *plaintext_data, size_t plaintext_data_len
);

void resume_connection_internal(Skissm__Account *account);

#ifdef __cplusplus
}
#endif

#endif // E2EE_CLIENT_INTERNAL_H_