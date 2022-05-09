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
 * @brief Get the pre key bundle internal object.
 *
 * @param from
 * @param to
 * @return Skissm__InviteResponse *
 */
Skissm__InviteResponse *get_pre_key_bundle_internal(Skissm__E2eeAddress *from, Skissm__E2eeAddress *to);

/**
 * @brief Send invite requesst to server.
 *
 * @param outbound_session
 * @param pre_shared_keys
 * @param pre_shared_keys_len
 * @return Skissm__InviteResponse *
 */
Skissm__InviteResponse *invite_internal(Skissm__Session *outbound_session, ProtobufCBinaryData **pre_shared_keys, size_t pre_shared_keys_len);

/**
 * @brief Send accept requesst to server.
 *
 * @param e2ee_pack_id
 * @param from
 * @param to
 * @param ciphertext_1
 * @return Skissm__AcceptResponse *
 */
Skissm__AcceptResponse *accept_internal(const char *e2ee_pack_id, Skissm__E2eeAddress *from, Skissm__E2eeAddress *to, ProtobufCBinaryData *ciphertext_1);

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
Skissm__SendOne2oneMsgResponse *send_one2one_msg_internal(Skissm__Session *outbound_session, const uint8_t *plaintext_data, size_t plaintext_data_len);

/**
 * @brief Send consume_proto_msg request to server.
 *
 * @param msg_id
 * @return Skissm__ConsumeProtoMsgResponse *
 */
Skissm__ConsumeProtoMsgResponse *consume_proto_msg_internal(char *proto_msg_id);

#ifdef __cplusplus
}
#endif

#endif // E2EE_CLIENT_INTERNAL_H_