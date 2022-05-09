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
#ifndef SESSION_MANAGER_H_
#define SESSION_MANAGER_H_

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "skissm/skissm.h"

/**
 * @brief Create a get_pre_key_bundle_request to be sent to messaging server.
 *
 * @param peer_address
 * @return Skissm__GetPreKeyBundleRequest*
 */
Skissm__GetPreKeyBundleRequest *produce_get_pre_key_bundle_request(Skissm__E2eeAddress *peer_address);

/**
 * @brief Process an incoming get_pre_key_bundle_response_payload.
 *
 * @param from
 * @param to
 * @param response
 * @return Skissm__InviteResponse *
 */
Skissm__InviteResponse *consume_get_pre_key_bundle_response (
    Skissm__E2eeAddress *from,
    Skissm__E2eeAddress *to,
    Skissm__GetPreKeyBundleResponse *response);
/**
 * @brief Create a send_one2one_msg_request to be sent to messaging server.
 *
 * @param outbound_session
 * @param plaintext_data
 * @param plaintext_data_len
 * @return Skissm__SendOne2oneMsgRequest*
 */
Skissm__SendOne2oneMsgRequest *produce_send_one2one_msg_request(Skissm__Session *outbound_session, const uint8_t *plaintext_data, size_t plaintext_data_len);

/**
 * @brief Process an send_one2one_msg_response with corresponding inbound session.
 *
 * @param outbound_session
 * @param response
 * @return true
 * @return false
 */
bool consume_send_one2one_msg_response(Skissm__Session *outbound_session, Skissm__SendOne2oneMsgResponse *response);

/**
 * @brief Process a received Skissm__E2eeMsg message from server.
 *
 * @param receiver_address
 * @param e2ee_msg
 * @return true
 * @return false
 */
bool consume_one2one_msg(Skissm__E2eeAddress *receiver_address, Skissm__E2eeMsg *e2ee_msg);

/**
 * @brief Create a Skissm__InviteRequest message to be sent to server.
 *
 * @param outbound_session
 * @param pre_shared_keys
 * @param pre_shared_keys_len
 * @return Skissm__InviteRequest*
 */
Skissm__InviteRequest *produce_invite_request(
    Skissm__Session *outbound_session, ProtobufCBinaryData **pre_shared_keys, size_t pre_shared_keys_len);

/**
 * @brief Process an incoming InviteResponse message.
 *
 * @param response
 * @return true
 * @return false
 */
bool consume_invite_response(Skissm__InviteResponse *response);

/**
 * @brief Process an incoming E2eeAddress message.
 *
 * @param response
 * @return true
 * @return false
 */
bool consume_invite_msg(Skissm__E2eeAddress *receiver_address, Skissm__InviteMsg *msg);

/**
 * @brief Create a Skissm__AcceptRequest message to be sent to server.
 *
 * @param e2ee_pack_id
 * @param from
 * @param to
 * @param ciphertext_1
 * @return Skissm__AcceptRequest*
 */
Skissm__AcceptRequest *produce_accept_request(const char *e2ee_pack_id,
                                              Skissm__E2eeAddress *from,
                                              Skissm__E2eeAddress *to,
                                              ProtobufCBinaryData *ciphertext_1);

/**
 * @brief Process an incoming AcceptResponse message.
 *
 * @param response
 * @return true
 * @return false
 */
bool consume_accept_response(Skissm__AcceptResponse *response);

/**
 * @brief Process an incoming AcceptMs message.
 *
 * @param response
 * @return true
 * @return false
 */
bool consume_accept_msg(Skissm__E2eeAddress *receiver_address, Skissm__AcceptMsg *msg);

#ifdef __cplusplus
}
#endif

#endif /* SESSION_MANAGER_H_ */
