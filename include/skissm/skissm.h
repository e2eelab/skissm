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
#ifndef SKISSM_H_
#define SKISSM_H_

#include <stdint.h>
#include <stdlib.h>

#include "error.h"

#include "add_group_members_request_payload.pb-c.h"
#include "add_group_members_response_payload.pb-c.h"
#include "chain_key.pb-c.h"
#include "create_group_request_payload.pb-c.h"
#include "create_group_response_payload.pb-c.h"
#include "delete_user_request_payload.pb-c.h"
#include "delete_user_response_payload.pb-c.h"
#include "e2ee_account.pb-c.h"
#include "e2ee_address.pb-c.h"
#include "e2ee_commands.pb-c.h"
#include "e2ee_group_msg_payload.pb-c.h"
#include "e2ee_group_msg_response_payload.pb-c.h"
#include "e2ee_group_pre_key_payload.pb-c.h"
#include "e2ee_group_session.pb-c.h"
#include "e2ee_message.pb-c.h"
#include "e2ee_message_type.pb-c.h"
#include "e2ee_msg_payload.pb-c.h"
#include "e2ee_msg_response_payload.pb-c.h"
#include "e2ee_plaintext.pb-c.h"
#include "e2ee_plaintext_type.pb-c.h"
#include "e2ee_pre_key_payload.pb-c.h"
#include "e2ee_protocol_msg.pb-c.h"
#include "e2ee_session.pb-c.h"
#include "get_group_request_payload.pb-c.h"
#include "get_group_response_payload.pb-c.h"
#include "get_pre_key_bundle_request_payload.pb-c.h"
#include "get_pre_key_bundle_response_payload.pb-c.h"
#include "key_pair.pb-c.h"
#include "message_key.pb-c.h"
#include "one_time_pre_key_pair.pb-c.h"
#include "one_time_pre_key_public.pb-c.h"
#include "e2ee_pre_key_bundle.pb-c.h"
#include "publish_spk_request_payload.pb-c.h"
#include "publish_spk_response_payload.pb-c.h"
#include "e2ee_ratchet.pb-c.h"
#include "receiver_chain_node.pb-c.h"
#include "register_user_request_payload.pb-c.h"
#include "register_user_response_payload.pb-c.h"
#include "remove_group_members_request_payload.pb-c.h"
#include "remove_group_members_response_payload.pb-c.h"
#include "sender_chain_node.pb-c.h"
#include "signed_pre_key_pair.pb-c.h"
#include "signed_pre_key_public.pb-c.h"
#include "skipped_message_key_node.pb-c.h"
#include "supply_opks_request_payload.pb-c.h"
#include "supply_opks_response_payload.pb-c.h"

#define PROTOCOL_VERSION 0x01

#define GROUP_VERSION 0x01

#define PLAINTEXT_VERSION 0x01

#define UUID_LEN 64

#define SIGNED_PRE_KEY_EXPIRATION 604800

// callback handlers
typedef struct skissm_event_handler {
  /**
   * @brief notify error
   * @param error_code
   * @param error_msg
   */
  void (*on_error)(ErrorCode, char *);

  /**
   * @brief notify one2one msg received event
   * @param from_address
   * @param to_address
   * @param plaintext
   * @param plaintext_len
   */
  void (*on_one2one_msg_received)(
    Org__E2eelab__Skissm__Proto__E2eeAddress *,
    Org__E2eelab__Skissm__Proto__E2eeAddress *,
    uint8_t *, size_t);

  /**
   * @brief notify group msg received event
   * @param from_address
   * @param group_address
   * @param plaintext
   * @param plaintext_len
   */
  void (*on_group_msg_received)(
    Org__E2eelab__Skissm__Proto__E2eeAddress *,
    Org__E2eelab__Skissm__Proto__E2eeAddress *,
    uint8_t *, size_t);

  /**
   * @brief notify group created event
   * @param group_address
   * @param group_name
   */
  void (*on_group_created)(
    Org__E2eelab__Skissm__Proto__E2eeAddress *,
    ProtobufCBinaryData *);

  /**
   * @brief notify group members added
   * @param group_address
   * @param group_name
   * @param member_addresses
   */
  void (*on_group_members_added)(
    Org__E2eelab__Skissm__Proto__E2eeAddress *,
    ProtobufCBinaryData *,
    Org__E2eelab__Skissm__Proto__E2eeAddress **);

  /**
   * @brief notify group members removed
   * @param group_address
   * @param group_name
   * @param member_addresses
   */
  void (*on_group_members_removed)(
    Org__E2eelab__Skissm__Proto__E2eeAddress *,
    ProtobufCBinaryData *,
    Org__E2eelab__Skissm__Proto__E2eeAddress **);
} skissm_event_handler;

void ssm_begin();

void ssm_end();

void set_skissm_event_handler(skissm_event_handler *event_handler);

void ssm_notify_error(ErrorCode, char *);

void ssm_notify_one2one_msg(
  Org__E2eelab__Skissm__Proto__E2eeAddress *from_address,
  Org__E2eelab__Skissm__Proto__E2eeAddress *to_address,
  uint8_t *plaintext, size_t plaintext_len);

void ssm_notify_group_msg(
  Org__E2eelab__Skissm__Proto__E2eeAddress *from_address,
  Org__E2eelab__Skissm__Proto__E2eeAddress *group_address,
  uint8_t *plaintext, size_t plaintext_len);

void ssm_notify_group_created(
  Org__E2eelab__Skissm__Proto__E2eeAddress *group_address,
  ProtobufCBinaryData *group_name);

void ssm_notify_group_members_added(
  Org__E2eelab__Skissm__Proto__E2eeAddress *group_address,
  ProtobufCBinaryData *group_name,
  Org__E2eelab__Skissm__Proto__E2eeAddress **member_addresses
  );

void ssm_notify_group_members_removed(
  Org__E2eelab__Skissm__Proto__E2eeAddress *group_address,
  ProtobufCBinaryData *group_name,
  Org__E2eelab__Skissm__Proto__E2eeAddress **member_addresses
  );
typedef struct skissm_handler {
  // common handlers
  int64_t (*handle_get_ts)();
  void (*handle_rg)(uint8_t *, size_t);
  void (*handle_generate_uuid)(uint8_t uuid[UUID_LEN]);
  int (*handle_send)(u_int8_t *, size_t);

  // account related handlers
  /**
   * @brief store account to db
   * @param account
   */
  void (*store_account)(Org__E2eelab__Skissm__Proto__E2eeAccount *);
  /**
   * @brief load account from db
   * @param account_id
   * @param account
   */
  void (*load_account)(ProtobufCBinaryData *,
                       Org__E2eelab__Skissm__Proto__E2eeAccount **);
  /**
   * @brief load all accounts from db
   * @param accounts
   * @return number of loaded accounts
   */
  size_t (*load_accounts)(Org__E2eelab__Skissm__Proto__E2eeAccount ***);
  /**
   * @brief load account from db by giving address
   * @param address
   * @param account
   */
  void (*load_account_by_address)(Org__E2eelab__Skissm__Proto__E2eeAddress *,
                                  Org__E2eelab__Skissm__Proto__E2eeAccount **);
  /**
   * @brief update identity key of account to db
   * @param account
   * @param identity_key_pair
   */
  void (*update_identity_key)(Org__E2eelab__Skissm__Proto__E2eeAccount *,
                              Org__E2eelab__Skissm__Proto__KeyPair *);
  /**
   * @brief update signed pre key of account to db
   * @param account
   * @param signed_pre_key
   */
  void (*update_signed_pre_key)(
      Org__E2eelab__Skissm__Proto__E2eeAccount *,
      Org__E2eelab__Skissm__Proto__SignedPreKeyPair *);
  /**
   * @brief load old signed pre key by spk_id
   * @param account_id
   * @param spk_id
   * @param signed_pre_key_pair
   */
  void (*load_old_signed_pre_key)(
      ProtobufCBinaryData *,
      uint32_t,
      Org__E2eelab__Skissm__Proto__SignedPreKeyPair **);
  /**
   * @brief remove expired signed pre key of account from db
   * @param account_id
   */
  void (*remove_expired_signed_pre_key)(
      ProtobufCBinaryData *);
  /**
   * @brief update address of account to db
   * @param account
   * @param address
   */
  void (*update_address)(Org__E2eelab__Skissm__Proto__E2eeAccount *,
                         Org__E2eelab__Skissm__Proto__E2eeAddress *);
  /**
   * @brief add an one time pre key of account to db
   * @param account
   * @param one_time_pre_key
   */
  void (*add_one_time_pre_key)(
      Org__E2eelab__Skissm__Proto__E2eeAccount *,
      Org__E2eelab__Skissm__Proto__OneTimePreKeyPair *);
  /**
   * @brief remove an one time pre key of acount from db
   * @param account
   * @param one_time_pre_key_id
   */
  void (*remove_one_time_pre_key)(Org__E2eelab__Skissm__Proto__E2eeAccount *,
                                  uint32_t);

  // session related handlers
  /**
   * @brief find inbound session
   * @param session_id
   * @param owner
   * @param inbound_session
   */
  void (*load_inbound_session)(ProtobufCBinaryData,
                               Org__E2eelab__Skissm__Proto__E2eeAddress *,
                               Org__E2eelab__Skissm__Proto__E2eeSession **);
  /**
   * @brief store session
   * @param session
   */
  void (*store_session)(Org__E2eelab__Skissm__Proto__E2eeSession *);
  /**
   * @brief find outbound session
   * @param owner
   * @param to
   * @param outbound_session
   */
  void (*load_outbound_session)(Org__E2eelab__Skissm__Proto__E2eeAddress *,
                                Org__E2eelab__Skissm__Proto__E2eeAddress *,
                                Org__E2eelab__Skissm__Proto__E2eeSession **);
  /**
   * @brief delete old inbound session
   * @param owner
   * @param from
   * @param to
   */
  void (*unload_session)(Org__E2eelab__Skissm__Proto__E2eeAddress *,
                         Org__E2eelab__Skissm__Proto__E2eeAddress *,
                         Org__E2eelab__Skissm__Proto__E2eeAddress *);

  // group session related handlers
  /**
   * @brief find outbound group session
   * @param user_address
   * @param group_address
   * @param inbound_group_session
   */
  void (*load_outbound_group_session)(
      Org__E2eelab__Skissm__Proto__E2eeAddress *,
      Org__E2eelab__Skissm__Proto__E2eeAddress *,
      Org__E2eelab__Skissm__Proto__E2eeGroupSession **);
  /**
   * @brief find inbound group session
   * @param group_session_id
   * @param user_address
   * @param outbound_group_session
   */
  void (*load_inbound_group_session)(
      ProtobufCBinaryData, Org__E2eelab__Skissm__Proto__E2eeAddress *,
      Org__E2eelab__Skissm__Proto__E2eeGroupSession **);
  /**
   * @brief store group session
   * @param group_session
   */
  void (*store_group_session)(Org__E2eelab__Skissm__Proto__E2eeGroupSession *);
  /**
   * @brief delete group session
   * @param group_session
   */
  void (*unload_group_session)(Org__E2eelab__Skissm__Proto__E2eeGroupSession *);
  /**
   * @brief delete old inbound group session
   * @param user_address
   * @param old_session_id
   */
  void (*unload_inbound_group_session)(
      Org__E2eelab__Skissm__Proto__E2eeAddress *,
      ProtobufCBinaryData *
  );
} skissm_handler;

extern const struct skissm_handler ssm_handler;

#endif /* SKISSM_H_ */
