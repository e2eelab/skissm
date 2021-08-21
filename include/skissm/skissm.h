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
#include "pre_key_bundle.pb-c.h"
#include "publish_spk_request_payload.pb-c.h"
#include "publish_spk_response_payload.pb-c.h"
#include "ratchet.pb-c.h"
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

#define UUID_LEN 64

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
    Org__E2eelab__Lib__Protobuf__E2eeAddress *,
    Org__E2eelab__Lib__Protobuf__E2eeAddress *,
    uint8_t *, size_t);

  /**
   * @brief notify group msg received event
   * @param from_address
   * @param group_address
   * @param plaintext
   * @param plaintext_len
   */
  void (*on_group_msg_received)(
    Org__E2eelab__Lib__Protobuf__E2eeAddress *,
    Org__E2eelab__Lib__Protobuf__E2eeAddress *,
    uint8_t *, size_t);

  /**
   * @brief notify group created event
   * @param group_address
   * @param group_name
   */
  void (*on_group_created)(
    Org__E2eelab__Lib__Protobuf__E2eeAddress *,
    ProtobufCBinaryData *);

  /**
   * @brief notify group members added
   * @param group_address
   * @param group_name
   * @param member_addresses
   */
  void (*on_group_members_added)(
    Org__E2eelab__Lib__Protobuf__E2eeAddress *,
    ProtobufCBinaryData *,
    Org__E2eelab__Lib__Protobuf__E2eeAddress **);

  /**
   * @brief notify group members removed
   * @param group_address
   * @param group_name
   * @param member_addresses
   */
  void (*on_group_members_removed)(
    Org__E2eelab__Lib__Protobuf__E2eeAddress *,
    ProtobufCBinaryData *,
    Org__E2eelab__Lib__Protobuf__E2eeAddress **);
} skissm_event_handler;

void set_skissm_event_handler(skissm_event_handler *event_handler);

void ssm_notify_error(ErrorCode, char *);

void ssm_notify_one2one_msg(
  Org__E2eelab__Lib__Protobuf__E2eeAddress *from_address,
  Org__E2eelab__Lib__Protobuf__E2eeAddress *to_address,
  uint8_t *plaintext, size_t plaintext_len);

void ssm_notify_group_msg(
  Org__E2eelab__Lib__Protobuf__E2eeAddress *from_address,
  Org__E2eelab__Lib__Protobuf__E2eeAddress *group_address,
  uint8_t *plaintext, size_t plaintext_len);

void ssm_notify_group_created(
  Org__E2eelab__Lib__Protobuf__E2eeAddress *group_address,
  ProtobufCBinaryData *group_name);

void ssm_notify_group_members_added(
  Org__E2eelab__Lib__Protobuf__E2eeAddress *group_address,
  ProtobufCBinaryData *group_name,
  Org__E2eelab__Lib__Protobuf__E2eeAddress **member_addresses
  );

void ssm_notify_group_members_removed(
  Org__E2eelab__Lib__Protobuf__E2eeAddress *group_address,
  ProtobufCBinaryData *group_name,
  Org__E2eelab__Lib__Protobuf__E2eeAddress **member_addresses
  );
typedef struct skissm_handler {
  // common handlers
  int64_t (*handle_get_ts)();
  void (*handle_rg)(uint8_t *, size_t);
  void (*handle_generate_uuid)(uint8_t uuid[UUID_LEN]);
  int (*handle_send)(u_int8_t *, size_t);

  // account related handlers
  void (*init_account)(Org__E2eelab__Lib__Protobuf__E2eeAccount *);
  void (*load_account)(ProtobufCBinaryData *,
                       Org__E2eelab__Lib__Protobuf__E2eeAccount **);
  void (*load_account_by_address)(Org__E2eelab__Lib__Protobuf__E2eeAddress *,
                                  Org__E2eelab__Lib__Protobuf__E2eeAccount **);
  void (*update_identity_key)(Org__E2eelab__Lib__Protobuf__E2eeAccount *,
                              Org__E2eelab__Lib__Protobuf__KeyPair *);
  void (*update_signed_pre_key)(
      Org__E2eelab__Lib__Protobuf__E2eeAccount *,
      Org__E2eelab__Lib__Protobuf__SignedPreKeyPair *);
  void (*update_address)(Org__E2eelab__Lib__Protobuf__E2eeAccount *,
                         Org__E2eelab__Lib__Protobuf__E2eeAddress *);
  void (*add_one_time_pre_key)(
      Org__E2eelab__Lib__Protobuf__E2eeAccount *,
      Org__E2eelab__Lib__Protobuf__OneTimePreKeyPair *);
  void (*remove_one_time_pre_key)(Org__E2eelab__Lib__Protobuf__E2eeAccount *,
                                  uint32_t);

  // session related handlers
  /**
   * @brief find inbound session
   * @param session_id
   * @param owner
   * @param inbound_session
   */
  void (*load_inbound_session)(ProtobufCBinaryData,
                               Org__E2eelab__Lib__Protobuf__E2eeAddress *,
                               Org__E2eelab__Lib__Protobuf__E2eeSession **);
  /**
   * @brief store session
   * @param session
   */
  void (*store_session)(Org__E2eelab__Lib__Protobuf__E2eeSession *);
  /**
   * @brief find outbound session
   * @param owner
   * @param to
   * @param outbound_session
   */
  void (*load_outbound_session)(Org__E2eelab__Lib__Protobuf__E2eeAddress *,
                                Org__E2eelab__Lib__Protobuf__E2eeAddress *,
                                Org__E2eelab__Lib__Protobuf__E2eeSession **);
  /**
   * @brief delete old inbound session
   * @param owner
   * @param from
   * @param to
   */
  void (*unload_session)(Org__E2eelab__Lib__Protobuf__E2eeAddress *,
                         Org__E2eelab__Lib__Protobuf__E2eeAddress *,
                         Org__E2eelab__Lib__Protobuf__E2eeAddress *);

  // group session related handlers
  /**
   * @brief find outbound group session
   * @param user_address
   * @param group_address
   * @param inbound_group_session
   */
  void (*load_outbound_group_session)(
      Org__E2eelab__Lib__Protobuf__E2eeAddress *,
      Org__E2eelab__Lib__Protobuf__E2eeAddress *,
      Org__E2eelab__Lib__Protobuf__E2eeGroupSession **);
  /**
   * @brief find inbound group session
   * @param group_session_id
   * @param user_address
   * @param outbound_group_session
   */
  void (*load_inbound_group_session)(
      ProtobufCBinaryData, Org__E2eelab__Lib__Protobuf__E2eeAddress *,
      Org__E2eelab__Lib__Protobuf__E2eeGroupSession **);
  /**
   * @brief store group session
   * @param group_session
   */
  void (*store_group_session)(Org__E2eelab__Lib__Protobuf__E2eeGroupSession *);
  /**
   * @brief delete group session
   * @param group_session
   */
  void (*unload_group_session)(Org__E2eelab__Lib__Protobuf__E2eeGroupSession *);
  /**
   * @brief delete old inbound group session
   * @param user_address
   * @param group_address
   * @param member_num
   * @param member_addresses
   */
  void (*unload_inbound_group_session)(
      Org__E2eelab__Lib__Protobuf__E2eeAddress *,
      Org__E2eelab__Lib__Protobuf__E2eeAddress *,
      size_t,
      Org__E2eelab__Lib__Protobuf__E2eeAddress **
  );
} skissm_handler;

extern const struct skissm_handler ssm_handler;

#endif /* SKISSM_H_ */
