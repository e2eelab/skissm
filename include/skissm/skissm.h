#ifndef SKISSM_H_
#define SKISSM_H_

#include <stdint.h>
#include <stdlib.h>

#include "e2ee_account.pb-c.h"
#include "e2ee_address.pb-c.h"
#include "e2ee_commands.pb-c.h"
#include "e2ee_message.pb-c.h"
#include "e2ee_pre_key_bundle.pb-c.h"
#include "e2ee_session.pb-c.h"
#include "error.h"

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

  // group session related handlers
  void (*load_outbound_group_session)(
      Org__E2eelab__Lib__Protobuf__E2eeAddress *,
      Org__E2eelab__Lib__Protobuf__E2eeAddress *,
      Org__E2eelab__Lib__Protobuf__E2eeGroupSession **);
  void (*load_inbound_group_session)(
      ProtobufCBinaryData, Org__E2eelab__Lib__Protobuf__E2eeAddress *,
      Org__E2eelab__Lib__Protobuf__E2eeGroupSession **);
  void (*store_group_session)(Org__E2eelab__Lib__Protobuf__E2eeGroupSession *);
  void (*unload_group_session)(Org__E2eelab__Lib__Protobuf__E2eeGroupSession *);
} skissm_handler;

extern const struct skissm_handler ssm_handler;

#endif /* SKISSM_H_ */
