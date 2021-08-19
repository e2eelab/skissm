#include "skissm.h"

static skissm_event_handler *ssm_event_handler = NULL;

void set_skissm_event_handler(skissm_event_handler *event_handler) {
  ssm_event_handler = event_handler;
}

void ssm_notify_error(ErrorCode error_code, char *error_msg) {
  if (ssm_event_handler != NULL)
    ssm_event_handler->on_error(error_code, error_msg);
}

void ssm_notify_one2one_msg(
    Org__E2eelab__Lib__Protobuf__E2eeAddress *from_address,
    Org__E2eelab__Lib__Protobuf__E2eeAddress *to_address, uint8_t *plaintext,
    size_t plaintext_len) {
  if (ssm_event_handler != NULL)
    ssm_event_handler->on_one2one_msg_received(from_address, to_address,
                                               plaintext, plaintext_len);
}

void ssm_notify_group_msg(
    Org__E2eelab__Lib__Protobuf__E2eeAddress *from_address,
    Org__E2eelab__Lib__Protobuf__E2eeAddress *group_address, uint8_t *plaintext,
    size_t plaintext_len) {
  if (ssm_event_handler != NULL)
    ssm_event_handler->on_group_msg_received(from_address, group_address,
                                             plaintext, plaintext_len);
}
