#ifndef E2EE_PROTOCOL_HANDLER_H_
#define E2EE_PROTOCOL_HANDLER_H_

#include <stdlib.h>
#include <stdint.h>

#include "skissm.h"

typedef struct register_user_response_handler{
    Org__E2eelab__Skissm__Proto__E2eeAccount *account;
    void (*handle_response)(
        struct register_user_response_handler *this_handler,
        Org__E2eelab__Skissm__Proto__E2eeAddress *address);
    void (*handle_release)(struct register_user_response_handler *this_handler);
} register_user_response_handler;

typedef struct publish_spk_response_handler{
    Org__E2eelab__Skissm__Proto__E2eeAccount *account;
    void (*handle_response)(
        struct publish_spk_response_handler *this_handler);
    void (*handle_release)(struct publish_spk_response_handler *this_handler);
} publish_spk_response_handler;

typedef struct supply_opks_handler{
    Org__E2eelab__Skissm__Proto__E2eeAccount *account;
    void (*handle_release)(struct supply_opks_handler *this_handler);
} supply_opks_handler;

typedef struct pre_key_bundle_handler{
    Org__E2eelab__Skissm__Proto__E2eeAddress *from;
    Org__E2eelab__Skissm__Proto__E2eeAddress *to;
    uint8_t *context;
    size_t context_len;
    void (*handle_response)(
        struct pre_key_bundle_handler *this_handler,
        Org__E2eelab__Skissm__Proto__E2eePreKeyBundle *pre_key_bundle);
    void (*handle_release)(struct pre_key_bundle_handler *this_handler);
} pre_key_bundle_response_handler;

typedef struct create_group_response_handler{
    Org__E2eelab__Skissm__Proto__E2eeAddress *sender_address;
    ProtobufCBinaryData *group_name;
    Org__E2eelab__Skissm__Proto__E2eeAddress **member_addresses;
    size_t member_num;
    void (*handle_response)(
        struct create_group_response_handler *this_handler,
        Org__E2eelab__Skissm__Proto__E2eeAddress *group_address);
    void (*handle_release)(struct create_group_response_handler *this_handler);
} create_group_response_handler;

typedef struct get_group_response_handler{
    Org__E2eelab__Skissm__Proto__E2eeAddress *group_address;
    ProtobufCBinaryData *group_name;
    size_t member_num;
    Org__E2eelab__Skissm__Proto__E2eeAddress **member_addresses;
    void (*handle_response)(
        struct get_group_response_handler *this_handler,
        ProtobufCBinaryData *group_name,
        size_t member_num,
        Org__E2eelab__Skissm__Proto__E2eeAddress **member_addresses);
    void (*handle_release)(struct get_group_response_handler *this_handler);
} get_group_response_handler;

typedef struct add_group_members_response_handler{
    Org__E2eelab__Skissm__Proto__E2eeGroupSession *outbound_group_session;
    Org__E2eelab__Skissm__Proto__E2eeAddress **adding_member_addresses;
    size_t adding_member_num;
    void (*handle_response)(
        struct add_group_members_response_handler *this_handler);
    void (*handle_release)(struct add_group_members_response_handler *this_handler);
} add_group_members_response_handler;

typedef struct remove_group_members_response_handler{
    Org__E2eelab__Skissm__Proto__E2eeGroupSession *outbound_group_session;
    Org__E2eelab__Skissm__Proto__E2eeAddress **removing_member_addresses;
    size_t removing_member_num;
    void (*handle_response)(
        struct remove_group_members_response_handler *this_handler);
    void (*handle_release)();
} remove_group_members_response_handler;

#endif /* E2EE_PROTOCOL_HANDLER_H_ */
