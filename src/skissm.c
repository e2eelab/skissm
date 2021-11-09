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
#include "skissm.h"
#include "account.h"
#include "e2ee_protocol.h"

static skissm_event_handler *ssm_event_handler = NULL;

void ssm_begin() {
    account_begin();
    protocol_begin();
}

void ssm_end() {
    account_end();
    protocol_end();
}

void set_skissm_event_handler(skissm_event_handler *event_handler) {
    ssm_event_handler = event_handler;
}

void ssm_notify_error(ErrorCode error_code, char *error_msg) {
    if (ssm_event_handler != NULL)
        ssm_event_handler->on_error(error_code, error_msg);
}

void ssm_notify_user_registered(Org__E2eelab__Skissm__Proto__E2eeAccount *account){
    if (ssm_event_handler != NULL)
        ssm_event_handler->on_user_registered(account);
}

void ssm_notify_one2one_msg(Org__E2eelab__Skissm__Proto__E2eeAddress *from_address,
                            Org__E2eelab__Skissm__Proto__E2eeAddress *to_address, uint8_t *plaintext,
                            size_t plaintext_len) {
    if (ssm_event_handler != NULL)
        ssm_event_handler->on_one2one_msg_received(from_address, to_address, plaintext, plaintext_len);
}

void ssm_notify_group_msg(Org__E2eelab__Skissm__Proto__E2eeAddress *from_address,
                          Org__E2eelab__Skissm__Proto__E2eeAddress *group_address, uint8_t *plaintext,
                          size_t plaintext_len) {
    if (ssm_event_handler != NULL)
        ssm_event_handler->on_group_msg_received(from_address, group_address, plaintext, plaintext_len);
}

void ssm_notify_group_created(Org__E2eelab__Skissm__Proto__E2eeAddress *group_address,
                              ProtobufCBinaryData *group_name) {
    if (ssm_event_handler != NULL)
        ssm_event_handler->on_group_created(group_address, group_name);
}

void ssm_notify_group_members_added(Org__E2eelab__Skissm__Proto__E2eeAddress *group_address,
                                    ProtobufCBinaryData *group_name,
                                    Org__E2eelab__Skissm__Proto__E2eeAddress **member_addresses) {
    if (ssm_event_handler != NULL)
        ssm_event_handler->on_group_members_added(group_address, group_name, member_addresses);
}

void ssm_notify_group_members_removed(Org__E2eelab__Skissm__Proto__E2eeAddress *group_address,
                                      ProtobufCBinaryData *group_name,
                                      Org__E2eelab__Skissm__Proto__E2eeAddress **member_addresses) {
    if (ssm_event_handler != NULL)
        ssm_event_handler->on_group_members_removed(group_address, group_name, member_addresses);
}
