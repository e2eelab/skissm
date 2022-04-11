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
#include "skissm/skissm.h"

#include "skissm/account.h"
#include "skissm/e2ee_protocol.h"

static skissm_plugin_t *skissm_plugin;

void skissm_begin(skissm_plugin_t *ssm_plugin) {
    skissm_plugin = ssm_plugin;

    account_begin();
    protocol_begin();
}

void skissm_end() {
    skissm_plugin = NULL;

    account_end();
    protocol_end();
}

skissm_plugin_t *get_skissm_plugin() {
    return skissm_plugin;
}

void ssm_notify_error(ErrorCode error_code, char *error_msg) {
    if (skissm_plugin != NULL)
        skissm_plugin->event_handler.on_error(error_code, error_msg);
}

void ssm_notify_user_registered(Skissm__E2eeAccount *account){
    if (skissm_plugin != NULL)
        skissm_plugin->event_handler.on_user_registered(account);
}

void ssm_notify_inbound_session_ready(Skissm__E2eeSession *inbound_session) {
    if (skissm_plugin != NULL)
        skissm_plugin->event_handler.on_inbound_session_ready(inbound_session);
}

void ssm_notify_outbound_session_ready(Skissm__E2eeSession *outbound_session) {
    if (skissm_plugin != NULL)
        skissm_plugin->event_handler.on_outbound_session_ready(outbound_session);
}

void ssm_notify_one2one_msg(Skissm__E2eeAddress *from_address,
                            Skissm__E2eeAddress *to_address, uint8_t *plaintext,
                            size_t plaintext_len) {
    if (skissm_plugin != NULL)
        skissm_plugin->event_handler.on_one2one_msg_received(from_address, to_address, plaintext, plaintext_len);
}

void ssm_notify_group_msg(Skissm__E2eeAddress *from_address,
                          Skissm__E2eeAddress *group_address, uint8_t *plaintext,
                          size_t plaintext_len) {
    if (skissm_plugin != NULL)
        skissm_plugin->event_handler.on_group_msg_received(from_address, group_address, plaintext, plaintext_len);
}

void ssm_notify_group_created(Skissm__E2eeAddress *group_address, char *group_name) {
    if (skissm_plugin != NULL)
        skissm_plugin->event_handler.on_group_created(group_address, group_name);
}

void ssm_notify_group_members_added(Skissm__E2eeAddress *group_address,
                                    char *group_name,
                                    Skissm__E2eeAddress **member_addresses) {
    if (skissm_plugin != NULL)
        skissm_plugin->event_handler.on_group_members_added(group_address, group_name, member_addresses);
}

void ssm_notify_group_members_removed(Skissm__E2eeAddress *group_address,
                                      char *group_name,
                                      Skissm__E2eeAddress **member_addresses) {
    if (skissm_plugin != NULL)
        skissm_plugin->event_handler.on_group_members_removed(group_address, group_name, member_addresses);
}
