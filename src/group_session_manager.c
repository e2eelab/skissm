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
#include "e2ee_protocol_handler.h"
#include "group_session_manager.h"
#include "crypto.h"
#include "mem_util.h"
#include "e2ee_protocol.h"
#include "session.h"
#include "group_session.h"

static const size_t SHARED_KEY_LENGTH = SHA256_OUTPUT_LENGTH;

static void handle_create_group_response(
    create_group_response_handler *response_handler,
    Org__E2eelab__Skissm__Proto__E2eeAddress *group_address
) {
    create_outbound_group_session(response_handler->sender_address, group_address, response_handler->member_addresses, response_handler->member_num, NULL);
    ssm_notify_group_created(group_address, response_handler->group_name);
}

static void handle_create_group_release(
    create_group_response_handler *this_handler
) {
    this_handler->sender_address = NULL;
    this_handler->group_name = NULL;
    this_handler->member_addresses = NULL;
    this_handler->member_num = 0;
}

create_group_response_handler create_group_response_handler_store = {
    NULL,
    NULL,
    NULL,
    0,
    handle_create_group_response,
    handle_create_group_release
};

static void handle_get_group_response(
    get_group_response_handler *this_handler,
    ProtobufCBinaryData *group_name,
    size_t member_num,
    Org__E2eelab__Skissm__Proto__E2eeAddress **member_addresses
) {
    this_handler->group_name = (ProtobufCBinaryData *) malloc(sizeof(ProtobufCBinaryData));
    copy_protobuf_from_protobuf(this_handler->group_name, group_name);
    this_handler->member_num = member_num;
    copy_member_addresses_from_member_addresses(&(this_handler->member_addresses), (const Org__E2eelab__Skissm__Proto__E2eeAddress **)member_addresses, member_num);
}

static void handle_get_group_release(
    get_group_response_handler *this_handler
) {
    this_handler->group_address = NULL;
    free_mem((void **)&(this_handler->group_name->data), this_handler->group_name->len);
    free_mem((void **)&(this_handler->group_name), sizeof(ProtobufCBinaryData));
    this_handler->group_name = NULL;
    free_member_addresses(&(this_handler->member_addresses), this_handler->member_num);
    this_handler->member_num = 0;
}

get_group_response_handler get_group_response_handler_store = {
    NULL,
    NULL,
    0,
    NULL,
    handle_get_group_response,
    handle_get_group_release
};

static void handle_add_group_members_response(
    add_group_members_response_handler *this_handler
) {
    Org__E2eelab__Skissm__Proto__E2eeAddress *sender_address = this_handler->outbound_group_session->session_owner;
    Org__E2eelab__Skissm__Proto__E2eeAddress *group_address = this_handler->outbound_group_session->group_address;

    size_t old_member_num = this_handler->outbound_group_session->n_member_addresses;
    size_t member_num = old_member_num + this_handler->adding_member_num;
    Org__E2eelab__Skissm__Proto__E2eeAddress **member_addresses = (Org__E2eelab__Skissm__Proto__E2eeAddress **) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeAddress *) * member_num);
    size_t i;
    for (i = 0; i < old_member_num; i++){
        copy_address_from_address(&(member_addresses[i]), (this_handler->outbound_group_session->member_addresses)[i]);
    }
    for (i = old_member_num; i < member_num; i++){
        copy_address_from_address(&(member_addresses[i]), (this_handler->adding_member_addresses)[i - old_member_num]);
    }

    /* delete the old outbound group session */
    get_ssm_plugin()->unload_group_session(this_handler->outbound_group_session);
    ProtobufCBinaryData *old_session_id = &(this_handler->outbound_group_session->session_id);

    /* generate a new outbound group session */
    create_outbound_group_session(sender_address, group_address, member_addresses, member_num, old_session_id);
}

static void handle_add_group_members_release(
    add_group_members_response_handler *this_handler
) {
    org__e2eelab__skissm__proto__e2ee_group_session__free_unpacked(this_handler->outbound_group_session, NULL);
    this_handler->outbound_group_session = NULL;
    this_handler->adding_member_addresses = NULL;
    this_handler->adding_member_num = 0;
}

add_group_members_response_handler add_group_members_response_handler_store = {
    NULL,
    NULL,
    0,
    handle_add_group_members_response,
    handle_add_group_members_release
};

static void handle_remove_group_members_response(
    remove_group_members_response_handler *this_handler
) {
    Org__E2eelab__Skissm__Proto__E2eeAddress *sender_address = this_handler->outbound_group_session->session_owner;
    Org__E2eelab__Skissm__Proto__E2eeAddress *group_address = this_handler->outbound_group_session->group_address;

    size_t original_member_num = this_handler->outbound_group_session->n_member_addresses;
    size_t member_num = original_member_num - this_handler->removing_member_num;
    Org__E2eelab__Skissm__Proto__E2eeAddress **member_addresses = (Org__E2eelab__Skissm__Proto__E2eeAddress **) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeAddress *) * member_num);
    size_t i, j;
    for (j = 0; j < this_handler->removing_member_num; j++){
        for (i = 0; i < original_member_num; i++){
            if (compare_address((this_handler->outbound_group_session->member_addresses)[i], (this_handler->removing_member_addresses)[j])){
                org__e2eelab__skissm__proto__e2ee_address__free_unpacked((this_handler->outbound_group_session->member_addresses)[i], NULL);
                (this_handler->outbound_group_session->member_addresses)[i] = NULL;
                break;
            }
        }
    }
    i = 0, j = 0;
    while (i < member_num){
        if ((this_handler->outbound_group_session->member_addresses)[i + j] != NULL){
            copy_address_from_address(&(member_addresses[i]), (this_handler->outbound_group_session->member_addresses)[i + j]);
            i++;
        } else{
            j++;
        }
    }

    /* delete the old outbound group session */
    get_ssm_plugin()->unload_group_session(this_handler->outbound_group_session);
    ProtobufCBinaryData *old_session_id = &(this_handler->outbound_group_session->session_id);

    /* generate a new outbound group session */
    create_outbound_group_session(sender_address, group_address, member_addresses, member_num, old_session_id);
}

static void handle_remove_group_members_release(
    remove_group_members_response_handler *this_handler
) {
    org__e2eelab__skissm__proto__e2ee_group_session__free_unpacked(this_handler->outbound_group_session, NULL);
    this_handler->outbound_group_session = NULL;
    this_handler->removing_member_addresses = NULL;
    this_handler->removing_member_num = 0;
}

remove_group_members_response_handler remove_group_members_response_handler_store = {
    NULL,
    NULL,
    0,
    handle_remove_group_members_response,
    handle_remove_group_members_release
};

void create_group(
    Org__E2eelab__Skissm__Proto__E2eeAddress *user_address,
    ProtobufCBinaryData *group_name,
    Org__E2eelab__Skissm__Proto__E2eeAddress **member_addresses,
    size_t member_num
) {
    create_group_response_handler_store.sender_address = user_address;
    create_group_response_handler_store.group_name = group_name;
    create_group_response_handler_store.member_addresses = member_addresses;
    create_group_response_handler_store.member_num = member_num;
    send_create_group_request(&create_group_response_handler_store);
}

get_group_response_handler *get_group_members(Org__E2eelab__Skissm__Proto__E2eeAddress *group_address){
    get_group_response_handler_store.group_address = group_address;
    send_get_group_request(&get_group_response_handler_store);

    return &get_group_response_handler_store;
}

size_t add_group_members(
    Org__E2eelab__Skissm__Proto__E2eeAddress *sender_address,
    Org__E2eelab__Skissm__Proto__E2eeAddress *group_address,
    Org__E2eelab__Skissm__Proto__E2eeAddress **adding_member_addresses,
    size_t adding_member_num
) {
    get_ssm_plugin()->load_outbound_group_session(sender_address, group_address, &(add_group_members_response_handler_store.outbound_group_session));
    if (add_group_members_response_handler_store.outbound_group_session == NULL){
        ssm_notify_error(BAD_GROUP_SESSION, "add_group_members()");
        return (size_t)(-1);
    }
    add_group_members_response_handler_store.adding_member_addresses = adding_member_addresses;
    add_group_members_response_handler_store.adding_member_num = adding_member_num;

    send_add_group_members_request(&add_group_members_response_handler_store);

    return (size_t)0;
}

void remove_group_members(
    Org__E2eelab__Skissm__Proto__E2eeAddress *sender_address,
    Org__E2eelab__Skissm__Proto__E2eeAddress *group_address,
    Org__E2eelab__Skissm__Proto__E2eeAddress **removing_member_addresses,
    size_t removing_member_num
) {
    get_ssm_plugin()->load_outbound_group_session(sender_address, group_address, &(remove_group_members_response_handler_store.outbound_group_session));
    remove_group_members_response_handler_store.removing_member_addresses = removing_member_addresses;
    remove_group_members_response_handler_store.removing_member_num = removing_member_num;

    send_remove_group_members_request(&remove_group_members_response_handler_store);
}
