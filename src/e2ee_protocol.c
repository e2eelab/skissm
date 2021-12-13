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
#include "skissm/e2ee_protocol.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "skissm/account.h"
#include "skissm/account_manager.h"
#include "skissm/e2ee_protocol_handler.h"
#include "skissm/group_session.h"
#include "skissm/group_session_manager.h"
#include "skissm/mem_util.h"
#include "skissm/session.h"
#include "skissm/session_manager.h"

#define REQUEST_HANDLERS_NUM 1
#define RESPONSE_CMD_FLAG 0x1000

void handle_supply_opks_request(uint32_t num, Skissm__E2eeAddress *address, Skissm__ResponseData **response_data);

void handle_create_group_request(Skissm__E2eeAddress *receiver_address, Skissm__E2eeAddress *group_address,
                                 Skissm__E2eeAddress **member_addresses, size_t member_num, Skissm__ResponseData **response_data);

void handle_add_group_members_request(Skissm__E2eeAddress *receiver_address, Skissm__E2eeAddress *group_address, size_t adding_member_num,
                                      Skissm__E2eeAddress **adding_member_addresses, Skissm__ResponseData **response_data);

void handle_remove_group_members_request(Skissm__E2eeAddress *receiver_address, Skissm__E2eeAddress *group_address, size_t member_num,
                                         Skissm__E2eeAddress **member_addresses, Skissm__ResponseData **response_data);

typedef struct handler_entry_node {
    uint32_t key;
    void *handler;
    struct handler_entry_node *next;
} handler_entry_node;

static Skissm__E2eeAccount *_account = NULL;

static volatile uint32_t request_id = 0;

static volatile handler_entry *request_handlers_map[REQUEST_HANDLERS_NUM] = {NULL};
static volatile uint8_t next_request_handler_pos = 0;

static volatile handler_entry_node *response_handlers_map = NULL;

void protocol_begin() {
    request_id = 0;
    next_request_handler_pos = 0;
    handler_entry *entry = (handler_entry *)malloc(sizeof(handler_entry));
    entry->key = SKISSM__E2EE_COMMANDS__supply_opks_request;
    entry->handler = handle_supply_opks_request;
    add_request_handler(entry);
    response_handlers_map = NULL;
}

void protocol_end() {
    unsigned short i;
    for (i = 0; i < REQUEST_HANDLERS_NUM; i++) {
        if (request_handlers_map[i]) {
            free((void *)request_handlers_map[i]);
            request_handlers_map[i] = NULL;
        }
    }
    destroy_response_handlers_map();
}

uint32_t next_request_id() { return request_id++; }

void add_request_handler(handler_entry *entry) {
    request_handlers_map[next_request_handler_pos] = entry;
    next_request_handler_pos++;
}

void remove_request_handler(handler_entry *entry) {
    unsigned short i;
    for (i = 0; i < REQUEST_HANDLERS_NUM; i++) {
        handler_entry *entry1 = (handler_entry *)request_handlers_map[i];
        if (entry->key == entry1->key) {
            request_handlers_map[i] = NULL;
            next_request_handler_pos--;
            return;
        }
    }
}

void *get_request_handler(Skissm__E2eeCommands cmd) {
    unsigned short i;
    for (i = 0; i < REQUEST_HANDLERS_NUM; i++) {
        handler_entry *entry = (handler_entry *)request_handlers_map[i];
        if (((uint32_t)cmd) == entry->key) {
            return entry->handler;
        }
    }
    return NULL;
}

void insert_response_handler(uint32_t id, void *response_handler) {
    handler_entry_node *prev = (handler_entry_node *)response_handlers_map;
    handler_entry_node *cur;
    if (prev != NULL) {
        while (prev->next != NULL)
            prev = prev->next;
    }
    cur = (handler_entry_node *)malloc(sizeof(handler_entry_node));
    cur->key = id;
    cur->handler = response_handler;
    cur->next = NULL;
    if (prev != NULL) {
        prev->next = cur;
    } else {
        response_handlers_map = cur;
    }
}

void delete_response_handler(uint32_t id) {
    handler_entry_node *cur = (handler_entry_node *)response_handlers_map;
    handler_entry_node *prev = NULL;
    while (cur != NULL) {
        if (cur->key == id) {
            if (prev != NULL) {
                prev->next = cur->next;
                free(cur);
            } else {
                response_handlers_map = cur->next;
                free(cur);
            }
            return;
        }
        prev = cur;
        cur = cur->next;
    }
}

void *get_response_handler(uint32_t id) {
    handler_entry_node *cur = (handler_entry_node *)response_handlers_map;
    while (cur != NULL) {
        if (cur->key == id) {
            return cur->handler;
        }
        cur = cur->next;
    }
    return NULL;
}

void destroy_response_handlers_map() {
    handler_entry_node *cur = (handler_entry_node *)response_handlers_map;
    handler_entry_node *prev = NULL;
    while (cur != NULL) {
        prev = cur;
        cur = cur->next;
        free(prev);
    }
    response_handlers_map = NULL;
}

void send_register_user_request(Skissm__E2eeAccount *account, register_user_response_handler *response_handler) {
    Skissm__E2eeProtocolMsg *e2ee_command_request = (Skissm__E2eeProtocolMsg *)malloc(sizeof(Skissm__E2eeProtocolMsg));
    skissm__e2ee_protocol_msg__init(e2ee_command_request);

    e2ee_command_request->cmd = SKISSM__E2EE_COMMANDS__register_user_request;
    e2ee_command_request->id = next_request_id();
    Skissm__RegisterUserRequestPayload *payload = produce_register_request_payload(account);

    e2ee_command_request->payload.len = skissm__register_user_request_payload__get_packed_size(payload);
    e2ee_command_request->payload.data = (uint8_t *)malloc(sizeof(uint8_t) * e2ee_command_request->payload.len);
    skissm__register_user_request_payload__pack(payload, e2ee_command_request->payload.data);

    size_t packed_message_len = skissm__e2ee_protocol_msg__get_packed_size(e2ee_command_request);
    uint8_t *packed_message = (uint8_t *)malloc(sizeof(uint8_t) * packed_message_len);
    skissm__e2ee_protocol_msg__pack(e2ee_command_request, packed_message);

    // done
    insert_response_handler(e2ee_command_request->id, response_handler);
    get_ssm_plugin()->handle_send(packed_message, packed_message_len);

    // release
    skissm__e2ee_protocol_msg__free_unpacked(e2ee_command_request, NULL);
    free_mem((void **)&packed_message, packed_message_len);
}

void send_publish_spk_request(Skissm__E2eeAccount *account, publish_spk_response_handler *response_handler) {
    Skissm__E2eeProtocolMsg *e2ee_command_request = (Skissm__E2eeProtocolMsg *)malloc(sizeof(Skissm__E2eeProtocolMsg));
    skissm__e2ee_protocol_msg__init(e2ee_command_request);

    e2ee_command_request->cmd = SKISSM__E2EE_COMMANDS__publish_spk_request;
    e2ee_command_request->id = next_request_id();

    Skissm__PublishSpkRequestPayload *publish_spk_message = produce_publish_spk_request_payload(account);

    e2ee_command_request->payload.len = skissm__publish_spk_request_payload__get_packed_size(publish_spk_message);
    e2ee_command_request->payload.data = (uint8_t *)malloc(sizeof(uint8_t) * e2ee_command_request->payload.len);
    skissm__publish_spk_request_payload__pack(publish_spk_message, e2ee_command_request->payload.data);

    size_t packed_message_len = skissm__e2ee_protocol_msg__get_packed_size(e2ee_command_request);
    uint8_t *packed_message = (uint8_t *)malloc(sizeof(uint8_t) * packed_message_len);
    skissm__e2ee_protocol_msg__pack(e2ee_command_request, packed_message);

    // done
    insert_response_handler(e2ee_command_request->id, response_handler);
    get_ssm_plugin()->handle_send(packed_message, packed_message_len);

    skissm__e2ee_protocol_msg__free_unpacked(e2ee_command_request, NULL);
    free_mem((void **)&packed_message, packed_message_len);
}

void handle_supply_opks_request(uint32_t num, Skissm__E2eeAddress *address, Skissm__ResponseData **response_data) {
    _account = get_local_account(address);
    Skissm__OneTimePreKeyPair **inserted_one_time_pre_key_pair_list = generate_opks((size_t)num, _account);

    *response_data = (Skissm__ResponseData *)malloc(sizeof(Skissm__ResponseData));
    skissm__response_data__init(*response_data);
    Skissm__SupplyOpksResponsePayload *supply_opks_response =
        (Skissm__SupplyOpksResponsePayload *)malloc(sizeof(Skissm__SupplyOpksResponsePayload));
    skissm__supply_opks_response_payload__init(supply_opks_response);
    supply_opks_response->n_one_time_pre_key_public = (size_t)num;
    supply_opks_response->one_time_pre_key_public = (Skissm__OneTimePreKeyPublic **)malloc(sizeof(Skissm__OneTimePreKeyPublic *) * num);

    unsigned int i;
    for (i = 0; i < num; i++) {
        supply_opks_response->one_time_pre_key_public[i] = (Skissm__OneTimePreKeyPublic *)malloc(sizeof(Skissm__OneTimePreKeyPublic));
        skissm__one_time_pre_key_public__init(supply_opks_response->one_time_pre_key_public[i]);
        supply_opks_response->one_time_pre_key_public[i]->opk_id = inserted_one_time_pre_key_pair_list[i]->opk_id;
        copy_protobuf_from_protobuf(&(supply_opks_response->one_time_pre_key_public[i]->public_key), &(inserted_one_time_pre_key_pair_list[i]->key_pair->public_key));
    }

    copy_address_from_address(&(supply_opks_response->user_address), _account->address);

    /* code */
    (*response_data)->code = OK;
    size_t payload_length = skissm__supply_opks_response_payload__get_packed_size(supply_opks_response);
    (*response_data)->data.len = payload_length;
    (*response_data)->data.data = (uint8_t *)malloc(sizeof(uint8_t) * payload_length);
    skissm__supply_opks_response_payload__pack(supply_opks_response, (*response_data)->data.data);

    /* release */
    skissm__supply_opks_response_payload__free_unpacked(supply_opks_response, NULL);
}

void handle_create_group_request(Skissm__E2eeAddress *receiver_address, Skissm__E2eeAddress *group_address,
                                 Skissm__E2eeAddress **member_addresses, size_t member_num, Skissm__ResponseData **response_data) {
    /* create a new outbound group session */
    create_outbound_group_session(receiver_address, group_address, member_addresses, member_num, NULL);

    /* prepare the response payload */
    *response_data = (Skissm__ResponseData *)malloc(sizeof(Skissm__ResponseData));
    skissm__response_data__init(*response_data);
    Skissm__CreateGroupResponsePayload *create_group_response_payload =
        (Skissm__CreateGroupResponsePayload *)malloc(sizeof(Skissm__CreateGroupResponsePayload));
    skissm__create_group_response_payload__init(create_group_response_payload);

    /* code */
    (*response_data)->code = OK;
    (*response_data)->data.len = skissm__create_group_response_payload__get_packed_size(create_group_response_payload);
    (*response_data)->data.data = (uint8_t *)malloc(sizeof(uint8_t) * (*response_data)->data.len);
    skissm__create_group_response_payload__pack(create_group_response_payload, (*response_data)->data.data);

    /* release */
    skissm__create_group_response_payload__free_unpacked(create_group_response_payload, NULL);
}

void handle_add_group_members_request(Skissm__E2eeAddress *receiver_address, Skissm__E2eeAddress *group_address, size_t adding_member_num,
                                      Skissm__E2eeAddress **adding_member_addresses, Skissm__ResponseData **response_data) {
    Skissm__E2eeGroupSession *group_session = NULL;
    get_ssm_plugin()->load_outbound_group_session(receiver_address, group_address, &group_session);

    // TODO: compare adding_member_addresses

    if (group_session != NULL) {
        size_t new_member_num = group_session->n_member_addresses + adding_member_num;
        Skissm__E2eeAddress **new_member_addresses = (Skissm__E2eeAddress **)malloc(sizeof(Skissm__E2eeAddress *) * new_member_num);
        size_t i;
        for (i = 0; i < group_session->n_member_addresses; i++) {
            copy_address_from_address(&(new_member_addresses[i]), (group_session->member_addresses)[i]);
        }
        for (i = 0; i < adding_member_num; i++) {
            copy_address_from_address(&(new_member_addresses[group_session->n_member_addresses + i]), adding_member_addresses[i]);
        }
        /* delete the old group session */
        get_ssm_plugin()->unload_group_session(group_session);
        ProtobufCBinaryData *old_session_id = &(group_session->session_id);

        /* create a new outbound group session */
        create_outbound_group_session(receiver_address, group_address, new_member_addresses, new_member_num, old_session_id);
    } else {
        get_group_response_handler *handler = get_group_members(group_address);
        create_outbound_group_session(receiver_address, group_address, handler->member_addresses, handler->member_num, NULL);
    }

    /* prepare the response payload */
    *response_data = (Skissm__ResponseData *)malloc(sizeof(Skissm__ResponseData));
    skissm__response_data__init(*response_data);

    /* code */
    (*response_data)->code = OK;
}

void handle_remove_group_members_request(Skissm__E2eeAddress *receiver_address, Skissm__E2eeAddress *group_address, size_t removing_member_num,
                                         Skissm__E2eeAddress **removing_member_addresses, Skissm__ResponseData **response_data) {
    Skissm__E2eeGroupSession *group_session = NULL;
    get_ssm_plugin()->load_outbound_group_session(receiver_address, group_address, &group_session);

    size_t new_member_num = group_session->n_member_addresses - removing_member_num;
    Skissm__E2eeAddress **new_member_addresses = (Skissm__E2eeAddress **)malloc(sizeof(Skissm__E2eeAddress *) * new_member_num);
    size_t i = 0, j = 0;
    while (i < group_session->n_member_addresses) {
        if (j < removing_member_num) {
            if (compare_address(group_session->member_addresses[i], removing_member_addresses[j])) {
                i++;
                j++;
            } else {
                copy_address_from_address(&(new_member_addresses[i - j]), group_session->member_addresses[i]);
                i++;
            }
        } else {
            copy_address_from_address(&(new_member_addresses[i - j]), group_session->member_addresses[i]);
            i++;
        }
    }
    /* delete the old group session */
    get_ssm_plugin()->unload_group_session(group_session);
    ProtobufCBinaryData *old_session_id = &(group_session->session_id);

    /* create a new outbound group session */
    create_outbound_group_session(receiver_address, group_address, new_member_addresses, new_member_num, old_session_id);

    /* prepare the response payload */
    *response_data = (Skissm__ResponseData *)malloc(sizeof(Skissm__ResponseData));
    skissm__response_data__init(*response_data);

    /* code */
    (*response_data)->code = OK;
}

void send_supply_opks_response(uint32_t request_id, Skissm__ResponseData *response_data, supply_opks_handler *handler, Skissm__E2eeAddress *user_address) {
    Skissm__E2eeProtocolMsg *e2ee_command_request = (Skissm__E2eeProtocolMsg *)malloc(sizeof(Skissm__E2eeProtocolMsg));
    skissm__e2ee_protocol_msg__init(e2ee_command_request);

    e2ee_command_request->cmd = SKISSM__E2EE_COMMANDS__supply_opks_response;
    e2ee_command_request->id = request_id;

    e2ee_command_request->payload.len = skissm__response_data__get_packed_size(response_data);
    e2ee_command_request->payload.data = (uint8_t *)malloc(sizeof(uint8_t) * e2ee_command_request->payload.len);
    skissm__response_data__pack(response_data, e2ee_command_request->payload.data);

    size_t packed_message_len = skissm__e2ee_protocol_msg__get_packed_size(e2ee_command_request);
    uint8_t *packed_message = (uint8_t *)malloc(sizeof(uint8_t) * packed_message_len);
    skissm__e2ee_protocol_msg__pack(e2ee_command_request, packed_message);

    // done
    int result = get_ssm_plugin()->handle_send(packed_message, packed_message_len);
    if (result == 0) {
        handler->account = get_local_account(user_address);
        supply_opks(handler);
    }

    /* release */
    skissm__e2ee_protocol_msg__free_unpacked(e2ee_command_request, NULL);
    free_mem((void **)&packed_message, packed_message_len);
}

void send_create_group_response(uint32_t request_id, Skissm__ResponseData *response_data) {
    Skissm__E2eeProtocolMsg *e2ee_command_request = (Skissm__E2eeProtocolMsg *)malloc(sizeof(Skissm__E2eeProtocolMsg));
    skissm__e2ee_protocol_msg__init(e2ee_command_request);

    e2ee_command_request->cmd = SKISSM__E2EE_COMMANDS__create_group_response;
    e2ee_command_request->id = request_id;

    e2ee_command_request->payload.len = skissm__response_data__get_packed_size(response_data);
    e2ee_command_request->payload.data = (uint8_t *)malloc(sizeof(uint8_t) * e2ee_command_request->payload.len);
    skissm__response_data__pack(response_data, e2ee_command_request->payload.data);

    size_t packed_message_len = skissm__e2ee_protocol_msg__get_packed_size(e2ee_command_request);
    uint8_t *packed_message = (uint8_t *)malloc(sizeof(uint8_t) * packed_message_len);
    skissm__e2ee_protocol_msg__pack(e2ee_command_request, packed_message);

    get_ssm_plugin()->handle_send(packed_message, packed_message_len);

    /* release */
    skissm__e2ee_protocol_msg__free_unpacked(e2ee_command_request, NULL);
    free_mem((void **)&packed_message, packed_message_len);
}

void send_add_group_members_response(uint32_t request_id, Skissm__ResponseData *response_data) {
    Skissm__E2eeProtocolMsg *e2ee_command_request = (Skissm__E2eeProtocolMsg *)malloc(sizeof(Skissm__E2eeProtocolMsg));
    skissm__e2ee_protocol_msg__init(e2ee_command_request);

    e2ee_command_request->cmd = SKISSM__E2EE_COMMANDS__add_group_members_response;
    e2ee_command_request->id = request_id;

    e2ee_command_request->payload.len = skissm__response_data__get_packed_size(response_data);
    e2ee_command_request->payload.data = (uint8_t *)malloc(sizeof(uint8_t) * e2ee_command_request->payload.len);
    skissm__response_data__pack(response_data, e2ee_command_request->payload.data);

    size_t packed_message_len = skissm__e2ee_protocol_msg__get_packed_size(e2ee_command_request);
    uint8_t *packed_message = (uint8_t *)malloc(sizeof(uint8_t) * packed_message_len);
    skissm__e2ee_protocol_msg__pack(e2ee_command_request, packed_message);

    get_ssm_plugin()->handle_send(packed_message, packed_message_len);

    /* release */
    skissm__e2ee_protocol_msg__free_unpacked(e2ee_command_request, NULL);
    free_mem((void **)&packed_message, packed_message_len);
}

void send_remove_group_members_response(uint32_t request_id, Skissm__ResponseData *response_data) {
    Skissm__E2eeProtocolMsg *e2ee_command_request = (Skissm__E2eeProtocolMsg *)malloc(sizeof(Skissm__E2eeProtocolMsg));
    skissm__e2ee_protocol_msg__init(e2ee_command_request);

    e2ee_command_request->cmd = SKISSM__E2EE_COMMANDS__remove_group_members_response;
    e2ee_command_request->id = request_id;

    e2ee_command_request->payload.len = skissm__response_data__get_packed_size(response_data);
    e2ee_command_request->payload.data = (uint8_t *)malloc(sizeof(uint8_t) * e2ee_command_request->payload.len);
    skissm__response_data__pack(response_data, e2ee_command_request->payload.data);

    size_t packed_message_len = skissm__e2ee_protocol_msg__get_packed_size(e2ee_command_request);
    uint8_t *packed_message = (uint8_t *)malloc(sizeof(uint8_t) * packed_message_len);
    skissm__e2ee_protocol_msg__pack(e2ee_command_request, packed_message);

    get_ssm_plugin()->handle_send(packed_message, packed_message_len);

    /* release */
    skissm__e2ee_protocol_msg__free_unpacked(e2ee_command_request, NULL);
    free_mem((void **)&packed_message, packed_message_len);
}

void send_get_pre_key_bundle_request(Skissm__E2eeAddress *to, pre_key_bundle_response_handler *response_handler) {
    Skissm__E2eeProtocolMsg *e2ee_command_request = (Skissm__E2eeProtocolMsg *)malloc(sizeof(Skissm__E2eeProtocolMsg));
    skissm__e2ee_protocol_msg__init(e2ee_command_request);

    e2ee_command_request->cmd = SKISSM__E2EE_COMMANDS__get_pre_key_bundle_request;
    e2ee_command_request->id = next_request_id();

    Skissm__GetPreKeyBundleRequestPayload *get_pre_key_bundle_request_payload = produce_get_pre_key_bundle_request_payload(to);

    e2ee_command_request->payload.len = skissm__get_pre_key_bundle_request_payload__get_packed_size(get_pre_key_bundle_request_payload);
    e2ee_command_request->payload.data = (uint8_t *)malloc(sizeof(uint8_t) * e2ee_command_request->payload.len);
    skissm__get_pre_key_bundle_request_payload__pack(get_pre_key_bundle_request_payload, e2ee_command_request->payload.data);

    size_t packed_message_len = skissm__e2ee_protocol_msg__get_packed_size(e2ee_command_request);
    uint8_t *packed_message = (uint8_t *)malloc(sizeof(uint8_t) * packed_message_len);
    skissm__e2ee_protocol_msg__pack(e2ee_command_request, packed_message);

    // done
    insert_response_handler(e2ee_command_request->id, response_handler);
    get_ssm_plugin()->handle_send(packed_message, packed_message_len);

    // release
    skissm__e2ee_protocol_msg__free_unpacked(e2ee_command_request, NULL);
    skissm__get_pre_key_bundle_request_payload__free_unpacked(get_pre_key_bundle_request_payload, NULL);
}

void send_one2one_msg(Skissm__E2eeSession *outbound_session, const uint8_t *e2ee_plaintext, size_t e2ee_plaintext_len) {
    Skissm__E2eeMessage *outbound_e2ee_message_payload = produce_e2ee_message_payload(outbound_session, e2ee_plaintext, e2ee_plaintext_len);
    Skissm__E2eeProtocolMsg *protocol_msg = (Skissm__E2eeProtocolMsg *)malloc(sizeof(Skissm__E2eeProtocolMsg));
    skissm__e2ee_protocol_msg__init(protocol_msg);
    protocol_msg->cmd = SKISSM__E2EE_COMMANDS__send_one2one_msg_request;

    protocol_msg->payload.len = skissm__e2ee_message__get_packed_size(outbound_e2ee_message_payload);
    protocol_msg->payload.data = (uint8_t *)malloc(protocol_msg->payload.len);
    skissm__e2ee_message__pack(outbound_e2ee_message_payload, protocol_msg->payload.data);

    size_t message_len = skissm__e2ee_protocol_msg__get_packed_size(protocol_msg);
    uint8_t *message = (uint8_t *)malloc(sizeof(uint8_t) * message_len);
    skissm__e2ee_protocol_msg__pack(protocol_msg, message);

    // send message to server
    get_ssm_plugin()->handle_send(message, message_len);

    // store sesson state
    get_ssm_plugin()->store_session(outbound_session);

    // release
    free_mem((void **)(&message), message_len);
    skissm__e2ee_message__free_unpacked(outbound_e2ee_message_payload, NULL);
    skissm__e2ee_protocol_msg__free_unpacked(protocol_msg, NULL);
}

void send_group_msg(Skissm__E2eeGroupSession *group_session, const uint8_t *plaintext, size_t plaintext_len) {
    Skissm__E2eeMessage *group_message = produce_group_msg(group_session, plaintext, plaintext_len);

    /* Prepare the e2ee protocol message */
    Skissm__E2eeProtocolMsg *protocol_msg = (Skissm__E2eeProtocolMsg *) malloc(sizeof(Skissm__E2eeProtocolMsg));
    skissm__e2ee_protocol_msg__init(protocol_msg);
    protocol_msg->cmd = SKISSM__E2EE_COMMANDS__send_group_msg_request;

    /* Pack the e2ee message into the e2ee protocol message */
    protocol_msg->payload.len = skissm__e2ee_message__get_packed_size(group_message);
    protocol_msg->payload.data = (uint8_t *) malloc(protocol_msg->payload.len);
    skissm__e2ee_message__pack(group_message, protocol_msg->payload.data);

    /* Pack the e2ee protocol message */
    size_t message_len = skissm__e2ee_protocol_msg__get_packed_size(protocol_msg);
    uint8_t *message = (uint8_t *) malloc(sizeof(uint8_t) * message_len);
    skissm__e2ee_protocol_msg__pack(protocol_msg, message);

    /* send message to server */
    get_ssm_plugin()->handle_send(message, message_len);

    /* store sesson state */
    get_ssm_plugin()->store_group_session(group_session);

    /* release */
    skissm__e2ee_message__free_unpacked(group_message, NULL);
    skissm__e2ee_protocol_msg__free_unpacked(protocol_msg, NULL);
}

size_t send_e2ee_protocol_msg(Skissm__E2eeSession *outbound_session, const uint8_t *plaintext, size_t plaintext_len) {
    Skissm__E2eeMessage *outbound_e2ee_message_payload = produce_e2ee_message_payload(outbound_session, plaintext, plaintext_len);
    Skissm__E2eeProtocolMsg *protocol_msg = (Skissm__E2eeProtocolMsg *)malloc(sizeof(Skissm__E2eeProtocolMsg));
    skissm__e2ee_protocol_msg__init(protocol_msg);
    protocol_msg->cmd = SKISSM__E2EE_COMMANDS__send_one2one_msg_request;

    protocol_msg->payload.len = skissm__e2ee_message__get_packed_size(outbound_e2ee_message_payload);
    protocol_msg->payload.data = (uint8_t *)malloc(protocol_msg->payload.len);
    skissm__e2ee_message__pack(outbound_e2ee_message_payload, protocol_msg->payload.data);

    size_t message_len = skissm__e2ee_protocol_msg__get_packed_size(protocol_msg);
    uint8_t *message = (uint8_t *)malloc(sizeof(uint8_t) * message_len);
    skissm__e2ee_protocol_msg__pack(protocol_msg, message);

    // send message to server
    get_ssm_plugin()->handle_send(message, message_len);

    // store sesson state
    get_ssm_plugin()->store_session(outbound_session);

    // release
    free_mem((void **)(&message), message_len);
    skissm__e2ee_message__free_unpacked(outbound_e2ee_message_payload, NULL);
    skissm__e2ee_protocol_msg__free_unpacked(protocol_msg, NULL);

    // done
    return message_len;
}

void send_create_group_request(create_group_response_handler *response_handler) {
    Skissm__E2eeProtocolMsg *e2ee_command_request = (Skissm__E2eeProtocolMsg *)malloc(sizeof(Skissm__E2eeProtocolMsg));
    skissm__e2ee_protocol_msg__init(e2ee_command_request);

    e2ee_command_request->cmd = SKISSM__E2EE_COMMANDS__create_group_request;
    e2ee_command_request->id = next_request_id();

    Skissm__CreateGroupRequestPayload *create_group_request_payload = produce_create_group_request_payload(
        response_handler->sender_address,
        response_handler->group_name,
        response_handler->member_num,
        response_handler->member_addresses);

    e2ee_command_request->payload.len = skissm__create_group_request_payload__get_packed_size(create_group_request_payload);
    e2ee_command_request->payload.data = (uint8_t *)malloc(sizeof(uint8_t) * e2ee_command_request->payload.len);
    skissm__create_group_request_payload__pack(create_group_request_payload, e2ee_command_request->payload.data);

    size_t packed_message_len = skissm__e2ee_protocol_msg__get_packed_size(e2ee_command_request);
    uint8_t *packed_message = (uint8_t *)malloc(sizeof(uint8_t) * packed_message_len);
    skissm__e2ee_protocol_msg__pack(e2ee_command_request, packed_message);

    // done
    insert_response_handler(e2ee_command_request->id, response_handler);
    get_ssm_plugin()->handle_send(packed_message, packed_message_len);

    // release
    skissm__e2ee_protocol_msg__free_unpacked(e2ee_command_request, NULL);
    skissm__create_group_request_payload__free_unpacked(create_group_request_payload, NULL);
}

void send_get_group_request(get_group_response_handler *response_handler) {
    Skissm__E2eeProtocolMsg *e2ee_command_request = (Skissm__E2eeProtocolMsg *)malloc(sizeof(Skissm__E2eeProtocolMsg));
    skissm__e2ee_protocol_msg__init(e2ee_command_request);

    e2ee_command_request->cmd = SKISSM__E2EE_COMMANDS__get_group_request;
    e2ee_command_request->id = next_request_id();

    Skissm__GetGroupRequestPayload *get_group_request_payload = produce_get_group_request_payload(response_handler->group_address);

    e2ee_command_request->payload.len = skissm__get_group_request_payload__get_packed_size(get_group_request_payload);
    e2ee_command_request->payload.data = (uint8_t *)malloc(sizeof(uint8_t) * e2ee_command_request->payload.len);
    skissm__get_group_request_payload__pack(get_group_request_payload, e2ee_command_request->payload.data);

    size_t packed_message_len = skissm__e2ee_protocol_msg__get_packed_size(e2ee_command_request);
    uint8_t *packed_message = (uint8_t *)malloc(sizeof(uint8_t) * packed_message_len);
    skissm__e2ee_protocol_msg__pack(e2ee_command_request, packed_message);

    // done
    insert_response_handler(e2ee_command_request->id, response_handler);
    get_ssm_plugin()->handle_send(packed_message, packed_message_len);

    // release
    skissm__e2ee_protocol_msg__free_unpacked(e2ee_command_request, NULL);
    skissm__get_group_request_payload__free_unpacked(get_group_request_payload, NULL);
}

void send_add_group_members_request(add_group_members_response_handler *response_handler) {
    Skissm__E2eeProtocolMsg *e2ee_command_request = (Skissm__E2eeProtocolMsg *)malloc(sizeof(Skissm__E2eeProtocolMsg));
    skissm__e2ee_protocol_msg__init(e2ee_command_request);

    e2ee_command_request->cmd = SKISSM__E2EE_COMMANDS__add_group_members_request;
    e2ee_command_request->id = next_request_id();

    Skissm__AddGroupMembersRequestPayload *add_group_member_msg =
        (Skissm__AddGroupMembersRequestPayload *)malloc(sizeof(Skissm__AddGroupMembersRequestPayload));
    skissm__add_group_members_request_payload__init(add_group_member_msg);

    copy_address_from_address(&(add_group_member_msg->sender_address), response_handler->outbound_group_session->session_owner);
    copy_address_from_address(&(add_group_member_msg->group_address), response_handler->outbound_group_session->group_address);
    add_group_member_msg->n_member_addresses = response_handler->adding_member_num;
    copy_member_addresses_from_member_addresses(&(add_group_member_msg->member_addresses), (const Skissm__E2eeAddress **)response_handler->adding_member_addresses,
                                                response_handler->adding_member_num);

    e2ee_command_request->payload.len = skissm__add_group_members_request_payload__get_packed_size(add_group_member_msg);
    e2ee_command_request->payload.data = (uint8_t *)malloc(sizeof(uint8_t) * e2ee_command_request->payload.len);
    skissm__add_group_members_request_payload__pack(add_group_member_msg, e2ee_command_request->payload.data);

    size_t packed_message_len = skissm__e2ee_protocol_msg__get_packed_size(e2ee_command_request);
    uint8_t *packed_message = (uint8_t *)malloc(sizeof(uint8_t) * packed_message_len);
    skissm__e2ee_protocol_msg__pack(e2ee_command_request, packed_message);

    // done
    insert_response_handler(e2ee_command_request->id, response_handler);
    get_ssm_plugin()->handle_send(packed_message, packed_message_len);

    // release
    skissm__e2ee_protocol_msg__free_unpacked(e2ee_command_request, NULL);
    skissm__add_group_members_request_payload__free_unpacked(add_group_member_msg, NULL);
}

void send_remove_group_members_request(remove_group_members_response_handler *response_handler) {
    Skissm__E2eeProtocolMsg *e2ee_command_request = (Skissm__E2eeProtocolMsg *)malloc(sizeof(Skissm__E2eeProtocolMsg));
    skissm__e2ee_protocol_msg__init(e2ee_command_request);

    e2ee_command_request->cmd = SKISSM__E2EE_COMMANDS__remove_group_members_request;
    e2ee_command_request->id = next_request_id();

    Skissm__RemoveGroupMembersRequestPayload *remove_group_member_msg =
        (Skissm__RemoveGroupMembersRequestPayload *)malloc(sizeof(Skissm__RemoveGroupMembersRequestPayload));
    skissm__remove_group_members_request_payload__init(remove_group_member_msg);

    copy_address_from_address(&(remove_group_member_msg->sender_address), response_handler->outbound_group_session->session_owner);
    copy_address_from_address(&(remove_group_member_msg->group_address), response_handler->outbound_group_session->group_address);
    remove_group_member_msg->n_member_addresses = response_handler->removing_member_num;
    copy_member_addresses_from_member_addresses(&(remove_group_member_msg->member_addresses), (const Skissm__E2eeAddress **)response_handler->removing_member_addresses,
                                                response_handler->removing_member_num);

    e2ee_command_request->payload.len = skissm__remove_group_members_request_payload__get_packed_size(remove_group_member_msg);
    e2ee_command_request->payload.data = (uint8_t *)malloc(sizeof(uint8_t) * e2ee_command_request->payload.len);
    skissm__remove_group_members_request_payload__pack(remove_group_member_msg, e2ee_command_request->payload.data);

    size_t packed_message_len = skissm__e2ee_protocol_msg__get_packed_size(e2ee_command_request);
    uint8_t *packed_message = (uint8_t *)malloc(sizeof(uint8_t) * packed_message_len);
    skissm__e2ee_protocol_msg__pack(e2ee_command_request, packed_message);

    // done
    insert_response_handler(e2ee_command_request->id, response_handler);
    get_ssm_plugin()->handle_send(packed_message, packed_message_len);

    // release
    skissm__e2ee_protocol_msg__free_unpacked(e2ee_command_request, NULL);
    skissm__remove_group_members_request_payload__free_unpacked(remove_group_member_msg, NULL);
}

static void send_receive_msg_response(uint32_t request_id, Skissm__ResponseData *response_data) {
    Skissm__E2eeProtocolMsg *e2ee_protocol_msg = (Skissm__E2eeProtocolMsg *)malloc(sizeof(Skissm__E2eeProtocolMsg));
    skissm__e2ee_protocol_msg__init(e2ee_protocol_msg);

    e2ee_protocol_msg->cmd = SKISSM__E2EE_COMMANDS__send_one2one_msg_response;
    e2ee_protocol_msg->id = request_id;

    response_data->code = OK;

    e2ee_protocol_msg->payload.len = skissm__response_data__get_packed_size(response_data);
    e2ee_protocol_msg->payload.data = (uint8_t *)malloc(sizeof(uint8_t) * e2ee_protocol_msg->payload.len);
    skissm__response_data__pack(response_data, e2ee_protocol_msg->payload.data);

    size_t packed_message_len = skissm__e2ee_protocol_msg__get_packed_size(e2ee_protocol_msg);
    uint8_t *packed_message = (uint8_t *)malloc(sizeof(uint8_t) * packed_message_len);
    skissm__e2ee_protocol_msg__pack(e2ee_protocol_msg, packed_message);

    /* done */
    get_ssm_plugin()->handle_send(packed_message, packed_message_len);

    /* release */
    skissm__e2ee_protocol_msg__free_unpacked(e2ee_protocol_msg, NULL);
}

static void send_receive_group_msg_response(uint32_t request_id, Skissm__ResponseData *response_data) {
    Skissm__E2eeProtocolMsg *e2ee_protocol_msg = (Skissm__E2eeProtocolMsg *)malloc(sizeof(Skissm__E2eeProtocolMsg));
    skissm__e2ee_protocol_msg__init(e2ee_protocol_msg);

    e2ee_protocol_msg->cmd = SKISSM__E2EE_COMMANDS__send_group_msg_response;
    e2ee_protocol_msg->id = request_id;

    response_data->code = OK;

    e2ee_protocol_msg->payload.len = skissm__response_data__get_packed_size(response_data);
    e2ee_protocol_msg->payload.data = (uint8_t *)malloc(sizeof(uint8_t) * e2ee_protocol_msg->payload.len);
    skissm__response_data__pack(response_data, e2ee_protocol_msg->payload.data);

    size_t packed_message_len = skissm__e2ee_protocol_msg__get_packed_size(e2ee_protocol_msg);
    uint8_t *packed_message = (uint8_t *)malloc(sizeof(uint8_t) * packed_message_len);
    skissm__e2ee_protocol_msg__pack(e2ee_protocol_msg, packed_message);

    /* done */
    get_ssm_plugin()->handle_send(packed_message, packed_message_len);

    /* release */
    skissm__e2ee_protocol_msg__free_unpacked(e2ee_protocol_msg, NULL);
}

static void process_request_msg(Skissm__E2eeProtocolMsg *request_msg, Skissm__E2eeAddress *receiver_address) {
    void *request_handler = NULL;
    request_handler = get_request_handler(request_msg->cmd);

    // handle commands
    switch (request_msg->cmd) {
    case SKISSM__E2EE_COMMANDS__supply_opks_request: {
        Skissm__SupplyOpksRequestPayload *request_opks_payload =
            skissm__supply_opks_request_payload__unpack(NULL, request_msg->payload.len, request_msg->payload.data);
        uint32_t num = request_opks_payload->opks_num;
        Skissm__E2eeAddress *user_address = request_opks_payload->user_address;
        Skissm__ResponseData *response_data;
        handle_supply_opks_request(num, user_address, &response_data);

        supply_opks_handler *supply_opks_request_handler = (supply_opks_handler *)request_handler;
        send_supply_opks_response(request_msg->id, response_data, supply_opks_request_handler, user_address);

        // release
        skissm__response_data__free_unpacked(response_data, NULL);
        skissm__supply_opks_request_payload__free_unpacked(request_opks_payload, NULL);
        supply_opks_request_handler->handle_release(supply_opks_request_handler);
    } break;

    case SKISSM__E2EE_COMMANDS__create_group_request: {
        Skissm__CreateGroupRequestPayload *create_group_payload =
            skissm__create_group_request_payload__unpack(NULL, request_msg->payload.len, request_msg->payload.data);
        size_t member_num = create_group_payload->n_member_addresses;
        Skissm__E2eeAddress **member_addresses = create_group_payload->member_addresses;
        Skissm__E2eeAddress *group_address = create_group_payload->group_address;
        Skissm__ResponseData *response_data;
        handle_create_group_request(receiver_address, group_address, member_addresses, member_num, &response_data);
        send_create_group_response(request_msg->id, response_data);

        // release
        skissm__response_data__free_unpacked(response_data, NULL);
        skissm__create_group_request_payload__free_unpacked(create_group_payload, NULL);
    } break;

    case SKISSM__E2EE_COMMANDS__add_group_members_request: {
        Skissm__AddGroupMembersRequestPayload *add_group_members_request_payload =
            skissm__add_group_members_request_payload__unpack(NULL, request_msg->payload.len, request_msg->payload.data);
        Skissm__E2eeAddress *group_address = add_group_members_request_payload->group_address;
        size_t adding_member_num = add_group_members_request_payload->n_member_addresses;
        Skissm__E2eeAddress **adding_member_addresses = add_group_members_request_payload->member_addresses;
        Skissm__ResponseData *response_data;
        handle_add_group_members_request(receiver_address, group_address, adding_member_num, adding_member_addresses, &response_data);
        send_add_group_members_response(request_msg->id, response_data);

        // release
        skissm__response_data__free_unpacked(response_data, NULL);
    } break;

    case SKISSM__E2EE_COMMANDS__remove_group_members_request: {
        Skissm__RemoveGroupMembersRequestPayload *remove_group_members_request_payload =
            skissm__remove_group_members_request_payload__unpack(NULL, request_msg->payload.len, request_msg->payload.data);
        Skissm__E2eeAddress *group_address = remove_group_members_request_payload->group_address;
        size_t removing_member_num = remove_group_members_request_payload->n_member_addresses;
        Skissm__E2eeAddress **removing_member_addresses = remove_group_members_request_payload->member_addresses;
        Skissm__ResponseData *response_data;
        handle_remove_group_members_request(receiver_address, group_address, removing_member_num, removing_member_addresses, &response_data);
        send_remove_group_members_response(request_msg->id, response_data);

        // release
        skissm__response_data__free_unpacked(response_data, NULL);
    } break;

    case SKISSM__E2EE_COMMANDS__send_one2one_msg_request: {
        Skissm__E2eeMessage *receive_msg_payload = skissm__e2ee_message__unpack(NULL, request_msg->payload.len, request_msg->payload.data);

        size_t result = consume_e2ee_message_payload(receive_msg_payload);

        Skissm__ResponseData *response_data = (Skissm__ResponseData *)malloc(sizeof(Skissm__ResponseData));
        skissm__response_data__init(response_data);

        send_receive_msg_response(request_msg->id, response_data);

        // release
        skissm__response_data__free_unpacked(response_data, NULL);
    } break;

    case SKISSM__E2EE_COMMANDS__send_group_msg_request: {
        Skissm__E2eeMessage *received_group_msg_payload = skissm__e2ee_message__unpack(NULL, request_msg->payload.len, request_msg->payload.data);

        Skissm__ResponseData *response_data = (Skissm__ResponseData *)malloc(sizeof(Skissm__ResponseData));
        skissm__response_data__init(response_data);

        consume_group_msg(receiver_address, received_group_msg_payload);

        send_receive_group_msg_response(request_msg->id, response_data);

        // release
        skissm__response_data__free_unpacked(response_data, NULL);
    } break;

    default:
        break;
    }
}

static void process_response_msg(Skissm__E2eeProtocolMsg *response_msg) {
    void *response_handler = NULL;

    response_handler = get_response_handler(response_msg->id);
    if (response_handler == NULL) {
        return;
    }
    delete_response_handler(response_msg->id);

    Skissm__ResponseData *response_data = skissm__response_data__unpack(NULL, response_msg->payload.len, response_msg->payload.data);

    if (response_data == NULL) {
        ssm_notify_error(BAD_SERVER_MESSAGE, "process_response_msg() null response_data");
        return;
    }

    if (response_data->code == OK) {
        // handle commands
        switch (response_msg->cmd) {
        case SKISSM__E2EE_COMMANDS__register_user_response: {
            Skissm__RegisterUserResponsePayload *payload =
                skissm__register_user_response_payload__unpack(NULL, response_data->data.len, response_data->data.data);
            register_user_response_handler *this_response_handler = (register_user_response_handler *)response_handler;
            consume_register_response_payload(this_response_handler->account, payload);
            // release
            this_response_handler->handle_release(this_response_handler);
            skissm__register_user_response_payload__free_unpacked(payload, NULL);
        } break;

        case SKISSM__E2EE_COMMANDS__delete_user_response:
            /* code */
            break;

        case SKISSM__E2EE_COMMANDS__get_pre_key_bundle_response: {
            Skissm__GetPreKeyBundleResponsePayload *get_pre_key_bundle_response_payload =
                skissm__get_pre_key_bundle_response_payload__unpack(NULL, response_data->data.len, response_data->data.data);

            pre_key_bundle_response_handler *this_response_handler = (pre_key_bundle_response_handler *)response_handler;
            Skissm__E2eeAddress *from = this_response_handler->from;
            Skissm__E2eeAddress *to = this_response_handler->to;

            consume_get_pre_key_bundle_response_payload(from, to, get_pre_key_bundle_response_payload);
            // release
            this_response_handler->handle_release(this_response_handler);
            skissm__get_pre_key_bundle_response_payload__free_unpacked(get_pre_key_bundle_response_payload, NULL);
        } break;

        case SKISSM__E2EE_COMMANDS__publish_spk_response: {
            publish_spk_response_handler *this_response_handler = (publish_spk_response_handler *)response_handler;
            consume_publish_spk_response_payload(this_response_handler->account);
            // release
            this_response_handler->handle_release(this_response_handler);
        } break;

        case SKISSM__E2EE_COMMANDS__create_group_response: {
            Skissm__CreateGroupResponsePayload *create_group_response_payload =
                skissm__create_group_response_payload__unpack(NULL, response_data->data.len, response_data->data.data);
            create_group_response_handler *this_response_handler = (create_group_response_handler *)response_handler;
            consume_create_group_response_payload(
                this_response_handler->sender_address,
                this_response_handler->group_name,
                this_response_handler->member_num,
                this_response_handler->member_addresses,
                create_group_response_payload
            );
            // release
            this_response_handler->handle_release(this_response_handler);
            skissm__create_group_response_payload__free_unpacked(create_group_response_payload, NULL);
        } break;

        case SKISSM__E2EE_COMMANDS__get_group_response: {
            Skissm__GetGroupResponsePayload *get_group_response_payload =
                skissm__get_group_response_payload__unpack(NULL, response_data->data.len, response_data->data.data);
            get_group_response_handler *this_response_handler = (get_group_response_handler *)response_handler;
            consume_get_group_response_payload(get_group_response_payload);
            // release
            this_response_handler->handle_release(this_response_handler);
            skissm__get_group_response_payload__free_unpacked(get_group_response_payload, NULL);
        } break;

        case SKISSM__E2EE_COMMANDS__add_group_members_response: {
            add_group_members_response_handler *this_response_handler = (add_group_members_response_handler *)response_handler;
            this_response_handler->handle_response(this_response_handler);
            // release
            this_response_handler->handle_release(this_response_handler);
        } break;

        case SKISSM__E2EE_COMMANDS__remove_group_members_response: {
            remove_group_members_response_handler *this_response_handler = (remove_group_members_response_handler *)response_handler;
            this_response_handler->handle_response(this_response_handler);
            // release
            this_response_handler->handle_release(this_response_handler);
        } break;

        case SKISSM__E2EE_COMMANDS__send_one2one_msg_response: {
            /* code */
        } break;

        default:
            break;
        }
    } else {
        ssm_notify_error(BAD_SERVER_MESSAGE, "process_response_msg() response_data->code != OK");
    }
    // release
    skissm__response_data__free_unpacked(response_data, NULL);
}

void process_protocol_msg(uint8_t *server_msg, size_t server_msg_len, Skissm__E2eeAddress *receiver_address) {
    Skissm__E2eeProtocolMsg *protocol_msg = skissm__e2ee_protocol_msg__unpack(NULL, server_msg_len, server_msg);
    if (protocol_msg == NULL) {
        ssm_notify_error(BAD_SERVER_MESSAGE, "parse_incoming_message()");
        return;
    }

    Skissm__E2eeCommands e2ee_command = protocol_msg->cmd;

    if (e2ee_command & RESPONSE_CMD_FLAG)
        process_response_msg(protocol_msg);
    else
        process_request_msg(protocol_msg, receiver_address);

    // release
    skissm__e2ee_protocol_msg__free_unpacked(protocol_msg, NULL);
}
