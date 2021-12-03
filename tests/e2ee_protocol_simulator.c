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
#include <string.h>
#include <stdio.h>

#include "test_env.h"
#include "e2ee_protocol_simulator.h"
#include "e2ee_protocol.h"
#include "mem_util.h"

typedef struct user_data{
    Skissm__E2eeAddress *address;
    Skissm__RegisterUserRequestPayload *pre_key;
} user_data;

typedef struct group_data{
    Skissm__E2eeAddress *group_address;
    ProtobufCBinaryData group_name;
    size_t member_num;
    Skissm__E2eeAddress **member_addresses;
} group_data;

#define user_data_max 8

#define group_data_max 8

static user_data user_data_set[user_data_max] = {{NULL, NULL},
                                                 {NULL, NULL},
                                                 {NULL, NULL},
                                                 {NULL, NULL},
                                                 {NULL, NULL},
                                                 {NULL, NULL},
                                                 {NULL, NULL},
                                                 {NULL, NULL}};

static group_data group_data_set[user_data_max] = {{NULL, {0, NULL}, 0, NULL},
                                                   {NULL, {0, NULL}, 0, NULL},
                                                   {NULL, {0, NULL}, 0, NULL},
                                                   {NULL, {0, NULL}, 0, NULL},
                                                   {NULL, {0, NULL}, 0, NULL},
                                                   {NULL, {0, NULL}, 0, NULL},
                                                   {NULL, {0, NULL}, 0, NULL},
                                                   {NULL, {0, NULL}, 0, NULL}};

static uint8_t user_data_set_insert_pos = 0;

static uint8_t group_data_set_insert_pos = 0;

void protocol_simulator_begin(){
}

void protocol_simulator_end(){
    uint8_t i, j;
    for (i = 0; i < user_data_set_insert_pos; i++){
        skissm__e2ee_address__free_unpacked(user_data_set[i].address, NULL);
        user_data_set[i].address = NULL;
        skissm__register_user_request_payload__free_unpacked(user_data_set[i].pre_key, NULL);
        user_data_set[i].pre_key = NULL;
    }
    user_data_set_insert_pos = 0;
    for (i = 0; i < group_data_set_insert_pos; i++){
        skissm__e2ee_address__free_unpacked(group_data_set[i].group_address, NULL);
        group_data_set[i].group_address = NULL;
        free_mem((void **)&(group_data_set[i].group_name.data), group_data_set[i].group_name.len);
        group_data_set[i].group_name.len = 0;
        for (j = 0; j < group_data_set[i].member_num; j++){
            skissm__e2ee_address__free_unpacked(group_data_set[i].member_addresses[j], NULL);
            group_data_set[i].member_addresses[j] = NULL;
        }
        group_data_set[i].member_num = 0;
    }
    group_data_set_insert_pos = 0;
}

static void mock_protocol_send(
    Skissm__E2eeProtocolMsg *response,
    Skissm__E2eeAddress *receiver_address
) {
    /* pack response */
    size_t server_msg_len = skissm__e2ee_protocol_msg__get_packed_size(response);
    uint8_t *server_msg = (uint8_t *) malloc(sizeof(uint8_t) * server_msg_len);
    skissm__e2ee_protocol_msg__pack(response, server_msg);

    /* send to client */
    process_protocol_msg(server_msg, server_msg_len, receiver_address);

    /* release */
    free_mem((void **)&server_msg, server_msg_len);
}

static void process_register_user_request(
    Skissm__E2eeProtocolMsg *request,
    Skissm__E2eeProtocolMsg *response
) {
    response->cmd = SKISSM__E2EE_COMMANDS__register_user_response;

    /* unpack */
    Skissm__RegisterUserRequestPayload *payload = skissm__register_user_request_payload__unpack(NULL, request->payload.len, request->payload.data);

    /* prepare to store */
    user_data_set[user_data_set_insert_pos].pre_key = (Skissm__RegisterUserRequestPayload *) malloc(sizeof(Skissm__RegisterUserRequestPayload));
    skissm__register_user_request_payload__init(user_data_set[user_data_set_insert_pos].pre_key);

    copy_protobuf_from_protobuf(&(user_data_set[user_data_set_insert_pos].pre_key->identity_key_public), &(payload->identity_key_public));
    user_data_set[user_data_set_insert_pos].pre_key->signed_pre_key_public = (Skissm__SignedPreKeyPublic *) malloc(sizeof(Skissm__SignedPreKeyPublic));
    skissm__signed_pre_key_public__init(user_data_set[user_data_set_insert_pos].pre_key->signed_pre_key_public);
    user_data_set[user_data_set_insert_pos].pre_key->signed_pre_key_public->spk_id = payload->signed_pre_key_public->spk_id;
    copy_protobuf_from_protobuf(&(user_data_set[user_data_set_insert_pos].pre_key->signed_pre_key_public->public_key), &(payload->signed_pre_key_public->public_key));
    copy_protobuf_from_protobuf(&(user_data_set[user_data_set_insert_pos].pre_key->signed_pre_key_public->signature), &(payload->signed_pre_key_public->signature));
    user_data_set[user_data_set_insert_pos].pre_key->n_one_time_pre_keys = payload->n_one_time_pre_keys;
    user_data_set[user_data_set_insert_pos].pre_key->one_time_pre_keys = (Skissm__OneTimePreKeyPublic **) malloc(sizeof(Skissm__OneTimePreKeyPublic *) * user_data_set[user_data_set_insert_pos].pre_key->n_one_time_pre_keys);
    unsigned int i;
    for (i = 0; i < user_data_set[user_data_set_insert_pos].pre_key->n_one_time_pre_keys; i++){
        user_data_set[user_data_set_insert_pos].pre_key->one_time_pre_keys[i] = (Skissm__OneTimePreKeyPublic *) malloc(sizeof(Skissm__OneTimePreKeyPublic));
        skissm__one_time_pre_key_public__init(user_data_set[user_data_set_insert_pos].pre_key->one_time_pre_keys[i]);
        user_data_set[user_data_set_insert_pos].pre_key->one_time_pre_keys[i]->opk_id = payload->one_time_pre_keys[i]->opk_id;
        copy_protobuf_from_protobuf(&(user_data_set[user_data_set_insert_pos].pre_key->one_time_pre_keys[i]->public_key), &(payload->one_time_pre_keys[i]->public_key));
    }

    Skissm__RegisterUserResponsePayload *register_user_response_payload = (Skissm__RegisterUserResponsePayload *) malloc(sizeof(Skissm__RegisterUserResponsePayload));
    skissm__register_user_response_payload__init(register_user_response_payload);

    /* Generate a random address */
    Skissm__E2eeAddress *random_address = (Skissm__E2eeAddress *) malloc(sizeof(Skissm__E2eeAddress));
    skissm__e2ee_address__init(random_address);
    create_domain(&(random_address->domain));
    random_id(&(random_address->user_id), 32);
    random_id(&(random_address->device_id), 32);

    copy_address_from_address(&(user_data_set[user_data_set_insert_pos].address), random_address);

    user_data_set_insert_pos++;

    register_user_response_payload->address = random_address;

    Skissm__ResponseData *response_data = (Skissm__ResponseData *)malloc(sizeof(Skissm__ResponseData));
    skissm__response_data__init(response_data);

    /* pack */
    response_data->code = OK;
    response_data->data.len = skissm__register_user_response_payload__get_packed_size(register_user_response_payload);
    response_data->data.data = (uint8_t *) malloc(sizeof(uint8_t) *  response_data->data.len);
    skissm__register_user_response_payload__pack(register_user_response_payload, response_data->data.data);

    response->id = request->id;
    response->payload.len = skissm__response_data__get_packed_size(response_data);
    response->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * response->payload.len);
    skissm__response_data__pack(response_data, response->payload.data);

    /* release */
    skissm__response_data__free_unpacked(response_data, NULL);
    skissm__register_user_request_payload__free_unpacked(payload, NULL);
    skissm__register_user_response_payload__free_unpacked(register_user_response_payload, NULL);
}

static void process_delete_user_request(
    Skissm__E2eeProtocolMsg *request,
    Skissm__E2eeProtocolMsg *response
) {
    response->cmd = SKISSM__E2EE_COMMANDS__delete_user_response;

    /* unpack */
    Skissm__DeleteUserRequestPayload *payload = skissm__delete_user_request_payload__unpack(NULL, request->payload.len, request->payload.data);

    uint8_t user_data_find = 0;
    while (user_data_find < user_data_set_insert_pos)
    {
        if ((user_data_set[user_data_find].address) && (payload->address)
            && compare_address(user_data_set[user_data_find].address, payload->address)
        ) {
            break;
        }
        user_data_find++;
    }

    Skissm__ResponseData *response_data = (Skissm__ResponseData *)malloc(sizeof(Skissm__ResponseData));
    skissm__response_data__init(response_data);

    if (user_data_find == user_data_set_insert_pos){
        response_data->code = Internal_Server_Error;
    } else{
        response_data->code = OK;
        skissm__register_user_request_payload__free_unpacked(user_data_set[user_data_find].pre_key, NULL);
        user_data_set[user_data_find].pre_key = NULL;
        skissm__e2ee_address__free_unpacked(user_data_set[user_data_find].address, NULL);
        user_data_set[user_data_find].address = NULL;
        unset((void volatile *)&user_data_set[user_data_find], sizeof(user_data));
    }

    /* pack */
    response->id = request->id;
    response->payload.len = skissm__response_data__get_packed_size(response_data);
    response->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * response->payload.len);
    skissm__response_data__pack(response_data, response->payload.data);

    /* release */
    skissm__response_data__free_unpacked(response_data, NULL);
    skissm__delete_user_request_payload__free_unpacked(payload, NULL);
}

static void process_get_pre_key_bundle_request(
    Skissm__E2eeProtocolMsg *request,
    Skissm__E2eeProtocolMsg *response
) {
    response->cmd = SKISSM__E2EE_COMMANDS__get_pre_key_bundle_response;

    /* unpack */
    Skissm__GetPreKeyBundleRequestPayload *payload = skissm__get_pre_key_bundle_request_payload__unpack(NULL, request->payload.len, request->payload.data);

    /* prepare a response payload */
    Skissm__GetPreKeyBundleResponsePayload *get_pre_key_bundle_response_payload = (Skissm__GetPreKeyBundleResponsePayload *) malloc(sizeof(Skissm__GetPreKeyBundleResponsePayload));
    skissm__get_pre_key_bundle_response_payload__init(get_pre_key_bundle_response_payload);

    uint8_t user_data_find = 0;
    while (user_data_find < user_data_set_insert_pos)
    {
        if ((user_data_set[user_data_find].address) && (payload->peer_address)
            && compare_address(user_data_set[user_data_find].address, payload->peer_address)
        ) {
            break;
        }
        user_data_find++;
    }

    Skissm__ResponseData *response_data = (Skissm__ResponseData *)malloc(sizeof(Skissm__ResponseData));
    skissm__response_data__init(response_data);

    if (user_data_find == user_data_set_insert_pos){
        response_data->code = Internal_Server_Error;
        goto complete;
    }

    get_pre_key_bundle_response_payload->pre_key_bundle = (Skissm__E2eePreKeyBundle *) malloc(sizeof(Skissm__E2eePreKeyBundle));
    skissm__e2ee_pre_key_bundle__init(get_pre_key_bundle_response_payload->pre_key_bundle);

    copy_address_from_address(&(get_pre_key_bundle_response_payload->pre_key_bundle->peer_address), payload->peer_address);
    copy_protobuf_from_protobuf(&(get_pre_key_bundle_response_payload->pre_key_bundle->identity_key_public), &(user_data_set[user_data_find].pre_key->identity_key_public));
    get_pre_key_bundle_response_payload->pre_key_bundle->signed_pre_key_public = (Skissm__SignedPreKeyPublic *) malloc(sizeof(Skissm__SignedPreKeyPublic));
    skissm__signed_pre_key_public__init(get_pre_key_bundle_response_payload->pre_key_bundle->signed_pre_key_public);
    get_pre_key_bundle_response_payload->pre_key_bundle->signed_pre_key_public->spk_id = user_data_set[user_data_find].pre_key->signed_pre_key_public->spk_id;
    copy_protobuf_from_protobuf(&(get_pre_key_bundle_response_payload->pre_key_bundle->signed_pre_key_public->public_key), &(user_data_set[user_data_find].pre_key->signed_pre_key_public->public_key));
    copy_protobuf_from_protobuf(&(get_pre_key_bundle_response_payload->pre_key_bundle->signed_pre_key_public->signature), &(user_data_set[user_data_find].pre_key->signed_pre_key_public->signature));
    uint8_t i;
    for (i = 0; i < user_data_set[user_data_find].pre_key->n_one_time_pre_keys; i++){
        if (user_data_set[user_data_find].pre_key->one_time_pre_keys[i]){
            get_pre_key_bundle_response_payload->pre_key_bundle->one_time_pre_key_public = (Skissm__OneTimePreKeyPublic *) malloc(sizeof(Skissm__OneTimePreKeyPublic));
            skissm__one_time_pre_key_public__init(get_pre_key_bundle_response_payload->pre_key_bundle->one_time_pre_key_public);
            get_pre_key_bundle_response_payload->pre_key_bundle->one_time_pre_key_public->opk_id = user_data_set[user_data_find].pre_key->one_time_pre_keys[i]->opk_id;
            copy_protobuf_from_protobuf(&(get_pre_key_bundle_response_payload->pre_key_bundle->one_time_pre_key_public->public_key), &(user_data_set[user_data_find].pre_key->one_time_pre_keys[i]->public_key));
            break;
        }
    }
    /* release the one-time pre-key */
    skissm__one_time_pre_key_public__free_unpacked(user_data_set[user_data_find].pre_key->one_time_pre_keys[i], NULL);
    user_data_set[user_data_find].pre_key->one_time_pre_keys[i] = NULL;

    response_data->code = OK;
    response_data->data.len = skissm__get_pre_key_bundle_response_payload__get_packed_size(get_pre_key_bundle_response_payload);
    response_data->data.data = (uint8_t *) malloc(sizeof(uint8_t) * response_data->data.len);
    skissm__get_pre_key_bundle_response_payload__pack(get_pre_key_bundle_response_payload, response_data->data.data);

complete:
    /* pack */
    response->id = request->id;
    response->payload.len = skissm__response_data__get_packed_size(response_data);
    response->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * response->payload.len);
    skissm__response_data__pack(response_data, response->payload.data);

    /* release */
    skissm__response_data__free_unpacked(response_data, NULL);
    skissm__get_pre_key_bundle_request_payload__free_unpacked(payload, NULL);
    skissm__get_pre_key_bundle_response_payload__free_unpacked(get_pre_key_bundle_response_payload, NULL);
}

static void process_publish_spk_request(
    Skissm__E2eeProtocolMsg *request,
    Skissm__E2eeProtocolMsg *response
) {
    response->cmd = SKISSM__E2EE_COMMANDS__publish_spk_response;

    Skissm__PublishSpkRequestPayload *payload = skissm__publish_spk_request_payload__unpack(NULL, request->payload.len, request->payload.data);

    /* prepare response payload */
    Skissm__ResponseData *response_data = (Skissm__ResponseData *)malloc(sizeof(Skissm__ResponseData));
    skissm__response_data__init(response_data);

    uint8_t user_data_find = 0;
    while (user_data_find < user_data_set_insert_pos)
    {
        if ((user_data_set[user_data_find].address) && (payload->user_address)
            && compare_address(user_data_set[user_data_find].address, payload->user_address)
        ) {
            break;
        }
        user_data_find++;
    }

    if (user_data_find == user_data_set_insert_pos){
        response_data->code = Internal_Server_Error;
        goto complete;
    }

    user_data_set[user_data_find].pre_key->signed_pre_key_public->spk_id = payload->signed_pre_key_public->spk_id;

    /* release old memory */
    free_mem((void **)&(user_data_set[user_data_find].pre_key->signed_pre_key_public->public_key.data), user_data_set[user_data_find].pre_key->signed_pre_key_public->public_key.len);
    free_mem((void **)&(user_data_set[user_data_find].pre_key->signed_pre_key_public->signature.data), user_data_set[user_data_find].pre_key->signed_pre_key_public->signature.len);

    copy_protobuf_from_protobuf(&(user_data_set[user_data_find].pre_key->signed_pre_key_public->public_key), &(payload->signed_pre_key_public->public_key));
    copy_protobuf_from_protobuf(&(user_data_set[user_data_find].pre_key->signed_pre_key_public->signature), &(payload->signed_pre_key_public->signature));

    response_data->code = OK;

complete:
    /* pack */
    response->id = request->id;
    response->payload.len = skissm__response_data__get_packed_size(response_data);
    response->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * response->payload.len);
    skissm__response_data__pack(response_data, response->payload.data);

    /* release */
    skissm__response_data__free_unpacked(response_data, NULL);
    skissm__publish_spk_request_payload__free_unpacked(payload, NULL);
}

static void process_supply_opks_response(
    Skissm__E2eeProtocolMsg *in
) {
    Skissm__SupplyOpksResponsePayload *payload = skissm__supply_opks_response_payload__unpack(NULL, in->payload.len, in->payload.data);

    uint8_t user_data_find = 0;
    while (user_data_find < user_data_set_insert_pos)
    {
        if ((user_data_set[user_data_find].address) && (payload->user_address)
            && compare_address(user_data_set[user_data_find].address, payload->user_address)
        ) {
            break;
        }
        user_data_find++;
    }

    if (user_data_find == user_data_set_insert_pos){
        goto complete;
    }

    size_t old_num = user_data_set[user_data_find].pre_key->n_one_time_pre_keys;

    user_data_set[user_data_find].pre_key->n_one_time_pre_keys += payload->n_one_time_pre_key_public;
    Skissm__OneTimePreKeyPublic **temp;
    temp = (Skissm__OneTimePreKeyPublic **) malloc(sizeof(Skissm__OneTimePreKeyPublic *) * user_data_set[user_data_find].pre_key->n_one_time_pre_keys);
    size_t i;
    for (i = 0; i < old_num; i++){
        temp[i] = (Skissm__OneTimePreKeyPublic *) malloc(sizeof(Skissm__OneTimePreKeyPublic));
        skissm__one_time_pre_key_public__init(temp[i]);
        temp[i]->opk_id = user_data_set[user_data_find].pre_key->one_time_pre_keys[i]->opk_id;
        copy_protobuf_from_protobuf(&(temp[i]->public_key), &(user_data_set[user_data_find].pre_key->one_time_pre_keys[i]->public_key));
        skissm__one_time_pre_key_public__free_unpacked(user_data_set[user_data_find].pre_key->one_time_pre_keys[i], NULL);
        user_data_set[user_data_find].pre_key->one_time_pre_keys[i] = NULL;
    }
    free(user_data_set[user_data_find].pre_key->one_time_pre_keys);
    user_data_set[user_data_find].pre_key->one_time_pre_keys = temp;

    for (i = old_num; i < user_data_set[user_data_find].pre_key->n_one_time_pre_keys; i++){
        user_data_set[user_data_find].pre_key->one_time_pre_keys[i] = (Skissm__OneTimePreKeyPublic *) malloc(sizeof(Skissm__OneTimePreKeyPublic));
        skissm__one_time_pre_key_public__init(user_data_set[user_data_find].pre_key->one_time_pre_keys[i]);
        user_data_set[user_data_find].pre_key->one_time_pre_keys[i]->opk_id = payload->one_time_pre_key_public[i - old_num]->opk_id;
        copy_protobuf_from_protobuf(&(user_data_set[user_data_find].pre_key->one_time_pre_keys[i]->public_key), &(payload->one_time_pre_key_public[i - old_num]->public_key));
    }

complete:
    /* release */
    skissm__supply_opks_response_payload__free_unpacked(payload, NULL);
}

static void process_create_group_request(
    Skissm__E2eeProtocolMsg *request,
    Skissm__E2eeProtocolMsg *response
) {
    response->cmd = SKISSM__E2EE_COMMANDS__create_group_response;

    /* unpack */
    Skissm__CreateGroupRequestPayload *payload = skissm__create_group_request_payload__unpack(NULL, request->payload.len, request->payload.data);

    /* prepare to store */
    copy_protobuf_from_protobuf(&(group_data_set[group_data_set_insert_pos].group_name), &(payload->group_name));
    group_data_set[group_data_set_insert_pos].member_num = payload->n_member_addresses;
    copy_member_addresses_from_member_addresses(&(group_data_set[group_data_set_insert_pos].member_addresses), (const Skissm__E2eeAddress **)payload->member_addresses, payload->n_member_addresses);

    /* Generate a random address */
    Skissm__E2eeAddress *random_address = (Skissm__E2eeAddress *) malloc(sizeof(Skissm__E2eeAddress));
    skissm__e2ee_address__init(random_address);
    create_domain(&(random_address->domain));
    random_id(&(random_address->group_id), 32);
    copy_address_from_address(&(group_data_set[group_data_set_insert_pos].group_address), random_address);

    Skissm__CreateGroupResponsePayload *create_group_response_payload = (Skissm__CreateGroupResponsePayload *) malloc(sizeof(Skissm__CreateGroupResponsePayload));
    skissm__create_group_response_payload__init(create_group_response_payload);

    /* prepare response payload */
    Skissm__ResponseData *response_data = (Skissm__ResponseData *)malloc(sizeof(Skissm__ResponseData));
    skissm__response_data__init(response_data);

    create_group_response_payload->group_address = random_address;

    /* pack */
    response_data->code = OK;
    response_data->data.len = skissm__create_group_response_payload__get_packed_size(create_group_response_payload);
    response_data->data.data = (uint8_t *) malloc(sizeof(uint8_t) * response_data->data.len);
    skissm__create_group_response_payload__pack(create_group_response_payload, response_data->data.data);

    response->id = request->id;
    response->payload.len = skissm__response_data__get_packed_size(response_data);
    response->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * response->payload.len);
    skissm__response_data__pack(response_data, response->payload.data);

    /* prepare a new request */
    copy_address_from_address(&(payload->group_address), random_address);

    Skissm__E2eeProtocolMsg *new_request = (Skissm__E2eeProtocolMsg *) malloc(sizeof(Skissm__E2eeProtocolMsg));
    skissm__e2ee_protocol_msg__init(new_request);
    new_request->cmd = request->cmd;
    new_request->id = request->id;
    new_request->payload.len = skissm__create_group_request_payload__get_packed_size(payload);
    new_request->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * new_request->payload.len);
    skissm__create_group_request_payload__pack(payload, new_request->payload.data);

    /* send the message to all the other members in the group */
    size_t i;
    for (i = 0; i < group_data_set[group_data_set_insert_pos].member_num; i++){
        if (compare_address(payload->sender_address, group_data_set[group_data_set_insert_pos].member_addresses[i]) == false){
            mock_protocol_send(new_request, group_data_set[group_data_set_insert_pos].member_addresses[i]);
        }
    }

    group_data_set_insert_pos++;

    /* release */
    skissm__response_data__free_unpacked(response_data, NULL);
    skissm__create_group_request_payload__free_unpacked(payload, NULL);
    skissm__create_group_response_payload__free_unpacked(create_group_response_payload, NULL);
}

static void process_get_group_request(
    Skissm__E2eeProtocolMsg *request,
    Skissm__E2eeProtocolMsg *response
) {
    response->cmd = SKISSM__E2EE_COMMANDS__get_group_response;

    /* prepare a response payload */
    Skissm__GetGroupResponsePayload *get_group_response_payload = (Skissm__GetGroupResponsePayload *) malloc(sizeof(Skissm__GetGroupResponsePayload));
    skissm__get_group_response_payload__init(get_group_response_payload);

    /* unpack */
    Skissm__GetGroupRequestPayload *payload = skissm__get_group_request_payload__unpack(NULL, request->payload.len, request->payload.data);

    /* prepare response payload */
    Skissm__ResponseData *response_data = (Skissm__ResponseData *)malloc(sizeof(Skissm__ResponseData));
    skissm__response_data__init(response_data);

    uint8_t group_data_find = 0;
    while (group_data_find < group_data_set_insert_pos){
        if ((group_data_set[group_data_find].group_address) && (payload->group_address)
            && compare_address(group_data_set[group_data_find].group_address, payload->group_address)
        ) {
            break;
        }
        group_data_find++;
    }

    if (group_data_find == group_data_set_insert_pos){
        response_data->code = Internal_Server_Error;
        goto complete;
    }

    copy_protobuf_from_protobuf(&(get_group_response_payload->group_name), &(group_data_set[group_data_find].group_name));
    get_group_response_payload->n_member_addresses = group_data_set[group_data_find].member_num;
    copy_member_addresses_from_member_addresses(&(get_group_response_payload->member_addresses), (const Skissm__E2eeAddress **)group_data_set[group_data_find].member_addresses, get_group_response_payload->n_member_addresses);

    response_data->code = OK;
    response_data->data.len = skissm__get_group_response_payload__get_packed_size(get_group_response_payload);
    response_data->data.data = (uint8_t *) malloc(sizeof(uint8_t) * response_data->data.len);
    skissm__get_group_response_payload__pack(get_group_response_payload, response_data->data.data);

complete:
    /* pack */
    response->id = request->id;
    response->payload.len = skissm__response_data__get_packed_size(response_data);
    response->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * response->payload.len);
    skissm__response_data__pack(response_data, response->payload.data);

    /* release */
    skissm__response_data__free_unpacked(response_data, NULL);
    skissm__get_group_request_payload__free_unpacked(payload, NULL);
    skissm__get_group_response_payload__free_unpacked(get_group_response_payload, NULL);
}

static void process_add_group_members_request(
    Skissm__E2eeProtocolMsg *request,
    Skissm__E2eeProtocolMsg *response
) {
    response->cmd = SKISSM__E2EE_COMMANDS__add_group_members_response;

    /* prepare response payload */
    Skissm__ResponseData *response_data = (Skissm__ResponseData *)malloc(sizeof(Skissm__ResponseData));
    skissm__response_data__init(response_data);

    /* unpack */
    Skissm__AddGroupMembersRequestPayload *payload = skissm__add_group_members_request_payload__unpack(NULL, request->payload.len, request->payload.data);

    /* find the group */
    uint8_t group_data_find = 0;
    while (group_data_find < group_data_set_insert_pos){
        if ((group_data_set[group_data_find].group_address) && (payload->group_address)
            && compare_address(group_data_set[group_data_find].group_address, payload->group_address)
        ) {
            break;
        }
        group_data_find++;
    }

    if (group_data_find == group_data_set_insert_pos){
        response_data->code = Internal_Server_Error;
        goto complete;
    }

    /* update the data */
    size_t old_member_num = group_data_set[group_data_find].member_num;
    size_t new_member_num = group_data_set[group_data_find].member_num + payload->n_member_addresses;
    group_data_set[group_data_find].member_num = new_member_num;

    Skissm__E2eeAddress **temp_member_addresses = NULL;
    temp_member_addresses = (Skissm__E2eeAddress **) malloc(sizeof(Skissm__E2eeAddress *) * new_member_num);
    size_t i;
    for (i = 0; i < old_member_num; i++){
        copy_address_from_address(&(temp_member_addresses[i]), group_data_set[group_data_find].member_addresses[i]);
        skissm__e2ee_address__free_unpacked(group_data_set[group_data_find].member_addresses[i], NULL);
    }
    free(group_data_set[group_data_find].member_addresses);
    group_data_set[group_data_find].member_addresses = temp_member_addresses;

    for (i = old_member_num; i < new_member_num; i++){
        copy_address_from_address(&(group_data_set[group_data_find].member_addresses[i]), (payload->member_addresses)[i - old_member_num]);
    }

    /* send the message to all the other members in the group */
    for (i = 0; i < group_data_set[group_data_find].member_num; i++){
        if (compare_address(payload->sender_address, group_data_set[group_data_find].member_addresses[i]) == false){
            mock_protocol_send(request, group_data_set[group_data_find].member_addresses[i]);
        }
    }

    response_data->code = OK;

complete:
    response->id = request->id;
    response->payload.len = skissm__response_data__get_packed_size(response_data);
    response->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * response->payload.len);
    skissm__response_data__pack(response_data, response->payload.data);

    /* release */
    skissm__response_data__free_unpacked(response_data, NULL);
    skissm__add_group_members_request_payload__free_unpacked(payload, NULL);
}

static void process_remove_group_members_request(
    Skissm__E2eeProtocolMsg *request,
    Skissm__E2eeProtocolMsg *response
) {
    response->cmd = SKISSM__E2EE_COMMANDS__remove_group_members_response;

    /* prepare response payload */
    Skissm__ResponseData *response_data = (Skissm__ResponseData *)malloc(sizeof(Skissm__ResponseData));
    skissm__response_data__init(response_data);

    /* unpack */
    Skissm__RemoveGroupMembersRequestPayload *payload = skissm__remove_group_members_request_payload__unpack(NULL, request->payload.len, request->payload.data);

    /* find the group */
    uint8_t group_data_find = 0;
    while (group_data_find < group_data_set_insert_pos){
        if ((group_data_set[group_data_find].group_address) && (payload->group_address)
            && compare_address(group_data_set[group_data_find].group_address, payload->group_address)
        ) {
            break;
        }
        group_data_find++;
    }

    if (group_data_find == group_data_set_insert_pos){
        response_data->code = Internal_Server_Error;
        goto complete;
    }

    /* update the data */
    size_t original_member_num = group_data_set[group_data_find].member_num;
    size_t new_member_num = original_member_num - payload->n_member_addresses;
    group_data_set[group_data_find].member_num = new_member_num;

    size_t i,j;
    for (j = 0; j < payload->n_member_addresses; j++){
        for (i = 0; i < original_member_num; i++){
            if (compare_address(group_data_set[group_data_find].member_addresses[i], payload->member_addresses[j])){
                skissm__e2ee_address__free_unpacked(group_data_set[group_data_find].member_addresses[i], NULL);
                group_data_set[group_data_find].member_addresses[i] = NULL;
                break;
            }
        }
    }

    Skissm__E2eeAddress **temp_member_addresses;
    temp_member_addresses = (Skissm__E2eeAddress **) malloc(sizeof(Skissm__E2eeAddress *) * new_member_num);
    i = 0; j = 0;
    while (i < new_member_num && j < original_member_num){
        if (group_data_set[group_data_find].member_addresses[j] != NULL){
            copy_address_from_address(&(temp_member_addresses[i]), group_data_set[group_data_find].member_addresses[j]);
            i++; j++;
        } else{
            j++;
        }
    }

    i = 0;
    for (i = 0; i < original_member_num; i++){
        skissm__e2ee_address__free_unpacked(group_data_set[group_data_find].member_addresses[i], NULL);
        group_data_set[group_data_find].member_addresses[i] = NULL;
    }
    free(group_data_set[group_data_find].member_addresses);
    group_data_set[group_data_find].member_addresses = temp_member_addresses;

    /* send the message to all the other members in the group */
    for (i = 0; i < group_data_set[group_data_find].member_num; i++){
        if (compare_address(payload->sender_address, group_data_set[group_data_find].member_addresses[i]) == false){
            mock_protocol_send(request, group_data_set[group_data_find].member_addresses[i]);
        }
    }

    response_data->code = OK;

complete:
    response->id = request->id;
    response->payload.len = skissm__response_data__get_packed_size(response_data);
    response->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * response->payload.len);
    skissm__response_data__pack(response_data, response->payload.data);

    /* release */
    skissm__response_data__free_unpacked(response_data, NULL);
    skissm__remove_group_members_request_payload__free_unpacked(payload, NULL);
}

static void process_send_msg_request(
    Skissm__E2eeProtocolMsg *request,
    Skissm__E2eeProtocolMsg *response
) {
    response->cmd = SKISSM__E2EE_COMMANDS__send_one2one_msg_response;

    /* prepare response payload */
    Skissm__ResponseData *response_data = (Skissm__ResponseData *)malloc(sizeof(Skissm__ResponseData));
    skissm__response_data__init(response_data);

    /* sending */
    mock_protocol_send(request, NULL);

    response_data->code = OK;
    response->id = request->id;
    response->payload.len = skissm__response_data__get_packed_size(response_data);
    response->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * response->payload.len);
    skissm__response_data__pack(response_data, response->payload.data);

    /* release */
    skissm__response_data__free_unpacked(response_data, NULL);
}

static void process_send_group_msg_request(
    Skissm__E2eeProtocolMsg *request,
    Skissm__E2eeProtocolMsg *response
) {
    response->cmd = SKISSM__E2EE_COMMANDS__send_group_msg_response;

    /* prepare response payload */
    Skissm__ResponseData *response_data = (Skissm__ResponseData *)malloc(sizeof(Skissm__ResponseData));
    skissm__response_data__init(response_data);

    /* unpack */
    Skissm__E2eeMessage *e2ee_msg = skissm__e2ee_message__unpack(NULL, request->payload.len, request->payload.data);

    /* find the group */
    uint8_t group_data_find = 0;
    while (group_data_find < group_data_set_insert_pos){
        if ((group_data_set[group_data_find].group_address) && (e2ee_msg->to)
            && compare_address(group_data_set[group_data_find].group_address, e2ee_msg->to)
        ) {
            break;
        }
        group_data_find++;
    }

    if (group_data_find == group_data_set_insert_pos){
        response_data->code = Internal_Server_Error;
        goto complete;
    }

    /* send the message to all the other members in the group */
    size_t i;
    for (i = 0; i < group_data_set[group_data_find].member_num; i++){
        if (compare_address(e2ee_msg->from, group_data_set[group_data_find].member_addresses[i]) == false){
            mock_protocol_send(request, group_data_set[group_data_find].member_addresses[i]);
        }
    }

    response_data->code = OK;

complete:
    response->id = request->id;
    response->payload.len = skissm__response_data__get_packed_size(response_data);
    response->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * response->payload.len);
    skissm__response_data__pack(response_data, response->payload.data);

    /* release */
    skissm__response_data__free_unpacked(response_data, NULL);
    skissm__e2ee_message__free_unpacked(e2ee_msg, NULL);
}

void mock_protocol_receive(uint8_t *msg, size_t msg_len){
    Skissm__E2eeProtocolMsg *client_msg = skissm__e2ee_protocol_msg__unpack(NULL, msg_len, msg);

    Skissm__E2eeProtocolMsg *response = (Skissm__E2eeProtocolMsg *) malloc(sizeof(Skissm__E2eeProtocolMsg));
    skissm__e2ee_protocol_msg__init(response);

    switch (client_msg->cmd)
    {
    case SKISSM__E2EE_COMMANDS__register_user_request:
        process_register_user_request(client_msg, response);
        break;
    case SKISSM__E2EE_COMMANDS__delete_user_request:
        process_delete_user_request(client_msg, response);
        break;
    case SKISSM__E2EE_COMMANDS__get_pre_key_bundle_request:
        process_get_pre_key_bundle_request(client_msg, response);
        break;
    case SKISSM__E2EE_COMMANDS__publish_spk_request:
        process_publish_spk_request(client_msg, response);
        break;
    case SKISSM__E2EE_COMMANDS__supply_opks_response:
        process_supply_opks_response(client_msg);
        return;
        break;
    case SKISSM__E2EE_COMMANDS__create_group_request:
        process_create_group_request(client_msg, response);
        break;
    case SKISSM__E2EE_COMMANDS__create_group_response:
        return;
        break;
    case SKISSM__E2EE_COMMANDS__get_group_request:
        process_get_group_request(client_msg, response);
        break;
    case SKISSM__E2EE_COMMANDS__add_group_members_request:
        process_add_group_members_request(client_msg, response);
        break;
    case SKISSM__E2EE_COMMANDS__add_group_members_response:
        return;
        break;
    case SKISSM__E2EE_COMMANDS__remove_group_members_request:
        process_remove_group_members_request(client_msg, response);
        break;
    case SKISSM__E2EE_COMMANDS__remove_group_members_response:
        return;
        break;
    case SKISSM__E2EE_COMMANDS__send_one2one_msg_request:
        process_send_msg_request(client_msg, response);
        break;
    case SKISSM__E2EE_COMMANDS__send_one2one_msg_response:
        return;
        break;
    case SKISSM__E2EE_COMMANDS__send_group_msg_request:
        process_send_group_msg_request(client_msg, response);
        break;
    case SKISSM__E2EE_COMMANDS__send_group_msg_response:
        return;
        break;

    default:
        break;
    }

    mock_protocol_send(response, NULL);

    /* release */
    skissm__e2ee_protocol_msg__free_unpacked(client_msg, NULL);
    skissm__e2ee_protocol_msg__free_unpacked(response, NULL);
}

