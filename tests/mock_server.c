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
#include "mock_server.h"

#include <string.h>

#include "skissm/mem_util.h"
#include "skissm/e2ee_client.h"

#include "test_util.h"

#define user_data_max 8
#define group_data_max 8

typedef struct user_data{
    Skissm__E2eeAddress *address;
    const char *user_name;
    Skissm__IdentityKeyPublic *identity_key_public;
    Skissm__SignedPreKeyPublic *signed_pre_key_public;
    Skissm__OneTimePreKeyPublic **one_time_pre_keys;
    size_t n_one_time_pre_keys;
} user_data;

typedef struct group_data{
    Skissm__E2eeAddress *group_address;
    char *group_name;
    size_t group_members_num;
    Skissm__GroupMember **group_members;
} group_data;

static user_data user_data_set[user_data_max] = {
    {NULL, NULL, NULL, NULL, NULL, 0},
    {NULL, NULL, NULL, NULL, NULL, 0},
    {NULL, NULL, NULL, NULL, NULL, 0},
    {NULL, NULL, NULL, NULL, NULL, 0},
    {NULL, NULL, NULL, NULL, NULL, 0},
    {NULL, NULL, NULL, NULL, NULL, 0},
    {NULL, NULL, NULL, NULL, NULL, 0},
    {NULL, NULL, NULL, NULL, NULL, 0}};

static group_data group_data_set[group_data_max] = {
    {NULL, NULL, 0, NULL},
    {NULL, NULL, 0, NULL},
    {NULL, NULL, 0, NULL},
    {NULL, NULL, 0, NULL},
    {NULL, NULL, 0, NULL},
    {NULL, NULL, 0, NULL},
    {NULL, NULL, 0, NULL},
    {NULL, NULL, 0, NULL}};

static uint8_t user_data_set_insert_pos = 0;

static uint8_t group_data_set_insert_pos = 0;

static size_t find_user_addresses(const char *user_id, Skissm__E2eeAddress ***user_addresses) {
    size_t user_addresses_num = 0;
    uint8_t i;
    for (i = 0; i<user_data_max; i++) {
        if (user_data_set[i].address != NULL) {
            if (safe_strcmp(user_data_set[i].address->user->user_id, user_id))
                user_addresses_num++;
        }
    }
    *user_addresses = (Skissm__E2eeAddress **)malloc(sizeof(Skissm__E2eeAddress *) * user_addresses_num);
    uint8_t j = 0;
    for (i = 0; i<user_data_max; i++) {
        if (user_data_set[i].address != NULL) {
            if (safe_strcmp(user_data_set[i].address->user->user_id, user_id))
                copy_address_from_address(&((*user_addresses)[j++]), user_data_set[i].address);
        }
    }
    return user_addresses_num;
}

void mock_server_begin(){
}

void mock_server_end(){
    uint8_t i;
    size_t j;
    for (i = 0; i < user_data_set_insert_pos; i++){
        skissm__e2ee_address__free_unpacked(user_data_set[i].address, NULL);
        user_data_set[i].address = NULL;

        free((void *)(user_data_set[i].user_name));
        skissm__identity_key_public__free_unpacked(user_data_set[i].identity_key_public, NULL);
        skissm__signed_pre_key_public__free_unpacked(user_data_set[i].signed_pre_key_public, NULL);
        for (j = 0; j < user_data_set[i].n_one_time_pre_keys; j++) {
            Skissm__OneTimePreKeyPublic *cur_opk = user_data_set[i].one_time_pre_keys[j];
            if (cur_opk != NULL) {
                skissm__one_time_pre_key_public__free_unpacked(cur_opk, NULL);
                cur_opk = NULL;
            }
        }
        free_mem((void **)(&(user_data_set[i].one_time_pre_keys)), sizeof(Skissm__OneTimePreKeyPublic *) * user_data_set[i].n_one_time_pre_keys);
        user_data_set[i].user_name = NULL;
        user_data_set[i].identity_key_public = NULL;
        user_data_set[i].signed_pre_key_public = NULL;
        user_data_set[i].one_time_pre_keys = NULL;
        user_data_set[i].n_one_time_pre_keys = 0;
    }
    user_data_set_insert_pos = 0;
    for (i = 0; i < group_data_set_insert_pos; i++){
        skissm__e2ee_address__free_unpacked(group_data_set[i].group_address, NULL);
        group_data_set[i].group_address = NULL;
        free(group_data_set[i].group_name);
        group_data_set[i].group_name = NULL;
        for (j = 0; j < group_data_set[i].group_members_num; j++){
            Skissm__GroupMember *cur_group_member = group_data_set[i].group_members[j];
            if (cur_group_member != NULL){
                skissm__group_member__free_unpacked(cur_group_member, NULL);
                cur_group_member = NULL;
            }
        }
        free_mem((void **)(&(group_data_set[i].group_members)), sizeof(Skissm__GroupMember *) * group_data_set[i].group_members_num);
        group_data_set[i].group_members_num = 0;
    }
    group_data_set_insert_pos = 0;
}

Skissm__RegisterUserResponse *mock_register_user(Skissm__RegisterUserRequest *request) {
    user_data *cur_data = &(user_data_set[user_data_set_insert_pos]);
    /* prepare to store */
    cur_data->user_name = strdup(request->user_name);

    copy_ik_public_from_ik_public(&(cur_data->identity_key_public), request->identity_key_public);
    copy_spk_public_from_spk_public(&(cur_data->signed_pre_key_public), request->signed_pre_key_public);
    cur_data->n_one_time_pre_keys = request->n_one_time_pre_keys;
    cur_data->one_time_pre_keys = (Skissm__OneTimePreKeyPublic **) malloc(sizeof(Skissm__OneTimePreKeyPublic *) * cur_data->n_one_time_pre_keys);
    size_t i;
    for (i = 0; i < cur_data->n_one_time_pre_keys; i++){
        copy_opk_public_from_opk_public(&(cur_data->one_time_pre_keys[i]), request->one_time_pre_keys[i]);
    }

    /* Generate a random address */
    mock_random_user_address(&(cur_data->address));
    free(cur_data->address->user->device_id);
    cur_data->address->user->device_id = strdup(request->device_id);

    user_data_set_insert_pos++;

    Skissm__RegisterUserResponse *response
        = (Skissm__RegisterUserResponse *)malloc(sizeof(Skissm__RegisterUserResponse));
    skissm__register_user_response__init(response);
    copy_address_from_address(&(response->address), cur_data->address);
    response->code = SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK;

    return response;
}

Skissm__GetPreKeyBundleResponse *mock_get_pre_key_bundle(Skissm__GetPreKeyBundleRequest *request) {
    Skissm__GetPreKeyBundleResponse *response = NULL;

    uint8_t user_data_find = 0;
    while (user_data_find < user_data_set_insert_pos)
    {
        if ((user_data_set[user_data_find].address) && (request->user_address)
            && compare_address(user_data_set[user_data_find].address, request->user_address)
        ) {
            break;
        }
        user_data_find++;
    }

    user_data *cur_data = &(user_data_set[user_data_find]);

    response = (Skissm__GetPreKeyBundleResponse *) malloc(sizeof(Skissm__GetPreKeyBundleResponse));
    skissm__get_pre_key_bundle_response__init(response);
    response->pre_key_bundles = (Skissm__PreKeyBundle **) malloc(sizeof(Skissm__PreKeyBundle *)*1);
    response->n_pre_key_bundles = 1;
    response->pre_key_bundles[0] = (Skissm__PreKeyBundle *) malloc(sizeof(Skissm__PreKeyBundle));
    skissm__pre_key_bundle__init(response->pre_key_bundles[0]);

    response->pre_key_bundles[0]->e2ee_pack_id = strdup(TEST_E2EE_PACK_ID);
    copy_address_from_address(&(response->pre_key_bundles[0]->user_address), request->user_address);
    copy_ik_public_from_ik_public(&(response->pre_key_bundles[0]->identity_key_public), cur_data->identity_key_public);
    copy_spk_public_from_spk_public(&(response->pre_key_bundles[0]->signed_pre_key_public), cur_data->signed_pre_key_public);
    // TODO: remove one_time_pre_keys[0] and append to response->pre_key_bundles
    size_t i;
    for (i = 0; i < cur_data->n_one_time_pre_keys; i++){
        if (cur_data->one_time_pre_keys[i]){
            copy_opk_public_from_opk_public(&(response->pre_key_bundles[0]->one_time_pre_key_public), cur_data->one_time_pre_keys[i]);
            break;
        }
    }
    /* release the one-time pre-key */
    skissm__one_time_pre_key_public__free_unpacked(cur_data->one_time_pre_keys[i], NULL);
    cur_data->one_time_pre_keys[i] = NULL;
    response->code = SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK;

    return response;
}

Skissm__InviteResponse *mock_invite(Skissm__InviteRequest *request) {
    Skissm__InviteMsg *invite_msg = request->msg;
    size_t invite_msg_data_len = skissm__invite_msg__get_packed_size(invite_msg);
    uint8_t invite_msg_data[invite_msg_data_len];
    skissm__invite_msg__pack(invite_msg, invite_msg_data);

    // forward a copy of InviteMsg
    Skissm__ProtoMsg *proto_msg = (Skissm__ProtoMsg *)malloc(sizeof(Skissm__ProtoMsg));
    skissm__proto_msg__init(proto_msg);
    copy_address_from_address(&(proto_msg->from), invite_msg->from);
    copy_address_from_address(&(proto_msg->to), invite_msg->to);
    proto_msg->payload_case = SKISSM__PROTO_MSG__PAYLOAD_INVITE_MSG;
    proto_msg->invite_msg = skissm__invite_msg__unpack(NULL, invite_msg_data_len, invite_msg_data);

    size_t proto_msg_data_len = skissm__proto_msg__get_packed_size(proto_msg);
    uint8_t proto_msg_data[proto_msg_data_len];
    skissm__proto_msg__pack(proto_msg, proto_msg_data);
    Skissm__ConsumeProtoMsgResponse *consume_proto_msg_response = process_proto_msg(proto_msg_data, proto_msg_data_len);

    // prepare response
    Skissm__InviteResponse *response = (Skissm__InviteResponse *)malloc(sizeof(Skissm__InviteResponse));
    skissm__invite_response__init(response);
    response->code = SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK;

    // release
    skissm__proto_msg__free_unpacked(proto_msg, NULL);
    skissm__consume_proto_msg_response__free_unpacked(consume_proto_msg_response, NULL);

    // done
    return response;
}

Skissm__AcceptResponse *mock_accept(Skissm__AcceptRequest *request) {
    Skissm__AcceptMsg *accept_msg = request->msg;
    size_t accept_msg_data_len = skissm__accept_msg__get_packed_size(accept_msg);
    uint8_t accept_msg_data[accept_msg_data_len];
    skissm__accept_msg__pack(accept_msg, accept_msg_data);

    // forward a copy of AcceptMsg
    Skissm__ProtoMsg *proto_msg = (Skissm__ProtoMsg *)malloc(sizeof(Skissm__ProtoMsg));
    skissm__proto_msg__init(proto_msg);
    copy_address_from_address(&(proto_msg->from), accept_msg->from);
    copy_address_from_address(&(proto_msg->to), accept_msg->to);
    proto_msg->payload_case = SKISSM__PROTO_MSG__PAYLOAD_ACCEPT_MSG;
    proto_msg->accept_msg = skissm__accept_msg__unpack(NULL, accept_msg_data_len, accept_msg_data);

    size_t proto_msg_data_len = skissm__proto_msg__get_packed_size(proto_msg);
    uint8_t proto_msg_data[proto_msg_data_len];
    skissm__proto_msg__pack(proto_msg, proto_msg_data);
    Skissm__ConsumeProtoMsgResponse *consume_proto_msg_response = process_proto_msg(proto_msg_data, proto_msg_data_len);

    // prepare response
    Skissm__AcceptResponse *response = (Skissm__AcceptResponse *)malloc(sizeof(Skissm__AcceptResponse));
    skissm__accept_response__init(response);
    response->code = SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK;

    // release
    skissm__proto_msg__free_unpacked(proto_msg, NULL);
    skissm__consume_proto_msg_response__free_unpacked(consume_proto_msg_response, NULL);

    // done
    return response;
}

Skissm__PublishSpkResponse *mock_publish_spk(Skissm__PublishSpkRequest *request) {
    uint8_t user_data_find = 0;
    while (user_data_find < user_data_set_insert_pos)
    {
        if ((user_data_set[user_data_find].address) && (request->user_address)
            && compare_address(user_data_set[user_data_find].address, request->user_address)
        ) {
            break;
        }
        user_data_find++;
    }

    // data not found
    if (user_data_find == user_data_set_insert_pos){
        Skissm__PublishSpkResponse *response = (Skissm__PublishSpkResponse *)malloc(sizeof(Skissm__PublishSpkResponse));
        skissm__publish_spk_response__init(response);
        response->code = SKISSM__RESPONSE_CODE__RESPONSE_CODE_INTERNAL_SERVER_ERROR;
        return response;
    }

    user_data *cur_data = &(user_data_set[user_data_find]);
    // release old memory
    skissm__signed_pre_key_public__free_unpacked(cur_data->signed_pre_key_public, NULL);
    // copy new data
    copy_spk_public_from_spk_public(&(cur_data->signed_pre_key_public), request->signed_pre_key_public);

    Skissm__PublishSpkResponse *response = (Skissm__PublishSpkResponse *)malloc(sizeof(Skissm__PublishSpkResponse));
    skissm__publish_spk_response__init(response);
    response->code = SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK;

    return response;
}

Skissm__SupplyOpksResponse *mock_supply_opks(Skissm__SupplyOpksRequest *request) {
    uint8_t user_data_find = 0;
    while (user_data_find < user_data_set_insert_pos)
    {
        if ((user_data_set[user_data_find].address) && (request->user_address)
            && compare_address(user_data_set[user_data_find].address, request->user_address)
        ) {
            break;
        }
        user_data_find++;
    }

    if (user_data_find == user_data_set_insert_pos){
        // not found
        return NULL;
    }

    user_data *cur_data = &(user_data_set[user_data_find]);

    size_t old_num = cur_data->n_one_time_pre_keys;

    cur_data->n_one_time_pre_keys += request->n_one_time_pre_key_public;
    Skissm__OneTimePreKeyPublic **temp;
    temp = (Skissm__OneTimePreKeyPublic **) malloc(sizeof(Skissm__OneTimePreKeyPublic *) * cur_data->n_one_time_pre_keys);
    size_t i;
    for (i = 0; i < old_num; i++){
        copy_opk_public_from_opk_public(&(temp[i]), cur_data->one_time_pre_keys[i]);
        skissm__one_time_pre_key_public__free_unpacked(cur_data->one_time_pre_keys[i], NULL);
        cur_data->one_time_pre_keys[i] = NULL;
    }
    free(cur_data->one_time_pre_keys);
    cur_data->one_time_pre_keys = temp;

    // copy new one-time pre-keys
    for (i = old_num; i < cur_data->n_one_time_pre_keys; i++){
        copy_opk_public_from_opk_public(&(cur_data->one_time_pre_keys[i]), request->one_time_pre_key_public[i - old_num]);
    }

    // prepare response
    Skissm__SupplyOpksResponse *response = (Skissm__SupplyOpksResponse *)malloc(sizeof(Skissm__SupplyOpksResponse));
    skissm__supply_opks_response__init(response);
    response->code = SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK;

    return response;
}

Skissm__SendOne2oneMsgResponse *mock_send_one2one_msg(Skissm__SendOne2oneMsgRequest *request) {
    Skissm__E2eeMsg *e2ee_msg = request->msg;
    size_t e2ee_msg_data_len = skissm__e2ee_msg__get_packed_size(e2ee_msg);
    uint8_t e2ee_msg_data[e2ee_msg_data_len];
    skissm__e2ee_msg__pack(e2ee_msg, e2ee_msg_data);

    // forward a copy of E2eeMsg
    Skissm__ProtoMsg *proto_msg = (Skissm__ProtoMsg *)malloc(sizeof(Skissm__ProtoMsg));
    skissm__proto_msg__init(proto_msg);
    copy_address_from_address(&(proto_msg->from), e2ee_msg->from);
    copy_address_from_address(&(proto_msg->to), e2ee_msg->to);
    proto_msg->payload_case = SKISSM__PROTO_MSG__PAYLOAD_E2EE_MSG;
    proto_msg->e2ee_msg = skissm__e2ee_msg__unpack(NULL, e2ee_msg_data_len, e2ee_msg_data);

    size_t proto_msg_data_len = skissm__proto_msg__get_packed_size(proto_msg);
    uint8_t proto_msg_data[proto_msg_data_len];
    skissm__proto_msg__pack(proto_msg, proto_msg_data);
    Skissm__ConsumeProtoMsgResponse *consume_proto_msg_response = process_proto_msg(proto_msg_data, proto_msg_data_len);

    // prepare response
    Skissm__SendOne2oneMsgResponse *response = (Skissm__SendOne2oneMsgResponse *)malloc(sizeof(Skissm__SendOne2oneMsgResponse));
    skissm__send_one2one_msg_response__init(response);
    response->code = SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK;

    // release
    skissm__proto_msg__free_unpacked(proto_msg, NULL);
    skissm__consume_proto_msg_response__free_unpacked(consume_proto_msg_response, NULL);

    // done
    return response;
}

Skissm__CreateGroupResponse *mock_create_group(Skissm__CreateGroupRequest *request) {
    if (request == NULL) {
        return NULL;
    }
    if (request->msg == NULL) {
        return NULL;
    }

    // create a new group
    group_data *cur_group_data = &(group_data_set[group_data_set_insert_pos]);

    // Generate a random address
    mock_random_group_address(&(cur_group_data->group_address));

    // pack CreateGroupMsg
    Skissm__CreateGroupMsg *create_group_msg = request->msg;
    copy_address_from_address(&(create_group_msg->group_address), cur_group_data->group_address);
    size_t create_group_msg_data_len = skissm__create_group_msg__get_packed_size(create_group_msg);
    uint8_t create_group_msg_data[create_group_msg_data_len];
    skissm__create_group_msg__pack(create_group_msg, create_group_msg_data);

    // prepare to store
    cur_group_data->group_name = strdup(create_group_msg->group_name);
    cur_group_data->group_members_num = create_group_msg->n_group_members;
    copy_group_members(&(cur_group_data->group_members), create_group_msg->group_members, create_group_msg->n_group_members);

    // send the message to all the other members in the group
    Skissm__E2eeAddress *sender_address = create_group_msg->sender_address;
    const char *sender_user_id = sender_address->user->user_id;
    uint8_t i, j;
    for (i = 0; i < group_data_set[group_data_set_insert_pos].group_members_num; i++){
        // send to other group members
        const char *member_user_id = cur_group_data->group_members[i]->user_id;
        if (safe_strcmp(sender_user_id, member_user_id) == false){
            // copy_address_from_address(&(new_request->to), group_data_set[group_data_set_insert_pos].group_members[i]);
            // mock_protocol_send(new_request);

            // forward a copy of CreateGroupMsg
            Skissm__E2eeAddress **to_member_addresses = NULL;
            size_t to_member_addresses_num = find_user_addresses(member_user_id, &to_member_addresses);
            for (j = 0; j < to_member_addresses_num; j++) {
                Skissm__E2eeAddress *to_member_address = to_member_addresses[j];
                if (to_member_address == NULL)
                    continue;
                Skissm__ProtoMsg *proto_msg = (Skissm__ProtoMsg *)malloc(sizeof(Skissm__ProtoMsg));
                skissm__proto_msg__init(proto_msg);
                copy_address_from_address(&(proto_msg->from), sender_address);
                copy_address_from_address(&(proto_msg->to), to_member_address);
                proto_msg->payload_case = SKISSM__PROTO_MSG__PAYLOAD_CREATE_GROUP_MSG;
                proto_msg->create_group_msg = skissm__create_group_msg__unpack(NULL, create_group_msg_data_len, create_group_msg_data);

                size_t proto_msg_data_len = skissm__proto_msg__get_packed_size(proto_msg);
                uint8_t proto_msg_data[proto_msg_data_len];
                skissm__proto_msg__pack(proto_msg, proto_msg_data);

                Skissm__ConsumeProtoMsgResponse *consume_proto_msg_response = process_proto_msg(proto_msg_data, proto_msg_data_len);

                // release
                skissm__proto_msg__free_unpacked(proto_msg, NULL);
                skissm__consume_proto_msg_response__free_unpacked(consume_proto_msg_response, NULL);
                skissm__e2ee_address__free_unpacked(to_member_address, NULL);
            }
            // release
            if (to_member_addresses != NULL) {
                free((void *)to_member_addresses);
            }
        }
    }

    // prepare response
    Skissm__CreateGroupResponse *response = (Skissm__CreateGroupResponse *)malloc(sizeof(Skissm__CreateGroupResponse));
    skissm__create_group_response__init(response);
    copy_address_from_address(&(response->group_address), cur_group_data->group_address);
    response->code = SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK;

    // done
    group_data_set_insert_pos++;
    return response;
}

Skissm__AddGroupMembersResponse *mock_add_group_members(Skissm__AddGroupMembersRequest *request) {
    Skissm__AddGroupMembersMsg *add_group_members_msg = request->msg;
    size_t add_group_members_msg_data_len = skissm__add_group_members_msg__get_packed_size(add_group_members_msg);
    uint8_t add_group_members_msg_data[add_group_members_msg_data_len];
    skissm__add_group_members_msg__pack(add_group_members_msg, add_group_members_msg_data);

    // find the group
    uint8_t group_data_find = 0;
    while (group_data_find < group_data_set_insert_pos){
        if ((group_data_set[group_data_find].group_address) && (request->msg->group_address)
            && compare_address(group_data_set[group_data_find].group_address, request->msg->group_address)
        ) {
            break;
        }
        group_data_find++;
    }

    // data not found
    if (group_data_find == group_data_set_insert_pos){
        Skissm__AddGroupMembersResponse *response = (Skissm__AddGroupMembersResponse *)malloc(sizeof(Skissm__AddGroupMembersResponse));
        skissm__add_group_members_response__init(response);
        response->code = SKISSM__RESPONSE_CODE__RESPONSE_CODE_INTERNAL_SERVER_ERROR;
        return response;
    }

    group_data *cur_group_data = &(group_data_set[group_data_find]);

    // update the data
    size_t old_group_members_num = cur_group_data->group_members_num;
    size_t new_group_members_num = cur_group_data->group_members_num + request->msg->n_adding_members;
    cur_group_data->group_members_num = new_group_members_num;

    Skissm__GroupMember **temp_group_members = NULL;
    temp_group_members = (Skissm__GroupMember **) malloc(sizeof(Skissm__GroupMember *) * new_group_members_num);
    size_t i;
    for (i = 0; i < old_group_members_num; i++){
        Skissm__GroupMember *cur_group_member = (cur_group_data->group_members)[i];
        copy_group_member(&(temp_group_members[i]), cur_group_member);
        skissm__group_member__free_unpacked(cur_group_member, NULL);
        cur_group_member = NULL;
    }
    free_mem((void **)(&(cur_group_data->group_members)), sizeof(Skissm__GroupMember *) * old_group_members_num);
    cur_group_data->group_members = temp_group_members;

    for (i = old_group_members_num; i < new_group_members_num; i++){
        copy_group_member(&(cur_group_data->group_members[i]), (request->msg->adding_members)[i - old_group_members_num]);
    }

    // send the message to all the other members in the group
    Skissm__E2eeAddress *sender_address = add_group_members_msg->sender_address;
    const char *sender_user_id = sender_address->user->user_id;
    size_t j;
    for (i = 0; i < group_data_set[group_data_find].group_members_num; i++){
        // send to other group members
        const char *member_user_id = cur_group_data->group_members[i]->user_id;
        if (safe_strcmp(sender_user_id, member_user_id) == false){
            // copy_address_from_address(&(new_request->to), group_data_set[group_data_set_insert_pos].group_members[i]);
            // mock_protocol_send(new_request);

            // forward a copy of AddGroupMembersMsg
            Skissm__E2eeAddress **to_member_addresses = NULL;
            size_t to_member_addresses_num = find_user_addresses(member_user_id, &to_member_addresses);
            for (j = 0; j < to_member_addresses_num; j++) {
                Skissm__E2eeAddress *to_member_address = to_member_addresses[j];
                if (to_member_address == NULL)
                    continue;
                Skissm__ProtoMsg *proto_msg = (Skissm__ProtoMsg *)malloc(sizeof(Skissm__ProtoMsg));
                skissm__proto_msg__init(proto_msg);
                copy_address_from_address(&(proto_msg->from), sender_address);
                copy_address_from_address(&(proto_msg->to), to_member_address);
                proto_msg->payload_case = SKISSM__PROTO_MSG__PAYLOAD_ADD_GROUP_MEMBERS_MSG;
                proto_msg->add_group_members_msg = skissm__add_group_members_msg__unpack(NULL, add_group_members_msg_data_len, add_group_members_msg_data);

                size_t proto_msg_data_len = skissm__proto_msg__get_packed_size(proto_msg);
                uint8_t proto_msg_data[proto_msg_data_len];
                skissm__proto_msg__pack(proto_msg, proto_msg_data);

                Skissm__ConsumeProtoMsgResponse *consume_proto_msg_response = process_proto_msg(proto_msg_data, proto_msg_data_len);

                // release
                skissm__proto_msg__free_unpacked(proto_msg, NULL);
                skissm__consume_proto_msg_response__free_unpacked(consume_proto_msg_response, NULL);
                skissm__e2ee_address__free_unpacked(to_member_address, NULL);
            }
            // release
            if (to_member_addresses != NULL) {
                free((void *)to_member_addresses);
            }
        }
    }

    Skissm__AddGroupMembersResponse *response = (Skissm__AddGroupMembersResponse *)malloc(sizeof(Skissm__AddGroupMembersResponse));
    skissm__add_group_members_response__init(response);
    response->code = SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK;
    response->n_group_members = new_group_members_num;
    response->group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *));
    for (i = 0; i < new_group_members_num; i++){
        (response->group_members)[i] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
        skissm__group_member__init((response->group_members)[i]);
        copy_group_member(&((response->group_members)[i]), (cur_group_data->group_members)[i]);
    }

    return response;
}

Skissm__RemoveGroupMembersResponse *mock_remove_group_members(Skissm__RemoveGroupMembersRequest *request) {
    Skissm__RemoveGroupMembersMsg *remove_group_members_msg = request->msg;
    size_t remove_group_members_msg_data_len = skissm__remove_group_members_msg__get_packed_size(remove_group_members_msg);
    uint8_t remove_group_members_msg_data[remove_group_members_msg_data_len];
    skissm__remove_group_members_msg__pack(remove_group_members_msg, remove_group_members_msg_data);

    // find the group
    uint8_t group_data_find = 0;
    while (group_data_find < group_data_set_insert_pos){
        if ((group_data_set[group_data_find].group_address) && (request->msg->group_address)
            && compare_address(group_data_set[group_data_find].group_address, request->msg->group_address)
        ) {
            break;
        }
        group_data_find++;
    }

    // data not found
    if (group_data_find == group_data_set_insert_pos){
        Skissm__RemoveGroupMembersResponse *response = (Skissm__RemoveGroupMembersResponse *)malloc(sizeof(Skissm__RemoveGroupMembersResponse));
        skissm__remove_group_members_response__init(response);
        response->code = SKISSM__RESPONSE_CODE__RESPONSE_CODE_INTERNAL_SERVER_ERROR;
        return response;
    }

    group_data *cur_group_data = &(group_data_set[group_data_find]);

    // update the data
    size_t original_group_members_num = cur_group_data->group_members_num;
    size_t new_group_members_num = original_group_members_num - request->msg->n_removing_members;
    cur_group_data->group_members_num = new_group_members_num;

    Skissm__GroupMember **temp_group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *) * new_group_members_num);
    size_t i = 0, j = 0;
    size_t cur_removing_member_num;
    while (i < new_group_members_num && j < original_group_members_num){
        cur_removing_member_num = j - i;
        if (cur_removing_member_num < request->msg->n_removing_members){
            if (!safe_strcmp((cur_group_data->group_members)[j]->user_id, request->msg->removing_members[cur_removing_member_num]->user_id)){
                copy_group_member(&(temp_group_members[i]), (cur_group_data->group_members)[j]);
                i++; j++;
            } else{
                j++;
            }
        } else{
            copy_group_member(&(temp_group_members[i]), (cur_group_data->group_members)[j]);
        }
    }

    for (i = 0; i < original_group_members_num; i++){
        skissm__group_member__free_unpacked((cur_group_data->group_members)[i], NULL);
        (cur_group_data->group_members)[i] = NULL;
    }
    free(cur_group_data->group_members);
    cur_group_data->group_members = temp_group_members;

    // send the message to all the other members in the group
    Skissm__E2eeAddress *sender_address = remove_group_members_msg->sender_address;
    const char *sender_user_id = sender_address->user->user_id;
    for (i = 0; i < group_data_set[group_data_find].group_members_num; i++){
        // send to other group members
        const char *member_user_id = cur_group_data->group_members[i]->user_id;
        if (safe_strcmp(sender_user_id, member_user_id) == false){
            // copy_address_from_address(&(new_request->to), group_data_set[group_data_set_insert_pos].group_members[i]);
            // mock_protocol_send(new_request);

            // forward a copy of RemoveGroupMembersMsg
            Skissm__E2eeAddress **to_member_addresses = NULL;
            size_t to_member_addresses_num = find_user_addresses(member_user_id, &to_member_addresses);
            for (j = 0; j < to_member_addresses_num; j++) {
                Skissm__E2eeAddress *to_member_address = to_member_addresses[j];
                if (to_member_address == NULL)
                    continue;
                Skissm__ProtoMsg *proto_msg = (Skissm__ProtoMsg *)malloc(sizeof(Skissm__ProtoMsg));
                skissm__proto_msg__init(proto_msg);
                copy_address_from_address(&(proto_msg->from), sender_address);
                copy_address_from_address(&(proto_msg->to), to_member_address);
                proto_msg->payload_case = SKISSM__PROTO_MSG__PAYLOAD_REMOVE_GROUP_MEMBERS_MSG;
                proto_msg->remove_group_members_msg = skissm__remove_group_members_msg__unpack(NULL, remove_group_members_msg_data_len, remove_group_members_msg_data);

                size_t proto_msg_data_len = skissm__proto_msg__get_packed_size(proto_msg);
                uint8_t proto_msg_data[proto_msg_data_len];
                skissm__proto_msg__pack(proto_msg, proto_msg_data);

                Skissm__ConsumeProtoMsgResponse *consume_proto_msg_response = process_proto_msg(proto_msg_data, proto_msg_data_len);

                // release
                skissm__proto_msg__free_unpacked(proto_msg, NULL);
                skissm__consume_proto_msg_response__free_unpacked(consume_proto_msg_response, NULL);
                skissm__e2ee_address__free_unpacked(to_member_address, NULL);
            }
            // release
            if (to_member_addresses != NULL) {
                free((void *)to_member_addresses);
            }
        }
    }

    Skissm__RemoveGroupMembersResponse *response = (Skissm__RemoveGroupMembersResponse *)malloc(sizeof(Skissm__RemoveGroupMembersResponse));
    skissm__remove_group_members_response__init(response);
    response->code = SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK;
    response->n_group_members = new_group_members_num;
    response->group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *));
    for (i = 0; i < new_group_members_num; i++){
        (response->group_members)[i] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
        skissm__group_member__init((response->group_members)[i]);
        copy_group_member(&((response->group_members)[i]), (cur_group_data->group_members)[i]);
    }

    return response;
}

Skissm__SendGroupMsgResponse *mock_send_group_msg(Skissm__SendGroupMsgRequest *request) {
    Skissm__E2eeMsg *e2ee_msg = request->msg;
    size_t e2ee_msg_data_len = skissm__e2ee_msg__get_packed_size(e2ee_msg);
    uint8_t e2ee_msg_data[e2ee_msg_data_len];
    skissm__e2ee_msg__pack(e2ee_msg, e2ee_msg_data);

    // send the message to all the other members in the group
    Skissm__E2eeAddress *sender_address = e2ee_msg->from;
    Skissm__E2eeAddress *group_address = e2ee_msg->to;

    // find the group
    uint8_t group_data_find = 0;
    while (group_data_find < group_data_set_insert_pos){
        if ((group_data_set[group_data_find].group_address) && group_address
            && compare_address(group_data_set[group_data_find].group_address, group_address)
        ) {
            break;
        }
        group_data_find++;
    }

    // data not found
    if (group_data_find == group_data_set_insert_pos){
        Skissm__SendGroupMsgResponse *response = (Skissm__SendGroupMsgResponse *)malloc(sizeof(Skissm__SendGroupMsgResponse));
        skissm__send_group_msg_response__init(response);
        response->code = SKISSM__RESPONSE_CODE__RESPONSE_CODE_INTERNAL_SERVER_ERROR;
        return response;
    }

    group_data *cur_group_data = &(group_data_set[group_data_find]);

    const char *sender_user_id = sender_address->user->user_id;
    size_t i, j;
    for (i = 0; i < group_data_set[group_data_find].group_members_num; i++){
        // send to other group members
        const char *member_user_id = cur_group_data->group_members[i]->user_id;
        if (safe_strcmp(sender_user_id, member_user_id) == false){
            // copy_address_from_address(&(new_request->to), group_data_set[group_data_set_insert_pos].group_members[i]);
            // mock_protocol_send(new_request);

            // forward a copy of E2eeMsg
            Skissm__E2eeAddress **to_member_addresses = NULL;
            size_t to_member_addresses_num = find_user_addresses(member_user_id, &to_member_addresses);
            for (j = 0; j < to_member_addresses_num; j++) {
                Skissm__E2eeAddress *to_member_address = to_member_addresses[j];
                if (to_member_address == NULL)
                    continue;
                Skissm__ProtoMsg *proto_msg = (Skissm__ProtoMsg *)malloc(sizeof(Skissm__ProtoMsg));
                skissm__proto_msg__init(proto_msg);
                copy_address_from_address(&(proto_msg->from), sender_address);
                copy_address_from_address(&(proto_msg->to), to_member_address);
                proto_msg->payload_case = SKISSM__PROTO_MSG__PAYLOAD_E2EE_MSG;
                proto_msg->e2ee_msg = skissm__e2ee_msg__unpack(NULL, e2ee_msg_data_len, e2ee_msg_data);

                size_t proto_msg_data_len = skissm__proto_msg__get_packed_size(proto_msg);
                uint8_t proto_msg_data[proto_msg_data_len];
                skissm__proto_msg__pack(proto_msg, proto_msg_data);

                Skissm__ConsumeProtoMsgResponse *consume_proto_msg_response = process_proto_msg(proto_msg_data, proto_msg_data_len);

                // release
                skissm__proto_msg__free_unpacked(proto_msg, NULL);
                skissm__consume_proto_msg_response__free_unpacked(consume_proto_msg_response, NULL);
                skissm__e2ee_address__free_unpacked(to_member_address, NULL);
            }
            // release
            if (to_member_addresses != NULL) {
                free((void *)to_member_addresses);
            }
        }
    }

    Skissm__SendGroupMsgResponse *response = (Skissm__SendGroupMsgResponse *)malloc(sizeof(Skissm__SendGroupMsgResponse));
    skissm__send_group_msg_response__init(response);
    response->code = SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK;

    return response;
}

Skissm__ConsumeProtoMsgResponse *mock_consume_proto_msg(Skissm__ConsumeProtoMsgRequest *request) {
    size_t request_data_len = skissm__consume_proto_msg_request__get_packed_size(request);
    uint8_t *request_data = (uint8_t *)malloc(request_data_len);
    skissm__consume_proto_msg_request__pack(request, request_data);

    Skissm__ConsumeProtoMsgResponse *response = (Skissm__ConsumeProtoMsgResponse *)malloc(sizeof(Skissm__ConsumeProtoMsgResponse));
    skissm__consume_proto_msg_response__init(response);
    response->code = SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK;

    return response;
}
