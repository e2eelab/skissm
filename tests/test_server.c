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
#include "test_server.h"

#include <string.h>

#include "skissm/mem_util.h"

#include "test_util.h"

typedef struct user_data{
    Skissm__E2eeAddress *address;
    const char *device_id;
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

#define user_data_max 8

#define group_data_max 8

static user_data user_data_set[user_data_max] = {
    {NULL, NULL, NULL, NULL, NULL, NULL, 0},
    {NULL, NULL, NULL, NULL, NULL, NULL, 0},
    {NULL, NULL, NULL, NULL, NULL, NULL, 0},
    {NULL, NULL, NULL, NULL, NULL, NULL, 0},
    {NULL, NULL, NULL, NULL, NULL, NULL, 0},
    {NULL, NULL, NULL, NULL, NULL, NULL, 0},
    {NULL, NULL, NULL, NULL, NULL, NULL, 0},
    {NULL, NULL, NULL, NULL, NULL, NULL, 0}};

static group_data group_data_set[user_data_max] = {
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

void test_server_begin(){
}

void test_server_end(){
   uint8_t i, j;
   for (i = 0; i < user_data_set_insert_pos; i++){
       skissm__e2ee_address__free_unpacked(user_data_set[i].address, NULL);
       user_data_set[i].address = NULL;

       free((void *)(user_data_set[i].device_id));
       free((void *)(user_data_set[i].user_name));
       skissm__identity_key_public__free_unpacked(user_data_set[i].identity_key_public, NULL);
       skissm__signed_pre_key_public__free_unpacked(user_data_set[i].signed_pre_key_public, NULL);
       for(int j=0; j<user_data_set[i].n_one_time_pre_keys; j++) {
           skissm__one_time_pre_key_public__free_unpacked(user_data_set[i].one_time_pre_keys[j], NULL);
       }
       free_mem((void **)(&(user_data_set[i].one_time_pre_keys)), sizeof(Skissm__OneTimePreKeyPublic *) * user_data_set[i].n_one_time_pre_keys);
       user_data_set[i].user_name = NULL;
       user_data_set[i].device_id = NULL;
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
           skissm__group_member__free_unpacked(group_data_set[i].group_members[j], NULL);
           group_data_set[i].group_members[j] = NULL;
       }
       free_mem((void **)(&(group_data_set[i].group_members)), sizeof(Skissm__GroupMember *) * group_data_set[i].group_members_num);
       group_data_set[i].group_members_num = 0;
   }
   group_data_set_insert_pos = 0;
}

Skissm__RegisterUserResponse *test_register_user(Skissm__RegisterUserRequest *request) {
    user_data *cur_data = &(user_data_set[user_data_set_insert_pos]);
    /* prepare to store */
    cur_data->device_id = strdup(request->device_id);
    cur_data->user_name = strdup(request->user_name);

    copy_ik_public_from_ik_public(&(cur_data->identity_key_public), request->identity_key_public);
    copy_spk_public_from_spk_public(&(cur_data->signed_pre_key_public), request->signed_pre_key_public);
    cur_data->n_one_time_pre_keys = request->n_one_time_pre_keys;
    cur_data->one_time_pre_keys = (Skissm__OneTimePreKeyPublic **) malloc(sizeof(Skissm__OneTimePreKeyPublic *) * cur_data->n_one_time_pre_keys);
    unsigned i;
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

    return response;
}

Skissm__GetPreKeyBundleResponse *test_get_pre_key_bundle(Skissm__GetPreKeyBundleRequest *request) {
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

    // Skissm__ResponseData *response_data = (Skissm__ResponseData *)malloc(sizeof(Skissm__ResponseData));
    // skissm__response_data__init(response_data);

    // if (user_data_find == user_data_set_insert_pos){
    //     response_data->code = Internal_Server_Error;
    //     goto complete;
    // }

    user_data *cur_data = &(user_data_set[user_data_find]);

    response = (Skissm__GetPreKeyBundleResponse *) malloc(sizeof(Skissm__GetPreKeyBundleResponse));
    skissm__get_pre_key_bundle_response__init(response);
    response->pre_key_bundles = (Skissm__PreKeyBundle **) malloc(sizeof(Skissm__PreKeyBundle *));
    response->pre_key_bundles[0] = (Skissm__PreKeyBundle *) malloc(sizeof(Skissm__PreKeyBundle));
    skissm__pre_key_bundle__init(response->pre_key_bundles[0]);

    copy_address_from_address(&(response->pre_key_bundles[0]->user_address), request->user_address);
    copy_ik_public_from_ik_public(&(response->pre_key_bundles[0]->identity_key_public), cur_data->identity_key_public);
    copy_spk_public_from_spk_public(&(response->pre_key_bundles[0]->signed_pre_key_public), cur_data->signed_pre_key_public);
    // TODO: remove one_time_pre_keys[0] and append to response->pre_key_bundles
    unsigned i;
    for (i = 0; i < cur_data->n_one_time_pre_keys; i++){
        if (cur_data->one_time_pre_keys[i]){
            copy_opk_public_from_opk_public(&(response->pre_key_bundles[0]->one_time_pre_key_public), cur_data->one_time_pre_keys[i]);
            break;
        }
    }
    /* release the one-time pre-key */
    skissm__one_time_pre_key_public__free_unpacked(cur_data->one_time_pre_keys[i], NULL);
    cur_data->one_time_pre_keys[i] = NULL;

    return response;
}

Skissm__InviteResponse *test_invite(Skissm__InviteRequest *request) {
    size_t request_data_len = skissm__invite_request__get_packed_size(request);
    uint8_t *request_data = (uint8_t *)malloc(request_data_len);
    skissm__invite_request__pack(request, request_data);

    Skissm__InviteResponse *response = NULL;
    return response;
}

Skissm__AcceptResponse *test_accept(Skissm__AcceptRequest *request) {
    size_t request_data_len = skissm__accept_request__get_packed_size(request);
    uint8_t *request_data = (uint8_t *)malloc(request_data_len);
    skissm__accept_request__pack(request, request_data);

    Skissm__AcceptResponse *response = NULL;
    return response;
}

Skissm__PublishSpkResponse *test_publish_spk(Skissm__PublishSpkRequest *request) {
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

    // if (user_data_find == user_data_set_insert_pos){
    //     response_data->code = Internal_Server_Error;
    //     goto complete;
    // }

    user_data *cur_data = &(user_data_set[user_data_find]);
    // release old memory
    skissm__signed_pre_key_public__free_unpacked(cur_data->signed_pre_key_public, NULL);
    // copy new data
    copy_spk_public_from_spk_public(&(cur_data->signed_pre_key_public), request->signed_pre_key_public);

    Skissm__PublishSpkResponse *response = NULL;
    return response;
}

Skissm__SupplyOpksResponse *test_supply_opks(Skissm__SupplyOpksRequest *request) {
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
    unsigned i;
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

    Skissm__SupplyOpksResponse *response = NULL;
    return response;
}

Skissm__SendOne2oneMsgResponse *test_send_one2one_msg(Skissm__SendOne2oneMsgRequest *request) {
    size_t request_data_len = skissm__send_one2one_msg_request__get_packed_size(request);
    uint8_t *request_data = (uint8_t *)malloc(request_data_len);
    skissm__send_one2one_msg_request__pack(request, request_data);

    Skissm__SendOne2oneMsgResponse *response = NULL;
    return response;
}

Skissm__CreateGroupResponse *test_create_group(Skissm__CreateGroupRequest *request) {
    group_data *cur_group_data = &(group_data_set[group_data_set_insert_pos]);
    /* prepare to store */
    cur_group_data->group_name = strdup(request->msg->group_name);
    cur_group_data->group_members_num = request->msg->n_group_members;
    copy_group_members(&(cur_group_data->group_members), request->msg->group_members, request->msg->n_group_members);

    /* Generate a random address */
    mock_random_group_address(&(cur_group_data->group_address));

    /* prepare a new request */
    // TODO

    /* send the message to all the other members in the group */
    unsigned i;
    for (i = 0; i < group_data_set[group_data_set_insert_pos].group_members_num; i++){
        if (safe_strcmp(request->msg->sender_address->user->user_id, cur_group_data->group_members[i]->user_id) == false){
            // copy_address_from_address(&(new_request->to), group_data_set[group_data_set_insert_pos].group_members[i]);
            // mock_protocol_send(new_request);
        }
    }

    group_data_set_insert_pos++;

    Skissm__CreateGroupResponse *response = NULL;
    return response;
}

Skissm__AddGroupMembersResponse *test_add_group_members(Skissm__AddGroupMembersRequest *request) {
    /* find the group */
    uint8_t group_data_find = 0;
    while (group_data_find < group_data_set_insert_pos){
        if ((group_data_set[group_data_find].group_address) && (request->msg->group_address)
            && compare_address(group_data_set[group_data_find].group_address, request->msg->group_address)
        ) {
            break;
        }
        group_data_find++;
    }

    // if (group_data_find == group_data_set_insert_pos){
    //     response_data->code = Internal_Server_Error;
    //     goto complete;
    // }

    group_data *cur_group_data = &(group_data_set[group_data_find]);

    /* update the data */
    size_t old_group_members_num = cur_group_data->group_members_num;
    size_t new_group_members_num = cur_group_data->group_members_num + request->msg->n_adding_members;
    cur_group_data->group_members_num = new_group_members_num;

    Skissm__GroupMember **temp_group_members = NULL;
    temp_group_members = (Skissm__GroupMember **) malloc(sizeof(Skissm__GroupMember *) * new_group_members_num);
    unsigned i;
    for (i = 0; i < old_group_members_num; i++){
        copy_group_member(&(temp_group_members[i]), cur_group_data->group_members[i]);
        skissm__group_member__free_unpacked(cur_group_data->group_members[i], NULL);
    }
    free_mem((void **)(&(cur_group_data->group_members)), sizeof(Skissm__GroupMember *) * old_group_members_num);
    cur_group_data->group_members = temp_group_members;

    for (i = old_group_members_num; i < new_group_members_num; i++){
        copy_group_member(&(cur_group_data->group_members[i]), (request->msg->adding_members)[i - old_group_members_num]);
    }

    /* send the message to all the other members in the group */
    for (i = 0; i < cur_group_data->group_members_num; i++){
        if (safe_strcmp(request->msg->sender_address->user->user_id, cur_group_data->group_members[i]->user_id) == false){
            // copy_address_from_address(&(request->to), cur_group_data->group_members[i]);
            // mock_protocol_send(request);
        }
    }

    Skissm__AddGroupMembersResponse *response = NULL;
    return response;
}

Skissm__RemoveGroupMembersResponse *test_remove_group_members(Skissm__RemoveGroupMembersRequest *request) {
    /* find the group */
    uint8_t group_data_find = 0;
    while (group_data_find < group_data_set_insert_pos){
        if ((group_data_set[group_data_find].group_address) && (request->msg->group_address)
            && compare_address(group_data_set[group_data_find].group_address, request->msg->group_address)
        ) {
            break;
        }
        group_data_find++;
    }

    // if (group_data_find == group_data_set_insert_pos){
    //     response_data->code = Internal_Server_Error;
    //     goto complete;
    // }

    group_data *cur_group_data = &(group_data_set[group_data_find]);

    /* update the data */
    size_t original_group_members_num = cur_group_data->group_members_num;
    size_t new_group_members_num = original_group_members_num - request->msg->n_removing_members;
    cur_group_data->group_members_num = new_group_members_num;

    size_t i,j;
    for (j = 0; j < request->msg->n_removing_members; j++){
        for (i = 0; i < original_group_members_num; i++){
            if (safe_strcmp(cur_group_data->group_members[i]->user_id, request->msg->removing_members[j]->user_id)){
                skissm__group_member__free_unpacked(cur_group_data->group_members[i], NULL);
                cur_group_data->group_members[i] = NULL;
                break;
            }
        }
    }

    Skissm__GroupMember **temp_group_members;
    temp_group_members = (Skissm__GroupMember **) malloc(sizeof(Skissm__GroupMember *) * new_group_members_num);
    i = 0; j = 0;
    while (i < new_group_members_num && j < original_group_members_num){
        if (cur_group_data->group_members[j] != NULL){
            copy_group_member(&(temp_group_members[i]), cur_group_data->group_members[j]);
            i++; j++;
        } else{
            j++;
        }
    }

    i = 0;
    for (i = 0; i < original_group_members_num; i++){
        skissm__group_member__free_unpacked(cur_group_data->group_members[i], NULL);
        cur_group_data->group_members[i] = NULL;
    }
    free(cur_group_data->group_members);
    cur_group_data->group_members = temp_group_members;

    /* send the message to all the other members in the group */
    for (i = 0; i < cur_group_data->group_members_num; i++){
        if (safe_strcmp(request->msg->sender_address->user->user_id, cur_group_data->group_members[i]->user_id) == false){
            // copy_address_from_address(&(request->to), cur_group_data->group_members[i]);
            // mock_protocol_send(request);
        }
    }

    Skissm__RemoveGroupMembersResponse *response = NULL;
    return response;
}

Skissm__SendGroupMsgResponse *test_send_group_msg(Skissm__SendGroupMsgRequest *request) {
    size_t request_data_len = skissm__send_group_msg_request__get_packed_size(request);
    uint8_t *request_data = (uint8_t *)malloc(request_data_len);
    skissm__send_group_msg_request__pack(request, request_data);

    Skissm__SendGroupMsgResponse *response = NULL;
    return response;
}

Skissm__ConsumeProtoMsgResponse *test_consume_proto_msg(Skissm__ConsumeProtoMsgRequest *request) {
    size_t request_data_len = skissm__consume_proto_msg_request__get_packed_size(request);
    uint8_t *request_data = (uint8_t *)malloc(request_data_len);
    skissm__consume_proto_msg_request__pack(request, request_data);

    Skissm__ConsumeProtoMsgResponse *response = NULL;
    return response;
}