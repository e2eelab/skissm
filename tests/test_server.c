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

#include "skissm/mem_util.h"

#include "test_util.h"

typedef struct user_data{
    Skissm__E2eeAddress *address;
    char *deviceId;
    char *userName;
    Skissm__IdentityKeyPublic *identity_key_public;
    Skissm__SignedPreKeyPublic *signed_pre_key_public;
    Skissm__OneTimePreKeyPublic **one_time_pre_keys;
    size_t n_one_time_pre_keys;
} user_data;

typedef struct group_data{
    Skissm__E2eeAddress *group_address;
    char *group_name;
    size_t member_num;
    Skissm__E2eeAddress **member_addresses;
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
//    uint8_t i, j;
//    for (i = 0; i < user_data_set_insert_pos; i++){
//        skissm__e2ee_address__free_unpacked(user_data_set[i].address, NULL);
//        user_data_set[i].address = NULL;
//
//        free(user_data_set[i].deviceId);
//        free(user_data_set[i].userName);
//        skissm__identity_key_public__free_unpacked(user_data_set[i].identity_key_public, NULL);
//        skissm__signed_pre_key_public__free_unpacked(user_data_set[i].signed_pre_key_public, NULL);
//        for(int j=0; j<user_data_set[i].n_one_time_pre_keys; j++) {
//            skissm__one_time_pre_key_public__free_unpacked(one_time_pre_keys[j], NULL);
//        }
//        free_mem((void **)(&(user_data_set[i].one_time_pre_keys)), user_data_set[i].n_one_time_pre_keys);
//        user_data_set[i].user
//        = NULL;
//        user_data_set[i].deviceId = NULL;
//        user_data_set[i].identity_key_public = NULL;
//        user_data_set[i].signed_pre_key_public = NULL;
//        user_data_set[i].one_time_pre_keys = NULL;
//        user_data_set[i].n_one_time_pre_keys = 0;
//    }
//    user_data_set_insert_pos = 0;
//    for (i = 0; i < group_data_set_insert_pos; i++){
//        skissm__e2ee_address__free_unpacked(group_data_set[i].group_address, NULL);
//        group_data_set[i].group_address = NULL;
//        free(group_data_set[i].group_name);
//        group_data_set[i].group_name = NULL;
//        for (j = 0; j < group_data_set[i].member_num; j++){
//            skissm__e2ee_address__free_unpacked(group_data_set[i].member_addresses[j], NULL);
//            group_data_set[i].member_addresses[j] = NULL;
//        }
//        group_data_set[i].member_num = 0;
//    }
//    group_data_set_insert_pos = 0;
}

Skissm__RegisterUserResponse *test_register_user(Skissm__RegisterUserRequest *request) {
//    /* prepare to store */
//    user_data_set[user_data_set_insert_pos].deviceId = strdup(request->device_id);
//    user_data_set[user_data_set_insert_pos].userName = strdup(request->user_name);
//    user_data_set[user_data_set_insert_pos].identity_key_public = request->identity_key_public;
//    user_data_set[user_data_set_insert_pos].signed_pre_key_public = request->signed_pre_key_public;
//    user_data_set[user_data_set_insert_pos].one_time_pre_keys = request->identity_key_public;
//    user_data_set[user_data_set_insert_pos].n_one_time_pre_keys = ;
//
//
//
//    user_data_set[user_data_set_insert_pos].identity_key_public = (Skissm__IdentityKeyPublic *) malloc(sizeof(Skissm__IdentityKeyPublic));
//    skissm__identity_key_public__init(user_data_set[user_data_set_insert_pos].identity_key_public);
//    copy_protobuf_from_protobuf(&(user_data_set[user_data_set_insert_pos].identity_key_public->asym_public_key), &(request->identity_key_public->asym_public_key));
//    copy_protobuf_from_protobuf(&(user_data_set[user_data_set_insert_pos].identity_key_public->sign_public_key), &(request->identity_key_public->sign_public_key));
//    user_data_set[user_data_set_insert_pos].signed_pre_key_public = (Skissm__SignedPreKeyPublic *) malloc(sizeof(Skissm__SignedPreKeyPublic));
//    skissm__signed_pre_key_public__init(user_data_set[user_data_set_insert_pos].signed_pre_key_public);
//    user_data_set[user_data_set_insert_pos].signed_pre_key_public->spk_id = request->signed_pre_key_public->spk_id;
//    copy_protobuf_from_protobuf(&(user_data_set[user_data_set_insert_pos].signed_pre_key_public->public_key), &(request->signed_pre_key_public->public_key));
//    copy_protobuf_from_protobuf(&(user_data_set[user_data_set_insert_pos].signed_pre_key_public->signature), &(request->signed_pre_key_public->signature));
//    user_data_set[user_data_set_insert_pos].n_one_time_pre_keys = request->n_one_time_pre_keys;
//    user_data_set[user_data_set_insert_pos].one_time_pre_keys = (Skissm__OneTimePreKeyPublic **) malloc(sizeof(Skissm__OneTimePreKeyPublic *) * user_data_set[user_data_set_insert_pos].n_one_time_pre_keys);
//    unsigned int i;
//    for (i = 0; i < user_data_set[user_data_set_insert_pos].n_one_time_pre_keys; i++){
//        user_data_set[user_data_set_insert_pos].one_time_pre_keys[i] = (Skissm__OneTimePreKeyPublic *) malloc(sizeof(Skissm__OneTimePreKeyPublic));
//        skissm__one_time_pre_key_public__init(user_data_set[user_data_set_insert_pos].one_time_pre_keys[i]);
//        user_data_set[user_data_set_insert_pos].one_time_pre_keys[i]->opk_id = request->one_time_pre_keys[i]->opk_id;
//        copy_protobuf_from_protobuf(&(user_data_set[user_data_set_insert_pos].one_time_pre_keys[i]->public_key), &(request->one_time_pre_keys[i]->public_key));
//    }
//
//    /* Generate a random address */
//    user_data_set[user_data_set_insert_pos].address = mock_random_address();
//
//    user_data_set_insert_pos++;
//
//    Skissm__RegisterUserResponse *response
//        = (Skissm__RegisterUserResponse *)malloc(sizeof(Skissm__RegisterUserResponse));
//    skissm__register_user_response__init(response);
//    copy_address_from_address(&(response->address),user_data_set[user_data_set_insert_pos].address);
//
//    return response;
    return NULL;
}

Skissm__GetPreKeyBundleResponse *test_get_pre_key_bundle(Skissm__GetPreKeyBundleRequest *request) {
    Skissm__GetPreKeyBundleResponse *response = NULL;

    // uint8_t user_data_find = 0;
    // while (user_data_find < user_data_set_insert_pos)
    // {
    //     if ((user_data_set[user_data_find].address) && (request->peer_address)
    //         && compare_address(user_data_set[user_data_find].address, request->peer_address)
    //     ) {
    //         break;
    //     }
    //     user_data_find++;
    // }

    // // Skissm__ResponseData *response_data = (Skissm__ResponseData *)malloc(sizeof(Skissm__ResponseData));
    // // skissm__response_data__init(response_data);

    // // if (user_data_find == user_data_set_insert_pos){
    // //     response_data->code = Internal_Server_Error;
    // //     goto complete;
    // // }

    // get_pre_key_bundle_response_payload->pre_key_bundle = (Skissm__PreKeyBundle *) malloc(sizeof(Skissm__PreKeyBundle));
    // skissm__pre_key_bundle__init(get_pre_key_bundle_response_payload->pre_key_bundle);

    // copy_address_from_address(&(get_pre_key_bundle_response_payload->pre_key_bundle->peer_address), request->peer_address);
    // get_pre_key_bundle_response_payload->pre_key_bundle->identity_key_public = (Skissm__IdentityKeyPublic *) malloc(sizeof(Skissm__IdentityKeyPublic));
    // skissm__identity_key_public__init(get_pre_key_bundle_response_payload->pre_key_bundle->identity_key_public);
    // copy_protobuf_from_protobuf(&(get_pre_key_bundle_response_payload->pre_key_bundle->identity_key_public->asym_public_key), &(user_data_set[user_data_find].pre_key->identity_key_public->asym_public_key));
    // copy_protobuf_from_protobuf(&(get_pre_key_bundle_response_payload->pre_key_bundle->identity_key_public->sign_public_key), &(user_data_set[user_data_find].pre_key->identity_key_public->sign_public_key));
    // get_pre_key_bundle_response_payload->pre_key_bundle->signed_pre_key_public = (Skissm__SignedPreKeyPublic *) malloc(sizeof(Skissm__SignedPreKeyPublic));
    // skissm__signed_pre_key_public__init(get_pre_key_bundle_response_payload->pre_key_bundle->signed_pre_key_public);
    // get_pre_key_bundle_response_payload->pre_key_bundle->signed_pre_key_public->spk_id = user_data_set[user_data_find].pre_key->signed_pre_key_public->spk_id;
    // copy_protobuf_from_protobuf(&(get_pre_key_bundle_response_payload->pre_key_bundle->signed_pre_key_public->public_key), &(user_data_set[user_data_find].pre_key->signed_pre_key_public->public_key));
    // copy_protobuf_from_protobuf(&(get_pre_key_bundle_response_payload->pre_key_bundle->signed_pre_key_public->signature), &(user_data_set[user_data_find].pre_key->signed_pre_key_public->signature));
    // uint8_t i;
    // for (i = 0; i < user_data_set[user_data_find].pre_key->n_one_time_pre_keys; i++){
    //     if (user_data_set[user_data_find].pre_key->one_time_pre_keys[i]){
    //         get_pre_key_bundle_response_payload->pre_key_bundle->one_time_pre_key_public = (Skissm__OneTimePreKeyPublic *) malloc(sizeof(Skissm__OneTimePreKeyPublic));
    //         skissm__one_time_pre_key_public__init(get_pre_key_bundle_response_payload->pre_key_bundle->one_time_pre_key_public);
    //         get_pre_key_bundle_response_payload->pre_key_bundle->one_time_pre_key_public->opk_id = user_data_set[user_data_find].pre_key->one_time_pre_keys[i]->opk_id;
    //         copy_protobuf_from_protobuf(&(get_pre_key_bundle_response_payload->pre_key_bundle->one_time_pre_key_public->public_key), &(user_data_set[user_data_find].pre_key->one_time_pre_keys[i]->public_key));
    //         break;
    //     }
    // }
    // /* release the one-time pre-key */
    // skissm__one_time_pre_key_public__free_unpacked(user_data_set[user_data_find].pre_key->one_time_pre_keys[i], NULL);
    // user_data_set[user_data_find].pre_key->one_time_pre_keys[i] = NULL;

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
    size_t request_data_len = skissm__publish_spk_request__get_packed_size(request);
    uint8_t *request_data = (uint8_t *)malloc(request_data_len);
    skissm__publish_spk_request__pack(request, request_data);

    Skissm__PublishSpkResponse *response = NULL;
    return response;
}

Skissm__SupplyOpksResponse *test_supply_opks(Skissm__SupplyOpksRequest *request) {
    size_t request_data_len = skissm__supply_opks_request__get_packed_size(request);
    uint8_t *request_data = (uint8_t *)malloc(request_data_len);
    skissm__supply_opks_request__pack(request, request_data);

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
    size_t request_data_len = skissm__create_group_request__get_packed_size(request);
    uint8_t *request_data = (uint8_t *)malloc(request_data_len);
    skissm__create_group_request__pack(request, request_data);

    Skissm__CreateGroupResponse *response = NULL;
    return response;
}

Skissm__AddGroupMembersResponse *test_add_group_members(Skissm__AddGroupMembersRequest *request) {
    size_t request_data_len = skissm__add_group_members_request__get_packed_size(request);
    uint8_t *request_data = (uint8_t *)malloc(request_data_len);
    skissm__add_group_members_request__pack(request, request_data);

    Skissm__AddGroupMembersResponse *response = NULL;
    return response;
}

Skissm__RemoveGroupMembersResponse *test_remove_group_members(Skissm__RemoveGroupMembersRequest *request) {
    size_t request_data_len = skissm__remove_group_members_request__get_packed_size(request);
    uint8_t *request_data = (uint8_t *)malloc(request_data_len);
    skissm__remove_group_members_request__pack(request, request_data);

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