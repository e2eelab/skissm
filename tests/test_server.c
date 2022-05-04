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


Skissm__RegisterUserResponse *test_register_user(Skissm__RegisterUserRequest *request) {
    size_t request_data_len = skissm__register_user_request__get_packed_size(request);
    uint8_t *request_data = (uint8_t *)malloc(request_data_len);
    skissm__register_user_request__pack(request, request_data);

    Skissm__RegisterUserResponse *response = NULL;
    return response;
}

Skissm__GetPreKeyBundleResponse *test_get_pre_key_bundle(Skissm__GetPreKeyBundleRequest *request) {
    size_t request_data_len = skissm__get_pre_key_bundle_request__get_packed_size(request);
    uint8_t *request_data = (uint8_t *)malloc(request_data_len);
    skissm__get_pre_key_bundle_request__pack(request, request_data);

    Skissm__GetPreKeyBundleResponse *response = NULL;
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