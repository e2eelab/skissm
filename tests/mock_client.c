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
#include "mock_client.h"
#include "mock_client_transport.h"
#include "rr_type.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

Skissm__RegisterUserResponse *process_register_user(Skissm__RegisterUserRequest *request) {
    proto_msg_package proto_msg_bytes;

    size_t len = skissm__register_user_request__get_packed_size(request);
    uint8_t *data = (uint8_t *)malloc(sizeof(uint8_t) * len);
    skissm__register_user_request__pack(request, data);

    proto_msg_bytes.type = REGISTER_USER;

    Skissm__E2eeAddress *user_address = (Skissm__E2eeAddress *)malloc(sizeof(Skissm__E2eeAddress));
    skissm__e2ee_address__init(user_address);
    user_address->peer_case = SKISSM__E2EE_ADDRESS__PEER_USER;
    user_address->user = (Skissm__PeerUser *)malloc(sizeof(Skissm__PeerUser));
    skissm__peer_user__init(user_address->user);
    user_address->user->user_name = strdup(request->user_name);
    user_address->user->user_id = strdup(request->user_id);
    user_address->user->device_id = strdup(request->device_id);

    proto_msg_bytes.address_data = user_address;
    proto_msg_bytes.proto_msg_len = len;
    proto_msg_bytes.proto_msg_data = data;

    uint8_t *cl_msg = (uint8_t *)malloc(sizeof(proto_msg_bytes));
    send_to_server(cl_msg);
}

Skissm__GetPreKeyBundleResponse *process_get_pre_key_bundle(
    Skissm__E2eeAddress *from, const char *auth, Skissm__GetPreKeyBundleRequest *request
) {
    size_t len = skissm__get_pre_key_bundle_request__get_packed_size(request);
    uint8_t *data = (uint8_t *)malloc(sizeof(uint8_t) * len);
    skissm__get_pre_key_bundle_request__pack(request, data);
}

Skissm__InviteResponse *process_invite(Skissm__E2eeAddress *from, const char *auth, Skissm__InviteRequest *request) {
    size_t len = skissm__invite_request__get_packed_size(request);
    uint8_t *data = (uint8_t *)malloc(sizeof(uint8_t) * len);
    skissm__invite_request__pack(request, data);
}

Skissm__AcceptResponse *process_accept(Skissm__E2eeAddress *from, const char *auth, Skissm__AcceptRequest *request) {
    size_t len = skissm__accept_request__get_packed_size(request);
    uint8_t *data = (uint8_t *)malloc(sizeof(uint8_t) * len);
    skissm__accept_request__pack(request, data);
}

Skissm__PublishSpkResponse *process_publish_spk(Skissm__E2eeAddress *from, const char *auth, Skissm__PublishSpkRequest *request) {
    size_t len = skissm__publish_spk_request__get_packed_size(request);
    uint8_t *data = (uint8_t *)malloc(sizeof(uint8_t) * len);
    skissm__publish_spk_request__pack(request, data);
}

Skissm__SupplyOpksResponse *process_supply_opks(Skissm__E2eeAddress *from, const char *auth, Skissm__SupplyOpksRequest *request) {
    size_t len = skissm__supply_opks_request__get_packed_size(request);
    uint8_t *data = (uint8_t *)malloc(sizeof(uint8_t) * len);
    skissm__supply_opks_request__pack(request, data);
}

Skissm__SendOne2oneMsgResponse *process_send_one2one_msg(
    Skissm__E2eeAddress *from, const char *auth, Skissm__SendOne2oneMsgRequest *request
) {
    size_t len = skissm__send_one2one_msg_request__get_packed_size(request);
    uint8_t *data = (uint8_t *)malloc(sizeof(uint8_t) * len);
    skissm__send_one2one_msg_request__pack(request, data);
}

Skissm__CreateGroupResponse *process_create_group(Skissm__E2eeAddress *from, const char *auth, Skissm__CreateGroupRequest *request) {
    size_t len = skissm__create_group_request__get_packed_size(request);
    uint8_t *data = (uint8_t *)malloc(sizeof(uint8_t) * len);
    skissm__create_group_request__pack(request, data);
}

Skissm__AddGroupMembersResponse *process_add_group_members(
    Skissm__E2eeAddress *from, const char *auth, Skissm__AddGroupMembersRequest *request
) {
    size_t len = skissm__add_group_members_request__get_packed_size(request);
    uint8_t *data = (uint8_t *)malloc(sizeof(uint8_t) * len);
    skissm__add_group_members_request__pack(request, data);
}

Skissm__AddGroupMemberDeviceResponse *process_add_group_member_device(
    Skissm__E2eeAddress *from, const char *auth, Skissm__AddGroupMemberDeviceRequest *request
) {
    size_t len = skissm__add_group_member_device_request__get_packed_size(request);
    uint8_t *data = (uint8_t *)malloc(sizeof(uint8_t) * len);
    skissm__add_group_member_device_request__pack(request, data);
}

Skissm__RemoveGroupMembersResponse *process_remove_group_members(
    Skissm__E2eeAddress *from, const char *auth, Skissm__RemoveGroupMembersRequest *request
) {
    size_t len = skissm__remove_group_members_request__get_packed_size(request);
    uint8_t *data = (uint8_t *)malloc(sizeof(uint8_t) * len);
    skissm__remove_group_members_request__pack(request, data);
}

Skissm__LeaveGroupResponse *process_leave_group(Skissm__E2eeAddress *from, const char *auth, Skissm__LeaveGroupRequest *request) {
    size_t len = skissm__leave_group_request__get_packed_size(request);
    uint8_t *data = (uint8_t *)malloc(sizeof(uint8_t) * len);
    skissm__leave_group_request__pack(request, data);
}

Skissm__SendGroupMsgResponse *process_send_group_msg(
    Skissm__E2eeAddress *from, const char *auth, Skissm__SendGroupMsgRequest *request
) {
    size_t len = skissm__send_group_msg_request__get_packed_size(request);
    uint8_t *data = (uint8_t *)malloc(sizeof(uint8_t) * len);
    skissm__send_group_msg_request__pack(request, data);
}

Skissm__ConsumeProtoMsgResponse *process_consume_proto_msg(
    Skissm__E2eeAddress *from, const char *auth, Skissm__ConsumeProtoMsgRequest *request
) {
    size_t len = skissm__consume_proto_msg_request__get_packed_size(request);
    uint8_t *data = (uint8_t *)malloc(sizeof(uint8_t) * len);
    skissm__consume_proto_msg_request__pack(request, data);
}
