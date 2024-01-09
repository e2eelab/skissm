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
#ifndef MOCK_SERVER_H_
#define MOCK_SERVER_H_

#include "skissm/skissm.h"

void mock_server_begin();

/**
 * @brief Close the mock server
 * 
 */
void mock_server_end();

/**
 * @brief 
 * 
 * @param request 
 * @return Skissm__RegisterUserResponse* 
 */
Skissm__RegisterUserResponse *mock_register_user(Skissm__RegisterUserRequest *request);

/**
 * @brief Get the pre-key bundle object
 * 
 * @param from 
 * @param auth 
 * @param request 
 * @return Skissm__GetPreKeyBundleResponse* 
 */
Skissm__GetPreKeyBundleResponse *mock_get_pre_key_bundle(Skissm__E2eeAddress *from, const char *auth, Skissm__GetPreKeyBundleRequest *request);

/**
 * @brief 
 * 
 * @param request 
 * @return Skissm__InviteResponse* 
 */
Skissm__InviteResponse *mock_invite(Skissm__E2eeAddress *from, const char *auth, Skissm__InviteRequest *request);

/**
 * @brief 
 * 
 * @param from 
 * @param auth 
 * @param request 
 * @return Skissm__AcceptResponse* 
 */
Skissm__AcceptResponse *mock_accept(Skissm__E2eeAddress *from, const char *auth, Skissm__AcceptRequest *request);

/**
 * @brief 
 * 
 * @param from 
 * @param auth 
 * @param request 
 * @return Skissm__PublishSpkResponse* 
 */
Skissm__PublishSpkResponse *mock_publish_spk(Skissm__E2eeAddress *from, const char *auth, Skissm__PublishSpkRequest *request);

/**
 * @brief 
 * 
 * @param from 
 * @param auth 
 * @param request 
 * @return Skissm__SupplyOpksResponse* 
 */
Skissm__SupplyOpksResponse *mock_supply_opks(Skissm__E2eeAddress *from, const char *auth, Skissm__SupplyOpksRequest *request);

/**
 * @brief 
 * 
 * @param from 
 * @param auth 
 * @param request 
 * @return Skissm__SendOne2oneMsgResponse* 
 */
Skissm__SendOne2oneMsgResponse *mock_send_one2one_msg(Skissm__E2eeAddress *from, const char *auth, Skissm__SendOne2oneMsgRequest *request);

/**
 * @brief Create a group object
 * 
 * @param from 
 * @param auth 
 * @param request 
 * @return Skissm__CreateGroupResponse* 
 */
Skissm__CreateGroupResponse *mock_create_group(Skissm__E2eeAddress *from, const char *auth, Skissm__CreateGroupRequest *request);

/**
 * @brief 
 * 
 * @param from 
 * @param auth 
 * @param request 
 * @return Skissm__AddGroupMembersResponse* 
 */
Skissm__AddGroupMembersResponse *mock_add_group_members(Skissm__E2eeAddress *from, const char *auth, Skissm__AddGroupMembersRequest *request);

/**
 * @brief 
 * 
 * @param from 
 * @param auth 
 * @param request 
 * @return Skissm__AddGroupMemberDeviceResponse* 
 */
Skissm__AddGroupMemberDeviceResponse *mock_add_group_member_device(
    Skissm__E2eeAddress *from, const char *auth, Skissm__AddGroupMemberDeviceRequest *request
);

/**
 * @brief 
 * 
 * @param from 
 * @param auth 
 * @param request 
 * @return Skissm__RemoveGroupMembersResponse* 
 */
Skissm__RemoveGroupMembersResponse *mock_remove_group_members(Skissm__E2eeAddress *from, const char *auth, Skissm__RemoveGroupMembersRequest *request);

/**
 * @brief 
 * 
 * @param from 
 * @param auth 
 * @param request 
 * @return Skissm__LeaveGroupResponse* 
 */
Skissm__LeaveGroupResponse *mock_leave_group(Skissm__E2eeAddress *from, const char *auth, Skissm__LeaveGroupRequest *request);

/**
 * @brief 
 * 
 * @param from 
 * @param auth 
 * @param request 
 * @return Skissm__SendGroupMsgResponse* 
 */
Skissm__SendGroupMsgResponse *mock_send_group_msg(Skissm__E2eeAddress *from, const char *auth, Skissm__SendGroupMsgRequest *request);

/**
 * @brief 
 * 
 * @param from 
 * @param auth 
 * @param request 
 * @return Skissm__ConsumeProtoMsgResponse* 
 */
Skissm__ConsumeProtoMsgResponse *mock_consume_proto_msg(Skissm__E2eeAddress *from, const char *auth, Skissm__ConsumeProtoMsgRequest *request);

#endif /* MOCK_SERVER_H_ */
