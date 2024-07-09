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
#ifndef GROUP_SESSION_MANAGER_H_
#define GROUP_SESSION_MANAGER_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "skissm/skissm.h"

/**
 * @brief Create a CreateGroupRequest message to be sent to server.
 * @param request_out
 * @param sender_address
 * @param group_name
 * @param group_members
 * @param group_members_num
 * @return 0 if success
 */
int produce_create_group_request(
    Skissm__CreateGroupRequest **request_out,
    Skissm__E2eeAddress *sender_address,
    const char *group_name,
    Skissm__GroupMember **group_member_list,
    size_t group_members_num
);

/**
 * @brief Process an incoming CreateGroupResponse message.
 * @param e2ee_pack_id
 * @param sender_address
 * @param group_name
 * @param group_members
 * @param group_members_num
 * @param response
 * @return 0 if success
 */
int consume_create_group_response(
    uint32_t e2ee_pack_id,
    Skissm__E2eeAddress *sender_address,
    const char *group_name,
    Skissm__GroupMember **group_members,
    size_t group_members_num,
    Skissm__CreateGroupResponse *response
);

/**
 * @brief Create a CreateGroupMsg message to be sent to server.
 * @param receiver_address
 * @param msg
 * @return true for success
 */
bool consume_create_group_msg(
    Skissm__E2eeAddress *receiver_address,
    Skissm__CreateGroupMsg *msg
);

/**
 * @brief Process an incoming GetGroupResponse message.
 * @param response
 *
 */
bool consume_get_group_response(Skissm__GetGroupResponse *response);

/**
 * @brief Create a AddGroupMembersRequest message to be sent to server.
 * @param request_out
 * @param outbound_group_session
 * @param adding_members
 * @param adding_members_num
 * @return 0 if success
 */
int produce_add_group_members_request(
    Skissm__AddGroupMembersRequest **request_out,
    Skissm__GroupSession *outbound_group_session,
    Skissm__GroupMember **adding_member_list,
    size_t adding_members_num
);

/**
 * @brief Process an incoming AddGroupMembersResponse message.
 * @param outbound_group_session
 * @param response
 * @param adding_members
 * @param adding_members_num
 * @return 0 if success
 */
int consume_add_group_members_response(
    Skissm__GroupSession *outbound_group_session,
    Skissm__AddGroupMembersResponse *response,
    Skissm__GroupMember **adding_members,
    size_t adding_members_num
);

/**
 * @brief Process an incoming AddGroupMembersMsg message.
 * @param receiver_address
 * @param msg
 * @return true for success
 */
bool consume_add_group_members_msg(
    Skissm__E2eeAddress *receiver_address,
    Skissm__AddGroupMembersMsg *msg
);

/**
 * @brief Create a AddGroupMemberDeviceRequest message to be sent to server.
 * @param request_out
 * @param outbound_group_session
 * @param new_device_address
 * @return 0 if success
 */
int produce_add_group_member_device_request(
    Skissm__AddGroupMemberDeviceRequest **request_out,
    Skissm__GroupSession *outbound_group_session,
    Skissm__E2eeAddress *new_device_address
);

/**
 * @brief Process an incoming AddGroupMemberDeviceResponse message.
 * @param outbound_group_session
 * @param response
 * @return 0 if success
 */
int consume_add_group_member_device_response(
    Skissm__GroupSession *outbound_group_session,
    Skissm__AddGroupMemberDeviceResponse *response
);

/**
 * @brief Process an incoming AddGroupMemberDeviceMsg message.
 * @param receiver_address
 * @param msg
 * @return true for success
 */
bool consume_add_group_member_device_msg(
    Skissm__E2eeAddress *receiver_address,
    Skissm__AddGroupMemberDeviceMsg *msg
);

/**
 * @brief Create a RemoveGroupMembersRequest message to be sent to server.
 * @param request_out
 * @param outbound_group_session
 * @param removing_group_members
 * @param removing_group_members_num
 * @return 0 if success
 */
int produce_remove_group_members_request(
    Skissm__RemoveGroupMembersRequest **request_out,
    Skissm__GroupSession *outbound_group_session,
    Skissm__GroupMember **removing_group_members,
    size_t removing_group_members_num
);

/**
 * @brief Process an incoming RemoveGroupMembersResponse message.
 * @param outbound_group_session
 * @param response
 * @param removing_members
 * @param removing_members_num
 * @return 0 if success
 */
int consume_remove_group_members_response(
    Skissm__GroupSession *outbound_group_session,
    Skissm__RemoveGroupMembersResponse *response,
    Skissm__GroupMember **removing_members,
    size_t removing_members_num
);

/**
 * @brief Process an incoming RemoveGroupMembersMsg message.
 * @param receiver_address
 * @param msg
 * @return true for success
 */
bool consume_remove_group_members_msg(
    Skissm__E2eeAddress *receiver_address,
    Skissm__RemoveGroupMembersMsg *msg
);

/**
 * @brief Create a Skissm__LeaveGroupRequest message to be sent to server.
 * @param request_out
 * @param user_address
 * @param group_address
 * @return 0 if success
 */
int produce_leave_group_request(
    Skissm__LeaveGroupRequest **request_out,
    Skissm__E2eeAddress *user_address,
    Skissm__E2eeAddress *group_address
);

/**
 * @brief Process an incoming Skissm__LeaveGroupResponse message.
 * @param user_address
 * @param response
 * @return 0 if success
 */
int consume_leave_group_response(
    Skissm__E2eeAddress *user_address,
    Skissm__LeaveGroupResponse *response
);

/**
 * @brief Process an incoming Skissm__LeaveGroupMsg message.
 * @param receiver_address
 * @param msg
 * @return true for success
 */
bool consume_leave_group_msg(
    Skissm__E2eeAddress *receiver_address,
    Skissm__LeaveGroupMsg *msg
);

/**
 * @brief Create a SendGroupMsgRequest message to be sent to server.
 * @param request_out
 * @param group_session
 * @param notif_level
 * @param plaintext_data
 * @param plaintext_data_len
 * @param allow_list
 * @param allow_list_len
 * @param denny_list
 * @param denny_list_len
 * @return 0 if success
 */
int produce_send_group_msg_request(
    Skissm__SendGroupMsgRequest **request_out,
    Skissm__GroupSession *outbound_group_session,
    uint32_t notif_level,
    const uint8_t *plaintext_data, size_t plaintext_data_len,
    Skissm__E2eeAddress **allow_list,
    size_t allow_list_len,
    Skissm__E2eeAddress **deny_list,
    size_t deny_list_len
);

/**
 * @brief Process an incoming SendGroupMsgResponse message.
 * @param outbound_group_session
 * @param response
 * @return 0 if success
 */
int consume_send_group_msg_response(
    Skissm__GroupSession *outbound_group_session,
    Skissm__SendGroupMsgResponse *response
);

/**
 * @brief Process an incoming E2eeMsg message.
 * @param receiver_address
 * @param e2ee_msg
 * @return true for success
 */
bool consume_group_msg(
    Skissm__E2eeAddress *receiver_address,
    Skissm__E2eeMsg *e2ee_msg
);

#ifdef __cplusplus
}
#endif

#endif /* GROUP_SESSION_MANAGER_H_ */
