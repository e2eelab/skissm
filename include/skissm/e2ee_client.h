#ifndef E2EE_CLIENT_H_
#define E2EE_CLIENT_H_

#include "skissm/skissm.h"


#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Register a new account.
 * @param e2ee_pack_id The e2ee package id to be used.
 * @param user_name The user name that is creating the new account.
 * @param user_id The unique user id that will be binded to the new account.
 * @param device_id The device id that will be binded to the new account.
 * @param authenticator The authenticator (email and etc.) is used to receive an register auth code.
 * @param auth_code The auth code that is received by the authenticator.
 * @return Skissm__RegisterUserResponse *
 */
Skissm__RegisterUserResponse *register_user(
    uint32_t e2ee_pack_id,
    const char *user_name,
    const char *user_id,
    const char *device_id,
    const char *authenticator,
    const char *auth_code
);

/**
 * @brief Send invite request again if the outbound session has not been responded.
 * @param outbound_session The outbound session
 * @return  Skissm__InviteResponse *
 */
Skissm__InviteResponse *reinvite(Skissm__Session *outbound_session);

/**
 * @brief Send invite request and create a new outbound session
 * that needs to be responded before it can be used
 * to send encryption message.
 * @param from From address
 * @param to_user_id The receiver's user_id
 * @param to_domain The receiver's domain
 * @return  Skissm__InviteResponse *
 */
Skissm__InviteResponse *invite(
    Skissm__E2eeAddress *from,
    const char *to_user_id,
    const char *to_domain
);

/**
 * @brief Send invite request to create a new outbound session
 * and delete the old outbound session.
 * @param from From address
 * @param to_user_id The receiver's user_id
 * @param to_domain The receiver's domain
 * @return  Skissm__InviteResponse *
 */
Skissm__InviteResponse *new_invite(
    Skissm__E2eeAddress *from,
    const char *to_user_id,
    const char *to_domain
);

/**
 * @brief Send one2one msg.
 * @param from
 * @param to_user_id
 * @param to_domain
 * @param notif_level
 * @param plaintext_data
 * @param plaintext_data_len
 * @return Skissm__SendOne2oneMsgResponse *
 */
Skissm__SendOne2oneMsgResponse *send_one2one_msg(
    Skissm__E2eeAddress *from, const char *to_user_id, const char *to_domain,
    uint32_t notif_level,
    const uint8_t *plaintext_data, size_t plaintext_data_len
);

/**
 * @brief Send sync msg to other devices.
 * @param from
 * @param plaintext_data 
 * @param plaintext_data_len 
 */
void send_sync_msg(Skissm__E2eeAddress *from, const uint8_t *plaintext_data, size_t plaintext_data_len);

/**
 * @brief Send sync invite msg to other devices.
 * @param from
 * @param to_user_id 
 * @param to_domain
 * @param to_device_id_list
 * @param to_device_num
 */
void send_sync_invite_msg(
    Skissm__E2eeAddress *from, const char *to_user_id, const char *to_domain,
    char **to_device_id_list, size_t to_device_num
);

/**
 * @brief Create a group.
 * @param sender_address
 * @param group_name
 * @param group_members
 * @param group_members_num
 * @return Skissm__CreateGroupResponse *
 */
Skissm__CreateGroupResponse *create_group(
    Skissm__E2eeAddress *sender_address, const char *group_name,
    Skissm__GroupMember **group_members, size_t group_members_num
);

/**
 * @brief Add group members.
 * @param sender_address
 * @param group_address
 * @param adding_members
 * @param adding_members_num
 * @return Skissm__AddGroupMembersResponse *
 */
Skissm__AddGroupMembersResponse *add_group_members(
    Skissm__E2eeAddress *sender_address,
    Skissm__E2eeAddress *group_address,
    Skissm__GroupMember **adding_members,
    size_t adding_members_num
);

/**
 * @brief Remove group members.
 * @param sender_address
 * @param group_address
 * @param removing_members
 * @param removing_members_num
 * @return Skissm__RemoveGroupMembersResponse *
 */
Skissm__RemoveGroupMembersResponse *remove_group_members(
    Skissm__E2eeAddress *sender_address,
    Skissm__E2eeAddress *group_address,
    Skissm__GroupMember **removing_members,
    size_t removing_members_num
);

/**
 * @brief Leave group.
 * @param sender_address
 * @param group_address
 * @return Skissm__LeaveGroupResponse *
 */
Skissm__LeaveGroupResponse *leave_group(
    Skissm__E2eeAddress *sender_address,
    Skissm__E2eeAddress *group_address
);

/**
 * @brief Send group msg.
 * @param sender_address
 * @param group_address
 * @param notif_level,
 * @param plaintext_data
 * @param plaintext_data_len
 * @return Skissm__SendGroupMsgResponse *
 */
Skissm__SendGroupMsgResponse *send_group_msg(
    Skissm__E2eeAddress *sender_address, Skissm__E2eeAddress *group_address,
    uint32_t notif_level,
    const uint8_t *plaintext_data, size_t plaintext_data_len
);

/**
 * @brief Send group msg with filter.
 * @param sender_address
 * @param group_address
 * @param notif_level,
 * @param plaintext_data
 * @param plaintext_data_len
 * @param allow_list optional allow list with type Skissm__E2eeAddress **.
 * @param allow_list_len optional allow list len with type size_t.
 * @param deny_list optional deny list with type Skissm__E2eeAddress **.
 * @param deny_list_len optional deny list len with type size_t.
 * @return Skissm__SendGroupMsgResponse *
 */
Skissm__SendGroupMsgResponse *send_group_msg_with_filter(
    Skissm__E2eeAddress *sender_address, Skissm__E2eeAddress *group_address,
    uint32_t notif_level,
    const uint8_t *plaintext_data, size_t plaintext_data_len,
    Skissm__E2eeAddress **allow_list,
    size_t allow_list_len,
    Skissm__E2eeAddress **deny_list,
    size_t deny_list_len
);

/**
 * @brief Send consume_proto_msg request to server.
 * @param sender_address
 * @param proto_msg_id
 * @return Skissm__ConsumeProtoMsgResponse *
 */
Skissm__ConsumeProtoMsgResponse *consume_proto_msg(Skissm__E2eeAddress *sender_address, const char *proto_msg_id);

/**
 * @brief Process incoming protocol messages.
 * @param proto_msg_data
 * @param proto_msg_data_len
 * @return Skissm__ConsumeProtoMsgResponse *
 */
Skissm__ConsumeProtoMsgResponse *process_proto_msg(uint8_t *proto_msg_data, size_t proto_msg_data_len);

void resume_connection();

#ifdef __cplusplus
}
#endif

#endif // E2EE_CLIENT_H_
