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
#include "skissm/group_session_manager.h"

#include <string.h>

#include "skissm/cipher.h"
#include "skissm/e2ee_client.h"
#include "skissm/group_session.h"
#include "skissm/mem_util.h"
#include "skissm/session.h"

Skissm__CreateGroupRequest *produce_create_group_request(
    Skissm__E2eeAddress *sender_address,
    const char *group_name,
    Skissm__GroupMember **group_member_list,
    size_t group_members_num
) {
    Skissm__Account *account = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(sender_address, &account);
    if (account == NULL) {
        ssm_notify_log(sender_address, BAD_ACCOUNT, "produce_create_group_request()");
        return NULL;
    }

    Skissm__CreateGroupRequest *request =
        (Skissm__CreateGroupRequest *)malloc(sizeof(Skissm__CreateGroupRequest));
    skissm__create_group_request__init(request);

    Skissm__CreateGroupMsg *msg =
        (Skissm__CreateGroupMsg *)malloc(sizeof(Skissm__CreateGroupMsg));
    skissm__create_group_msg__init(msg);

    copy_address_from_address(&(msg->sender_address), sender_address);

    msg->e2ee_pack_id = account->e2ee_pack_id;

    msg->group_info = (Skissm__GroupInfo *)malloc(sizeof(Skissm__GroupInfo));
    Skissm__GroupInfo *group_info = msg->group_info;
    skissm__group_info__init(group_info);
    group_info->group_name = strdup(group_name);
    group_info->n_group_member_list = group_members_num;
    copy_group_members(&(group_info->group_member_list), group_member_list, group_members_num);

    // done
    skissm__account__free_unpacked(account, NULL);
    request->msg = msg;
    return request;
}

bool consume_create_group_response(
    uint32_t e2ee_pack_id,
    Skissm__E2eeAddress *sender_address,
    const char *group_name,
    Skissm__GroupMember **group_member_list,
    size_t group_members_num,
    Skissm__CreateGroupResponse *response
) {
    if (response != NULL && response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
        Skissm__E2eeAddress *group_address = response->group_address;
        new_outbound_group_session_by_sender(
            response->n_member_info_list, response->member_info_list,
            e2ee_pack_id, sender_address, group_name, group_address, group_member_list, group_members_num, NULL
        );
        // notify
        ssm_notify_group_created(sender_address, group_address, group_name, group_member_list, group_members_num);

        // done
        return true;
    } else {
        return false;
    }
}

bool consume_create_group_msg(Skissm__E2eeAddress *receiver_address, Skissm__CreateGroupMsg *msg) {
    uint32_t e2ee_pack_id = msg->e2ee_pack_id;
    Skissm__GroupInfo *group_info = msg->group_info;
    const char *group_name = group_info->group_name;
    Skissm__E2eeAddress *sender_address = msg->sender_address;
    Skissm__E2eeAddress *group_address = group_info->group_address;
    size_t group_members_num = group_info->n_group_member_list;
    Skissm__GroupMember **group_member_list = group_info->group_member_list;

    // try to load inbound group session
    size_t i;
    Skissm__GroupSession *inbound_group_session = NULL;
    get_skissm_plugin()->db_handler.load_group_session_by_address(sender_address, receiver_address, group_address, &inbound_group_session);
    if (inbound_group_session == NULL) {
        for (i = 0; i < msg->n_member_info_list; i++) {
            Skissm__GroupMemberInfo *cur_group_member_info = (msg->member_info_list)[i];
            if (!compare_address(cur_group_member_info->member_address, receiver_address)) {
                new_inbound_group_session_by_member_id(e2ee_pack_id, receiver_address, cur_group_member_info, group_info);
                ssm_notify_log(
                    receiver_address,
                    DEBUG_LOG,
                    "consume_create_group_msg() new_inbound_group_session_by_member_id: member_address: [%s:%s]",
                    cur_group_member_info->member_address->user->user_id,
                    cur_group_member_info->member_address->user->device_id
                );
            } else {
                ssm_notify_log(
                    receiver_address,
                    DEBUG_LOG,
                    "consume_create_group_msg() new_inbound_group_session_by_member_id: skip member_address: [%s:%s]",
                    cur_group_member_info->member_address->user->user_id,
                    cur_group_member_info->member_address->user->device_id
                );
            }
        }
    } else {
        for (i = 0; i < msg->n_member_info_list; i++) {
            Skissm__GroupMemberInfo *cur_group_member_info = (msg->member_info_list)[i];
            if (!compare_address(cur_group_member_info->member_address, sender_address)) {
                if (!compare_address(cur_group_member_info->member_address, receiver_address)) {
                    new_and_complete_inbound_group_session(cur_group_member_info, inbound_group_session);
                    ssm_notify_log(
                        receiver_address,
                        DEBUG_LOG,
                        "consume_create_group_msg() new_and_complete_inbound_group_session: member_address: [%s:%s]",
                        cur_group_member_info->member_address->user->user_id,
                        cur_group_member_info->member_address->user->device_id
                    );
                } else {
                    ssm_notify_log(
                        receiver_address,
                        DEBUG_LOG,
                        "consume_create_group_msg() new_and_complete_inbound_group_session: skip member_address: [%s:%s]",
                        cur_group_member_info->member_address->user->user_id,
                        cur_group_member_info->member_address->user->device_id
                    );
                }
            } else {
                complete_inbound_group_session_by_member_id(inbound_group_session, cur_group_member_info);
                ssm_notify_log(
                    receiver_address,
                    DEBUG_LOG,
                    "consume_create_group_msg() complete_inbound_group_session_by_member_id: member_address: [%s:%s]",
                    cur_group_member_info->member_address->user->user_id,
                    cur_group_member_info->member_address->user->device_id
                );
            }
        }

        // create a new outbound group session
        new_outbound_group_session_by_receiver(
            &(inbound_group_session->group_seed),
            e2ee_pack_id,
            receiver_address,
            group_name,
            group_address,
            inbound_group_session->session_id,
            group_member_list,
            group_members_num
        );
        ssm_notify_log(
            receiver_address,
            DEBUG_LOG,
            "consume_create_group_msg() new_outbound_group_session_by_receiver: session_owner and sender_address: [%s:%s]",
            receiver_address->user->user_id,
            receiver_address->user->device_id
        );

        // release
        skissm__group_session__free_unpacked(inbound_group_session, NULL);
    }

    // notify
    ssm_notify_group_created(receiver_address, group_address, group_name, group_member_list, group_members_num);

    // done
    return true;
}

bool consume_get_group_response(Skissm__GetGroupResponse *response) {
    if (response != NULL && response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
        char *group_name = response->group_name;
        size_t n_group_member_list = response->n_group_member_list;
        Skissm__GroupMember **group_member_list = response->group_member_list;

        // @TODO update group info, and notify
        return true;
    } else {
        return false;
    }
}

Skissm__AddGroupMembersRequest *produce_add_group_members_request(
    Skissm__GroupSession *outbound_group_session,
    Skissm__GroupMember **adding_member_list,
    size_t adding_members_num
) {
    Skissm__Account *account = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(outbound_group_session->session_owner, &account);
    if (account == NULL) {
        ssm_notify_log(outbound_group_session->session_owner, BAD_ACCOUNT, "produce_add_group_members_request()");
        return NULL;
    }

    Skissm__AddGroupMembersRequest *request =
        (Skissm__AddGroupMembersRequest *)malloc(sizeof(Skissm__AddGroupMembersRequest));
    skissm__add_group_members_request__init(request);

    Skissm__AddGroupMembersMsg *msg =
        (Skissm__AddGroupMembersMsg *)malloc(sizeof(Skissm__AddGroupMembersMsg));
    skissm__add_group_members_msg__init(msg);

    msg->e2ee_pack_id = account->e2ee_pack_id;

    copy_address_from_address(&(msg->sender_address), outbound_group_session->session_owner);

    msg->sequence = outbound_group_session->sequence;

    msg->n_adding_member_list = adding_members_num;
    copy_group_members(&(msg->adding_member_list), adding_member_list, adding_members_num);
    add_group_members_to_group_info(&(msg->group_info), outbound_group_session->group_info, adding_member_list, adding_members_num);

    // done
    skissm__account__free_unpacked(account, NULL);
    request->msg = msg;
    return request;
}

bool consume_add_group_members_response(
    Skissm__GroupSession *outbound_group_session,
    Skissm__AddGroupMembersResponse *response,
    Skissm__GroupMember **added_members,
    size_t added_members_num
) {
    if (response != NULL && response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
        Skissm__GroupMember **new_group_members = response->group_member_list;
        size_t new_group_members_num = response->n_group_member_list;

        // renew the outbound group session
        Skissm__E2eeAddress *session_owner = outbound_group_session->session_owner;

        renew_outbound_group_session_by_welcome_and_add(
            outbound_group_session, NULL, session_owner,
            response->n_adding_member_info_list, response->adding_member_info_list,
            added_members_num, added_members
        );
        // use renewed group_info
        const char *group_name = outbound_group_session->group_info->group_name;
        Skissm__E2eeAddress *group_address = outbound_group_session->group_info->group_address;

        // notify
        ssm_notify_group_members_added(
            session_owner,
            group_address,
            group_name,
            new_group_members,
            new_group_members_num,
            added_members,
            added_members_num
        );

        // done
        return true;
    } else {
        return false;
    }
}

bool consume_add_group_members_msg(Skissm__E2eeAddress *receiver_address, Skissm__AddGroupMembersMsg *msg) {
    Skissm__E2eeAddress *group_address = msg->group_info->group_address;
    const char *group_name = msg->group_info->group_name;
    Skissm__GroupMember **new_group_members = msg->group_info->group_member_list;
    size_t new_group_members_num = msg->group_info->n_group_member_list;
    uint32_t e2ee_pack_id = msg->e2ee_pack_id;

    /** The old group members have their own outbound group sessions, so they need to renew them.
     *  On the other hand, the new group members need to create the outbound group session.
     */
    Skissm__GroupSession *outbound_group_session = NULL;
    get_skissm_plugin()->db_handler.load_group_session_by_address(
        receiver_address, receiver_address, group_address, &outbound_group_session
    );
    // renew the outbound group session if it exists
    if (outbound_group_session != NULL) {
        // load the inbound group session to get the chain key
        Skissm__GroupSession *inbound_group_session = NULL;
        get_skissm_plugin()->db_handler.load_group_session_by_id(
            msg->sender_address, receiver_address, outbound_group_session->session_id, &inbound_group_session
        );
        if (inbound_group_session == NULL) {
            ssm_notify_log(receiver_address, BAD_MESSAGE_FORMAT, "consume_add_group_members_msg()");
            skissm__group_session__free_unpacked(outbound_group_session, NULL);
            return false;
        }
        const cipher_suite_t *cipher_suite = get_e2ee_pack(inbound_group_session->e2ee_pack_id)->cipher_suite;
        uint32_t their_sequence = msg->sequence;
        while (inbound_group_session->sequence < their_sequence) {
            advance_group_chain_key(cipher_suite, &(inbound_group_session->chain_key));
            inbound_group_session->sequence += 1;
        }

        // renew the outbound group session
        renew_outbound_group_session_by_welcome_and_add(
            outbound_group_session, &(inbound_group_session->chain_key), msg->sender_address,
            msg->n_adding_member_info_list, msg->adding_member_info_list,
            msg->n_adding_member_list, msg->adding_member_list
        );
        // release
        skissm__group_session__free_unpacked(outbound_group_session, NULL);
        skissm__group_session__free_unpacked(inbound_group_session, NULL);
    } else {
        // check
    }

    // notify
    ssm_notify_group_members_added(
        receiver_address,
        group_address,
        group_name,
        new_group_members,
        new_group_members_num,
        msg->adding_member_list,
        msg->n_adding_member_list
    );

    // done
    return true;
}

Skissm__AddGroupMemberDeviceRequest *produce_add_group_member_device_request(
    Skissm__GroupSession *outbound_group_session,
    Skissm__E2eeAddress *new_device_address
) {
    Skissm__Account *account = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(outbound_group_session->session_owner, &account);
    if (account == NULL) {
        ssm_notify_log(outbound_group_session->session_owner, BAD_ACCOUNT, "produce_add_group_member_device_request()");
        return NULL;
    }

    Skissm__AddGroupMemberDeviceRequest *request =
        (Skissm__AddGroupMemberDeviceRequest *)malloc(sizeof(Skissm__AddGroupMemberDeviceRequest));
    skissm__add_group_member_device_request__init(request);

    Skissm__AddGroupMemberDeviceMsg *msg =
        (Skissm__AddGroupMemberDeviceMsg *)malloc(sizeof(Skissm__AddGroupMemberDeviceMsg));
    skissm__add_group_member_device_msg__init(msg);

    msg->e2ee_pack_id = account->e2ee_pack_id;

    copy_address_from_address(&(msg->sender_address), outbound_group_session->session_owner);

    msg->sequence = outbound_group_session->sequence;

    copy_group_info(&(msg->group_info), outbound_group_session->group_info);

    msg->adding_member_device = (Skissm__GroupMemberInfo *)malloc(sizeof(Skissm__GroupMemberInfo));
    skissm__group_member_info__init(msg->adding_member_device);
    copy_address_from_address(&(msg->adding_member_device->member_address), new_device_address);

    // done
    skissm__account__free_unpacked(account, NULL);
    request->msg = msg;
    return request;
}

bool consume_add_group_member_device_response(
    Skissm__GroupSession *outbound_group_session,
    Skissm__AddGroupMemberDeviceResponse *response,
    Skissm__E2eeAddress *new_device_address
) {
    const char *group_name = outbound_group_session->group_info->group_name;
    Skissm__E2eeAddress *session_owner = outbound_group_session->session_owner;
    Skissm__E2eeAddress *group_address = outbound_group_session->group_info->group_address;

    if (response != NULL) {
        if (response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
            Skissm__GroupMemberInfo *adding_member_device_info = response->adding_member_device_info;
            // renew the outbound group session
            renew_group_sessions_with_new_device(
                outbound_group_session, NULL, session_owner, new_device_address, adding_member_device_info
            );
            ssm_notify_log(
                outbound_group_session->session_owner,
                DEBUG_LOG,
                "consume_add_group_member_device_response() success, new_device_address: [%s:%s], group_address:[%s@%s]",
                new_device_address->user->user_id,
                new_device_address->user->device_id,
                group_address->group->group_id,
                group_address->domain
            );
            // done
            return true;
        } else if (response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_NO_CONTENT) {
            ssm_notify_log(
                outbound_group_session->session_owner,
                DEBUG_LOG,
                "consume_add_group_member_device_response() no content, give up: [%s:%s], group_address:[%s@%s]",
                new_device_address->user->user_id,
                new_device_address->user->device_id,
                group_address->group->group_id,
                group_address->domain
            );
            // give up
            return true;
        } else {
            ssm_notify_log(
                outbound_group_session->session_owner,
                DEBUG_LOG,
                "consume_add_group_member_device_response() response error, new_device_address: [%s:%s], group_address:[%s@%s]",
                new_device_address->user->user_id,
                new_device_address->user->device_id,
                group_address->group->group_id,
                group_address->domain
            );
            // for retry
            return false;
        }
    } else {
        ssm_notify_log(
            outbound_group_session->session_owner,
            DEBUG_LOG,
            "consume_add_group_member_device_response() no response error, new_device_address: [%s:%s], group_address:[%s@%s]",
            new_device_address->user->user_id,
            new_device_address->user->device_id,
            group_address->group->group_id,
            group_address->domain
        );
        // for retry
        return false;
    }
}

bool consume_add_group_member_device_msg(
    Skissm__E2eeAddress *receiver_address,
    Skissm__AddGroupMemberDeviceMsg *msg
) {
    Skissm__E2eeAddress *group_address = msg->group_info->group_address;
    const char *group_name = msg->group_info->group_name;
    Skissm__GroupMember **group_member_list = msg->group_info->group_member_list;
    size_t group_members_num = msg->group_info->n_group_member_list;
    uint32_t e2ee_pack_id = msg->e2ee_pack_id;

    /** The old group members have their own outbound group sessions, so they need to renew them.
     *  On the other hand, the new group members need to create the outbound group session.
     */
    Skissm__GroupSession *outbound_group_session = NULL;
    get_skissm_plugin()->db_handler.load_group_session_by_address(
        receiver_address, receiver_address, group_address, &outbound_group_session
    );
    // renew the outbound group session if it exists
    if (outbound_group_session != NULL) {
        // load the inbound group session to get the chain key
        Skissm__GroupSession *inbound_group_session = NULL;
        get_skissm_plugin()->db_handler.load_group_session_by_id(
            msg->sender_address, receiver_address, outbound_group_session->session_id, &inbound_group_session
        );
        if (inbound_group_session == NULL) {
            ssm_notify_log(receiver_address, BAD_MESSAGE_FORMAT, "consume_add_group_member_device_msg()");
            // release
            skissm__group_session__free_unpacked(outbound_group_session, NULL);
            return false;
        }
        const cipher_suite_t *cipher_suite = get_e2ee_pack(inbound_group_session->e2ee_pack_id)->cipher_suite;
        uint32_t their_sequence = msg->sequence;
        while (inbound_group_session->sequence < their_sequence) {
            advance_group_chain_key(cipher_suite, &(inbound_group_session->chain_key));
            inbound_group_session->sequence += 1;
        }

        // renew the outbound group session
        renew_group_sessions_with_new_device(
            outbound_group_session, &(inbound_group_session->chain_key),
            msg->sender_address, msg->adding_member_device->member_address, msg->adding_member_device
        );

        // release
        skissm__group_session__free_unpacked(outbound_group_session, NULL);
        skissm__group_session__free_unpacked(inbound_group_session, NULL);
    } else {
        // check
    }

    // done
    return true;
}

Skissm__RemoveGroupMembersRequest *produce_remove_group_members_request(
    Skissm__GroupSession *outbound_group_session,
    Skissm__GroupMember **removing_group_members,
    size_t removing_group_members_num
) {
    ssm_notify_log(
        outbound_group_session->session_owner,
        DEBUG_LOG,
        "produce_remove_group_members_request() session_owner address: [%s:%s]",
        outbound_group_session->session_owner->user->user_id,
        outbound_group_session->session_owner->user->device_id
    );

    Skissm__Account *account = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(outbound_group_session->session_owner, &account);
    if (account == NULL) {
        ssm_notify_log(outbound_group_session->session_owner, BAD_ACCOUNT, "produce_remove_group_members_request()");
        return NULL;
    }

    Skissm__RemoveGroupMembersRequest *request =
        (Skissm__RemoveGroupMembersRequest *)malloc(sizeof(Skissm__RemoveGroupMembersRequest));
    skissm__remove_group_members_request__init(request);

    Skissm__RemoveGroupMembersMsg *msg =
        (Skissm__RemoveGroupMembersMsg *)malloc(sizeof(Skissm__RemoveGroupMembersMsg));
    skissm__remove_group_members_msg__init(msg);

    msg->e2ee_pack_id = account->e2ee_pack_id;

    copy_address_from_address(&(msg->sender_address), outbound_group_session->session_owner);

    remove_group_members_from_group_info(
        &(msg->group_info), outbound_group_session->group_info, removing_group_members, removing_group_members_num
    );

    msg->n_removing_member_list = removing_group_members_num;
    copy_group_members(&(msg->removing_member_list), removing_group_members, removing_group_members_num);

    // done
    skissm__account__free_unpacked(account, NULL);
    request->msg = msg;
    return request;
}

static bool user_in_group(Skissm__E2eeAddress *user_address, Skissm__GroupMember **group_member_list, size_t group_members_num) {
    size_t i;
    for (i = 0; i < group_members_num; i++) {
        if (safe_strcmp(group_member_list[i]->user_id, user_address->user->user_id)
            && safe_strcmp(group_member_list[i]->domain, user_address->domain)
        ) {
            return true;
        }
    }
    return false;
}

bool consume_remove_group_members_response(
    Skissm__GroupSession *outbound_group_session,
    Skissm__RemoveGroupMembersResponse *response,
    Skissm__GroupMember **removed_members,
    size_t removed_members_num
) {
    if (response != NULL) {
        if (response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
            uint32_t e2ee_pack_id = outbound_group_session->e2ee_pack_id;
            Skissm__E2eeAddress *sender_address = outbound_group_session->session_owner;
            Skissm__E2eeAddress *group_address = outbound_group_session->group_info->group_address;
            Skissm__GroupMember **group_member_list = response->group_member_list;
            size_t group_members_num = response->n_group_member_list;

            // delete the old outbound group session
            char *old_session_id = outbound_group_session->session_id;
            get_skissm_plugin()->db_handler.unload_group_session_by_id(sender_address, old_session_id);
            const char *group_name = outbound_group_session->group_info->group_name;

            if (group_members_num > 0 && user_in_group(sender_address, group_member_list, group_members_num)) {
                // generate a new outbound group session
                new_outbound_group_session_by_sender(
                    response->n_member_info_list, response->member_info_list,
                    e2ee_pack_id, sender_address, group_name, group_address, group_member_list, group_members_num, old_session_id
                );
            } else {
                // user is removed from group
                get_skissm_plugin()->event_handler.on_log(sender_address, DEBUG_LOG, "consume_remove_group_members_response() skip renew outbound group session since user is not in group");
            }

            // notify
            ssm_notify_group_members_removed(
                sender_address,
                group_address,
                group_name,
                group_member_list,
                group_members_num,
                removed_members,
                removed_members_num
            );
            // done
            return true;
        } else if (response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_NO_CONTENT) {
            // member is not existed, just skip it
            // should we remove the group member device ?
            return true;
        }
    }
    // done
    return false;
}

bool consume_remove_group_members_msg(Skissm__E2eeAddress *receiver_address, Skissm__RemoveGroupMembersMsg *msg) {
    uint32_t e2ee_pack_id = msg->e2ee_pack_id;
    Skissm__GroupInfo *group_info = msg->group_info;
    const char *group_name = group_info->group_name;
    Skissm__E2eeAddress *sender_address = msg->sender_address;
    Skissm__E2eeAddress *group_address = group_info->group_address;
    size_t new_group_members_num = group_info->n_group_member_list;
    Skissm__GroupMember **new_group_members = group_info->group_member_list;

    // if the receiver is the one who is going to be removed, the receiver should unload his or her own group session
    size_t i;
    for (i = 0; i < msg->n_removing_member_list; i++) {
        if (safe_strcmp(receiver_address->user->user_id, msg->removing_member_list[i]->user_id) && safe_strcmp(receiver_address->domain, msg->removing_member_list[i]->domain)) {
            // unload all outbound and inbound group sessions
            get_skissm_plugin()->db_handler.unload_group_session_by_address(receiver_address, group_address);

            // notify
            ssm_notify_group_members_removed(
                receiver_address,
                group_address,
                group_name,
                new_group_members,
                new_group_members_num,
                msg->removing_member_list,
                msg->n_removing_member_list
            );

            // done
            // no need to renew outbound group session
            get_skissm_plugin()->event_handler.on_log(receiver_address, DEBUG_LOG, "consume_remove_group_members_msg() skip renew outbound group session because local user is removed");
            return true;
        }
    }

    // unload the old group sessions if necessary
    bool new_group_session = true;
    Skissm__GroupSession *inbound_group_session = NULL;
    get_skissm_plugin()->db_handler.load_group_session_by_address(sender_address, receiver_address, group_address, &inbound_group_session);

    if (inbound_group_session != NULL) {
        if (!compare_group_member(
            inbound_group_session->group_info->group_member_list, inbound_group_session->group_info->n_group_member_list,
            new_group_members, new_group_members_num)
        ) {
            new_group_session = false;
            // unload the old group sessions
            get_skissm_plugin()->db_handler.unload_group_session_by_id(receiver_address, inbound_group_session->session_id);
        }
    } else {
        // there is no inbound group session
        new_group_session = false;
    }

    if (new_group_session == false) {
        for (i = 0; i < msg->n_member_info_list; i++) {
            Skissm__GroupMemberInfo *cur_group_member_id = (msg->member_info_list)[i];
            if (!compare_address(cur_group_member_id->member_address, receiver_address))
                new_inbound_group_session_by_member_id(e2ee_pack_id, receiver_address, cur_group_member_id, group_info);
        }
    } else {
        for (i = 0; i < msg->n_member_info_list; i++) {
            Skissm__GroupMemberInfo *cur_group_member_id = (msg->member_info_list)[i];
            if (!compare_address(cur_group_member_id->member_address, sender_address)) {
                if (!compare_address(cur_group_member_id->member_address, receiver_address))
                    new_and_complete_inbound_group_session(cur_group_member_id, inbound_group_session);
            } else {
                complete_inbound_group_session_by_member_id(inbound_group_session, cur_group_member_id);
            }
        }

        // create a new outbound group session
        new_outbound_group_session_by_receiver(
            &(inbound_group_session->group_seed),
            e2ee_pack_id,
            receiver_address,
            group_name,
            group_address,
            inbound_group_session->session_id,
            new_group_members,
            new_group_members_num
        );
    }

    // notify
    ssm_notify_group_members_removed(
        receiver_address,
        group_address,
        group_name,
        new_group_members,
        new_group_members_num,
        msg->removing_member_list,
        msg->n_removing_member_list
    );

    // release
    if (inbound_group_session != NULL) {
        skissm__group_session__free_unpacked(inbound_group_session, NULL);
    }

    return true;
}

Skissm__LeaveGroupRequest *produce_leave_group_request(
    Skissm__E2eeAddress *user_address,
    Skissm__E2eeAddress *group_address
) {
    Skissm__LeaveGroupRequest *request =
        (Skissm__LeaveGroupRequest *)malloc(sizeof(Skissm__LeaveGroupRequest));
    skissm__leave_group_request__init(request);

    Skissm__LeaveGroupMsg *msg =
        (Skissm__LeaveGroupMsg *)malloc(sizeof(Skissm__LeaveGroupMsg));
    skissm__leave_group_msg__init(msg);

    copy_address_from_address(&(msg->user_address), user_address);
    copy_address_from_address(&(msg->group_address), group_address);

    request->msg = msg;

    // done
    return request;
}

bool consume_leave_group_response(
    Skissm__E2eeAddress *user_address,
    Skissm__LeaveGroupResponse *response
) {
    if (response != NULL) {
        if (response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
            ssm_notify_log(user_address, DEBUG_LOG, "consume_leave_group_response() success, unload group session");
            // unload
            get_skissm_plugin()->db_handler.unload_group_session_by_address(user_address,response->group_address);
            return true;
        }  if (response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_NO_CONTENT) {
            ssm_notify_log(user_address, DEBUG_LOG, "consume_leave_group_response() no content, skipped");
            return true;
        }
    }
    ssm_notify_log(user_address, DEBUG_LOG, "consume_leave_group_response() failed, redo later");
    // done
    return false;
}

bool consume_leave_group_msg(Skissm__E2eeAddress *receiver_address, Skissm__LeaveGroupMsg *msg) {
    // prepare the removing group member
    Skissm__GroupMember **removing_group_members = (Skissm__GroupMember **)malloc(sizeof(Skissm__GroupMember *));
    removing_group_members[0] = (Skissm__GroupMember *)malloc(sizeof(Skissm__GroupMember));
    skissm__group_member__init(removing_group_members[0]);
    removing_group_members[0]->user_id = strdup(msg->user_address->user->user_id);
    removing_group_members[0]->domain = strdup(msg->user_address->domain);
    removing_group_members[0]->role = SKISSM__GROUP_ROLE__GROUP_ROLE_MEMBER;
    size_t removing_group_member_num = 1;

    Skissm__RemoveGroupMembersResponse *remove_group_members_response = remove_group_members(
        receiver_address, msg->group_address, removing_group_members, removing_group_member_num
    );

    bool succ = false;
    if (remove_group_members_response != NULL) {
        if (remove_group_members_response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
            ssm_notify_log(receiver_address, DEBUG_LOG, "consume_leave_group_msg() succes");
            succ = true;
        } else if(remove_group_members_response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_NO_CONTENT) {
            // member already removed, just consume it
            ssm_notify_log(receiver_address, DEBUG_LOG, "consume_leave_group_msg(), no such member");
            succ = true;
        }
        // release
        skissm__remove_group_members_response__free_unpacked(remove_group_members_response, NULL);
    }
    // release
    skissm__group_member__free_unpacked(removing_group_members[0], NULL);
    free_mem((void **)&removing_group_members, sizeof(Skissm__GroupMember *));

    // done
    return succ;
}

Skissm__SendGroupMsgRequest *produce_send_group_msg_request(
    Skissm__GroupSession *outbound_group_session,
    uint32_t notif_level,
    const uint8_t *plaintext_data, size_t plaintext_data_len,
    Skissm__E2eeAddress **allow_list,
    size_t allow_list_len,
    Skissm__E2eeAddress **deny_list,
    size_t deny_list_len
) {
    Skissm__Account *account = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(outbound_group_session->sender, &account);
    if (account == NULL) {
        ssm_notify_log(outbound_group_session->sender, BAD_ACCOUNT, "produce_send_group_msg_request()");
        return NULL;
    }

    const cipher_suite_t *cipher_suite = get_e2ee_pack(outbound_group_session->e2ee_pack_id)->cipher_suite;

    Skissm__SendGroupMsgRequest *request = (Skissm__SendGroupMsgRequest *)malloc(sizeof(Skissm__SendGroupMsgRequest));
    skissm__send_group_msg_request__init(request);

    // create the message key
    Skissm__MsgKey *msg_key = (Skissm__MsgKey *) malloc(sizeof(Skissm__MsgKey));
    skissm__msg_key__init(msg_key);
    create_group_message_key(cipher_suite, &(outbound_group_session->chain_key), msg_key);

    // prepare an e2ee message
    Skissm__E2eeMsg *e2ee_msg = (Skissm__E2eeMsg *) malloc(sizeof(Skissm__E2eeMsg));
    skissm__e2ee_msg__init(e2ee_msg);
    e2ee_msg->version = strdup(outbound_group_session->version);
    e2ee_msg->session_id = strdup(outbound_group_session->session_id);
    e2ee_msg->msg_id = generate_uuid_str();
    e2ee_msg->notif_level = notif_level;
    copy_address_from_address(&(e2ee_msg->from), outbound_group_session->session_owner);
    copy_address_from_address(&(e2ee_msg->to), outbound_group_session->group_info->group_address);
    e2ee_msg->payload_case = SKISSM__E2EE_MSG__PAYLOAD_GROUP_MSG;

    // prepare a group_msg_payload
    Skissm__GroupMsgPayload *group_msg_payload = (Skissm__GroupMsgPayload *) malloc(sizeof(Skissm__GroupMsgPayload));
    skissm__group_msg_payload__init(group_msg_payload);
    group_msg_payload->sequence = outbound_group_session->sequence;

    // encryption
    group_msg_payload->ciphertext.len = cipher_suite->symmetric_encryption_suite->encrypt(
        &(outbound_group_session->associated_data),
        msg_key->derived_key.data,
        plaintext_data,
        plaintext_data_len,
        &(group_msg_payload->ciphertext.data)
    );

    // signature
    uint32_t sig_len = cipher_suite->digital_signature_suite->get_crypto_param().sig_len;
    group_msg_payload->signature.len = sig_len;
    group_msg_payload->signature.data = (uint8_t *) malloc(sizeof(uint8_t) * sig_len);
    size_t signature_out_len;
    cipher_suite->digital_signature_suite->sign(
        group_msg_payload->signature.data, &signature_out_len,
        group_msg_payload->ciphertext.data,
        group_msg_payload->ciphertext.len,
        account->identity_key->sign_key_pair->private_key.data
    );

    // optional allow_list and denny_list
    size_t i;
    if (allow_list_len > 0 && allow_list) {
        ssm_notify_log(outbound_group_session->sender, DEBUG_LOG, "produce_send_group_msg_request() with allow_list_len: %d", allow_list_len);
        request->n_allow_list = allow_list_len;
        request->allow_list = (Skissm__E2eeAddress **)malloc(sizeof(Skissm__E2eeAddress *) * allow_list_len);
        for(i = 0; i <allow_list_len; i++) {
            copy_address_from_address(&((request->allow_list)[i]), allow_list[i]);
        }
    }
    if (deny_list_len > 0 && deny_list) {
        ssm_notify_log(outbound_group_session->sender, DEBUG_LOG, "produce_send_group_msg_request() with deny_list_len: %d", deny_list_len);
        request->n_deny_list = deny_list_len;
        request->deny_list = (Skissm__E2eeAddress **)malloc(sizeof(Skissm__E2eeAddress *) * deny_list_len);
        for(i = 0; i <deny_list_len; i++) {
            copy_address_from_address(&((request->deny_list)[i]), deny_list[i]);
        }
    }
    
    // release
    skissm__account__free_unpacked(account, NULL);
    skissm__msg_key__free_unpacked(msg_key, NULL);

    // done
    e2ee_msg->group_msg = group_msg_payload;
    request->msg = e2ee_msg;
    return request;
}

bool consume_send_group_msg_response(Skissm__GroupSession *outbound_group_session, Skissm__SendGroupMsgResponse *response) {
    // prepare a new chain key for next encryption
    const cipher_suite_t *cipher_suite = get_e2ee_pack(outbound_group_session->e2ee_pack_id)->cipher_suite;
    advance_group_chain_key(cipher_suite, &(outbound_group_session->chain_key));
    outbound_group_session->sequence += 1;
    // store sesson state
    get_skissm_plugin()->db_handler.store_group_session(outbound_group_session);

    if (response != NULL && response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
        return true;
    } else {
        return false;
    }
}

bool consume_group_msg(Skissm__E2eeAddress *receiver_address, Skissm__E2eeMsg *e2ee_msg) {
    // load the inbound group session
    Skissm__GroupSession *inbound_group_session = NULL;
    get_skissm_plugin()->db_handler.load_group_session_by_id(e2ee_msg->from, receiver_address, e2ee_msg->session_id, &inbound_group_session);

    if (inbound_group_session == NULL){
        ssm_notify_log(receiver_address, BAD_GROUP_SESSION, "consume_group_msg() inbound group session not found, just consume it");
        return true;
    }

    const cipher_suite_t *cipher_suite = get_e2ee_pack(inbound_group_session->e2ee_pack_id)->cipher_suite;
    int sign_key_len = cipher_suite->digital_signature_suite->get_crypto_param().sign_pub_key_len;

    if (inbound_group_session->associated_data.data == NULL || inbound_group_session->associated_data.len < sign_key_len){
        ssm_notify_log(receiver_address, BAD_GROUP_SESSION, "consume_group_msg() inbound group session associated_data is null, just consume it");
        return true;
    }

    // unpack the e2ee message
    Skissm__GroupMsgPayload *group_msg_payload = e2ee_msg->group_msg;

    uint8_t *identity_public_key = (uint8_t *)malloc(sizeof(uint8_t) * sign_key_len);
    memcpy(identity_public_key, inbound_group_session->associated_data.data, sign_key_len);

    // verify the signature
    int succ = cipher_suite->digital_signature_suite->verify(
        group_msg_payload->signature.data, group_msg_payload->signature.len,
        group_msg_payload->ciphertext.data, group_msg_payload->ciphertext.len,
        identity_public_key
    );
    if (succ < 0){
        ssm_notify_log(inbound_group_session->session_owner, BAD_SIGNATURE, "consume_group_msg()");
        // release
        skissm__group_session__free_unpacked(inbound_group_session, NULL);
        free_mem((void **)&identity_public_key, sign_key_len);
        return false;
    }

    // advance the chain key
    while (inbound_group_session->sequence < group_msg_payload->sequence){
        advance_group_chain_key(cipher_suite, &(inbound_group_session->chain_key));
        inbound_group_session->sequence += 1;
    }

    // create the message key
    Skissm__MsgKey *msg_key = (Skissm__MsgKey *) malloc(sizeof(Skissm__MsgKey));
    skissm__msg_key__init(msg_key);
    create_group_message_key(cipher_suite, &(inbound_group_session->chain_key), msg_key);

    // decryption
    uint8_t *plaintext_data;
    size_t plaintext_data_len = cipher_suite->symmetric_encryption_suite->decrypt(
        &(inbound_group_session->associated_data),
        msg_key->derived_key.data,
        group_msg_payload->ciphertext.data, group_msg_payload->ciphertext.len,
        &plaintext_data
    );

    if (plaintext_data_len <= 0){
        ssm_notify_log(inbound_group_session->session_owner, BAD_MESSAGE_DECRYPTION, "consume_group_msg()");
    } else {
        ssm_notify_group_msg(inbound_group_session->session_owner, e2ee_msg->from, inbound_group_session->group_info->group_address, plaintext_data, plaintext_data_len);
        free_mem((void **)&plaintext_data, plaintext_data_len);

        // advance the chain key
        advance_group_chain_key(cipher_suite, &(inbound_group_session->chain_key));
        inbound_group_session->sequence += 1;
        get_skissm_plugin()->db_handler.store_group_session(inbound_group_session);
    }

    // release
    skissm__group_session__free_unpacked(inbound_group_session, NULL);
    free_mem((void **)&identity_public_key, sign_key_len);
    skissm__msg_key__free_unpacked(msg_key, NULL);

    return succ>=0;
}
