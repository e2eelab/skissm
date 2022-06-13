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
#include "skissm/e2ee_client.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "skissm/mem_util.h"
#include "skissm/account.h"
#include "skissm/account_manager.h"
#include "skissm/e2ee_client_internal.h"
#include "skissm/group_session_manager.h"
#include "skissm/session.h"
#include "skissm/session_manager.h"

Skissm__RegisterUserResponse *register_user(
    uint64_t account_id,
    const char *e2ee_pack_id,
    const char *user_name,
    const char *device_id,
    const char *authenticator,
    const char *auth_code) {
    Skissm__Account *account = create_account(account_id, e2ee_pack_id);

    // register account to server
    Skissm__RegisterUserRequest *request = produce_register_request(account);
    request->user_name = strdup(user_name);
    request->device_id = strdup(device_id);
    request->authenticator = strdup(authenticator);
    request->auth_code = strdup(auth_code);
    request->e2ee_pack_id = strdup(e2ee_pack_id);

    Skissm__RegisterUserResponse *response = get_skissm_plugin()->proto_handler.register_user(request);
    bool consumed = consume_register_response(account, response);
    if (consumed) {
        set_account(account);
    } else {
        skissm__account__free_unpacked(account, NULL);
    }

    // release
    skissm__register_user_request__free_unpacked(request, NULL);

    // done
    return response;
}

Skissm__InviteResponse *invite(Skissm__E2eeAddress *from, Skissm__E2eeAddress *to) {
    Skissm__Session **outbound_sessions = NULL;
    size_t outbound_sessions_num = get_skissm_plugin()->db_handler.load_outbound_sessions(from, to->user->user_id, &outbound_sessions);
    if (outbound_sessions_num == (size_t)(0)) {
        return get_pre_key_bundle_internal(from, to);
    } else {
        size_t i;
        for (i = 0; i < outbound_sessions_num; i++) {
            if (!outbound_sessions[i]->responded) {
                // resend ?
            }
            // release
            skissm__session__free_unpacked(outbound_sessions[i], NULL);
        }
        // release
        free_mem((void **)(&outbound_sessions), sizeof(Skissm__Session *) * outbound_sessions_num);
        return NULL;
    }
}

Skissm__SendOne2oneMsgResponse *send_one2one_msg(Skissm__E2eeAddress *from, Skissm__E2eeAddress *to, const uint8_t *plaintext_data, size_t plaintext_data_len) {
    Skissm__Session **outbound_sessions = NULL;
    size_t outbound_sessions_num = get_skissm_plugin()->db_handler.load_outbound_sessions(from, to->user->user_id, &outbound_sessions);
    if (outbound_sessions_num <= (size_t)(0) || outbound_sessions == NULL) {
        ssm_notify_error(BAD_SESSION, "send_one2one_msg() outbound session is not responded");
        return NULL;
    }
    size_t i;
    for (i = 0; i < outbound_sessions_num; i++) {
        Skissm__Session *outbound_session = outbound_sessions[i];

        // pack common plaintext before sending it
        uint8_t *common_plaintext_data = NULL;
        size_t common_plaintext_data_len;
        pack_common_plaintext(plaintext_data, plaintext_data_len, &common_plaintext_data, &common_plaintext_data_len);

        if (outbound_session->responded == false) {
            // save common_plaintext_data with flag responded = false
            get_skissm_plugin()->db_handler.store_pending_plaintext_data(
                outbound_session->to,
                false,
                common_plaintext_data,
                common_plaintext_data_len);
            // release
            free_mem((void **)(&common_plaintext_data), common_plaintext_data_len);
            skissm__session__free_unpacked(outbound_session, NULL);
            continue;
        }

        // send message to server
        Skissm__SendOne2oneMsgResponse *response = send_one2one_msg_internal(outbound_session, common_plaintext_data, common_plaintext_data_len);

        // done
        // if error happened, keep common_plaintext_data in db
        if (response == NULL) {
            // save common_plaintext_data with flag responded = true
            get_skissm_plugin()->db_handler.store_pending_plaintext_data(
                outbound_session->to,
                true,
                common_plaintext_data,
                common_plaintext_data_len);
        }

        // release
        free_mem((void **)(&common_plaintext_data), common_plaintext_data_len);
        skissm__session__free_unpacked(outbound_session, NULL);

        // check if i is the last index
        if (i == (outbound_sessions_num - 1)) {
            // return response and release outbound_sessions
            free_mem((void **)(&outbound_sessions), sizeof(Skissm__Session *) * outbound_sessions_num);
            return response;
        } else {
            // release response
            if (response != NULL)
                skissm__send_one2one_msg_response__free_unpacked(response, NULL);
            else {
                // what if response error?
            }
        }
    }

    // release
    free_mem((void **)(&outbound_sessions), sizeof(Skissm__Session *) * outbound_sessions_num);

    // done;
    return NULL;
}

Skissm__CreateGroupResponse *create_group(
    Skissm__E2eeAddress *sender_address,
    const char *group_name,
    Skissm__GroupMember **group_members,
    size_t group_members_num) {
    Skissm__Account *account = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(sender_address, &account);
    if (account == NULL) {
        ssm_notify_error(BAD_ACCOUNT, "create_group()");
        return NULL;
    }

    // send message to server
    Skissm__CreateGroupRequest *request = produce_create_group_request(sender_address, group_name, group_members, group_members_num);
    Skissm__CreateGroupResponse *response = get_skissm_plugin()->proto_handler.create_group(request);
    consume_create_group_response(account->e2ee_pack_id, sender_address, group_name, group_members, group_members_num, response);

    // release
    skissm__account__free_unpacked(account, NULL);
    skissm__create_group_request__free_unpacked(request, NULL);

    // done
    return response;
}

Skissm__AddGroupMembersResponse *add_group_members(
    Skissm__E2eeAddress *sender_address,
    Skissm__E2eeAddress *group_address,
    Skissm__GroupMember **adding_members,
    size_t adding_members_num) {
    Skissm__GroupSession *outbound_group_session = NULL;
    get_skissm_plugin()->db_handler.load_outbound_group_session(sender_address, group_address, &outbound_group_session);
    if (outbound_group_session == NULL) {
        ssm_notify_error(BAD_GROUP_SESSION, "add_group_members()");
        return NULL;
    }

    // send message to server
    Skissm__AddGroupMembersRequest *request = produce_add_group_members_request(outbound_group_session, adding_members, adding_members_num);
    Skissm__AddGroupMembersResponse *response = get_skissm_plugin()->proto_handler.add_group_members(request);
    consume_add_group_members_response(outbound_group_session, response);

    // release
    skissm__add_group_members_request__free_unpacked(request, NULL);
    skissm__group_session__free_unpacked(outbound_group_session, NULL);

    // done
    return response;
}

Skissm__RemoveGroupMembersResponse *remove_group_members(
    Skissm__E2eeAddress *sender_address,
    Skissm__E2eeAddress *group_address,
    Skissm__GroupMember **removing_members,
    size_t removing_members_num) {
    Skissm__GroupSession *outbound_group_session = NULL;
    get_skissm_plugin()->db_handler.load_outbound_group_session(sender_address, group_address, &outbound_group_session);

    if (outbound_group_session == NULL) {
        ssm_notify_error(BAD_GROUP_SESSION, "remove_group_members()");
        return NULL;
    }

    // send message to server
    Skissm__RemoveGroupMembersRequest *request = produce_remove_group_members_request(outbound_group_session, removing_members, removing_members_num);
    Skissm__RemoveGroupMembersResponse *response = get_skissm_plugin()->proto_handler.remove_group_members(request);
    consume_remove_group_members_response(outbound_group_session, response);

    // release
    skissm__remove_group_members_request__free_unpacked(request, NULL);
    skissm__group_session__free_unpacked(outbound_group_session, NULL);

    // done
    return response;
}

Skissm__SendGroupMsgResponse *send_group_msg(
    Skissm__E2eeAddress *sender_address,
    Skissm__E2eeAddress *group_address,
    const uint8_t *plaintext_data,
    size_t plaintext_data_len) {
    // load the outbound group session
    Skissm__GroupSession *outbound_group_session = NULL;
    get_skissm_plugin()->db_handler.load_outbound_group_session(sender_address, group_address, &outbound_group_session);
    if (outbound_group_session == NULL) {
        // outbound_group_session is not exist
        return NULL;
    }
    Skissm__SendGroupMsgRequest *request = produce_send_group_msg_request(outbound_group_session, plaintext_data, plaintext_data_len);
    Skissm__SendGroupMsgResponse *response = get_skissm_plugin()->proto_handler.send_group_msg(request);
    consume_send_group_msg_response(outbound_group_session, response);

    // release
    skissm__send_group_msg_request__free_unpacked(request, NULL);
    skissm__group_session__free_unpacked(outbound_group_session, NULL);

    // done
    return response;
}

Skissm__ConsumeProtoMsgResponse *consume_proto_msg(const char *proto_msg_id) {
    Skissm__ConsumeProtoMsgRequest *request = (Skissm__ConsumeProtoMsgRequest*)malloc(sizeof(Skissm__ConsumeProtoMsgRequest));
    skissm__consume_proto_msg_request__init(request);
    request->proto_msg_id = strdup(proto_msg_id);
    Skissm__ConsumeProtoMsgResponse *response = get_skissm_plugin()->proto_handler.consume_proto_msg(request);

    // release
    skissm__consume_proto_msg_request__free_unpacked(request, NULL);

    // done
    return response;
}

Skissm__ConsumeProtoMsgResponse *process_proto_msg(uint8_t *proto_msg_data, size_t proto_msg_data_len) {
    Skissm__ProtoMsg *proto_msg = skissm__proto_msg__unpack(NULL, proto_msg_data_len, proto_msg_data);
    Skissm__E2eeAddress *receiver_address = proto_msg->to;

    bool consumed = false;
    switch(proto_msg->payload_case) {
        case SKISSM__PROTO_MSG__PAYLOAD_SUPPLY_OPKS_MSG:
            consumed = consume_supply_opks_msg(receiver_address, proto_msg->supply_opks_msg);
            break;
        case SKISSM__PROTO_MSG__PAYLOAD_NEW_USER_DEVICE_MSG:
            consumed = consume_new_user_device_msg(receiver_address, proto_msg->new_user_device_msg);
            break;
        case SKISSM__PROTO_MSG__PAYLOAD_INVITE_MSG:
            consumed = consume_invite_msg(receiver_address, proto_msg->invite_msg);
            break;
        case SKISSM__PROTO_MSG__PAYLOAD_ACCEPT_MSG:
            consumed = consume_accept_msg(receiver_address, proto_msg->accept_msg);
            break;
        case SKISSM__PROTO_MSG__PAYLOAD_E2EE_MSG:
            if (proto_msg->e2ee_msg->payload_case == SKISSM__E2EE_MSG__PAYLOAD_ONE2ONE_MSG)
                consumed = consume_one2one_msg(receiver_address, proto_msg->e2ee_msg);
            else if (proto_msg->e2ee_msg->payload_case == SKISSM__E2EE_MSG__PAYLOAD_GROUP_MSG)
                consumed = consume_group_msg(receiver_address, proto_msg->e2ee_msg);
            break;
        case SKISSM__PROTO_MSG__PAYLOAD_CREATE_GROUP_MSG:
            consumed = consume_create_group_msg(receiver_address, proto_msg->create_group_msg);
            break;
        case SKISSM__PROTO_MSG__PAYLOAD_ADD_GROUP_MEMBERS_MSG:
            consumed = consume_add_group_members_msg(receiver_address, proto_msg->add_group_members_msg);
            break;
        case SKISSM__PROTO_MSG__PAYLOAD_REMOVE_GROUP_MEMBERS_MSG:
            consumed = consume_remove_group_members_msg(receiver_address, proto_msg->remove_group_members_msg);
            break;
        default:
            // consume the messag that is arriving here
            consumed = true;
            break;
    };

    // notify server that the proto_msg has been consumed
    Skissm__ConsumeProtoMsgResponse *response = NULL;
    if (consumed && (proto_msg->tag != NULL)) {
        response = consume_proto_msg(proto_msg->tag->proto_msg_id);
    } else {
        response = (Skissm__ConsumeProtoMsgResponse *)malloc(sizeof(Skissm__ConsumeProtoMsgResponse));
        skissm__consume_proto_msg_response__init(response);
        response->code = SKISSM__RESPONSE_CODE__RESPONSE_CODE_NO_CONTENT;
    }

    // release
    skissm__proto_msg__free_unpacked(proto_msg, NULL);

    // done
    return response;
}

