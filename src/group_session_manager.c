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
    Skissm__GroupMember **group_members,
    size_t group_members_num
) {
    Skissm__CreateGroupRequest *request =
        (Skissm__CreateGroupRequest *)malloc(sizeof(Skissm__CreateGroupRequest));
    skissm__create_group_request__init(request);

    Skissm__CreateGroupMsg *msg =
        (Skissm__CreateGroupMsg *)malloc(sizeof(Skissm__CreateGroupMsg));
    skissm__create_group_msg__init(msg);

    copy_address_from_address(&(msg->sender_address), sender_address);
    msg->e2ee_pack_id = strdup(E2EE_PACK_ID_ECC_DEFAULT);
    Skissm__GroupInfo *group_info = msg->group_info;
    group_info = (Skissm__GroupInfo *)malloc(sizeof(Skissm__GroupInfo));
    skissm__group_info__init(group_info);
    group_info->group_name = strdup(group_name);
    group_info->n_group_members = group_members_num;
    copy_group_members(&(group_info->group_members), group_members, group_members_num);

    //done
    request->msg = msg;
    return request;
}

bool consume_create_group_response(
    const char *e2ee_pack_id,
    Skissm__E2eeAddress *sender_address,
    const char *group_name,
    Skissm__GroupMember **group_members,
    size_t group_members_num,
    Skissm__CreateGroupResponse *response
) {
    if (response != NULL && response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
        Skissm__E2eeAddress *group_address = response->group_address;
        create_outbound_group_session(e2ee_pack_id, sender_address, group_address, group_members, group_members_num, NULL);
        ssm_notify_group_created(group_address, group_name);
        return true;
    } else {
        return false;
    }
}

bool consume_create_group_msg(Skissm__E2eeAddress *receiver_address, Skissm__CreateGroupMsg *msg) {
    const char *e2ee_pack_id = msg->e2ee_pack_id;
    Skissm__E2eeAddress *group_address = msg->group_info->group_address;
    size_t group_members_num = msg->group_info->n_group_members;
    Skissm__GroupMember **group_members = msg->group_info->group_members;

    // create a new outbound group session
    create_outbound_group_session(e2ee_pack_id, receiver_address, group_address, group_members, group_members_num, NULL);

    // done
    return true;
}

Skissm__GetGroupRequest *produce_get_group_request(Skissm__E2eeAddress *group_address) {
    Skissm__GetGroupRequest *request = (Skissm__GetGroupRequest *)malloc(sizeof(Skissm__GetGroupRequest));
    skissm__get_group_request__init(request);
    copy_address_from_address(&(request->group_address), group_address);
    return request;
}

bool consume_get_group_response(Skissm__GetGroupResponse *response) {
    if (response != NULL && response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
        char *group_name = response->group_name;
        size_t n_group_members = response->n_group_members;
        Skissm__GroupMember **group_members = response->group_members;

        // @TODO update group info, and notify
        return true;
    } else {
        return false;
    }
}

Skissm__AddGroupMembersRequest *produce_add_group_members_request(
    Skissm__GroupSession *outbound_group_session,
    Skissm__GroupMember **adding_members,
    size_t adding_members_num
) {
    Skissm__AddGroupMembersRequest *request =
        (Skissm__AddGroupMembersRequest *)malloc(sizeof(Skissm__AddGroupMembersRequest));
    skissm__add_group_members_request__init(request);

    Skissm__AddGroupMembersMsg *msg =
        (Skissm__AddGroupMembersMsg *)malloc(sizeof(Skissm__AddGroupMembersMsg));
    skissm__add_group_members_msg__init(msg);

    msg->e2ee_pack_id = strdup(E2EE_PACK_ID_ECC_DEFAULT);
    copy_address_from_address(&(msg->sender_address), outbound_group_session->session_owner);
    copy_address_from_address(&(msg->group_address), outbound_group_session->group_address);
    msg->n_adding_members = adding_members_num;
    copy_group_members(&(msg->adding_members), adding_members, adding_members_num);

    // done
    request->msg = msg;
    return request;
}

bool consume_add_group_members_response(
    Skissm__GroupSession *outbound_group_session,
    Skissm__AddGroupMembersResponse *response
) {
    if (response != NULL && response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
        const char *e2ee_pack_id = outbound_group_session->e2ee_pack_id;
        Skissm__E2eeAddress *session_owner = outbound_group_session->session_owner;
        Skissm__E2eeAddress *group_address = outbound_group_session->group_address;
        size_t new_group_members_num = response->n_group_members;
        Skissm__GroupMember **new_group_members = response->group_members;

        // delete the old outbound group session
        get_skissm_plugin()->db_handler.unload_group_session(outbound_group_session);
        char *old_session_id = strdup(outbound_group_session->session_id);

        // generate a new outbound group session
        create_outbound_group_session(e2ee_pack_id, session_owner, group_address, new_group_members,
                                      new_group_members_num, old_session_id);

        // release
        free_mem((void **) &old_session_id, strlen(old_session_id));

        // done
        return true;
    } else {
        return false;
    }
}

bool consume_add_group_members_msg(Skissm__E2eeAddress *receiver_address, Skissm__AddGroupMembersMsg *msg) {
    Skissm__E2eeAddress *group_address = msg->group_address;
    size_t new_group_members_num = msg->n_all_members;
    Skissm__GroupMember **new_group_members = msg->all_members;
    const char *e2ee_pack_id = msg->e2ee_pack_id;

    /** The old group members have their own outbound group sessions, so they need to delete them.
     *  On the other hand, the new group members do not need to do this.
     */
    Skissm__GroupSession *outbound_group_session = NULL;
    get_skissm_plugin()->db_handler.load_outbound_group_session(receiver_address, group_address, &outbound_group_session);
    // delete the old outbound group session if it exists
    if (outbound_group_session != NULL) {
        get_skissm_plugin()->db_handler.unload_group_session(outbound_group_session);
        char *old_session_id = strdup(outbound_group_session->session_id);
        // create a new outbound group session
        create_outbound_group_session(e2ee_pack_id, receiver_address, group_address, new_group_members, new_group_members_num, old_session_id);
        // release
        skissm__group_session__free_unpacked(outbound_group_session, NULL);
        free_mem((void **) &old_session_id, strlen(old_session_id));
    } else{
        // create an outbound group session
        create_outbound_group_session(e2ee_pack_id, receiver_address, group_address, new_group_members, new_group_members_num, NULL);
    }

    // done
    return true;
}

Skissm__RemoveGroupMembersRequest *produce_remove_group_members_request(
    Skissm__GroupSession *outbound_group_session,
    Skissm__GroupMember **removing_group_members,
    size_t removing_group_members_num
) {
    Skissm__RemoveGroupMembersRequest *request =
        (Skissm__RemoveGroupMembersRequest *)malloc(sizeof(Skissm__RemoveGroupMembersRequest));
    skissm__remove_group_members_request__init(request);

    Skissm__RemoveGroupMembersMsg *msg =
        (Skissm__RemoveGroupMembersMsg *)malloc(sizeof(Skissm__RemoveGroupMembersMsg));
    skissm__remove_group_members_msg__init(msg);

    msg->e2ee_pack_id = strdup(E2EE_PACK_ID_ECC_DEFAULT);
    copy_address_from_address(&(msg->sender_address), outbound_group_session->session_owner);
    copy_address_from_address(&(msg->group_address), outbound_group_session->group_address);
    msg->n_removing_members = removing_group_members_num;
    copy_group_members(&(msg->removing_members), removing_group_members, removing_group_members_num);

    // done
    request->msg = msg;
    return request;
}

bool consume_remove_group_members_response(
    Skissm__GroupSession *outbound_group_session,
    Skissm__RemoveGroupMembersResponse *response
) {
    if (response != NULL && response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
        const char *e2ee_pack_id = outbound_group_session->e2ee_pack_id;
        Skissm__E2eeAddress *sender_address = outbound_group_session->session_owner;
        Skissm__E2eeAddress *group_address = outbound_group_session->group_address;
        Skissm__GroupMember **group_members = response->group_members;
        size_t group_members_num = response->n_group_members;

        // delete the old outbound group session
        get_skissm_plugin()->db_handler.unload_group_session(outbound_group_session);
        char *old_session_id = strdup(outbound_group_session->session_id);

        // generate a new outbound group session
        create_outbound_group_session(e2ee_pack_id, sender_address, group_address, group_members,
                                      group_members_num, old_session_id);

        // release
        free_mem((void **) &old_session_id, strlen(old_session_id));

        // done
        return true;
    } else {
        return false;
    }
}

bool consume_remove_group_members_msg(Skissm__E2eeAddress *receiver_address, Skissm__RemoveGroupMembersMsg *msg) {
    Skissm__E2eeAddress *group_address = msg->group_address;

    // if the receiver is the one who is going to be removed, the receiver should unload his or her own group session
    size_t i;
    for (i = 0; i < msg->n_removing_members; i++) {
        if (safe_strcmp(receiver_address->user->user_id, msg->removing_members[i]->user_id)) {
            // unload outbound group session
            Skissm__GroupSession *outbound_group_session = NULL;
            get_skissm_plugin()->db_handler.load_outbound_group_session(receiver_address, group_address, &outbound_group_session);
            if (outbound_group_session != NULL) {
                get_skissm_plugin()->db_handler.unload_group_session(outbound_group_session);
                // release
                skissm__group_session__free_unpacked(outbound_group_session, NULL);
            }
            // unload inbound group sessions
            Skissm__GroupSession **inbound_group_sessions = NULL;
            size_t inbound_group_sessions_num = get_skissm_plugin()->db_handler.load_inbound_group_sessions(receiver_address, group_address, &inbound_group_sessions);
            size_t j;
            for (j = 0; j < inbound_group_sessions_num; j++) {
                get_skissm_plugin()->db_handler.unload_group_session(inbound_group_sessions[j]);
                // release
                skissm__group_session__free_unpacked(inbound_group_sessions[j], NULL);
            }
            free(inbound_group_sessions);

            return true;
        }
    }

    // renew outbound group session
    size_t new_group_members_num = msg->n_all_members;
    Skissm__GroupMember **new_group_members = msg->all_members;
    const char *e2ee_pack_id = msg->e2ee_pack_id;

    Skissm__GroupSession *outbound_group_session = NULL;
    get_skissm_plugin()->db_handler.load_outbound_group_session(receiver_address, group_address, &outbound_group_session);
    // delete the old outbound group session if it exists
    if (outbound_group_session != NULL) {
        get_skissm_plugin()->db_handler.unload_group_session(outbound_group_session);
        char *old_session_id = strdup(outbound_group_session->session_id);
        // create a new outbound group session
        create_outbound_group_session(e2ee_pack_id, receiver_address, group_address, new_group_members, new_group_members_num, old_session_id);
        // release
        skissm__group_session__free_unpacked(outbound_group_session, NULL);
        free_mem((void **) &old_session_id, strlen(old_session_id));
    } else{
        // create an outbound group session
        create_outbound_group_session(e2ee_pack_id, receiver_address, group_address, new_group_members, new_group_members_num, NULL);
    }

    // done
    return true;
}

Skissm__SendGroupMsgRequest *produce_send_group_msg_request(
    Skissm__GroupSession *outbound_group_session,
    const uint8_t *plaintext_data, size_t plaintext_data_len
) {
    const cipher_suite_t *cipher_suite = get_e2ee_pack(outbound_group_session->e2ee_pack_id)->cipher_suite;

    Skissm__SendGroupMsgRequest *request = (Skissm__SendGroupMsgRequest *)malloc(sizeof(Skissm__SendGroupMsgRequest));
    skissm__send_group_msg_request__init(request);

    // Create the message key
    Skissm__MsgKey *msg_key = (Skissm__MsgKey *) malloc(sizeof(Skissm__MsgKey));
    skissm__msg_key__init(msg_key);
    create_group_message_key(cipher_suite, &(outbound_group_session->chain_key), msg_key);

    // Prepare an e2ee message
    Skissm__E2eeMsg *e2ee_msg = (Skissm__E2eeMsg *) malloc(sizeof(Skissm__E2eeMsg));
    skissm__e2ee_msg__init(e2ee_msg);
    e2ee_msg->version = strdup(outbound_group_session->version);
    e2ee_msg->session_id = strdup(outbound_group_session->session_id);
    e2ee_msg->msg_id = generate_uuid_str();
    copy_address_from_address(&(e2ee_msg->from), outbound_group_session->session_owner);
    copy_address_from_address(&(e2ee_msg->to), outbound_group_session->group_address);
    e2ee_msg->payload_case = SKISSM__E2EE_MSG__PAYLOAD_GROUP_MSG;

    // Prepare a group_msg_payload
    Skissm__GroupMsgPayload *group_msg_payload = (Skissm__GroupMsgPayload *) malloc(sizeof(Skissm__GroupMsgPayload));
    skissm__group_msg_payload__init(group_msg_payload);
    group_msg_payload->sequence = outbound_group_session->sequence;
    uint8_t *ad = outbound_group_session->associated_data.data;

    // Encryption
    group_msg_payload->ciphertext.len = cipher_suite->encrypt(
        ad,
        msg_key->derived_key.data,
        plaintext_data,
        plaintext_data_len,
        &(group_msg_payload->ciphertext.data)
    );

    // Signature
    int sig_len = cipher_suite->get_crypto_param().sig_len;
    group_msg_payload->signature.len = sig_len;
    group_msg_payload->signature.data = (uint8_t *) malloc(sizeof(uint8_t) * sig_len);
    cipher_suite->sign(
        outbound_group_session->signature_private_key.data,
        group_msg_payload->ciphertext.data,
        group_msg_payload->ciphertext.len,
        group_msg_payload->signature.data
    );

    // release
    skissm__msg_key__free_unpacked(msg_key, NULL);

    // done
    e2ee_msg->group_msg = group_msg_payload;
    request->msg = e2ee_msg;
    return request;
}

bool consume_send_group_msg_response(Skissm__GroupSession *outbound_group_session, Skissm__SendGroupMsgResponse *response) {
    if (response != NULL && response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
        // Prepare a new chain key for next encryption
        const cipher_suite_t *cipher_suite = get_e2ee_pack(outbound_group_session->e2ee_pack_id)->cipher_suite;
        advance_group_chain_key(cipher_suite, &(outbound_group_session->chain_key), outbound_group_session->sequence);
        outbound_group_session->sequence += 1;

        // store sesson state
        get_skissm_plugin()->db_handler.store_group_session(outbound_group_session);
        return true;
    } else {
        return false;
    }
}

bool consume_group_msg(Skissm__E2eeAddress *receiver_address, Skissm__E2eeMsg *e2ee_msg) {
    // load the inbound group session
    Skissm__GroupSession *inbound_group_session = NULL;
    get_skissm_plugin()->db_handler.load_inbound_group_session(receiver_address, e2ee_msg->session_id, &inbound_group_session);

    if (inbound_group_session == NULL){
        ssm_notify_error(BAD_MESSAGE_FORMAT, "consume_group_msg()");
        return false;
    }

    const cipher_suite_t *cipher_suite = get_e2ee_pack(inbound_group_session->e2ee_pack_id)->cipher_suite;

    // unpack the e2ee message
    Skissm__GroupMsgPayload *group_msg_payload = e2ee_msg->group_msg;

    // verify the signature
    size_t result = cipher_suite->verify(
        group_msg_payload->signature.data,
        inbound_group_session->signature_public_key.data,
        group_msg_payload->ciphertext.data, group_msg_payload->ciphertext.len);
    if (result < 0){
        ssm_notify_error(BAD_SIGNATURE, "consume_group_msg()");
        skissm__group_session__free_unpacked(inbound_group_session, NULL);
        return false;
    }

    // advance the chain key
    while (inbound_group_session->sequence < group_msg_payload->sequence){
        advance_group_chain_key(cipher_suite, &(inbound_group_session->chain_key), inbound_group_session->sequence);
        inbound_group_session->sequence += 1;
    }

    // create the message key
    Skissm__MsgKey *msg_key = (Skissm__MsgKey *) malloc(sizeof(Skissm__MsgKey));
    skissm__msg_key__init(msg_key);
    create_group_message_key(cipher_suite, &(inbound_group_session->chain_key), msg_key);

    // decryption
    uint8_t *plaintext_data;
    size_t plaintext_data_len = cipher_suite->decrypt(
        inbound_group_session->associated_data.data,
        msg_key->derived_key.data,
        group_msg_payload->ciphertext.data, group_msg_payload->ciphertext.len,
        &plaintext_data
    );

    if (plaintext_data_len <= 0){
        ssm_notify_error(BAD_MESSAGE_DECRYPTION, "consume_group_msg()");
    } else {
        ssm_notify_group_msg(e2ee_msg->from, inbound_group_session->group_address, plaintext_data, plaintext_data_len);
        free_mem((void **)&plaintext_data, plaintext_data_len);
    }

    // release
    skissm__group_session__free_unpacked(inbound_group_session, NULL);
    // group_msg_payload is within e2ee_msg
    skissm__msg_key__free_unpacked(msg_key, NULL);

    return result>0;
}
