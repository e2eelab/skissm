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

Skissm__CreateGroupRequest *produce_create_group_request(Skissm__E2eeAddress *sender_address, char *group_name, size_t member_num, Skissm__E2eeAddress **member_addresses) {
    Skissm__CreateGroupRequest *request =
        (Skissm__CreateGroupRequest *)malloc(sizeof(Skissm__CreateGroupRequest));
    skissm__create_group_request__init(request);

    Skissm__CreateGroupMsg *msg =
        (Skissm__CreateGroupMsg *)malloc(sizeof(Skissm__CreateGroupMsg));
    skissm__create_group_msg__init(msg);

    copy_address_from_address(&(msg->sender_address), sender_address);
    msg->group_name = strdup(group_name);
    msg->n_member_addresses = member_num;
    copy_member_addresses_from_member_addresses(&(msg->member_addresses), (const Skissm__E2eeAddress **)member_addresses, member_num);

    //done
    request->msg = msg;
    return request;
}

void consume_create_group_response(
    uint32_t e2ee_pack_id,
    Skissm__E2eeAddress *sender_address,
    char *group_name,
    size_t member_num,
    Skissm__E2eeAddress **member_addresses,
    Skissm__CreateGroupResponse *response
) {
    if (response->code == OK) {
        Skissm__E2eeAddress *group_address = response->group_address;
        create_outbound_group_session(e2ee_pack_id, sender_address, group_address, member_addresses, member_num, NULL);
        ssm_notify_group_created(group_address, group_name);
    }
}

bool consume_create_group_msg(Skissm__E2eeAddress *receiver_address, Skissm__CreateGroupMsg *msg) {
    uint32_t e2ee_pack_id = msg->e2ee_pack_id;
    size_t member_num = msg->n_member_addresses;
    Skissm__E2eeAddress **member_addresses = msg->member_addresses;
    Skissm__E2eeAddress *group_address = msg->group_address;

    // create a new outbound group session
    create_outbound_group_session(e2ee_pack_id, receiver_address, group_address, member_addresses, member_num, NULL);

    // done
    return true;
}

Skissm__GetGroupRequest *produce_get_group_request(Skissm__E2eeAddress *group_address) {
    Skissm__GetGroupRequest *request = (Skissm__GetGroupRequest *)malloc(sizeof(Skissm__GetGroupRequest));
    skissm__get_group_request__init(request);
    copy_address_from_address(&(request->group_address), group_address);
    return request;
}

void consume_get_group_response(Skissm__GetGroupResponse *response) {
    if (response->code == OK) {
        char *group_name = response->group_name;
        size_t member_num = response->n_member_addresses;
        Skissm__E2eeAddress **member_addresses = response->member_addresses;

        // @TODO update group info, and notify
    }
}

Skissm__AddGroupMembersRequest *produce_add_group_members_request(Skissm__GroupSession *outbound_group_session, const Skissm__E2eeAddress **adding_member_addresses, size_t adding_member_num) {
    Skissm__AddGroupMembersRequest *request =
        (Skissm__AddGroupMembersRequest *)malloc(sizeof(Skissm__AddGroupMembersRequest));
    skissm__add_group_members_request__init(request);

    Skissm__AddGroupMembersMsg *msg =
        (Skissm__AddGroupMembersMsg *)malloc(sizeof(Skissm__AddGroupMembersMsg));
    skissm__add_group_members_msg__init(msg);

    copy_address_from_address(&(msg->sender_address), outbound_group_session->session_owner);
    copy_address_from_address(&(msg->group_address), outbound_group_session->group_address);
    msg->n_member_addresses = adding_member_num;
    copy_member_addresses_from_member_addresses(&(msg->member_addresses), adding_member_addresses, adding_member_num);

    // done
    request->msg = msg;
    return request;
}

void consume_add_group_members_response(
    Skissm__GroupSession *outbound_group_session,
    const Skissm__E2eeAddress **adding_member_addresses,
    size_t adding_member_num,
    Skissm__AddGroupMembersResponse *response) {
    uint32_t e2ee_pack_id = outbound_group_session->e2ee_pack_id;
    Skissm__E2eeAddress *sender_address = outbound_group_session->session_owner;
    Skissm__E2eeAddress *group_address = outbound_group_session->group_address;

    size_t old_member_num = outbound_group_session->n_member_addresses;
    size_t member_num = old_member_num + adding_member_num;
    Skissm__E2eeAddress **member_addresses = (Skissm__E2eeAddress **) malloc(sizeof(Skissm__E2eeAddress *) * member_num);
    size_t i;
    for (i = 0; i < old_member_num; i++){
        copy_address_from_address(&(member_addresses[i]), (outbound_group_session->member_addresses)[i]);
    }
    for (i = old_member_num; i < member_num; i++){
        copy_address_from_address(&(member_addresses[i]), adding_member_addresses[i - old_member_num]);
    }

    // delete the old outbound group session
    get_skissm_plugin()->db_handler.unload_group_session(outbound_group_session);
    char *old_session_id = strdup(outbound_group_session->session_id);

    // generate a new outbound group session
    create_outbound_group_session(e2ee_pack_id, sender_address, group_address, member_addresses, member_num, old_session_id);

    // release
    free_mem((void **)&old_session_id, strlen(old_session_id));
}

bool consume_add_group_members_msg(Skissm__E2eeAddress *receiver_address, Skissm__AddGroupMembersMsg *msg) {
    Skissm__E2eeAddress *group_address = msg->group_address;
    size_t adding_member_num = msg->n_member_addresses;
    Skissm__E2eeAddress **adding_member_addresses = msg->member_addresses;
    uint32_t e2ee_pack_id = msg->e2ee_pack_id;

    Skissm__GroupSession *inbound_group_session = NULL;
    get_skissm_plugin()->db_handler.load_inbound_group_session(receiver_address, group_address, &inbound_group_session);

    // TODO: compare adding_member_addresses
    if (inbound_group_session != NULL) {
        size_t new_member_num = inbound_group_session->n_member_addresses + adding_member_num;
        Skissm__E2eeAddress **new_member_addresses = (Skissm__E2eeAddress **)malloc(sizeof(Skissm__E2eeAddress *) * new_member_num);
        size_t i;
        for (i = 0; i < inbound_group_session->n_member_addresses; i++) {
            copy_address_from_address(&(new_member_addresses[i]), (inbound_group_session->member_addresses)[i]);
        }
        for (i = 0; i < adding_member_num; i++) {
            copy_address_from_address(&(new_member_addresses[inbound_group_session->n_member_addresses + i]), adding_member_addresses[i]);
        }
        // delete the old group session
        char *old_session_id = strdup(inbound_group_session->session_id);
        get_skissm_plugin()->db_handler.unload_group_session(inbound_group_session);

        // create a new outbound group session
        create_outbound_group_session(e2ee_pack_id, receiver_address, group_address, new_member_addresses, new_member_num, old_session_id);

        // release
        free_mem((void **)&old_session_id, strlen(old_session_id));
    } else {
        // get_group_members(group_address);
        // create_outbound_group_session(e2ee_pack_id, receiver_address, group_address, member_addresses, member_num, NULL);
    }

    // done
    return true;
}

Skissm__RemoveGroupMembersRequest *produce_remove_group_members_request(Skissm__GroupSession *outbound_group_session, const Skissm__E2eeAddress **removing_member_addresses, size_t removing_member_num) {
    Skissm__RemoveGroupMembersRequest *request =
        (Skissm__RemoveGroupMembersRequest *)malloc(sizeof(Skissm__RemoveGroupMembersRequest));
    skissm__remove_group_members_request__init(request);

    Skissm__RemoveGroupMembersMsg *msg =
        (Skissm__RemoveGroupMembersMsg *)malloc(sizeof(Skissm__RemoveGroupMembersMsg));
    skissm__remove_group_members_msg__init(msg);

    copy_address_from_address(&(msg->sender_address), outbound_group_session->session_owner);
    copy_address_from_address(&(msg->group_address), outbound_group_session->group_address);
    msg->n_member_addresses = removing_member_num;
    copy_member_addresses_from_member_addresses(&(msg->member_addresses), removing_member_addresses, removing_member_num);

    return request;
}

void consume_remove_group_members_response(
    Skissm__GroupSession *outbound_group_session,
    const Skissm__E2eeAddress **removing_member_addresses,
    size_t removing_member_num,
    Skissm__RemoveGroupMembersResponse *response) {
    uint32_t e2ee_pack_id = outbound_group_session->e2ee_pack_id;
    Skissm__E2eeAddress *sender_address = outbound_group_session->session_owner;
    Skissm__E2eeAddress *group_address = outbound_group_session->group_address;

    size_t original_member_num = outbound_group_session->n_member_addresses;
    size_t member_num = original_member_num - removing_member_num;
    Skissm__E2eeAddress **member_addresses = (Skissm__E2eeAddress **) malloc(sizeof(Skissm__E2eeAddress *) * member_num);
    size_t i, j;
    for(j = 0; j < removing_member_num; j++) {
        for(i = 0; i < original_member_num; i++) {
            if(compare_address((Skissm__E2eeAddress *)outbound_group_session->member_addresses[i], (Skissm__E2eeAddress *)removing_member_addresses[j])){
                skissm__e2ee_address__free_unpacked(outbound_group_session->member_addresses[i], NULL);
                outbound_group_session->member_addresses[i] = NULL;
                break;
            }
        }
    }
    i = 0, j = 0;
    while (i < member_num){
        if ((outbound_group_session->member_addresses)[i + j] != NULL){
            copy_address_from_address(&(member_addresses[i]), (outbound_group_session->member_addresses)[i + j]);
            i++;
        } else{
            j++;
        }
    }

    // delete the old outbound group session
    get_skissm_plugin()->db_handler.unload_group_session(outbound_group_session);
    char *old_session_id = strdup(outbound_group_session->session_id);

    // generate a new outbound group session
    create_outbound_group_session(e2ee_pack_id, sender_address, group_address, member_addresses, member_num, old_session_id);

    // release
    free_mem((void **)&old_session_id, strlen(old_session_id));
}

bool consume_remove_group_members_msg(Skissm__E2eeAddress *receiver_address, Skissm__RemoveGroupMembersMsg *msg) {
    Skissm__E2eeAddress *group_address = msg->group_address;
    size_t removing_member_num = msg->n_member_addresses;
    Skissm__E2eeAddress **removing_member_addresses = msg->member_addresses;
    uint32_t e2ee_pack_id = msg->e2ee_pack_id;

    Skissm__GroupSession *group_session = NULL;
    get_skissm_plugin()->db_handler.load_inbound_group_session(receiver_address, group_address, &group_session);

    size_t new_member_num = group_session->n_member_addresses - removing_member_num;
    Skissm__E2eeAddress **new_member_addresses = (Skissm__E2eeAddress **)malloc(sizeof(Skissm__E2eeAddress *) * new_member_num);
    size_t i = 0, j = 0;
    while (i < group_session->n_member_addresses) {
        if (j < removing_member_num) {
            if (compare_address(group_session->member_addresses[i], removing_member_addresses[j])) {
                i++;
                j++;
            } else {
                copy_address_from_address(&(new_member_addresses[i - j]), group_session->member_addresses[i]);
                i++;
            }
        } else {
            copy_address_from_address(&(new_member_addresses[i - j]), group_session->member_addresses[i]);
            i++;
        }
    }
    // delete the old group session
    get_skissm_plugin()->db_handler.unload_group_session(group_session);
    char *old_session_id = strdup(group_session->session_id);

    // create a new outbound group session
    create_outbound_group_session(e2ee_pack_id, receiver_address, group_address, new_member_addresses, new_member_num, old_session_id);

    // release
    free_mem((void **)&old_session_id, strlen(old_session_id));

    // done
    return true;
}

Skissm__SendGroupMsgRequest *produce_send_group_msg_request(Skissm__GroupSession *group_session, const uint8_t *plaintext_data, size_t plaintext_data_len) {
    const cipher_suite_t *cipher_suite = get_e2ee_pack(group_session->e2ee_pack_id)->cipher_suite;

    Skissm__SendGroupMsgRequest *request = (Skissm__SendGroupMsgRequest *)malloc(sizeof(Skissm__SendGroupMsgRequest));
    skissm__send_group_msg_request__init(request);

    // Create the message key
    Skissm__MsgKey *msg_key = (Skissm__MsgKey *) malloc(sizeof(Skissm__MsgKey));
    skissm__msg_key__init(msg_key);
    create_group_message_key(cipher_suite, &(group_session->chain_key), msg_key);

    // Prepare an e2ee message
    Skissm__E2eeMsg *e2ee_msg = (Skissm__E2eeMsg *) malloc(sizeof(Skissm__E2eeMsg));
    skissm__e2ee_msg__init(e2ee_msg);
    e2ee_msg->version = group_session->version;
    e2ee_msg->session_id = strdup(group_session->session_id);
    e2ee_msg->msg_id = generate_uuid_str();
    copy_address_from_address(&(e2ee_msg->from), group_session->session_owner);
    copy_address_from_address(&(e2ee_msg->to), group_session->group_address);
    e2ee_msg->payload_case = SKISSM__E2EE_MSG__PAYLOAD_GROUP_MSG;

    // Prepare a group_msg_payload
    Skissm__GroupMsgPayload *group_msg_payload = (Skissm__GroupMsgPayload *) malloc(sizeof(Skissm__GroupMsgPayload));
    skissm__group_msg_payload__init(group_msg_payload);
    group_msg_payload->sequence = group_session->sequence;
    uint8_t *ad = group_session->associated_data.data;

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
        group_session->signature_private_key.data,
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

void consume_send_group_msg_response(Skissm__GroupSession *outbound_group_session, Skissm__SendGroupMsgResponse *response) {
    if (response->code == OK) {
        // Prepare a new chain key for next encryption
        const cipher_suite_t *cipher_suite = get_e2ee_pack(outbound_group_session->e2ee_pack_id)->cipher_suite;
        advance_group_chain_key(cipher_suite, &(outbound_group_session->chain_key), outbound_group_session->sequence);
        outbound_group_session->sequence += 1;

        // store sesson state
        get_skissm_plugin()->db_handler.store_group_session(outbound_group_session);
    }
}

bool consume_group_msg(Skissm__E2eeAddress *receiver_address, Skissm__E2eeMsg *e2ee_msg) {
    // load the inbound group session
    Skissm__GroupSession *inbound_group_session = NULL;
    get_skissm_plugin()->db_handler.load_inbound_group_session(receiver_address, e2ee_msg->to, &inbound_group_session);

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
        goto complete;
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

complete:
    // release
    skissm__msg_key__free_unpacked(msg_key, NULL);
    skissm__group_msg_payload__free_unpacked(group_msg_payload, NULL);
    skissm__group_session__free_unpacked(inbound_group_session, NULL);

    return result>0;
}
