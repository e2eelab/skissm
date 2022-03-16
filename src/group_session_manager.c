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
#include "skissm/e2ee_protocol.h"
#include "skissm/e2ee_protocol_handler.h"
#include "skissm/group_session.h"
#include "skissm/mem_util.h"
#include "skissm/session.h"

static void handle_create_group_release(
    create_group_response_handler *this_handler
) {
    this_handler->sender_address = NULL;
    this_handler->group_name = NULL;
    this_handler->member_addresses = NULL;
    this_handler->member_num = 0;
}

create_group_response_handler create_group_response_handler_store = {
    NULL,
    NULL,
    NULL,
    0,
    handle_create_group_release
};

static void handle_get_group_release(
    get_group_response_handler *this_handler
) {
    this_handler->group_name = NULL;
    this_handler->group_address = NULL;
    this_handler->member_num = 0;
}

get_group_response_handler get_group_response_handler_store = {
    NULL,
    NULL,
    0,
    NULL,
    handle_get_group_release
};

static void handle_add_group_members_response(
    add_group_members_response_handler *this_handler
) {
    Skissm__E2eeAddress *sender_address = this_handler->outbound_group_session->session_owner;
    Skissm__E2eeAddress *group_address = this_handler->outbound_group_session->group_address;

    size_t old_member_num = this_handler->outbound_group_session->n_member_addresses;
    size_t member_num = old_member_num + this_handler->adding_member_num;
    Skissm__E2eeAddress **member_addresses = (Skissm__E2eeAddress **) malloc(sizeof(Skissm__E2eeAddress *) * member_num);
    size_t i;
    for (i = 0; i < old_member_num; i++){
        copy_address_from_address(&(member_addresses[i]), (this_handler->outbound_group_session->member_addresses)[i]);
    }
    for (i = old_member_num; i < member_num; i++){
        copy_address_from_address(&(member_addresses[i]), (this_handler->adding_member_addresses)[i - old_member_num]);
    }

    /* delete the old outbound group session */
    get_ssm_plugin()->unload_group_session(this_handler->outbound_group_session);
    char *old_session_id = strdup(this_handler->outbound_group_session->session_id);

    /* generate a new outbound group session */
    create_outbound_group_session(sender_address, group_address, member_addresses, member_num, old_session_id);

    // release
    free_mem((void **)&old_session_id, strlen(old_session_id));
}

static void handle_add_group_members_release(
    add_group_members_response_handler *this_handler
) {
    skissm__e2ee_group_session__free_unpacked(this_handler->outbound_group_session, NULL);
    this_handler->outbound_group_session = NULL;
    this_handler->adding_member_addresses = NULL;
    this_handler->adding_member_num = 0;
}

add_group_members_response_handler add_group_members_response_handler_store = {
    NULL,
    NULL,
    0,
    handle_add_group_members_response,
    handle_add_group_members_release
};

static void handle_remove_group_members_response(
    remove_group_members_response_handler *this_handler
) {
    Skissm__E2eeAddress *sender_address = this_handler->outbound_group_session->session_owner;
    Skissm__E2eeAddress *group_address = this_handler->outbound_group_session->group_address;

    size_t original_member_num = this_handler->outbound_group_session->n_member_addresses;
    size_t member_num = original_member_num - this_handler->removing_member_num;
    Skissm__E2eeAddress **member_addresses = (Skissm__E2eeAddress **) malloc(sizeof(Skissm__E2eeAddress *) * member_num);
    size_t i, j;
    for (j = 0; j < this_handler->removing_member_num; j++){
        for (i = 0; i < original_member_num; i++){
            if (compare_address((this_handler->outbound_group_session->member_addresses)[i], (this_handler->removing_member_addresses)[j])){
                skissm__e2ee_address__free_unpacked((this_handler->outbound_group_session->member_addresses)[i], NULL);
                (this_handler->outbound_group_session->member_addresses)[i] = NULL;
                break;
            }
        }
    }
    i = 0, j = 0;
    while (i < member_num){
        if ((this_handler->outbound_group_session->member_addresses)[i + j] != NULL){
            copy_address_from_address(&(member_addresses[i]), (this_handler->outbound_group_session->member_addresses)[i + j]);
            i++;
        } else{
            j++;
        }
    }

    /* delete the old outbound group session */
    get_ssm_plugin()->unload_group_session(this_handler->outbound_group_session);
    char *old_session_id = strdup(this_handler->outbound_group_session->session_id);

    /* generate a new outbound group session */
    create_outbound_group_session(sender_address, group_address, member_addresses, member_num, old_session_id);

    // release
    free_mem((void **)&old_session_id, strlen(old_session_id));
}

static void handle_remove_group_members_release(
    remove_group_members_response_handler *this_handler
) {
    skissm__e2ee_group_session__free_unpacked(this_handler->outbound_group_session, NULL);
    this_handler->outbound_group_session = NULL;
    this_handler->removing_member_addresses = NULL;
    this_handler->removing_member_num = 0;
}

remove_group_members_response_handler remove_group_members_response_handler_store = {
    NULL,
    NULL,
    0,
    handle_remove_group_members_response,
    handle_remove_group_members_release
};

void create_group(
    Skissm__E2eeAddress *user_address,
    char *group_name,
    Skissm__E2eeAddress **member_addresses,
    size_t member_num
) {
    create_group_response_handler_store.sender_address = user_address;
    create_group_response_handler_store.group_name = strdup(group_name);
    create_group_response_handler_store.member_addresses = member_addresses;
    create_group_response_handler_store.member_num = member_num;
    send_create_group_request(&create_group_response_handler_store);
}

Skissm__CreateGroupRequestPayload *produce_create_group_request_payload(Skissm__E2eeAddress *sender_address, char *group_name, size_t member_num, Skissm__E2eeAddress **member_addresses) {
    Skissm__CreateGroupRequestPayload *create_group_request_payload =
        (Skissm__CreateGroupRequestPayload *)malloc(sizeof(Skissm__CreateGroupRequestPayload));
    skissm__create_group_request_payload__init(create_group_request_payload);

    copy_address_from_address(&(create_group_request_payload->sender_address), sender_address);
    create_group_request_payload->group_name = strdup(group_name);
    create_group_request_payload->n_member_addresses = member_num;
    copy_member_addresses_from_member_addresses(&(create_group_request_payload->member_addresses), (const Skissm__E2eeAddress **)member_addresses, member_num);

    return create_group_request_payload;
}

void consume_create_group_response_payload(
    Skissm__E2eeAddress *sender_address,
    char *group_name,
    size_t member_num,
    Skissm__E2eeAddress **member_addresses,
    Skissm__CreateGroupResponsePayload *create_group_response_payload
) {
    Skissm__E2eeAddress *group_address = create_group_response_payload->group_address;
    create_outbound_group_session(sender_address, group_address, member_addresses, member_num, NULL);
    ssm_notify_group_created(group_address, group_name);
}

Skissm__GetGroupRequestPayload *produce_get_group_request_payload(Skissm__E2eeAddress *group_address) {
    Skissm__GetGroupRequestPayload *get_group_request_payload = (Skissm__GetGroupRequestPayload *)malloc(sizeof(Skissm__GetGroupRequestPayload));
    skissm__get_group_request_payload__init(get_group_request_payload);
    copy_address_from_address(&(get_group_request_payload->group_address), group_address);
    return get_group_request_payload;
}

void consume_get_group_response_payload(Skissm__GetGroupResponsePayload *get_group_response_payload) {
    char *group_name = get_group_response_payload->group_name;
    size_t member_num = get_group_response_payload->n_member_addresses;
    Skissm__E2eeAddress **member_addresses = get_group_response_payload->member_addresses;

    // @TODO update group info, and notify
}

get_group_response_handler *get_group_members(Skissm__E2eeAddress *group_address){
    get_group_response_handler_store.group_address = group_address;
    send_get_group_request(&get_group_response_handler_store);

    return &get_group_response_handler_store;
}

size_t add_group_members(
    Skissm__E2eeAddress *sender_address,
    Skissm__E2eeAddress *group_address,
    Skissm__E2eeAddress **adding_member_addresses,
    size_t adding_member_num
) {
    get_ssm_plugin()->load_outbound_group_session(sender_address, group_address, &(add_group_members_response_handler_store.outbound_group_session));
    if (add_group_members_response_handler_store.outbound_group_session == NULL){
        ssm_notify_error(BAD_GROUP_SESSION, "add_group_members()");
        return (size_t)(-1);
    }
    add_group_members_response_handler_store.adding_member_addresses = adding_member_addresses;
    add_group_members_response_handler_store.adding_member_num = adding_member_num;

    send_add_group_members_request(&add_group_members_response_handler_store);

    return (size_t)0;
}

void remove_group_members(
    Skissm__E2eeAddress *sender_address,
    Skissm__E2eeAddress *group_address,
    Skissm__E2eeAddress **removing_member_addresses,
    size_t removing_member_num
) {
    get_ssm_plugin()->load_outbound_group_session(sender_address, group_address, &(remove_group_members_response_handler_store.outbound_group_session));
    remove_group_members_response_handler_store.removing_member_addresses = removing_member_addresses;
    remove_group_members_response_handler_store.removing_member_num = removing_member_num;

    send_remove_group_members_request(&remove_group_members_response_handler_store);
}

Skissm__E2eeMessage *produce_group_msg(Skissm__E2eeGroupSession *group_session, const uint8_t *plaintext, size_t plaintext_len) {
    /* Create the message key */
    Skissm__MessageKey *keys = (Skissm__MessageKey *) malloc(sizeof(Skissm__MessageKey));
    skissm__message_key__init(keys);
    create_group_message_keys(&(group_session->chain_key), keys);

    /* Prepare an e2ee message */
    Skissm__E2eeMessage *group_message = (Skissm__E2eeMessage *) malloc(sizeof(Skissm__E2eeMessage));
    skissm__e2ee_message__init(group_message);
    group_message->msg_type = SKISSM__E2EE_MESSAGE_TYPE__GROUP_MESSAGE;
    group_message->version = group_session->version;
    group_message->session_id = strdup(group_session->session_id);
    copy_address_from_address(&(group_message->from), group_session->session_owner);
    copy_address_from_address(&(group_message->to), group_session->group_address);

    /* Prepare a group message */
    Skissm__E2eeGroupMsgPayload *group_msg_payload = (Skissm__E2eeGroupMsgPayload *) malloc(sizeof(Skissm__E2eeGroupMsgPayload));
    skissm__e2ee_group_msg_payload__init(group_msg_payload);
    group_msg_payload->sequence = group_session->sequence;
    uint8_t *ad = group_session->associated_data.data;

    /* Encryption */
    group_msg_payload->ciphertext.len = CIPHER.suite1->encrypt(
        ad,
        keys->derived_key.data,
        plaintext,
        plaintext_len,
        &(group_msg_payload->ciphertext.data)
    );

    /* Signature */
    int sig_len = CIPHER.suite1->get_crypto_param().sig_len;
    group_msg_payload->signature.len = sig_len;
    group_msg_payload->signature.data = (uint8_t *) malloc(sizeof(uint8_t) * sig_len);
    CIPHER.suite1->sign(
        group_session->signature_private_key.data,
        group_msg_payload->ciphertext.data,
        group_msg_payload->ciphertext.len,
        group_msg_payload->signature.data
    );

    /* Pack the group message into the e2ee message */
    group_message->payload.len = skissm__e2ee_group_msg_payload__get_packed_size(group_msg_payload);
    group_message->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * group_message->payload.len);
    skissm__e2ee_group_msg_payload__pack(group_msg_payload, group_message->payload.data);

    /* Prepare a new chain key for next encryption */
    advance_group_chain_key(&(group_session->chain_key), group_session->sequence);
    group_session->sequence += 1;

    // release
    skissm__message_key__free_unpacked(keys, NULL);
    skissm__e2ee_group_msg_payload__free_unpacked(group_msg_payload, NULL);

    // done
    return group_message;
}

void encrypt_group_session(
    Skissm__E2eeAddress *sender_address,
    Skissm__E2eeAddress *group_address,
    const uint8_t *plaintext, size_t plaintext_len
) {
    /* Load the outbound group session */
    Skissm__E2eeGroupSession *group_session = NULL;
    get_ssm_plugin()->load_outbound_group_session(sender_address, group_address, &group_session);

    /* Do the encryption */
    send_group_msg(group_session, plaintext, plaintext_len);

    /* Release the group session */
    close_group_session(group_session);
}

void consume_group_msg(Skissm__E2eeAddress *receiver_address, Skissm__E2eeMessage *group_msg) {
    /* Load the inbound group session */
    Skissm__E2eeGroupSession *group_session = NULL;
    get_ssm_plugin()->load_inbound_group_session(receiver_address, group_msg->to, &group_session);

    if (group_session == NULL){
        ssm_notify_error(BAD_MESSAGE_FORMAT, "consume_group_msg()");
        return;
    }

    Skissm__E2eeGroupMsgPayload *group_msg_payload = NULL;
    Skissm__MessageKey *keys = NULL;

    /* Unpack the e2ee message */
    group_msg_payload = skissm__e2ee_group_msg_payload__unpack(NULL, group_msg->payload.len, group_msg->payload.data);

    /* Verify the signature */
    size_t result = CIPHER.suite1->verify(
        group_msg_payload->signature.data,
        group_session->signature_public_key.data,
        group_msg_payload->ciphertext.data, group_msg_payload->ciphertext.len);
    if (result < 0){
        ssm_notify_error(BAD_SIGNATURE, "consume_group_msg()");
        goto complete;
    }

    /* Advance the chain key */
    while (group_session->sequence < group_msg_payload->sequence){
        advance_group_chain_key(&(group_session->chain_key), group_session->sequence);
        group_session->sequence += 1;
    }

    /* Create the message key */
    keys = (Skissm__MessageKey *) malloc(sizeof(Skissm__MessageKey));
    skissm__message_key__init(keys);
    create_group_message_keys(&(group_session->chain_key), keys);

    /* Decryption */
    uint8_t *plaintext;
    size_t plaintext_len = CIPHER.suite1->decrypt(
        group_session->associated_data.data,
        keys->derived_key.data,
        group_msg_payload->ciphertext.data, group_msg_payload->ciphertext.len,
        &plaintext
    );

    if (plaintext_len == (size_t)(-1)){
        ssm_notify_error(BAD_MESSAGE_DECRYPTION, "consume_group_msg()");
    } else {
        ssm_notify_group_msg(group_msg->from, group_session->group_address, plaintext, plaintext_len);
        free_mem((void **)&plaintext, plaintext_len);
    }

complete:
    /* release */
    skissm__message_key__free_unpacked(keys, NULL);
    skissm__e2ee_group_msg_payload__free_unpacked(group_msg_payload, NULL);
    skissm__e2ee_group_session__free_unpacked(group_session, NULL);
}
