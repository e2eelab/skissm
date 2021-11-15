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
#include "group_session.h"
#include "group_session_manager.h"
#include "cipher.h"
#include "crypto.h"
#include "mem_util.h"
#include "session.h"

static const uint8_t CHAIN_KEY_SEED[1] = {0x02};
static const char MESSAGE_KEY_SEED[] = "MessageKeys";

static const struct cipher CIPHER = CIPHER_INIT;

static const size_t SHARED_KEY_LENGTH = SHA256_OUTPUT_LENGTH;
static const size_t MESSAGE_KEY_LENGTH = AES256_KEY_LENGTH + AES256_IV_LENGTH;

static void close_group_session(Org__E2eelab__Skissm__Proto__E2eeGroupSession *group_session){
    if (group_session != NULL){
        org__e2eelab__skissm__proto__e2ee_group_session__free_unpacked(group_session, NULL);
        group_session = NULL;
    }
}

static void advance_chain_key(
    ProtobufCBinaryData *chain_key, uint32_t iteration
) {
    uint8_t shared_key[SHARED_KEY_LENGTH];
    CIPHER.suit1->hmac(
        chain_key->data, chain_key->len,
        CHAIN_KEY_SEED, sizeof(CHAIN_KEY_SEED),
        shared_key
    );

    overwrite_protobuf_from_array(chain_key, shared_key);
}

static void create_message_keys(
    const ProtobufCBinaryData *chain_key,
    Org__E2eelab__Skissm__Proto__MessageKey *message_key
) {
    free_protobuf(&(message_key->derived_key));
    message_key->derived_key.data = (uint8_t *) malloc(sizeof(uint8_t) * MESSAGE_KEY_LENGTH);
    message_key->derived_key.len = MESSAGE_KEY_LENGTH;

    uint8_t salt[SHA256_OUTPUT_LENGTH] = {0};
    CIPHER.suit1->hkdf(
        chain_key->data, chain_key->len,
        salt, sizeof(salt),
        (uint8_t *)MESSAGE_KEY_SEED, sizeof(MESSAGE_KEY_SEED) - 1,
        message_key->derived_key.data, message_key->derived_key.len
    );
}

void create_outbound_group_session(
    Org__E2eelab__Skissm__Proto__E2eeAddress *user_address,
    Org__E2eelab__Skissm__Proto__E2eeAddress *group_address,
    Org__E2eelab__Skissm__Proto__E2eeAddress **member_addresses,
    size_t member_num,
    ProtobufCBinaryData *old_session_id
) {
    Org__E2eelab__Skissm__Proto__E2eeGroupSession *group_session = (Org__E2eelab__Skissm__Proto__E2eeGroupSession *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeGroupSession));
    org__e2eelab__skissm__proto__e2ee_group_session__init(group_session);

    group_session->version = PROTOCOL_VERSION;

    copy_address_from_address(&(group_session->session_owner), user_address);

    copy_address_from_address(&(group_session->group_address), group_address);

    CIPHER.suit1->gen_private_key(&(group_session->session_id), 32);

    group_session->n_member_addresses = member_num;

    copy_member_addresses_from_member_addresses(&(group_session->member_addresses), (const Org__E2eelab__Skissm__Proto__E2eeAddress **)member_addresses, member_num);

    group_session->sequence = 0;

    CIPHER.suit1->gen_private_key(&(group_session->chain_key), SHARED_KEY_LENGTH);

    CIPHER.suit1->gen_private_key(&(group_session->signature_private_key), CURVE25519_KEY_LENGTH);

    CIPHER.suit1->gen_public_key(&(group_session->signature_public_key), &(group_session->signature_private_key));

    group_session->associated_data.len = AD_LENGTH;
    group_session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * AD_LENGTH);
    memcpy(group_session->associated_data.data, group_session->signature_public_key.data, CURVE25519_KEY_LENGTH);
    memcpy((group_session->associated_data.data) + CURVE25519_KEY_LENGTH, group_session->signature_public_key.data, CURVE25519_KEY_LENGTH);

    get_ssm_plugin()->store_group_session(group_session);

    /* pack the group pre-key message */
    Org__E2eelab__Skissm__Proto__E2eeGroupPreKeyPayload *group_pre_key_payload = (Org__E2eelab__Skissm__Proto__E2eeGroupPreKeyPayload *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeGroupPreKeyPayload));
    org__e2eelab__skissm__proto__e2ee_group_pre_key_payload__init(group_pre_key_payload);

    group_pre_key_payload->version = GROUP_VERSION;

    copy_protobuf_from_protobuf(&(group_pre_key_payload->session_id), &(group_session->session_id));

    if (old_session_id != NULL) {
        copy_protobuf_from_protobuf(&(group_pre_key_payload->old_session_id), old_session_id);
    }

    copy_address_from_address(&(group_pre_key_payload->group_address), group_address);

    group_pre_key_payload->n_member_addresses = member_num;
    copy_member_addresses_from_member_addresses(&(group_pre_key_payload->member_addresses), (const Org__E2eelab__Skissm__Proto__E2eeAddress **)group_session->member_addresses, member_num);

    group_pre_key_payload->sequence = group_session->sequence;
    copy_protobuf_from_protobuf(&(group_pre_key_payload->chain_key), &(group_session->chain_key));
    copy_protobuf_from_protobuf(&(group_pre_key_payload->signature_public_key), &(group_session->signature_public_key));

    size_t plaintext_len = org__e2eelab__skissm__proto__e2ee_group_pre_key_payload__get_packed_size(group_pre_key_payload);
    uint8_t *plaintext = (uint8_t *) malloc(sizeof(uint8_t) * plaintext_len);
    org__e2eelab__skissm__proto__e2ee_group_pre_key_payload__pack(group_pre_key_payload, plaintext);

    /* pack the e2ee_plaintext */
    uint8_t *context = NULL;
    size_t context_len;
    pack_e2ee_plaintext(
        plaintext, plaintext_len,
        ORG__E2EELAB__SKISSM__PROTO__E2EE_PLAINTEXT_TYPE__GROUP_PRE_KEY,
        &context, &context_len
    );

    /* send the group pre-key message to the members in the group */
    size_t i;
    for (i = 0; i < group_session->n_member_addresses; i++){
        if (compare_address(group_session->session_owner, group_session->member_addresses[i]) == false){
            encrypt_session(group_session->session_owner, group_session->member_addresses[i], context, context_len);
        }
    }

    /* release */
    org__e2eelab__skissm__proto__e2ee_group_session__free_unpacked(group_session, NULL);
    org__e2eelab__skissm__proto__e2ee_group_pre_key_payload__free_unpacked(group_pre_key_payload, NULL);
    free_mem((void **)&plaintext, plaintext_len);
}

void create_inbound_group_session(
    Org__E2eelab__Skissm__Proto__E2eeGroupPreKeyPayload *group_pre_key_payload,
    Org__E2eelab__Skissm__Proto__E2eeAddress *user_address
) {
    Org__E2eelab__Skissm__Proto__E2eeGroupSession *group_session = (Org__E2eelab__Skissm__Proto__E2eeGroupSession *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeGroupSession));
    org__e2eelab__skissm__proto__e2ee_group_session__init(group_session);

    group_session->version = group_pre_key_payload->version;
    copy_address_from_address(&(group_session->session_owner), user_address);
    copy_protobuf_from_protobuf(&(group_session->session_id), &(group_pre_key_payload->session_id));

    copy_address_from_address(&(group_session->group_address), group_pre_key_payload->group_address);
    group_session->n_member_addresses = group_pre_key_payload->n_member_addresses;
    copy_member_addresses_from_member_addresses(&(group_session->member_addresses), (const Org__E2eelab__Skissm__Proto__E2eeAddress **)group_pre_key_payload->member_addresses, group_pre_key_payload->n_member_addresses);

    group_session->sequence = group_pre_key_payload->sequence;
    copy_protobuf_from_protobuf(&(group_session->chain_key), &(group_pre_key_payload->chain_key));
    copy_protobuf_from_protobuf(&(group_session->signature_public_key), &(group_pre_key_payload->signature_public_key));

    group_session->associated_data.len = AD_LENGTH;
    group_session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * AD_LENGTH);
    memcpy(group_session->associated_data.data, group_session->signature_public_key.data, CURVE25519_KEY_LENGTH);
    memcpy((group_session->associated_data.data) + CURVE25519_KEY_LENGTH, group_session->signature_public_key.data, CURVE25519_KEY_LENGTH);

    get_ssm_plugin()->store_group_session(group_session);

    /* release */
    org__e2eelab__skissm__proto__e2ee_group_session__free_unpacked(group_session, NULL);
}

void perform_encrypt_group_session(
    Org__E2eelab__Skissm__Proto__E2eeGroupSession *group_session,
    const uint8_t *plaintext, size_t plaintext_len
) {
    /* Create the message key */
    Org__E2eelab__Skissm__Proto__MessageKey *keys = (Org__E2eelab__Skissm__Proto__MessageKey *) malloc(sizeof(Org__E2eelab__Skissm__Proto__MessageKey));
    org__e2eelab__skissm__proto__message_key__init(keys);
    create_message_keys(&(group_session->chain_key), keys);

    /* Prepare an e2ee message */
    Org__E2eelab__Skissm__Proto__E2eeMessage *group_message = (Org__E2eelab__Skissm__Proto__E2eeMessage *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeMessage));
    org__e2eelab__skissm__proto__e2ee_message__init(group_message);
    group_message->msg_type = ORG__E2EELAB__SKISSM__PROTO__E2EE_MESSAGE_TYPE__GROUP_MESSAGE;
    group_message->version = group_session->version;
    copy_protobuf_from_protobuf(&(group_message->session_id), &(group_session->session_id));
    copy_address_from_address(&(group_message->from), group_session->session_owner);
    copy_address_from_address(&(group_message->to), group_session->group_address);

    /* Prepare a group message */
    Org__E2eelab__Skissm__Proto__E2eeGroupMsgPayload *group_msg_payload = (Org__E2eelab__Skissm__Proto__E2eeGroupMsgPayload *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeGroupMsgPayload));
    org__e2eelab__skissm__proto__e2ee_group_msg_payload__init(group_msg_payload);
    group_msg_payload->sequence = group_session->sequence;
    uint8_t *ad = group_session->associated_data.data;
    /* Encryption */
    group_msg_payload->ciphertext.len = CIPHER.suit1->encrypt(
        ad,
        keys->derived_key.data,
        plaintext,
        plaintext_len,
        &(group_msg_payload->ciphertext.data)
    );
    /* Signature */
    group_msg_payload->signature.len = CURVE_SIGNATURE_LENGTH;
    group_msg_payload->signature.data = (uint8_t *) malloc(sizeof(uint8_t) * CURVE_SIGNATURE_LENGTH);
    CIPHER.suit1->sign(
        group_session->signature_private_key.data,
        group_msg_payload->ciphertext.data,
        group_msg_payload->ciphertext.len,
        group_msg_payload->signature.data
    );

    /* Pack the group message into the e2ee message */
    group_message->payload.len = org__e2eelab__skissm__proto__e2ee_group_msg_payload__get_packed_size(group_msg_payload);
    group_message->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * group_message->payload.len);
    org__e2eelab__skissm__proto__e2ee_group_msg_payload__pack(group_msg_payload, group_message->payload.data);

    /* Prepare the e2ee protocol message */
    Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *protocol_msg = (Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeProtocolMsg));
    org__e2eelab__skissm__proto__e2ee_protocol_msg__init(protocol_msg);
    protocol_msg->cmd = ORG__E2EELAB__SKISSM__PROTO__E2EE_COMMANDS__send_group_msg_request;

    /* Pack the e2ee message into the e2ee protocol message */
    protocol_msg->payload.len = org__e2eelab__skissm__proto__e2ee_message__get_packed_size(group_message);
    protocol_msg->payload.data = (uint8_t *) malloc(protocol_msg->payload.len);
    org__e2eelab__skissm__proto__e2ee_message__pack(group_message, protocol_msg->payload.data);

    /* Pack the e2ee protocol message */
    size_t message_len = org__e2eelab__skissm__proto__e2ee_protocol_msg__get_packed_size(protocol_msg);
    uint8_t *message = (uint8_t *) malloc(sizeof(uint8_t) * message_len);
    org__e2eelab__skissm__proto__e2ee_protocol_msg__pack(protocol_msg, message);

    /* send message to server */
    get_ssm_plugin()->handle_send(message, message_len);

    /* Prepare a new chain key for next encryption */
    advance_chain_key(&(group_session->chain_key), group_session->sequence);
    group_session->sequence += 1;

    /* store sesson state */
    get_ssm_plugin()->store_group_session(group_session);

    /* release */
    org__e2eelab__skissm__proto__message_key__free_unpacked(keys, NULL);
    org__e2eelab__skissm__proto__e2ee_message__free_unpacked(group_message, NULL);
    org__e2eelab__skissm__proto__e2ee_group_msg_payload__free_unpacked(group_msg_payload, NULL);
    org__e2eelab__skissm__proto__e2ee_protocol_msg__free_unpacked(protocol_msg, NULL);
}

void encrypt_group_session(
    Org__E2eelab__Skissm__Proto__E2eeAddress *sender_address,
    Org__E2eelab__Skissm__Proto__E2eeAddress *group_address,
    const uint8_t *plaintext, size_t plaintext_len
) {
    /* Load the outbound group session */
    Org__E2eelab__Skissm__Proto__E2eeGroupSession *group_session = NULL;
    get_ssm_plugin()->load_outbound_group_session(sender_address, group_address, &group_session);

    /* Do the encryption */
    perform_encrypt_group_session(group_session, plaintext, plaintext_len);

    /* Release the group session */
    close_group_session(group_session);
}

void decrypt_group_session(
    Org__E2eelab__Skissm__Proto__E2eeAddress *user_address,
    Org__E2eelab__Skissm__Proto__E2eeMessage *group_msg
) {
    /* Load the inbound group session */
    Org__E2eelab__Skissm__Proto__E2eeGroupSession *group_session = NULL;
    get_ssm_plugin()->load_inbound_group_session(group_msg->session_id, user_address, &group_session);

    if (group_session == NULL){
        ssm_notify_error(BAD_MESSAGE_FORMAT, "decrypt_group_session()");
        return;
    }

    Org__E2eelab__Skissm__Proto__E2eeGroupMsgPayload *group_msg_payload = NULL;
    Org__E2eelab__Skissm__Proto__MessageKey *keys = NULL;

    /* Unpack the e2ee message */
    group_msg_payload = org__e2eelab__skissm__proto__e2ee_group_msg_payload__unpack(NULL, group_msg->payload.len, group_msg->payload.data);

    /* Verify the signature */
    size_t result = CIPHER.suit1->verify(
        group_msg_payload->signature.data,
        group_session->signature_public_key.data,
        group_msg_payload->ciphertext.data, group_msg_payload->ciphertext.len);
    if (result < 0){
        ssm_notify_error(BAD_SIGNATURE, "decrypt_group_session()");
        goto complete;
    }

    /* Advance the chain key */
    while (group_session->sequence < group_msg_payload->sequence){
        advance_chain_key(&(group_session->chain_key), group_session->sequence);
        group_session->sequence += 1;
    }

    /* Create the message key */
    keys = (Org__E2eelab__Skissm__Proto__MessageKey *) malloc(sizeof(Org__E2eelab__Skissm__Proto__MessageKey));
    org__e2eelab__skissm__proto__message_key__init(keys);
    create_message_keys(&(group_session->chain_key), keys);

    /* Decryption */
    uint8_t *plaintext;
    size_t plaintext_len = CIPHER.suit1->decrypt(
        group_session->associated_data.data,
        keys->derived_key.data,
        group_msg_payload->ciphertext.data, group_msg_payload->ciphertext.len,
        &plaintext
    );

    if (plaintext_len == (size_t)(-1)){
        ssm_notify_error(BAD_MESSAGE_DECRYPTION, "decrypt_group_session()");
    } else {
        ssm_notify_group_msg(group_msg->from, group_session->group_address, plaintext, plaintext_len);
        free_mem((void **)&plaintext, plaintext_len);
    }

complete:
    /* release */
    org__e2eelab__skissm__proto__message_key__free_unpacked(keys, NULL);
    org__e2eelab__skissm__proto__e2ee_group_msg_payload__free_unpacked(group_msg_payload, NULL);
    org__e2eelab__skissm__proto__e2ee_group_session__free_unpacked(group_session, NULL);
}
