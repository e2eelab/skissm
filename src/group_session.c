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
#include "skissm/group_session.h"

#include <string.h>

#include "skissm/cipher.h"
#include "skissm/group_session_manager.h"
#include "skissm/mem_util.h"
#include "skissm/session.h"
#include "skissm/session_manager.h"

/** length of a shared key */
#define GROUP_SHARED_KEY_LENGTH     CIPHER.suite1->get_crypto_param().hash_len

/** length of a message key */
#define GROUP_MESSAGE_KEY_LENGTH    (CIPHER.suite1->get_crypto_param().aead_key_len + CIPHER.suite1->get_crypto_param().aead_iv_len)

static const uint8_t CHAIN_KEY_SEED[1] = {0x02};
static const char MESSAGE_KEY_SEED[] = "MessageKeys";

void close_group_session(Skissm__E2eeGroupSession *group_session) {
    if (group_session != NULL){
        skissm__e2ee_group_session__free_unpacked(group_session, NULL);
        group_session = NULL;
    }
}

void advance_group_chain_key(ProtobufCBinaryData *chain_key, uint32_t iteration) {
    uint8_t shared_key[GROUP_SHARED_KEY_LENGTH];
    CIPHER.suite1->hmac(
        chain_key->data, chain_key->len,
        CHAIN_KEY_SEED, sizeof(CHAIN_KEY_SEED),
        shared_key
    );

    overwrite_protobuf_from_array(chain_key, shared_key);
}

void create_group_message_keys(
    const ProtobufCBinaryData *chain_key,
    Skissm__MessageKey *message_key
) {
    free_protobuf(&(message_key->derived_key));
    message_key->derived_key.data = (uint8_t *) malloc(sizeof(uint8_t) * GROUP_MESSAGE_KEY_LENGTH);
    message_key->derived_key.len = GROUP_MESSAGE_KEY_LENGTH;

    int hash_len = CIPHER.suite1->get_crypto_param().hash_len;
    uint8_t salt[hash_len];
    memset(salt, 0, hash_len);
    CIPHER.suite1->hkdf(
        chain_key->data, chain_key->len,
        salt, sizeof(salt),
        (uint8_t *)MESSAGE_KEY_SEED, sizeof(MESSAGE_KEY_SEED) - 1,
        message_key->derived_key.data, message_key->derived_key.len
    );
}

void create_outbound_group_session(
    Skissm__E2eeAddress *user_address,
    Skissm__E2eeAddress *group_address,
    Skissm__E2eeAddress **member_addresses,
    size_t member_num,
    ProtobufCBinaryData *old_session_id
) {
    int key_len = CIPHER.suite1->get_crypto_param().key_len;

    Skissm__E2eeGroupSession *group_session = (Skissm__E2eeGroupSession *) malloc(sizeof(Skissm__E2eeGroupSession));
    skissm__e2ee_group_session__init(group_session);

    group_session->version = PROTOCOL_VERSION;

    copy_address_from_address(&(group_session->session_owner), user_address);

    copy_address_from_address(&(group_session->group_address), group_address);

    group_session->session_id.len = 32;
    group_session->session_id.data = (uint8_t *) malloc(sizeof(uint8_t) * group_session->session_id.len);
    get_ssm_plugin()->handle_rg(group_session->session_id.data, group_session->session_id.len);

    group_session->n_member_addresses = member_num;

    copy_member_addresses_from_member_addresses(&(group_session->member_addresses), (const Skissm__E2eeAddress **)member_addresses, member_num);

    group_session->sequence = 0;

    group_session->chain_key.len = GROUP_SHARED_KEY_LENGTH;
    group_session->chain_key.data = (uint8_t *) malloc(sizeof(uint8_t) * group_session->chain_key.len);
    get_ssm_plugin()->handle_rg(group_session->chain_key.data, group_session->chain_key.len);

    CIPHER.suite1->mt_key_gen(&(group_session->signature_public_key), &(group_session->signature_private_key));

    int ad_len = CIPHER.suite1->get_crypto_param().aead_ad_len;
    group_session->associated_data.len = ad_len;
    group_session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * ad_len);
    memcpy(group_session->associated_data.data, group_session->signature_public_key.data, key_len);
    memcpy((group_session->associated_data.data) + key_len, group_session->signature_public_key.data, key_len);

    get_ssm_plugin()->store_group_session(group_session);

    /* pack the group pre-key message */
    Skissm__E2eeGroupPreKeyPayload *group_pre_key_payload = (Skissm__E2eeGroupPreKeyPayload *) malloc(sizeof(Skissm__E2eeGroupPreKeyPayload));
    skissm__e2ee_group_pre_key_payload__init(group_pre_key_payload);

    group_pre_key_payload->version = GROUP_VERSION;

    copy_protobuf_from_protobuf(&(group_pre_key_payload->session_id), &(group_session->session_id));

    if (old_session_id != NULL) {
        copy_protobuf_from_protobuf(&(group_pre_key_payload->old_session_id), old_session_id);
    }

    copy_address_from_address(&(group_pre_key_payload->group_address), group_address);

    group_pre_key_payload->n_member_addresses = member_num;
    copy_member_addresses_from_member_addresses(&(group_pre_key_payload->member_addresses), (const Skissm__E2eeAddress **)group_session->member_addresses, member_num);

    group_pre_key_payload->sequence = group_session->sequence;
    copy_protobuf_from_protobuf(&(group_pre_key_payload->chain_key), &(group_session->chain_key));
    copy_protobuf_from_protobuf(&(group_pre_key_payload->signature_public_key), &(group_session->signature_public_key));

    size_t plaintext_len = skissm__e2ee_group_pre_key_payload__get_packed_size(group_pre_key_payload);
    uint8_t *plaintext = (uint8_t *) malloc(sizeof(uint8_t) * plaintext_len);
    skissm__e2ee_group_pre_key_payload__pack(group_pre_key_payload, plaintext);

    /* pack the e2ee_plaintext */
    uint8_t *context = NULL;
    size_t context_len;
    pack_e2ee_plaintext(
        (const uint8_t *)plaintext, plaintext_len,
        SKISSM__E2EE_PLAINTEXT_TYPE__GROUP_PRE_KEY,
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
    skissm__e2ee_group_session__free_unpacked(group_session, NULL);
    skissm__e2ee_group_pre_key_payload__free_unpacked(group_pre_key_payload, NULL);
    free_mem((void **)&plaintext, plaintext_len);
}

void create_inbound_group_session(
    Skissm__E2eeGroupPreKeyPayload *group_pre_key_payload,
    Skissm__E2eeAddress *user_address
) {
    Skissm__E2eeGroupSession *group_session = (Skissm__E2eeGroupSession *) malloc(sizeof(Skissm__E2eeGroupSession));
    skissm__e2ee_group_session__init(group_session);

    group_session->version = group_pre_key_payload->version;
    copy_address_from_address(&(group_session->session_owner), user_address);
    copy_protobuf_from_protobuf(&(group_session->session_id), &(group_pre_key_payload->session_id));

    copy_address_from_address(&(group_session->group_address), group_pre_key_payload->group_address);
    group_session->n_member_addresses = group_pre_key_payload->n_member_addresses;
    copy_member_addresses_from_member_addresses(&(group_session->member_addresses), (const Skissm__E2eeAddress **)group_pre_key_payload->member_addresses, group_pre_key_payload->n_member_addresses);

    group_session->sequence = group_pre_key_payload->sequence;
    copy_protobuf_from_protobuf(&(group_session->chain_key), &(group_pre_key_payload->chain_key));
    copy_protobuf_from_protobuf(&(group_session->signature_public_key), &(group_pre_key_payload->signature_public_key));

    int ad_len = CIPHER.suite1->get_crypto_param().aead_ad_len;
    group_session->associated_data.len = ad_len;
    group_session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * ad_len);
    int key_len = CIPHER.suite1->get_crypto_param().key_len;
    memcpy(group_session->associated_data.data, group_session->signature_public_key.data, key_len);
    memcpy((group_session->associated_data.data) + key_len, group_session->signature_public_key.data, key_len);

    get_ssm_plugin()->store_group_session(group_session);

    /* release */
    skissm__e2ee_group_session__free_unpacked(group_session, NULL);
}
