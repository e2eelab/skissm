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
#include "skissm/e2ee_client.h"
#include "skissm/e2ee_client_internal.h"
#include "skissm/group_session_manager.h"
#include "skissm/mem_util.h"
#include "skissm/session.h"
#include "skissm/session_manager.h"

static const uint8_t CHAIN_KEY_SEED[1] = {0x02};
static const char MESSAGE_KEY_SEED[] = "MessageKeys";

void advance_group_chain_key(const cipher_suite_t *cipher_suite, ProtobufCBinaryData *chain_key, uint32_t iteration) {
    int group_shared_key_len = cipher_suite->get_crypto_param().hash_len;
    uint8_t shared_key[group_shared_key_len];
    cipher_suite->hmac(
        chain_key->data, chain_key->len,
        CHAIN_KEY_SEED, sizeof(CHAIN_KEY_SEED),
        shared_key
    );

    overwrite_protobuf_from_array(chain_key, shared_key);
}

void create_group_message_key(
    const cipher_suite_t *cipher_suite,
    const ProtobufCBinaryData *chain_key,
    Skissm__MsgKey *msg_key
) {
    int group_msg_key_len = cipher_suite->get_crypto_param().aead_key_len + cipher_suite->get_crypto_param().aead_iv_len;

    free_protobuf(&(msg_key->derived_key));
    msg_key->derived_key.data = (uint8_t *) malloc(sizeof(uint8_t) * group_msg_key_len);
    msg_key->derived_key.len = group_msg_key_len;

    int hash_len = cipher_suite->get_crypto_param().hash_len;
    uint8_t salt[hash_len];
    memset(salt, 0, hash_len);
    cipher_suite->hkdf(
        chain_key->data, chain_key->len,
        salt, sizeof(salt),
        (uint8_t *)MESSAGE_KEY_SEED, sizeof(MESSAGE_KEY_SEED) - 1,
        msg_key->derived_key.data, msg_key->derived_key.len
    );
}

static void pack_group_pre_key(Skissm__GroupPreKeyPayload *group_pre_key_payload, uint8_t **group_pre_key_plaintext_data, size_t *group_pre_key_plaintext_data_len) {
    Skissm__Plaintext *plaintext = (Skissm__Plaintext *)malloc(sizeof(Skissm__Plaintext));
    skissm__plaintext__init(plaintext);
    plaintext->version = strdup(E2EE_PLAINTEXT_VERSION);
    plaintext->payload_case = SKISSM__PLAINTEXT__PAYLOAD_GROUP_PRE_KEY;
    plaintext->group_pre_key = group_pre_key_payload;

    size_t len = skissm__plaintext__get_packed_size(plaintext);
    *group_pre_key_plaintext_data_len = len;
    *group_pre_key_plaintext_data = (uint8_t *)malloc(sizeof(uint8_t) * len);
    skissm__plaintext__pack(plaintext, *group_pre_key_plaintext_data);

    // release
    // group_pre_key_payload will also be released
    skissm__plaintext__free_unpacked(plaintext, NULL);
}

static size_t pack_group_pre_key_plaintext(
    Skissm__GroupSession *outbound_group_session,
    uint8_t **group_pre_key_plaintext_data,
    char *old_session_id
) {
    Skissm__GroupPreKeyPayload *group_pre_key_payload = (Skissm__GroupPreKeyPayload *) malloc(sizeof(Skissm__GroupPreKeyPayload));
    skissm__group_pre_key_payload__init(group_pre_key_payload);

    group_pre_key_payload->version = strdup(E2EE_GROUP_PRE_KEY_VERSION);

    group_pre_key_payload->session_id = strdup(outbound_group_session->session_id);

    if (old_session_id != NULL) {
        group_pre_key_payload->old_session_id = strdup(old_session_id);
    }

    copy_address_from_address(&(group_pre_key_payload->group_address), outbound_group_session->group_address);

    group_pre_key_payload->n_group_members = outbound_group_session->n_group_members;
    copy_group_members(&(group_pre_key_payload->group_members), outbound_group_session->group_members, outbound_group_session->n_group_members);

    group_pre_key_payload->sequence = outbound_group_session->sequence;
    copy_protobuf_from_protobuf(&(group_pre_key_payload->chain_key), &(outbound_group_session->chain_key));
    copy_protobuf_from_protobuf(&(group_pre_key_payload->signature_public_key), &(outbound_group_session->signature_public_key));

    // pack the e2ee_plaintext
    size_t group_pre_key_plaintext_data_len;
    pack_group_pre_key(
        group_pre_key_payload,
        group_pre_key_plaintext_data, &group_pre_key_plaintext_data_len
    );

    // release
    // group_pre_key_payload is released in pack_group_pre_key()

    // done
    return group_pre_key_plaintext_data_len;
}

void create_outbound_group_session(
    const char *e2ee_pack_id,
    Skissm__E2eeAddress *user_address,
    Skissm__E2eeAddress *group_address,
    Skissm__GroupMember **group_members,
    size_t group_members_num,
    char *session_id
) {
    const cipher_suite_t *cipher_suite = get_e2ee_pack(e2ee_pack_id)->cipher_suite;
    int key_len = cipher_suite->get_crypto_param().sign_key_len;

    Skissm__GroupSession *outbound_group_session = (Skissm__GroupSession *) malloc(sizeof(Skissm__GroupSession));
    skissm__group_session__init(outbound_group_session);

    outbound_group_session->version = strdup(E2EE_PROTOCOL_VERSION);
    outbound_group_session->e2ee_pack_id = strdup(e2ee_pack_id);

    copy_address_from_address(&(outbound_group_session->session_owner), user_address);
    copy_address_from_address(&(outbound_group_session->group_address), group_address);

    outbound_group_session->session_id = generate_uuid_str();
    outbound_group_session->n_group_members = group_members_num;
    copy_group_members(&(outbound_group_session->group_members), group_members, group_members_num);

    outbound_group_session->sequence = 0;

    outbound_group_session->chain_key.len = cipher_suite->get_crypto_param().hash_len;
    outbound_group_session->chain_key.data = (uint8_t *) malloc(sizeof(uint8_t) * outbound_group_session->chain_key.len);
    get_skissm_plugin()->common_handler.handle_gen_rand(outbound_group_session->chain_key.data, outbound_group_session->chain_key.len);

    cipher_suite->sign_key_gen(&(outbound_group_session->signature_public_key), &(outbound_group_session->signature_private_key));

    int ad_len = 2 * key_len;
    outbound_group_session->associated_data.len = ad_len;
    outbound_group_session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * ad_len);
    memcpy(outbound_group_session->associated_data.data, outbound_group_session->signature_public_key.data, key_len);
    memcpy((outbound_group_session->associated_data.data) + key_len, outbound_group_session->signature_public_key.data, key_len);

    get_skissm_plugin()->db_handler.store_group_session(outbound_group_session);

    uint8_t *group_pre_key_plaintext_data = NULL;
    size_t group_pre_key_plaintext_data_len = pack_group_pre_key_plaintext(outbound_group_session, &group_pre_key_plaintext_data, session_id);

    /* send the group pre-key message to the members in the group */
    unsigned i, j;
    for (i = 0; i < outbound_group_session->n_group_members; i++){
        if (!safe_strcmp(outbound_group_session->session_owner->user->user_id, outbound_group_session->group_members[i]->user_id)) {
            Skissm__E2eeAddress *group_member_address = (Skissm__E2eeAddress *)malloc(sizeof(Skissm__E2eeAddress));
            skissm__e2ee_address__init(group_member_address);
            Skissm__PeerUser *peer_user = (Skissm__PeerUser *)malloc(sizeof(Skissm__PeerUser));
            skissm__peer_user__init(peer_user);
            peer_user->user_id = strdup(outbound_group_session->group_members[i]->user_id);
            group_member_address->peer_case = SKISSM__E2EE_ADDRESS__PEER_USER;
            group_member_address->user = peer_user;
            Skissm__Session **outbound_sessions = NULL;
            size_t outbound_sessions_num = get_skissm_plugin()->db_handler.load_outbound_sessions(outbound_group_session->session_owner, group_member_address->user->user_id, &outbound_sessions);

            if (outbound_sessions_num > (size_t)(0) && outbound_sessions != NULL) {
                for(j = 0; j < outbound_sessions_num; j++) {
                    Skissm__Session *outbound_session = outbound_sessions[i];
                    if (outbound_session != NULL) {
                        send_one2one_msg_internal(outbound_session, group_pre_key_plaintext_data, group_pre_key_plaintext_data_len);
                    } else{
                        get_skissm_plugin()->db_handler.store_group_pre_key(group_member_address, group_pre_key_plaintext_data, group_pre_key_plaintext_data_len);
                        // send Invite
                        Skissm__InviteResponse *response = invite(outbound_group_session->session_owner, group_member_address);
                        // release
                        if (response != NULL)
                            skissm__invite_response__free_unpacked(response, NULL);
                        else {
                            // what if response error?
                        }
                    }
                    // release outbound_session
                    skissm__session__free_unpacked(outbound_session, NULL);
                }
                // release outbound_sessions
                free_mem((void **)(&outbound_sessions), sizeof(Skissm__Session *) * outbound_sessions_num);
            }

            // release
            skissm__e2ee_address__free_unpacked(group_member_address, NULL);
        }
    }

    /* release */
    skissm__group_session__free_unpacked(outbound_group_session, NULL);
}

void create_inbound_group_session(
    const char *e2ee_pack_id,
    Skissm__GroupPreKeyPayload *group_pre_key_payload,
    Skissm__E2eeAddress *user_address
) {
    Skissm__GroupSession *inbound_group_session = (Skissm__GroupSession *) malloc(sizeof(Skissm__GroupSession));
    skissm__group_session__init(inbound_group_session);

    inbound_group_session->version = strdup(group_pre_key_payload->version);
    inbound_group_session->e2ee_pack_id = strdup(e2ee_pack_id);
    copy_address_from_address(&(inbound_group_session->session_owner), user_address);
    inbound_group_session->session_id = strdup(group_pre_key_payload->session_id);

    copy_address_from_address(&(inbound_group_session->group_address), group_pre_key_payload->group_address);
    inbound_group_session->n_group_members = group_pre_key_payload->n_group_members;
    copy_group_members(&(inbound_group_session->group_members), group_pre_key_payload->group_members, group_pre_key_payload->n_group_members);

    inbound_group_session->sequence = group_pre_key_payload->sequence;
    copy_protobuf_from_protobuf(&(inbound_group_session->chain_key), &(group_pre_key_payload->chain_key));
    copy_protobuf_from_protobuf(&(inbound_group_session->signature_public_key), &(group_pre_key_payload->signature_public_key));

    const cipher_suite_t *cipher_suite = get_e2ee_pack(e2ee_pack_id)->cipher_suite;
    int key_len = cipher_suite->get_crypto_param().asym_key_len;
    int ad_len = 2 * key_len;
    inbound_group_session->associated_data.len = ad_len;
    inbound_group_session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * ad_len);
    memcpy(inbound_group_session->associated_data.data, inbound_group_session->signature_public_key.data, key_len);
    memcpy((inbound_group_session->associated_data.data) + key_len, inbound_group_session->signature_public_key.data, key_len);

    get_skissm_plugin()->db_handler.store_group_session(inbound_group_session);

    /* release */
    skissm__group_session__free_unpacked(inbound_group_session, NULL);
}
