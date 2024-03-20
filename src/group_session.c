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

#define SEED_SECRET_LEN 32

static const char ROOT_SEED[] = "ROOT";
static const uint8_t CHAIN_KEY_SEED[1] = {0x02};
static const char MESSAGE_KEY_SEED[] = "MessageKeys";

void advance_group_chain_key(const cipher_suite_t *cipher_suite, ProtobufCBinaryData *chain_key) {
    int group_shared_key_len = cipher_suite->symmetric_encryption_suite->get_crypto_param().hash_len;
    uint8_t shared_key[group_shared_key_len];
    cipher_suite->symmetric_encryption_suite->hmac(
        chain_key->data, chain_key->len,
        CHAIN_KEY_SEED, sizeof(CHAIN_KEY_SEED),
        shared_key
    );

    overwrite_protobuf_from_array(chain_key, shared_key);
}

void advance_group_chain_key_by_welcome(
    const cipher_suite_t *cipher_suite, const ProtobufCBinaryData *src_chain_key, ProtobufCBinaryData **dest_chain_key
) {
    int hash_len = cipher_suite->symmetric_encryption_suite->get_crypto_param().hash_len;
    uint8_t salt[] = "welcome";

    *dest_chain_key = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));

    (*dest_chain_key)->len = hash_len;
    (*dest_chain_key)->data = (uint8_t *)malloc(sizeof(uint8_t) * hash_len);

    cipher_suite->symmetric_encryption_suite->hkdf(
        src_chain_key->data, src_chain_key->len,
        salt, sizeof(salt) - 1,
        CHAIN_KEY_SEED, sizeof(CHAIN_KEY_SEED),
        (*dest_chain_key)->data, (*dest_chain_key)->len
    );
}

void advance_group_chain_key_by_add(
    const cipher_suite_t *cipher_suite, const ProtobufCBinaryData *src_chain_key, ProtobufCBinaryData *dest_chain_key
) {
    int hash_len = cipher_suite->symmetric_encryption_suite->get_crypto_param().hash_len;
    uint8_t salt[] = "add";

    ProtobufCBinaryData *new_chain_key = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));

    new_chain_key->len = hash_len;
    new_chain_key->data = (uint8_t *)malloc(sizeof(uint8_t) * hash_len);

    cipher_suite->symmetric_encryption_suite->hkdf(
        src_chain_key->data, src_chain_key->len,
        salt, sizeof(salt) - 1,
        CHAIN_KEY_SEED, sizeof(CHAIN_KEY_SEED),
        new_chain_key->data, new_chain_key->len
    );

    overwrite_protobuf_from_array(dest_chain_key, new_chain_key->data);

    // release
    free_mem((void **)&(new_chain_key->data), sizeof(uint8_t) * hash_len);
    free_mem((void **)&new_chain_key, sizeof(ProtobufCBinaryData));
}

void create_group_message_key(
    const cipher_suite_t *cipher_suite,
    const ProtobufCBinaryData *chain_key,
    Skissm__MsgKey *msg_key
) {
    int group_msg_key_len = cipher_suite->symmetric_encryption_suite->get_crypto_param().aead_key_len + cipher_suite->symmetric_encryption_suite->get_crypto_param().aead_iv_len;

    free_protobuf(&(msg_key->derived_key));
    msg_key->derived_key.data = (uint8_t *) malloc(sizeof(uint8_t) * group_msg_key_len);
    msg_key->derived_key.len = group_msg_key_len;

    int hash_len = cipher_suite->symmetric_encryption_suite->get_crypto_param().hash_len;
    uint8_t salt[hash_len];
    memset(salt, 0, hash_len);
    cipher_suite->symmetric_encryption_suite->hkdf(
        chain_key->data, chain_key->len,
        salt, sizeof(salt),
        (uint8_t *)MESSAGE_KEY_SEED, sizeof(MESSAGE_KEY_SEED) - 1,
        msg_key->derived_key.data, msg_key->derived_key.len
    );
}

static void pack_group_pre_key(
    Skissm__GroupPreKeyBundle *group_pre_key_bundle,
    uint8_t **group_pre_key_plaintext_data,
    size_t *group_pre_key_plaintext_data_len
) {
    Skissm__Plaintext *plaintext = (Skissm__Plaintext *)malloc(sizeof(Skissm__Plaintext));
    skissm__plaintext__init(plaintext);
    plaintext->version = strdup(E2EE_PLAINTEXT_VERSION);
    plaintext->payload_case = SKISSM__PLAINTEXT__PAYLOAD_GROUP_PRE_KEY_BUNDLE;
    plaintext->group_pre_key_bundle = group_pre_key_bundle;

    size_t len = skissm__plaintext__get_packed_size(plaintext);
    *group_pre_key_plaintext_data_len = len;
    *group_pre_key_plaintext_data = (uint8_t *)malloc(sizeof(uint8_t) * len);
    skissm__plaintext__pack(plaintext, *group_pre_key_plaintext_data);

    // release
    // group_pre_key_bundle will also be released
    skissm__plaintext__free_unpacked(plaintext, NULL);
}

size_t pack_group_pre_key_plaintext(
    Skissm__GroupSession *outbound_group_session,
    uint8_t **group_pre_key_plaintext_data,
    char *old_session_id
) {
    Skissm__GroupPreKeyBundle *group_pre_key_bundle = (Skissm__GroupPreKeyBundle *) malloc(sizeof(Skissm__GroupPreKeyBundle));
    skissm__group_pre_key_bundle__init(group_pre_key_bundle);

    group_pre_key_bundle->version = strdup(outbound_group_session->version);

    group_pre_key_bundle->e2ee_pack_id = outbound_group_session->e2ee_pack_id;

    copy_address_from_address(&(group_pre_key_bundle->sender), outbound_group_session->sender);

    group_pre_key_bundle->session_id = strdup(outbound_group_session->session_id);

    if (old_session_id != NULL) {
        group_pre_key_bundle->old_session_id = strdup(old_session_id);
    }

    copy_group_info(&(group_pre_key_bundle->group_info), outbound_group_session->group_info);

    group_pre_key_bundle->sequence = outbound_group_session->sequence;
    copy_protobuf_from_protobuf(&(group_pre_key_bundle->group_seed), &(outbound_group_session->group_seed));

    // pack the group_pre_key_bundle
    size_t group_pre_key_plaintext_data_len;
    pack_group_pre_key(
        group_pre_key_bundle,
        group_pre_key_plaintext_data, &group_pre_key_plaintext_data_len
    );

    // release
    // group_pre_key_bundle is released in pack_group_pre_key()

    // done
    return group_pre_key_plaintext_data_len;
}

static void pack_group_ratchet_state(
    Skissm__GroupUpdateKeyBundle *group_update_key_bundle,
    uint8_t **group_ratchet_state_plaintext_data,
    size_t *group_ratchet_state_plaintext_data_len
) {
    Skissm__Plaintext *plaintext = (Skissm__Plaintext *)malloc(sizeof(Skissm__Plaintext));
    skissm__plaintext__init(plaintext);
    plaintext->version = strdup(E2EE_PLAINTEXT_VERSION);
    plaintext->payload_case = SKISSM__PLAINTEXT__PAYLOAD_GROUP_UPDATE_KEY_BUNDLE;
    plaintext->group_update_key_bundle = group_update_key_bundle;

    size_t len = skissm__plaintext__get_packed_size(plaintext);
    *group_ratchet_state_plaintext_data_len = len;
    *group_ratchet_state_plaintext_data = (uint8_t *)malloc(sizeof(uint8_t) * len);
    skissm__plaintext__pack(plaintext, *group_ratchet_state_plaintext_data);

    // release
    // group_update_key_bundle will also be released
    skissm__plaintext__free_unpacked(plaintext, NULL);
}

size_t pack_group_ratchet_state_plaintext(
    Skissm__GroupSession *outbound_group_session,
    uint8_t **group_ratchet_state_plaintext_data,
    bool adding,
    ProtobufCBinaryData *identity_public_key,
    size_t n_adding_member_info_list,
    Skissm__GroupMemberInfo **adding_member_info_list
) {
    Skissm__GroupUpdateKeyBundle *group_update_key_bundle = (Skissm__GroupUpdateKeyBundle *)malloc(sizeof(Skissm__GroupUpdateKeyBundle));
    skissm__group_update_key_bundle__init(group_update_key_bundle);

    group_update_key_bundle->version = strdup(outbound_group_session->version);
    group_update_key_bundle->e2ee_pack_id = outbound_group_session->e2ee_pack_id;

    copy_address_from_address(&(group_update_key_bundle->sender), outbound_group_session->sender);

    group_update_key_bundle->adding = adding;

    group_update_key_bundle->session_id = strdup(outbound_group_session->session_id);

    copy_group_info(&(group_update_key_bundle->group_info), outbound_group_session->group_info);

    group_update_key_bundle->sequence = outbound_group_session->sequence;

    copy_protobuf_from_protobuf(&(group_update_key_bundle->chain_key), &(outbound_group_session->chain_key));

    copy_protobuf_from_protobuf(&(group_update_key_bundle->sign_public_key), identity_public_key);

    group_update_key_bundle->n_adding_member_info_list = n_adding_member_info_list;
    copy_group_member_ids(&(group_update_key_bundle->adding_member_info_list), adding_member_info_list, n_adding_member_info_list);

    // pack
    size_t group_ratchet_state_plaintext_data_len;
    pack_group_ratchet_state(
        group_update_key_bundle,
        group_ratchet_state_plaintext_data, &group_ratchet_state_plaintext_data_len
    );

    // release
    // group_update_key_bundle is released in pack_group_ratchet_state()

    // done
    return group_ratchet_state_plaintext_data_len;
}

static void insert_outbound_group_session_data(
    Skissm__GroupSession *outbound_group_session,
    uint32_t e2ee_pack_id,
    Skissm__E2eeAddress *user_address,
    const char *group_name,
    Skissm__E2eeAddress *group_address,
    const char *session_id,
    Skissm__GroupMember **group_member_list,
    size_t group_members_num,
    const uint8_t *identity_public_key
) {
    const cipher_suite_t *cipher_suite = get_e2ee_pack(e2ee_pack_id)->cipher_suite;
    int sign_key_len = cipher_suite->digital_signature_suite->get_crypto_param().sign_pub_key_len;

    outbound_group_session->version = strdup(E2EE_PROTOCOL_VERSION);
    outbound_group_session->e2ee_pack_id = e2ee_pack_id;

    copy_address_from_address(&(outbound_group_session->sender), user_address);
    copy_address_from_address(&(outbound_group_session->session_owner), user_address);
    if (session_id == NULL)
        outbound_group_session->session_id = generate_uuid_str();
    else
        outbound_group_session->session_id = strdup(session_id);

    outbound_group_session->group_info = (Skissm__GroupInfo *)malloc(sizeof(Skissm__GroupInfo));
    Skissm__GroupInfo *group_info = outbound_group_session->group_info;
    skissm__group_info__init(group_info);
    group_info->group_name = strdup(group_name);
    copy_address_from_address(&(group_info->group_address), group_address);
    group_info->n_group_member_list = group_members_num;
    copy_group_members(&(group_info->group_member_list), group_member_list, group_members_num);

    outbound_group_session->sequence = 0;

    // combine seed secret and ID
    size_t secret_len = SEED_SECRET_LEN + sign_key_len;
    uint8_t *secret = (uint8_t *) malloc(sizeof(uint8_t) * secret_len);
    memcpy(secret, outbound_group_session->group_seed.data, SEED_SECRET_LEN);
    memcpy(secret + SEED_SECRET_LEN, identity_public_key, sign_key_len);

    // generate a chain key
    int hash_len = cipher_suite->symmetric_encryption_suite->get_crypto_param().hash_len;
    uint8_t salt[hash_len];
    memset(salt, 0, hash_len);
    outbound_group_session->chain_key.len = hash_len;
    outbound_group_session->chain_key.data = (uint8_t *) malloc(sizeof(uint8_t) * outbound_group_session->chain_key.len);
    cipher_suite->symmetric_encryption_suite->hkdf(
        secret, secret_len,
        salt, sizeof(salt),
        (uint8_t *)ROOT_SEED, sizeof(ROOT_SEED) - 1,
        outbound_group_session->chain_key.data, outbound_group_session->chain_key.len
    );

    int ad_len = 2 * sign_key_len;
    outbound_group_session->associated_data.len = ad_len;
    outbound_group_session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * ad_len);
    memcpy(outbound_group_session->associated_data.data, identity_public_key, sign_key_len);
    memcpy((outbound_group_session->associated_data.data) + sign_key_len, identity_public_key, sign_key_len);

    // release
    free_mem((void **)&secret, sizeof(uint8_t) * secret_len);
}

static void insert_inbound_group_session_data(
    Skissm__GroupMemberInfo *group_member_id,
    Skissm__GroupSession *other_group_session,
    Skissm__GroupSession *inbound_group_session
) {
    inbound_group_session->e2ee_pack_id = other_group_session->e2ee_pack_id;
    copy_address_from_address(&(inbound_group_session->session_owner), other_group_session->session_owner);

    inbound_group_session->version = strdup(other_group_session->version);
    inbound_group_session->session_id = strdup(other_group_session->session_id);

    copy_address_from_address(&(inbound_group_session->sender), group_member_id->member_address);

    copy_group_info(&(inbound_group_session->group_info), other_group_session->group_info);
}

int new_outbound_group_session_by_sender(
    size_t n_member_info_list,
    Skissm__GroupMemberInfo **member_info_list,
    uint32_t e2ee_pack_id,
    Skissm__E2eeAddress *user_address,
    const char *group_name,
    Skissm__E2eeAddress *group_address,
    Skissm__GroupMember **group_member_list,
    size_t group_members_num,
    char *old_session_id
) {
    int ret = 0;

    Skissm__Account *account = NULL;
    uint8_t *identity_public_key = NULL;
    if (user_address == NULL) {
        ssm_notify_log(NULL, BAD_ACCOUNT, "new_outbound_group_session_by_sender()");
        ret = -1;
    } else {
        get_skissm_plugin()->db_handler.load_account_by_address(user_address, &account);
        if (account == NULL) {
            ssm_notify_log(user_address, BAD_ACCOUNT, "new_outbound_group_session_by_sender()");
            ret = -1;
        } else {
            identity_public_key = get_identity_public_key_ds_uint8_from_account(account);
            if (identity_public_key == NULL) {
                ssm_notify_log(user_address, BAD_ACCOUNT, "new_outbound_group_session_by_sender()");
                ret = -1;
            }
        }
    }

    if (n_member_info_list == 0) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_outbound_group_session_by_sender()");
        ret = -1;
    }
    if (member_info_list == NULL) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_outbound_group_session_by_sender()");
        ret = -1;
    }
    if (group_name == NULL) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_outbound_group_session_by_sender()");
        ret = -1;
    }
    if (group_address == NULL) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_outbound_group_session_by_sender()");
        ret = -1;
    }
    if (group_member_list == NULL) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_outbound_group_session_by_sender()");
        ret = -1;
    }
    if (group_members_num == 0) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_outbound_group_session_by_sender()");
        ret = -1;
    }

    if (ret == 0) {
        Skissm__GroupSession *outbound_group_session = (Skissm__GroupSession *) malloc(sizeof(Skissm__GroupSession));
        skissm__group_session__init(outbound_group_session);

        // the sender needs to generate a random seed secret
        outbound_group_session->group_seed.len = SEED_SECRET_LEN;
        outbound_group_session->group_seed.data = (uint8_t *) malloc(sizeof(uint8_t) * outbound_group_session->group_seed.len);
        get_skissm_plugin()->common_handler.gen_rand(outbound_group_session->group_seed.data, outbound_group_session->group_seed.len);

        insert_outbound_group_session_data(
            outbound_group_session, e2ee_pack_id,
            user_address, group_name, group_address, NULL,
            group_member_list, group_members_num, identity_public_key
        );

        // only the group creator needs to send the group pre-key bundle to others
        uint8_t *group_pre_key_plaintext_data = NULL;
        size_t group_pre_key_plaintext_data_len = pack_group_pre_key_plaintext(
            outbound_group_session, &group_pre_key_plaintext_data, old_session_id
        );

        // send the group pre-key message to the members in the group
        size_t i, j;
        char *cur_user_id, *cur_user_domain;
        for (i = 0; i < outbound_group_session->group_info->n_group_member_list; i++) {
            cur_user_id = outbound_group_session->group_info->group_member_list[i]->user_id;
            cur_user_domain = outbound_group_session->group_info->group_member_list[i]->domain;
            Skissm__Session **outbound_sessions = NULL;
            size_t outbound_sessions_num = get_skissm_plugin()->db_handler.load_outbound_sessions(
                outbound_group_session->session_owner, cur_user_id, cur_user_domain, &outbound_sessions
            );

            if (outbound_sessions_num > 0 && outbound_sessions != NULL) {
                for (j = 0; j < outbound_sessions_num; j++) {
                    Skissm__Session *outbound_session = outbound_sessions[j];
                    if (compare_address(outbound_session->their_address, outbound_group_session->session_owner))
                        continue;
                    if (outbound_session->responded) {
                        Skissm__SendOne2oneMsgResponse *response;
                        response = send_one2one_msg_internal(
                            outbound_session,
                            SKISSM__NOTIF_LEVEL__NOTIF_LEVEL_SESSION,
                            group_pre_key_plaintext_data, group_pre_key_plaintext_data_len
                        );
                        skissm__send_one2one_msg_response__free_unpacked(response, NULL);
                    } else {
                        /** Since the other has not responded, we store the group pre-key first so that
                         *  we can send it right after receiving the other's accept message.
                         */
                        store_pending_common_plaintext_data_internal(
                            outbound_session->our_address,
                            outbound_session->their_address,
                            group_pre_key_plaintext_data,
                            group_pre_key_plaintext_data_len,
                            SKISSM__NOTIF_LEVEL__NOTIF_LEVEL_SESSION
                        );
                    }
                    // release outbound_session
                    skissm__session__free_unpacked(outbound_session, NULL);
                }
                // release outbound_sessions
                free_mem((void **)&outbound_sessions, sizeof(Skissm__Session *) * outbound_sessions_num);
            } else {
                /** Since we haven't created any session, we need to create a session before sending the group pre-key. */
                Skissm__InviteResponse *invite_response = get_pre_key_bundle_internal(
                    outbound_group_session->session_owner,
                    account->auth,
                    cur_user_id, cur_user_domain,
                    NULL, true,
                    group_pre_key_plaintext_data, group_pre_key_plaintext_data_len
                );
                // release
                if (invite_response != NULL) {
                    skissm__invite_response__free_unpacked(invite_response, NULL);
                } else {
                    // nothing to do
                }
            }
        }

        // create the inbound group sessions
        for (i = 0; i < n_member_info_list; i++) {
            if (!compare_address(member_info_list[i]->member_address, user_address))
                new_and_complete_inbound_group_session(member_info_list[i], outbound_group_session);
        }

        // we do not store the seed secret in the session
        free_mem((void **)&(outbound_group_session->group_seed.data), sizeof(uint8_t) * outbound_group_session->group_seed.len);
        outbound_group_session->group_seed.len = 0;

        // store
        get_skissm_plugin()->db_handler.store_group_session(outbound_group_session);

        // release
        skissm__account__free_unpacked(account, NULL);
        skissm__group_session__free_unpacked(outbound_group_session, NULL);
        free_mem((void **)&group_pre_key_plaintext_data, sizeof(uint8_t) * group_pre_key_plaintext_data_len);
    }

    return ret;
}

int new_outbound_group_session_by_receiver(
    const ProtobufCBinaryData *group_seed,
    uint32_t e2ee_pack_id,
    Skissm__E2eeAddress *user_address,
    const char *group_name,
    Skissm__E2eeAddress *group_address,
    const char *session_id,
    Skissm__GroupMember **group_member_list,
    size_t group_members_num
) {
    int ret = 0;

    Skissm__Account *account = NULL;
    uint8_t *identity_public_key = NULL;
    if (user_address == NULL) {
        ssm_notify_log(NULL, BAD_ACCOUNT, "new_outbound_group_session_by_receiver()");
        ret = -1;
    } else {
        get_skissm_plugin()->db_handler.load_account_by_address(user_address, &account);
        if (account == NULL) {
            ssm_notify_log(NULL, BAD_ACCOUNT, "new_outbound_group_session_by_receiver()");
            ret = -1;
        } else {
            identity_public_key = get_identity_public_key_ds_uint8_from_account(account);
            if (identity_public_key == NULL) {
                ssm_notify_log(NULL, BAD_ACCOUNT, "new_outbound_group_session_by_receiver()");
                ret = -1;
            }
        }
    }

    if (group_seed->data == NULL) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_outbound_group_session_by_receiver()");
        ret = -1;
    }
    if (group_name == NULL) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_outbound_group_session_by_receiver()");
        ret = -1;
    }
    if (group_address == NULL) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_outbound_group_session_by_receiver()");
        ret = -1;
    }
    if (session_id == NULL) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_outbound_group_session_by_receiver()");
        ret = -1;
    }
    if (group_member_list == NULL) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_outbound_group_session_by_receiver()");
        ret = -1;
    }
    if (group_members_num == 0) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_outbound_group_session_by_receiver()");
        ret = -1;
    }

    if (ret == 0) {
        Skissm__GroupSession *outbound_group_session = (Skissm__GroupSession *) malloc(sizeof(Skissm__GroupSession));
        skissm__group_session__init(outbound_group_session);

        // the receiver gets the seed secret from the sender
        outbound_group_session->group_seed.len = group_seed->len;
        outbound_group_session->group_seed.data = (uint8_t *) malloc(sizeof(uint8_t) * outbound_group_session->group_seed.len);
        memcpy(outbound_group_session->group_seed.data, group_seed->data, group_seed->len);

        insert_outbound_group_session_data(
            outbound_group_session, e2ee_pack_id,
            user_address, group_name, group_address, session_id,
            group_member_list, group_members_num, identity_public_key
        );

        // we do not store the seed secret in the session
        free_mem((void **)&(outbound_group_session->group_seed.data), sizeof(uint8_t) * outbound_group_session->group_seed.len);
        outbound_group_session->group_seed.len = 0;

        // store
        get_skissm_plugin()->db_handler.store_group_session(outbound_group_session);

        // release
        skissm__account__free_unpacked(account, NULL);
        skissm__group_session__free_unpacked(outbound_group_session, NULL);
    }

    return ret;
}

int new_outbound_group_session_invited(
    Skissm__GroupUpdateKeyBundle *group_update_key_bundle,
    Skissm__E2eeAddress *user_address
) {
    int ret = 0;

    Skissm__Account *account = NULL;
    uint8_t *identity_public_key = NULL;
    if (user_address == NULL) {
        ssm_notify_log(NULL, BAD_ACCOUNT, "new_outbound_group_session_invited()");
        ret = -1;
    } else {
        get_skissm_plugin()->db_handler.load_account_by_address(user_address, &account);
        if (account == NULL) {
            ssm_notify_log(NULL, BAD_ACCOUNT, "new_outbound_group_session_invited()");
            ret = -1;
        } else {
            identity_public_key = get_identity_public_key_ds_uint8_from_account(account);
            if (identity_public_key == NULL) {
                ssm_notify_log(NULL, BAD_ACCOUNT, "new_outbound_group_session_invited()");
                ret = -1;
            }
        }
    }

    if (group_update_key_bundle->version == NULL) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_outbound_group_session_invited()");
        ret = -1;
    }
    if (group_update_key_bundle->session_id == NULL) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_outbound_group_session_invited()");
        ret = -1;
    }
    if (group_update_key_bundle->group_info == NULL) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_outbound_group_session_invited()");
        ret = -1;
    }
    if (group_update_key_bundle->chain_key.data == NULL) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_outbound_group_session_invited()");
        ret = -1;
    }
    if (group_update_key_bundle->adding_member_info_list == NULL) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_outbound_group_session_invited()");
        ret = -1;
    }

    if (ret == 0) {
        const cipher_suite_t *cipher_suite = get_e2ee_pack(group_update_key_bundle->e2ee_pack_id)->cipher_suite;
        int sign_key_len = cipher_suite->digital_signature_suite->get_crypto_param().sign_pub_key_len;

        Skissm__GroupSession *outbound_group_session = (Skissm__GroupSession *) malloc(sizeof(Skissm__GroupSession));
        skissm__group_session__init(outbound_group_session);

        outbound_group_session->version = strdup(group_update_key_bundle->version);
        outbound_group_session->e2ee_pack_id = group_update_key_bundle->e2ee_pack_id;

        copy_address_from_address(&(outbound_group_session->sender), user_address);
        copy_address_from_address(&(outbound_group_session->session_owner), user_address);
        outbound_group_session->session_id = strdup(group_update_key_bundle->session_id);

        copy_group_info(&(outbound_group_session->group_info), group_update_key_bundle->group_info);

        size_t i;
        size_t n_adding_member_info_list = group_update_key_bundle->n_adding_member_info_list;
        ProtobufCBinaryData *sender_chain_key = &(group_update_key_bundle->chain_key);
        ProtobufCBinaryData **adding_members_chain_key = (ProtobufCBinaryData **)malloc(sizeof(ProtobufCBinaryData *) * n_adding_member_info_list);
        for (i = 0; i < n_adding_member_info_list; i++) {
            // generate the chain keys, including the sender's and new members'
            advance_group_chain_key_by_welcome(cipher_suite, sender_chain_key, &adding_members_chain_key[i]);
            advance_group_chain_key_by_add(cipher_suite, adding_members_chain_key[i], sender_chain_key);

            if (compare_address(group_update_key_bundle->adding_member_info_list[i]->member_address, user_address)) {
                // create an outbound group session
                copy_protobuf_from_protobuf(&(outbound_group_session->chain_key), adding_members_chain_key[i]);
                outbound_group_session->sequence = 0;
            } else {
                // create an inbound group session corresponding to other new members
                new_and_complete_inbound_group_session_with_chain_key(
                    group_update_key_bundle->adding_member_info_list[i],
                    outbound_group_session,
                    adding_members_chain_key[i]
                );
            }
        }

        int ad_len = 2 * sign_key_len;
        outbound_group_session->associated_data.len = ad_len;
        outbound_group_session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * ad_len);
        memcpy(outbound_group_session->associated_data.data, identity_public_key, sign_key_len);
        memcpy((outbound_group_session->associated_data.data) + sign_key_len, identity_public_key, sign_key_len);

        // store
        get_skissm_plugin()->db_handler.store_group_session(outbound_group_session);

        // notify
        Skissm__GroupMember **added_member_list = NULL;
        size_t added_group_members_num = member_info_to_group_members(&added_member_list,
                                                                      group_update_key_bundle->adding_member_info_list, group_update_key_bundle->n_adding_member_info_list,
                                                                      outbound_group_session->group_info->group_member_list, outbound_group_session->group_info->n_group_member_list);
        if (added_group_members_num > 0) {
            ssm_notify_group_members_added(
                    user_address,
                    outbound_group_session->group_info->group_address,
                    outbound_group_session->group_info->group_name,
                    outbound_group_session->group_info->group_member_list,
                    outbound_group_session->group_info->n_group_member_list,
                    added_member_list,
                    added_group_members_num
            );
            // release
            free_group_members(&added_member_list, added_group_members_num);
        }

        // release
        skissm__account__free_unpacked(account, NULL);
        skissm__group_session__free_unpacked(outbound_group_session, NULL);
        for (i = 0; i < n_adding_member_info_list; i++) {
            free_protobuf(adding_members_chain_key[i]);
            free_mem((void **)&adding_members_chain_key[i], sizeof(ProtobufCBinaryData));
        }
        free_mem((void **)&adding_members_chain_key, sizeof(ProtobufCBinaryData *) * n_adding_member_info_list);
    }

    return ret;
}

int new_inbound_group_session_by_pre_key_bundle(
    uint32_t e2ee_pack_id,
    Skissm__E2eeAddress *user_address,
    Skissm__GroupPreKeyBundle *group_pre_key_bundle
) {
    int ret = 0;

    if (user_address == NULL) {
        ssm_notify_log(NULL, BAD_ACCOUNT, "new_inbound_group_session_by_pre_key_bundle()");
        ret = -1;
    }

    if (group_pre_key_bundle == NULL) {
        ssm_notify_log(NULL, BAD_PRE_KEY_BUNDLE, "new_inbound_group_session_by_pre_key_bundle()");
        ret = -1;
    }

    if (ret == 0) {
        if (group_pre_key_bundle->version == NULL) {
            ssm_notify_log(NULL, BAD_PRE_KEY_BUNDLE, "new_inbound_group_session_by_pre_key_bundle()");
            ret = -1;
        }
        if (group_pre_key_bundle->session_id == NULL) {
            ssm_notify_log(NULL, BAD_PRE_KEY_BUNDLE, "new_inbound_group_session_by_pre_key_bundle()");
            ret = -1;
        }
        if (group_pre_key_bundle->sender == NULL) {
            ssm_notify_log(NULL, BAD_PRE_KEY_BUNDLE, "new_inbound_group_session_by_pre_key_bundle()");
            ret = -1;
        }
        if (group_pre_key_bundle->group_info == NULL) {
            ssm_notify_log(NULL, BAD_PRE_KEY_BUNDLE, "new_inbound_group_session_by_pre_key_bundle()");
            ret = -1;
        }
        if (group_pre_key_bundle->group_seed.data == NULL) {
            ssm_notify_log(NULL, BAD_PRE_KEY_BUNDLE, "new_inbound_group_session_by_pre_key_bundle()");
            ret = -1;
        }
    }

    if (ret == 0) {
        const cipher_suite_t *cipher_suite = get_e2ee_pack(e2ee_pack_id)->cipher_suite;
        int sign_key_len = cipher_suite->digital_signature_suite->get_crypto_param().sign_pub_key_len;

        Skissm__GroupSession *inbound_group_session = (Skissm__GroupSession *) malloc(sizeof(Skissm__GroupSession));
        skissm__group_session__init(inbound_group_session);

        inbound_group_session->e2ee_pack_id = e2ee_pack_id;
        copy_address_from_address(&(inbound_group_session->session_owner), user_address);

        inbound_group_session->version = strdup(group_pre_key_bundle->version);
        inbound_group_session->session_id = strdup(group_pre_key_bundle->session_id);

        copy_address_from_address(&(inbound_group_session->sender), group_pre_key_bundle->sender);

        copy_group_info(&(inbound_group_session->group_info), group_pre_key_bundle->group_info);

        inbound_group_session->sequence = group_pre_key_bundle->sequence;

        ProtobufCBinaryData *group_seed = &(group_pre_key_bundle->group_seed);
        inbound_group_session->group_seed.len = group_seed->len;
        inbound_group_session->group_seed.data = (uint8_t *) malloc(sizeof(uint8_t) * inbound_group_session->group_seed.len);
        memcpy(inbound_group_session->group_seed.data, group_seed->data, group_seed->len);

        get_skissm_plugin()->db_handler.store_group_session(inbound_group_session);

        // release
        skissm__group_session__free_unpacked(inbound_group_session, NULL);
    }

    return ret;
}

int new_inbound_group_session_by_member_id(
    uint32_t e2ee_pack_id,
    Skissm__E2eeAddress *user_address,
    Skissm__GroupMemberInfo *group_member_id,
    Skissm__GroupInfo *group_info
) {
    int ret = 0;

    if (user_address == NULL) {
        ssm_notify_log(NULL, BAD_ACCOUNT, "new_inbound_group_session_by_member_id()");
        ret = -1;
    }
    if (group_member_id == NULL) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_inbound_group_session_by_member_id()");
        ret = -1;
    } else {
        if (group_member_id->member_address == NULL) {
            ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_inbound_group_session_by_member_id()");
            ret = -1;
        }
        if (group_member_id->sign_public_key.data == NULL) {
            ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_inbound_group_session_by_member_id()");
            ret = -1;
        }
    }
    if (group_info == NULL) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_inbound_group_session_by_member_id()");
        ret = -1;
    }

    if (ret == 0) {
        const cipher_suite_t *cipher_suite = get_e2ee_pack(e2ee_pack_id)->cipher_suite;
        int sign_key_len = cipher_suite->digital_signature_suite->get_crypto_param().sign_pub_key_len;

        Skissm__GroupSession *inbound_group_session = (Skissm__GroupSession *) malloc(sizeof(Skissm__GroupSession));
        skissm__group_session__init(inbound_group_session);

        inbound_group_session->e2ee_pack_id = e2ee_pack_id;
        copy_address_from_address(&(inbound_group_session->session_owner), user_address);

        copy_address_from_address(&(inbound_group_session->sender), group_member_id->member_address);
        copy_group_info(&(inbound_group_session->group_info), group_info);

        int ad_len = 2 * sign_key_len;
        inbound_group_session->associated_data.len = ad_len;
        inbound_group_session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * ad_len);
        memcpy(inbound_group_session->associated_data.data, group_member_id->sign_public_key.data, sign_key_len);
        memcpy((inbound_group_session->associated_data.data) + sign_key_len, group_member_id->sign_public_key.data, sign_key_len);

        get_skissm_plugin()->db_handler.store_group_session(inbound_group_session);

        // release
        skissm__group_session__free_unpacked(inbound_group_session, NULL);
    }

    return ret;
}

int complete_inbound_group_session_by_pre_key_bundle(
    Skissm__GroupSession *inbound_group_session,
    Skissm__GroupPreKeyBundle *group_pre_key_bundle
) {
    int ret = 0;

    if (inbound_group_session == NULL) {
        ssm_notify_log(NULL, BAD_GROUP_SESSION, "complete_inbound_group_session_by_pre_key_bundle()");
        ret = -1;
    } else {
        if (inbound_group_session->associated_data.data == NULL) {
            ssm_notify_log(NULL, BAD_GROUP_SESSION, "complete_inbound_group_session_by_pre_key_bundle()");
            ret = -1;
        }
    }
    if (group_pre_key_bundle == NULL) {
        ssm_notify_log(NULL, BAD_PRE_KEY_BUNDLE, "complete_inbound_group_session_by_pre_key_bundle()");
        ret = -1;
    } else {
        if (group_pre_key_bundle->version == NULL) {
            ssm_notify_log(NULL, BAD_PRE_KEY_BUNDLE, "complete_inbound_group_session_by_pre_key_bundle()");
            ret = -1;
        }
        if (group_pre_key_bundle->session_id == NULL) {
            ssm_notify_log(NULL, BAD_PRE_KEY_BUNDLE, "complete_inbound_group_session_by_pre_key_bundle()");
            ret = -1;
        }
        if (group_pre_key_bundle->group_seed.data == NULL) {
            ssm_notify_log(NULL, BAD_PRE_KEY_BUNDLE, "complete_inbound_group_session_by_pre_key_bundle()");
            ret = -1;
        }
    }

    if (ret == 0) {
        const cipher_suite_t *cipher_suite = get_e2ee_pack(inbound_group_session->e2ee_pack_id)->cipher_suite;
        int sign_key_len = cipher_suite->digital_signature_suite->get_crypto_param().sign_pub_key_len;

        size_t secret_len = SEED_SECRET_LEN + sign_key_len;
        uint8_t *secret = (uint8_t *) malloc(sizeof(uint8_t) * secret_len);

        inbound_group_session->version = strdup(group_pre_key_bundle->version);
        inbound_group_session->session_id = strdup(group_pre_key_bundle->session_id);

        inbound_group_session->sequence = group_pre_key_bundle->sequence;

        // combine seed secret and ID
        memcpy(secret, group_pre_key_bundle->group_seed.data, SEED_SECRET_LEN);
        memcpy(secret + SEED_SECRET_LEN, inbound_group_session->associated_data.data, sign_key_len);  // only copy the first half

        // generate a chain key
        int hash_len = cipher_suite->symmetric_encryption_suite->get_crypto_param().hash_len;
        uint8_t salt[hash_len];
        memset(salt, 0, hash_len);
        inbound_group_session->chain_key.len = hash_len;
        inbound_group_session->chain_key.data = (uint8_t *) malloc(sizeof(uint8_t) * inbound_group_session->chain_key.len);
        cipher_suite->symmetric_encryption_suite->hkdf(
            secret, secret_len,
            salt, sizeof(salt),
            (uint8_t *)ROOT_SEED, sizeof(ROOT_SEED) - 1,
            inbound_group_session->chain_key.data, inbound_group_session->chain_key.len
        );

        get_skissm_plugin()->db_handler.store_group_session(inbound_group_session);

        // release
        free_mem((void **)&secret, secret_len);
    }

    return ret;
}

int complete_inbound_group_session_by_member_id(
    Skissm__GroupSession *inbound_group_session,
    Skissm__GroupMemberInfo *group_member_id
) {
    int ret = 0;

    if (inbound_group_session == NULL) {
        ssm_notify_log(NULL, BAD_GROUP_SESSION, "complete_inbound_group_session_by_member_id()");
        ret = -1;
    } else {
        if (inbound_group_session->group_seed.data == NULL) {
            ssm_notify_log(NULL, BAD_GROUP_SESSION, "complete_inbound_group_session_by_member_id()");
            ret = -1;
        }
    }
    if (group_member_id == NULL) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "complete_inbound_group_session_by_member_id()");
        ret = -1;
    } else {
        if (group_member_id->sign_public_key.data == NULL) {
            ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "complete_inbound_group_session_by_member_id()");
            ret = -1;
        }
    }

    if (ret == 0) {
        const cipher_suite_t *cipher_suite = get_e2ee_pack(inbound_group_session->e2ee_pack_id)->cipher_suite;
        int sign_key_len = cipher_suite->digital_signature_suite->get_crypto_param().sign_pub_key_len;

        size_t secret_len = SEED_SECRET_LEN + sign_key_len;
        uint8_t *secret = (uint8_t *) malloc(sizeof(uint8_t) * secret_len);

        int ad_len = 2 * sign_key_len;
        inbound_group_session->associated_data.len = ad_len;
        inbound_group_session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * ad_len);
        memcpy(inbound_group_session->associated_data.data, group_member_id->sign_public_key.data, sign_key_len);
        memcpy((inbound_group_session->associated_data.data) + sign_key_len, group_member_id->sign_public_key.data, sign_key_len);

        // combine seed secret and ID
        memcpy(secret, inbound_group_session->group_seed.data, SEED_SECRET_LEN);
        memcpy(secret + SEED_SECRET_LEN, group_member_id->sign_public_key.data, sign_key_len);

        // we do not store the seed secret in the session
        free_mem((void **)&(inbound_group_session->group_seed.data), sizeof(uint8_t) * inbound_group_session->group_seed.len);
        inbound_group_session->group_seed.len = 0;

        // generate a chain key
        int hash_len = cipher_suite->symmetric_encryption_suite->get_crypto_param().hash_len;
        uint8_t salt[hash_len];
        memset(salt, 0, hash_len);
        inbound_group_session->chain_key.len = hash_len;
        inbound_group_session->chain_key.data = (uint8_t *) malloc(sizeof(uint8_t) * inbound_group_session->chain_key.len);
        cipher_suite->symmetric_encryption_suite->hkdf(
            secret, secret_len,
            salt, sizeof(salt),
            (uint8_t *)ROOT_SEED, sizeof(ROOT_SEED) - 1,
            inbound_group_session->chain_key.data, inbound_group_session->chain_key.len
        );

        get_skissm_plugin()->db_handler.store_group_session(inbound_group_session);

        // release
        free_mem((void **)&secret, secret_len);
    }

    return ret;
}

int new_and_complete_inbound_group_session(
    Skissm__GroupMemberInfo *group_member_id,
    Skissm__GroupSession *other_group_session
) {
    int ret = 0;

    if (group_member_id == NULL) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_and_complete_inbound_group_session()");
        ret = -1;
    } else {
        if (group_member_id->member_address == NULL) {
            ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_and_complete_inbound_group_session()");
            ret = -1;
        }
        if (group_member_id->sign_public_key.data == NULL) {
            ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_and_complete_inbound_group_session()");
            ret = -1;
        }
    }

    if (other_group_session == NULL) {
        ssm_notify_log(NULL, BAD_GROUP_SESSION, "new_and_complete_inbound_group_session()");
        ret = -1;
    } else {
        if (other_group_session->sender == NULL) {
            ssm_notify_log(NULL, BAD_GROUP_SESSION, "new_and_complete_inbound_group_session()");
            ret = -1;
        }
        if (other_group_session->version == NULL) {
            ssm_notify_log(NULL, BAD_GROUP_SESSION, "new_and_complete_inbound_group_session()");
            ret = -1;
        }
        if (other_group_session->session_id == NULL) {
            ssm_notify_log(NULL, BAD_GROUP_SESSION, "new_and_complete_inbound_group_session()");
            ret = -1;
        }
        if (other_group_session->session_owner == NULL) {
            ssm_notify_log(NULL, BAD_GROUP_SESSION, "new_and_complete_inbound_group_session()");
            ret = -1;
        }
        if (other_group_session->group_info == NULL) {
            ssm_notify_log(NULL, BAD_GROUP_SESSION, "new_and_complete_inbound_group_session()");
            ret = -1;
        }
        if (other_group_session->group_seed.data == NULL) {
            ssm_notify_log(NULL, BAD_GROUP_SESSION, "new_and_complete_inbound_group_session()");
            ret = -1;
        }
    }

    if (ret == 0) {
        Skissm__GroupSession *inbound_group_session = (Skissm__GroupSession *) malloc(sizeof(Skissm__GroupSession));
        skissm__group_session__init(inbound_group_session);

        insert_inbound_group_session_data(group_member_id, other_group_session, inbound_group_session);

        const cipher_suite_t *cipher_suite = get_e2ee_pack(other_group_session->e2ee_pack_id)->cipher_suite;
        int sign_key_len = cipher_suite->digital_signature_suite->get_crypto_param().sign_pub_key_len;

        uint8_t *identity_public_key = group_member_id->sign_public_key.data;

        ProtobufCBinaryData *group_seed = &(other_group_session->group_seed);

        size_t secret_len = SEED_SECRET_LEN + sign_key_len;
        uint8_t *secret = (uint8_t *) malloc(sizeof(uint8_t) * secret_len);

        // combine seed secret and ID
        memcpy(secret, group_seed->data, SEED_SECRET_LEN);
        memcpy(secret + SEED_SECRET_LEN, identity_public_key, sign_key_len);

        // generate a chain key
        int hash_len = cipher_suite->symmetric_encryption_suite->get_crypto_param().hash_len;
        uint8_t salt[hash_len];
        memset(salt, 0, hash_len);
        inbound_group_session->chain_key.len = hash_len;
        inbound_group_session->chain_key.data = (uint8_t *) malloc(sizeof(uint8_t) * inbound_group_session->chain_key.len);
        cipher_suite->symmetric_encryption_suite->hkdf(
            secret, secret_len,
            salt, sizeof(salt),
            (uint8_t *)ROOT_SEED, sizeof(ROOT_SEED) - 1,
            inbound_group_session->chain_key.data, inbound_group_session->chain_key.len
        );
        inbound_group_session->sequence = 0;

        int ad_len = 2 * sign_key_len;
        inbound_group_session->associated_data.len = ad_len;
        inbound_group_session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * ad_len);
        memcpy(inbound_group_session->associated_data.data, identity_public_key, sign_key_len);
        memcpy((inbound_group_session->associated_data.data) + sign_key_len, identity_public_key, sign_key_len);

        get_skissm_plugin()->db_handler.store_group_session(inbound_group_session);

        // release
        skissm__group_session__free_unpacked(inbound_group_session, NULL);
        free_mem((void **)&secret, sizeof(uint8_t) * secret_len);
    }

    return ret;
}

int new_and_complete_inbound_group_session_with_chain_key(
    Skissm__GroupMemberInfo *group_member_info,
    Skissm__GroupSession *other_group_session,
    ProtobufCBinaryData *their_chain_key
) {
    int ret = 0;

    if (group_member_info == NULL) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_and_complete_inbound_group_session_with_chain_key()");
        ret = -1;
    } else {
        if (group_member_info->member_address == NULL) {
            ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_and_complete_inbound_group_session_with_chain_key()");
            ret = -1;
        }
        if (group_member_info->sign_public_key.data == NULL) {
            ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_and_complete_inbound_group_session_with_chain_key()");
            ret = -1;
        }
    }
    if (other_group_session == NULL) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_and_complete_inbound_group_session_with_chain_key()");
        ret = -1;
    } else {
        if (other_group_session->session_owner == NULL) {
            ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_and_complete_inbound_group_session_with_chain_key()");
            ret = -1;
        }
        if (other_group_session->version == NULL) {
            ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_and_complete_inbound_group_session_with_chain_key()");
            ret = -1;
        }
        if (other_group_session->session_id == NULL) {
            ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_and_complete_inbound_group_session_with_chain_key()");
            ret = -1;
        }
        if (other_group_session->group_info == NULL) {
            ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_and_complete_inbound_group_session_with_chain_key()");
            ret = -1;
        }
    }
    if (their_chain_key == NULL) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_and_complete_inbound_group_session_with_chain_key()");
        ret = -1;
    }

    if (ret == 0) {
        Skissm__GroupSession *inbound_group_session = (Skissm__GroupSession *) malloc(sizeof(Skissm__GroupSession));
        skissm__group_session__init(inbound_group_session);

        insert_inbound_group_session_data(group_member_info, other_group_session, inbound_group_session);

        const cipher_suite_t *cipher_suite = get_e2ee_pack(other_group_session->e2ee_pack_id)->cipher_suite;
        int sign_key_len = cipher_suite->digital_signature_suite->get_crypto_param().sign_pub_key_len;

        uint8_t *identity_public_key = group_member_info->sign_public_key.data;

        copy_protobuf_from_protobuf(&(inbound_group_session->chain_key), their_chain_key);
        inbound_group_session->sequence = 0;

        int ad_len = 2 * sign_key_len;
        inbound_group_session->associated_data.len = ad_len;
        inbound_group_session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * ad_len);

        memcpy(inbound_group_session->associated_data.data, identity_public_key, sign_key_len);
        memcpy((inbound_group_session->associated_data.data) + sign_key_len, identity_public_key, sign_key_len);

        get_skissm_plugin()->db_handler.store_group_session(inbound_group_session);

        // release
        skissm__group_session__free_unpacked(inbound_group_session, NULL);
    }

    return ret;
}

int new_and_complete_inbound_group_session_with_ratchet_state(
    Skissm__GroupUpdateKeyBundle *group_update_key_bundle,
    Skissm__E2eeAddress *user_address
) {
    int ret = 0;

    if (user_address == NULL) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_and_complete_inbound_group_session_with_ratchet_state()");
        ret = -1;
    }
    if (group_update_key_bundle == NULL) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_and_complete_inbound_group_session_with_ratchet_state()");
        ret = -1;
    } else {
        if (group_update_key_bundle->version == NULL) {
            ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_and_complete_inbound_group_session_with_ratchet_state()");
            ret = -1;
        }
        if (group_update_key_bundle->session_id == NULL) {
            ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_and_complete_inbound_group_session_with_ratchet_state()");
            ret = -1;
        }
        if (group_update_key_bundle->sender == NULL) {
            ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_and_complete_inbound_group_session_with_ratchet_state()");
            ret = -1;
        }
        if (group_update_key_bundle->group_info == NULL) {
            ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_and_complete_inbound_group_session_with_ratchet_state()");
            ret = -1;
        }
        if (group_update_key_bundle->chain_key.data == NULL) {
            ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_and_complete_inbound_group_session_with_ratchet_state()");
            ret = -1;
        }
        if (group_update_key_bundle->sign_public_key.data == NULL) {
            ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "new_and_complete_inbound_group_session_with_ratchet_state()");
            ret = -1;
        }
    }

    if (ret == 0) {
        Skissm__GroupSession *inbound_group_session = (Skissm__GroupSession *) malloc(sizeof(Skissm__GroupSession));
        skissm__group_session__init(inbound_group_session);

        inbound_group_session->version = strdup(group_update_key_bundle->version);
        inbound_group_session->e2ee_pack_id = group_update_key_bundle->e2ee_pack_id;
        inbound_group_session->session_id = strdup(group_update_key_bundle->session_id);

        const cipher_suite_t *cipher_suite = get_e2ee_pack(group_update_key_bundle->e2ee_pack_id)->cipher_suite;

        copy_address_from_address(&(inbound_group_session->sender), group_update_key_bundle->sender);

        copy_address_from_address(&(inbound_group_session->session_owner), user_address);

        copy_group_info(&(inbound_group_session->group_info), group_update_key_bundle->group_info);

        /** We have generated the sender's chain key in new_outbound_group_session_invited(),
         *  so we just need to generate others' chain key.
         */
        if (group_update_key_bundle->adding == false) {
            advance_group_chain_key_by_add(cipher_suite, &(group_update_key_bundle->chain_key), &(group_update_key_bundle->chain_key));
        }
        copy_protobuf_from_protobuf(&(inbound_group_session->chain_key), &(group_update_key_bundle->chain_key));
        inbound_group_session->sequence = 0;

        int sign_key_len = cipher_suite->digital_signature_suite->get_crypto_param().sign_pub_key_len;

        uint8_t *identity_public_key = group_update_key_bundle->sign_public_key.data;

        int ad_len = 2 * sign_key_len;
        inbound_group_session->associated_data.len = ad_len;
        inbound_group_session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * ad_len);
        memcpy(inbound_group_session->associated_data.data, identity_public_key, sign_key_len);
        memcpy((inbound_group_session->associated_data.data) + sign_key_len, identity_public_key, sign_key_len);

        get_skissm_plugin()->db_handler.store_group_session(inbound_group_session);

        // release
        skissm__group_session__free_unpacked(inbound_group_session, NULL);
    }

    return ret;
}

int renew_outbound_group_session_by_welcome_and_add(
    Skissm__GroupSession *outbound_group_session,
    ProtobufCBinaryData *sender_chain_key,
    Skissm__E2eeAddress *sender_address,
    size_t n_adding_member_info_list,
    Skissm__GroupMemberInfo **adding_member_info_list,
    size_t adding_group_members_num,
    Skissm__GroupMember **adding_group_members
) {
    int ret = 0;

    Skissm__Account *account = NULL;
    ProtobufCBinaryData *identity_public_key = NULL;
    if (outbound_group_session == NULL) {
        ssm_notify_log(NULL, BAD_GROUP_SESSION, "renew_outbound_group_session_by_welcome_and_add()");
        ret = -1;
    } else {
        if (outbound_group_session->session_owner == NULL) {
            ssm_notify_log(NULL, BAD_GROUP_SESSION, "renew_outbound_group_session_by_welcome_and_add()");
            ret = -1;
        } else {
            get_skissm_plugin()->db_handler.load_account_by_address(outbound_group_session->session_owner, &account);
            if (account == NULL) {
                ssm_notify_log(outbound_group_session->session_owner, BAD_ACCOUNT, "renew_outbound_group_session_welcome_and_add()");
                ret = -1;
            } else {
                identity_public_key = get_identity_public_key_ds_bytes_from_account(account);
                if (identity_public_key == NULL) {
                    ssm_notify_log(outbound_group_session->session_owner, BAD_ACCOUNT, "renew_outbound_group_session_welcome_and_add()");
                    ret = -1;
                }
            }
        }
        if (outbound_group_session->version == NULL) {
            ssm_notify_log(NULL, BAD_GROUP_SESSION, "renew_outbound_group_session_by_welcome_and_add()");
            ret = -1;
        }
        if (outbound_group_session->sender == NULL) {
            ssm_notify_log(NULL, BAD_GROUP_SESSION, "renew_outbound_group_session_by_welcome_and_add()");
            ret = -1;
        }
        if (outbound_group_session->session_id == NULL) {
            ssm_notify_log(NULL, BAD_GROUP_SESSION, "renew_outbound_group_session_by_welcome_and_add()");
            ret = -1;
        }
        if (outbound_group_session->group_info == NULL) {
            ssm_notify_log(NULL, BAD_GROUP_SESSION, "renew_outbound_group_session_by_welcome_and_add()");
            ret = -1;
        }
        if (outbound_group_session->chain_key.data == NULL) {
            ssm_notify_log(NULL, BAD_GROUP_SESSION, "renew_outbound_group_session_by_welcome_and_add()");
            ret = -1;
        }
    }
    if (sender_address == NULL) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "renew_outbound_group_session_by_welcome_and_add()");
        ret = -1;
    }
    if (adding_member_info_list == NULL) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "renew_outbound_group_session_by_welcome_and_add()");
        ret = -1;
    }
    if (adding_group_members == NULL) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "renew_outbound_group_session_by_welcome_and_add()");
        ret = -1;
    }

    if (ret == 0) {
        const cipher_suite_t *cipher_suite = get_e2ee_pack(outbound_group_session->e2ee_pack_id)->cipher_suite;

        // renew the group members
        Skissm__GroupInfo *old_group_info = NULL;
        copy_group_info(&old_group_info, outbound_group_session->group_info);
        skissm__group_info__free_unpacked(outbound_group_session->group_info, NULL);

        add_group_members_to_group_info(
            &(outbound_group_session->group_info), old_group_info, adding_group_members, adding_group_members_num
        );
        // release old_group_info
        skissm__group_info__free_unpacked(old_group_info, NULL);

        // send the current ratchet state to the new group members
        size_t i, j;
        char *cur_user_id, *cur_user_domain;
        uint8_t *group_ratchet_state_plaintext_data = NULL;
        size_t group_ratchet_state_plaintext_data_len;
        for (i = 0; i < adding_group_members_num; i++) {
            // pack
            group_ratchet_state_plaintext_data_len = pack_group_ratchet_state_plaintext(
                outbound_group_session, &group_ratchet_state_plaintext_data,
                sender_chain_key == NULL, identity_public_key,
                n_adding_member_info_list, adding_member_info_list
            );

            cur_user_id = adding_group_members[i]->user_id;
            cur_user_domain = adding_group_members[i]->domain;
            Skissm__Session **outbound_sessions = NULL;
            size_t outbound_sessions_num = get_skissm_plugin()->db_handler.load_outbound_sessions(
                outbound_group_session->session_owner, cur_user_id, cur_user_domain, &outbound_sessions
            );

            if (outbound_sessions_num > 0 && outbound_sessions != NULL) {
                for (j = 0; j < outbound_sessions_num; j++) {
                    Skissm__Session *outbound_session = outbound_sessions[j];
                    if (compare_address(outbound_session->their_address, outbound_group_session->session_owner))
                        continue;
                    if (outbound_session->responded) {
                        Skissm__SendOne2oneMsgResponse *response;
                        response = send_one2one_msg_internal(
                            outbound_session,
                            SKISSM__NOTIF_LEVEL__NOTIF_LEVEL_SESSION,
                            group_ratchet_state_plaintext_data, group_ratchet_state_plaintext_data_len
                        );
                        skissm__send_one2one_msg_response__free_unpacked(response, NULL);
                    } else {
                        /** Since the other has not responded, we store the group pre-key first so that
                         *  we can send it right after receiving the other's accept message.
                         */
                        store_pending_common_plaintext_data_internal(
                            outbound_session->our_address,
                            outbound_session->their_address,
                            group_ratchet_state_plaintext_data,
                            group_ratchet_state_plaintext_data_len,
                            SKISSM__NOTIF_LEVEL__NOTIF_LEVEL_SESSION
                        );
                    }
                    // release outbound_session
                    skissm__session__free_unpacked(outbound_session, NULL);
                }
                // release outbound_sessions
                free_mem((void **)&outbound_sessions, sizeof(Skissm__Session *) * outbound_sessions_num);
            } else {
                /** Since we haven't created any session, we need to create a session before sending the group pre-key. */
                Skissm__InviteResponse *invite_response = get_pre_key_bundle_internal(
                    outbound_group_session->session_owner,
                    account->auth,
                    cur_user_id, cur_user_domain,
                    NULL, true,
                    group_ratchet_state_plaintext_data, group_ratchet_state_plaintext_data_len
                );
                // release
                if (invite_response != NULL) {
                    skissm__invite_response__free_unpacked(invite_response, NULL);
                } else {
                    // nothing to do
                }
            }
        }

        ProtobufCBinaryData **their_chain_keys = (ProtobufCBinaryData **)malloc(sizeof(ProtobufCBinaryData *) * n_adding_member_info_list);
        // advance the chain key
        if (sender_chain_key == NULL) {
            // the sender
            for (i = 0; i < n_adding_member_info_list; i++) {
                advance_group_chain_key_by_welcome(cipher_suite, &(outbound_group_session->chain_key), &their_chain_keys[i]);
                advance_group_chain_key_by_add(cipher_suite, their_chain_keys[i], &(outbound_group_session->chain_key));
            }
        } else {
            // the receiver
            for (i = 0; i < n_adding_member_info_list; i++) {
                advance_group_chain_key_by_welcome(cipher_suite, sender_chain_key, &their_chain_keys[i]);
                advance_group_chain_key_by_add(cipher_suite, their_chain_keys[i], sender_chain_key);
            }
            advance_group_chain_key_by_add(cipher_suite, &(outbound_group_session->chain_key), &(outbound_group_session->chain_key));
        }

        // reset the sequence
        outbound_group_session->sequence = 0;

        // store
        get_skissm_plugin()->db_handler.store_group_session(outbound_group_session);

        // renew existed inbound group sessions
        Skissm__GroupSession **inbound_group_sessions = NULL;
        size_t inbound_group_sessions_num = get_skissm_plugin()->db_handler.load_group_sessions(
            outbound_group_session->session_owner, outbound_group_session->group_info->group_address, &inbound_group_sessions
        );

        if (inbound_group_sessions_num > 0 && inbound_group_sessions != NULL) {
            for (i = 0; i < inbound_group_sessions_num; i++) {
                // there is one outbound group session in inbound_group_sessions, so we need to ignore it
                if (!compare_address(outbound_group_session->session_owner, inbound_group_sessions[i]->sender)) {
                    if (compare_address(sender_address, inbound_group_sessions[i]->sender)) {
                        renew_inbound_group_session_by_welcome_and_add(
                            sender_chain_key,
                            inbound_group_sessions[i],
                            outbound_group_session->group_info
                        );
                    } else {
                        renew_inbound_group_session_by_welcome_and_add(
                            NULL,
                            inbound_group_sessions[i],
                            outbound_group_session->group_info
                        );
                    }
                    ssm_notify_log(
                        outbound_group_session->session_owner,
                        DEBUG_LOG,
                        "renew_outbound_group_session_by_welcome_and_add() renew the inbound group sessions: sender_address:[%s:%s], inbound_group_sessions[%zu of %zu]->sender:[%s:%s]", 
                        sender_address->user->user_id,
                        sender_address->user->device_id,
                        i+1, inbound_group_sessions_num,
                        inbound_group_sessions[i]->sender->user->user_id,
                        inbound_group_sessions[i]->sender->user->device_id
                    );
                }
                // release inbound_group_sessions[i]
                skissm__group_session__free_unpacked(inbound_group_sessions[i], NULL);
            }
            // release inbound_group_sessions
            free_mem((void **)&inbound_group_sessions, sizeof(Skissm__Session *) * inbound_group_sessions_num);
        } else {
            ssm_notify_log(
                outbound_group_session->session_owner,
                DEBUG_LOG,
                "renew_outbound_group_session_by_welcome_and_add(), no existed inbound group sessions, renew the inbound group sessions skipped"
            );
        }

        // create new inbound group sessions to the adding members
        for (i = 0; i < n_adding_member_info_list; i++) {
            new_and_complete_inbound_group_session_with_chain_key(adding_member_info_list[i], outbound_group_session, their_chain_keys[i]);
        }

        // release
        skissm__account__free_unpacked(account, NULL);
        free_mem((void **)&group_ratchet_state_plaintext_data, sizeof(uint8_t) * group_ratchet_state_plaintext_data_len);
        free_mem((void **)&their_chain_keys, sizeof(ProtobufCBinaryData));
    }

    return ret;
}

int renew_inbound_group_session_by_welcome_and_add(
    ProtobufCBinaryData *sender_chain_key,
    Skissm__GroupSession *inbound_group_session,
    Skissm__GroupInfo *new_group_info
) {
    int ret = 0;

    if (inbound_group_session == NULL) {
        ssm_notify_log(NULL, BAD_GROUP_SESSION, "renew_inbound_group_session_by_welcome_and_add()");
        ret = -1;
    } else {
        if (inbound_group_session->session_owner == NULL) {
            ssm_notify_log(NULL, BAD_GROUP_SESSION, "renew_inbound_group_session_by_welcome_and_add()");
            ret = -1;
        }
        if (inbound_group_session->group_info == NULL) {
            ssm_notify_log(NULL, BAD_GROUP_SESSION, "renew_inbound_group_session_by_welcome_and_add()");
            ret = -1;
        }
        if (inbound_group_session->chain_key.data == NULL) {
            ssm_notify_log(NULL, BAD_GROUP_SESSION, "renew_inbound_group_session_by_welcome_and_add()");
            ret = -1;
        }
    }
    if (new_group_info == NULL) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "renew_inbound_group_session_by_welcome_and_add()");
        ret = -1;
    }

    if (ret == 0) {
        ssm_notify_log(
            inbound_group_session->session_owner,
            DEBUG_LOG,
            "renew_inbound_group_session_by_welcome_and_add() sender_chain_key is Null: %s",
            sender_chain_key == NULL ? "true" : "false"
        );

        const cipher_suite_t *cipher_suite = get_e2ee_pack(inbound_group_session->e2ee_pack_id)->cipher_suite;

        skissm__group_info__free_unpacked(inbound_group_session->group_info, NULL);
        copy_group_info(&(inbound_group_session->group_info), new_group_info);

        if (sender_chain_key != NULL) {
            free_mem((void **)&(inbound_group_session->chain_key.data), inbound_group_session->chain_key.len);

            copy_protobuf_from_protobuf(&(inbound_group_session->chain_key), sender_chain_key);
        } else {
            advance_group_chain_key_by_add(cipher_suite, &(inbound_group_session->chain_key), &(inbound_group_session->chain_key));
        }

        inbound_group_session->sequence = 0;

        // store
        get_skissm_plugin()->db_handler.store_group_session(inbound_group_session);
    }

    return ret;
}

int renew_group_sessions_with_new_device(
    Skissm__GroupSession *outbound_group_session,
    ProtobufCBinaryData *sender_chain_key,
    Skissm__E2eeAddress *sender_address,
    Skissm__E2eeAddress *new_device_address,
    Skissm__GroupMemberInfo *adding_member_device_info
) {
    int ret = 0;

    Skissm__Account *account = NULL;
    ProtobufCBinaryData *identity_public_key = NULL;
    if (outbound_group_session == NULL) {
        ssm_notify_log(NULL, BAD_GROUP_SESSION, "renew_group_sessions_with_new_device()");
        ret = -1;
    } else {
        if (outbound_group_session->session_owner == NULL) {
            ssm_notify_log(NULL, BAD_GROUP_SESSION, "renew_group_sessions_with_new_device()");
            ret = -1;
        } else {
            get_skissm_plugin()->db_handler.load_account_by_address(outbound_group_session->session_owner, &account);
            if (account == NULL) {
                ssm_notify_log(outbound_group_session->session_owner, BAD_ACCOUNT, "renew_group_sessions_with_new_device()");
                ret = -1;
            } else {
                identity_public_key = get_identity_public_key_ds_bytes_from_account(account);
                if (identity_public_key == NULL) {
                    ssm_notify_log(outbound_group_session->session_owner, BAD_ACCOUNT, "renew_outbound_group_session_welcome_and_add()");
                    ret = -1;
                }
            }
        }
        if (outbound_group_session->version == NULL) {
            ssm_notify_log(NULL, BAD_GROUP_SESSION, "renew_group_sessions_with_new_device()");
            ret = -1;
        }
        if (outbound_group_session->sender == NULL) {
            ssm_notify_log(NULL, BAD_GROUP_SESSION, "renew_group_sessions_with_new_device()");
            ret = -1;
        }
        if (outbound_group_session->session_id == NULL) {
            ssm_notify_log(NULL, BAD_GROUP_SESSION, "renew_group_sessions_with_new_device()");
            ret = -1;
        }
        if (outbound_group_session->group_info == NULL) {
            ssm_notify_log(NULL, BAD_GROUP_SESSION, "renew_group_sessions_with_new_device()");
            ret = -1;
        }
        if (outbound_group_session->chain_key.data == NULL) {
            ssm_notify_log(NULL, BAD_GROUP_SESSION, "renew_group_sessions_with_new_device()");
            ret = -1;
        }
    }
    if (sender_address == NULL) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "renew_group_sessions_with_new_device()");
        ret = -1;
    } else {
        if (sender_address->user->user_id == NULL) {
            ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "renew_group_sessions_with_new_device()");
            ret = -1;
        }
        if (sender_address->domain == NULL) {
            ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "renew_group_sessions_with_new_device()");
            ret = -1;
        }
        if (sender_address->user->device_id == NULL) {
            ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "renew_group_sessions_with_new_device()");
            ret = -1;
        }
    }
    if (new_device_address == NULL) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "renew_group_sessions_with_new_device()");
        ret = -1;
    } else {
        if (new_device_address->user->user_id == NULL) {
            ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "renew_group_sessions_with_new_device()");
            ret = -1;
        }
        if (new_device_address->domain == NULL) {
            ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "renew_group_sessions_with_new_device()");
            ret = -1;
        }
        if (new_device_address->user->device_id == NULL) {
            ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "renew_group_sessions_with_new_device()");
            ret = -1;
        }
    }
    if (adding_member_device_info == NULL) {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "renew_group_sessions_with_new_device()");
        ret = -1;
    } else {
        if (adding_member_device_info->member_address == NULL) {
            ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "renew_group_sessions_with_new_device()");
            ret = -1;
        }
        if (adding_member_device_info->sign_public_key.data == NULL) {
            ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "renew_group_sessions_with_new_device()");
            ret = -1;
        }
    }

    if (ret == 0) {
        ssm_notify_log(
            outbound_group_session->session_owner,
            DEBUG_LOG,
            "renew_group_sessions_with_new_device() owner address: [%s:%s] sender address: [%s:%s] member address: [%s:%s]",
            outbound_group_session->session_owner->user->user_id,
            outbound_group_session->session_owner->user->device_id,
            sender_address->user->user_id,
            sender_address->user->device_id,
            adding_member_device_info->member_address->user->user_id,
            adding_member_device_info->member_address->user->device_id
        );

        // renew outbound group session
        const cipher_suite_t *cipher_suite = get_e2ee_pack(outbound_group_session->e2ee_pack_id)->cipher_suite;

        char *cur_user_id = new_device_address->user->user_id, *cur_user_domain = new_device_address->domain;
        char *cur_user_device_id = new_device_address->user->device_id;
        uint8_t *group_ratchet_state_plaintext_data = NULL;
        size_t group_ratchet_state_plaintext_data_len;

        group_ratchet_state_plaintext_data_len = pack_group_ratchet_state_plaintext(
            outbound_group_session, &group_ratchet_state_plaintext_data,
            sender_chain_key == NULL, identity_public_key,
            1, &adding_member_device_info
        );

        Skissm__Session *outbound_session = NULL;
        get_skissm_plugin()->db_handler.load_outbound_session(
            outbound_group_session->session_owner, new_device_address, &outbound_session
        );

        if (outbound_session != NULL) {
            if (outbound_session->responded) {
                ssm_notify_log(
                    outbound_group_session->session_owner,
                    DEBUG_LOG,
                    "renew_group_sessions_with_new_device() outbound_session found and is responded"
                );
                Skissm__SendOne2oneMsgResponse *response;
                response = send_one2one_msg_internal(
                    outbound_session,
                    SKISSM__NOTIF_LEVEL__NOTIF_LEVEL_SESSION,
                    group_ratchet_state_plaintext_data, group_ratchet_state_plaintext_data_len
                );
                skissm__send_one2one_msg_response__free_unpacked(response, NULL);
            } else {
                ssm_notify_log(
                    outbound_group_session->session_owner,
                    DEBUG_LOG,
                    "renew_group_sessions_with_new_device() outbound_session found and is not responded"
                );
                /** Since the other has not responded, we store the group pre-key first so that
                 *  we can send it right after receiving the other's accept message.
                 */
                store_pending_common_plaintext_data_internal(
                    outbound_session->our_address,
                    outbound_session->their_address,
                    group_ratchet_state_plaintext_data,
                    group_ratchet_state_plaintext_data_len,
                    SKISSM__NOTIF_LEVEL__NOTIF_LEVEL_SESSION
                );                
            }
            // release outbound_session
            skissm__session__free_unpacked(outbound_session, NULL);
        } else {
            ssm_notify_log(
                outbound_group_session->session_owner,
                DEBUG_LOG,
                "renew_group_sessions_with_new_device() outbound_session not found"
            );
            /** Since we haven't created any session, we need to create a session before sending the group pre-key. */
            Skissm__InviteResponse *response = get_pre_key_bundle_internal(
                outbound_group_session->session_owner,
                account->auth,
                cur_user_id, cur_user_domain,
                cur_user_device_id, false,
                group_ratchet_state_plaintext_data, group_ratchet_state_plaintext_data_len
            );
            // release
            if (response != NULL) {
                skissm__invite_response__free_unpacked(response, NULL);
            } else {
                // nothing to do
            }
        }

        ProtobufCBinaryData *their_chain_keys = NULL;
        // advance the chain key
        if (sender_chain_key == NULL) {
            // the sender
            advance_group_chain_key_by_welcome(cipher_suite, &(outbound_group_session->chain_key), &their_chain_keys);
            advance_group_chain_key_by_add(cipher_suite, their_chain_keys, &(outbound_group_session->chain_key));
            ssm_notify_log(
                outbound_group_session->session_owner,
                DEBUG_LOG,
                "renew_group_sessions_with_new_device() sender_chain_key is the case of null, create their_chain_keys"
            );
        } else {
            // the receiver
            advance_group_chain_key_by_welcome(cipher_suite, sender_chain_key, &their_chain_keys);
            advance_group_chain_key_by_add(cipher_suite, their_chain_keys, sender_chain_key);
            advance_group_chain_key_by_add(cipher_suite, &(outbound_group_session->chain_key), &(outbound_group_session->chain_key));
            ssm_notify_log(
                outbound_group_session->session_owner,
                DEBUG_LOG,
                "renew_group_sessions_with_new_device() sender_chain_key is the case of not null, create their_chain_keys"
            );
        }

        // reset the sequence
        outbound_group_session->sequence = 0;

        // store
        get_skissm_plugin()->db_handler.store_group_session(outbound_group_session);

        // renew the inbound group sessions
        Skissm__GroupSession **inbound_group_sessions = NULL;
        size_t inbound_group_sessions_num = get_skissm_plugin()->db_handler.load_group_sessions(
            outbound_group_session->session_owner, outbound_group_session->group_info->group_address, &inbound_group_sessions
        );
        if (inbound_group_sessions_num > 0 && inbound_group_sessions != NULL) {
            size_t i;
            for (i = 0; i < inbound_group_sessions_num; i++) {
                // there is one outbound group session in inbound_group_sessions, so we need to ignore it
                if (!compare_address(outbound_group_session->session_owner, inbound_group_sessions[i]->sender)) {
                    if (compare_address(sender_address, inbound_group_sessions[i]->sender)) {
                        renew_inbound_group_session_by_welcome_and_add(
                            sender_chain_key,
                            inbound_group_sessions[i],
                            outbound_group_session->group_info
                        );
                    } else {
                        renew_inbound_group_session_by_welcome_and_add(
                            NULL,
                            inbound_group_sessions[i],
                            outbound_group_session->group_info
                        );
                    }
                    ssm_notify_log(
                        outbound_group_session->session_owner,
                        DEBUG_LOG,
                        "renew_group_sessions_with_new_device() renew the inbound group sessions: sender_address:[%s:%s], inbound_group_sessions[%zu of %zu]->sender:[%s:%s]", 
                        sender_address->user->user_id,
                        sender_address->user->device_id,
                        i + 1,
                        inbound_group_sessions_num,
                        inbound_group_sessions[i]->sender->user->user_id,
                        inbound_group_sessions[i]->sender->user->device_id
                    );
                }
                // release inbound_group_sessions[i]
                skissm__group_session__free_unpacked(inbound_group_sessions[i], NULL);
            }
            // release inbound_group_sessions
            free_mem((void **)&inbound_group_sessions, sizeof(Skissm__Session *) * inbound_group_sessions_num);

            // create the inbound group session for new device
            new_and_complete_inbound_group_session_with_chain_key(adding_member_device_info, outbound_group_session, their_chain_keys);
        } else {
            ssm_notify_log(
                outbound_group_session->session_owner,
                DEBUG_LOG,
                "renew_group_sessions_with_new_device(), no inbound group sessions, renew the inbound group sessions skipped"
            );
        }

        // release
        skissm__account__free_unpacked(account, NULL);
        free_mem((void **)&their_chain_keys, sizeof(ProtobufCBinaryData));
    }

    return ret;
}
