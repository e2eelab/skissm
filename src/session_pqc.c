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
#include "skissm/session.h"

#include <stdio.h>
#include <string.h>

#include "skissm/account.h"
#include "skissm/account_cache.h"
#include "skissm/cipher.h"
#include "skissm/e2ee_client_internal.h"
#include "skissm/group_session.h"
#include "skissm/mem_util.h"
#include "skissm/ratchet.h"
#include "skissm/validation.h"

static const char FINGERPRINT_SEED[] = "Fingerprint";

int pqc_new_outbound_session_v2(
    Skissm__InviteResponse **response_out,
    Skissm__E2eeAddress *from,
    Skissm__PreKeyBundle *their_pre_key_bundle
) {
    int ret = 0;

    uint32_t e2ee_pack_id;
    cipher_suite_t *cipher_suite = NULL;
    Skissm__Account *local_account = NULL;
    Skissm__KeyPair *my_identity_key_pair = NULL;
    Skissm__IdentityKeyPublic *their_ik = NULL;
    Skissm__SignedPreKeyPublic *their_spk = NULL;
    Skissm__OneTimePreKeyPublic *their_opk = NULL;
    uint32_t asym_pub_key_len, sign_pub_key_len, sig_len, kem_ciphertext_len;
    Skissm__E2eeAddress *to = NULL;
    Skissm__Session *outbound_session = NULL;
    Skissm__InviteResponse *response = NULL;

    if (is_valid_address(from)) {
        // load the account
        get_skissm_plugin()->db_handler.load_account_by_address(from, &local_account);
        if (is_valid_registered_account(local_account)) {
            my_identity_key_pair = local_account->identity_key->asym_key_pair;
            if (is_valid_pre_key_bundle(their_pre_key_bundle)) {
                e2ee_pack_id = their_pre_key_bundle->e2ee_pack_id;
                cipher_suite = get_e2ee_pack(e2ee_pack_id)->cipher_suite;
                to = their_pre_key_bundle->user_address;
                if (is_valid_cipher_suite(cipher_suite)) {
                    asym_pub_key_len = cipher_suite->kem_suite->get_crypto_param().asym_pub_key_len;
                    sign_pub_key_len = cipher_suite->digital_signature_suite->get_crypto_param().sign_pub_key_len;
                    sig_len = cipher_suite->digital_signature_suite->get_crypto_param().sig_len;
                    kem_ciphertext_len = cipher_suite->kem_suite->get_crypto_param().kem_ciphertext_len;

                    their_ik = their_pre_key_bundle->identity_key_public;
                    their_spk = their_pre_key_bundle->signed_pre_key_public;
                    their_opk = their_pre_key_bundle->one_time_pre_key_public;
                } else {
                    ret = -1;
                }
            } else {
                ssm_notify_log(from, BAD_PRE_KEY_BUNDLE, "pqc_new_outbound_session()");
                ret = -1;
            }
        } else {
            ssm_notify_log(from, BAD_ACCOUNT, "pqc_new_outbound_session()");
            ret = -1;
        }
    } else {
        ret = -1;
    }

    if (ret == 0) {
        if (their_ik->asym_public_key.len != asym_pub_key_len) {
            ret = -1;
        }
        if (their_ik->sign_public_key.len != sign_pub_key_len) {
            ret = -1;
        }
        if (their_spk->public_key.len != asym_pub_key_len) {
            ret = -1;
        }
        if (their_spk->signature.len != sig_len) {
            ret = -1;
        }
        if (their_opk->public_key.len != asym_pub_key_len) {
            ret = -1;
        }
    }

    if (ret == 0) {
        // verify the signature
        ret = cipher_suite->digital_signature_suite->verify(
            their_spk->signature.data, their_spk->signature.len,
            their_spk->public_key.data, asym_pub_key_len,
            their_ik->sign_public_key.data
        );

        if (ret != 0) {
            ssm_notify_log(from, BAD_SIGNATURE, "pqc_new_outbound_session()");
        }
    }

    if (ret == 0) {
        outbound_session = (Skissm__Session *)malloc(sizeof(Skissm__Session));
        initialise_session(outbound_session, e2ee_pack_id, from, to);

        // set the version
        outbound_session->version = strdup(E2EE_PROTOCOL_VERSION);
        // set the session ID
        outbound_session->session_id = generate_uuid_str();
        // set session not verified
        outbound_session->f2f = false;

        uint8_t x3dh_epoch = 2;
        outbound_session->responded = false;
        outbound_session->bob_signed_pre_key_id = their_spk->spk_id;

        outbound_session->ratchet = (Skissm__Ratchet *)malloc(sizeof(Skissm__Ratchet));
        skissm__ratchet__init(outbound_session->ratchet);
        outbound_session->ratchet->sender_chain = (Skissm__SenderChainNode *)malloc(sizeof(Skissm__SenderChainNode));
        skissm__sender_chain_node__init(outbound_session->ratchet->sender_chain);
        copy_protobuf_from_protobuf(&(outbound_session->ratchet->sender_chain->their_ratchet_public_key), &(their_spk->public_key));

        // server may return empty one-time pre-key(public)
        if (their_opk) {
            outbound_session->bob_one_time_pre_key_id = their_opk->opk_id;
            x3dh_epoch = 3;
        }

        int ad_len = 2 * asym_pub_key_len;
        outbound_session->associated_data.len = ad_len;
        outbound_session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * ad_len);
        memcpy(outbound_session->associated_data.data, my_identity_key_pair->public_key.data, asym_pub_key_len);
        memcpy((outbound_session->associated_data.data) + asym_pub_key_len, their_ik->asym_public_key.data, asym_pub_key_len);

        // hash the public keys
        int hash_input_len = asym_pub_key_len * (x3dh_epoch + 1);
        uint8_t *hash_input = (uint8_t *)malloc(sizeof(uint8_t) * hash_input_len);
        memcpy(hash_input, my_identity_key_pair->public_key.data, asym_pub_key_len);
        memcpy(hash_input + asym_pub_key_len, their_ik->asym_public_key.data, asym_pub_key_len);
        memcpy(hash_input + asym_pub_key_len + asym_pub_key_len, their_spk->public_key.data, asym_pub_key_len);
        if (x3dh_epoch == 3)
            memcpy(hash_input + asym_pub_key_len + asym_pub_key_len + asym_pub_key_len, their_opk->public_key.data, asym_pub_key_len);

        int shared_key_len = cipher_suite->hash_suite->get_crypto_param().hash_len;
        uint8_t derived_secrets[2 * shared_key_len];
        int hash_len = cipher_suite->hash_suite->get_crypto_param().hash_len;
        uint8_t salt[hash_len];
        memset(salt, 0, hash_len);
        cipher_suite->hash_suite->hkdf(
            hash_input, hash_input_len,
            salt, sizeof(salt),
            (uint8_t *)FINGERPRINT_SEED, sizeof(FINGERPRINT_SEED) - 1,
            derived_secrets, sizeof(derived_secrets)
        );

        copy_protobuf_from_array(&(outbound_session->fingerprint), derived_secrets, sizeof(derived_secrets));

        int shared_secret_len = cipher_suite->kem_suite->get_crypto_param().shared_secret_len;
        // calculate the shared secret S via encapsulation
        uint8_t secret[x3dh_epoch * shared_secret_len];
        uint8_t *pos = secret;
        ProtobufCBinaryData ciphertext_2, ciphertext_3, ciphertext_4;

        cipher_suite->kem_suite->encaps(pos, &ciphertext_2, &(their_ik->asym_public_key));
        pos += shared_secret_len;
        cipher_suite->kem_suite->encaps(pos, &ciphertext_3, &(their_spk->public_key));
        if (x3dh_epoch == 3) {
            pos += shared_secret_len;
            cipher_suite->kem_suite->encaps(pos, &ciphertext_4, &(their_opk->public_key));
        } else{
            ciphertext_4.len = 0;
            ciphertext_4.data = NULL;
        }

        // the first part of the shared secret will be determined after receiving the acception message
        char zero_array[shared_secret_len];
        memset(zero_array, 0, shared_secret_len);
        outbound_session->temp_shared_secret.len = (x3dh_epoch + 1) * shared_secret_len;
        outbound_session->temp_shared_secret.data = (uint8_t *)malloc(sizeof(uint8_t) * outbound_session->temp_shared_secret.len);
        memcpy(outbound_session->temp_shared_secret.data, zero_array, shared_secret_len);
        memcpy(outbound_session->temp_shared_secret.data + shared_secret_len, secret, x3dh_epoch * shared_secret_len);

        // prepare the encaps_ciphertext_list
        outbound_session->n_pre_shared_input_list = x3dh_epoch;
        outbound_session->pre_shared_input_list = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData) * x3dh_epoch);
        init_protobuf(&(outbound_session->pre_shared_input_list[0]));
        copy_protobuf_from_protobuf(&(outbound_session->pre_shared_input_list[0]), &ciphertext_2);
        init_protobuf(&(outbound_session->pre_shared_input_list[1]));
        copy_protobuf_from_protobuf(&(outbound_session->pre_shared_input_list[1]), &ciphertext_3);
        if (x3dh_epoch == 3) {
            init_protobuf(&(outbound_session->pre_shared_input_list[2]));
            copy_protobuf_from_protobuf(&(outbound_session->pre_shared_input_list[2]), &ciphertext_4);
        }

        // generate the base key
        outbound_session->alice_base_key = (Skissm__KeyPair *)malloc(sizeof(Skissm__KeyPair));
        skissm__key_pair__init(outbound_session->alice_base_key);
        cipher_suite->kem_suite->asym_key_gen(&outbound_session->alice_base_key->public_key, &outbound_session->alice_base_key->private_key);

        // store sesson state before send invite
        ssm_notify_log(
            outbound_session->our_address,
            DEBUG_LOG,
            "pqc_new_outbound_session() store sesson state before send invite session_id=%s, from [%s:%s], to [%s:%s]",
            outbound_session->session_id,
            outbound_session->our_address->user->user_id,
            outbound_session->our_address->user->device_id,
            outbound_session->their_address->user->user_id,
            outbound_session->their_address->user->device_id
        );
        outbound_session->invite_t = get_skissm_plugin()->common_handler.gen_ts();
        get_skissm_plugin()->db_handler.store_session(outbound_session);

        // send the invite request to the peer
        ret = invite_internal(&response, outbound_session);

        // release
        unset(secret, sizeof(secret));
        free_protobuf(&ciphertext_2);
        free_protobuf(&ciphertext_3);
        free_protobuf(&ciphertext_4);
        skissm__session__free_unpacked(outbound_session, NULL);
        outbound_session = NULL;
    }

    if (ret == 0) {
        *response_out = response;
    }

    return ret;
}

int pqc_new_inbound_session(
    Skissm__Session **inbound_session_out,
    Skissm__Account *local_account,
    Skissm__InviteMsg *msg
) {
    int ret = 0;

    Skissm__Session *session = NULL;
    Skissm__AcceptResponse *accept_response = NULL;
    cipher_suite_t *cipher_suite = NULL;
    Skissm__E2eeAddress *address = NULL;
    Skissm__IdentityKey *our_ik = NULL;
    Skissm__SignedPreKey *our_spk = NULL;
    Skissm__SignedPreKey *old_spk_data = NULL;
    bool old_spk = false;
    Skissm__OneTimePreKey *our_one_time_pre_key = NULL;
    uint32_t bob_signed_pre_key_id;
    uint32_t bob_one_time_pre_key_id;
    Skissm__KeyPair *bob_identity_key = NULL;
    Skissm__KeyPair *bob_signed_pre_key = NULL;
    Skissm__KeyPair *bob_one_time_pre_key = NULL;
    uint8_t x3dh_epoch = 3;
    int asym_pub_key_len;
    int ad_len;
    int hash_input_len;
    uint8_t *hash_input = NULL;
    int shared_key_len;
    int hash_len;
    int shared_secret_len;
    uint32_t ciphertext_len;
    ProtobufCBinaryData ciphertext_1 = {0, NULL};
    Skissm__Ratchet *ratchet = NULL;

    if (is_valid_registered_account(local_account)) {
        our_ik = local_account->identity_key;
        our_spk = local_account->signed_pre_key;
        address = local_account->address;
    } else {
        ssm_notify_log(NULL, BAD_ACCOUNT, "pqc_new_inbound_session()");
        ret = -1;
    }
    if (is_valid_invite_msg(msg)) {
        cipher_suite = get_e2ee_pack(msg->e2ee_pack_id)->cipher_suite;
        asym_pub_key_len = cipher_suite->kem_suite->get_crypto_param().asym_pub_key_len;
        shared_key_len = cipher_suite->hash_suite->get_crypto_param().hash_len;
        hash_len = cipher_suite->hash_suite->get_crypto_param().hash_len;
        shared_secret_len = cipher_suite->kem_suite->get_crypto_param().shared_secret_len;
        ciphertext_len = cipher_suite->kem_suite->get_crypto_param().kem_ciphertext_len;
        bob_signed_pre_key_id = msg->bob_signed_pre_key_id;
        bob_one_time_pre_key_id = msg->bob_one_time_pre_key_id;
    } else {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "pqc_new_inbound_session()");
        ret = -1;
    }

    if (ret == 0) {
        // verify the signed pre-key
        if (our_spk->spk_id != bob_signed_pre_key_id) {
            get_skissm_plugin()->db_handler.load_signed_pre_key(address, bob_signed_pre_key_id, &old_spk_data);
            if (is_valid_signed_pre_key(old_spk_data)) {
                old_spk = true;
            } else {
                ssm_notify_log(NULL, BAD_SIGNED_PRE_KEY, "pqc_new_inbound_session()");
                ret = -1;
            }
        }
    }

    if (ret == 0) {
        // check the one-time pre-key
        if (bob_one_time_pre_key_id != 0) {
            x3dh_epoch = 4;
            our_one_time_pre_key = lookup_one_time_pre_key(local_account, bob_one_time_pre_key_id);
            if (!is_valid_one_time_pre_key(our_one_time_pre_key)) {
                ssm_notify_log(NULL, BAD_ONE_TIME_PRE_KEY, "pqc_new_inbound_session()");
                ret = -1;
            }
        }
    }

    if (ret == 0) {
        // create a session
        session = (Skissm__Session *)malloc(sizeof(Skissm__Session));
        initialise_session(session, msg->e2ee_pack_id, msg->to, msg->from);
        // set the version and session id
        session->version = strdup(msg->version);
        session->session_id = strdup(msg->session_id);

        // identity key
        bob_identity_key = our_ik->asym_key_pair;
        // signed pre-key
        if (old_spk == false) {
            bob_signed_pre_key = our_spk->key_pair;
        } else {
            bob_signed_pre_key = old_spk_data->key_pair;
        }
        session->bob_signed_pre_key_id = bob_signed_pre_key_id;
        // one-time pre-key
        if (x3dh_epoch == 4) {
            bob_one_time_pre_key = our_one_time_pre_key->key_pair;
            // set the one-time pre-key id
            mark_opk_as_used(local_account, our_one_time_pre_key->opk_id);
            get_skissm_plugin()->db_handler.update_one_time_pre_key(address, our_one_time_pre_key->opk_id);
            session->bob_one_time_pre_key_id = our_one_time_pre_key->opk_id;
        } else {
            bob_one_time_pre_key = NULL;
        }

        // establish the associated data
        ad_len = 2 * asym_pub_key_len;
        session->associated_data.len = ad_len;
        session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * ad_len);
        memcpy(session->associated_data.data, msg->alice_identity_key.data, asym_pub_key_len);
        memcpy((session->associated_data.data) + asym_pub_key_len, our_ik->asym_key_pair->public_key.data, asym_pub_key_len);

        // hash the public keys
        hash_input_len = asym_pub_key_len * x3dh_epoch;
        hash_input = (uint8_t *)malloc(sizeof(uint8_t) * hash_input_len);
        memcpy(hash_input, msg->alice_identity_key.data, asym_pub_key_len);
        memcpy(hash_input + asym_pub_key_len, our_ik->asym_key_pair->public_key.data, asym_pub_key_len);
        memcpy(hash_input + asym_pub_key_len + asym_pub_key_len, our_spk->key_pair->public_key.data, asym_pub_key_len);
        if (x3dh_epoch == 4) {
            memcpy(hash_input + asym_pub_key_len + asym_pub_key_len + asym_pub_key_len, bob_one_time_pre_key->public_key.data, asym_pub_key_len);
        }
        uint8_t derived_secrets[2 * shared_key_len];
        uint8_t salt[hash_len];
        memset(salt, 0, hash_len);
        cipher_suite->hash_suite->hkdf(
            hash_input, hash_input_len,
            salt, sizeof(salt),
            (uint8_t *)FINGERPRINT_SEED, sizeof(FINGERPRINT_SEED) - 1,
            derived_secrets, sizeof(derived_secrets)
        );
        copy_protobuf_from_array(&(session->fingerprint), derived_secrets, sizeof(derived_secrets));

        // calculate the shared secret S via KEM
        uint8_t secret[x3dh_epoch * shared_secret_len];
        uint8_t *pos = secret;

        cipher_suite->kem_suite->encaps(pos, &ciphertext_1, &(msg->alice_identity_key));
        pos += shared_secret_len;
        cipher_suite->kem_suite->decaps(pos, &(bob_identity_key->private_key), &(msg->pre_shared_input_list[0]));
        pos += shared_secret_len;
        cipher_suite->kem_suite->decaps(pos, &(bob_signed_pre_key->private_key), &(msg->pre_shared_input_list[1]));
        if (x3dh_epoch == 4) {
            pos += shared_secret_len;
            cipher_suite->kem_suite->decaps(pos, &(bob_one_time_pre_key->private_key), &(msg->pre_shared_input_list[2]));
        }

        ret = initialise_as_bob(&ratchet, cipher_suite, secret, sizeof(secret), bob_signed_pre_key, &(msg->alice_base_key));

        session->responded = true;
        session->invite_t = msg->invite_t;

        // unset the secret
        unset(secret, sizeof(secret));
    }

    if (ret == 0) {
        session->ratchet = ratchet;
        // store sesson state
        get_skissm_plugin()->db_handler.store_session(session);
    }

    if (ret == 0) {
        /** The one who sends the acception message will be the one who received the invitation message.
         *  Thus, the "from" and "to" of acception message will be different from those in the session. */
        ret = accept_internal(
            &accept_response,
            session->e2ee_pack_id,
            session->our_address,
            session->their_address,
            &ciphertext_1,
            &(session->ratchet->sender_chain->our_ratchet_public_key)
        );
    }

    if (ret == 0) {
        *inbound_session_out = session;
    } else {
        free_proto(session);
    }

    // release
    if (old_spk_data != NULL) {
        skissm__signed_pre_key__free_unpacked(old_spk_data, NULL);
        old_spk_data = NULL;
    }
    free_protobuf(&ciphertext_1);
    free_proto(accept_response);

    // done
    return ret;
}

int pqc_complete_outbound_session(Skissm__Session **outbound_session_out, Skissm__AcceptMsg *msg) {
    int ret = 0;

    Skissm__Session *session = NULL;
    cipher_suite_t *cipher_suite = NULL;
    Skissm__Account *account = NULL;
    Skissm__IdentityKey *identity_key = NULL;
    ProtobufCBinaryData their_ratchet_key = {0, NULL};

    if (is_valid_accept_msg(msg)) {
        get_skissm_plugin()->db_handler.load_outbound_session(msg->to, msg->from, &session);
        if (is_valid_uncompleted_session(session)) {
            load_identity_key_from_cache(&identity_key, session->our_address);

            if (identity_key == NULL) {
                get_skissm_plugin()->db_handler.load_account_by_address(session->our_address, &account);
                if (is_valid_registered_account(account)) {
                    copy_ik_from_ik(&identity_key, account->identity_key);
                } else {
                    ssm_notify_log(NULL, BAD_ACCOUNT, "pqc_complete_outbound_session()");
                    ret = -1;
                }
            }
        } else {
            ssm_notify_log(NULL, BAD_SESSION, "pqc_complete_outbound_session()");
            ret = -1;
        }
    } else {
        ssm_notify_log(NULL, BAD_SERVER_MESSAGE, "pqc_complete_outbound_session()");
        ret = -1;
    }

    if (ret == 0) {
        cipher_suite = get_e2ee_pack(session->e2ee_pack_id)->cipher_suite;

        copy_protobuf_from_protobuf(&their_ratchet_key, &(session->ratchet->sender_chain->their_ratchet_public_key));
        skissm__sender_chain_node__free_unpacked(session->ratchet->sender_chain, NULL);
        session->ratchet->sender_chain = NULL;

        session->responded = true;

        // complete the shared secret of the X3DH
        cipher_suite->kem_suite->decaps(
            session->temp_shared_secret.data,
            &(identity_key->asym_key_pair->private_key),
            &(msg->encaps_ciphertext)
        );

        // create the root key and chain keys
        ret = initialise_as_alice(
            &(session->ratchet), cipher_suite,
            session->temp_shared_secret.data, session->temp_shared_secret.len,
            session->alice_base_key, &their_ratchet_key, &(msg->ratchet_key)
        );
    }

    if (ret == 0) {
        *outbound_session_out = session;
        // store sesson state
        get_skissm_plugin()->db_handler.store_session(session);
    } else {
        free_proto(session);
    }

    // release
    free_protobuf(&their_ratchet_key);
    free_proto(account);
    free_proto(identity_key);

    // done
    return ret;
}

session_suite_t E2EE_SESSION_PQC = {
    pqc_new_outbound_session_v2,
    pqc_new_inbound_session,
    pqc_complete_outbound_session
};
