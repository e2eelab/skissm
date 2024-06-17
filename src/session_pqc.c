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

static const char FINGERPRINT_SEED[] = "Fingerprint";

Skissm__InviteResponse *pqc_new_outbound_session(
    Skissm__Session *outbound_session, const Skissm__Account *local_account, Skissm__PreKeyBundle *their_pre_key_bundle
) {
    Skissm__IdentityKeyPublic *their_ik = their_pre_key_bundle->identity_key_public;
    Skissm__SignedPreKeyPublic *their_spk = their_pre_key_bundle->signed_pre_key_public;
    Skissm__OneTimePreKeyPublic *their_opk = their_pre_key_bundle->one_time_pre_key_public;

    const cipher_suite_t *cipher_suite = get_e2ee_pack(outbound_session->e2ee_pack_id)->cipher_suite;
    int key_len = cipher_suite->kem_suite->get_crypto_param().asym_pub_key_len;
    // verify the signature
    int result;
    if ((their_ik->asym_public_key.len != key_len)
        || (their_spk->public_key.len != key_len)
        || (their_spk->signature.len != cipher_suite->digital_signature_suite->get_crypto_param().sig_len)
    ) {
        ssm_notify_log(NULL, BAD_PRE_KEY_BUNDLE, "pqc_new_outbound_session()");
        return NULL;
    }
    result = cipher_suite->digital_signature_suite->verify(
        their_spk->signature.data, their_spk->signature.len,
        their_spk->public_key.data, key_len,
        their_ik->sign_public_key.data
    );
    if (result < 0) {
        ssm_notify_log(outbound_session->our_address, BAD_SIGNATURE, "pqc_new_outbound_session()");
        return NULL;
    }

    // set the version
    outbound_session->version = strdup(E2EE_PROTOCOL_VERSION);
    // set the cipher suite id
    outbound_session->e2ee_pack_id = local_account->e2ee_pack_id;
    // set the session ID
    outbound_session->session_id = generate_uuid_str();
    // set session not verified
    outbound_session->f2f = false;

    // store some information into the session
    Skissm__KeyPair *my_identity_key_pair = local_account->identity_key->asym_key_pair;

    uint8_t x3dh_epoch = 2;
    outbound_session->responded = false;
    outbound_session->bob_signed_pre_key_id = their_spk->spk_id;
    outbound_session->ratchet->sender_chain = (Skissm__SenderChainNode *)malloc(sizeof(Skissm__SenderChainNode));
    skissm__sender_chain_node__init(outbound_session->ratchet->sender_chain);
    copy_protobuf_from_protobuf(&(outbound_session->ratchet->sender_chain->their_ratchet_public_key), &(their_spk->public_key));

    // server may return empty one-time pre-key(public)
    if (their_opk) {
        outbound_session->bob_one_time_pre_key_id = their_opk->opk_id;
        x3dh_epoch = 3;
    }

    int ad_len = 2 * key_len;
    outbound_session->associated_data.len = ad_len;
    outbound_session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * ad_len);
    memcpy(outbound_session->associated_data.data, my_identity_key_pair->public_key.data, key_len);
    memcpy((outbound_session->associated_data.data) + key_len, their_ik->asym_public_key.data, key_len);

    // hash the public keys
    int hash_input_len = key_len * (x3dh_epoch + 1);
    uint8_t *hash_input = (uint8_t *)malloc(sizeof(uint8_t) * hash_input_len);
    memcpy(hash_input, my_identity_key_pair->public_key.data, key_len);
    memcpy(hash_input + key_len, their_ik->asym_public_key.data, key_len);
    memcpy(hash_input + key_len + key_len, their_spk->public_key.data, key_len);
    if (x3dh_epoch == 3)
        memcpy(hash_input + key_len + key_len + key_len, their_opk->public_key.data, key_len);

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
    ProtobufCBinaryData *ciphertext_2, *ciphertext_3, *ciphertext_4;
    ciphertext_2 = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));
    ciphertext_3 = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));
    ciphertext_4 = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));

    uint32_t ciphertext_len = cipher_suite->kem_suite->get_crypto_param().kem_ciphertext_len;

    ciphertext_2->len = ciphertext_len;
    ciphertext_2->data = cipher_suite->kem_suite->ss_key_gen(NULL, &(their_ik->asym_public_key), pos);
    pos += shared_secret_len;
    ciphertext_3->len = ciphertext_len;
    ciphertext_3->data = cipher_suite->kem_suite->ss_key_gen(NULL, &(their_spk->public_key), pos);
    if (x3dh_epoch == 3) {
        pos += shared_secret_len;
        ciphertext_4->len = ciphertext_len;
        ciphertext_4->data = cipher_suite->kem_suite->ss_key_gen(NULL, &(their_opk->public_key), pos);
    } else{
        ciphertext_4->len = 0;
        ciphertext_4->data = NULL;
    }

    // the first part of the shared secret will be determined after receiving the acception message
    char zero_array[shared_secret_len];
    memset(zero_array, 0, shared_secret_len);
    outbound_session->temp_shared_secret.len = (x3dh_epoch + 1) * shared_secret_len;
    outbound_session->temp_shared_secret.data = (uint8_t *) malloc(sizeof(uint8_t) * outbound_session->temp_shared_secret.len);
    memcpy(outbound_session->temp_shared_secret.data, zero_array, shared_secret_len);
    memcpy(outbound_session->temp_shared_secret.data + shared_secret_len, secret, x3dh_epoch * shared_secret_len);

    // prepare the encaps_ciphertext_list
    outbound_session->n_pre_shared_input_list = x3dh_epoch;
    outbound_session->pre_shared_input_list = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData) * x3dh_epoch);
    init_protobuf(&(outbound_session->pre_shared_input_list[0]));
    copy_protobuf_from_protobuf(&(outbound_session->pre_shared_input_list[0]), ciphertext_2);
    init_protobuf(&(outbound_session->pre_shared_input_list[1]));
    copy_protobuf_from_protobuf(&(outbound_session->pre_shared_input_list[1]), ciphertext_3);
    if (x3dh_epoch == 3) {
        init_protobuf(&(outbound_session->pre_shared_input_list[2]));
        copy_protobuf_from_protobuf(&(outbound_session->pre_shared_input_list[2]), ciphertext_4);
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
    Skissm__InviteResponse *response = invite_internal(outbound_session);

    // release
    unset(secret, sizeof(secret));
    free_mem((void **)&ciphertext_2, sizeof(ProtobufCBinaryData));
    free_mem((void **)&ciphertext_3, sizeof(ProtobufCBinaryData));
    free_mem((void **)&ciphertext_4, sizeof(ProtobufCBinaryData));

    // done
    return response;
}

int pqc_new_inbound_session(Skissm__Session *inbound_session, Skissm__Account *local_account, Skissm__InviteMsg *msg) {
    Skissm__IdentityKey *our_ik = local_account->identity_key;
    Skissm__SignedPreKey *our_spk = local_account->signed_pre_key;

    const cipher_suite_t *cipher_suite = get_e2ee_pack(inbound_session->e2ee_pack_id)->cipher_suite;

    // verify the signed pre-key
    bool old_spk = 0;
    Skissm__SignedPreKey *old_spk_data = NULL;
    if (our_spk->spk_id != msg->bob_signed_pre_key_id) {
        get_skissm_plugin()->db_handler.load_signed_pre_key(local_account->address, msg->bob_signed_pre_key_id, &old_spk_data);
        if (old_spk_data == NULL) {
            ssm_notify_log(NULL, BAD_SIGNED_PRE_KEY, "pqc_new_inbound_session()");
            return -1;
        } else {
            old_spk = 1;
        }
    }

    uint8_t x3dh_epoch = 3;
    inbound_session->bob_signed_pre_key_id = msg->bob_signed_pre_key_id;
    if (msg->bob_one_time_pre_key_id != 0) {
        x3dh_epoch = 4;
    }

    int key_len = cipher_suite->kem_suite->get_crypto_param().asym_pub_key_len;
    int ad_len = 2 * key_len;
    inbound_session->associated_data.len = ad_len;
    inbound_session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * ad_len);
    memcpy(inbound_session->associated_data.data, msg->alice_identity_key.data, key_len);
    memcpy((inbound_session->associated_data.data) + key_len, our_ik->asym_key_pair->public_key.data, key_len);

    // mark the one-time pre-key as used
    const Skissm__OneTimePreKey *our_one_time_pre_key;
    if (x3dh_epoch == 4) {
        our_one_time_pre_key = lookup_one_time_pre_key(local_account, msg->bob_one_time_pre_key_id);

        if (!our_one_time_pre_key) {
            ssm_notify_log(NULL, BAD_ONE_TIME_PRE_KEY, "pqc_new_inbound_session()");

            // release
            skissm__signed_pre_key__free_unpacked(old_spk_data, NULL);

            return -1;
        } else {
            mark_opk_as_used(local_account, our_one_time_pre_key->opk_id);
            get_skissm_plugin()->db_handler.update_one_time_pre_key(local_account->address, our_one_time_pre_key->opk_id);
            inbound_session->bob_one_time_pre_key_id = our_one_time_pre_key->opk_id;
        }
    } else {
        our_one_time_pre_key = NULL;
    }

    const Skissm__KeyPair *bob_identity_key = our_ik->asym_key_pair;
    const Skissm__KeyPair *bob_signed_pre_key;
    if (old_spk == 0) {
        bob_signed_pre_key = our_spk->key_pair;
    } else {
        bob_signed_pre_key = old_spk_data->key_pair;
    }
    const Skissm__KeyPair *bob_one_time_pre_key;
    if (x3dh_epoch == 4) {
        bob_one_time_pre_key = our_one_time_pre_key->key_pair;
    } else {
        bob_one_time_pre_key = NULL;
    }

    // hash the public keys
    int hash_input_len = key_len * x3dh_epoch;
    uint8_t *hash_input = (uint8_t *)malloc(sizeof(uint8_t) * hash_input_len);
    memcpy(hash_input, msg->alice_identity_key.data, key_len);
    memcpy(hash_input + key_len, our_ik->asym_key_pair->public_key.data, key_len);
    memcpy(hash_input + key_len + key_len, our_spk->key_pair->public_key.data, key_len);
    if (x3dh_epoch == 4)
        memcpy(hash_input + key_len + key_len + key_len, bob_one_time_pre_key->public_key.data, key_len);

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

    copy_protobuf_from_array(&(inbound_session->fingerprint), derived_secrets, sizeof(derived_secrets));

    int shared_secret_len = cipher_suite->kem_suite->get_crypto_param().shared_secret_len;
    // calculate the shared secret S via KEM
    uint8_t secret[x3dh_epoch * shared_secret_len];
    uint8_t *pos = secret;
    ProtobufCBinaryData *ciphertext_1 = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));

    uint32_t ciphertext_len = cipher_suite->kem_suite->get_crypto_param().kem_ciphertext_len;

    ciphertext_1->len = ciphertext_len;
    ciphertext_1->data = cipher_suite->kem_suite->ss_key_gen(NULL, &(msg->alice_identity_key), pos);
    pos += shared_secret_len;
    cipher_suite->kem_suite->ss_key_gen(&(bob_identity_key->private_key), &(msg->pre_shared_input_list[0]), pos);
    pos += shared_secret_len;
    cipher_suite->kem_suite->ss_key_gen(&(bob_signed_pre_key->private_key), &(msg->pre_shared_input_list[1]), pos);
    if (x3dh_epoch == 4) {
        pos += shared_secret_len;
        cipher_suite->kem_suite->ss_key_gen(&(bob_one_time_pre_key->private_key), &(msg->pre_shared_input_list[2]), pos);
    }

    initialise_as_bob(cipher_suite, inbound_session->ratchet, secret, sizeof(secret), bob_signed_pre_key, &(msg->alice_base_key));

    inbound_session->responded = true;

    inbound_session->invite_t = msg->invite_t;

    // store sesson state
    get_skissm_plugin()->db_handler.store_session(inbound_session);

    /** The one who sends the acception message will be the one who received the invitation message.
     *  Thus, the "from" and "to" of acception message will be different from those in the session. */
    Skissm__AcceptResponse *response = accept_internal(
        inbound_session->e2ee_pack_id,
        inbound_session->our_address,
        inbound_session->their_address,
        ciphertext_1,
        &(inbound_session->ratchet->sender_chain->our_ratchet_public_key)
    );

    // release
    skissm__signed_pre_key__free_unpacked(old_spk_data, NULL);
    unset(secret, sizeof(secret));
    free_mem((void **)&ciphertext_1, sizeof(ProtobufCBinaryData));
    skissm__accept_response__free_unpacked(response, NULL);

    // done
    return 0;
}

int pqc_complete_outbound_session(Skissm__Session *outbound_session, Skissm__AcceptMsg *msg) {
    ssm_notify_log(NULL, DEBUG_LOG, "pqc_complete_outbound_session()");
    const cipher_suite_t *cipher_suite = get_e2ee_pack(outbound_session->e2ee_pack_id)->cipher_suite;

    if (outbound_session->temp_shared_secret.data == NULL) {
        ssm_notify_log(NULL, BAD_SESSION, "pqc_complete_outbound_session()");
        return -1;
    }

    ProtobufCBinaryData *their_ratchet_key = NULL;
    if (outbound_session->ratchet->sender_chain != NULL) {
        if (outbound_session->ratchet->sender_chain->their_ratchet_public_key.data != NULL) {
            their_ratchet_key = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));
            copy_protobuf_from_protobuf(their_ratchet_key, &(outbound_session->ratchet->sender_chain->their_ratchet_public_key));

            skissm__sender_chain_node__free_unpacked(outbound_session->ratchet->sender_chain, NULL);
            outbound_session->ratchet->sender_chain = NULL;
        } else {
            ssm_notify_log(NULL, BAD_SESSION, "pqc_complete_outbound_session()");
            return -1;
        }
    } else {
        ssm_notify_log(NULL, BAD_SESSION, "pqc_complete_outbound_session()");
        return -1;
    }

    outbound_session->responded = true;

    // load account to get the private identity key
    Skissm__Account *account = NULL;
    Skissm__IdentityKey *identity_key = NULL;

    load_identity_key_from_cache(&identity_key, outbound_session->our_address);

    if (identity_key == NULL) {
        get_skissm_plugin()->db_handler.load_account_by_address(outbound_session->our_address, &account);
        if (account == NULL) {
            // release
            free_protobuf(their_ratchet_key);
            free_mem((void **)&their_ratchet_key, sizeof(ProtobufCBinaryData));

            ssm_notify_log(NULL, BAD_ACCOUNT, "pqc_complete_outbound_session()");
            return -1;
        }
        copy_ik_from_ik(&identity_key, account->identity_key);
    }

    // complete the shared secret of the X3DH
    cipher_suite->kem_suite->ss_key_gen(&(identity_key->asym_key_pair->private_key), &(msg->encaps_ciphertext), outbound_session->temp_shared_secret.data);

    // create the root key and chain keys
    initialise_as_alice(
        cipher_suite, outbound_session->ratchet,
        outbound_session->temp_shared_secret.data, outbound_session->temp_shared_secret.len,
        outbound_session->alice_base_key, their_ratchet_key, &(msg->ratchet_key)
    );

    // release
    free_protobuf(their_ratchet_key);
    free_mem((void **)&their_ratchet_key, sizeof(ProtobufCBinaryData));
    if (account != NULL) {
        skissm__account__free_unpacked(account, NULL);
        account = NULL;
    }

    // done
    return 0;
}

session_suite_t E2EE_SESSION_PQC = {
    pqc_new_outbound_session,
    pqc_new_inbound_session,
    pqc_complete_outbound_session
};
