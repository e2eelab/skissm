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
#include "skissm/cipher.h"
#include "skissm/e2ee_client_internal.h"
#include "skissm/error.h"
#include "skissm/group_session.h"
#include "skissm/mem_util.h"
#include "skissm/ratchet.h"

/** length of the shared secret created by a PQC operation */
#define CRYPTO_BYTES_KEY 32

/** length of the ciphertext created by a PQC operation */
#define CRYPTO_CIPHERTEXTBYTES 1039

size_t pqc_new_outbound_session(Skissm__Session *outbound_session, const Skissm__Account *local_account, Skissm__PreKeyBundle *their_pre_key_bundle) {
    const cipher_suite_t *cipher_suite = get_e2ee_pack(outbound_session->e2ee_pack_id)->cipher_suite;
    int key_len = cipher_suite->get_crypto_param().asym_key_len;
    // Verify the signature
    size_t result;
    if ((their_pre_key_bundle->identity_key_public->asym_public_key.len != key_len) || (their_pre_key_bundle->signed_pre_key_public->public_key.len != key_len) ||
        (their_pre_key_bundle->signed_pre_key_public->signature.len != cipher_suite->get_crypto_param().sig_len)) {
        ssm_notify_error(BAD_PRE_KEY_BUNDLE, "pqc_new_outbound_session()");
        return (size_t)(-1);
    }
    result = cipher_suite->verify(their_pre_key_bundle->signed_pre_key_public->signature.data, their_pre_key_bundle->identity_key_public->sign_public_key.data,
                                  their_pre_key_bundle->signed_pre_key_public->public_key.data, key_len);
    if (result < 0) {
        ssm_notify_error(BAD_SIGNATURE, "pqc_new_outbound_session()");
        return (size_t)(-1);
    }

    // Set the version
    outbound_session->version = strdup(E2EE_PROTOCOL_VERSION);
    // Set the cipher suite id
    outbound_session->e2ee_pack_id = strdup(E2EE_PACK_ID_PQC_DEFAULT);

    // Store some information into the session
    const Skissm__KeyPair my_identity_key_pair = *(local_account->identity_key->asym_key_pair);

    uint8_t x3dh_epoch = 2;
    outbound_session->responded = false;
    copy_protobuf_from_protobuf(&(outbound_session->alice_identity_key), &(my_identity_key_pair.public_key));
    copy_protobuf_from_protobuf(&(outbound_session->bob_signed_pre_key), &(their_pre_key_bundle->signed_pre_key_public->public_key));
    outbound_session->bob_signed_pre_key_id = their_pre_key_bundle->signed_pre_key_public->spk_id;

    // Server may return empty one-time pre-key(public)
    if (their_pre_key_bundle->one_time_pre_key_public) {
        copy_protobuf_from_protobuf(&(outbound_session->bob_one_time_pre_key), &(their_pre_key_bundle->one_time_pre_key_public->public_key));
        outbound_session->bob_one_time_pre_key_id = their_pre_key_bundle->one_time_pre_key_public->opk_id;
        x3dh_epoch = 3;
    }

    int ad_len = 2 * key_len;
    outbound_session->associated_data.len = ad_len;
    outbound_session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * ad_len);
    memcpy(outbound_session->associated_data.data, my_identity_key_pair.public_key.data, key_len);
    memcpy((outbound_session->associated_data.data) + key_len, their_pre_key_bundle->identity_key_public->asym_public_key.data, key_len);

    // Calculate the shared secret S via encapsulation
    uint8_t secret[x3dh_epoch * CRYPTO_BYTES_KEY];
    uint8_t *pos = secret;
    ProtobufCBinaryData *ciphertext_2, *ciphertext_3, *ciphertext_4;

    ciphertext_2->len = CRYPTO_CIPHERTEXTBYTES;
    ciphertext_2->data = cipher_suite->ss_key_gen(NULL, &(their_pre_key_bundle->identity_key_public->asym_public_key), pos);
    pos += CRYPTO_BYTES_KEY;
    ciphertext_3->len = CRYPTO_CIPHERTEXTBYTES;
    ciphertext_3->data = cipher_suite->ss_key_gen(NULL, &(their_pre_key_bundle->signed_pre_key_public->public_key), pos);
    if (x3dh_epoch == 3) {
        pos += CRYPTO_BYTES_KEY;
        ciphertext_4->len = CRYPTO_CIPHERTEXTBYTES;
        ciphertext_4->data = cipher_suite->ss_key_gen(NULL, &(their_pre_key_bundle->one_time_pre_key_public->public_key), pos);
    } else{
        ciphertext_4->len = 0;
    }

    // The first part of the shared secret will be determined after receiving the acception message
    outbound_session->alice_ephemeral_key.len = (x3dh_epoch + 1) * CRYPTO_BYTES_KEY;
    outbound_session->alice_ephemeral_key.data = (uint8_t *) malloc(sizeof(uint8_t) * outbound_session->alice_ephemeral_key.len);
    memcpy(outbound_session->alice_ephemeral_key.data + CRYPTO_BYTES_KEY, secret, x3dh_epoch * CRYPTO_BYTES_KEY);

    // Set the session ID
    outbound_session->session_id = generate_uuid_str();

    // store sesson state before send invite
    get_skissm_plugin()->db_handler.store_session(outbound_session);

    // Send the invite request to the peer
    size_t pre_shared_keys_len = 3;
    ProtobufCBinaryData *pre_shared_keys[3] = {ciphertext_2, ciphertext_3, ciphertext_4};
    invite_internal(outbound_session, pre_shared_keys, pre_shared_keys_len);

    // release
    unset(secret, sizeof(secret));

    // done
    return (size_t)(0);
}

size_t pqc_new_inbound_session(Skissm__Session *inbound_session, Skissm__Account *local_account, Skissm__InviteMsg *msg) {
    const cipher_suite_t *cipher_suite = get_e2ee_pack(inbound_session->e2ee_pack_id)->cipher_suite;

    /* Verify the signed pre-key */
    bool old_spk = 0;
    Skissm__SignedPreKey *old_spk_data = NULL;
    if (local_account->signed_pre_key->spk_id != msg->bob_signed_pre_key_id) {
        get_skissm_plugin()->db_handler.load_signed_pre_key(local_account->account_id, msg->bob_signed_pre_key_id, &old_spk_data);
        if (old_spk_data == NULL) {
            ssm_notify_error(BAD_SIGNED_PRE_KEY, "pqc_new_inbound_session()");
            return (size_t)(-1);
        } else {
            old_spk = 1;
        }
    }

    uint8_t x3dh_epoch = 3;
    copy_protobuf_from_protobuf(&(inbound_session->alice_identity_key), &(msg->alice_identity_key));
    inbound_session->bob_signed_pre_key_id = msg->bob_signed_pre_key_id;
    if (old_spk == 0) {
        copy_protobuf_from_protobuf(&(inbound_session->bob_signed_pre_key), &(local_account->signed_pre_key->key_pair->public_key));
    } else {
        copy_protobuf_from_protobuf(&(inbound_session->bob_signed_pre_key), &(old_spk_data->key_pair->public_key));
    }
    if (msg->bob_one_time_pre_key_id != 0) {
        x3dh_epoch = 4;
    }

    int key_len = cipher_suite->get_crypto_param().asym_key_len;
    int ad_len = 2 * key_len;
    inbound_session->associated_data.len = ad_len;
    inbound_session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * ad_len);
    memcpy(inbound_session->associated_data.data, msg->alice_identity_key.data, key_len);
    memcpy((inbound_session->associated_data.data) + key_len, local_account->identity_key->asym_key_pair->public_key.data, key_len);

    /* Mark the one-time pre-key as used */
    const Skissm__OneTimePreKey *our_one_time_pre_key;
    if (x3dh_epoch == 4) {
        our_one_time_pre_key = lookup_one_time_pre_key(local_account, msg->bob_one_time_pre_key_id);

        if (!our_one_time_pre_key) {
            ssm_notify_error(BAD_ONE_TIME_PRE_KEY, "pqc_new_inbound_session()");
            return (size_t)(-1);
        } else {
            mark_opk_as_used(local_account, our_one_time_pre_key->opk_id);
            get_skissm_plugin()->db_handler.update_one_time_pre_key(local_account->account_id, our_one_time_pre_key->opk_id);
            copy_protobuf_from_protobuf(&(inbound_session->bob_one_time_pre_key), &(our_one_time_pre_key->key_pair->public_key));
            inbound_session->bob_one_time_pre_key_id = our_one_time_pre_key->opk_id;
        }
    } else {
        our_one_time_pre_key = NULL;
    }

    const Skissm__KeyPair *bob_identity_key = local_account->identity_key->asym_key_pair;
    const Skissm__KeyPair *bob_signed_pre_key;
    if (old_spk == 0) {
        bob_signed_pre_key = local_account->signed_pre_key->key_pair;
    } else {
        bob_signed_pre_key = old_spk_data->key_pair;
    }
    const Skissm__KeyPair *bob_one_time_pre_key;
    if (x3dh_epoch == 4) {
        bob_one_time_pre_key = our_one_time_pre_key->key_pair;
    } else {
        bob_one_time_pre_key = NULL;
    }

    // Calculate the shared secret S via KEM
    uint8_t secret[x3dh_epoch * CRYPTO_BYTES_KEY];
    uint8_t *pos = secret;
    ProtobufCBinaryData *ciphertext_1;

    ciphertext_1->len = CRYPTO_CIPHERTEXTBYTES;
    ciphertext_1->data = cipher_suite->ss_key_gen(NULL, &(inbound_session->alice_identity_key), pos);
    pos += CRYPTO_BYTES_KEY;
    cipher_suite->ss_key_gen(&(bob_identity_key->private_key), &(msg->pre_shared_keys[0]), pos);
    pos += CRYPTO_BYTES_KEY;
    cipher_suite->ss_key_gen(&(bob_signed_pre_key->private_key), &(msg->pre_shared_keys[1]), pos);
    if (x3dh_epoch == 4) {
        pos += CRYPTO_BYTES_KEY;
        cipher_suite->ss_key_gen(&(bob_one_time_pre_key->private_key), &(msg->pre_shared_keys[2]), pos);
    }

    inbound_session->alice_ephemeral_key.len = x3dh_epoch * CRYPTO_BYTES_KEY;
    inbound_session->alice_ephemeral_key.data = (uint8_t *) malloc(sizeof(uint8_t) * inbound_session->alice_ephemeral_key.len);
    memcpy(inbound_session->alice_ephemeral_key.data, secret, x3dh_epoch * CRYPTO_BYTES_KEY);

    initialise_as_bob(cipher_suite, inbound_session->ratchet, secret, sizeof(secret), bob_signed_pre_key);

    // store sesson state
    get_skissm_plugin()->db_handler.store_session(inbound_session);

    /** The one who sends the acception message will be the one who received the invitation message.
     *  Thus, the "from" and "to" of acception message will be different from those in the session. */
    accept_internal(inbound_session->e2ee_pack_id, inbound_session->to, inbound_session->from, ciphertext_1);

    // release
    skissm__signed_pre_key__free_unpacked(old_spk_data, NULL);
    unset(secret, sizeof(secret));

    // done
    return (size_t)(0);
}

size_t pqc_complete_outbound_session(Skissm__Session *outbound_session, Skissm__AcceptMsg *msg) {
    const cipher_suite_t *cipher_suite = get_e2ee_pack(outbound_session->e2ee_pack_id)->cipher_suite;

    outbound_session->responded = true;

    uint8_t *pos = outbound_session->alice_ephemeral_key.data;
    cipher_suite->ss_key_gen(&(outbound_session->alice_identity_key), &(msg->pre_shared_keys[0]), pos);

    // Create the root key and chain keys(????????????????)
    initialise_as_alice(cipher_suite, outbound_session->ratchet, pos, outbound_session->alice_ephemeral_key.len, NULL, NULL);

    // done
    return (size_t)(0);
}

const session_suite_t E2EE_SESSION_NTRUP_SPHINCS_SHA256_256S_AES256_GCM_SHA256 = {
    pqc_new_outbound_session,
    pqc_new_inbound_session,
    pqc_complete_outbound_session
};
