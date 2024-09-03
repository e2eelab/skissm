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
#include "skissm/group_session.h"
#include "skissm/mem_util.h"
#include "skissm/ratchet.h"

Skissm__InviteResponse *crypto_curve25519_new_outbound_session(
    Skissm__Session *outbound_session, const Skissm__Account *local_account, Skissm__PreKeyBundle *their_pre_key_bundle
) {
    const cipher_suite_t *cipher_suite = get_e2ee_pack(outbound_session->e2ee_pack_id)->cipher_suite;
    int key_len = cipher_suite->kem_suite->get_crypto_param().asym_pub_key_len;
    // verify the signature
    int result;
    if ((their_pre_key_bundle->identity_key_public->asym_public_key.len != key_len)
        || (their_pre_key_bundle->signed_pre_key_public->public_key.len != key_len)
        || (their_pre_key_bundle->signed_pre_key_public->signature.len != cipher_suite->digital_signature_suite->get_crypto_param().sig_len)
    ) {
        ssm_notify_log(outbound_session->our_address, BAD_PRE_KEY_BUNDLE, "crypto_curve25519_new_outbound_session()");
        return NULL;
    }
    result = cipher_suite->digital_signature_suite->verify(
        their_pre_key_bundle->signed_pre_key_public->signature.data,
        their_pre_key_bundle->signed_pre_key_public->signature.len,
        their_pre_key_bundle->signed_pre_key_public->public_key.data, key_len,
        their_pre_key_bundle->identity_key_public->sign_public_key.data
    );
    if (result < 0) {
       ssm_notify_log(outbound_session->our_address, BAD_SIGNATURE, "crypto_curve25519_new_outbound_session()");
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

    // generate a new random ephemeral key pair
    Skissm__KeyPair my_ephemeral_key;
    cipher_suite->kem_suite->asym_key_gen(&my_ephemeral_key.public_key, &my_ephemeral_key.private_key);

    // generate a new random ratchet key pair
    Skissm__KeyPair my_ratchet_key;
    cipher_suite->kem_suite->asym_key_gen(&my_ratchet_key.public_key, &my_ratchet_key.private_key);

    const Skissm__KeyPair my_identity_key_pair = *(local_account->identity_key->asym_key_pair);

    uint8_t x3dh_epoch = 3;
    outbound_session->responded = false;
    outbound_session->n_pre_shared_input_list = 1;
    outbound_session->pre_shared_input_list = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));
    copy_protobuf_from_protobuf(&(outbound_session->pre_shared_input_list[0]), &(my_ephemeral_key.public_key));
    outbound_session->bob_signed_pre_key_id = their_pre_key_bundle->signed_pre_key_public->spk_id;

    copy_key_pair_from_key_pair(&(outbound_session->alice_base_key), &my_ratchet_key);

    // server may return empty one-time pre-key(public)
    if (their_pre_key_bundle->one_time_pre_key_public) {
        outbound_session->bob_one_time_pre_key_id = their_pre_key_bundle->one_time_pre_key_public->opk_id;
        x3dh_epoch = 4;
    }

    int ad_len = 2 * key_len;
    outbound_session->associated_data.len = ad_len;
    outbound_session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * ad_len);
    memcpy(outbound_session->associated_data.data, my_identity_key_pair.public_key.data, key_len);
    memcpy((outbound_session->associated_data.data) + key_len, their_pre_key_bundle->identity_key_public->asym_public_key.data, key_len);

    int shared_secret_len = cipher_suite->kem_suite->get_crypto_param().shared_secret_len;
    // calculate the shared secret S via quadruple ECDH
    uint8_t secret[x3dh_epoch * shared_secret_len];
    uint8_t *pos = secret;

    cipher_suite->kem_suite->decaps(pos, &(my_identity_key_pair.private_key), &(their_pre_key_bundle->signed_pre_key_public->public_key));
    pos += shared_secret_len;
    cipher_suite->kem_suite->decaps(pos, &(my_ephemeral_key.private_key), &(their_pre_key_bundle->identity_key_public->asym_public_key));
    pos += shared_secret_len;
    cipher_suite->kem_suite->decaps(pos, &(my_ephemeral_key.private_key), &(their_pre_key_bundle->signed_pre_key_public->public_key));
    if (x3dh_epoch == 4) {
        pos += shared_secret_len;
        cipher_suite->kem_suite->decaps(pos, &(my_ephemeral_key.private_key), &(their_pre_key_bundle->one_time_pre_key_public->public_key));
    }

    // create the root key and chain keys
    initialise_as_alice(
        &(outbound_session->ratchet), cipher_suite,
        secret, sizeof(secret),
        &my_ratchet_key, &(their_pre_key_bundle->signed_pre_key_public->public_key), NULL
    );

    // store sesson state before send invite
    outbound_session->invite_t = get_skissm_plugin()->common_handler.gen_ts();
    get_skissm_plugin()->db_handler.store_session(outbound_session);

    // send the invite request to the peer
    int ret = SKISSM_RESULT_SUCC;
    Skissm__InviteResponse *response = NULL;
    ret = invite_internal(&response, outbound_session);

    // release
    free_protobuf(&(my_ephemeral_key.private_key));
    free_protobuf(&(my_ephemeral_key.public_key));
    unset((void volatile *)&my_ephemeral_key, sizeof(Skissm__KeyPair));
    free_protobuf(&(my_ratchet_key.private_key));
    free_protobuf(&(my_ratchet_key.public_key));
    unset((void volatile *)&my_ratchet_key, sizeof(Skissm__KeyPair));
    unset(secret, sizeof(secret));

    // done
    return response;
}

int crypto_curve25519_new_inbound_session(Skissm__Session *inbound_session, Skissm__Account *local_account, Skissm__InviteMsg *msg) {
    const cipher_suite_t *cipher_suite = get_e2ee_pack(inbound_session->e2ee_pack_id)->cipher_suite;

    // verify the signed pre-key
    bool old_spk = 0;
    Skissm__SignedPreKey *old_spk_data = NULL;
    if (local_account->signed_pre_key->spk_id != msg->bob_signed_pre_key_id) {
        get_skissm_plugin()->db_handler.load_signed_pre_key(local_account->address, msg->bob_signed_pre_key_id, &old_spk_data);
        if (old_spk_data == NULL) {
            ssm_notify_log(inbound_session->our_address, BAD_SIGNED_PRE_KEY, "crypto_curve25519_new_inbound_session()");
            return -1;
        } else {
            old_spk = 1;
        }
    }

    uint8_t x3dh_epoch = 3;
    inbound_session->n_pre_shared_input_list = msg->n_pre_shared_input_list;
    inbound_session->pre_shared_input_list = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));
    copy_protobuf_from_protobuf(&(inbound_session->pre_shared_input_list[0]), &(msg->pre_shared_input_list[0]));
    inbound_session->bob_signed_pre_key_id = msg->bob_signed_pre_key_id;
    if (msg->bob_one_time_pre_key_id != 0) {
        x3dh_epoch = 4;
    }

    int key_len = cipher_suite->kem_suite->get_crypto_param().asym_pub_key_len;
    int ad_len = 2 * key_len;
    inbound_session->associated_data.len = ad_len;
    inbound_session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * ad_len);
    memcpy(inbound_session->associated_data.data, msg->alice_identity_key.data, key_len);
    memcpy((inbound_session->associated_data.data) + key_len, local_account->identity_key->asym_key_pair->public_key.data, key_len);

    // mark the one-time pre-key as used
    Skissm__OneTimePreKey *our_one_time_pre_key;
    if (x3dh_epoch == 4) {
        our_one_time_pre_key = lookup_one_time_pre_key(local_account, msg->bob_one_time_pre_key_id);

        if (!our_one_time_pre_key) {
            ssm_notify_log(inbound_session->our_address, BAD_ONE_TIME_PRE_KEY, "crypto_curve25519_new_inbound_session()");
            return -1;
        } else {
            mark_opk_as_used(local_account, our_one_time_pre_key->opk_id);
            get_skissm_plugin()->db_handler.update_one_time_pre_key(local_account->address, our_one_time_pre_key->opk_id);
            inbound_session->bob_one_time_pre_key_id = our_one_time_pre_key->opk_id;
        }
    } else {
        our_one_time_pre_key = NULL;
    }

    const Skissm__KeyPair *bob_identity_key = local_account->identity_key->asym_key_pair;
    Skissm__KeyPair *bob_signed_pre_key = NULL;
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

    int shared_secret_len = cipher_suite->kem_suite->get_crypto_param().shared_secret_len;
    // calculate the shared secret S via quadruple DH
    uint8_t secret[x3dh_epoch * shared_secret_len];
    uint8_t *pos = secret;
    cipher_suite->kem_suite->decaps(pos, &(bob_signed_pre_key->private_key), &msg->alice_identity_key);
    pos += shared_secret_len;
    cipher_suite->kem_suite->decaps(pos, &(bob_identity_key->private_key), &inbound_session->pre_shared_input_list[0]);
    pos += shared_secret_len;
    cipher_suite->kem_suite->decaps(pos, &(bob_signed_pre_key->private_key), &inbound_session->pre_shared_input_list[0]);
    if (x3dh_epoch == 4) {
        pos += shared_secret_len;
        cipher_suite->kem_suite->decaps(pos, &(bob_one_time_pre_key->private_key), &inbound_session->pre_shared_input_list[0]);
    }

    initialise_as_bob(&inbound_session->ratchet, cipher_suite, secret, sizeof(secret), bob_signed_pre_key, &(msg->alice_base_key));

    inbound_session->responded = true;

    // this is not a face-to-face session
    inbound_session->f2f = false;

    inbound_session->invite_t = msg->invite_t;

    // store sesson state
    get_skissm_plugin()->db_handler.store_session(inbound_session);

    /** The one who sends the accept message will be the one who received the invitation message.
     *  Thus, the "from" and "to" of acception message will be different from those in the session. */
    int ret = SKISSM_RESULT_SUCC;
    Skissm__AcceptResponse *response = NULL;
    ret = accept_internal(
        &response,
        inbound_session->e2ee_pack_id,
        inbound_session->our_address,
        inbound_session->their_address,
        NULL,
        &(bob_signed_pre_key->public_key)
    );

    // release
    skissm__signed_pre_key__free_unpacked(old_spk_data, NULL);
    unset(secret, sizeof(secret));
    skissm__accept_response__free_unpacked(response, NULL);

    // done
    return 0;
}

int crypto_curve25519_complete_outbound_session(Skissm__Session *outbound_session, Skissm__AcceptMsg *msg) {
    outbound_session->responded = true;

    // done
    return 0;
}

session_suite_t E2EE_SESSION_ECC = {
    // crypto_curve25519_new_outbound_session,
    // crypto_curve25519_new_inbound_session,
    // crypto_curve25519_complete_outbound_session
    NULL,
    NULL,
    NULL
};
