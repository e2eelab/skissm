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
#include "skissm/e2ee_protocol.h"
#include "skissm/error.h"
#include "skissm/group_session.h"
#include "skissm/mem_util.h"
#include "skissm/ratchet.h"

/** length of the shared secret created by a Curve25519 ECDH operation */
#define CURVE25519_SHARED_SECRET_LENGTH 32

size_t crypto_curve25519_new_outbound_session(Skissm__E2eeSession *session, const Skissm__E2eeAccount *local_account, Skissm__E2eePreKeyBundle *their_pre_key_bundle) {
    const cipher_suite_t *cipher_suite = get_e2ee_pack(session->e2ee_pack_id)->cipher_suite;
    int key_len = cipher_suite->get_crypto_param().asym_key_len;
    // Verify the signature
    size_t result;
    if ((their_pre_key_bundle->identity_key_public->asym_public_key.len != key_len) || (their_pre_key_bundle->signed_pre_key_public->public_key.len != key_len) ||
        (their_pre_key_bundle->signed_pre_key_public->signature.len != cipher_suite->get_crypto_param().sig_len)) {
        ssm_notify_error(BAD_PRE_KEY_BUNDLE, "crypto_curve25519_new_outbound_session()");
        return (size_t)(-1);
    }
    result = cipher_suite->verify(their_pre_key_bundle->signed_pre_key_public->signature.data, their_pre_key_bundle->identity_key_public->sign_public_key.data,
                                  their_pre_key_bundle->signed_pre_key_public->public_key.data, key_len);
    if (result < 0) {
        ssm_notify_error(BAD_SIGNATURE, "crypto_curve25519_new_outbound_session()");
        return (size_t)(-1);
    }

    // Set the version
    session->version = PROTOCOL_VERSION;
    // Set the cipher suite id
    session->e2ee_pack_id = 0;

    // Generate a new random ephemeral key pair
    Skissm__KeyPair my_ephemeral_key;
    cipher_suite->asym_key_gen(&(my_ephemeral_key.public_key), &(my_ephemeral_key.private_key));

    // Generate a new random ratchet key pair
    Skissm__KeyPair my_ratchet_key;
    cipher_suite->asym_key_gen(&(my_ratchet_key.public_key), &(my_ratchet_key.private_key));

    const Skissm__KeyPair my_identity_key_pair = *(local_account->identity_key->asym_key_pair);

    uint8_t x3dh_epoch = 3;
    session->responded = false;
    copy_protobuf_from_protobuf(&(session->alice_identity_key), &(my_identity_key_pair.public_key));
    copy_protobuf_from_protobuf(&(session->alice_ephemeral_key), &(my_ephemeral_key.public_key));
    copy_protobuf_from_protobuf(&(session->bob_signed_pre_key), &(their_pre_key_bundle->signed_pre_key_public->public_key));
    session->bob_signed_pre_key_id = their_pre_key_bundle->signed_pre_key_public->spk_id;

    // server may return empty one-time pre-key(public)
    if (their_pre_key_bundle->one_time_pre_key_public) {
        copy_protobuf_from_protobuf(&(session->bob_one_time_pre_key), &(their_pre_key_bundle->one_time_pre_key_public->public_key));
        session->bob_one_time_pre_key_id = their_pre_key_bundle->one_time_pre_key_public->opk_id;
        x3dh_epoch = 4;
    }

    int ad_len = 2 * key_len;
    session->associated_data.len = ad_len;
    session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * ad_len);
    memcpy(session->associated_data.data, my_identity_key_pair.public_key.data, key_len);
    memcpy((session->associated_data.data) + key_len, their_pre_key_bundle->identity_key_public->asym_public_key.data, key_len);

    // Calculate the shared secret S via quadruple ECDH
    uint8_t secret[x3dh_epoch * CURVE25519_SHARED_SECRET_LENGTH];
    uint8_t *pos = secret;

    cipher_suite->ss_key_gen(&(my_identity_key_pair.private_key), &(their_pre_key_bundle->signed_pre_key_public->public_key), pos);
    pos += CURVE25519_SHARED_SECRET_LENGTH;
    cipher_suite->ss_key_gen(&(my_ephemeral_key.private_key), &(their_pre_key_bundle->identity_key_public->asym_public_key), pos);
    pos += CURVE25519_SHARED_SECRET_LENGTH;
    cipher_suite->ss_key_gen(&(my_ephemeral_key.private_key), &(their_pre_key_bundle->signed_pre_key_public->public_key), pos);
    if (x3dh_epoch == 4) {
        pos += CURVE25519_SHARED_SECRET_LENGTH;
        cipher_suite->ss_key_gen(&(my_ephemeral_key.private_key), &(their_pre_key_bundle->one_time_pre_key_public->public_key), pos);
    }

    // Create the root key and chain keys
    initialise_as_alice(cipher_suite, session->ratchet, secret, sizeof(secret), &my_ratchet_key, &(their_pre_key_bundle->signed_pre_key_public->public_key));
    session->session_id = generate_uuid_str();

    // store sesson state
    get_skissm_plugin()->db_handler.store_session(session);

    send_invite_request(session, &(session->alice_ephemeral_key), NULL, NULL);

    // release
    free_protobuf(&(my_ephemeral_key.private_key));
    free_protobuf(&(my_ephemeral_key.public_key));
    unset((void volatile *)&my_ephemeral_key, sizeof(Skissm__KeyPair));
    free_protobuf(&(my_ratchet_key.private_key));
    free_protobuf(&(my_ratchet_key.public_key));
    unset((void volatile *)&my_ratchet_key, sizeof(Skissm__KeyPair));
    unset(secret, sizeof(secret));

    // done
    return (size_t)(0);
}

size_t crypto_curve25519_new_inbound_session(Skissm__E2eeSession *session, Skissm__E2eeAccount *local_account, Skissm__E2eeInvitePayload *e2ee_invite_payload) {
    const cipher_suite_t *cipher_suite = get_e2ee_pack(session->e2ee_pack_id)->cipher_suite;

    /* Verify the signed pre-key */
    bool old_spk = 0;
    Skissm__SignedPreKey *old_spk_data = NULL;
    if (local_account->signed_pre_key->spk_id != e2ee_invite_payload->bob_signed_pre_key_id) {
        get_skissm_plugin()->db_handler.load_signed_pre_key(local_account->account_id, e2ee_invite_payload->bob_signed_pre_key_id, &old_spk_data);
        if (old_spk_data == NULL) {
            ssm_notify_error(BAD_SIGNED_PRE_KEY, "crypto_curve25519_new_inbound_session()");
            skissm__e2ee_invite_payload__free_unpacked(e2ee_invite_payload, NULL);
            return (size_t)(-1);
        } else {
            old_spk = 1;
        }
    }

    uint8_t x3dh_epoch = 3;
    copy_protobuf_from_protobuf(&(session->alice_identity_key), &(e2ee_invite_payload->alice_identity_key));
    copy_protobuf_from_protobuf(&(session->alice_ephemeral_key), e2ee_invite_payload->pre_shared_key);
    session->bob_signed_pre_key_id = e2ee_invite_payload->bob_signed_pre_key_id;
    if (old_spk == 0) {
        copy_protobuf_from_protobuf(&(session->bob_signed_pre_key), &(local_account->signed_pre_key->key_pair->public_key));
    } else {
        copy_protobuf_from_protobuf(&(session->bob_signed_pre_key), &(old_spk_data->key_pair->public_key));
    }
    if (e2ee_invite_payload->bob_one_time_pre_key_id != 0) {
        x3dh_epoch = 4;
    }

    int key_len = cipher_suite->get_crypto_param().asym_key_len;
    int ad_len = 2 * key_len;
    session->associated_data.len = ad_len;
    session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * ad_len);
    memcpy(session->associated_data.data, e2ee_invite_payload->alice_identity_key.data, key_len);
    memcpy((session->associated_data.data) + key_len, local_account->identity_key->asym_key_pair->public_key.data, key_len);

    /* Mark the one-time pre-key as used */
    const Skissm__OneTimePreKey *our_one_time_pre_key;
    if (x3dh_epoch == 4) {
        our_one_time_pre_key = lookup_one_time_pre_key(local_account, e2ee_invite_payload->bob_one_time_pre_key_id);

        if (!our_one_time_pre_key) {
            ssm_notify_error(BAD_ONE_TIME_PRE_KEY, "crypto_curve25519_new_inbound_session()");
            skissm__e2ee_invite_payload__free_unpacked(e2ee_invite_payload, NULL);
            return (size_t)(-1);
        } else {
            mark_opk_as_used(local_account, our_one_time_pre_key->opk_id);
            get_skissm_plugin()->db_handler.update_one_time_pre_key(local_account->account_id, our_one_time_pre_key->opk_id);
            copy_protobuf_from_protobuf(&(session->bob_one_time_pre_key), &(our_one_time_pre_key->key_pair->public_key));
            session->bob_one_time_pre_key_id = our_one_time_pre_key->opk_id;
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

    // Calculate the shared secret S via quadruple DH
    uint8_t secret[x3dh_epoch * CURVE25519_SHARED_SECRET_LENGTH];
    uint8_t *pos = secret;
    cipher_suite->ss_key_gen(&(bob_signed_pre_key->private_key), &session->alice_identity_key, pos);
    pos += CURVE25519_SHARED_SECRET_LENGTH;
    cipher_suite->ss_key_gen(&(bob_identity_key->private_key), &session->alice_ephemeral_key, pos);
    pos += CURVE25519_SHARED_SECRET_LENGTH;
    cipher_suite->ss_key_gen(&(bob_signed_pre_key->private_key), &session->alice_ephemeral_key, pos);
    if (x3dh_epoch == 4) {
        pos += CURVE25519_SHARED_SECRET_LENGTH;
        cipher_suite->ss_key_gen(&(bob_one_time_pre_key->private_key), &session->alice_ephemeral_key, pos);
    }

    initialise_as_bob(cipher_suite, session->ratchet, secret, sizeof(secret), bob_signed_pre_key);

    /** The one who sends the acception message will be the one who received the invitation message.
     *  Thus, the "from" and "to" of acception message will be different from those in the session. */    
    send_accept_request(session->e2ee_pack_id, session->to, session->from, NULL);

    // release
    skissm__signed_pre_key__free_unpacked(old_spk_data, NULL);
    unset(secret, sizeof(secret));

    // done
    return (size_t)(0);
}

size_t crypto_curve25519_complete_outbound_session(Skissm__E2eeSession *outbound_session, Skissm__E2eeAcceptPayload *e2ee_accept_payload) {
    outbound_session->responded = true;

    // done
    return (size_t)(0);
}

const session_suite_t E2EE_SESSION_ECDH_X25519_AES256_GCM_SHA256 = {
    crypto_curve25519_new_outbound_session,
    crypto_curve25519_new_inbound_session,
    crypto_curve25519_complete_outbound_session
};
