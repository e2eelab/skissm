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

/** length of the shared secret created by a PQC operation */
#define CRYPTO_BYTES_KEY 32

/** length of the ciphertext created by a PQC operation */
#define CRYPTO_CIPHERTEXTBYTES 1039

size_t pqc_new_outbound_session(Skissm__E2eeSession *session, const Skissm__E2eeAccount *local_account, Skissm__E2eePreKeyBundle *their_pre_key_bundle) {
    int key_len = CIPHER.suite2->get_crypto_param().asym_key_len;
    // Verify the signature
    size_t result;
    if ((their_pre_key_bundle->identity_key_public->asym_public_key.len != key_len) || (their_pre_key_bundle->signed_pre_key_public->public_key.len != key_len) ||
        (their_pre_key_bundle->signed_pre_key_public->signature.len != CIPHER.suite2->get_crypto_param().sig_len)) {
        ssm_notify_error(BAD_PRE_KEY_BUNDLE, "pqc_new_outbound_session()");
        return (size_t)(-1);
    }
    result = CIPHER.suite2->verify(their_pre_key_bundle->signed_pre_key_public->signature.data, their_pre_key_bundle->identity_key_public->sign_public_key.data,
                                  their_pre_key_bundle->signed_pre_key_public->public_key.data, key_len);
    if (result < 0) {
        ssm_notify_error(BAD_SIGNATURE, "pqc_new_outbound_session()");
        return (size_t)(-1);
    }

    // Set the version
    session->version = PROTOCOL_VERSION;

    // Store some information into the session
    const Skissm__KeyPair my_identity_key_pair = *(local_account->identity_key->asym_key_pair);

    uint8_t x3dh_epoch = 2;
    session->responded = false;
    copy_protobuf_from_protobuf(&(session->alice_identity_key), &(my_identity_key_pair.public_key));
    copy_protobuf_from_protobuf(&(session->bob_signed_pre_key), &(their_pre_key_bundle->signed_pre_key_public->public_key));
    session->bob_signed_pre_key_id = their_pre_key_bundle->signed_pre_key_public->spk_id;

    // Server may return empty one-time pre-key(public)
    if (their_pre_key_bundle->one_time_pre_key_public) {
        copy_protobuf_from_protobuf(&(session->bob_one_time_pre_key), &(their_pre_key_bundle->one_time_pre_key_public->public_key));
        session->bob_one_time_pre_key_id = their_pre_key_bundle->one_time_pre_key_public->opk_id;
        x3dh_epoch = 3;
    }

    int ad_len = 2 * key_len;
    session->associated_data.len = ad_len;
    session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * ad_len);
    memcpy(session->associated_data.data, my_identity_key_pair.public_key.data, key_len);
    memcpy((session->associated_data.data) + key_len, their_pre_key_bundle->identity_key_public->asym_public_key.data, key_len);

    // Calculate the shared secret S via encapsulation
    uint8_t secret[x3dh_epoch * CRYPTO_BYTES_KEY];
    uint8_t *pos = secret;
    ProtobufCBinaryData *ciphertext_2, *ciphertext_3, *ciphertext_4;

    ciphertext_2->len = CRYPTO_CIPHERTEXTBYTES;
    ciphertext_2->data = CIPHER.suite2->ss_key_gen(NULL, &(their_pre_key_bundle->identity_key_public->asym_public_key), pos);
    pos += CRYPTO_BYTES_KEY;
    ciphertext_3->len = CRYPTO_CIPHERTEXTBYTES;
    ciphertext_3->data = CIPHER.suite2->ss_key_gen(NULL, &(their_pre_key_bundle->signed_pre_key_public->public_key), pos);
    if (x3dh_epoch == 3) {
        pos += CRYPTO_BYTES_KEY;
        ciphertext_4->len = CRYPTO_CIPHERTEXTBYTES;
        ciphertext_4->data = CIPHER.suite2->ss_key_gen(NULL, &(their_pre_key_bundle->one_time_pre_key_public->public_key), pos);
    } else{
        ciphertext_4->len = 0;
    }

    // The first part of the shared secret will be determined after receiving the acception message
    session->alice_ephemeral_key.len = (x3dh_epoch + 1) * CRYPTO_BYTES_KEY;
    session->alice_ephemeral_key.data = (uint8_t *) malloc(sizeof(uint8_t) * session->alice_ephemeral_key.len);
    memcpy(session->alice_ephemeral_key.data + CRYPTO_BYTES_KEY, secret, x3dh_epoch * CRYPTO_BYTES_KEY);

    // Set the session ID
    session->session_id = generate_uuid_str();

    // Send the invitation message to the other
    send_invite_request(session, ciphertext_2, ciphertext_3, ciphertext_4);

    // release
    unset(secret, sizeof(secret));

    // done
    return (size_t)(0);
}

size_t pqc_new_inbound_session(Skissm__E2eeSession *session, Skissm__E2eeAccount *local_account, Skissm__E2eeMsg *inbound_message) {
    session->version = inbound_message->version;
    session->session_id = strdup(inbound_message->session_id);

    Skissm__E2eeInvitePayload *e2ee_invite_payload = skissm__e2ee_invite_payload__unpack(NULL, inbound_message->payload.len, inbound_message->payload.data);
    /* Verify the signed pre-key */
    bool old_spk = 0;
    Skissm__SignedPreKey *old_spk_data = NULL;
    if (local_account->signed_pre_key->spk_id != e2ee_invite_payload->bob_signed_pre_key_id) {
        get_skissm_plugin()->db_handler.load_signed_pre_key(local_account->account_id, e2ee_invite_payload->bob_signed_pre_key_id, &old_spk_data);
        if (old_spk_data == NULL) {
            ssm_notify_error(BAD_SIGNED_PRE_KEY, "pqc_new_inbound_session()");
            skissm__e2ee_invite_payload__free_unpacked(e2ee_invite_payload, NULL);
            return (size_t)(-1);
        } else {
            old_spk = 1;
        }
    }

    uint8_t x3dh_epoch = 3;
    copy_protobuf_from_protobuf(&(session->alice_identity_key), &(e2ee_invite_payload->alice_identity_key));
    session->bob_signed_pre_key_id = e2ee_invite_payload->bob_signed_pre_key_id;
    if (old_spk == 0) {
        copy_protobuf_from_protobuf(&(session->bob_signed_pre_key), &(local_account->signed_pre_key->key_pair->public_key));
    } else {
        copy_protobuf_from_protobuf(&(session->bob_signed_pre_key), &(old_spk_data->key_pair->public_key));
    }
    if (e2ee_invite_payload->bob_one_time_pre_key_id != 0) {
        x3dh_epoch = 4;
    }

    int key_len = CIPHER.suite2->get_crypto_param().asym_key_len;
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
            ssm_notify_error(BAD_ONE_TIME_PRE_KEY, "pqc_new_inbound_session()");
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

    // Calculate the shared secret S via KEM
    uint8_t secret[x3dh_epoch * CRYPTO_BYTES_KEY];
    uint8_t *pos = secret;
    ProtobufCBinaryData *ciphertext_1;

    ciphertext_1->len = CRYPTO_CIPHERTEXTBYTES;
    ciphertext_1->data = CIPHER.suite2->ss_key_gen(NULL, &(session->alice_identity_key), pos);
    pos += CRYPTO_BYTES_KEY;
    CIPHER.suite2->ss_key_gen(&(bob_identity_key->private_key), &(e2ee_invite_payload->ciphertext2), pos);
    pos += CRYPTO_BYTES_KEY;
    CIPHER.suite2->ss_key_gen(&(bob_signed_pre_key->private_key), &(e2ee_invite_payload->ciphertext3), pos);
    if (x3dh_epoch == 4) {
        pos += CRYPTO_BYTES_KEY;
        CIPHER.suite2->ss_key_gen(&(bob_one_time_pre_key->private_key), &(e2ee_invite_payload->ciphertext4), pos);
    }

    session->alice_ephemeral_key.len = x3dh_epoch * CRYPTO_BYTES_KEY;
    session->alice_ephemeral_key.data = (uint8_t *) malloc(sizeof(uint8_t) * session->alice_ephemeral_key.len);
    memcpy(session->alice_ephemeral_key.data, secret, x3dh_epoch * CRYPTO_BYTES_KEY);

    initialise_as_bob(session->ratchet, secret, sizeof(secret), bob_signed_pre_key);

    send_accept_request(ciphertext_1);

    // release
    skissm__signed_pre_key__free_unpacked(old_spk_data, NULL);
    unset(secret, sizeof(secret));

    // done
    return (size_t)(0);
}

size_t pqc_complete_outbound_session(Skissm__E2eeSession *outbound_session, Skissm__E2eeAcceptPayload *e2ee_accept_payload) {
    uint8_t *pos = outbound_session->alice_ephemeral_key.data;
    CIPHER.suite2->ss_key_gen(&(outbound_session->alice_identity_key), &(e2ee_accept_payload->ciphertext1), pos);

    // Create the root key and chain keys(????????????????)
    initialise_as_alice(outbound_session->ratchet, pos, outbound_session->alice_ephemeral_key.len, NULL, NULL);

    // done
    return (size_t)(0);
}

const struct session_suite PQC_AES256_GCM_SHA256 = {
    pqc_new_outbound_session,
    pqc_new_inbound_session
};
