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

/** length of the shared secret created by a Curve25519 ECDH operation */
#define CURVE25519_SHARED_SECRET_LENGTH 32

Skissm__InviteResponse *crypto_curve25519_new_outbound_session(Skissm__Session *outbound_session, const Skissm__Account *local_account, Skissm__PreKeyBundle *their_pre_key_bundle) {
    const cipher_suite_t *cipher_suite = get_e2ee_pack(outbound_session->e2ee_pack_id)->cipher_suite;
    int key_len = cipher_suite->get_crypto_param().asym_key_len;
    // verify the signature
    size_t result;
    if ((their_pre_key_bundle->identity_key_public->asym_public_key.len != key_len) || (their_pre_key_bundle->signed_pre_key_public->public_key.len != key_len) ||
        (their_pre_key_bundle->signed_pre_key_public->signature.len != cipher_suite->get_crypto_param().sig_len)) {
        ssm_notify_error(BAD_PRE_KEY_BUNDLE, "crypto_curve25519_new_outbound_session()");
        return NULL;
    }
    result = cipher_suite->verify(their_pre_key_bundle->signed_pre_key_public->signature.data, their_pre_key_bundle->identity_key_public->sign_public_key.data,
                                  their_pre_key_bundle->signed_pre_key_public->public_key.data, key_len);
    if (result < 0) {
        ssm_notify_error(BAD_SIGNATURE, "crypto_curve25519_new_outbound_session()");
        return NULL;
    }

    // set the version
    outbound_session->version = strdup(E2EE_PROTOCOL_VERSION);
    // set the cipher suite id
    outbound_session->e2ee_pack_id = strdup(E2EE_PACK_ID_ECC_DEFAULT);

    // generate a new random ephemeral key pair
    Skissm__KeyPair my_ephemeral_key;
    cipher_suite->asym_key_gen(&(my_ephemeral_key.public_key), &(my_ephemeral_key.private_key));

    // generate a new random ratchet key pair
    Skissm__KeyPair my_ratchet_key;
    cipher_suite->asym_key_gen(&(my_ratchet_key.public_key), &(my_ratchet_key.private_key));

    const Skissm__KeyPair my_identity_key_pair = *(local_account->identity_key->asym_key_pair);

    uint8_t x3dh_epoch = 3;
    outbound_session->responded = false;
    copy_protobuf_from_protobuf(&(outbound_session->alice_identity_key), &(my_identity_key_pair.public_key));
    copy_protobuf_from_protobuf(&(outbound_session->alice_ephemeral_key), &(my_ephemeral_key.public_key));
    copy_protobuf_from_protobuf(&(outbound_session->bob_signed_pre_key), &(their_pre_key_bundle->signed_pre_key_public->public_key));
    outbound_session->bob_signed_pre_key_id = their_pre_key_bundle->signed_pre_key_public->spk_id;

    // server may return empty one-time pre-key(public)
    if (their_pre_key_bundle->one_time_pre_key_public) {
        copy_protobuf_from_protobuf(&(outbound_session->bob_one_time_pre_key), &(their_pre_key_bundle->one_time_pre_key_public->public_key));
        outbound_session->bob_one_time_pre_key_id = their_pre_key_bundle->one_time_pre_key_public->opk_id;
        x3dh_epoch = 4;
    }

    int ad_len = 2 * key_len;
    outbound_session->associated_data.len = ad_len;
    outbound_session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * ad_len);
    memcpy(outbound_session->associated_data.data, my_identity_key_pair.public_key.data, key_len);
    memcpy((outbound_session->associated_data.data) + key_len, their_pre_key_bundle->identity_key_public->asym_public_key.data, key_len);

    // calculate the shared secret S via quadruple ECDH
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

    // create the root key and chain keys
    initialise_as_alice(cipher_suite, outbound_session->ratchet, secret, sizeof(secret), &my_ratchet_key, &(their_pre_key_bundle->signed_pre_key_public->public_key));
    outbound_session->session_id = generate_uuid_str();

    // this is not a face-to-face session
    outbound_session->f2f = false;

    // store sesson state before send invite
    get_skissm_plugin()->db_handler.store_session(outbound_session);

    // the pre_shared_keys is an array with only one element in it
    ProtobufCBinaryData *pre_shared_keys[1] = {&(outbound_session->alice_ephemeral_key)};
    // send the invite request to the peer
    Skissm__InviteResponse *response = invite_internal(outbound_session, pre_shared_keys, 1);

    if (response == NULL || response->code != SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
        // unload outbound_session to enable retry
        get_skissm_plugin()->db_handler.unload_session(outbound_session->session_owner, outbound_session->from, outbound_session->to);
    }

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

size_t crypto_curve25519_new_inbound_session(Skissm__Session *inbound_session, Skissm__Account *local_account, Skissm__InviteMsg *msg) {
    const cipher_suite_t *cipher_suite = get_e2ee_pack(inbound_session->e2ee_pack_id)->cipher_suite;

    // verify the signed pre-key
    bool old_spk = 0;
    Skissm__SignedPreKey *old_spk_data = NULL;
    if (local_account->signed_pre_key->spk_id != msg->bob_signed_pre_key_id) {
        get_skissm_plugin()->db_handler.load_signed_pre_key(local_account->account_id, msg->bob_signed_pre_key_id, &old_spk_data);
        if (old_spk_data == NULL) {
            ssm_notify_error(BAD_SIGNED_PRE_KEY, "crypto_curve25519_new_inbound_session()");
            return (size_t)(-1);
        } else {
            old_spk = 1;
        }
    }

    uint8_t x3dh_epoch = 3;
    copy_protobuf_from_protobuf(&(inbound_session->alice_identity_key), &(msg->alice_identity_key));
    copy_protobuf_from_protobuf(&(inbound_session->alice_ephemeral_key), &(msg->pre_shared_keys[0]));
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

    // mark the one-time pre-key as used
    const Skissm__OneTimePreKey *our_one_time_pre_key;
    if (x3dh_epoch == 4) {
        our_one_time_pre_key = lookup_one_time_pre_key(local_account, msg->bob_one_time_pre_key_id);

        if (!our_one_time_pre_key) {
            ssm_notify_error(BAD_ONE_TIME_PRE_KEY, "crypto_curve25519_new_inbound_session()");
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

    // calculate the shared secret S via quadruple DH
    uint8_t secret[x3dh_epoch * CURVE25519_SHARED_SECRET_LENGTH];
    uint8_t *pos = secret;
    cipher_suite->ss_key_gen(&(bob_signed_pre_key->private_key), &inbound_session->alice_identity_key, pos);
    pos += CURVE25519_SHARED_SECRET_LENGTH;
    cipher_suite->ss_key_gen(&(bob_identity_key->private_key), &inbound_session->alice_ephemeral_key, pos);
    pos += CURVE25519_SHARED_SECRET_LENGTH;
    cipher_suite->ss_key_gen(&(bob_signed_pre_key->private_key), &inbound_session->alice_ephemeral_key, pos);
    if (x3dh_epoch == 4) {
        pos += CURVE25519_SHARED_SECRET_LENGTH;
        cipher_suite->ss_key_gen(&(bob_one_time_pre_key->private_key), &inbound_session->alice_ephemeral_key, pos);
    }

    initialise_as_bob(cipher_suite, inbound_session->ratchet, secret, sizeof(secret), bob_signed_pre_key);

    // this is not a face-to-face session
    inbound_session->f2f = false;

    // store sesson state
    get_skissm_plugin()->db_handler.store_session(inbound_session);

    /** The one who sends the accept message will be the one who received the invitation message.
     *  Thus, the "from" and "to" of acception message will be different from those in the session. */
    accept_internal(inbound_session->e2ee_pack_id, inbound_session->to, inbound_session->from, NULL);

    // release
    skissm__signed_pre_key__free_unpacked(old_spk_data, NULL);
    unset(secret, sizeof(secret));

    // done
    return (size_t)(0);
}

size_t crypto_curve25519_complete_outbound_session(Skissm__Session *outbound_session, Skissm__AcceptMsg *msg) {
    outbound_session->responded = true;

    // done
    return (size_t)(0);
}

size_t crypto_curve25519_new_f2f_outbound_session(
    Skissm__Session *outbound_session,
    Skissm__F2fPreKeyInviteMsg *f2f_pre_key_invite_msg
) {
    const cipher_suite_t *cipher_suite = get_e2ee_pack(f2f_pre_key_invite_msg->e2ee_pack_id)->cipher_suite;
    int key_len = cipher_suite->get_crypto_param().asym_key_len;

    // set the version
    outbound_session->version = strdup(f2f_pre_key_invite_msg->version);
    // set the cipher suite id
    outbound_session->e2ee_pack_id = strdup(f2f_pre_key_invite_msg->e2ee_pack_id);

    // set the session id
    outbound_session->session_id = strdup(f2f_pre_key_invite_msg->session_id);

    // set the address
    copy_address_from_address(&(outbound_session->from), f2f_pre_key_invite_msg->from);
    copy_address_from_address(&(outbound_session->to), f2f_pre_key_invite_msg->to);

    // store the secret bytes(store in the associated_data)
    copy_protobuf_from_protobuf(&(outbound_session->associated_data), &(f2f_pre_key_invite_msg->secret));

    outbound_session->responded = false;

    // this is a face-to-face session
    outbound_session->f2f = true;

    // done
    return (size_t)(0);
}

size_t crypto_curve25519_new_f2f_inbound_session(
    Skissm__Session *inbound_session,
    Skissm__Account *local_account,
    uint8_t *secret
) {
    const cipher_suite_t *cipher_suite = get_e2ee_pack(inbound_session->e2ee_pack_id)->cipher_suite;

    initialise_as_bob(cipher_suite, inbound_session->ratchet, secret, 4 * CURVE25519_SHARED_SECRET_LENGTH, local_account->signed_pre_key->key_pair);

    // this is a face-to-face session
    inbound_session->f2f = true;

    // insert the associated data
    int key_len = local_account->identity_key->asym_key_pair->public_key.len;
    int ad_len = 2 * key_len;
    inbound_session->associated_data.len = ad_len;
    inbound_session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * ad_len);
    uint8_t *key_data = local_account->identity_key->asym_key_pair->public_key.data;
    memcpy(inbound_session->associated_data.data, key_data, key_len);
    memcpy((inbound_session->associated_data.data) + key_len, key_data, key_len);

    Skissm__E2eeAddress *sender_address = NULL;
    copy_address_from_address(&(sender_address), inbound_session->from);
    if (strcmp(inbound_session->from->user->user_id, inbound_session->to->user->user_id) != 0) {
        // no need to record the device id of the sender's address in the face-to-face inbound session
        free(inbound_session->from->user->device_id);
        inbound_session->from->user->device_id = '\0';
    }

    // store sesson state
    get_skissm_plugin()->db_handler.store_session(inbound_session);

    /** The one who sends the accept message will be the one who received the invitation message.
     *  Thus, the "from" and "to" of acception message will be different from those in the session. */
    f2f_accept_internal(inbound_session->e2ee_pack_id, inbound_session->to, sender_address, local_account);

    // release
    skissm__e2ee_address__free_unpacked(sender_address, NULL);

    // done
    return (size_t)(0);
}

size_t crypto_curve25519_complete_f2f_outbound_session(Skissm__Session *outbound_session, Skissm__F2fAcceptMsg *msg) {
    // get the cipher suite
    const cipher_suite_t *cipher_suite = get_e2ee_pack(outbound_session->e2ee_pack_id)->cipher_suite;

    // unpack
    Skissm__F2fPreKeyAcceptMsg *f2f_pre_key_accept_msg = skissm__f2f_pre_key_accept_msg__unpack(NULL, msg->pre_key_msg.len, msg->pre_key_msg.data);

    // set the other's signed pre-key
    copy_protobuf_from_protobuf(&(outbound_session->bob_signed_pre_key), &(f2f_pre_key_accept_msg->bob_signed_pre_key));

    // generate a new random ratchet key pair
    Skissm__KeyPair my_ratchet_key;
    cipher_suite->asym_key_gen(&(my_ratchet_key.public_key), &(my_ratchet_key.private_key));

    // create the root key and chain keys
    initialise_as_alice(
        cipher_suite, outbound_session->ratchet,
        outbound_session->associated_data.data, outbound_session->associated_data.len,
        &my_ratchet_key, &(outbound_session->bob_signed_pre_key)
    );

    // replace the associated data
    int key_len = f2f_pre_key_accept_msg->bob_identity_public_key.len;
    int ad_len = 2 * key_len;
    outbound_session->associated_data.len = ad_len;
    uint8_t *key_data = f2f_pre_key_accept_msg->bob_identity_public_key.data;
    memcpy(outbound_session->associated_data.data, key_data, key_len);
    memcpy((outbound_session->associated_data.data) + key_len, key_data, key_len);

    if (strcmp(outbound_session->from->user->user_id, outbound_session->to->user->user_id) != 0) {
        // no need to record the device id of the receiver's address in the face-to-face outbound session
        free(outbound_session->to->user->device_id);
        outbound_session->to->user->device_id = '\0';
    }

    outbound_session->responded = true;

    // release
    skissm__f2f_pre_key_accept_msg__free_unpacked(f2f_pre_key_accept_msg, NULL);
    free_protobuf(&(my_ratchet_key.private_key));
    free_protobuf(&(my_ratchet_key.public_key));
    unset((void volatile *)&my_ratchet_key, sizeof(Skissm__KeyPair));

    // done
    return (size_t)(0);
}

const session_suite_t E2EE_SESSION_ECDH_X25519_AES256_GCM_SHA256 = {
    crypto_curve25519_new_outbound_session,
    crypto_curve25519_new_inbound_session,
    crypto_curve25519_complete_outbound_session,
    crypto_curve25519_new_f2f_outbound_session,
    crypto_curve25519_new_f2f_inbound_session,
    crypto_curve25519_complete_f2f_outbound_session
};
