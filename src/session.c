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
#include <stdio.h>
#include <string.h>

#include "account.h"
#include "e2ee_protocol.h"
#include "error.h"
#include "group_session.h"
#include "mem_util.h"
#include "ratchet.h"
#include "session.h"
#include "skissm.h"

static const struct cipher CIPHER = CIPHER_INIT;

static void create_session_id(Skissm__E2eeSession *session) {
    uint8_t tmp[CURVE25519_KEY_LENGTH * 4];
    uint8_t *pos = tmp;
    memcpy(pos, session->alice_identity_key.data, CURVE25519_KEY_LENGTH);
    memcpy(pos + CURVE25519_KEY_LENGTH, session->alice_ephemeral_key.data, CURVE25519_KEY_LENGTH);
    memcpy(pos + CURVE25519_KEY_LENGTH + CURVE25519_KEY_LENGTH, session->bob_signed_pre_key.data, CURVE25519_KEY_LENGTH);
    memcpy(pos + CURVE25519_KEY_LENGTH + CURVE25519_KEY_LENGTH + CURVE25519_KEY_LENGTH, session->bob_one_time_pre_key.data, CURVE25519_KEY_LENGTH);

    session->session_id.data = (uint8_t *)malloc(sizeof(uint8_t) * SHA256_OUTPUT_LENGTH);
    session->session_id.len = SHA256_OUTPUT_LENGTH;
    CIPHER.suit1->hash(tmp, sizeof(tmp), session->session_id.data);
}

void initialise_session(Skissm__E2eeSession *session, Skissm__E2eeAddress *from, Skissm__E2eeAddress *to) {
    skissm__e2ee_session__init(session);
    copy_address_from_address(&(session->from), from);
    copy_address_from_address(&(session->to), to);
    initialise_ratchet(&(session->ratchet));
}

void close_session(Skissm__E2eeSession *session) {
    if (session != NULL) {
        skissm__e2ee_session__free_unpacked(session, NULL);
        session = NULL;
    }
}

void pack_e2ee_plaintext(uint8_t *plaintext, size_t plaintext_len, Skissm__E2eePlaintextType plaintext_type, uint8_t **context, size_t *context_len) {
    Skissm__E2eePlaintext *e2ee_plaintext = (Skissm__E2eePlaintext *)malloc(sizeof(Skissm__E2eePlaintext));
    skissm__e2ee_plaintext__init(e2ee_plaintext);
    e2ee_plaintext->version = PLAINTEXT_VERSION;
    e2ee_plaintext->plaintext_type = plaintext_type;
    e2ee_plaintext->payload.len = plaintext_len;
    e2ee_plaintext->payload.data = (uint8_t *)malloc(sizeof(uint8_t) * plaintext_len);
    memcpy(e2ee_plaintext->payload.data, plaintext, plaintext_len);

    *context_len = skissm__e2ee_plaintext__get_packed_size(e2ee_plaintext);
    *context = (uint8_t *)malloc(sizeof(uint8_t) * (*context_len));
    skissm__e2ee_plaintext__pack(e2ee_plaintext, *context);
}

size_t new_outbound_session(Skissm__E2eeSession *session, const Skissm__E2eeAccount *local_account, Skissm__E2eePreKeyBundle *their_pre_key_bundle) {
    // Verify the signature
    size_t result;
    if ((their_pre_key_bundle->identity_key_public.len != CURVE25519_KEY_LENGTH) || (their_pre_key_bundle->signed_pre_key_public->public_key.len != CURVE25519_KEY_LENGTH) ||
        (their_pre_key_bundle->signed_pre_key_public->signature.len != CURVE_SIGNATURE_LENGTH)) {
        ssm_notify_error(BAD_PRE_KEY_BUNDLE, "new_outbound_session()");
        return (size_t)(-1);
    }
    result = CIPHER.suit1->verify(their_pre_key_bundle->signed_pre_key_public->signature.data, their_pre_key_bundle->identity_key_public.data,
                                  their_pre_key_bundle->signed_pre_key_public->public_key.data, CURVE25519_KEY_LENGTH);
    if (result < 0) {
        ssm_notify_error(BAD_SIGNATURE, "new_outbound_session()");
        return (size_t)(-1);
    }

    // Set the version
    session->version = PROTOCOL_VERSION;

    // Generate a new random ephemeral key pair
    Skissm__KeyPair my_ephemeral_key;
    CIPHER.suit1->gen_key_pair(&my_ephemeral_key);

    // Generate a new random ratchet key pair
    Skissm__KeyPair my_ratchet_key;
    CIPHER.suit1->gen_key_pair(&my_ratchet_key);

    const Skissm__KeyPair my_identity_key_pair = *(local_account->identity_key_pair);

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

    session->associated_data.len = AD_LENGTH;
    session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * AD_LENGTH);
    memcpy(session->associated_data.data, my_identity_key_pair.public_key.data, CURVE25519_KEY_LENGTH);
    memcpy((session->associated_data.data) + CURVE25519_KEY_LENGTH, their_pre_key_bundle->identity_key_public.data, CURVE25519_KEY_LENGTH);

    // Calculate the shared secret S via quadruple ECDH
    uint8_t secret[x3dh_epoch * CURVE25519_SHARED_SECRET_LENGTH];
    uint8_t *pos = secret;

    CIPHER.suit1->dh(&my_identity_key_pair, &(their_pre_key_bundle->signed_pre_key_public->public_key), pos);
    pos += CURVE25519_SHARED_SECRET_LENGTH;
    CIPHER.suit1->dh(&my_ephemeral_key, &(their_pre_key_bundle->identity_key_public), pos);
    pos += CURVE25519_SHARED_SECRET_LENGTH;
    CIPHER.suit1->dh(&my_ephemeral_key, &(their_pre_key_bundle->signed_pre_key_public->public_key), pos);
    if (x3dh_epoch == 4) {
        pos += CURVE25519_SHARED_SECRET_LENGTH;
        CIPHER.suit1->dh(&my_ephemeral_key, &(their_pre_key_bundle->one_time_pre_key_public->public_key), pos);
    }

    // Create the root key and chain keys
    initialise_as_alice(session->ratchet, secret, sizeof(secret), &my_ratchet_key, &(their_pre_key_bundle->signed_pre_key_public->public_key));
    create_session_id(session);

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

size_t new_inbound_session(Skissm__E2eeSession *session, Skissm__E2eeAccount *local_account, Skissm__E2eeMessage *inbound_message) {
    session->version = inbound_message->version;

    Skissm__E2eePreKeyPayload *pre_key_context = skissm__e2ee_pre_key_payload__unpack(NULL, inbound_message->payload.len, inbound_message->payload.data);

    /* Verify the signed pre-key */
    bool old_spk = 0;
    Skissm__SignedPreKeyPair *old_spk_data = NULL;
    if (local_account->signed_pre_key_pair->spk_id != pre_key_context->bob_signed_pre_key_id) {
        get_ssm_plugin()->load_old_signed_pre_key(&(local_account->account_id), pre_key_context->bob_signed_pre_key_id, &old_spk_data);
        if (old_spk_data == NULL) {
            ssm_notify_error(BAD_SIGNED_PRE_KEY, "new_inbound_session()");
            skissm__e2ee_pre_key_payload__free_unpacked(pre_key_context, NULL);
            return (size_t)(-1);
        } else {
            old_spk = 1;
        }
    }

    uint8_t x3dh_epoch = 3;
    copy_protobuf_from_protobuf(&(session->alice_identity_key), &(pre_key_context->alice_identity_key));
    copy_protobuf_from_protobuf(&(session->alice_ephemeral_key), &(pre_key_context->alice_ephemeral_key));
    session->bob_signed_pre_key_id = pre_key_context->bob_signed_pre_key_id;
    if (old_spk == 0) {
        copy_protobuf_from_protobuf(&(session->bob_signed_pre_key), &(local_account->signed_pre_key_pair->key_pair->public_key));
    } else {
        copy_protobuf_from_protobuf(&(session->bob_signed_pre_key), &(old_spk_data->key_pair->public_key));
    }
    if (pre_key_context->bob_one_time_pre_key_id != 0) {
        x3dh_epoch = 4;
    }

    session->associated_data.len = AD_LENGTH;
    session->associated_data.data = (uint8_t *)malloc(sizeof(uint8_t) * AD_LENGTH);
    memcpy(session->associated_data.data, pre_key_context->alice_identity_key.data, CURVE25519_KEY_LENGTH);
    memcpy((session->associated_data.data) + CURVE25519_KEY_LENGTH, local_account->identity_key_pair->public_key.data, CURVE25519_KEY_LENGTH);

    /* Mark the one-time pre-key as used */
    const Skissm__OneTimePreKeyPair *our_one_time_pre_key;
    if (x3dh_epoch == 4) {
        our_one_time_pre_key = lookup_one_time_pre_key(local_account, pre_key_context->bob_one_time_pre_key_id);

        if (!our_one_time_pre_key) {
            ssm_notify_error(BAD_ONE_TIME_PRE_KEY, "new_inbound_session()");
            skissm__e2ee_pre_key_payload__free_unpacked(pre_key_context, NULL);
            return (size_t)(-1);
        } else {
            mark_opk_as_used(local_account, our_one_time_pre_key->opk_id);
            get_ssm_plugin()->update_one_time_pre_key(&(local_account->account_id), our_one_time_pre_key->opk_id);
            copy_protobuf_from_protobuf(&(session->bob_one_time_pre_key), &(our_one_time_pre_key->key_pair->public_key));
            session->bob_one_time_pre_key_id = our_one_time_pre_key->opk_id;
        }
    } else {
        our_one_time_pre_key = NULL;
    }

    const Skissm__KeyPair *bob_identity_key = local_account->identity_key_pair;
    const Skissm__KeyPair *bob_signed_pre_key;
    if (old_spk == 0) {
        bob_signed_pre_key = local_account->signed_pre_key_pair->key_pair;
    } else {
        bob_signed_pre_key = old_spk_data->key_pair;
    }
    const Skissm__KeyPair *bob_one_time_pre_key;
    if (x3dh_epoch == 4) {
        bob_one_time_pre_key = our_one_time_pre_key->key_pair;
    } else {
        bob_one_time_pre_key = NULL;
    }

    // Calculate the shared secret S via triple DH
    uint8_t secret[x3dh_epoch * CURVE25519_SHARED_SECRET_LENGTH];
    uint8_t *pos = secret;
    CIPHER.suit1->dh(bob_signed_pre_key, &session->alice_identity_key, pos);
    pos += CURVE25519_SHARED_SECRET_LENGTH;
    CIPHER.suit1->dh(bob_identity_key, &session->alice_ephemeral_key, pos);
    pos += CURVE25519_SHARED_SECRET_LENGTH;
    CIPHER.suit1->dh(bob_signed_pre_key, &session->alice_ephemeral_key, pos);
    if (x3dh_epoch == 4) {
        pos += CURVE25519_SHARED_SECRET_LENGTH;
        CIPHER.suit1->dh(bob_one_time_pre_key, &session->alice_ephemeral_key, pos);
    }

    initialise_as_bob(session->ratchet, secret, sizeof(secret), bob_signed_pre_key);
    create_session_id(session);

    // release
    skissm__signed_pre_key_pair__free_unpacked(old_spk_data, NULL);
    unset(secret, sizeof(secret));

    // done
    return (size_t)(0);
}

size_t perform_encrypt_session(Skissm__E2eeSession *session, const uint8_t *plaintext, size_t plaintext_len) {
    Skissm__E2eeMessage *outbound_message;
    outbound_message = (Skissm__E2eeMessage *)malloc(sizeof(Skissm__E2eeMessage));
    skissm__e2ee_message__init(outbound_message);

    outbound_message->version = PROTOCOL_VERSION;
    copy_protobuf_from_protobuf(&(outbound_message->session_id), &(session->session_id));
    copy_address_from_address(&(outbound_message->from), session->from);
    copy_address_from_address(&(outbound_message->to), session->to);

    Skissm__E2eeMsgPayload *msg_context = NULL;

    if (session->responded) {
        outbound_message->msg_type = SKISSM__E2EE_MESSAGE_TYPE__MESSAGE;
        encrypt_ratchet(session->ratchet, session->associated_data, plaintext, plaintext_len, &msg_context);

        size_t msg_len = skissm__e2ee_msg_payload__get_packed_size(msg_context);
        outbound_message->payload.len = msg_len;
        outbound_message->payload.data = (uint8_t *)malloc(sizeof(uint8_t) * msg_len);
        skissm__e2ee_msg_payload__pack(msg_context, outbound_message->payload.data);
    } else {
        outbound_message->msg_type = SKISSM__E2EE_MESSAGE_TYPE__PRE_KEY;
        Skissm__E2eePreKeyPayload *pre_key_context = (Skissm__E2eePreKeyPayload *)malloc(sizeof(Skissm__E2eePreKeyPayload));
        skissm__e2ee_pre_key_payload__init(pre_key_context);
        copy_protobuf_from_protobuf(&pre_key_context->alice_identity_key, &session->alice_identity_key);
        copy_protobuf_from_protobuf(&pre_key_context->alice_ephemeral_key, &session->alice_ephemeral_key);
        pre_key_context->bob_signed_pre_key_id = session->bob_signed_pre_key_id;
        pre_key_context->bob_one_time_pre_key_id = session->bob_one_time_pre_key_id;

        encrypt_ratchet(session->ratchet, session->associated_data, plaintext, plaintext_len, &msg_context);

        pre_key_context->msg_payload = msg_context;

        size_t pre_key_len = skissm__e2ee_pre_key_payload__get_packed_size(pre_key_context);
        outbound_message->payload.len = pre_key_len;
        outbound_message->payload.data = (uint8_t *)malloc(sizeof(uint8_t) * pre_key_len);
        skissm__e2ee_pre_key_payload__pack(pre_key_context, outbound_message->payload.data);
    }

    Skissm__E2eeProtocolMsg *protocol_msg = (Skissm__E2eeProtocolMsg *)malloc(sizeof(Skissm__E2eeProtocolMsg));
    skissm__e2ee_protocol_msg__init(protocol_msg);
    protocol_msg->cmd = SKISSM__E2EE_COMMANDS__send_one2one_msg_request;

    protocol_msg->payload.len = skissm__e2ee_message__get_packed_size(outbound_message);
    protocol_msg->payload.data = (uint8_t *)malloc(protocol_msg->payload.len);
    skissm__e2ee_message__pack(outbound_message, protocol_msg->payload.data);

    size_t message_len = skissm__e2ee_protocol_msg__get_packed_size(protocol_msg);
    uint8_t *message = (uint8_t *)malloc(sizeof(uint8_t) * message_len);
    skissm__e2ee_protocol_msg__pack(protocol_msg, message);

    // send message to server
    get_ssm_plugin()->handle_send(message, message_len);

    // store sesson state
    get_ssm_plugin()->store_session(session);

    // release
    free_mem((void **)(&message), message_len);
    skissm__e2ee_message__free_unpacked(outbound_message, NULL);
    skissm__e2ee_protocol_msg__free_unpacked(protocol_msg, NULL);

    // done
    return message_len;
}

static void handle_pre_key_bundle_response(pre_key_bundle_response_handler *this_response_handler, Skissm__E2eePreKeyBundle *their_pre_key_bundle) {
    Skissm__E2eeAddress *from = this_response_handler->from;
    Skissm__E2eeAddress *to = this_response_handler->to;
    uint8_t *plaintext = this_response_handler->context;
    size_t plaintext_len = this_response_handler->context_len;

    Skissm__E2eeSession *session = (Skissm__E2eeSession *)malloc(sizeof(Skissm__E2eeSession));
    initialise_session(session, from, to);
    copy_address_from_address(&(session->session_owner), from);
    Skissm__E2eeAccount *local_account = get_local_account(from);
    new_outbound_session(session, local_account, their_pre_key_bundle);
    perform_encrypt_session(session, plaintext, plaintext_len);

    // release
    close_session(session);
}

static void handle_pre_key_bundle_release(pre_key_bundle_response_handler *this_response_handler) {
    this_response_handler->from = NULL;
    this_response_handler->to = NULL;
    this_response_handler->context = NULL;
    this_response_handler->context_len = 0;
}

static pre_key_bundle_response_handler pre_key_bundle_handler = {NULL, NULL, NULL, 0, handle_pre_key_bundle_response, handle_pre_key_bundle_release};

void encrypt_session(Skissm__E2eeAddress *from, Skissm__E2eeAddress *to, const uint8_t *plaintext, size_t plaintext_len) {
    Skissm__E2eeSession *session = NULL;
    get_ssm_plugin()->load_outbound_session(from, to, &session);
    if (session == NULL) {
        // there is no outbound session, create a new one after receiving the pre-key bundle of receipient(to).
        pre_key_bundle_handler.from = from;
        pre_key_bundle_handler.to = to;
        pre_key_bundle_handler.context = (uint8_t *)plaintext;
        pre_key_bundle_handler.context_len = plaintext_len;
        send_get_pre_key_bundle_request(to, &pre_key_bundle_handler);
        return;
    }

    perform_encrypt_session(session, plaintext, plaintext_len);

    close_session(session);
}

size_t decrypt_session(Skissm__E2eeMessage *inbound_message) {
    Skissm__E2eePreKeyPayload *pre_key_context = NULL;
    Skissm__E2eeMsgPayload *msg_payload = NULL;

    if (inbound_message->msg_type != SKISSM__E2EE_MESSAGE_TYPE__PRE_KEY && inbound_message->msg_type != SKISSM__E2EE_MESSAGE_TYPE__MESSAGE) {
        ssm_notify_error(BAD_MESSAGE_FORMAT, "decrypt_session()");
        return (size_t)(-1);
    }

    if (inbound_message->session_id.data == NULL) {
        ssm_notify_error(BAD_MESSAGE_FORMAT, "decrypt_session()");
        return (size_t)(-1);
    }

    /* load the corresponding inbound session */
    Skissm__E2eeSession *session = NULL;
    get_ssm_plugin()->load_inbound_session(inbound_message->session_id, inbound_message->to, &session);
    if (session == NULL) {
        if (inbound_message->msg_type != SKISSM__E2EE_MESSAGE_TYPE__PRE_KEY) {
            ssm_notify_error(BAD_MESSAGE_FORMAT, "decrypt_session()");
            return (size_t)(-1);
        }
        /* delete the old inbound session if it exists */
        get_ssm_plugin()->unload_session(inbound_message->to, inbound_message->from, inbound_message->to);
        /* create a new inbound session */
        session = (Skissm__E2eeSession *)malloc(sizeof(Skissm__E2eeSession));
        initialise_session(session, inbound_message->from, inbound_message->to);
        copy_address_from_address(&(session->session_owner), inbound_message->to);
        Skissm__E2eeAccount *local_account = get_local_account(inbound_message->to);
        size_t result = new_inbound_session(session, local_account, inbound_message);

        if (result == (size_t)(-1) || compare_protobuf(&(session->session_id), &(inbound_message->session_id)) == false) {
            close_session(session);
            ssm_notify_error(BAD_MESSAGE_FORMAT, "decrypt_session()");
            return (size_t)(-1);
        }
    }

    uint8_t *context = NULL;
    size_t context_len = -1;
    if (inbound_message->msg_type == SKISSM__E2EE_MESSAGE_TYPE__MESSAGE) {
        msg_payload = skissm__e2ee_msg_payload__unpack(NULL, inbound_message->payload.len, inbound_message->payload.data);
    } else if (inbound_message->msg_type == SKISSM__E2EE_MESSAGE_TYPE__PRE_KEY) {
        pre_key_context = skissm__e2ee_pre_key_payload__unpack(NULL, inbound_message->payload.len, inbound_message->payload.data);
        msg_payload = pre_key_context->msg_payload;
    }

    if (msg_payload != NULL) {
        context_len = decrypt_ratchet(session->ratchet, session->associated_data, msg_payload, &context);

        // store sesson state
        get_ssm_plugin()->store_session(session);

        if (context_len == (size_t)(-1)) {
            ssm_notify_error(BAD_MESSAGE_DECRYPTION, "decrypt_session()");
            goto complete;
        } else {
            Skissm__E2eePlaintext *e2ee_plaintext = skissm__e2ee_plaintext__unpack(NULL, context_len, context);
            if (e2ee_plaintext->plaintext_type == SKISSM__E2EE_PLAINTEXT_TYPE__COMMON_MSG) {
                ssm_notify_one2one_msg(inbound_message->from, inbound_message->to, e2ee_plaintext->payload.data, e2ee_plaintext->payload.len);
            } else if (e2ee_plaintext->plaintext_type == SKISSM__E2EE_PLAINTEXT_TYPE__GROUP_PRE_KEY) {
                Skissm__E2eeGroupPreKeyPayload *group_pre_key_payload = skissm__e2ee_group_pre_key_payload__unpack(NULL, e2ee_plaintext->payload.len, e2ee_plaintext->payload.data);
                get_ssm_plugin()->unload_inbound_group_session(inbound_message->to, &(group_pre_key_payload->old_session_id));
                create_inbound_group_session(group_pre_key_payload, inbound_message->to);
                skissm__e2ee_group_pre_key_payload__free_unpacked(group_pre_key_payload, NULL);
            }
        }

        // try to find outbound session
        Skissm__E2eeSession *outbound_session = NULL;
        get_ssm_plugin()->load_outbound_session(inbound_message->to, inbound_message->from, &outbound_session);
        if (outbound_session != NULL) {
            if (outbound_session->responded == false) {
                outbound_session->responded = true;
                get_ssm_plugin()->store_session(outbound_session);
            }
        }

        // release
        free_mem((void **)&context, context_len);
    }

complete:
    // release
    if (inbound_message->msg_type == SKISSM__E2EE_MESSAGE_TYPE__MESSAGE) {
        skissm__e2ee_msg_payload__free_unpacked(msg_payload, NULL);
    } else if (inbound_message->msg_type == SKISSM__E2EE_MESSAGE_TYPE__PRE_KEY) {
        skissm__e2ee_pre_key_payload__free_unpacked(pre_key_context, NULL);
    }
    close_session(session);

    // done
    return context_len;
}
