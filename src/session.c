#include <stdio.h>
#include <string.h>

#include "skissm.h"
#include "account.h"
#include "session.h"
#include "ratchet.h"
#include "error.h"
#include "mem_util.h"
#include "e2ee_protocol.h"
#include "group_session.h"

static const struct cipher CIPHER = CIPHER_INIT;

static void create_session_id(Org__E2eelab__Skissm__Proto__E2eeSession *session) {
    uint8_t tmp[CURVE25519_KEY_LENGTH * 4];
    uint8_t *pos = tmp;
    memcpy(pos, session->alice_identity_key.data, CURVE25519_KEY_LENGTH);
    memcpy(pos + CURVE25519_KEY_LENGTH, session->alice_ephemeral_key.data, CURVE25519_KEY_LENGTH);
    memcpy(pos + CURVE25519_KEY_LENGTH + CURVE25519_KEY_LENGTH, session->bob_signed_pre_key.data, CURVE25519_KEY_LENGTH);
    memcpy(pos + CURVE25519_KEY_LENGTH + CURVE25519_KEY_LENGTH + CURVE25519_KEY_LENGTH, session->bob_one_time_pre_key.data, CURVE25519_KEY_LENGTH);

    session->session_id.data = (uint8_t *) malloc(sizeof(uint8_t) * SHA256_OUTPUT_LENGTH);
    session->session_id.len = SHA256_OUTPUT_LENGTH;
    CIPHER.suit1->hash(tmp, sizeof(tmp), session->session_id.data);
}

static bool check_message_fields(
    Org__E2eelab__Skissm__Proto__E2eePreKeyPayload *pre_key_context,
    bool have_their_identity_key
) {
    bool ok = true;
    ok = ok && (have_their_identity_key || pre_key_context->alice_identity_key.data);
    if (pre_key_context->alice_identity_key.data) {
        ok = ok && pre_key_context->alice_identity_key.len == CURVE25519_KEY_LENGTH;
    }
    ok = ok && pre_key_context->alice_ephemeral_key.data;
    ok = ok && pre_key_context->alice_ephemeral_key.len == CURVE25519_KEY_LENGTH;
    ok = ok && pre_key_context->bob_signed_pre_key.data;
    ok = ok && pre_key_context->bob_signed_pre_key.len == CURVE25519_KEY_LENGTH;
    ok = ok && pre_key_context->bob_one_time_pre_key.data;
    ok = ok && pre_key_context->bob_one_time_pre_key.len == CURVE25519_KEY_LENGTH;
    return ok;
}

void initialise_session(
    Org__E2eelab__Skissm__Proto__E2eeSession *session,
    Org__E2eelab__Skissm__Proto__E2eeAddress *from,
    Org__E2eelab__Skissm__Proto__E2eeAddress *to
) {
    org__e2eelab__skissm__proto__e2ee_session__init(session);
    copy_address_from_address(&(session->from), from);
    copy_address_from_address(&(session->to), to);
    initialise_ratchet(&(session->ratchet));
}

static void close_session(Org__E2eelab__Skissm__Proto__E2eeSession *session){
    if (session != NULL){
        org__e2eelab__skissm__proto__e2ee_session__free_unpacked(session, NULL);
        session = NULL;
    }
}

void pack_e2ee_plaintext(
    uint8_t *plaintext, size_t plaintext_len,
    Org__E2eelab__Skissm__Proto__E2eePlaintextType plaintext_type,
    uint8_t **context, size_t *context_len
) {
    Org__E2eelab__Skissm__Proto__E2eePlaintext *e2ee_plaintext = (Org__E2eelab__Skissm__Proto__E2eePlaintext *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eePlaintext));
    org__e2eelab__skissm__proto__e2ee_plaintext__init(e2ee_plaintext);
    e2ee_plaintext->version = PLAINTEXT_VERSION;
    e2ee_plaintext->plaintext_type = plaintext_type;
    e2ee_plaintext->payload.len = plaintext_len;
    e2ee_plaintext->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * plaintext_len);
    memcpy(e2ee_plaintext->payload.data, plaintext, plaintext_len);

    *context_len = org__e2eelab__skissm__proto__e2ee_plaintext__get_packed_size(e2ee_plaintext);
    *context = (uint8_t *) malloc(sizeof(uint8_t) * (*context_len));
    org__e2eelab__skissm__proto__e2ee_plaintext__pack(e2ee_plaintext, *context);
}

size_t new_outbound_session(
    Org__E2eelab__Skissm__Proto__E2eeSession *session,
    const Org__E2eelab__Skissm__Proto__E2eeAccount *local_account,
    Org__E2eelab__Skissm__Proto__E2eePreKeyBundle *their_pre_key_bundle
) {
    // Verify the signature
    size_t result;
    if ((their_pre_key_bundle->identity_key_public.len != CURVE25519_KEY_LENGTH)
        || (their_pre_key_bundle->signed_pre_key_public->public_key.len != CURVE25519_KEY_LENGTH)
        || (their_pre_key_bundle->signed_pre_key_public->signature.len != CURVE_SIGNATURE_LENGTH)
    ) {
        ssm_notify_error(BAD_PRE_KEY_BUNDLE, "new_outbound_session()");
        return (size_t)(-1);
    }
    result = CIPHER.suit1->verify(
        their_pre_key_bundle->signed_pre_key_public->signature.data,
        their_pre_key_bundle->identity_key_public.data,
        their_pre_key_bundle->signed_pre_key_public->public_key.data, CURVE25519_KEY_LENGTH);
    if (result < 0){
        ssm_notify_error(BAD_SIGNATURE, "new_outbound_session()");
        return (size_t)(-1);
    }

    // Set the version
    session->version = PROTOCOL_VERSION;

    // Generate a new random ephemeral key pair
    Org__E2eelab__Skissm__Proto__KeyPair my_ephemeral_key;
    CIPHER.suit1->gen_key_pair(&my_ephemeral_key);

    // Generate a new random ratchet key pair
    Org__E2eelab__Skissm__Proto__KeyPair my_ratchet_key;
    CIPHER.suit1->gen_key_pair(&my_ratchet_key);

    const Org__E2eelab__Skissm__Proto__KeyPair my_identity_key_pair =
        *(local_account->identity_key_pair);

    uint8_t x3dh_epoch = 3;
    session->responded = false;
    copy_protobuf_from_protobuf(&(session->alice_identity_key), &(my_identity_key_pair.public_key));
    copy_protobuf_from_protobuf(&(session->alice_ephemeral_key), &(my_ephemeral_key.public_key));
    copy_protobuf_from_protobuf(&(session->bob_signed_pre_key), &(their_pre_key_bundle->signed_pre_key_public->public_key));
    // server may return empty one-time pre-key(public)
    if (their_pre_key_bundle->one_time_pre_key_public){
        copy_protobuf_from_protobuf(&(session->bob_one_time_pre_key), &(their_pre_key_bundle->one_time_pre_key_public->public_key));
        x3dh_epoch = 4;
    }

    session->associated_data.len = AD_LENGTH;
    session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * AD_LENGTH);
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
    if (x3dh_epoch == 4){
        pos += CURVE25519_SHARED_SECRET_LENGTH;
        CIPHER.suit1->dh(&my_ephemeral_key, &(their_pre_key_bundle->one_time_pre_key_public->public_key), pos);
    }

    // Create the root key and chain keys
    initialise_as_alice(session->ratchet, secret, sizeof(secret), &my_ratchet_key, &(their_pre_key_bundle->signed_pre_key_public->public_key));
    create_session_id(session);

    // release
    free_protobuf(&(my_ephemeral_key.private_key));
    free_protobuf(&(my_ephemeral_key.public_key));
    unset((void volatile *)&my_ephemeral_key, sizeof(Org__E2eelab__Skissm__Proto__KeyPair));
    free_protobuf(&(my_ratchet_key.private_key));
    free_protobuf(&(my_ratchet_key.public_key));
    unset((void volatile *)&my_ratchet_key, sizeof(Org__E2eelab__Skissm__Proto__KeyPair));
    unset(secret, sizeof(secret));

    // done
    return (size_t)(0);
}

size_t new_inbound_session(
    Org__E2eelab__Skissm__Proto__E2eeSession *session,
    Org__E2eelab__Skissm__Proto__E2eeAccount *local_account,
    Org__E2eelab__Skissm__Proto__E2eeMessage *inbound_message
) {
    session->version = inbound_message->version;

    Org__E2eelab__Skissm__Proto__E2eePreKeyPayload *pre_key_context = org__e2eelab__skissm__proto__e2ee_pre_key_payload__unpack(NULL, inbound_message->payload.len, inbound_message->payload.data);

    /* Verify the signed pre-key */
    if (compare_protobuf(&(local_account->signed_pre_key_pair->key_pair->public_key), &(pre_key_context->bob_signed_pre_key)) == false){
        ssm_notify_error(BAD_SIGNED_PRE_KEY, "new_inbound_session()");
        org__e2eelab__skissm__proto__e2ee_pre_key_payload__free_unpacked(pre_key_context, NULL);
        return (size_t)(-1);
    }

    uint8_t x3dh_epoch = 3;
    copy_protobuf_from_protobuf(&(session->alice_identity_key), &(pre_key_context->alice_identity_key));
    copy_protobuf_from_protobuf(&(session->alice_ephemeral_key), &(pre_key_context->alice_ephemeral_key));
    copy_protobuf_from_protobuf(&(session->bob_signed_pre_key), &(pre_key_context->bob_signed_pre_key));
    if (pre_key_context->bob_one_time_pre_key.data){
        copy_protobuf_from_protobuf(&(session->bob_one_time_pre_key), &(pre_key_context->bob_one_time_pre_key));
        x3dh_epoch = 4;
    }

    session->associated_data.len = AD_LENGTH;
    session->associated_data.data = (uint8_t *) malloc(sizeof(uint8_t) * AD_LENGTH);
    memcpy(session->associated_data.data, pre_key_context->alice_identity_key.data, CURVE25519_KEY_LENGTH);
    memcpy((session->associated_data.data) + CURVE25519_KEY_LENGTH, local_account->identity_key_pair->public_key.data, CURVE25519_KEY_LENGTH);

    /* Mark the one-time pre-key as used */
    const Org__E2eelab__Skissm__Proto__OneTimePreKeyPair *our_one_time_pre_key;
    if (x3dh_epoch == 4){
        our_one_time_pre_key = lookup_one_time_pre_key(local_account, session->bob_one_time_pre_key);

        if (!our_one_time_pre_key){
            ssm_notify_error(BAD_ONE_TIME_PRE_KEY, "new_inbound_session()");
            org__e2eelab__skissm__proto__e2ee_pre_key_payload__free_unpacked(pre_key_context, NULL);
            return (size_t)(-1);
        } else{
            mark_opk_as_used(local_account, our_one_time_pre_key->opk_id);
        }
    } else{
        our_one_time_pre_key = NULL;
    }

    const Org__E2eelab__Skissm__Proto__KeyPair *bob_identity_key = local_account->identity_key_pair;
    const Org__E2eelab__Skissm__Proto__KeyPair *bob_signed_pre_key = local_account->signed_pre_key_pair->key_pair;
    const Org__E2eelab__Skissm__Proto__KeyPair *bob_one_time_pre_key;
    if (x3dh_epoch == 4){
        bob_one_time_pre_key = our_one_time_pre_key->key_pair;
    } else{
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
    if (x3dh_epoch == 4){
        pos += CURVE25519_SHARED_SECRET_LENGTH;
        CIPHER.suit1->dh(bob_one_time_pre_key, &session->alice_ephemeral_key, pos);
    }

    initialise_as_bob(session->ratchet, secret, sizeof(secret), bob_signed_pre_key);
    create_session_id(session);

    // release
    unset(secret, sizeof(secret));

    // done
    return (size_t)(0);
}

static size_t perform_encrypt_session(
    Org__E2eelab__Skissm__Proto__E2eeSession *session,
    const uint8_t *context, size_t context_len
) {
    Org__E2eelab__Skissm__Proto__E2eeMessage *outbound_message;
    outbound_message = (Org__E2eelab__Skissm__Proto__E2eeMessage *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeMessage));
    org__e2eelab__skissm__proto__e2ee_message__init(outbound_message);

    outbound_message->version = PROTOCOL_VERSION;
    copy_protobuf_from_protobuf(&(outbound_message->session_id), &(session->session_id));
    copy_address_from_address(&(outbound_message->from), session->from);
    copy_address_from_address(&(outbound_message->to), session->to);

    Org__E2eelab__Skissm__Proto__E2eeMsgPayload *msg_context = NULL;

    if (session->responded){
        outbound_message->msg_type = ORG__E2EELAB__SKISSM__PROTO__E2EE_MESSAGE_TYPE__MESSAGE;
        encrypt_ratchet(
            session->ratchet,
            session->associated_data,
            context, context_len,
            &msg_context);

        size_t msg_len = org__e2eelab__skissm__proto__e2ee_msg_payload__get_packed_size(msg_context);
        outbound_message->payload.len = msg_len;
        outbound_message->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * msg_len);
        org__e2eelab__skissm__proto__e2ee_msg_payload__pack(msg_context, outbound_message->payload.data);
    } else {
        outbound_message->msg_type = ORG__E2EELAB__SKISSM__PROTO__E2EE_MESSAGE_TYPE__PRE_KEY;
        Org__E2eelab__Skissm__Proto__E2eePreKeyPayload *pre_key_context = (Org__E2eelab__Skissm__Proto__E2eePreKeyPayload *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eePreKeyPayload));
        org__e2eelab__skissm__proto__e2ee_pre_key_payload__init(pre_key_context);
        copy_protobuf_from_protobuf(&pre_key_context->alice_identity_key, &session->alice_identity_key);
        copy_protobuf_from_protobuf(&pre_key_context->alice_ephemeral_key, &session->alice_ephemeral_key);
        copy_protobuf_from_protobuf(&pre_key_context->bob_signed_pre_key, &session->bob_signed_pre_key);
        copy_protobuf_from_protobuf(&pre_key_context->bob_one_time_pre_key, &session->bob_one_time_pre_key);

        encrypt_ratchet(
            session->ratchet,
            session->associated_data,
            context, context_len,
            &msg_context);

        pre_key_context->msg_payload = msg_context;

        size_t pre_key_len = org__e2eelab__skissm__proto__e2ee_pre_key_payload__get_packed_size(pre_key_context);
        outbound_message->payload.len = pre_key_len;
        outbound_message->payload.data = (uint8_t *) malloc(sizeof(uint8_t) * pre_key_len);
        org__e2eelab__skissm__proto__e2ee_pre_key_payload__pack(pre_key_context, outbound_message->payload.data);
    }

    Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *protocol_msg = (Org__E2eelab__Skissm__Proto__E2eeProtocolMsg *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeProtocolMsg));
    org__e2eelab__skissm__proto__e2ee_protocol_msg__init(protocol_msg);
    protocol_msg->cmd = ORG__E2EELAB__SKISSM__PROTO__E2EE_COMMANDS__e2ee_msg;

    protocol_msg->payload.len = org__e2eelab__skissm__proto__e2ee_message__get_packed_size(outbound_message);
    protocol_msg->payload.data = (uint8_t *) malloc(protocol_msg->payload.len);
    org__e2eelab__skissm__proto__e2ee_message__pack(outbound_message, protocol_msg->payload.data);

    size_t message_len = org__e2eelab__skissm__proto__e2ee_protocol_msg__get_packed_size(protocol_msg);
    uint8_t *message = (uint8_t *) malloc(sizeof(uint8_t) * message_len);
    org__e2eelab__skissm__proto__e2ee_protocol_msg__pack(protocol_msg, message);

    // send message to server
    ssm_handler.handle_send(message, message_len);

    // store sesson state
    ssm_handler.store_session(session);

    // release
    free_mem((void **)(&message), message_len);
    org__e2eelab__skissm__proto__e2ee_message__free_unpacked(outbound_message, NULL);
    org__e2eelab__skissm__proto__e2ee_protocol_msg__free_unpacked(protocol_msg, NULL);

    // done
    return message_len;
}

static void handle_pre_key_bundle_response(
    Org__E2eelab__Skissm__Proto__E2eePreKeyBundle *their_pre_key_bundle,
    Org__E2eelab__Skissm__Proto__E2eeAddress *from,
    Org__E2eelab__Skissm__Proto__E2eeAddress *to,
    const uint8_t *context, size_t context_len
) {
    Org__E2eelab__Skissm__Proto__E2eeSession *session = (Org__E2eelab__Skissm__Proto__E2eeSession *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeSession));
    initialise_session(session, from, to);
    copy_address_from_address(&(session->session_owner), from);
    Org__E2eelab__Skissm__Proto__E2eeAccount *local_account = get_local_account(from);
    new_outbound_session(session, local_account, their_pre_key_bundle);
    perform_encrypt_session(session, context, context_len);

    // release
    close_session(session);
}

static pre_key_bundle_response_handler pre_key_bundle_handler = {
    NULL,
    NULL,
    NULL,
    0,
    handle_pre_key_bundle_response
};

size_t encrypt_session(
    Org__E2eelab__Skissm__Proto__E2eeAddress *from,
    Org__E2eelab__Skissm__Proto__E2eeAddress *to,
    const uint8_t *context, size_t context_len
) {
    Org__E2eelab__Skissm__Proto__E2eeSession *session = NULL;
    ssm_handler.load_outbound_session(from, to, &session);
    if (session == NULL){
        pre_key_bundle_handler.from = from;
        pre_key_bundle_handler.to = to;
        pre_key_bundle_handler.context = (uint8_t *)context;
        pre_key_bundle_handler.context_len = context_len;
        send_get_pre_key_bundle_request(to, context, context_len, &pre_key_bundle_handler);
        return (size_t)(0);
    }

    perform_encrypt_session(session, context, context_len);

    close_session(session);

    return (size_t)(0);
}

size_t decrypt_session(
    Org__E2eelab__Skissm__Proto__E2eeMessage *inbound_message
) {
    Org__E2eelab__Skissm__Proto__E2eePreKeyPayload *pre_key_context = NULL;
    Org__E2eelab__Skissm__Proto__E2eeMsgPayload *msg_payload = NULL;

    if (inbound_message->msg_type != ORG__E2EELAB__SKISSM__PROTO__E2EE_MESSAGE_TYPE__PRE_KEY
        && inbound_message->msg_type != ORG__E2EELAB__SKISSM__PROTO__E2EE_MESSAGE_TYPE__MESSAGE
    ) {
        ssm_notify_error(BAD_MESSAGE_FORMAT, "decrypt_session()");
        return (size_t)(-1);
    }

    if (inbound_message->session_id.data == NULL){
        ssm_notify_error(BAD_MESSAGE_FORMAT, "decrypt_session()");
        return (size_t)(-1);
    }

    /* load the corresponding inbound session */
    Org__E2eelab__Skissm__Proto__E2eeSession *session = NULL;
    ssm_handler.load_inbound_session(inbound_message->session_id, inbound_message->to, &session);
    if (session == NULL){
        if (inbound_message->msg_type != ORG__E2EELAB__SKISSM__PROTO__E2EE_MESSAGE_TYPE__PRE_KEY){
            ssm_notify_error(BAD_MESSAGE_FORMAT, "decrypt_session()");
            return (size_t)(-1);
        }
        /* delete the old inbound session if it exists */
        ssm_handler.unload_session(inbound_message->to, inbound_message->from, inbound_message->to);
        /* create a new inbound session */
        session = (Org__E2eelab__Skissm__Proto__E2eeSession *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeSession));
        initialise_session(session, inbound_message->from, inbound_message->to);
        copy_address_from_address(&(session->session_owner), inbound_message->to);
        Org__E2eelab__Skissm__Proto__E2eeAccount *local_account = get_local_account(inbound_message->to);
        size_t result = new_inbound_session(session, local_account, inbound_message);

        if (result == (size_t)(-1) || compare_protobuf(&(session->session_id), &(inbound_message->session_id)) == false){
            close_session(session);
            ssm_notify_error(BAD_MESSAGE_FORMAT, "decrypt_session()");
            return (size_t)(-1);
        }
    }

    uint8_t *context = NULL;
    size_t context_len = -1;
    if (inbound_message->msg_type == ORG__E2EELAB__SKISSM__PROTO__E2EE_MESSAGE_TYPE__MESSAGE){
        msg_payload = org__e2eelab__skissm__proto__e2ee_msg_payload__unpack(NULL, inbound_message->payload.len, inbound_message->payload.data);
    } else if (inbound_message->msg_type == ORG__E2EELAB__SKISSM__PROTO__E2EE_MESSAGE_TYPE__PRE_KEY){
        pre_key_context = org__e2eelab__skissm__proto__e2ee_pre_key_payload__unpack(NULL, inbound_message->payload.len, inbound_message->payload.data);
        msg_payload = pre_key_context->msg_payload;
    }

    if (msg_payload != NULL) {
        context_len = decrypt_ratchet(session->ratchet, session->associated_data, msg_payload, &context);

        // store sesson state
        ssm_handler.store_session(session);

        if (context_len == (size_t)(-1)){
            ssm_notify_error(BAD_MESSAGE_DECRYPTION, "decrypt_session()");
            goto complete;
        } else{
            Org__E2eelab__Skissm__Proto__E2eePlaintext *e2ee_plaintext = org__e2eelab__skissm__proto__e2ee_plaintext__unpack(NULL, context_len, context);
            if (e2ee_plaintext->plaintext_type == ORG__E2EELAB__SKISSM__PROTO__E2EE_PLAINTEXT_TYPE__COMMON_MSG){
                ssm_notify_one2one_msg(inbound_message->from, inbound_message->to, e2ee_plaintext->payload.data, e2ee_plaintext->payload.len);
            } else if (e2ee_plaintext->plaintext_type == ORG__E2EELAB__SKISSM__PROTO__E2EE_PLAINTEXT_TYPE__GROUP_PRE_KEY){
                Org__E2eelab__Skissm__Proto__E2eeGroupPreKeyPayload *group_pre_key_payload = org__e2eelab__skissm__proto__e2ee_group_pre_key_payload__unpack(NULL, e2ee_plaintext->payload.len, e2ee_plaintext->payload.data);
                ssm_handler.unload_inbound_group_session(inbound_message->to, group_pre_key_payload->group_address, group_pre_key_payload->n_member_addresses, group_pre_key_payload->member_addresses);
                create_inbound_group_session(group_pre_key_payload, inbound_message->to);
                org__e2eelab__skissm__proto__e2ee_group_pre_key_payload__free_unpacked(group_pre_key_payload, NULL);
            }
        }

        // try to find outbound session
        Org__E2eelab__Skissm__Proto__E2eeSession *outbound_session = NULL;
        ssm_handler.load_outbound_session(inbound_message->to, inbound_message->from, &outbound_session);
        if (outbound_session != NULL){
            if (outbound_session->responded == false){
                outbound_session->responded = true;
                ssm_handler.store_session(outbound_session);
            }
        }

        // release
        free_mem((void **)&context, context_len);
    }

complete:
    // release
    if (inbound_message->msg_type == ORG__E2EELAB__SKISSM__PROTO__E2EE_MESSAGE_TYPE__MESSAGE){
        org__e2eelab__skissm__proto__e2ee_msg_payload__free_unpacked(msg_payload, NULL);
    } else if (inbound_message->msg_type == ORG__E2EELAB__SKISSM__PROTO__E2EE_MESSAGE_TYPE__PRE_KEY){
        org__e2eelab__skissm__proto__e2ee_pre_key_payload__free_unpacked(pre_key_context, NULL);
    }
    close_session(session);

    // done
    return context_len;
}

void describe(Org__E2eelab__Skissm__Proto__E2eeSession *session, char *describe_buffer, size_t buflen) {
    if (buflen == 0) return;

    describe_buffer[0] = '\0';
    char *buf_pos = describe_buffer;

    int size;

    size = snprintf(
        buf_pos, buflen - (buf_pos - describe_buffer),
        "sender chain index: %d ", session->ratchet->sender_chain->chain_key->index
    );
    if (size > 0) buf_pos += size;

    size = snprintf(buf_pos, buflen - (buf_pos - describe_buffer), "receiver chain indices:");
    if (size > 0) buf_pos += size;
    int i;
    for (i = 0; i < session->ratchet->n_receiver_chains; i++){
        size = snprintf(
            buf_pos, buflen - (buf_pos - describe_buffer),
            " %d", session->ratchet->receiver_chains[i]->chain_key->index
        );
        if (size > 0) buf_pos += size;
    }

    size = snprintf(buf_pos, buflen - (buf_pos - describe_buffer), " skipped message keys:");
    if (size >= 0) buf_pos += size;
    for (i = 0; i < session->ratchet->n_skipped_message_keys; i++){
        size = snprintf(
            buf_pos, buflen - (buf_pos - describe_buffer),
            " %d", session->ratchet->skipped_message_keys[i]->message_key->index
        );
        if (size > 0) buf_pos += size;
    }
}
