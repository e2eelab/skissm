#include "skissm/session_manager.h"

#include <stdio.h>
#include <string.h>

#include "skissm/account.h"
#include "skissm/e2ee_protocol.h"
#include "skissm/error.h"
#include "skissm/group_session.h"
#include "skissm/mem_util.h"
#include "skissm/ratchet.h"
#include "skissm/session.h"

Skissm__GetPreKeyBundleRequestPayload *produce_get_pre_key_bundle_request_payload(Skissm__E2eeAddress *e2ee_address) {
    Skissm__GetPreKeyBundleRequestPayload *get_pre_key_bundle_request_payload =
        (Skissm__GetPreKeyBundleRequestPayload *)malloc(sizeof(Skissm__GetPreKeyBundleRequestPayload));
    skissm__get_pre_key_bundle_request_payload__init(get_pre_key_bundle_request_payload);
    copy_address_from_address(&(get_pre_key_bundle_request_payload->peer_address), e2ee_address);
    return get_pre_key_bundle_request_payload;
}

size_t consume_get_pre_key_bundle_response_payload(
    Skissm__E2eeAddress *from,
    Skissm__E2eeAddress *to,
    Skissm__GetPreKeyBundleResponsePayload *get_pre_key_bundle_response_payload) {
    Skissm__E2eePreKeyBundle *their_pre_key_bundle = get_pre_key_bundle_response_payload->pre_key_bundle;

    Skissm__E2eeSession *outbound_session = (Skissm__E2eeSession *) malloc(sizeof(Skissm__E2eeSession));
    initialise_session(outbound_session, from, to);
    copy_address_from_address(&(outbound_session->session_owner), from);
    Skissm__E2eeAccount *local_account = get_local_account(from);
    const session_suite *suite = get_session_suite(their_pre_key_bundle->cipher_suite_id);
    size_t result = suite->new_outbound_session(outbound_session, local_account, their_pre_key_bundle);

    if (result == (size_t)(-1)) {
        close_session(outbound_session);
        ssm_notify_error(BAD_SESSION, "consume_get_pre_key_bundle_response_payload()");
        return (size_t)(-1);
    }

    // store sesson state (We have store the session in the new_outbound_session)
    //get_skissm_plugin()->db_handler.store_session(outbound_session);

    // release
    close_session(outbound_session);

    return (size_t)(0);
}

Skissm__E2eeMsg *produce_e2ee_message_payload(Skissm__E2eeSession *outbound_session, const uint8_t *e2ee_plaintext, size_t e2ee_plaintext_len) {
    Skissm__E2eeMsg *outbound_e2ee_message_payload;
    outbound_e2ee_message_payload = (Skissm__E2eeMsg *)malloc(sizeof(Skissm__E2eeMsg));
    skissm__e2ee_msg__init(outbound_e2ee_message_payload);

    outbound_e2ee_message_payload->version = PROTOCOL_VERSION;
    outbound_e2ee_message_payload->session_id = strdup(outbound_session->session_id);
    outbound_e2ee_message_payload->msg_id = generate_uuid_str();
    copy_address_from_address(&(outbound_e2ee_message_payload->from), outbound_session->from);
    copy_address_from_address(&(outbound_e2ee_message_payload->to), outbound_session->to);

    Skissm__E2eeMsgPayload *msg_context = NULL;

    outbound_e2ee_message_payload->e2ee_msg_type = SKISSM__E2EE_MSG_TYPE__MESSAGE;
    encrypt_ratchet(outbound_session->ratchet, outbound_session->associated_data, e2ee_plaintext, e2ee_plaintext_len, &msg_context);

    size_t msg_len = skissm__e2ee_msg_payload__get_packed_size(msg_context);
    outbound_e2ee_message_payload->payload.len = msg_len;
    outbound_e2ee_message_payload->payload.data = (uint8_t *)malloc(sizeof(uint8_t) * msg_len);
    skissm__e2ee_msg_payload__pack(msg_context, outbound_e2ee_message_payload->payload.data);

    return outbound_e2ee_message_payload;
}

size_t consume_e2ee_message_payload(Skissm__E2eeMsg *inbound_e2ee_message_payload) {
    //Skissm__E2eePreKeyPayload *pre_key_context = NULL;
    Skissm__E2eeMsgPayload *msg_payload = NULL;

    if (inbound_e2ee_message_payload->e2ee_msg_type != SKISSM__E2EE_MSG_TYPE__PRE_KEY && inbound_e2ee_message_payload->e2ee_msg_type != SKISSM__E2EE_MSG_TYPE__MESSAGE) {
        ssm_notify_error(BAD_MESSAGE_FORMAT, "consume_e2ee_message_payload()");
        return (size_t)(-1);
    }

    if (inbound_e2ee_message_payload->session_id == NULL) {
        ssm_notify_error(BAD_MESSAGE_FORMAT, "consume_e2ee_message_payload()");
        return (size_t)(-1);
    }

    /* load the corresponding inbound session */
    Skissm__E2eeSession *inbound_session = NULL;
    get_skissm_plugin()->db_handler.load_inbound_session(inbound_e2ee_message_payload->session_id, inbound_e2ee_message_payload->to, &inbound_session);
    if (inbound_session == NULL) {
        ssm_notify_error(BAD_SESSION, "consume_e2ee_message_payload()");
        return (size_t)(-1);
        /* delete the old inbound session if it exists */
        get_skissm_plugin()->db_handler.unload_session(inbound_e2ee_message_payload->to, inbound_e2ee_message_payload->from, inbound_e2ee_message_payload->to);
    }

    uint8_t *context = NULL;
    size_t context_len = -1;
    if (inbound_e2ee_message_payload->e2ee_msg_type == SKISSM__E2EE_MSG_TYPE__MESSAGE) {
        msg_payload = skissm__e2ee_msg_payload__unpack(NULL, inbound_e2ee_message_payload->payload.len, inbound_e2ee_message_payload->payload.data);
    }

    if (msg_payload != NULL) {
        context_len = decrypt_ratchet(inbound_session->ratchet, inbound_session->associated_data, msg_payload, &context);

        // store sesson state
        get_skissm_plugin()->db_handler.store_session(inbound_session);

        if (context_len == (size_t)(-1)) {
            ssm_notify_error(BAD_MESSAGE_DECRYPTION, "consume_e2ee_message_payload()");
            goto complete;
        } else {
            Skissm__E2eePlaintext *e2ee_plaintext = skissm__e2ee_plaintext__unpack(NULL, context_len, context);
            if (e2ee_plaintext != NULL) {
                if (e2ee_plaintext->plaintext_type == SKISSM__E2EE_PLAINTEXT_TYPE__COMMON_MSG) {
                    ssm_notify_one2one_msg(inbound_e2ee_message_payload->from, inbound_e2ee_message_payload->to, e2ee_plaintext->payload.data, e2ee_plaintext->payload.len);
                } else if (e2ee_plaintext->plaintext_type == SKISSM__E2EE_PLAINTEXT_TYPE__GROUP_PRE_KEY) {
                    Skissm__E2eeGroupPreKeyPayload *group_pre_key_payload = skissm__e2ee_group_pre_key_payload__unpack(NULL, e2ee_plaintext->payload.len, e2ee_plaintext->payload.data);
                    get_skissm_plugin()->db_handler.unload_inbound_group_session(inbound_e2ee_message_payload->to, group_pre_key_payload->old_session_id);
                    create_inbound_group_session(group_pre_key_payload, inbound_e2ee_message_payload->to);
                    skissm__e2ee_group_pre_key_payload__free_unpacked(group_pre_key_payload, NULL);
                }
                skissm__e2ee_plaintext__free_unpacked(e2ee_plaintext, NULL);
            } else {
                ssm_notify_error(BAD_MESSAGE_FORMAT, "consume_e2ee_message_payload(), skissm__e2ee_plaintext__unpack() error");
            }
        }

        // try to find outbound session, and mark it's state as responded
        Skissm__E2eeSession *outbound_session = NULL;
        get_skissm_plugin()->db_handler.load_outbound_session(inbound_e2ee_message_payload->to, inbound_e2ee_message_payload->from, &outbound_session);
        if (outbound_session != NULL) {
            if (outbound_session->responded == false) {
                outbound_session->responded = true;
                get_skissm_plugin()->db_handler.store_session(outbound_session);
            }
        }

        // release
        free_mem((void **)&context, context_len);
        close_session(outbound_session);
    }

complete:
    // release
    if (inbound_e2ee_message_payload->e2ee_msg_type == SKISSM__E2EE_MSG_TYPE__MESSAGE) {
        skissm__e2ee_msg_payload__free_unpacked(msg_payload, NULL);
    }
    close_session(inbound_session);

    // done
    return context_len;
}

Skissm__E2eeInvitePayload *produce_e2ee_invite_payload(
    Skissm__E2eeSession *outbound_session, ProtobufCBinaryData *pre_shared_key_1,
    ProtobufCBinaryData *pre_shared_key_2, ProtobufCBinaryData *pre_shared_key_3
) {
    if ((pre_shared_key_2 != NULL && pre_shared_key_3 == NULL) || (pre_shared_key_2 == NULL && pre_shared_key_3 != NULL)){
        return NULL;
    }
    Skissm__E2eeInvitePayload *e2ee_invite_payload = (Skissm__E2eeInvitePayload *) malloc(sizeof(Skissm__E2eeInvitePayload));
    skissm__e2ee_invite_payload__init(e2ee_invite_payload);

    e2ee_invite_payload->cipher_suite_id = outbound_session->cipher_suite_id;

    copy_protobuf_from_protobuf(&(e2ee_invite_payload->alice_identity_key), &(outbound_session->alice_identity_key));
    if (pre_shared_key_2 == NULL){
        // In the ECC version, the ephemeral public key will be sent
        e2ee_invite_payload->n_pre_shared_key = 1;
        e2ee_invite_payload->pre_shared_key = (ProtobufCBinaryData *) malloc(sizeof(ProtobufCBinaryData));
        copy_protobuf_from_protobuf(e2ee_invite_payload->pre_shared_key, pre_shared_key_1);
    } else{
        // In the PQC version, three "ciphertexts" will be sent
        size_t pre_shared_key_len = pre_shared_key_1->len;
        e2ee_invite_payload->n_pre_shared_key = 3;
        e2ee_invite_payload->pre_shared_key = (ProtobufCBinaryData *) malloc(sizeof(ProtobufCBinaryData) * 3);
        copy_protobuf_from_protobuf(e2ee_invite_payload->pre_shared_key, pre_shared_key_1);
        copy_protobuf_from_protobuf(e2ee_invite_payload->pre_shared_key + pre_shared_key_len, pre_shared_key_2);
        copy_protobuf_from_protobuf(e2ee_invite_payload->pre_shared_key + pre_shared_key_len + pre_shared_key_len, pre_shared_key_3);
    }
    e2ee_invite_payload->bob_signed_pre_key_id = outbound_session->bob_signed_pre_key_id;
    e2ee_invite_payload->bob_one_time_pre_key_id = outbound_session->bob_one_time_pre_key_id;

    return e2ee_invite_payload;
}

size_t consume_e2ee_invite_payload(Skissm__E2eeMsg *invite_msg_payload){
    /* create a new inbound session */
    Skissm__E2eeSession *inbound_session = (Skissm__E2eeSession *)malloc(sizeof(Skissm__E2eeSession));
    initialise_session(inbound_session, invite_msg_payload->from, invite_msg_payload->to);
    copy_address_from_address(&(inbound_session->session_owner), invite_msg_payload->to);
    Skissm__E2eeAccount *local_account = get_local_account(invite_msg_payload->to);
    Skissm__E2eeInvitePayload *e2ee_invite_payload = skissm__e2ee_invite_payload__unpack(NULL, invite_msg_payload->payload.len, invite_msg_payload->payload.data);
    const session_suite *suite = get_session_suite(e2ee_invite_payload->cipher_suite_id);
    // Set the version and session id
    inbound_session->version = invite_msg_payload->version;
    inbound_session->session_id = strdup(invite_msg_payload->session_id);
    // create a new inbound session
    size_t result = suite->new_inbound_session(inbound_session, local_account, e2ee_invite_payload);

    if (result == (size_t)(-1)
        || safe_strcmp(inbound_session->session_id, invite_msg_payload->session_id) == false) {
        close_session(inbound_session);
        ssm_notify_error(BAD_MESSAGE_FORMAT, "consume_e2ee_invite_payload()");
        return (size_t)(-1);
    }

    // store sesson state
    get_skissm_plugin()->db_handler.store_session(inbound_session);

    // notify
    ssm_notify_inbound_session_ready(inbound_session);

    return (size_t)(0);
}

Skissm__E2eeAcceptPayload *produce_e2ee_accept_payload(uint32_t cipher_suite_id, ProtobufCBinaryData *ciphertext_1) {
    Skissm__E2eeAcceptPayload *e2ee_accept_payload = (Skissm__E2eeAcceptPayload *) malloc(sizeof(Skissm__E2eeAcceptPayload));
    skissm__e2ee_accept_payload__init(e2ee_accept_payload);

    e2ee_accept_payload->cipher_suite_id = cipher_suite_id;

    if (ciphertext_1 == NULL){
        e2ee_accept_payload->n_pre_shared_key = 0;
        e2ee_accept_payload->pre_shared_key = NULL;
    } else{
        e2ee_accept_payload->n_pre_shared_key = 1;
        e2ee_accept_payload->pre_shared_key = (ProtobufCBinaryData *) malloc(sizeof(ProtobufCBinaryData) * 1);
        copy_protobuf_from_protobuf(e2ee_accept_payload->pre_shared_key, ciphertext_1);
    }

    return e2ee_accept_payload;
}

size_t consume_e2ee_accept_payload(Skissm__E2eeMsg *accept_msg_payload){
    Skissm__E2eeSession *outbound_session = NULL;
    // Is it unique?
    get_skissm_plugin()->db_handler.load_outbound_session(accept_msg_payload->to, accept_msg_payload->from, &outbound_session);
    if (outbound_session == NULL){
        ssm_notify_error(BAD_MESSAGE_FORMAT, "consume_e2ee_accept_payload()");
        return (size_t)(-1);
    }
    Skissm__E2eeAcceptPayload *e2ee_accept_payload = skissm__e2ee_accept_payload__unpack(NULL, accept_msg_payload->payload.len, accept_msg_payload->payload.data);
    const session_suite *suite = get_session_suite(e2ee_accept_payload->cipher_suite_id);
    size_t result = suite->complete_outbound_session(outbound_session, e2ee_accept_payload);

    // store sesson state
    get_skissm_plugin()->db_handler.store_session(outbound_session);

    // notify
    ssm_notify_outbound_session_ready(outbound_session);

    return (size_t)(0);
}

Skissm__E2eeMsg *produce_invite_message_payload(Skissm__E2eeSession *outbound_session, Skissm__E2eeInvitePayload *e2ee_invite_payload){
    Skissm__E2eeMsg *invite_message_payload;
    invite_message_payload = (Skissm__E2eeMsg *)malloc(sizeof(Skissm__E2eeMsg));
    skissm__e2ee_msg__init(invite_message_payload);

    invite_message_payload->e2ee_msg_type = SKISSM__E2EE_MSG_TYPE__INVITE;
    invite_message_payload->version = outbound_session->version;
    copy_address_from_address(&(invite_message_payload->from), outbound_session->from);
    copy_address_from_address(&(invite_message_payload->to), outbound_session->to);
    invite_message_payload->session_id = strdup(outbound_session->session_id);

    invite_message_payload->payload.len = skissm__e2ee_invite_payload__get_packed_size(e2ee_invite_payload);
    invite_message_payload->payload.data = (uint8_t *)malloc(sizeof(uint8_t) * invite_message_payload->payload.len);
    skissm__e2ee_invite_payload__pack(e2ee_invite_payload, invite_message_payload->payload.data);

    return invite_message_payload;
}

Skissm__E2eeMsg *produce_accept_message_payload(Skissm__E2eeAddress *from, Skissm__E2eeAddress *to, Skissm__E2eeAcceptPayload *e2ee_accept_payload){
    Skissm__E2eeMsg *accept_message_payload;
    accept_message_payload = (Skissm__E2eeMsg *)malloc(sizeof(Skissm__E2eeMsg));
    skissm__e2ee_msg__init(accept_message_payload);

    accept_message_payload->e2ee_msg_type = SKISSM__E2EE_MSG_TYPE__ACCEPT;

    copy_address_from_address(&(accept_message_payload->from), from);
    copy_address_from_address(&(accept_message_payload->to), to);

    accept_message_payload->payload.len = skissm__e2ee_accept_payload__get_packed_size(e2ee_accept_payload);
    accept_message_payload->payload.data = (uint8_t *)malloc(sizeof(uint8_t) * accept_message_payload->payload.len);
    skissm__e2ee_accept_payload__pack(e2ee_accept_payload, accept_message_payload->payload.data);

    return accept_message_payload;
}

static void handle_pre_key_bundle_release(pre_key_bundle_response_handler *this_response_handler) {
    this_response_handler->from = NULL;
    this_response_handler->to = NULL;
}

static pre_key_bundle_response_handler pre_key_bundle_handler = {NULL, NULL, handle_pre_key_bundle_release};

static void create_outbound_session(Skissm__E2eeAddress *from, Skissm__E2eeAddress *to) {
    // there is no outbound session, create a new one after receiving the pre-key bundle of receipient(to).
    pre_key_bundle_handler.from = from;
    pre_key_bundle_handler.to = to;
    send_get_pre_key_bundle_request(to, &pre_key_bundle_handler);
}

Skissm__E2eeSession *get_outbound_session(Skissm__E2eeAddress *from, Skissm__E2eeAddress *to) {
    Skissm__E2eeSession *outbound_session = NULL;
    get_skissm_plugin()->db_handler.load_outbound_session(from, to, &outbound_session);
    if (outbound_session != NULL) {
        return outbound_session;
    } else {
        create_outbound_session(from, to);
        return NULL;
    }
}
