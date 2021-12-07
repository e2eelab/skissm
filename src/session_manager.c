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
#include "skissm/skissm.h"

Skissm__GetPreKeyBundleRequestPayload *produce_get_pre_key_bundle_request_payload(Skissm__E2eeAddress *e2ee_address) {
        Skissm__GetPreKeyBundleRequestPayload *get_pre_key_bundle_request_payload =
        (Skissm__GetPreKeyBundleRequestPayload *)malloc(sizeof(Skissm__GetPreKeyBundleRequestPayload));
    skissm__get_pre_key_bundle_request_payload__init(get_pre_key_bundle_request_payload);
    copy_address_from_address(&(get_pre_key_bundle_request_payload->peer_address), e2ee_address);
    return get_pre_key_bundle_request_payload;
}

void consume_get_pre_key_bundle_response_payload(
    Skissm__E2eeAddress *from,
    Skissm__E2eeAddress *to,
    Skissm__GetPreKeyBundleResponsePayload *get_pre_key_bundle_response_payload) {
    Skissm__E2eePreKeyBundle *their_pre_key_bundle = get_pre_key_bundle_response_payload->pre_key_bundle;

    Skissm__E2eeSession *outbound_session = (Skissm__E2eeSession *) malloc(sizeof(Skissm__E2eeSession));
    initialise_session(outbound_session, from, to);
    copy_address_from_address(&(outbound_session->session_owner), from);
    Skissm__E2eeAccount *local_account = get_local_account(from);
    new_outbound_session(outbound_session, local_account, their_pre_key_bundle);

    // store sesson state
    get_ssm_plugin()->store_session(outbound_session);

    // release
    close_session(outbound_session);
}

Skissm__E2eeMessage *produce_e2ee_message_payload(Skissm__E2eeSession *outbound_session, const uint8_t *e2ee_plaintext, size_t e2ee_plaintext_len) {
    Skissm__E2eeMessage *outbound_e2ee_message_payload;
    outbound_e2ee_message_payload = (Skissm__E2eeMessage *)malloc(sizeof(Skissm__E2eeMessage));
    skissm__e2ee_message__init(outbound_e2ee_message_payload);

    outbound_e2ee_message_payload->version = PROTOCOL_VERSION;
    copy_protobuf_from_protobuf(&(outbound_e2ee_message_payload->session_id), &(outbound_session->session_id));
    copy_address_from_address(&(outbound_e2ee_message_payload->from), outbound_session->from);
    copy_address_from_address(&(outbound_e2ee_message_payload->to), outbound_session->to);

    Skissm__E2eeMsgPayload *msg_context = NULL;

    if (outbound_session->responded) {
        outbound_e2ee_message_payload->msg_type = SKISSM__E2EE_MESSAGE_TYPE__MESSAGE;
        encrypt_ratchet(outbound_session->ratchet, outbound_session->associated_data, e2ee_plaintext, e2ee_plaintext_len, &msg_context);

        size_t msg_len = skissm__e2ee_msg_payload__get_packed_size(msg_context);
        outbound_e2ee_message_payload->payload.len = msg_len;
        outbound_e2ee_message_payload->payload.data = (uint8_t *)malloc(sizeof(uint8_t) * msg_len);
        skissm__e2ee_msg_payload__pack(msg_context, outbound_e2ee_message_payload->payload.data);
    } else {
        outbound_e2ee_message_payload->msg_type = SKISSM__E2EE_MESSAGE_TYPE__PRE_KEY;
        Skissm__E2eePreKeyPayload *pre_key_context = (Skissm__E2eePreKeyPayload *)malloc(sizeof(Skissm__E2eePreKeyPayload));
        skissm__e2ee_pre_key_payload__init(pre_key_context);
        copy_protobuf_from_protobuf(&pre_key_context->alice_identity_key, &outbound_session->alice_identity_key);
        copy_protobuf_from_protobuf(&pre_key_context->alice_ephemeral_key, &outbound_session->alice_ephemeral_key);
        pre_key_context->bob_signed_pre_key_id = outbound_session->bob_signed_pre_key_id;
        pre_key_context->bob_one_time_pre_key_id = outbound_session->bob_one_time_pre_key_id;

        encrypt_ratchet(outbound_session->ratchet, outbound_session->associated_data, e2ee_plaintext, e2ee_plaintext_len, &msg_context);

        pre_key_context->msg_payload = msg_context;

        size_t pre_key_len = skissm__e2ee_pre_key_payload__get_packed_size(pre_key_context);
        outbound_e2ee_message_payload->payload.len = pre_key_len;
        outbound_e2ee_message_payload->payload.data = (uint8_t *)malloc(sizeof(uint8_t) * pre_key_len);
        skissm__e2ee_pre_key_payload__pack(pre_key_context, outbound_e2ee_message_payload->payload.data);
    }

    return outbound_e2ee_message_payload;
}

size_t consume_e2ee_message_payload(Skissm__E2eeMessage *inbound_e2ee_message_payload) {
    Skissm__E2eePreKeyPayload *pre_key_context = NULL;
    Skissm__E2eeMsgPayload *msg_payload = NULL;

    if (inbound_e2ee_message_payload->msg_type != SKISSM__E2EE_MESSAGE_TYPE__PRE_KEY && inbound_e2ee_message_payload->msg_type != SKISSM__E2EE_MESSAGE_TYPE__MESSAGE) {
        ssm_notify_error(BAD_MESSAGE_FORMAT, "consume_e2ee_message_payload()");
        return (size_t)(-1);
    }

    if (inbound_e2ee_message_payload->session_id.data == NULL) {
        ssm_notify_error(BAD_MESSAGE_FORMAT, "consume_e2ee_message_payload()");
        return (size_t)(-1);
    }

    /* load the corresponding inbound session */
    Skissm__E2eeSession *inbound_session = NULL;
    get_ssm_plugin()->load_inbound_session(inbound_e2ee_message_payload->session_id, inbound_e2ee_message_payload->to, &inbound_session);
    if (inbound_session == NULL) {
        if (inbound_e2ee_message_payload->msg_type != SKISSM__E2EE_MESSAGE_TYPE__PRE_KEY) {
            ssm_notify_error(BAD_MESSAGE_FORMAT, "consume_e2ee_message_payload()");
            return (size_t)(-1);
        }
        /* delete the old inbound session if it exists */
        get_ssm_plugin()->unload_session(inbound_e2ee_message_payload->to, inbound_e2ee_message_payload->from, inbound_e2ee_message_payload->to);
        /* create a new inbound session */
        inbound_session = (Skissm__E2eeSession *)malloc(sizeof(Skissm__E2eeSession));
        initialise_session(inbound_session, inbound_e2ee_message_payload->from, inbound_e2ee_message_payload->to);
        copy_address_from_address(&(inbound_session->session_owner), inbound_e2ee_message_payload->to);
        Skissm__E2eeAccount *local_account = get_local_account(inbound_e2ee_message_payload->to);
        size_t result = new_inbound_session(inbound_session, local_account, inbound_e2ee_message_payload);

        if (result == (size_t)(-1) || compare_protobuf(&(inbound_session->session_id), &(inbound_e2ee_message_payload->session_id)) == false) {
            close_session(inbound_session);
            ssm_notify_error(BAD_MESSAGE_FORMAT, "consume_e2ee_message_payload()");
            return (size_t)(-1);
        }
    }

    uint8_t *context = NULL;
    size_t context_len = -1;
    if (inbound_e2ee_message_payload->msg_type == SKISSM__E2EE_MESSAGE_TYPE__MESSAGE) {
        msg_payload = skissm__e2ee_msg_payload__unpack(NULL, inbound_e2ee_message_payload->payload.len, inbound_e2ee_message_payload->payload.data);
    } else if (inbound_e2ee_message_payload->msg_type == SKISSM__E2EE_MESSAGE_TYPE__PRE_KEY) {
        pre_key_context = skissm__e2ee_pre_key_payload__unpack(NULL, inbound_e2ee_message_payload->payload.len, inbound_e2ee_message_payload->payload.data);
        msg_payload = pre_key_context->msg_payload;
    }

    if (msg_payload != NULL) {
        context_len = decrypt_ratchet(inbound_session->ratchet, inbound_session->associated_data, msg_payload, &context);

        // store sesson state
        get_ssm_plugin()->store_session(inbound_session);

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
                    get_ssm_plugin()->unload_inbound_group_session(inbound_e2ee_message_payload->to, &(group_pre_key_payload->old_session_id));
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
        get_ssm_plugin()->load_outbound_session(inbound_e2ee_message_payload->to, inbound_e2ee_message_payload->from, &outbound_session);
        if (outbound_session != NULL) {
            if (outbound_session->responded == false) {
                outbound_session->responded = true;
                get_ssm_plugin()->store_session(outbound_session);
            }
        }

        // release
        free_mem((void **)&context, context_len);
        close_session(outbound_session);
    }

complete:
    // release
    if (inbound_e2ee_message_payload->msg_type == SKISSM__E2EE_MESSAGE_TYPE__MESSAGE) {
        skissm__e2ee_msg_payload__free_unpacked(msg_payload, NULL);
    } else if (inbound_e2ee_message_payload->msg_type == SKISSM__E2EE_MESSAGE_TYPE__PRE_KEY) {
        skissm__e2ee_pre_key_payload__free_unpacked(pre_key_context, NULL);
    }
    close_session(inbound_session);

    // done
    return context_len;
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

size_t encrypt_session(Skissm__E2eeAddress *from, Skissm__E2eeAddress *to, const uint8_t *e2ee_plaintext, size_t e2ee_plaintext_len) {
    Skissm__E2eeSession *outbound_session = NULL;
    get_ssm_plugin()->load_outbound_session(from, to, &outbound_session);
    if (outbound_session == NULL) {
        create_outbound_session(from, to);
        get_ssm_plugin()->load_outbound_session(from, to, &outbound_session);
    }

    send_one2one_msg(outbound_session, e2ee_plaintext, e2ee_plaintext_len);

    close_session(outbound_session);
    return (size_t)0;
}
