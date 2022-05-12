#include "skissm/session_manager.h"

#include <stdio.h>
#include <string.h>

#include "skissm/account.h"
#include "skissm/e2ee_client.h"
#include "skissm/e2ee_client_internal.h"
#include "skissm/error.h"
#include "skissm/group_session.h"
#include "skissm/mem_util.h"
#include "skissm/ratchet.h"
#include "skissm/session.h"

static void send_group_pre_key(Skissm__Session *outbound_session){
    // load group pre-key
    uint32_t n_group_pre_keys;
    uint8_t **group_pre_key_plaintext_data_list;
    size_t *group_pre_key_plaintext_data_len_list;
    n_group_pre_keys = get_skissm_plugin()->db_handler.load_group_pre_keys(outbound_session->to, &group_pre_key_plaintext_data_list, &group_pre_key_plaintext_data_len_list);
    if (n_group_pre_keys > 0) {
        unsigned int i;
        bool succ = true;
        for (i = 0; i < n_group_pre_keys; i++) {
            Skissm__SendOne2oneMsgResponse *response = send_one2one_msg_internal(outbound_session, group_pre_key_plaintext_data_list[i],
                                      group_pre_key_plaintext_data_len_list[i]);
            if (response == NULL) {
                succ = false;
                break;
            } else {
                // release
                skissm__send_one2one_msg_response__free_unpacked(response, NULL);
            }
        }

        // release
        for (i = 0; i < n_group_pre_keys; i++) {
            free_mem((void **) (&(group_pre_key_plaintext_data_list[i])),
                     group_pre_key_plaintext_data_len_list[i]);
        }
        free_mem((void **) (&group_pre_key_plaintext_data_list), sizeof(uint8_t *) * n_group_pre_keys);
        free_mem((void **) (&group_pre_key_plaintext_data_len_list), n_group_pre_keys);

        // done
        if (succ)
            get_skissm_plugin()->db_handler.unload_group_pre_key(outbound_session->to);
    }
}

Skissm__GetPreKeyBundleRequest *produce_get_pre_key_bundle_request(Skissm__E2eeAddress *peer_address) {
    Skissm__GetPreKeyBundleRequest *request =
        (Skissm__GetPreKeyBundleRequest *)malloc(sizeof(Skissm__GetPreKeyBundleRequest));
    skissm__get_pre_key_bundle_request__init(request);
    copy_address_from_address(&(request->peer_address), peer_address);
    return request;
}

Skissm__InviteResponse *consume_get_pre_key_bundle_response (
    Skissm__E2eeAddress *from,
    Skissm__E2eeAddress *to,
    Skissm__GetPreKeyBundleResponse *response) {
    if (response != NULL && response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
        Skissm__PreKeyBundle **their_pre_key_bundles = response->pre_key_bundles;
        size_t n_pre_key_bundles = response->n_pre_key_bundles;
        unsigned i;
        for (i = 0; i < n_pre_key_bundles; i++) {
            // find an account
            Skissm__Account *account = NULL;
            get_skissm_plugin()->db_handler.load_account_by_address(from, &account);
            if (account == NULL) {
                ssm_notify_error(BAD_ACCOUNT, "consume_get_pre_key_bundle_response()");
                return NULL;
            }

            const char *e2ee_pack_id = their_pre_key_bundles[i]->e2ee_pack_id;
            Skissm__Session *outbound_session = (Skissm__Session *) malloc(sizeof(Skissm__Session));
            initialise_session(outbound_session, e2ee_pack_id, from, to);
            copy_address_from_address(&(outbound_session->session_owner), from);

            const session_suite_t *session_suite = get_e2ee_pack(e2ee_pack_id)->session_suite;
            Skissm__InviteResponse *invite_response = session_suite->new_outbound_session(outbound_session,
                                                                                   account,their_pre_key_bundles[i]);
            // release
            skissm__account__free_unpacked(account, NULL);
            skissm__session__free_unpacked(outbound_session, NULL);

            // error check
            if (invite_response != NULL) {
                // return last invite response
                if (i == (n_pre_key_bundles-1))
                    return invite_response;
                else
                    skissm__invite_response__free_unpacked(invite_response, NULL);
            } else {
                ssm_notify_error(BAD_SESSION, "invite_response ()");
                return NULL;
            }
        }
        return NULL;
    } else {
        return NULL;
    }
}

Skissm__SendOne2oneMsgRequest *produce_send_one2one_msg_request(Skissm__Session *outbound_session, const uint8_t *plaintext_data, size_t plaintext_data_len) {
    const cipher_suite_t *cipher_suite = get_e2ee_pack(outbound_session->e2ee_pack_id)->cipher_suite;

    Skissm__SendOne2oneMsgRequest *request = (Skissm__SendOne2oneMsgRequest *)malloc(sizeof(Skissm__SendOne2oneMsgRequest));
    skissm__send_one2one_msg_request__init(request);

    /* Prepare an e2ee message */
    Skissm__E2eeMsg *e2ee_msg = (Skissm__E2eeMsg *)malloc(sizeof(Skissm__E2eeMsg));
    skissm__e2ee_msg__init(e2ee_msg);

    e2ee_msg->version = strdup(E2EE_PROTOCOL_VERSION);
    e2ee_msg->session_id = strdup(outbound_session->session_id);
    e2ee_msg->msg_id = generate_uuid_str();
    copy_address_from_address(&(e2ee_msg->from), outbound_session->from);
    copy_address_from_address(&(e2ee_msg->to), outbound_session->to);
    e2ee_msg->payload_case = SKISSM__E2EE_MSG__PAYLOAD_ONE2ONE_MSG;
    encrypt_ratchet(cipher_suite, outbound_session->ratchet, outbound_session->associated_data, plaintext_data, plaintext_data_len, &(e2ee_msg->one2one_msg));

    // done
    request->msg = e2ee_msg;
    return request;
}

bool consume_send_one2one_msg_response(Skissm__Session *outbound_session, Skissm__SendOne2oneMsgResponse *response) {
    if (response != NULL && response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
        // store sesson state
        get_skissm_plugin()->db_handler.store_session(outbound_session);
        return true;
    } else {
        return false;
    }
}

bool consume_one2one_msg(Skissm__E2eeAddress *receiver_address, Skissm__E2eeMsg *e2ee_msg) {
    if (e2ee_msg->session_id == NULL) {
        ssm_notify_error(BAD_MESSAGE_FORMAT, "consume_e2ee_message_payload()");
        return false;
    }

    /* load the corresponding inbound session */
    Skissm__Session *inbound_session = NULL;
    get_skissm_plugin()->db_handler.load_inbound_session(e2ee_msg->session_id, e2ee_msg->to, &inbound_session);
    if (inbound_session == NULL) {
        ssm_notify_error(BAD_SESSION, "consume_e2ee_message_payload()");
        return false;
        /* delete the old inbound session if it exists */
        get_skissm_plugin()->db_handler.unload_session(e2ee_msg->to, e2ee_msg->from, e2ee_msg->to);
    }

    Skissm__One2oneMsgPayload *payload = NULL;
    size_t plain_text_data_len = -1;
    if (e2ee_msg->payload_case == SKISSM__E2EE_MSG__PAYLOAD_ONE2ONE_MSG) {
        payload = e2ee_msg->one2one_msg;
    }
    if (payload != NULL) {
        uint8_t *plain_text_data = NULL;
        const cipher_suite_t *cipher_suite = get_e2ee_pack(inbound_session->e2ee_pack_id)->cipher_suite;
        plain_text_data_len = decrypt_ratchet(cipher_suite, inbound_session->ratchet, inbound_session->associated_data, payload, &plain_text_data);

        // store sesson state
        get_skissm_plugin()->db_handler.store_session(inbound_session);

        if (plain_text_data != NULL && plain_text_data_len != (size_t)(-1)) {
            Skissm__Plaintext *plaintext = skissm__plaintext__unpack(NULL, plain_text_data_len, plain_text_data);
            if (plaintext != NULL) {
                if (plaintext->payload_case == SKISSM__PLAINTEXT__PAYLOAD_COMMON_MSG) {
                    ssm_notify_one2one_msg(e2ee_msg->from, e2ee_msg->to, plaintext->common_msg.data, plaintext->common_msg.len);
                } else if (plaintext->payload_case == SKISSM__PLAINTEXT__PAYLOAD_GROUP_PRE_KEY) {
                    Skissm__GroupPreKeyPayload *group_pre_key_payload = plaintext->group_pre_key;
                    get_skissm_plugin()->db_handler.unload_inbound_group_session(e2ee_msg->to, group_pre_key_payload->old_session_id);
                    create_inbound_group_session(inbound_session->e2ee_pack_id, group_pre_key_payload, e2ee_msg->to);
                }
                skissm__plaintext__free_unpacked(plaintext, NULL);
            } else {
                ssm_notify_error(BAD_MESSAGE_FORMAT, "consume_e2ee_message_payload(), skissm__e2ee_plaintext__unpack() error");
            }
            // release
            free_mem((void **)&plain_text_data, plain_text_data_len);
        } else {
            ssm_notify_error(BAD_MESSAGE_DECRYPTION, "consume_e2ee_message_payload()");
        }
    }

    // release
    skissm__session__free_unpacked(inbound_session, NULL);

    // done
    return plain_text_data_len > 0;
}

bool consume_new_user_device_msg(Skissm__E2eeAddress *receiver_address, Skissm__NewUserDeviceMsg *msg) {
    Skissm__InviteResponse *response = get_pre_key_bundle_internal(receiver_address, msg->user_address);
    bool succ = false;
    if (response != NULL && response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
        succ = true;
    }
    // release
    skissm__invite_response__free_unpacked(response, NULL);

    // done
    return succ;
}

Skissm__InviteRequest *produce_invite_request(
    Skissm__Session *outbound_session, ProtobufCBinaryData **pre_shared_keys, size_t pre_shared_keys_len) {
    Skissm__InviteRequest *reqest = (Skissm__InviteRequest *) malloc(sizeof(Skissm__InviteRequest));
    skissm__invite_request__init(reqest);

    Skissm__InviteMsg *msg = (Skissm__InviteMsg *) malloc(sizeof(Skissm__InviteMsg));
    skissm__invite_msg__init(msg);

    msg->version = strdup(outbound_session->version);
    msg->e2ee_pack_id = strdup(outbound_session->e2ee_pack_id);
    msg->session_id = strdup(outbound_session->session_id);
    copy_address_from_address(&(msg->from), outbound_session->from);
    copy_address_from_address(&(msg->to), outbound_session->to);

    copy_protobuf_from_protobuf(&(msg->alice_identity_key), &(outbound_session->alice_identity_key));

    msg->n_pre_shared_keys = pre_shared_keys_len;
    if (pre_shared_keys_len > 0 && pre_shared_keys != NULL) {
        msg->pre_shared_keys = (ProtobufCBinaryData *) malloc(sizeof(ProtobufCBinaryData) * pre_shared_keys_len);
        int i = 0;
        for(int i = 0; i< pre_shared_keys_len; i++) {
            copy_protobuf_from_protobuf(&(msg->pre_shared_keys[i]), pre_shared_keys[i]);
        }
    }
    msg->bob_signed_pre_key_id = outbound_session->bob_signed_pre_key_id;
    msg->bob_one_time_pre_key_id = outbound_session->bob_one_time_pre_key_id;

    // done
    reqest->msg = msg;
    return reqest;
}

bool consume_invite_response(Skissm__InviteResponse *response) {
    if (response != NULL && response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK)
        return true;
    else
        return false;
}

bool consume_invite_msg(Skissm__E2eeAddress *receiver_address, Skissm__InviteMsg *msg) {
    const char *e2ee_pack_id = msg->e2ee_pack_id;
    Skissm__E2eeAddress *from = msg->from;
    Skissm__E2eeAddress *to = msg->to;

    // notify
    ssm_notify_inbound_session_invited(from);

    // automatic create inbound session and send accept request
    Skissm__Account *account = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(to, &account);
    if (account == NULL) {
        ssm_notify_error(BAD_ACCOUNT, "consume_invite_msg()");
        return (size_t)(-1);
    }
    /* create a new inbound session */
    Skissm__Session *inbound_session = (Skissm__Session *)malloc(sizeof(Skissm__Session));
    initialise_session(inbound_session, e2ee_pack_id, from, to);
    copy_address_from_address(&(inbound_session->session_owner), to);
    const session_suite_t *session_suite = get_e2ee_pack(e2ee_pack_id)->session_suite;
    // Set the version and session id
    inbound_session->version = strdup(msg->version);
    inbound_session->session_id = strdup(msg->session_id);
    // create a new inbound session
    size_t result = session_suite->new_inbound_session(inbound_session, account, msg);

    if (result != (size_t)(0)
        || safe_strcmp(inbound_session->session_id, msg->session_id) == false) {
        ssm_notify_error(BAD_MESSAGE_FORMAT, "consume_e2ee_invite_payload()");
        result = (size_t)(-1);
    } else {
        // notify
        ssm_notify_inbound_session_ready(inbound_session);
        return true;
    }
    // release
    skissm__account__free_unpacked(account, NULL);
    skissm__session__free_unpacked(inbound_session, NULL);

    // done
    return result;
}

Skissm__AcceptRequest *produce_accept_request(const char *e2ee_pack_id, Skissm__E2eeAddress *from, Skissm__E2eeAddress *to, ProtobufCBinaryData *ciphertext_1) {
    Skissm__AcceptRequest *request = (Skissm__AcceptRequest *) malloc(sizeof(Skissm__AcceptRequest));
    skissm__accept_request__init(request);

    Skissm__AcceptMsg *msg = (Skissm__AcceptMsg *) malloc(sizeof(Skissm__AcceptMsg));
    skissm__accept_msg__init(msg);

    msg->e2ee_pack_id = strdup(e2ee_pack_id);
    copy_address_from_address(&(msg->from), from);
    copy_address_from_address(&(msg->to), to);

    if (ciphertext_1 == NULL){
        msg->n_pre_shared_keys = 0;
        msg->pre_shared_keys = NULL;
    } else{
        msg->n_pre_shared_keys = 1;
        msg->pre_shared_keys = (ProtobufCBinaryData *) malloc(sizeof(ProtobufCBinaryData) * 1);
        copy_protobuf_from_protobuf(&(msg->pre_shared_keys[0]), ciphertext_1);
    }

    // done
    request->msg = msg;
    return request;
}

bool consume_accept_response(Skissm__AcceptResponse *response) {
    if (response != NULL && response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
        return true;
    } else {
        return false;
    }
}

bool consume_accept_msg(Skissm__E2eeAddress *receiver_address, Skissm__AcceptMsg *msg) {
    Skissm__Session *outbound_session = NULL;
    // Is it unique?
    get_skissm_plugin()->db_handler.load_outbound_session(msg->to, msg->from, &outbound_session);
    if (outbound_session == NULL){
        ssm_notify_error(BAD_MESSAGE_FORMAT, "consume_accept_msg()");
        return false;
    }
    const session_suite_t *session_suite = get_e2ee_pack(msg->e2ee_pack_id)->session_suite;
    size_t result = session_suite->complete_outbound_session(outbound_session, msg);

    // try to send group pre-keys if necessary
    send_group_pre_key(outbound_session);

    // store sesson state
    get_skissm_plugin()->db_handler.store_session(outbound_session);

    // notify
    ssm_notify_outbound_session_ready(outbound_session);

    return result == (size_t)(0);
}
