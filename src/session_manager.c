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

Skissm__Session *f2f_session_mid = NULL;

static void send_pending_plaintext_data(Skissm__Session *outbound_session) {
    // load pending plaintext data(may be the group pre-key or the common plaintext)
    uint32_t pending_plaintext_data_list_num;
    uint8_t **pending_plaintext_data_list;
    size_t *pending_plaintext_data_len_list;
    pending_plaintext_data_list_num =
        get_skissm_plugin()->db_handler.load_pending_plaintext_data(
            outbound_session->from,
            outbound_session->to,
            false,
            &pending_plaintext_data_list,
            &pending_plaintext_data_len_list
        );
    if (pending_plaintext_data_list_num > 0) {
        uint32_t i;
        bool succ = true;
        for (i = 0; i < pending_plaintext_data_list_num; i++) {
            Skissm__SendOne2oneMsgResponse *response = send_one2one_msg_internal(
                outbound_session,
                pending_plaintext_data_list[i],
                pending_plaintext_data_len_list[i]
            );
            if (response == NULL) {
                succ = false;
                break;
            } else {
                // release
                skissm__send_one2one_msg_response__free_unpacked(response, NULL);
            }
        }

        // release
        for (i = 0; i < pending_plaintext_data_list_num; i++) {
            free_mem((void **) (&(pending_plaintext_data_list[i])),
                     pending_plaintext_data_len_list[i]);
        }
        free_mem((void **) (&pending_plaintext_data_list), sizeof(uint8_t *) * pending_plaintext_data_list_num);
        free_mem((void **) (&pending_plaintext_data_len_list), pending_plaintext_data_list_num);

        // done
        if (succ)
            get_skissm_plugin()->db_handler.unload_pending_plaintext_data(outbound_session->from, outbound_session->to, false);
    }
}

static void send_f2f_session_msg(
    Skissm__E2eeAddress *to,
    Skissm__Session *f2f_session_data
) {
    // send the message to other self devices
    Skissm__Session **self_outbound_sessions = NULL;
    size_t self_outbound_sessions_num = get_skissm_plugin()->db_handler.load_outbound_sessions(to, to->user->user_id, &self_outbound_sessions);
    size_t i;
    for (i = 0; i < self_outbound_sessions_num; i++) {
        // check if the device is different from the sender's
        if (strcmp(self_outbound_sessions[i]->to->user->device_id, to->user->device_id) == 0)
            continue;

        Skissm__Session *self_outbound_session = self_outbound_sessions[i];

        // pack common plaintext before sending it
        uint8_t *common_plaintext_data = NULL;
        size_t common_plaintext_data_len;
        pack_f2f_session_plaintext(
            f2f_session_data,
            SKISSM__PLAINTEXT__PAYLOAD_F2F_SESSION_DATA,
            &common_plaintext_data, &common_plaintext_data_len
        );

        // send message to server
        send_one2one_msg_internal(self_outbound_session, common_plaintext_data, common_plaintext_data_len);

        // release
        free_mem((void **)(&common_plaintext_data), common_plaintext_data_len);
        skissm__session__free_unpacked(self_outbound_session, NULL);
    }
    // release
    if (self_outbound_sessions_num > 0) {
        free_mem((void **)(&self_outbound_sessions), sizeof(Skissm__Session *) * self_outbound_sessions_num);
    }
}

Skissm__GetPreKeyBundleRequest *produce_get_pre_key_bundle_request(
    const char *to_user_id, const char *to_domain
) {
    Skissm__GetPreKeyBundleRequest *request =
        (Skissm__GetPreKeyBundleRequest *)malloc(sizeof(Skissm__GetPreKeyBundleRequest));
    skissm__get_pre_key_bundle_request__init(request);
    request->domain = strdup(to_domain);
    request->user_id = strdup(to_user_id);
    return request;
}

Skissm__InviteResponse *consume_get_pre_key_bundle_response(
    Skissm__E2eeAddress *from,
    Skissm__GetPreKeyBundleResponse *response
) {
    if (response != NULL && response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
        Skissm__PreKeyBundle **their_pre_key_bundles = response->pre_key_bundles;
        size_t n_pre_key_bundles = response->n_pre_key_bundles;
        size_t i;
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
            initialise_session(outbound_session, e2ee_pack_id, from, their_pre_key_bundles[i]->user_address);
            copy_address_from_address(&(outbound_session->session_owner), from);

            const session_suite_t *session_suite = get_e2ee_pack(e2ee_pack_id)->session_suite;
            Skissm__InviteResponse *invite_response =
                session_suite->new_outbound_session(outbound_session, account, their_pre_key_bundles[i]);
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
                ssm_notify_error(BAD_SESSION, "consume_get_pre_key_bundle_response()");
                return NULL;
            }
        }
        return NULL;
    } else {
        return NULL;
    }
}

Skissm__SendOne2oneMsgRequest *produce_send_one2one_msg_request(
    Skissm__Session *outbound_session,
    const uint8_t *plaintext_data, size_t plaintext_data_len
) {
    const cipher_suite_t *cipher_suite = get_e2ee_pack(outbound_session->e2ee_pack_id)->cipher_suite;

    Skissm__SendOne2oneMsgRequest *request = (Skissm__SendOne2oneMsgRequest *)malloc(sizeof(Skissm__SendOne2oneMsgRequest));
    skissm__send_one2one_msg_request__init(request);

    // prepare an e2ee message
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

bool consume_send_one2one_msg_response(
    Skissm__Session *outbound_session,
    Skissm__SendOne2oneMsgResponse *response
) {
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
        ssm_notify_error(BAD_MESSAGE_FORMAT, "consume_one2one_msg()");
        return false;
    }

    // load the corresponding inbound session
    Skissm__Session *inbound_session = NULL;
    get_skissm_plugin()->db_handler.load_inbound_session(e2ee_msg->session_id, receiver_address, &inbound_session);
    if (inbound_session == NULL) {
        ssm_notify_error(BAD_SESSION, "consume_one2one_msg()");
        return false;
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
                } else if (plaintext->payload_case == SKISSM__PLAINTEXT__PAYLOAD_COMMON_SYNC_MSG) {
                    ssm_notify_other_device_msg(e2ee_msg->from, e2ee_msg->to, plaintext->common_sync_msg.data, plaintext->common_sync_msg.len);
                } else if (plaintext->payload_case == SKISSM__PLAINTEXT__PAYLOAD_F2F_SESSION_DATA) {
                    Skissm__Session *session = plaintext->f2f_session_data;
                    // check if the session is outbound or inbound
                    if (compare_user_id(session->from, e2ee_msg->from->user->user_id, e2ee_msg->from->domain)) {
                        /** Since the session is outbound, the reciever's device id has been inserted "'\0'".
                         *  But the sender's device id should be replaced with that of this device. */
                        skissm__e2ee_address__free_unpacked(session->from, NULL);
                        copy_address_from_address(&(session->from), e2ee_msg->to);
                        skissm__e2ee_address__free_unpacked(session->session_owner, NULL);
                        copy_address_from_address(&(session->session_owner), e2ee_msg->to);
                    } else if (compare_user_id(session->to, e2ee_msg->from->user->user_id, e2ee_msg->from->domain)) {
                        /** Since the session is inbound, the sender's device id has been inserted "'\0'".
                         *  But the receiver's device id should be replaced with that of this device. */
                        skissm__e2ee_address__free_unpacked(session->to, NULL);
                        copy_address_from_address(&(session->to), e2ee_msg->to);
                        skissm__e2ee_address__free_unpacked(session->session_owner, NULL);
                        copy_address_from_address(&(session->session_owner), e2ee_msg->to);
                    } else {
                        // error
                        ssm_notify_error(BAD_MESSAGE_FORMAT, "consume_one2one_msg()");
                        // release
                        skissm__session__free_unpacked(session, NULL);
                        skissm__plaintext__free_unpacked(plaintext, NULL);
                        free_mem((void **)&plain_text_data, plain_text_data_len);

                        return false;
                    }
                    get_skissm_plugin()->db_handler.store_session(session);
                    // notify
                    ssm_notify_f2f_session_ready(session);
                } else if (plaintext->payload_case == SKISSM__PLAINTEXT__PAYLOAD_GROUP_PRE_KEY_BUNDLE) {
                    Skissm__GroupPreKeyBundle *group_pre_key_bundle = plaintext->group_pre_key_bundle;
                    get_skissm_plugin()->db_handler.unload_inbound_group_session(e2ee_msg->to, group_pre_key_bundle->old_session_id);
                    create_inbound_group_session(inbound_session->e2ee_pack_id, group_pre_key_bundle, e2ee_msg->to);
                }
                skissm__plaintext__free_unpacked(plaintext, NULL);
            } else {
                ssm_notify_error(BAD_MESSAGE_FORMAT, "consume_one2one_msg(), skissm__plaintext__unpack() error");
            }
            // release
            free_mem((void **)&plain_text_data, plain_text_data_len);
        } else {
            ssm_notify_error(BAD_MESSAGE_DECRYPTION, "consume_one2one_msg()");
        }
    }

    // release
    skissm__session__free_unpacked(inbound_session, NULL);

    // done
    return plain_text_data_len > 0;
}

bool consume_new_user_device_msg(Skissm__E2eeAddress *receiver_address, Skissm__NewUserDeviceMsg *msg) {
    Skissm__InviteResponse *response = get_pre_key_bundle_internal(receiver_address, msg->user_address->user->user_id, msg->user_address->domain);
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
    Skissm__Session *outbound_session,
    ProtobufCBinaryData **pre_shared_keys, size_t pre_shared_keys_num
) {
    Skissm__InviteRequest *request = (Skissm__InviteRequest *) malloc(sizeof(Skissm__InviteRequest));
    skissm__invite_request__init(request);

    Skissm__InviteMsg *msg = (Skissm__InviteMsg *) malloc(sizeof(Skissm__InviteMsg));
    skissm__invite_msg__init(msg);

    msg->version = strdup(outbound_session->version);
    msg->e2ee_pack_id = strdup(outbound_session->e2ee_pack_id);
    msg->session_id = strdup(outbound_session->session_id);
    copy_address_from_address(&(msg->from), outbound_session->from);
    copy_address_from_address(&(msg->to), outbound_session->to);

    copy_protobuf_from_protobuf(&(msg->alice_identity_key), &(outbound_session->alice_identity_key));

    msg->n_pre_shared_keys = pre_shared_keys_num;
    if (pre_shared_keys_num > 0 && pre_shared_keys != NULL) {
        msg->pre_shared_keys = (ProtobufCBinaryData *) malloc(sizeof(ProtobufCBinaryData) * pre_shared_keys_num);
        size_t i = 0;
        for (i = 0; i < pre_shared_keys_num; i++) {
            copy_protobuf_from_protobuf(&(msg->pre_shared_keys[i]), pre_shared_keys[i]);
        }
    }
    msg->bob_signed_pre_key_id = outbound_session->bob_signed_pre_key_id;
    msg->bob_one_time_pre_key_id = outbound_session->bob_one_time_pre_key_id;

    // done
    request->msg = msg;
    return request;
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

    if (!compare_address(receiver_address, to)){
        ssm_notify_error(BAD_SERVER_MESSAGE, "consume_invite_msg()");
        return false;
    }

    // notify
    ssm_notify_inbound_session_invited(from);

    // automatic create inbound session and send accept request
    Skissm__Account *account = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(to, &account);
    if (account == NULL) {
        ssm_notify_error(BAD_ACCOUNT, "consume_invite_msg()");
        return false;
    }
    // create a new inbound session
    Skissm__Session *inbound_session = (Skissm__Session *)malloc(sizeof(Skissm__Session));
    initialise_session(inbound_session, e2ee_pack_id, from, to);
    copy_address_from_address(&(inbound_session->session_owner), to);
    const session_suite_t *session_suite = get_e2ee_pack(e2ee_pack_id)->session_suite;
    // set the version and session id
    inbound_session->version = strdup(msg->version);
    inbound_session->session_id = strdup(msg->session_id);
    // create a new inbound session
    size_t result = session_suite->new_inbound_session(inbound_session, account, msg);

    if (result != (size_t)(0)
        || safe_strcmp(inbound_session->session_id, msg->session_id) == false) {
        ssm_notify_error(BAD_MESSAGE_FORMAT, "consume_invite_msg()");
        result = (size_t)(-1);
    } else {
        // notify
        ssm_notify_inbound_session_ready(inbound_session);
    }
    // release
    skissm__account__free_unpacked(account, NULL);
    skissm__session__free_unpacked(inbound_session, NULL);

    // done
    return result == (size_t)(0);
}

Skissm__AcceptRequest *produce_accept_request(
    const char *e2ee_pack_id,
    Skissm__E2eeAddress *from,
    Skissm__E2eeAddress *to,
    ProtobufCBinaryData *ciphertext_1
) {
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
    if (!compare_address(receiver_address, msg->to)){
        ssm_notify_error(BAD_SERVER_MESSAGE, "consume_accept_msg()");
        return false;
    }

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
    send_pending_plaintext_data(outbound_session);

    // store sesson state
    get_skissm_plugin()->db_handler.store_session(outbound_session);

    // notify
    ssm_notify_outbound_session_ready(outbound_session);

    return result == (size_t)(0);
}

Skissm__F2fInviteRequest *produce_f2f_invite_request(
    Skissm__E2eeAddress *from, Skissm__E2eeAddress *to,
    char *e2ee_pack_id,
    uint8_t *secret, size_t secret_len
) {
    Skissm__F2fInviteRequest *request = (Skissm__F2fInviteRequest *)malloc(sizeof(Skissm__F2fInviteRequest));
    skissm__f2f_invite_request__init(request);

    Skissm__F2fInviteMsg *msg = (Skissm__F2fInviteMsg *) malloc(sizeof(Skissm__F2fInviteMsg));
    skissm__f2f_invite_msg__init(msg);

    msg->e2ee_pack_id = strdup(e2ee_pack_id);
    copy_address_from_address(&(msg->from), from);
    copy_address_from_address(&(msg->to), to);

    msg->secret_msg.len = secret_len;
    msg->secret_msg.data = (uint8_t *)malloc(sizeof(uint8_t) * secret_len);
    memcpy(msg->secret_msg.data, secret, secret_len);

    // done
    request->msg = msg;
    return request;
}

bool consume_f2f_invite_response(Skissm__F2fInviteRequest *request, Skissm__F2fInviteResponse *response) {
    if (response != NULL && response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
        return true;
    } else {
        return false;
    }
}

bool consume_f2f_invite_msg(Skissm__E2eeAddress *receiver_address, Skissm__F2fInviteMsg *msg) {
    const char *e2ee_pack_id = msg->e2ee_pack_id;
    Skissm__E2eeAddress *from = msg->from;
    Skissm__E2eeAddress *to = msg->to;

    if (!compare_address(receiver_address, to)){
        ssm_notify_error(BAD_SERVER_MESSAGE, "consume_f2f_invite_msg()");
        return false;
    }

    uint8_t *password = NULL;
    size_t password_len;
    get_skissm_plugin()->event_handler.on_f2f_password_acquired(&password, &password_len);

    // hkdf(produce the AES key)
    const cipher_suite_t *cipher_suite = get_e2ee_pack(e2ee_pack_id)->cipher_suite;
    int hash_len = cipher_suite->get_crypto_param().hash_len;
    uint8_t salt[hash_len];
    memset(salt, 0, hash_len);
    int aes_key_len = cipher_suite->get_crypto_param().aead_key_len + cipher_suite->get_crypto_param().aead_iv_len;
    uint8_t *aes_key = (uint8_t *)malloc(sizeof(uint8_t) * aes_key_len);
    cipher_suite->hkdf(
        password, password_len,
        salt, sizeof(salt),
        (uint8_t *)F2F_PSK_SEED, sizeof(F2F_PSK_SEED) - 1,
        aes_key, aes_key_len
    );

    // decrypt
    uint8_t ad[64];
    memset(ad, 0, 64);
    uint8_t *f2f_pre_key_plaintext = NULL;
    size_t f2f_pre_key_plaintext_len = cipher_suite->decrypt(
        ad,
        aes_key,
        msg->secret_msg.data, msg->secret_msg.len,
        &f2f_pre_key_plaintext
    );

    // unpack
    Skissm__F2fPreKeyInviteMsg *f2f_pre_key_invite_msg = skissm__f2f_pre_key_invite_msg__unpack(NULL, f2f_pre_key_plaintext_len, f2f_pre_key_plaintext);

    // notify
    ssm_notify_inbound_session_invited(from);

    // automatic create inbound session and send accept request
    Skissm__Account *account = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(to, &account);
    if (account == NULL) {
        ssm_notify_error(BAD_ACCOUNT, "consume_f2f_invite_msg()");
        return (size_t)(-1);
    }
    // create a new inbound session
    Skissm__Session *inbound_session = (Skissm__Session *)malloc(sizeof(Skissm__Session));
    initialise_session(inbound_session, e2ee_pack_id, from, to);
    copy_address_from_address(&(inbound_session->session_owner), to);
    const session_suite_t *session_suite = get_e2ee_pack(e2ee_pack_id)->session_suite;
    // set the version and session id
    inbound_session->version = strdup(f2f_pre_key_invite_msg->version);
    inbound_session->session_id = strdup(f2f_pre_key_invite_msg->session_id);
    // create a new inbound session
    size_t result = session_suite->new_f2f_inbound_session(inbound_session, account, f2f_pre_key_invite_msg->secret.data);

    if (result != (size_t)(0)
        || safe_strcmp(inbound_session->session_id, f2f_pre_key_invite_msg->session_id) == false
    ) {
        ssm_notify_error(BAD_MESSAGE_FORMAT, "consume_f2f_invite_msg()");
        result = (size_t)(-1);
    } else {
        // notify
        ssm_notify_inbound_session_ready(inbound_session);
        // check if this message is from other devices or other members
        if (strcmp(from->user->user_id, to->user->user_id) != 0) {
            // send the face-to-face inbound message to other devices if they are available
            send_f2f_session_msg(to, inbound_session);
        }
        // send the face-to-face invite back to the sender if necessary
        if (f2f_pre_key_invite_msg->responded == false) {
            f2f_invite(to, from, true, password, password_len);
        }
    }
    // release
    free_mem((void **)&password, password_len);
    free_mem((void **)&aes_key, aes_key_len);
    free_mem((void **)&f2f_pre_key_plaintext, f2f_pre_key_plaintext_len);
    skissm__f2f_pre_key_invite_msg__free_unpacked(f2f_pre_key_invite_msg, NULL);
    skissm__account__free_unpacked(account, NULL);
    skissm__session__free_unpacked(inbound_session, NULL);

    // done
    return result;
}

Skissm__F2fAcceptRequest *produce_f2f_accept_request(
    const char *e2ee_pack_id,
    Skissm__E2eeAddress *from,
    Skissm__E2eeAddress *to,
    Skissm__Account *local_account
) {
    Skissm__F2fAcceptRequest *request = (Skissm__F2fAcceptRequest *) malloc(sizeof(Skissm__F2fAcceptRequest));
    skissm__f2f_accept_request__init(request);

    Skissm__F2fAcceptMsg *msg = (Skissm__F2fAcceptMsg *) malloc(sizeof(Skissm__F2fAcceptMsg));
    skissm__f2f_accept_msg__init(msg);

    msg->e2ee_pack_id = strdup(e2ee_pack_id);
    copy_address_from_address(&(msg->from), from);
    copy_address_from_address(&(msg->to), to);

    // produce f2f_pre_key_accept_msg
    Skissm__F2fPreKeyAcceptMsg *f2f_pre_key_accept_msg = (Skissm__F2fPreKeyAcceptMsg *)malloc(sizeof(Skissm__F2fPreKeyAcceptMsg));
    skissm__f2f_pre_key_accept_msg__init(f2f_pre_key_accept_msg);
    copy_protobuf_from_protobuf(&(f2f_pre_key_accept_msg->bob_identity_public_key), &(local_account->identity_key->asym_key_pair->public_key));
    copy_protobuf_from_protobuf(&(f2f_pre_key_accept_msg->bob_signed_pre_key), &(local_account->signed_pre_key->key_pair->public_key));
    f2f_pre_key_accept_msg->bob_signed_pre_key_id = local_account->signed_pre_key->spk_id;

    // pack
    msg->pre_key_msg.len = skissm__f2f_pre_key_accept_msg__get_packed_size(f2f_pre_key_accept_msg);
    msg->pre_key_msg.data = (uint8_t *)malloc(sizeof(uint8_t) * msg->pre_key_msg.len);
    skissm__f2f_pre_key_accept_msg__pack(f2f_pre_key_accept_msg, msg->pre_key_msg.data);

    // done
    request->msg = msg;
    return request;
}

bool consume_f2f_accept_response(Skissm__F2fAcceptResponse *response) {
    if (response != NULL && response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
        return true;
    } else {
        return false;
    }
}

bool consume_f2f_accept_msg(Skissm__E2eeAddress *receiver_address, Skissm__F2fAcceptMsg *msg) {
    if (!compare_address(receiver_address, msg->to)){
        ssm_notify_error(BAD_SERVER_MESSAGE, "consume_f2f_accept_msg()");
        return false;
    }

    const session_suite_t *session_suite = get_e2ee_pack(msg->e2ee_pack_id)->session_suite;

    // check f2f_session_mid
    size_t result = session_suite->complete_f2f_outbound_session(f2f_session_mid, msg);

    // delete the old outbound session if it exists
    Skissm__Session *outbound_session = NULL;

    get_skissm_plugin()->db_handler.load_outbound_session(msg->to, msg->from, &outbound_session);
    if (outbound_session != NULL){
        get_skissm_plugin()->db_handler.unload_session(outbound_session->session_owner, outbound_session->from, outbound_session->to);
    }

    // store the face-to-face session
    get_skissm_plugin()->db_handler.store_session(f2f_session_mid);

    // notify
    ssm_notify_outbound_session_ready(f2f_session_mid);

    if (strcmp(receiver_address->user->user_id, msg->from->user->user_id) != 0) {
        // send the face-to-face outbound message to other devices if they are available
        send_f2f_session_msg(msg->to, f2f_session_mid);
    }

    // release
    skissm__session__free_unpacked(f2f_session_mid, NULL);
    f2f_session_mid = NULL;

    return result == (size_t)(0);
}
