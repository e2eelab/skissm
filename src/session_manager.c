#include "skissm/session_manager.h"

#include <stdio.h>
#include <string.h>

#include "skissm/account.h"
#include "skissm/e2ee_client.h"
#include "skissm/e2ee_client_internal.h"
#include "skissm/group_session.h"
#include "skissm/mem_util.h"
#include "skissm/ratchet.h"
#include "skissm/session.h"

static void send_pending_plaintext_data(Skissm__Session *outbound_session) {
    // load pending plaintext data(may be the group pre-key or the common plaintext)
    uint32_t pending_plaintext_data_list_num;
    char **pending_plaintext_id_list;
    uint8_t **pending_plaintext_data_list;
    size_t *pending_plaintext_data_len_list;
    pending_plaintext_data_list_num =
        get_skissm_plugin()->db_handler.load_pending_plaintext_data(
            outbound_session->from,
            outbound_session->to,
            &pending_plaintext_id_list,
            &pending_plaintext_data_list,
            &pending_plaintext_data_len_list
        );
    if (pending_plaintext_data_list_num > 0) {
        ssm_notify_log(outbound_session->session_owner, DEBUG_LOG, "send_pending_plaintext_data(): list num = %d", pending_plaintext_data_list_num);
        uint32_t i;
        for (i = 0; i < pending_plaintext_data_list_num; i++) {
            Skissm__SendOne2oneMsgResponse *response = send_one2one_msg_internal(
                outbound_session,
                pending_plaintext_data_list[i],
                pending_plaintext_data_len_list[i]
            );
            // always unload
            get_skissm_plugin()->db_handler.unload_pending_plaintext_data(
                outbound_session->from, outbound_session->to, pending_plaintext_id_list[i]
            );
            // release
            if (response != NULL) {
                skissm__send_one2one_msg_response__free_unpacked(response, NULL);
            }
        }

        // release
        for (i = 0; i < pending_plaintext_data_list_num; i++) {
            free_mem((void **)&(pending_plaintext_data_list[i]), pending_plaintext_data_len_list[i]);
            free(pending_plaintext_id_list[i]);
        }
        free_mem((void **)&pending_plaintext_id_list, sizeof(char *) * pending_plaintext_data_list_num);
        free_mem((void **)&pending_plaintext_data_list, sizeof(uint8_t *) * pending_plaintext_data_list_num);
        free_mem((void **)&pending_plaintext_data_len_list, sizeof(size_t) * pending_plaintext_data_list_num);
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
        Skissm__SendOne2oneMsgResponse *response;
        response = send_one2one_msg_internal(self_outbound_session, common_plaintext_data, common_plaintext_data_len);

        // release
        free_mem((void **)&common_plaintext_data, common_plaintext_data_len);
        skissm__session__free_unpacked(self_outbound_session, NULL);
        skissm__send_one2one_msg_response__free_unpacked(response, NULL);
    }
    // release
    if (self_outbound_sessions_num > 0) {
        free_mem((void **)&self_outbound_sessions, sizeof(Skissm__Session *) * self_outbound_sessions_num);
    }
}

Skissm__GetPreKeyBundleRequest *produce_get_pre_key_bundle_request(
    const char *to_user_id, const char *to_domain, const char *to_device_id
) {
    Skissm__GetPreKeyBundleRequest *request =
        (Skissm__GetPreKeyBundleRequest *)malloc(sizeof(Skissm__GetPreKeyBundleRequest));
    skissm__get_pre_key_bundle_request__init(request);
    request->domain = strdup(to_domain);
    request->user_id = strdup(to_user_id);
    if (to_device_id != NULL)
        request->device_id = strdup(to_device_id);
    return request;
}

Skissm__InviteResponse *consume_get_pre_key_bundle_response(
    Skissm__E2eeAddress *from,
    uint8_t *group_pre_key_plaintext_data,
    size_t group_pre_key_plaintext_data_len,
    Skissm__GetPreKeyBundleResponse *response
) {
    ssm_notify_log(from, DEBUG_LOG, "consume_get_pre_key_bundle_response() from[%s:%s]", from->user->user_id, from->user->device_id);

    if (response != NULL && response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
        Skissm__PreKeyBundle **their_pre_key_bundles = response->pre_key_bundles;
        size_t n_pre_key_bundles = response->n_pre_key_bundles;
        size_t i;
        for (i = 0; i < n_pre_key_bundles; i++) {
            Skissm__PreKeyBundle *cur_pre_key_bundle = their_pre_key_bundles[i];
            Skissm__E2eeAddress *cur_address = cur_pre_key_bundle->user_address;

            // skip if the pre-key bundle is from this device
            if (safe_strcmp(from->user->user_id, cur_address->user->user_id)) {
                if (compare_address(from, cur_address))
                    continue;
            }

            // find an account
            Skissm__Account *account = NULL;
            get_skissm_plugin()->db_handler.load_account_by_address(from, &account);
            if (account == NULL) {
                ssm_notify_log(from, BAD_ACCOUNT, "consume_get_pre_key_bundle_response()");
                return NULL;
            }

            // store the group pre-keys if necessary
            if (group_pre_key_plaintext_data != NULL) {
                ssm_notify_log(from, DEBUG_LOG, "consume_get_pre_key_bundle_response() store the group pre-keys");
                char *pending_plaintext_id = generate_uuid_str();
                get_skissm_plugin()->db_handler.store_pending_plaintext_data(
                    from,
                    cur_address,
                    pending_plaintext_id,
                    group_pre_key_plaintext_data,
                    group_pre_key_plaintext_data_len
                );
                // release
                free(pending_plaintext_id);
            }

            // prepare to create an outbound session
            const char *e2ee_pack_id = cur_pre_key_bundle->e2ee_pack_id;
            Skissm__Session *outbound_session = (Skissm__Session *) malloc(sizeof(Skissm__Session));
            initialise_session(outbound_session, e2ee_pack_id, from, cur_address);
            copy_address_from_address(&(outbound_session->session_owner), from);

            const session_suite_t *session_suite = get_e2ee_pack(e2ee_pack_id)->session_suite;
            Skissm__InviteResponse *invite_response =
                session_suite->new_outbound_session(outbound_session, account, cur_pre_key_bundle);
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
                ssm_notify_log(from, BAD_SESSION, "consume_get_pre_key_bundle_response()");
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
    // store sesson state
    get_skissm_plugin()->db_handler.store_session(outbound_session);

    if (response != NULL && response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
        return true;
    } else {
        return false;
    }
}

static bool process_f2f_session(Skissm__Session *f2f_session, Skissm__E2eeMsg *e2ee_msg) {
    if (f2f_session == NULL)
        return false;

    // check if the session is outbound or inbound
    if (compare_user_id(f2f_session->from, e2ee_msg->from->user->user_id, e2ee_msg->from->domain)) {
        /** Since the session is outbound, the reciever's device id has been inserted "'\0'".
         *  But the sender's device id should be replaced with that of this device. */
        skissm__e2ee_address__free_unpacked(f2f_session->from, NULL);
        copy_address_from_address(&(f2f_session->from), e2ee_msg->to);
        skissm__e2ee_address__free_unpacked(f2f_session->session_owner, NULL);
        copy_address_from_address(&(f2f_session->session_owner), e2ee_msg->to);
    } else if (compare_user_id(f2f_session->to, e2ee_msg->from->user->user_id, e2ee_msg->from->domain)) {
        /** Since the session is inbound, the sender's device id has been inserted "'\0'".
         *  But the receiver's device id should be replaced with that of this device. */
        skissm__e2ee_address__free_unpacked(f2f_session->to, NULL);
        copy_address_from_address(&(f2f_session->to), e2ee_msg->to);
        skissm__e2ee_address__free_unpacked(f2f_session->session_owner, NULL);
        copy_address_from_address(&(f2f_session->session_owner), e2ee_msg->to);
    } else {
        // error
        ssm_notify_log(f2f_session->from, BAD_MESSAGE_FORMAT, "consume_one2one_msg()");
        return false;
    }
    get_skissm_plugin()->db_handler.store_session(f2f_session);
    // notify
    ssm_notify_f2f_session_ready(f2f_session->from, f2f_session);
    return true;
}

bool consume_one2one_msg(Skissm__E2eeAddress *receiver_address, Skissm__E2eeMsg *e2ee_msg) {
    ssm_notify_log(receiver_address, DEBUG_LOG, "consume_one2one_msg(): from [%s:%s], to [%s:%s]", e2ee_msg->from->user->user_id, e2ee_msg->from->user->device_id, e2ee_msg->to->user->user_id, e2ee_msg->to->user->device_id);
    if (e2ee_msg->session_id == NULL) {
        ssm_notify_log(receiver_address, BAD_MESSAGE_FORMAT, "consume_one2one_msg(), wrong session_id");
        // wrong session_id, just consume it
        return true;
    }

    // load the corresponding inbound session
    Skissm__Session *inbound_session = NULL;
    get_skissm_plugin()->db_handler.load_inbound_session(e2ee_msg->session_id, receiver_address, &inbound_session);
    if (inbound_session == NULL) {
        ssm_notify_log(receiver_address, BAD_SESSION, "consume_one2one_msg(), no inbound session");
        // no inbound session, just consume it
        return true;
    }

    ssm_notify_log(receiver_address, DEBUG_LOG, "consume_one2one_msg(), session_id: %s, from: [%s:%s], to: [%s:%s]", e2ee_msg->session_id, e2ee_msg->from->user->user_id, e2ee_msg->from->user->device_id, e2ee_msg->to->user->user_id, e2ee_msg->to->user->device_id);
    Skissm__One2oneMsgPayload *payload = NULL;
    size_t plain_text_data_len = -1;
    if (e2ee_msg->payload_case == SKISSM__E2EE_MSG__PAYLOAD_ONE2ONE_MSG) {
        payload = e2ee_msg->one2one_msg;
    }
    if (payload != NULL) {
        uint8_t *plain_text_data = NULL;
        const cipher_suite_t *cipher_suite = get_e2ee_pack(inbound_session->e2ee_pack_id)->cipher_suite;
        plain_text_data_len = decrypt_ratchet(cipher_suite, inbound_session->ratchet, inbound_session->associated_data, payload, &plain_text_data);

        // store session state
        get_skissm_plugin()->db_handler.store_session(inbound_session);

        if (plain_text_data != NULL && plain_text_data_len > 0) {
            Skissm__Plaintext *plaintext = skissm__plaintext__unpack(NULL, plain_text_data_len, plain_text_data);
            if (plaintext != NULL) {
                if (plaintext->payload_case == SKISSM__PLAINTEXT__PAYLOAD_COMMON_MSG) {
                    ssm_notify_one2one_msg(receiver_address, e2ee_msg->from, e2ee_msg->to, plaintext->common_msg.data, plaintext->common_msg.len);
                } else if (plaintext->payload_case == SKISSM__PLAINTEXT__PAYLOAD_COMMON_SYNC_MSG) {
                    ssm_notify_other_device_msg(receiver_address, e2ee_msg->from, e2ee_msg->to, plaintext->common_sync_msg.data, plaintext->common_sync_msg.len);
                } else if (plaintext->payload_case == SKISSM__PLAINTEXT__PAYLOAD_F2F_SESSION_DATA) {
                    process_f2f_session(plaintext->f2f_session_data, e2ee_msg);
                } else if (plaintext->payload_case == SKISSM__PLAINTEXT__PAYLOAD_GROUP_PRE_KEY_BUNDLE) {
                    Skissm__GroupPreKeyBundle *group_pre_key_bundle = plaintext->group_pre_key_bundle;

                    // unload the old outbound and inbound group sessions
                    get_skissm_plugin()->db_handler.unload_group_session_by_id(receiver_address, group_pre_key_bundle->old_session_id);

                    // try to load the new group sessions
                    Skissm__GroupInfo *cur_group_info = group_pre_key_bundle->group_info;
                    Skissm__GroupSession **inbound_group_sessions = NULL;
                    size_t inbound_group_sessions_num = get_skissm_plugin()->db_handler.load_group_sessions(
                        e2ee_msg->from, receiver_address, cur_group_info->group_address, &inbound_group_sessions
                    );
                    if (inbound_group_sessions_num > 0) {
                        size_t i;
                        for (i = 0; i < inbound_group_sessions_num; i++) {
                            complete_inbound_group_session(inbound_group_sessions[i], group_pre_key_bundle, NULL, NULL);
                        }
                        new_outbound_group_session(
                            false, &(group_pre_key_bundle->seed_secret), 0, NULL,
                            group_pre_key_bundle->e2ee_pack_id,
                            receiver_address,
                            cur_group_info->group_name,
                            cur_group_info->group_address,
                            cur_group_info->group_members,
                            cur_group_info->n_group_members,
                            group_pre_key_bundle->old_session_id
                        );
                    } else {
                        new_inbound_group_session(group_pre_key_bundle->e2ee_pack_id, receiver_address, group_pre_key_bundle, NULL, NULL);
                    }
                }
                skissm__plaintext__free_unpacked(plaintext, NULL);
                // success
            } else {
                ssm_notify_log(receiver_address, BAD_MESSAGE_FORMAT, "consume_one2one_msg(), plaintext data unpack error");
                // error
            }
            // release
            free_mem((void **)&plain_text_data, plain_text_data_len);
        } else {
            ssm_notify_log(receiver_address, BAD_MESSAGE_FORMAT, "consume_one2one_msg() wrong plaintext data");
        }
    }

    // release
    skissm__session__free_unpacked(inbound_session, NULL);

    // done
    // just consume it
    return true;
}

bool consume_new_user_device_msg(Skissm__E2eeAddress *receiver_address, Skissm__NewUserDeviceMsg *msg) {
    ssm_notify_log(receiver_address, DEBUG_LOG, "consume_new_user_device_msg(): receiver_address [%s:%s], new user [%s:%s]", receiver_address->user->user_id, receiver_address->user->device_id, msg->user_address->user->user_id, msg->user_address->user->device_id);

    Skissm__Account *account = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(receiver_address, &account);
    if (account == NULL) {
        ssm_notify_log(receiver_address, BAD_ACCOUNT, "consume_new_user_device_msg()");
        return false;
    }

    Skissm__InviteResponse *invite_response = get_pre_key_bundle_internal(
        receiver_address,
        account->auth,
        msg->user_address->user->user_id,
        msg->user_address->domain,
        msg->user_address->user->device_id,
        NULL, 0
    );
    bool succ = false;
    if (invite_response != NULL && invite_response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
        if (msg->n_group_info_list > 0) {
            size_t i;
            for (i = 0; i < msg->n_group_info_list; i++) {
                Skissm__GroupInfo *cur_group = (msg->group_info_list)[i];
                char *old_session_id = NULL;
                // delete the old outbound group session
                Skissm__GroupSession *outbound_group_session = NULL;
                get_skissm_plugin()->db_handler.load_group_session_by_address(receiver_address, receiver_address, cur_group->group_address, &outbound_group_session);
                if (outbound_group_session != NULL) {
                    get_skissm_plugin()->db_handler.unload_group_session_by_id(receiver_address, outbound_group_session->session_id);
                    old_session_id = strdup(outbound_group_session->session_id);
                    skissm__group_session__free_unpacked(outbound_group_session, NULL);
                }
                // create a new outbound group session
                // create_outbound_group_session(
                //     account->e2ee_pack_id, receiver_address,
                //     cur_group->group_name,
                //     cur_group->group_address, cur_group->group_members,
                //     cur_group->n_group_members, old_session_id
                // );
                // release
                if (old_session_id != NULL) {
                    free_mem((void **)&old_session_id, strlen(old_session_id));
                }
            }
        }

        // release
        skissm__invite_response__free_unpacked(invite_response, NULL);

        succ = true;
    } else {
        succ = false;
    }

    // release
    skissm__account__free_unpacked(account, NULL);

    // done
    return succ;
}

Skissm__InviteRequest *produce_invite_request(
    Skissm__Session *outbound_session
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

    size_t pre_shared_keys_num = outbound_session->n_pre_shared_keys;
    ProtobufCBinaryData *pre_shared_keys = outbound_session->pre_shared_keys;
    msg->n_pre_shared_keys = pre_shared_keys_num;
    if (pre_shared_keys_num > 0 && pre_shared_keys != NULL) {
        msg->pre_shared_keys = (ProtobufCBinaryData *) malloc(sizeof(ProtobufCBinaryData) * pre_shared_keys_num);
        size_t i = 0;
        for (i = 0; i < pre_shared_keys_num; i++) {
            copy_protobuf_from_protobuf(&(msg->pre_shared_keys[i]), &(pre_shared_keys[i]));
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
    ssm_notify_log(receiver_address, DEBUG_LOG, "consume_invite_msg(): from [%s:%s], to [%s:%s]", msg->from->user->user_id, msg->from->user->device_id, msg->to->user->user_id, msg->to->user->device_id);

    const char *e2ee_pack_id = msg->e2ee_pack_id;
    Skissm__E2eeAddress *from = msg->from;
    Skissm__E2eeAddress *to = msg->to;

    if (!compare_address(receiver_address, to)){
        ssm_notify_log(receiver_address, BAD_SERVER_MESSAGE, "consume_invite_msg()");
        return false;
    }

    // try to load the corresponding inbound session if it exists
    Skissm__Session *inbound_session = NULL;
    get_skissm_plugin()->db_handler.load_inbound_session(msg->session_id, receiver_address, &inbound_session);
    if (inbound_session != NULL) {
        // the corresponding inbound session has already existed
        return true;
    }

    // notify
    ssm_notify_inbound_session_invited(receiver_address, from);

    // automatic create inbound session and send accept request
    Skissm__Account *account = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(to, &account);
    if (account == NULL) {
        ssm_notify_log(receiver_address, BAD_ACCOUNT, "consume_invite_msg()");
        return false;
    }
    // create a new inbound session
    inbound_session = (Skissm__Session *)malloc(sizeof(Skissm__Session));
    initialise_session(inbound_session, e2ee_pack_id, from, to);
    copy_address_from_address(&(inbound_session->session_owner), to);
    const session_suite_t *session_suite = get_e2ee_pack(e2ee_pack_id)->session_suite;
    // set the version and session id
    inbound_session->version = strdup(msg->version);
    inbound_session->session_id = strdup(msg->session_id);
    // create a new inbound session
    int result = session_suite->new_inbound_session(inbound_session, account, msg);

    if (result != 0
        || safe_strcmp(inbound_session->session_id, msg->session_id) == false) {
        ssm_notify_log(receiver_address, BAD_MESSAGE_FORMAT, "consume_invite_msg()");
        result = -1;
    } else {
        // notify
        ssm_notify_inbound_session_ready(receiver_address, inbound_session);
    }
    // release
    skissm__account__free_unpacked(account, NULL);
    skissm__session__free_unpacked(inbound_session, NULL);

    // done
    return result == 0;
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
    ssm_notify_log(receiver_address, DEBUG_LOG, "consume_accept_msg(): from [%s:%s], to [%s:%s]", msg->to->user->user_id, msg->to->user->device_id, msg->from->user->user_id, msg->from->user->device_id);

    if (!compare_address(receiver_address, msg->to)){
        ssm_notify_log(receiver_address, BAD_SERVER_MESSAGE, "consume_accept_msg()");
        return false;
    }

    Skissm__Session *outbound_session = NULL;
    // Is it unique?
    get_skissm_plugin()->db_handler.load_outbound_session(msg->to, msg->from, &outbound_session);
    if (outbound_session == NULL){
        ssm_notify_log(receiver_address, BAD_MESSAGE_FORMAT, "consume_accept_msg() from [], to []: can't load outbount session and make it a complete and responded session.", msg->to->user->user_id, msg->to->user->device_id, msg->from->user->user_id, msg->from->user->device_id);
        return false;
    }
    const session_suite_t *session_suite = get_e2ee_pack(msg->e2ee_pack_id)->session_suite;
    int result = session_suite->complete_outbound_session(outbound_session, msg);

    // store sesson state
    get_skissm_plugin()->db_handler.store_session(outbound_session);

    // notify
    ssm_notify_outbound_session_ready(receiver_address, outbound_session);

    // try to send group pre-keys if necessary
    send_pending_plaintext_data(outbound_session);

    return result >= 0;
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
    ssm_notify_log(receiver_address, DEBUG_LOG, "consume_f2f_invite_msg(): from [%s:%s], to [%s:%s]", msg->from->user->user_id, msg->from->user->device_id, msg->to->user->user_id, msg->to->user->device_id);

    const char *e2ee_pack_id = msg->e2ee_pack_id;
    Skissm__E2eeAddress *from = msg->from;
    Skissm__E2eeAddress *to = msg->to;

    if (!compare_address(receiver_address, to)){
        ssm_notify_log(receiver_address, BAD_SERVER_MESSAGE, "consume_f2f_invite_msg()");
        return false;
    }

    bool succ = false;
    uint8_t *password = NULL;
    size_t password_len;
    get_skissm_plugin()->event_handler.on_f2f_password_acquired(receiver_address, from, to, &password, &password_len);

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
    ProtobufCBinaryData *ad = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));
    ad->len = 64;
    ad->data = (uint8_t *)malloc(sizeof(uint8_t) * 64);
    memset(ad->data, 0, 64);
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
    ssm_notify_inbound_session_invited(receiver_address, from);

    // automatic create inbound session and send accept request
    Skissm__Account *account = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(to, &account);
    if (account == NULL) {
        ssm_notify_log(receiver_address, BAD_ACCOUNT, "consume_f2f_invite_msg()");
        return false;
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
    int result = session_suite->new_f2f_inbound_session(inbound_session, account, f2f_pre_key_invite_msg->secret.data);

    if (result < 0
        || safe_strcmp(inbound_session->session_id, f2f_pre_key_invite_msg->session_id) == false
    ) {
        ssm_notify_log(receiver_address, BAD_MESSAGE_FORMAT, "consume_f2f_invite_msg()");
        succ = false;
    } else {
        // notify
        ssm_notify_inbound_session_ready(receiver_address, inbound_session);
        // check if this message is from other devices or other members
        if (strcmp(from->user->user_id, to->user->user_id) != 0) {
            // send the face-to-face inbound message to other devices if they are available
            send_f2f_session_msg(to, inbound_session);
        }
        // send the face-to-face invite back to the sender if necessary
        if (f2f_pre_key_invite_msg->responded == false) {
            f2f_invite(to, from, true, password, password_len);
        }
        succ = true;
    }
    // release
    free_mem((void **)&password, password_len);
    free_mem((void **)&aes_key, aes_key_len);
    free_mem((void **)&(ad->data), ad->len);
    free_mem((void **)&ad, sizeof(ProtobufCBinaryData));
    free_mem((void **)&f2f_pre_key_plaintext, f2f_pre_key_plaintext_len);
    skissm__f2f_pre_key_invite_msg__free_unpacked(f2f_pre_key_invite_msg, NULL);
    skissm__account__free_unpacked(account, NULL);
    skissm__session__free_unpacked(inbound_session, NULL);

    // done
    return succ;
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
        ssm_notify_log(receiver_address, BAD_SERVER_MESSAGE, "consume_f2f_accept_msg()");
        return false;
    }

    // get the corresponding account
    account_context *context = get_account_context(receiver_address);

    if (context == NULL) {
        ssm_notify_log(receiver_address, BAD_ACCOUNT, "consume_f2f_accept_msg()");
        return false;
    }

    f2f_session_mid *cur_f2f_session_mid = context->f2f_session_mid_list;
    Skissm__Session *f2f_session_mid = NULL;
    while (cur_f2f_session_mid != NULL) {
        if (compare_address(cur_f2f_session_mid->peer_address, msg->from)) {
            f2f_session_mid = cur_f2f_session_mid->f2f_session;
            break;
        }
        cur_f2f_session_mid = cur_f2f_session_mid->next;
    }

    if (f2f_session_mid == NULL) {
        ssm_notify_log(receiver_address, BAD_SESSION, "consume_f2f_accept_msg()");
        return false;
    }

    const session_suite_t *session_suite = get_e2ee_pack(msg->e2ee_pack_id)->session_suite;

    // check f2f_session_mid
    int result = session_suite->complete_f2f_outbound_session(f2f_session_mid, msg);

    // delete the old outbound session if it exists
    Skissm__Session *outbound_session = NULL;

    get_skissm_plugin()->db_handler.load_outbound_session(msg->to, msg->from, &outbound_session);
    if (outbound_session != NULL){
        get_skissm_plugin()->db_handler.unload_session(outbound_session->session_owner, outbound_session->from, outbound_session->to);
    }

    // store the face-to-face session
    get_skissm_plugin()->db_handler.store_session(f2f_session_mid);

    // notify
    ssm_notify_outbound_session_ready(receiver_address, f2f_session_mid);

    if (strcmp(receiver_address->user->user_id, msg->from->user->user_id) != 0) {
        // send the face-to-face outbound message to other devices if they are available
        send_f2f_session_msg(msg->to, f2f_session_mid);
    }

    return result >= 0;
}
