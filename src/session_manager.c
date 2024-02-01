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
            outbound_session->our_address,
            outbound_session->their_address,
            &pending_plaintext_id_list,
            &pending_plaintext_data_list,
            &pending_plaintext_data_len_list
        );
    if (pending_plaintext_data_list_num > 0) {
        ssm_notify_log(
            outbound_session->our_address,
            DEBUG_LOG,
            "send_pending_plaintext_data(): list num = %d",
            pending_plaintext_data_list_num
        );
        uint32_t i;
        for (i = 0; i < pending_plaintext_data_list_num; i++) {
            Skissm__SendOne2oneMsgResponse *response = send_one2one_msg_internal(
                outbound_session,
                NOTIFICATION_LEVEL_NORMAL,
                pending_plaintext_data_list[i],
                pending_plaintext_data_len_list[i]
            );
            // always unload
            get_skissm_plugin()->db_handler.unload_pending_plaintext_data(
                outbound_session->our_address, outbound_session->their_address, pending_plaintext_id_list[i]
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
    Skissm__GetPreKeyBundleResponse *get_pre_key_bundle_response
) {
    // find an account
    Skissm__Account *account = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(from, &account);
    if (account == NULL) {
        ssm_notify_log(from, BAD_ACCOUNT, "consume_get_pre_key_bundle_response()");
        return NULL;
    }

    ssm_notify_log(
        from,
        DEBUG_LOG,
        "consume_get_pre_key_bundle_response() from[%s:%s]",
        from->user->user_id,
        from->user->device_id
    );

    Skissm__InviteResponse *invite_response = NULL;
    if (get_pre_key_bundle_response == NULL) {
        ssm_notify_log(from, DEBUG_LOG, "consume_get_pre_key_bundle_response() got error getPreKeyBundleResponse");
    } else {
        if (get_pre_key_bundle_response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
            // handle received pre-key bundles
            Skissm__PreKeyBundle **their_pre_key_bundles = get_pre_key_bundle_response->pre_key_bundles;
            size_t n_pre_key_bundles = get_pre_key_bundle_response->n_pre_key_bundles;
            if (their_pre_key_bundles == NULL || n_pre_key_bundles == 0) {
                // release
                skissm__account__free_unpacked(account, NULL);

                // error, should redo again
                ssm_notify_log(from, BAD_PRE_KEY_BUNDLE, "consume_get_pre_key_bundle_response() empty pre_key_bundles error");
                return NULL;
            }
            size_t i;
            for (i = 0; i < n_pre_key_bundles; i++) {
                Skissm__PreKeyBundle *cur_pre_key_bundle = their_pre_key_bundles[i];
                Skissm__E2eeAddress *to_address = cur_pre_key_bundle->user_address;
                // skip if the pre-key bundle is from this device
                if (safe_strcmp(from->user->user_id, to_address->user->user_id)) {
                    if (compare_address(from, to_address)) {
                        continue;
                    }
                }
                ssm_notify_log(
                    from,
                    DEBUG_LOG,
                    "consume_get_pre_key_bundle_response() [%d of %d] sending invite to: %s:%s",
                    i + 1,
                    n_pre_key_bundles,
                    to_address->user->user_id,
                    to_address->user->device_id
                );

                // store the group pre-keys if necessary
                if (group_pre_key_plaintext_data != NULL) {
                    ssm_notify_log(from, DEBUG_LOG, "consume_get_pre_key_bundle_response() store the group pre-keys");
                    char *pending_plaintext_id = generate_uuid_str();
                    get_skissm_plugin()->db_handler.store_pending_plaintext_data(
                        from,
                        to_address,
                        pending_plaintext_id,
                        group_pre_key_plaintext_data,
                        group_pre_key_plaintext_data_len
                    );
                    // release
                    free(pending_plaintext_id);
                }

                // create an outbound session
                uint32_t e2ee_pack_id = cur_pre_key_bundle->e2ee_pack_id;
                Skissm__Session *outbound_session = (Skissm__Session *) malloc(sizeof(Skissm__Session));
                initialise_session(outbound_session, e2ee_pack_id, from, to_address);
                copy_address_from_address(&(outbound_session->our_address), from);

                const session_suite_t *session_suite = get_e2ee_pack(e2ee_pack_id)->session_suite;
                invite_response =
                    session_suite->new_outbound_session(outbound_session, account, cur_pre_key_bundle);

                // release
                skissm__session__free_unpacked(outbound_session, NULL);

                // error check
                if (invite_response != NULL) {
                    // return last invite response
                    if (i != (n_pre_key_bundles-1)) {
                        skissm__invite_response__free_unpacked(invite_response, NULL);
                    }
                } else {
                    ssm_notify_log(from, BAD_SESSION, "consume_get_pre_key_bundle_response() got NULL invite_response");
                    // TODO: continue the rest, if there are ?
                    break;
                }
            }
        } else if (get_pre_key_bundle_response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_NOT_FOUND) {
            ssm_notify_log(from, DEBUG_LOG, "consume_get_pre_key_bundle_response() got no content response, pending reqest should be skipped");
            invite_response = (Skissm__InviteResponse *)malloc(sizeof(Skissm__InviteResponse));
            skissm__invite_response__init(invite_response);
            invite_response->code = SKISSM__RESPONSE_CODE__RESPONSE_CODE_NOT_FOUND;
        }
    }

    // release
    skissm__account__free_unpacked(account, NULL);

    // done
    return invite_response;
}

Skissm__SendOne2oneMsgRequest *produce_send_one2one_msg_request(
    Skissm__Session *outbound_session,
    uint32_t notif_level,
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
    e2ee_msg->notif_level = notif_level;
    copy_address_from_address(&(e2ee_msg->from), outbound_session->our_address);
    copy_address_from_address(&(e2ee_msg->to), outbound_session->their_address);
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
    bool succ = false;
    bool remove_session = false;
    if (response != NULL) {
        if (response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
            succ = true;
        } else if (response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_NOT_FOUND) {
            // user device is removed, we remove outbound_sessions
            remove_session = true;
            succ = true;
        } else {
            succ = false;
        }
    } else {
        succ = false;
    }
    // store sesson state
    if (remove_session) {
        get_skissm_plugin()->db_handler.unload_session(outbound_session->our_address, outbound_session->their_address);
    } else {
        get_skissm_plugin()->db_handler.store_session(outbound_session);
    }
    // done
    return succ;
}

bool consume_one2one_msg(Skissm__E2eeAddress *receiver_address, Skissm__E2eeMsg *e2ee_msg) {
    // ssm_notify_log(receiver_address, DEBUG_LOG, "consume_one2one_msg(): from [%s:%s], to [%s:%s]", e2ee_msg->from->user->user_id, e2ee_msg->from->user->device_id, e2ee_msg->to->user->user_id, e2ee_msg->to->user->device_id);
    if (e2ee_msg->session_id == NULL) {
        ssm_notify_log(receiver_address, BAD_MESSAGE_FORMAT, "consume_one2one_msg(), wrong session_id");
        // wrong session_id, just consume it
        return true;
    }

    // load the corresponding inbound session
    Skissm__Session *inbound_session = NULL;
    get_skissm_plugin()->db_handler.load_inbound_session(e2ee_msg->session_id, receiver_address, &inbound_session);
    if (inbound_session == NULL) {
        ssm_notify_log(receiver_address, BAD_SESSION, "consume_one2one_msg() inbound session not found, just consume it");
        // no inbound session, just consume it
        return true;
    }

    // ssm_notify_log(receiver_address, DEBUG_LOG, "consume_one2one_msg(), session_id: %s, from: [%s:%s], to: [%s:%s]", e2ee_msg->session_id, e2ee_msg->from->user->user_id, e2ee_msg->from->user->device_id, e2ee_msg->to->user->user_id, e2ee_msg->to->user->device_id);
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

        // delete old sessions if necessary
        get_skissm_plugin()->db_handler.unload_old_session(receiver_address, e2ee_msg->from);

        if (plain_text_data != NULL && plain_text_data_len > 0) {
            Skissm__Plaintext *plaintext = skissm__plaintext__unpack(NULL, plain_text_data_len, plain_text_data);
            if (plaintext != NULL) {
                if (plaintext->payload_case == SKISSM__PLAINTEXT__PAYLOAD_COMMON_MSG) {
                    ssm_notify_one2one_msg(receiver_address, e2ee_msg->from, e2ee_msg->to, plaintext->common_msg.data, plaintext->common_msg.len);
                } else if (plaintext->payload_case == SKISSM__PLAINTEXT__PAYLOAD_USER_DEVICES_BUNDLE) {
                    Skissm__UserDevicesBundle *their_device_id_list = plaintext->user_devices_bundle;

                    char *to_user_id = their_device_id_list->user_id;
                    char *to_domain = their_device_id_list->domain;

                    char *auth = NULL;
                    get_skissm_plugin()->db_handler.load_auth(receiver_address, &auth);

                    if (auth == NULL) {
                        ssm_notify_log(receiver_address, BAD_ACCOUNT, "invite() from [%s:%s] to [%s@%s]",
                            receiver_address->user->user_id,
                            receiver_address->user->device_id,
                            to_user_id,
                            to_domain);
                        return NULL;
                    }

                    Skissm__InviteResponse *invite_response = NULL;
                    size_t their_devices_num = their_device_id_list->n_device_id_list;
                    if (their_devices_num == 0) {
                        invite_response = get_pre_key_bundle_internal(receiver_address, auth, to_user_id, to_domain, NULL, false, NULL, 0);

                        if (invite_response != NULL) {
                            skissm__invite_response__free_unpacked(invite_response, NULL);
                            invite_response = NULL;
                        }
                    } else {
                        char *cur_device_id = NULL;
                        size_t i;
                        for (i = 0; i < their_devices_num; i++) {
                            cur_device_id = their_device_id_list->device_id_list[i];
                            invite_response = get_pre_key_bundle_internal(receiver_address, auth, to_user_id, to_domain, cur_device_id, false, NULL, 0);

                            if (invite_response != NULL) {
                                skissm__invite_response__free_unpacked(invite_response, NULL);
                                invite_response = NULL;
                            }
                        }
                    }

                    // release
                    free(auth);
                } else if (plaintext->payload_case == SKISSM__PLAINTEXT__PAYLOAD_COMMON_SYNC_MSG) {
                    ssm_notify_other_device_msg(receiver_address, e2ee_msg->from, e2ee_msg->to, plaintext->common_sync_msg.data, plaintext->common_sync_msg.len);
                } else if (plaintext->payload_case == SKISSM__PLAINTEXT__PAYLOAD_GROUP_PRE_KEY_BUNDLE) {
                    Skissm__GroupPreKeyBundle *group_pre_key_bundle = plaintext->group_pre_key_bundle;

                    // unload the old outbound and inbound group sessions
                    if ((group_pre_key_bundle->old_session_id)[0] != '\0') {
                        get_skissm_plugin()->db_handler.unload_group_session_by_id(receiver_address, group_pre_key_bundle->old_session_id);
                        ssm_notify_log(
                            receiver_address,
                            DEBUG_LOG,
                            "unload the old outbound and inbound group sessions session_id: %s, session_owner: [%s:%s]",
                            group_pre_key_bundle->old_session_id,
                            receiver_address->user->user_id,
                            receiver_address->user->device_id
                        );
                    }

                    // try to load the new group sessions
                    Skissm__GroupInfo *cur_group_info = group_pre_key_bundle->group_info;
                    Skissm__GroupSession **inbound_group_sessions = NULL;
                    size_t inbound_group_sessions_num = get_skissm_plugin()->db_handler.load_group_sessions(
                        receiver_address, group_pre_key_bundle->group_info->group_address, &inbound_group_sessions
                    );
                    ssm_notify_log(
                        receiver_address,
                        DEBUG_LOG,
                        "consume_one2one_msg() SKISSM__PLAINTEXT__PAYLOAD_GROUP_PRE_KEY_BUNDLE : inbound_group_sessions_num: %d, inbound_group_sessions: %p",
                        inbound_group_sessions_num,
                        inbound_group_sessions
                    );
                    if (inbound_group_sessions_num > 0 && inbound_group_sessions != NULL) {
                        size_t i;
                        for (i = 0; i < inbound_group_sessions_num; i++) {
                            if (compare_address(receiver_address, inbound_group_sessions[i]->sender)) {
                                // skip
                                continue;
                            }
                            complete_inbound_group_session_by_pre_key_bundle(inbound_group_sessions[i], group_pre_key_bundle);
                            ssm_notify_log(
                                receiver_address,
                                DEBUG_LOG,
                                "complete_inbound_group_session_by_pre_key_bundle: %s, session_owner: [%s:%s]",
                                group_pre_key_bundle->session_id,
                                receiver_address->user->user_id,
                                receiver_address->user->device_id
                            );

                            // release inbound_group_sessions[i]
                            skissm__group_session__free_unpacked(inbound_group_sessions[i], NULL);
                        }
                        // release inbound_group_sessions
                        free_mem((void **)&inbound_group_sessions, sizeof(Skissm__Session *) * inbound_group_sessions_num);

                        new_outbound_group_session_by_receiver(
                            &(group_pre_key_bundle->group_seed),
                            group_pre_key_bundle->e2ee_pack_id,
                            receiver_address,
                            cur_group_info->group_name,
                            cur_group_info->group_address,
                            group_pre_key_bundle->session_id,
                            cur_group_info->group_member_list,
                            cur_group_info->n_group_member_list
                        );
                        ssm_notify_log(
                            receiver_address,
                            DEBUG_LOG,
                            "new_outbound_group_session_by_receiver: %s, session_owner: [%s:%s]",
                            group_pre_key_bundle->session_id,
                            receiver_address->user->user_id,
                            receiver_address->user->device_id
                        );
                    } else {
                        new_inbound_group_session_by_pre_key_bundle(group_pre_key_bundle->e2ee_pack_id, receiver_address, group_pre_key_bundle);
                        ssm_notify_log(
                            receiver_address,
                            DEBUG_LOG,
                            "new_inbound_group_session_by_pre_key_bundle: %s, session_owner: [%s:%s]",
                            group_pre_key_bundle->session_id,
                            receiver_address->user->user_id,
                            receiver_address->user->device_id
                        );
                    }
                } else if (plaintext->payload_case == SKISSM__PLAINTEXT__PAYLOAD_GROUP_UPDATE_KEY_BUNDLE) {
                    Skissm__GroupUpdateKeyBundle *group_update_key_bundle = plaintext->group_update_key_bundle;

                    if (group_update_key_bundle->adding == true) {
                        // create the outbound group session
                        new_outbound_group_session_invited(group_update_key_bundle, receiver_address);
                        ssm_notify_log(
                            receiver_address,
                            DEBUG_LOG,
                            "new_outbound_group_session_invited: %s, session_owner: [%s:%s]",
                            group_update_key_bundle->session_id,
                            receiver_address->user->user_id,
                            receiver_address->user->device_id
                        );
                    }
                    new_and_complete_inbound_group_session_with_ratchet_state(group_update_key_bundle, receiver_address);
                    ssm_notify_log(
                        receiver_address,
                        DEBUG_LOG,
                        "new_and_complete_inbound_group_session_with_ratchet_state: %s, session_owner: [%s:%s]",
                        group_update_key_bundle->session_id,
                        receiver_address->user->user_id,
                        receiver_address->user->device_id
                    );
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
    Skissm__E2eeAddress *inviter_address = msg->inviter_address;
    Skissm__E2eeAddress *new_user_address = msg->user_address;
    if (inviter_address != NULL) {
        ssm_notify_log(
            receiver_address,
            DEBUG_LOG,
            "consume_new_user_device_msg(): receiver address [%s:%s], inviter address: [%s:%s], new user address[%s:%s]",
            receiver_address->user->user_id,
            receiver_address->user->device_id,
            inviter_address->user->user_id,
            inviter_address->user->device_id,
            new_user_address->user->user_id,
            new_user_address->user->device_id
        );
    } else {
        ssm_notify_log(
            receiver_address,
            DEBUG_LOG,
            "consume_new_user_device_msg(): receiver address [%s:%s], inviter address: null, new user address[%s:%s]",
            receiver_address->user->user_id,
            receiver_address->user->device_id,
            new_user_address->user->user_id,
            new_user_address->user->device_id
        );
    }

    // if receiver is the inviter, then add the new device into the joined groups
    if (compare_address(receiver_address, inviter_address)) {
        // load all outbound group addresses
        Skissm__E2eeAddress **group_addresses = NULL;
        size_t group_address_num = get_skissm_plugin()->db_handler.load_group_addresses(receiver_address, receiver_address, &group_addresses);

        size_t i;
        for (i = 0; i < group_address_num; i++) {
            Skissm__AddGroupMemberDeviceResponse *add_group_member_device_response = 
                add_group_member_device_internal(receiver_address, group_addresses[i], new_user_address);

            // release
            if (add_group_member_device_response != NULL) {
                skissm__add_group_member_device_response__free_unpacked(add_group_member_device_response, NULL);
                add_group_member_device_response = NULL;
            }
        }

        // release
        for (i = 0; i < group_address_num; i++) {
            skissm__e2ee_address__free_unpacked(group_addresses[i], NULL);
            group_addresses[i] = NULL;
        }
        if (group_addresses != NULL) {
            free_mem((void **)&group_addresses, sizeof(Skissm__E2eeAddress *) * group_address_num);
            group_addresses = NULL;
        }
    }

    // done
    return true;
}

Skissm__InviteRequest *produce_invite_request(
    Skissm__Session *outbound_session
) {
    const cipher_suite_t *cipher_suite = get_e2ee_pack(outbound_session->e2ee_pack_id)->cipher_suite;

    Skissm__InviteRequest *request = (Skissm__InviteRequest *) malloc(sizeof(Skissm__InviteRequest));
    skissm__invite_request__init(request);

    Skissm__InviteMsg *msg = (Skissm__InviteMsg *) malloc(sizeof(Skissm__InviteMsg));
    skissm__invite_msg__init(msg);

    msg->version = strdup(outbound_session->version);
    msg->e2ee_pack_id = outbound_session->e2ee_pack_id;
    msg->session_id = strdup(outbound_session->session_id);
    copy_address_from_address(&(msg->from), outbound_session->our_address);
    copy_address_from_address(&(msg->to), outbound_session->their_address);

    msg->n_pre_shared_input_list = outbound_session->n_pre_shared_input_list;
    msg->pre_shared_input_list = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData) * msg->n_pre_shared_input_list);
    size_t i;
    for (i = 0; i < msg->n_pre_shared_input_list; i++) {
        init_protobuf(&(msg->pre_shared_input_list[i]));
        copy_protobuf_from_protobuf(&(msg->pre_shared_input_list[i]), &(outbound_session->pre_shared_input_list[i]));
    }

    copy_protobuf_from_protobuf(&(msg->alice_base_key), &(outbound_session->alice_base_key->public_key));

    msg->bob_signed_pre_key_id = outbound_session->bob_signed_pre_key_id;
    msg->bob_one_time_pre_key_id = outbound_session->bob_one_time_pre_key_id;

    msg->invite_t = outbound_session->invite_t;

    // done
    request->msg = msg;
    return request;
}

bool consume_invite_response(
    Skissm__E2eeAddress *user_address,
    Skissm__InviteResponse *response
) {
    if (response != NULL) {
        if (response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK
            || response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_NOT_FOUND
        ) {
            ssm_notify_log(user_address, DEBUG_LOG, "consume_invite_response() response code: %d", response->code);
            return true;
        }
    }
    return false;
}

bool consume_invite_msg(Skissm__E2eeAddress *receiver_address, Skissm__InviteMsg *invite_msg) {
    ssm_notify_log(
        receiver_address, DEBUG_LOG, "consume_invite_msg(): from [%s:%s], to [%s:%s]",
        invite_msg->from->user->user_id,
        invite_msg->from->user->device_id,
        invite_msg->to->user->user_id,
        invite_msg->to->user->device_id
    );

    uint32_t e2ee_pack_id = invite_msg->e2ee_pack_id;
    Skissm__E2eeAddress *from = invite_msg->from;
    Skissm__E2eeAddress *to = invite_msg->to;

    if (!compare_address(receiver_address, to)) {
        ssm_notify_log(receiver_address, BAD_SERVER_MESSAGE, "consume_invite_msg()");
        return false;
    }

    Skissm__Session *our_session = NULL;
    get_skissm_plugin()->db_handler.load_outbound_session(receiver_address, from, &our_session);
    if (our_session != NULL) {
        if (our_session->invite_t > invite_msg->invite_t) {
            skissm__session__free_unpacked(our_session, NULL);
            // just consume
            return true;
        } else {
            // unload the old session if necessary
            get_skissm_plugin()->db_handler.unload_session(receiver_address, from);
        }
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
    Skissm__Session *inbound_session = NULL;
    inbound_session = (Skissm__Session *)malloc(sizeof(Skissm__Session));
    initialise_session(inbound_session, e2ee_pack_id, to, from);
    const session_suite_t *session_suite = get_e2ee_pack(e2ee_pack_id)->session_suite;
    // set the version and session id
    inbound_session->version = strdup(invite_msg->version);
    inbound_session->session_id = strdup(invite_msg->session_id);
    // create a new inbound session
    int result = session_suite->new_inbound_session(inbound_session, account, invite_msg);

    if (result != 0
        || safe_strcmp(inbound_session->session_id, invite_msg->session_id) == false) {
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
    uint32_t e2ee_pack_id,
    Skissm__E2eeAddress *from,
    Skissm__E2eeAddress *to,
    ProtobufCBinaryData *ciphertext_1,
    ProtobufCBinaryData *our_ratchet_key
) {
    Skissm__AcceptRequest *request = (Skissm__AcceptRequest *) malloc(sizeof(Skissm__AcceptRequest));
    skissm__accept_request__init(request);

    Skissm__AcceptMsg *msg = (Skissm__AcceptMsg *) malloc(sizeof(Skissm__AcceptMsg));
    skissm__accept_msg__init(msg);

    msg->e2ee_pack_id = e2ee_pack_id;
    copy_address_from_address(&(msg->from), from);
    copy_address_from_address(&(msg->to), to);

    if (ciphertext_1 != NULL) {
        copy_protobuf_from_protobuf(&(msg->encaps_ciphertext), ciphertext_1);
    }

    copy_protobuf_from_protobuf(&(msg->ratchet_key), our_ratchet_key);

    // done
    request->msg = msg;
    return request;
}

bool consume_accept_response(Skissm__E2eeAddress *user_address, Skissm__AcceptResponse *response) {
    if (response != NULL) {
        ssm_notify_log(user_address, DEBUG_LOG, "consume_accept_response() response code: %d", response->code);
        if (response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK
            || response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_NOT_FOUND) {
            return true;
        }
    }
    return false;
}

bool consume_accept_msg(Skissm__E2eeAddress *receiver_address, Skissm__AcceptMsg *accept_msg) {
    ssm_notify_log(receiver_address, DEBUG_LOG, "consume_accept_msg(): from [%s:%s], to [%s:%s]", 
        accept_msg->from->user->user_id,
        accept_msg->from->user->device_id,
        accept_msg->to->user->user_id,
        accept_msg->to->user->device_id);

    if (!compare_address(receiver_address, accept_msg->to)) {
        ssm_notify_log(receiver_address, BAD_SERVER_MESSAGE, "consume_accept_msg()");
        return false;
    }

    Skissm__Session *outbound_session = NULL;
    // Is it unique?
    get_skissm_plugin()->db_handler.load_outbound_session(accept_msg->to, accept_msg->from, &outbound_session);
    if (outbound_session == NULL) {
        ssm_notify_log(
            receiver_address,
            BAD_MESSAGE_FORMAT,
            "consume_accept_msg() from [], to []: can't load outbound session and make it a complete and responded session.",
            accept_msg->from->user->user_id,
            accept_msg->from->user->device_id,
            accept_msg->to->user->user_id,
            accept_msg->to->user->device_id);
        return false;
    }
    const session_suite_t *session_suite = get_e2ee_pack(accept_msg->e2ee_pack_id)->session_suite;
    int result = session_suite->complete_outbound_session(outbound_session, accept_msg);

    // store sesson state
    get_skissm_plugin()->db_handler.store_session(outbound_session);

    // notify
    ssm_notify_outbound_session_ready(receiver_address, outbound_session);

    // try to send group pre-keys if necessary
    send_pending_plaintext_data(outbound_session);

    return result >= 0;
}
