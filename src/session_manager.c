#include "skissm/session_manager.h"

#include <stdio.h>
#include <string.h>

#include "skissm/account.h"
#include "skissm/account_cache.h"
#include "skissm/e2ee_client.h"
#include "skissm/e2ee_client_internal.h"
#include "skissm/group_session.h"
#include "skissm/mem_util.h"
#include "skissm/ratchet.h"
#include "skissm/validation.h"
#include "skissm/session.h"

typedef struct group_address_node {
    Skissm__E2eeAddress *group_address;
    struct group_address_node *next;
} group_address_node;

static void send_pending_plaintext_data(Skissm__Session *outbound_session) {
    // load pending plaintext data(may be the group pre-key or the common plaintext)
    uint32_t pending_plaintext_data_list_num;
    char **pending_plaintext_id_list;
    uint8_t **pending_plaintext_data_list;
    size_t *pending_plaintext_data_len_list;
    Skissm__NotifLevel *notif_level_list;
    pending_plaintext_data_list_num =
        get_skissm_plugin()->db_handler.load_pending_plaintext_data(
            outbound_session->our_address,
            outbound_session->their_address,
            &pending_plaintext_id_list,
            &pending_plaintext_data_list,
            &pending_plaintext_data_len_list,
            &notif_level_list
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
                notif_level_list[i],
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
        free_mem((void **)&notif_level_list, sizeof(Skissm__NotifLevel) * pending_plaintext_data_list_num);
    }
}

int produce_get_pre_key_bundle_request(
    Skissm__GetPreKeyBundleRequest **request_out,
    const char *to_user_id,
    const char *to_domain,
    const char *to_device_id,
    bool active
) {
    int ret = SKISSM_RESULT_SUCC;

    Skissm__GetPreKeyBundleRequest *request = NULL;

    if (!is_valid_string(to_user_id)) {
        ret = SKISSM_RESULT_FAIL;
    }
    if (!is_valid_string(to_domain)) {
        ret = SKISSM_RESULT_FAIL;
    }

    if (ret == SKISSM_RESULT_SUCC) {
        request = (Skissm__GetPreKeyBundleRequest *)malloc(sizeof(Skissm__GetPreKeyBundleRequest));
        skissm__get_pre_key_bundle_request__init(request);
        request->domain = strdup(to_domain);
        request->user_id = strdup(to_user_id);
        if (to_device_id != NULL) {
            // the device ID may be empty or nonempty
            request->device_id = strdup(to_device_id);
        }

        *request_out = request;
    }

    return ret;
}

int consume_get_pre_key_bundle_response(
    Skissm__InviteResponse ***invite_response_list_out,
    size_t *invite_response_num,
    Skissm__E2eeAddress *from,
    uint8_t *group_pre_key_plaintext_data,
    size_t group_pre_key_plaintext_data_len,
    Skissm__GetPreKeyBundleResponse *get_pre_key_bundle_response
) {
    int ret = SKISSM_RESULT_SUCC;

    Skissm__PreKeyBundle **their_pre_key_bundles = NULL;
    size_t n_pre_key_bundles;
    Skissm__PreKeyBundle *cur_pre_key_bundle = NULL;
    Skissm__E2eeAddress *to_address = NULL;
    uint32_t e2ee_pack_id;
    Skissm__InviteResponse **invite_response_list = NULL;
    int invite_response_ret = 0;    // this parameter may be useful
    int server_check = 0;
    ProtobufCBinaryData server_public_key = {0, NULL};
    bool is_self = false;
    char *from_user_id = NULL;

    if (is_valid_address(from)) {
        from_user_id = from->user->user_id;
        if (is_valid_get_pre_key_bundle_response(get_pre_key_bundle_response)) {
            their_pre_key_bundles = get_pre_key_bundle_response->pre_key_bundles;
            n_pre_key_bundles = get_pre_key_bundle_response->n_pre_key_bundles;

            if (safe_strcmp(from_user_id, get_pre_key_bundle_response->user_id)) {
                if (n_pre_key_bundles > 1) {
                    // pre-key bundles from this and other devices, but we need not invite this device
                    is_self = true;
                    invite_response_list = (Skissm__InviteResponse **)malloc(sizeof(Skissm__InviteResponse *) * (n_pre_key_bundles - 1));
                } else if (n_pre_key_bundles == 1) {
                    if (!compare_address(from, their_pre_key_bundles[0]->user_address)) {
                        invite_response_list = (Skissm__InviteResponse **)malloc(sizeof(Skissm__InviteResponse *));
                    } else {
                        ret = SKISSM_RESULT_FAIL;
                    }
                } else {
                    ssm_notify_log(NULL, BAD_RESPONSE, "consume_get_pre_key_bundle_response()");
                    ret = SKISSM_RESULT_FAIL;
                }
            } else {
                invite_response_list = (Skissm__InviteResponse **)malloc(sizeof(Skissm__InviteResponse *) * n_pre_key_bundles);
            }

            load_server_public_key_from_cache(&server_public_key, from);
        } else {
            ssm_notify_log(NULL, BAD_RESPONSE, "consume_get_pre_key_bundle_response()");
            ret = SKISSM_RESULT_FAIL;
        }
    } else {
        ret = SKISSM_RESULT_FAIL;
    }

    if (ret == SKISSM_RESULT_SUCC) {
        size_t i;
        int insert_pos = 0;
        for (i = 0; i < n_pre_key_bundles; i++) {
            cur_pre_key_bundle = their_pre_key_bundles[i];
            e2ee_pack_id = cur_pre_key_bundle->e2ee_pack_id;
            to_address = cur_pre_key_bundle->user_address;
            // skip if the pre-key bundle is from this device
            if (is_self) {
                if (compare_address(from, to_address)) {
                    continue;
                }
            }

            if (is_valid_server_signed_signature(cur_pre_key_bundle->signature)) {
                digital_signature_suite_t *digital_signature_suite = get_digital_signature_suite(cur_pre_key_bundle->signature->signing_alg);
                server_check = digital_signature_suite->verify(
                    cur_pre_key_bundle->signature->signature.data,
                    cur_pre_key_bundle->signature->signature.len,
                    cur_pre_key_bundle->signature->msg_fingerprint.data,
                    cur_pre_key_bundle->signature->msg_fingerprint.len,
                    server_public_key.data
                );

                if (server_check < 0) {
                    ssm_notify_log(NULL, BAD_SERVER_SIGNATURE, "consume_get_pre_key_bundle_response()");
                }
            } else {
                ssm_notify_log(NULL, BAD_SERVER_SIGNATURE, "consume_get_pre_key_bundle_response()");
            }

            // store the group pre-keys if necessary
            if (group_pre_key_plaintext_data != NULL) {
                ssm_notify_log(from, DEBUG_LOG, "consume_get_pre_key_bundle_response() store the group pre-keys");
                char *pending_plaintext_id = generate_uuid_str();
                get_skissm_plugin()->db_handler.store_pending_plaintext_data(
                    from,
                    to_address,
                    pending_plaintext_id,
                    group_pre_key_plaintext_data,
                    group_pre_key_plaintext_data_len,
                    SKISSM__NOTIF_LEVEL__NOTIF_LEVEL_SESSION
                );
                // release
                free(pending_plaintext_id);
                pending_plaintext_id = NULL;
            }

            // create an outbound session
            const session_suite_t *session_suite = get_e2ee_pack(e2ee_pack_id)->session_suite;
            invite_response_ret = session_suite->new_outbound_session(&(invite_response_list[insert_pos]), from, cur_pre_key_bundle);
            insert_pos++;
        }

        *invite_response_list_out = invite_response_list;
        *invite_response_num = n_pre_key_bundles;
    }

    // done
    return ret;
}

int produce_send_one2one_msg_request(
    Skissm__SendOne2oneMsgRequest **request_out,
    Skissm__Session *outbound_session,
    uint32_t notif_level,
    const uint8_t *plaintext_data, size_t plaintext_data_len
) {
    int ret = SKISSM_RESULT_SUCC;

    Skissm__One2oneMsgPayload *payload_out = NULL;

    if (outbound_session != NULL) {
        if (outbound_session->session_id == NULL)
            ret = SKISSM_RESULT_FAIL;
        if (outbound_session->our_address == NULL)
            ret = SKISSM_RESULT_FAIL;
        if (outbound_session->their_address == NULL)
            ret = SKISSM_RESULT_FAIL;
        if (outbound_session->ratchet == NULL)
            ret = SKISSM_RESULT_FAIL;
    } else {
        ret = SKISSM_RESULT_FAIL;
    }

    if (ret == SKISSM_RESULT_SUCC) {
        const cipher_suite_t *cipher_suite = get_e2ee_pack(outbound_session->e2ee_pack_id)->cipher_suite;
        ret = encrypt_ratchet(
            &payload_out, cipher_suite,
            outbound_session->ratchet, outbound_session->associated_data,
            plaintext_data, plaintext_data_len
        );
    }

    if (ret == SKISSM_RESULT_SUCC) {
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
        e2ee_msg->one2one_msg = payload_out;

        Skissm__SendOne2oneMsgRequest *request = (Skissm__SendOne2oneMsgRequest *)malloc(sizeof(Skissm__SendOne2oneMsgRequest));
        skissm__send_one2one_msg_request__init(request);
        request->msg = e2ee_msg;

        *request_out = request;
    } else {
        *request_out = NULL;
    }

    return ret;
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
    int ret = SKISSM_RESULT_SUCC;
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
    if (e2ee_msg->payload_case == SKISSM__E2EE_MSG__PAYLOAD_ONE2ONE_MSG) {
        payload = e2ee_msg->one2one_msg;
    }
    if (payload != NULL) {
        uint8_t *decrypted_data_out = NULL;
        size_t decrypted_data_len_out;
        const cipher_suite_t *cipher_suite = get_e2ee_pack(inbound_session->e2ee_pack_id)->cipher_suite;
        ret = decrypt_ratchet(&decrypted_data_out, &decrypted_data_len_out, cipher_suite, inbound_session->ratchet, inbound_session->associated_data, payload);

        // store session state
        get_skissm_plugin()->db_handler.store_session(inbound_session);

        // delete old sessions if necessary
        get_skissm_plugin()->db_handler.unload_old_session(receiver_address, e2ee_msg->from, inbound_session->invite_t);

        if (decrypted_data_out != NULL && decrypted_data_len_out > 0) {
            Skissm__Plaintext *plaintext = skissm__plaintext__unpack(NULL, decrypted_data_len_out, decrypted_data_out);
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
                        ssm_notify_log(
                            receiver_address, BAD_ACCOUNT, "invite() from [%s:%s] to [%s@%s]",
                            receiver_address->user->user_id,
                            receiver_address->user->device_id,
                            to_user_id,
                            to_domain
                        );
                        return NULL;
                    }

                    Skissm__InviteResponse *invite_response = NULL;
                    Skissm__InviteResponse **invite_response_list = NULL;
                    size_t invite_response_num = 0;
                    size_t their_devices_num = their_device_id_list->n_device_id_list;
                    size_t i;
                    if (their_devices_num == 0) {
                        // this paragraph may be useless
                        ret = get_pre_key_bundle_internal(
                            &invite_response_list,
                            &invite_response_num,
                            receiver_address,
                            auth,
                            to_user_id,
                            to_domain,
                            NULL,
                            false,
                            NULL, 0
                        );
                        // release
                        free_invite_response_list(&invite_response_list, invite_response_num);
                    } else {
                        char *cur_device_id = NULL;
                        for (i = 0; i < their_devices_num; i++) {
                            cur_device_id = their_device_id_list->device_id_list[i];
                            ret = get_pre_key_bundle_internal(
                                &invite_response_list,
                                &invite_response_num,
                                receiver_address,
                                auth,
                                to_user_id,
                                to_domain,
                                cur_device_id,
                                false,
                                NULL, 0
                            );
                            // release
                            if (ret == SKISSM_RESULT_SUCC) {
                                free_invite_response_list(&invite_response_list, invite_response_num);
                            }
                        }
                    }

                    // release
                    free_string(&auth);
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
            free_mem((void **)&decrypted_data_out, decrypted_data_len_out);
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

bool consume_add_user_device_msg(Skissm__E2eeAddress *receiver_address, Skissm__AddUserDeviceMsg *msg) {
    int ret = SKISSM_RESULT_SUCC;

    Skissm__E2eeAddress *new_user_address = NULL;
    Skissm__E2eeAddress **old_address_list = NULL;
    size_t old_address_list_number;
    group_address_node *group_address_list = NULL;
    group_address_node *cur_group_address_node = NULL;
    group_address_node *tail_group_address_node = NULL;
    Skissm__E2eeAddress **group_addresses = NULL;
    size_t group_address_num;
    size_t i, j;

    if (!is_valid_address(receiver_address)) {
        ret = SKISSM_RESULT_FAIL;
    }
    if (is_valid_add_user_device_msg(msg)) {
        new_user_address = msg->user_address;
        old_address_list = msg->old_address_list;
        old_address_list_number = msg->n_old_address_list;
    } else {
        ret = SKISSM_RESULT_FAIL;
    }

    if (ret == -1) {
        return false;
    }

    for (i = 0; i < old_address_list_number; i++) {
        // load all outbound group addresses
        group_address_num = get_skissm_plugin()->db_handler.load_group_addresses(old_address_list[i], receiver_address, &group_addresses);

        if (group_address_num == 0)
            continue;

        for (j = 0; j < group_address_num; j++) {
            if (group_address_list != NULL) {
                cur_group_address_node = group_address_list;
                tail_group_address_node = NULL;
                while (cur_group_address_node != NULL) {
                    if (compare_address(cur_group_address_node->group_address, group_addresses[j])) {
                        break;
                    }
                    if (cur_group_address_node->next == NULL) {
                        tail_group_address_node = cur_group_address_node;
                    }
                    cur_group_address_node = cur_group_address_node->next;
                }
                if (tail_group_address_node != NULL) {
                    tail_group_address_node->next = (group_address_node *)malloc(sizeof(group_address_node));
                    copy_address_from_address(&(tail_group_address_node->next->group_address), group_addresses[j]);
                    tail_group_address_node->next->next = NULL;
                }
            } else {
                group_address_list = (group_address_node *)malloc(sizeof(group_address_node));
                copy_address_from_address(&(group_address_list->group_address), group_addresses[j]);
                group_address_list->next = NULL;
            }
        }

        // release
        for (j = 0; j < group_address_num; j++) {
            skissm__e2ee_address__free_unpacked(group_addresses[j], NULL);
            group_addresses[j] = NULL;
        }
        if (group_addresses != NULL) {
            free_mem((void **)&group_addresses, sizeof(Skissm__E2eeAddress *) * group_address_num);
            group_addresses = NULL;
        }
    }

    if (group_address_list != NULL) {
        cur_group_address_node = group_address_list;
        while (cur_group_address_node != NULL) {
            Skissm__AddGroupMemberDeviceResponse *add_group_member_device_response = NULL;
            ret = add_group_member_device_internal(
                &add_group_member_device_response, receiver_address, cur_group_address_node->group_address, new_user_address
            );

            // release
            free_proto(add_group_member_device_response);

            cur_group_address_node = cur_group_address_node->next;
        }
    }

    // done
    return true;
}

bool consume_remove_user_device_msg(Skissm__E2eeAddress *receiver_address, Skissm__RemoveUserDeviceMsg *msg) {
    if (!is_valid_address(receiver_address)) {
        return false;
    }
    if (!is_valid_remove_user_device_msg(msg)) {
        return false;
    }
    // delete the corresponding session
    get_skissm_plugin()->db_handler.unload_session(receiver_address, msg->user_address);

    return true;
}

int produce_invite_request(
    Skissm__InviteRequest **request_out,
    Skissm__Session *outbound_session
) {
    int ret = SKISSM_RESULT_SUCC;

    Skissm__InviteRequest *request = NULL;
    Skissm__InviteMsg *msg = NULL;

    if (!is_valid_uncompleted_session(outbound_session)) {
        ret = SKISSM_RESULT_FAIL;
    }

    if (ret == SKISSM_RESULT_SUCC) {
        msg = (Skissm__InviteMsg *)malloc(sizeof(Skissm__InviteMsg));
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

        request = (Skissm__InviteRequest *)malloc(sizeof(Skissm__InviteRequest));
        skissm__invite_request__init(request);
        request->msg = msg;

        *request_out = request;
    }

    return ret;
}

int consume_invite_response(
    Skissm__E2eeAddress *user_address,
    Skissm__InviteResponse *response
) {
    int ret = SKISSM_RESULT_SUCC;

    if (is_valid_address(user_address)) {
        if (!is_valid_invite_response(response)) {
            ssm_notify_log(NULL, BAD_RESPONSE, "consume_invite_response()");
            ret = SKISSM_RESULT_FAIL;
        }
    } else {
        ret = SKISSM_RESULT_FAIL;
    }

    if (ret == SKISSM_RESULT_SUCC) {
        // load the corresponding inbound session
        Skissm__Session *inbound_session = NULL;
        get_skissm_plugin()->db_handler.load_inbound_session(response->session_id, user_address, &inbound_session);
        if (inbound_session != NULL) {
            // update invite_t
            inbound_session->invite_t = response->invite_t;
            get_skissm_plugin()->db_handler.store_session(inbound_session);
        } else {
            ssm_notify_log(NULL, BAD_SESSION, "consume_invite_response()");
            ret = SKISSM_RESULT_FAIL;
        }
    }

    // if (response != NULL) {
    //     ssm_notify_log(user_address, DEBUG_LOG, "consume_invite_response() response code: %d", response->code);
    //     if (response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
    //         // load the corresponding inbound session
    //         Skissm__Session *inbound_session = NULL;
    //         get_skissm_plugin()->db_handler.load_inbound_session(response->session_id, user_address, &inbound_session);
    //         if (inbound_session != NULL) {
    //             // update invite_t
    //             inbound_session->invite_t = response->invite_t;
    //             get_skissm_plugin()->db_handler.store_session(inbound_session);
    //         }
    //         return true;
    //     } else if (response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_NOT_FOUND) {
    //         return true;
    //     }
    // }

    return ret;
}

bool consume_invite_msg(Skissm__E2eeAddress *receiver_address, Skissm__InviteMsg *invite_msg) {
    if (!is_valid_address(receiver_address)) {
        return false;
    }
    if (!is_valid_invite_msg(invite_msg)) {
        return false;
    }

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
    char *version = invite_msg->version;
    char *session_id = invite_msg->session_id;

    if (!compare_address(receiver_address, to)) {
        ssm_notify_log(receiver_address, BAD_SERVER_MESSAGE, "consume_invite_msg() wrong receiver_address, just consume it");
        // just consume it
        return true;
    }

    // check if session ID has been used
    Skissm__Session *inbound_session = NULL;
    get_skissm_plugin()->db_handler.load_inbound_session(session_id, receiver_address, &inbound_session);
    if (inbound_session != NULL) {
        ssm_notify_log(receiver_address, BAD_SESSION, "consume_invite_msg() session ID has been used, just consume it");
        // release
        skissm__session__free_unpacked(inbound_session, NULL);
        // just consume it
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

    inbound_session = NULL;
    const session_suite_t *session_suite = get_e2ee_pack(e2ee_pack_id)->session_suite;
    // create a new inbound session
    int result = session_suite->new_inbound_session(&inbound_session, account, invite_msg);

    if (result != 0
        || safe_strcmp(inbound_session->session_id, invite_msg->session_id) == false
    ) {
        ssm_notify_log(receiver_address, BAD_MESSAGE_FORMAT, "consume_invite_msg()");
        result = -1;
    } else {
        // notify
        ssm_notify_inbound_session_ready(receiver_address, inbound_session);
    }
    // release
    free_proto(account);
    skissm__session__free_unpacked(inbound_session, NULL);

    // done
    return result == 0;
}

int produce_accept_request(
    Skissm__AcceptRequest **request_out,
    uint32_t e2ee_pack_id,
    Skissm__E2eeAddress *from,
    Skissm__E2eeAddress *to,
    ProtobufCBinaryData *ciphertext_1,
    ProtobufCBinaryData *our_ratchet_key
) {
    int ret = SKISSM_RESULT_SUCC;

    Skissm__AcceptRequest *request = NULL;
    Skissm__AcceptMsg *msg = NULL;

    if (!is_valid_e2ee_pack_id(e2ee_pack_id)) {
        ret = SKISSM_RESULT_FAIL;
    }
    if (!is_valid_address(from)) {
        ret = SKISSM_RESULT_FAIL;
    }
    if (!is_valid_address(to)) {
        ret = SKISSM_RESULT_FAIL;
    }
    if (ciphertext_1 != NULL) {
        if (!is_valid_protobuf(ciphertext_1)) {
            ret = SKISSM_RESULT_FAIL;
        }
    }
    if (!is_valid_protobuf(our_ratchet_key)) {
        ret = SKISSM_RESULT_FAIL;
    }

    if (ret == SKISSM_RESULT_SUCC) {
        msg = (Skissm__AcceptMsg *)malloc(sizeof(Skissm__AcceptMsg));
        skissm__accept_msg__init(msg);

        msg->e2ee_pack_id = e2ee_pack_id;
        copy_address_from_address(&(msg->from), from);
        copy_address_from_address(&(msg->to), to);

        if (ciphertext_1 != NULL) {
            copy_protobuf_from_protobuf(&(msg->encaps_ciphertext), ciphertext_1);
        }

        copy_protobuf_from_protobuf(&(msg->ratchet_key), our_ratchet_key);

        request = (Skissm__AcceptRequest *)malloc(sizeof(Skissm__AcceptRequest));
        skissm__accept_request__init(request);
        request->msg = msg;

        *request_out = request;
    }

    return ret;
}

int consume_accept_response(Skissm__E2eeAddress *user_address, Skissm__AcceptResponse *response) {
    int ret = SKISSM_RESULT_SUCC;

    if (is_valid_address(user_address)) {
        if (!is_valid_accept_response(response)) {
            ssm_notify_log(NULL, BAD_RESPONSE, "consume_accept_response()");
            ret = SKISSM_RESULT_FAIL;
        }
    } else {
        ret = SKISSM_RESULT_FAIL;
    }

    // if (response != NULL) {
    //     ssm_notify_log(user_address, DEBUG_LOG, "consume_accept_response() response code: %d", response->code);
    //     if (response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK
    //         || response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_NOT_FOUND) {
    //         return true;
    //     }
    // }

    return ret;
}

bool consume_accept_msg(Skissm__E2eeAddress *receiver_address, Skissm__AcceptMsg *accept_msg) {
    if (!is_valid_address(receiver_address)) {
        return false;
    }
    if (!is_valid_accept_msg(accept_msg)) {
        return false;
    }

    ssm_notify_log(
        receiver_address, DEBUG_LOG, "consume_accept_msg(): from [%s:%s], to [%s:%s]", 
        accept_msg->from->user->user_id,
        accept_msg->from->user->device_id,
        accept_msg->to->user->user_id,
        accept_msg->to->user->device_id
    );

    if (!compare_address(receiver_address, accept_msg->to)) {
        ssm_notify_log(receiver_address, BAD_SERVER_MESSAGE, "consume_accept_msg()");
        // just consume it
        return true;
    }

    Skissm__Session *outbound_session = NULL;
    const session_suite_t *session_suite = get_e2ee_pack(accept_msg->e2ee_pack_id)->session_suite;
    int result = session_suite->complete_outbound_session(&outbound_session, accept_msg);

    if (result == 0) {
        // notify
        ssm_notify_outbound_session_ready(receiver_address, outbound_session);

        // try to send group pre-keys if necessary
        send_pending_plaintext_data(outbound_session);
    }

    return result >= 0;
}
