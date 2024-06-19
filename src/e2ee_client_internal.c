#include "skissm/e2ee_client_internal.h"

#include <string.h>

#include "skissm/account_manager.h"
#include "skissm/group_session_manager.h"
#include "skissm/mem_util.h"
#include "skissm/safe_check.h"
#include "skissm/session_manager.h"
#include "skissm/e2ee_client.h"

int get_pre_key_bundle_internal(
    Skissm__InviteResponse ***invite_response_list_out,
    Skissm__E2eeAddress *from,
    const char *auth,
    const char *to_user_id,
    const char *to_domain,
    const char *to_device_id,
    bool active,
    uint8_t *group_pre_key_plaintext_data,
    size_t group_pre_key_plaintext_data_len
) {
    int ret = 0;

    Skissm__GetPreKeyBundleRequest *get_pre_key_bundle_request = NULL;
    Skissm__GetPreKeyBundleResponse *get_pre_key_bundle_response = NULL;
    // Skissm__InviteResponse *invite_response = NULL;
    Skissm__InviteResponse **invite_response_list = NULL;

    if (!safe_address(from)) {
        ssm_notify_log(NULL, BAD_ADDRESS, "get_pre_key_bundle_internal()");
        ret = -1;
    }
    if (!nonempty_string(auth)) {
        ssm_notify_log(NULL, BAD_AUTH, "get_pre_key_bundle_internal()");
        ret = -1;
    }
    if (!nonempty_string(to_user_id)) {
        ssm_notify_log(NULL, BAD_USER_ID, "get_pre_key_bundle_internal()");
        ret = -1;
    }
    if (!nonempty_string(to_domain)) {
        ssm_notify_log(NULL, BAD_DOMAIN, "get_pre_key_bundle_internal()");
        ret = -1;
    }

    if (ret == 0) {
        // to_device_id can be null
        ret = produce_get_pre_key_bundle_request(&get_pre_key_bundle_request, to_user_id, to_domain, to_device_id);
    }

    if (ret == 0) {
        get_pre_key_bundle_response = get_skissm_plugin()->proto_handler.get_pre_key_bundle(from, auth, get_pre_key_bundle_request);

        if (!safe_get_pre_key_bundle_response(get_pre_key_bundle_response)) {
            ssm_notify_log(NULL, BAD_RESPONSE, "get_pre_key_bundle_internal()");
            ret = -1;
        }
    }

    if (ret == 0) {
        ret = consume_get_pre_key_bundle_response(
            &invite_response_list,
            from,
            group_pre_key_plaintext_data,
            group_pre_key_plaintext_data_len,
            get_pre_key_bundle_response
        );
    }

    if (ret == 0) {
        if (active == true) {
            size_t their_device_num = get_pre_key_bundle_response->n_pre_key_bundles;
            char **their_device_id = (char **)malloc(sizeof(char *) * their_device_num);
            Skissm__PreKeyBundle *cur_pre_key_bundle = NULL;
            size_t i;
            for (i = 0; i < their_device_num; i++) {
                cur_pre_key_bundle = get_pre_key_bundle_response->pre_key_bundles[i];
                their_device_id[i] = strdup(cur_pre_key_bundle->user_address->user->device_id);
            }
            // send to other devices in order to create sessions
            send_sync_invite_msg(from, to_user_id, to_domain, their_device_id, their_device_num);

            // release
            for (i = 0; i < their_device_num; i++) {
                free(their_device_id[i]);
                their_device_id[i] = NULL;
            }
            free_mem((void **)&their_device_id, sizeof(char *) * their_device_num);
        }

        *invite_response_list_out = invite_response_list;
    } else {
        if (get_pre_key_bundle_response != NULL) {
            if (get_pre_key_bundle_response->code != SKISSM__RESPONSE_CODE__RESPONSE_CODE_NO_CONTENT) {
                ssm_notify_log(from, DEBUG_LOG, "get_pre_key_bundle_internal() get_pre_key_bundle_response got error, pending request will be stored.");
                // pack request to get_pre_key_bundle_request_data which will be freed inside store_pending_request_internal
                size_t get_pre_key_bundle_request_data_len = skissm__get_pre_key_bundle_request__get_packed_size(get_pre_key_bundle_request);
                uint8_t *get_pre_key_bundle_request_data = (uint8_t *)malloc(sizeof(uint8_t) * get_pre_key_bundle_request_data_len);
                skissm__get_pre_key_bundle_request__pack(get_pre_key_bundle_request, get_pre_key_bundle_request_data);

                store_pending_request_internal(
                    from, SKISSM__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_GET_PRE_KEY_BUNDLE,
                    get_pre_key_bundle_request_data, get_pre_key_bundle_request_data_len,
                    group_pre_key_plaintext_data, group_pre_key_plaintext_data_len
                );

                // release
                free_mem((void *)&get_pre_key_bundle_request_data, get_pre_key_bundle_request_data_len);
            }
        }
        // What if get_pre_key_bundle_response is NULL? Should we store pending request?
    }

    // // does not invite, if the get_pre_key_bundle_response code is no content
    // if (get_pre_key_bundle_response != NULL 
    //     && get_pre_key_bundle_response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_NOT_FOUND
    // ) {
    //     ssm_notify_log(from, DEBUG_LOG, "get_pre_key_bundle_internal() got no content response, skip.");
    //     // release
    //     skissm__get_pre_key_bundle_request__free_unpacked(get_pre_key_bundle_request, NULL);
    //     skissm__get_pre_key_bundle_response__free_unpacked(get_pre_key_bundle_response, NULL);
    //     // skip invite
    //     return NULL;
    // }

    // invite_response = consume_get_pre_key_bundle_response(
    //     from, group_pre_key_plaintext_data, group_pre_key_plaintext_data_len, get_pre_key_bundle_response
    // );

    // if ((invite_response != NULL)
    //     && ((invite_response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK)
    //         || (invite_response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_NOT_FOUND)
    //     )
    // ) {
    //     // we do not store pending request if the invite_response code is no content
    // } else {
    //     ssm_notify_log(from, DEBUG_LOG, "get_pre_key_bundle_internal() invite_response got error, pending request will be stored.");
    //     // pack request to get_pre_key_bundle_request_data which will be freed inside store_pending_request_internal
    //     size_t get_pre_key_bundle_request_data_len = skissm__get_pre_key_bundle_request__get_packed_size(get_pre_key_bundle_request);
    //     uint8_t *get_pre_key_bundle_request_data = (uint8_t *)malloc(sizeof(uint8_t) * get_pre_key_bundle_request_data_len);
    //     skissm__get_pre_key_bundle_request__pack(get_pre_key_bundle_request, get_pre_key_bundle_request_data);

    //     store_pending_request_internal(
    //         from, SKISSM__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_GET_PRE_KEY_BUNDLE,
    //         get_pre_key_bundle_request_data, get_pre_key_bundle_request_data_len,
    //         group_pre_key_plaintext_data, group_pre_key_plaintext_data_len
    //     );

    //     // release
    //     free_mem((void *)&get_pre_key_bundle_request_data, get_pre_key_bundle_request_data_len);
    // }

    // if (active == true) {
    //     // this device has invited, but other devices has not
    //     if (get_pre_key_bundle_response != NULL) {
    //         size_t their_device_num = get_pre_key_bundle_response->n_pre_key_bundles;
    //         char **their_device_id = (char **)malloc(sizeof(char *) * their_device_num);
    //         Skissm__PreKeyBundle *cur_pre_key_bundle = NULL;
    //         size_t i;
    //         for (i = 0; i < their_device_num; i++) {
    //             cur_pre_key_bundle = get_pre_key_bundle_response->pre_key_bundles[i];
    //             their_device_id[i] = strdup(cur_pre_key_bundle->user_address->user->device_id);
    //         }
    //         // send to other devices in order to create sessions
    //         send_sync_invite_msg(from, to_user_id, to_domain, their_device_id, their_device_num);
    //     } else {
    //         send_sync_invite_msg(from, to_user_id, to_domain, NULL, 0);
    //     }
    // }

    // release
    skissm__get_pre_key_bundle_request__free_unpacked(get_pre_key_bundle_request, NULL);
    if (get_pre_key_bundle_response != NULL)
        skissm__get_pre_key_bundle_response__free_unpacked(get_pre_key_bundle_response, NULL);

    // done
    return ret;
}

int invite_internal(
    Skissm__InviteResponse **response_out,
    Skissm__Session *outbound_session
) {
    int ret = 0;

    Skissm__InviteRequest *request = NULL;
    Skissm__InviteResponse *response = NULL;
    Skissm__E2eeAddress *user_address = NULL;
    char *auth = NULL;

    if (safe_uncompleted_session(outbound_session)) {
        user_address = outbound_session->our_address;
        get_skissm_plugin()->db_handler.load_auth(user_address, &auth);
        if (!nonempty_string(auth)) {
            ssm_notify_log(user_address, BAD_AUTH, "invite_internal()");
            ret = -1;
        }
    } else {
        ssm_notify_log(user_address, BAD_SESSION, "invite_internal()");
        ret = -1;
    }

    if (ret == 0) {
        ret = produce_invite_request(&request, outbound_session);
    }

    if (ret == 0) {
        response = get_skissm_plugin()->proto_handler.invite(user_address, auth, request);

        if (safe_invite_response(response)) {
            ret = consume_invite_response(user_address, response);
        } else {
            // pack request to request_data
            size_t request_data_len = skissm__invite_request__get_packed_size(request);
            uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
            skissm__invite_request__pack(request, request_data);

            // store the request_data into pending
            store_pending_request_internal(
                user_address, SKISSM__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_INVITE, request_data, request_data_len, NULL, 0
            );
            // release
            free_mem((void *)&request_data, request_data_len);
        }

        // release
        free(auth);
        auth = NULL;
        skissm__invite_request__free_unpacked(request, NULL);
        request = NULL;
    }

    if (ret == 0) {
        *response_out = response;
    }

    // done
    return ret;
}

int accept_internal(
    Skissm__AcceptResponse **response_out,
    uint32_t e2ee_pack_id,
    Skissm__E2eeAddress *from,
    Skissm__E2eeAddress *to,
    ProtobufCBinaryData *ciphertext_1,
    ProtobufCBinaryData *our_ratchet_key
) {
    int ret = 0;

    Skissm__AcceptRequest *request = NULL;
    Skissm__AcceptResponse *response = NULL;
    char *auth = NULL;

    if (!safe_e2ee_pack_id(e2ee_pack_id)) {
        ssm_notify_log(from, BAD_E2EE_PACK, "accept_internal()");
        ret = -1;
    }
    if (safe_address(from)) {
        get_skissm_plugin()->db_handler.load_auth(from, &auth);
        if (!nonempty_string(auth)) {
            ssm_notify_log(from, BAD_AUTH, "accept_internal()");
            ret = -1;
        }
    } else {
        ssm_notify_log(from, BAD_ADDRESS, "accept_internal()");
        ret = -1;
    }
    if (!safe_address(to)) {
        ssm_notify_log(from, BAD_ADDRESS, "accept_internal()");
        ret = -1;
    }
    if (!safe_protobuf(ciphertext_1)) {
        ssm_notify_log(from, BAD_INPUT_DATA, "accept_internal()");
        ret = -1;
    }
    if (!safe_protobuf(our_ratchet_key)) {
        ssm_notify_log(from, BAD_INPUT_DATA, "accept_internal()");
        ret = -1;
    }

    // ssm_notify_log(from, DEBUG_LOG, "accept_internal(): from [%s:%s] to [%s:%s]", from->user->user_id, from->user->device_id, to->user->user_id, to->user->device_id);
    if (ret == 0) {
        ret = produce_accept_request(&request, e2ee_pack_id, from, to, ciphertext_1, our_ratchet_key);
    }

    if (ret == 0) {
        response = get_skissm_plugin()->proto_handler.accept(from, auth, request);

        if (safe_accept_response(response)) {
            ret = consume_accept_response(from, response);
        } else {
            // pack request to request_data
            size_t request_data_len = skissm__accept_request__get_packed_size(request);
            uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
            skissm__accept_request__pack(request, request_data);

            store_pending_request_internal(from, SKISSM__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_ACCEPT, request_data, request_data_len, NULL, 0);
            // release
            free_mem((void *)&request_data, request_data_len);
        }

        // release
        free(auth);
        auth = NULL;
        skissm__accept_request__free_unpacked(request, NULL);
        request = NULL;
    }

    if (ret == 0) {
        *response_out = response;
    }

    // done
    return ret;
}

int publish_spk_internal(
    Skissm__PublishSpkResponse **response_out,
    Skissm__Account *account
) {
    int ret = 0;

    Skissm__PublishSpkRequest *request = NULL;
    Skissm__PublishSpkResponse *response = NULL;

    // ssm_notify_log(account->address, DEBUG_LOG, "publish_spk_internal(): user_address [%s:%s]", account->address->user->user_id, account->address->user->device_id);
    
    ret = produce_publish_spk_request(&request, account);

    if (ret == 0) {
        response = get_skissm_plugin()->proto_handler.publish_spk(account->address, account->auth, request);

        if (safe_publish_spk_response(response)) {
            ret = consume_publish_spk_response(account, response);

            if (ret == -1) {
                skissm__publish_spk_response__free_unpacked(response, NULL);
                response = NULL;
                // we do not store pending request here
                ssm_notify_log(account->address, DEBUG_LOG, "publish_spk_internal() failed, do it on next start");
            }
        } else {
            if (response != NULL) {
                skissm__publish_spk_response__free_unpacked(response, NULL);
                response = NULL;
            }
        }
    }

    // release
    if (request != NULL) {
        skissm__publish_spk_request__free_unpacked(request, NULL);
        request = NULL;
    }

    if (ret == 0) {
        *response_out = response;
    }

    // done
    return ret;
}

Skissm__SupplyOpksResponse *supply_opks_internal(Skissm__Account *account, uint32_t opks_num) {
    int ret = 0;

    Skissm__SupplyOpksRequest *request = NULL;

    if (opks_num != 0) {
        if (!safe_registered_account(account)) {
            ssm_notify_log(account->address, BAD_ACCOUNT, "supply_opks_internal()");
            ret = -1;
        }
    } else {
        ssm_notify_log(account->address, BAD_INPUT_DATA, "supply_opks_internal()");
        ret = -1;
    }

    if (ret == 0) {
        ret = produce_supply_opks_request(&request, account, opks_num);
    }

    Skissm__SupplyOpksResponse *response = get_skissm_plugin()->proto_handler.supply_opks(account->address, account->auth, request);
    bool succ = consume_supply_opks_response(account, opks_num, response);
    if (!succ) {
        // pack request to request_data
        size_t request_data_len = skissm__supply_opks_request__get_packed_size(request);
        uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
        skissm__supply_opks_request__pack(request, request_data);
        
        store_pending_request_internal(
            account->address, SKISSM__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_SUPPLY_OPKS, request_data, request_data_len, NULL, 0
        );
        //release
        free_mem((void *)&request_data, request_data_len);
    }

    // release
    skissm__supply_opks_request__free_unpacked(request, NULL);

    // done
    return response;
}

Skissm__SendOne2oneMsgResponse *send_one2one_msg_internal(
    Skissm__Session *outbound_session,
    uint32_t notif_level,
    const uint8_t *plaintext_data, size_t plaintext_data_len
) {
    int ret = 0;

    Skissm__SendOne2oneMsgRequest *request = NULL;

    Skissm__E2eeAddress *user_address = outbound_session->our_address;
    char *auth = NULL;
    get_skissm_plugin()->db_handler.load_auth(user_address, &auth);

    if (auth == NULL) {
        ssm_notify_log(outbound_session->our_address, BAD_AUTH, "send_one2one_msg_internal()");
        return NULL;
    }

    ret = produce_send_one2one_msg_request(&request, outbound_session, notif_level, plaintext_data, plaintext_data_len);
    Skissm__SendOne2oneMsgResponse *response = get_skissm_plugin()->proto_handler.send_one2one_msg(user_address, auth, request);
    bool succ = consume_send_one2one_msg_response(outbound_session, response);
    if (!succ) {
        // pack request to request_data
        size_t request_data_len = skissm__send_one2one_msg_request__get_packed_size(request);
        uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
        skissm__send_one2one_msg_request__pack(request, request_data);

        store_pending_request_internal(
            outbound_session->our_address, SKISSM__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_SEND_ONE2ONE_MSG,
            request_data, request_data_len, NULL, 0
        );

        //release
        free_mem((void *)&request_data, request_data_len);
        skissm__send_one2one_msg_response__free_unpacked(response, NULL);
        
        // replace response code to enable another try
        response = (Skissm__SendOne2oneMsgResponse *)malloc(sizeof(Skissm__SendOne2oneMsgResponse));
        skissm__send_one2one_msg_response__init(response);
        response->code = SKISSM__RESPONSE_CODE__RESPONSE_CODE_REQUEST_TIMEOUT;
    }

    // release
    free(auth);
    skissm__send_one2one_msg_request__free_unpacked(request, NULL);

    // done
    return response;
}

int add_group_member_device_internal(
    Skissm__AddGroupMemberDeviceResponse **response_out,
    Skissm__E2eeAddress *sender_address,
    Skissm__E2eeAddress *group_address,
    Skissm__E2eeAddress *new_device_address
) {
    int ret = 0;

    Skissm__AddGroupMemberDeviceRequest *request = NULL;
    Skissm__AddGroupMemberDeviceResponse *response = NULL;
    Skissm__GroupSession *outbound_group_session = NULL;
    char *auth = NULL;

    if (safe_address(sender_address)) {
        get_skissm_plugin()->db_handler.load_auth(sender_address, &auth);

        if (auth != NULL) {
            if (safe_address(group_address)) {
                get_skissm_plugin()->db_handler.load_group_session_by_address(
                    sender_address, sender_address, group_address, &outbound_group_session
                );

                if (outbound_group_session == NULL) {
                    ssm_notify_log(sender_address, BAD_GROUP_SESSION, "add_group_member_device_internal()");
                    ret = -1;
                }
            } else {
                ssm_notify_log(NULL, BAD_ADDRESS, "add_group_member_device_internal()");
                ret = -1;
            }
        } {
            ssm_notify_log(sender_address, BAD_AUTH, "add_group_member_device_internal()");
            ret = -1;
        }
    } else {
        ssm_notify_log(NULL, BAD_ADDRESS, "add_group_member_device_internal()");
        ret = -1;
    }
    if (!safe_address(new_device_address)) {
        ssm_notify_log(NULL, BAD_ADDRESS, "add_group_member_device_internal()");
        ret = -1;
    }

    if (ret == 0) {
        ret = produce_add_group_member_device_request(&request, outbound_group_session, new_device_address);
    }

    if (ret == 0) {
        response = get_skissm_plugin()->proto_handler.add_group_member_device(sender_address, auth, request);

        if (!safe_add_group_member_device_response(response)) {
            ssm_notify_log(NULL, BAD_RESPONSE, "add_group_member_device_internal()");
            ret = -1;
        }
    }

    if (ret == 0) {
        bool succ = consume_add_group_member_device_response(outbound_group_session, response);
        if (!succ) {
            // pack request to request_data
            size_t request_data_len = skissm__add_group_member_device_request__get_packed_size(request);
            uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
            skissm__add_group_member_device_request__pack(request, request_data);

            store_pending_request_internal(
                sender_address, SKISSM__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_ADD_GROUP_MEMBER_DEVICE,
                request_data, request_data_len, NULL, 0
            );
            // release
            free_mem((void *)&request_data, request_data_len);
        }

        *response_out = response;
    }

    // release
    if (auth != NULL) {
        free(auth);
        auth = NULL;
    }
    if (request != NULL) {
        skissm__add_group_member_device_request__free_unpacked(request, NULL);
        request = NULL;
    }
    if (outbound_group_session) {
        skissm__group_session__free_unpacked(outbound_group_session, NULL);
        outbound_group_session = NULL;
    }

    return ret;
}

void store_pending_common_plaintext_data_internal(
    Skissm__E2eeAddress *from,
    Skissm__E2eeAddress *to,
    uint8_t *common_plaintext_data,
    size_t common_plaintext_data_len,
    Skissm__NotifLevel notif_level
) {
    char *pending_plaintext_id = generate_uuid_str();
    get_skissm_plugin()->db_handler.store_pending_plaintext_data(
        from,
        to,
        pending_plaintext_id,
        common_plaintext_data,
        common_plaintext_data_len,
        notif_level
    );

    // release
    free(pending_plaintext_id);
}

void store_pending_request_internal(
    Skissm__E2eeAddress *user_address, Skissm__PendingRequestType type,
    uint8_t *request_data, size_t request_data_len,
    uint8_t *args_data, size_t args_data_len
) {
    Skissm__PendingRequest *pending_request = (Skissm__PendingRequest *)malloc(sizeof(Skissm__PendingRequest));
    skissm__pending_request__init(pending_request);
    // pending request type
    pending_request->type = type;
    // request_data
    copy_protobuf_from_array(&(pending_request->request_data), request_data, request_data_len);
    // args
    if (args_data && args_data_len > 0) {
        pending_request->n_request_arg_list = 1;
        pending_request->request_arg_list = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));
        init_protobuf(pending_request->request_arg_list);
        copy_protobuf_from_array(pending_request->request_arg_list, args_data, args_data_len);
    } else {
        pending_request->n_request_arg_list = 0;
    }

    // pack pending_request
    size_t pending_request_data_len = skissm__pending_request__get_packed_size(pending_request);
    uint8_t *pending_request_data = (uint8_t *)malloc(sizeof(uint8_t) * pending_request_data_len);
    skissm__pending_request__pack(pending_request, pending_request_data);

    char *pending_request_id = generate_uuid_str();
    get_skissm_plugin()->db_handler.store_pending_request_data(user_address, pending_request_id, type, pending_request_data, pending_request_data_len
    );
    // release
    skissm__pending_request__free_unpacked(pending_request, NULL);
    free_mem((void *)(&pending_request_data), pending_request_data_len);
    free(pending_request_id);
}

static void resend_pending_request(Skissm__Account *account) {
    Skissm__E2eeAddress *user_address = account->address;
    char *auth = account->auth;

    // load all pending request data
    char **pending_request_id_list;
    uint8_t *request_type_list;
    uint8_t **request_data_list;
    size_t *request_data_len_list;
    size_t pending_request_data_num =
        get_skissm_plugin()->db_handler.load_pending_request_data(
            user_address, &pending_request_id_list, &request_type_list, &request_data_list, &request_data_len_list
        );
    // send the pending request data
    bool succ = false;
    size_t i;
    for (i = 0; i < pending_request_data_num; i++) {
        Skissm__PendingRequest *pending_request = skissm__pending_request__unpack(NULL, request_data_len_list[i], request_data_list[i]);
        ssm_notify_log(
            user_address,
            DEBUG_LOG,
            "resend_pending_request() request_type: %d",
            request_type_list[i]
        );
        switch (request_type_list[i]) {
            case SKISSM__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_GET_PRE_KEY_BUNDLE: {
                int ret = 0;
                size_t their_device_num;
                Skissm__GetPreKeyBundleRequest *get_pre_key_bundle_request = skissm__get_pre_key_bundle_request__unpack(NULL, pending_request->request_data.len, pending_request->request_data.data);
                Skissm__GetPreKeyBundleResponse *get_pre_key_bundle_response = get_skissm_plugin()->proto_handler.get_pre_key_bundle(user_address, auth, get_pre_key_bundle_request);
                size_t i;
                // check if pre_key_bundles is empty
                if (!safe_get_pre_key_bundle_response(get_pre_key_bundle_response)) {
                    ret = -1;
                }
                if (ret == 0) {
                    their_device_num = get_pre_key_bundle_response->n_pre_key_bundles;
                    Skissm__InviteResponse **invite_response_list = NULL;
                    bool has_args = pending_request->n_request_arg_list == 1;
                    size_t group_pre_key_plaintext_data_len = has_args ? pending_request->request_arg_list[0].len : 0;
                    uint8_t *group_pre_key_plaintext_data = has_args ? pending_request->request_arg_list[0].data : NULL;
                    ret = consume_get_pre_key_bundle_response(
                        &invite_response_list,
                        user_address,
                        group_pre_key_plaintext_data,
                        group_pre_key_plaintext_data_len,
                        get_pre_key_bundle_response
                    );

                    // release
                    if (invite_response_list != NULL) {
                        for (i = 0; i < their_device_num; i++) {
                            if (invite_response_list[i] != NULL) {
                                skissm__invite_response__free_unpacked(invite_response_list[i], NULL);
                            }
                        }
                        free_mem((void **)&invite_response_list, sizeof(Skissm__InviteResponse *) * their_device_num);
                    }
                } else {
                    // if the get_pre_key_bundle_response code is no content, we will unload the pending request data
                    if (get_pre_key_bundle_response != NULL) {
                        if (get_pre_key_bundle_response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_NO_CONTENT) {
                            ssm_notify_log(
                                user_address,
                                DEBUG_LOG,
                                "consume_get_pre_key_bundle_response() got empty pre_key_bundles, remove pending request"
                            );
                            succ = true;
                        }
                    }
                }
                if (ret == 0) {
                    if (get_pre_key_bundle_request->active == true) {
                        their_device_num = get_pre_key_bundle_response->n_pre_key_bundles;
                        char **their_device_id = (char **)malloc(sizeof(char *) * their_device_num);
                        Skissm__PreKeyBundle *cur_pre_key_bundle = NULL;
                        for (i = 0; i < their_device_num; i++) {
                            cur_pre_key_bundle = get_pre_key_bundle_response->pre_key_bundles[i];
                            their_device_id[i] = strdup(cur_pre_key_bundle->user_address->user->device_id);
                        }
                        // send to other devices in order to create sessions
                        send_sync_invite_msg(
                            user_address,
                            get_pre_key_bundle_request->user_id,
                            get_pre_key_bundle_request->domain,
                            their_device_id,
                            their_device_num
                        );

                        // release
                        for (i = 0; i < their_device_num; i++) {
                            free(their_device_id[i]);
                        }
                        free_mem((void **)&their_device_id, sizeof(char *) * their_device_num);
                    }
                }
                
                if (ret == 0 || succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(user_address, pending_request_id_list[i]);
                } else {
                    ssm_notify_log(user_address, DEBUG_LOG, "handle pending get_pre_key_bundle_request failed");
                }
                skissm__get_pre_key_bundle_request__free_unpacked(get_pre_key_bundle_request, NULL);
                skissm__get_pre_key_bundle_response__free_unpacked(get_pre_key_bundle_response, NULL);
                break;
            } case SKISSM__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_INVITE: {
                Skissm__InviteRequest *invite_request = skissm__invite_request__unpack(NULL, pending_request->request_data.len, pending_request->request_data.data);
                Skissm__InviteResponse *invite_response = get_skissm_plugin()->proto_handler.invite(user_address, auth, invite_request);
                succ = consume_invite_response(user_address, invite_response);
                if (succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(user_address, pending_request_id_list[i]);
                } else {
                    ssm_notify_log(user_address, DEBUG_LOG, "handle pending invite_request failed");
                }
                skissm__invite_request__free_unpacked(invite_request, NULL);
                skissm__invite_response__free_unpacked(invite_response, NULL);
                break;
            }
            case SKISSM__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_ACCEPT: {
                Skissm__AcceptRequest *accept_request = skissm__accept_request__unpack(NULL, pending_request->request_data.len, pending_request->request_data.data);
                Skissm__AcceptResponse *accept_response = get_skissm_plugin()->proto_handler.accept(user_address, auth,  accept_request);
                succ = consume_accept_response(user_address, accept_response);
                if (succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(user_address, pending_request_id_list[i]);
                } else {
                    ssm_notify_log(user_address, DEBUG_LOG, "handle pending accept_request failed");
                }
                skissm__accept_request__free_unpacked(accept_request, NULL);
                skissm__accept_response__free_unpacked(accept_response, NULL);
                break;
            }
            case SKISSM__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_PUBLISH_SPK: {
                Skissm__PublishSpkRequest *publish_spk_request = skissm__publish_spk_request__unpack(NULL, pending_request->request_data.len, pending_request->request_data.data);
                Skissm__PublishSpkResponse *publish_spk_response = get_skissm_plugin()->proto_handler.publish_spk(user_address, auth, publish_spk_request);
                succ = consume_publish_spk_response(account, publish_spk_response);
                if (succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(user_address, pending_request_id_list[i]);
                } else {
                    ssm_notify_log(user_address, DEBUG_LOG, "handle pending publish_spk_request failed");
                }
                skissm__publish_spk_request__free_unpacked(publish_spk_request, NULL);
                skissm__publish_spk_response__free_unpacked(publish_spk_response, NULL);
                break;
            }
            case SKISSM__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_SUPPLY_OPKS: {
                Skissm__SupplyOpksRequest *supply_opks_request = skissm__supply_opks_request__unpack(NULL, pending_request->request_data.len, pending_request->request_data.data);
                Skissm__SupplyOpksResponse *supply_opks_response = get_skissm_plugin()->proto_handler.supply_opks(user_address, auth,  supply_opks_request);
                succ = consume_supply_opks_response(account, (uint32_t)supply_opks_request->n_one_time_pre_key_public_list, supply_opks_response);
                if (succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(user_address, pending_request_id_list[i]);
                } else {
                    ssm_notify_log(user_address, DEBUG_LOG, "handle pending supply_opks_request failed");
                }
                skissm__supply_opks_request__free_unpacked(supply_opks_request, NULL);
                skissm__supply_opks_response__free_unpacked(supply_opks_response, NULL);
                break;
            }
            case SKISSM__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_SEND_ONE2ONE_MSG: {
                Skissm__SendOne2oneMsgRequest *send_one2one_msg_request = skissm__send_one2one_msg_request__unpack(NULL, pending_request->request_data.len, pending_request->request_data.data);
                Skissm__SendOne2oneMsgResponse *send_one2one_msg_response = get_skissm_plugin()->proto_handler.send_one2one_msg(user_address, auth, send_one2one_msg_request);
                if (send_one2one_msg_response != NULL && send_one2one_msg_response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
                    succ = true;
                }
                if (succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(user_address, pending_request_id_list[i]);
                } else {
                    ssm_notify_log(user_address, DEBUG_LOG, "handle pending send_one2one_msg_request failed");
                }
                skissm__send_one2one_msg_request__free_unpacked(send_one2one_msg_request, NULL);
                skissm__send_one2one_msg_response__free_unpacked(send_one2one_msg_response, NULL);
                break;
            }
            case SKISSM__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_CREATE_GROUP: {
                Skissm__CreateGroupRequest *create_group_request = skissm__create_group_request__unpack(NULL, pending_request->request_data.len, pending_request->request_data.data);
                Skissm__CreateGroupResponse *create_group_response = get_skissm_plugin()->proto_handler.create_group(user_address, auth, create_group_request);
                succ = consume_create_group_response(
                    account->e2ee_pack_id,
                    user_address,
                    create_group_request->msg->group_info->group_name,
                    create_group_request->msg->group_info->group_member_list,
                    create_group_request->msg->group_info->n_group_member_list,
                    create_group_response
                );
                if (succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(user_address, pending_request_id_list[i]);
                } else {
                    ssm_notify_log(user_address, DEBUG_LOG, "handle pending create_group_request failed");
                }
                skissm__create_group_request__free_unpacked(create_group_request, NULL);
                skissm__create_group_response__free_unpacked(create_group_response, NULL);
                break;
            }
            case SKISSM__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_ADD_GROUP_MEMBERS: {
                Skissm__AddGroupMembersRequest *add_group_members_request = skissm__add_group_members_request__unpack(NULL, pending_request->request_data.len, pending_request->request_data.data);

                Skissm__AddGroupMembersMsg *add_group_members_msg = add_group_members_request->msg;
                Skissm__GroupSession *outbound_group_session_1 = NULL;
                get_skissm_plugin()->db_handler.load_group_session_by_address(
                    user_address, user_address, add_group_members_msg->group_info->group_address, &outbound_group_session_1
                );

                if (outbound_group_session_1 == NULL) {
                    succ = false;
                } else {
                    Skissm__AddGroupMembersResponse *add_group_members_response = get_skissm_plugin()->proto_handler.add_group_members(user_address, auth, add_group_members_request);

                    succ = consume_add_group_members_response(
                        outbound_group_session_1, add_group_members_response,
                        add_group_members_msg->adding_member_list, add_group_members_msg->n_adding_member_list
                    );

                    // release
                    skissm__add_group_members_response__free_unpacked(add_group_members_response, NULL);
                    skissm__group_session__free_unpacked(outbound_group_session_1, NULL);
                }
                if (succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(user_address, pending_request_id_list[i]);
                } else {
                    ssm_notify_log(user_address, DEBUG_LOG, "handle pending add_group_members_request failed");
                }
                // release
                skissm__add_group_members_request__free_unpacked(add_group_members_request, NULL);
                break;
            }
            case SKISSM__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_ADD_GROUP_MEMBER_DEVICE: {
                Skissm__AddGroupMemberDeviceRequest *add_group_member_device_request = skissm__add_group_member_device_request__unpack(NULL, pending_request->request_data.len, pending_request->request_data.data);

                Skissm__GroupSession *outbound_group_session_4 = NULL;
                get_skissm_plugin()->db_handler.load_group_session_by_address(
                    user_address, user_address, add_group_member_device_request->msg->group_info->group_address, &outbound_group_session_4
                );

                if (outbound_group_session_4 == NULL) {
                    succ = false;
                } else {
                    Skissm__AddGroupMemberDeviceResponse *add_group_member_device_response = get_skissm_plugin()->proto_handler.add_group_member_device(user_address, auth, add_group_member_device_request);

                    succ = consume_add_group_member_device_response(
                        outbound_group_session_4, add_group_member_device_response);

                    // release
                    skissm__add_group_member_device_response__free_unpacked(add_group_member_device_response, NULL);
                    skissm__group_session__free_unpacked(outbound_group_session_4, NULL);
                }
                if (succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(user_address, pending_request_id_list[i]);
                } else {
                    ssm_notify_log(user_address, DEBUG_LOG, "handle pending add_group_member_device_request failed");
                }
                // release
                skissm__add_group_member_device_request__free_unpacked(add_group_member_device_request, NULL);
                break;
            }
            case SKISSM__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_REMOVE_GROUP_MEMBERS: {
                Skissm__RemoveGroupMembersRequest *remove_group_members_request = skissm__remove_group_members_request__unpack(NULL, pending_request->request_data.len, pending_request->request_data.data);

                Skissm__RemoveGroupMembersMsg *remove_group_members_msg = remove_group_members_request->msg;
                Skissm__GroupSession *outbound_group_session_2 = NULL;
                get_skissm_plugin()->db_handler.load_group_session_by_address(
                    user_address, user_address,
                    remove_group_members_msg->group_info->group_address, &outbound_group_session_2
                );

                if (outbound_group_session_2 == NULL) {
                    succ = false;
                } else {
                    Skissm__RemoveGroupMembersResponse *remove_group_members_response = get_skissm_plugin()->proto_handler.remove_group_members(user_address, auth, remove_group_members_request);
                    succ = consume_remove_group_members_response(
                        outbound_group_session_2, remove_group_members_response,
                        remove_group_members_msg->removing_member_list, remove_group_members_msg->n_removing_member_list
                    );
                    // release
                    skissm__remove_group_members_response__free_unpacked(remove_group_members_response, NULL);
                    skissm__group_session__free_unpacked(outbound_group_session_2, NULL);
                }
                if (succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(user_address, pending_request_id_list[i]);
                } else {
                    ssm_notify_log(user_address, DEBUG_LOG, "handle pending remove_group_members_request failed");
                }
                // release
                skissm__remove_group_members_request__free_unpacked(remove_group_members_request, NULL);
                break;
            }
            case SKISSM__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_LEAVE_GROUP: {
                Skissm__LeaveGroupRequest *leave_group_request = skissm__leave_group_request__unpack(NULL, pending_request->request_data.len, pending_request->request_data.data);

                Skissm__LeaveGroupResponse *leave_group_response = get_skissm_plugin()->proto_handler.leave_group(user_address, auth, leave_group_request);
                succ = consume_leave_group_response(user_address, leave_group_response);
                // release
                skissm__leave_group_response__free_unpacked(leave_group_response, NULL);
                if (succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(user_address, pending_request_id_list[i]);
                } else {
                    ssm_notify_log(user_address, DEBUG_LOG, "handle pending leave_group_request failed");
                }
                // release
                skissm__leave_group_request__free_unpacked(leave_group_request, NULL);
                break;
            }
            case SKISSM__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_SEND_GROUP_MSG: {
                Skissm__SendGroupMsgRequest *send_group_msg_request = skissm__send_group_msg_request__unpack(NULL, pending_request->request_data.len, pending_request->request_data.data);

                Skissm__GroupSession *outbound_group_session_3 = NULL;
                get_skissm_plugin()->db_handler.load_group_session_by_address(user_address, user_address, send_group_msg_request->msg->to, &outbound_group_session_3);

                if (outbound_group_session_3 == NULL) {
                    succ = false;
                } else {
                    Skissm__SendGroupMsgResponse *send_group_msg_response = get_skissm_plugin()->proto_handler.send_group_msg(user_address, auth, send_group_msg_request);

                    succ = consume_send_group_msg_response(outbound_group_session_3, send_group_msg_response);
                    // release
                    skissm__send_group_msg_response__free_unpacked(send_group_msg_response, NULL);
                    skissm__group_session__free_unpacked(outbound_group_session_3, NULL);
                }
                if (succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(user_address, pending_request_id_list[i]);
                } else {
                    ssm_notify_log(user_address, DEBUG_LOG, "handle pending send_group_msg_request failed");
                }
                // release
                skissm__send_group_msg_request__free_unpacked(send_group_msg_request, NULL);
                break;
            } 
            case SKISSM__PENDING_REQUEST_TYPE__PENDING_REQUEST_TYPE_PROTO_MSG: {
                Skissm__ProtoMsg *proto_msg = skissm__proto_msg__unpack(NULL, pending_request->request_data.len, pending_request->request_data.data);
                Skissm__ConsumeProtoMsgResponse *consume_proto_msg_response = consume_proto_msg(proto_msg->to, proto_msg->tag->proto_msg_id);
                if (consume_proto_msg_response != NULL || consume_proto_msg_response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(user_address, pending_request_id_list[i]);
                }
                skissm__proto_msg__free_unpacked(proto_msg, NULL);
                skissm__consume_proto_msg_response__free_unpacked(consume_proto_msg_response, NULL);
                break;
            }
            default:
                ssm_notify_log(
                    user_address,
                    DEBUG_LOG,
                    "resend_pending_request() unknown pending request type: %d, %s",
                    request_type_list[i]
                );
                break;
        };
        // release
        skissm__pending_request__free_unpacked(pending_request, NULL);
        free(pending_request_id_list[i]);
        free_mem((void **)&(request_data_list[i]), request_data_len_list[i]);
    }

    // release
    if (pending_request_data_num > 0) {
        free_mem((void **)&pending_request_id_list, sizeof(char *) * pending_request_data_num);
        free_mem((void **)&request_type_list, sizeof(uint8_t) * pending_request_data_num);
        free_mem((void **)&request_data_list, sizeof(uint8_t *) * pending_request_data_num);
        free_mem((void **)&request_data_len_list, sizeof(size_t) * pending_request_data_num);
    }
}

void resume_connection_internal(Skissm__Account *account) {
    if (account == NULL)
        return;

    resend_pending_request(account);
}
