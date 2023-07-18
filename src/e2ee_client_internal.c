#include "skissm/e2ee_client_internal.h"

#include <string.h>

#include "skissm/account_manager.h"
#include "skissm/group_session_manager.h"
#include "skissm/mem_util.h"
#include "skissm/session_manager.h"

Skissm__InviteResponse *get_pre_key_bundle_internal(
    Skissm__E2eeAddress *from, const char *auth, const char *to_user_id, const char *to_domain, const char *to_device_id,
    uint8_t *group_pre_key_plaintext_data, size_t group_pre_key_plaintext_data_len
) {
    Skissm__GetPreKeyBundleRequest *request = produce_get_pre_key_bundle_request(to_user_id, to_domain, to_device_id);
    Skissm__GetPreKeyBundleResponse *response = get_skissm_plugin()->proto_handler.get_pre_key_bundle(from, auth, request);
    Skissm__InviteResponse *invite_response = consume_get_pre_key_bundle_response(
        from, group_pre_key_plaintext_data, group_pre_key_plaintext_data_len, response
    );

    if (invite_response == NULL || invite_response->code != SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK) {
        ssm_notify_log(from, DEBUG_LOG, "get_pre_key_bundle_internal() invite_response got error, pending request witll be stored.");
        // pack reuest to request_data which will be freeed inside store_pending_request_internal
        size_t request_data_len = skissm__get_pre_key_bundle_request__get_packed_size(request);
        uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
        skissm__get_pre_key_bundle_request__pack(request, request_data);

        store_pending_request_internal(from, SKISSM__PENDING_REQUEST_TYPE__GET_PRE_KEY_BUNDLE_REQUEST, request_data, request_data_len, group_pre_key_plaintext_data, group_pre_key_plaintext_data_len);
        //release
        free_mem((void *)&request_data, request_data_len);
    }

    // release
    skissm__get_pre_key_bundle_request__free_unpacked(request, NULL);
    if (response != NULL)
        skissm__get_pre_key_bundle_response__free_unpacked(response, NULL);

    // done
    return invite_response;
}

Skissm__InviteResponse *invite_internal(
    Skissm__Session *outbound_session
) {
    Skissm__Account *account = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(outbound_session->from, &account);
    if (account == NULL) {
        ssm_notify_log(outbound_session->session_owner, BAD_ACCOUNT, "invite_internal()");
        return NULL;
    }

    Skissm__InviteRequest *request = produce_invite_request(outbound_session);
    Skissm__InviteResponse *response = get_skissm_plugin()->proto_handler.invite(account->address, account->auth, request);
    bool succ = consume_invite_response(response);
    if (!succ) {
        // pack reuest to request_data
        size_t request_data_len = skissm__invite_request__get_packed_size(request);
        uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
        skissm__invite_request__pack(request, request_data);

        store_pending_request_internal(outbound_session->from, SKISSM__PENDING_REQUEST_TYPE__INVITE_REQUEST, request_data, request_data_len, NULL, 0);
        //release
        free_mem((void *)&request_data, request_data_len);
    }

    // release
    skissm__account__free_unpacked(account, NULL);
    skissm__invite_request__free_unpacked(request, NULL);

    // done
    return response;
}

Skissm__AcceptResponse *accept_internal(
    const char *e2ee_pack_id,
    Skissm__E2eeAddress *from,
    Skissm__E2eeAddress *to,
    ProtobufCBinaryData *ciphertext_1
) {
    ssm_notify_log(from, DEBUG_LOG, "accept_internal(): from [%s:%s] to [%s:%s]", from->user->user_id, from->user->device_id, to->user->user_id, to->user->device_id);
    
    Skissm__Account *account = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(from, &account);
    if (account == NULL) {
        ssm_notify_log(from, BAD_ACCOUNT, "accept_internal()");
        return NULL;
    }

    Skissm__AcceptRequest *request = produce_accept_request(e2ee_pack_id, from, to, ciphertext_1);
    Skissm__AcceptResponse *response = get_skissm_plugin()->proto_handler.accept(account->address, account->auth, request);
    bool succ = consume_accept_response(response);
    if (!succ) {
        // pack reuest to request_data
        size_t request_data_len = skissm__accept_request__get_packed_size(request);
        uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
        skissm__accept_request__pack(request, request_data);
        
        store_pending_request_internal(from, SKISSM__PENDING_REQUEST_TYPE__ACCEPT_REQUEST, request_data, request_data_len, NULL, 0);
        //release
        free_mem((void *)&request_data, request_data_len);
    }
    // release
    skissm__account__free_unpacked(account, NULL);
    skissm__accept_request__free_unpacked(request, NULL);

    // done
    return response;
}

Skissm__F2fInviteResponse *f2f_invite_internal(
    Skissm__E2eeAddress *from, Skissm__E2eeAddress *to,
    char *e2ee_pack_id,
    uint8_t *secret, size_t secret_len
) {
    ssm_notify_log(from, DEBUG_LOG, "f2f_invite_internal(): from [%s:%s] to [%s:%s]", from->user->user_id, from->user->device_id, to->user->user_id, to->user->device_id);
    
    Skissm__Account *account = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(from, &account);
    if (account == NULL) {
        ssm_notify_log(from, BAD_ACCOUNT, "f2f_invite_internal()");
        return NULL;
    }

    Skissm__F2fInviteRequest *request = produce_f2f_invite_request(from, to, e2ee_pack_id, secret, secret_len);
    Skissm__F2fInviteResponse *response = get_skissm_plugin()->proto_handler.f2f_invite(account->address, account->auth, request);
    consume_f2f_invite_response(request, response);

    // release
    skissm__account__free_unpacked(account, NULL);
    skissm__f2f_invite_request__free_unpacked(request, NULL);

    // done
    return response;
}

Skissm__F2fAcceptResponse *f2f_accept_internal(
    const char *e2ee_pack_id,
    Skissm__E2eeAddress *from,
    Skissm__E2eeAddress *to,
    Skissm__Account *local_account
) {
    ssm_notify_log(from, DEBUG_LOG, "f2f_accept_internal(): from [%s:%s] to [%s:%s]", from->user->user_id, from->user->device_id, to->user->user_id, to->user->device_id);
    
    Skissm__Account *account = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(from, &account);
    if (account == NULL) {
        ssm_notify_log(from, BAD_ACCOUNT, "f2f_accept_internal()");
        return NULL;
    }

    Skissm__F2fAcceptRequest *request = produce_f2f_accept_request(e2ee_pack_id, from, to, local_account);
    Skissm__F2fAcceptResponse *response = get_skissm_plugin()->proto_handler.f2f_accept(account->address, account->auth, request);
    consume_f2f_accept_response(response);

    // release
    skissm__account__free_unpacked(account, NULL);
    skissm__f2f_accept_request__free_unpacked(request, NULL);

    // done
    return response;
}

Skissm__PublishSpkResponse *publish_spk_internal(Skissm__Account *account) {
    ssm_notify_log(account->address, DEBUG_LOG, "publish_spk_internal(): user_address [%s:%s]", account->address->user->user_id, account->address->user->device_id);
    
    Skissm__PublishSpkRequest *request = produce_publish_spk_request(account);
    Skissm__PublishSpkResponse *response = get_skissm_plugin()->proto_handler.publish_spk(account->address, account->auth, request);
    bool succ = consume_publish_spk_response(account, response);
    if (!succ) {
        // pack reuest to request_data
        size_t request_data_len = skissm__publish_spk_request__get_packed_size(request);
        uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
        skissm__publish_spk_request__pack(request, request_data);

        store_pending_request_internal(account->address, SKISSM__PENDING_REQUEST_TYPE__PUBLISH_SPK_REQUEST, request_data, request_data_len, NULL, 0);
        //release
        free_mem((void *)&request_data, request_data_len);
    }

    // release
    skissm__publish_spk_request__free_unpacked(request, NULL);

    // done
    return response;
}

Skissm__SupplyOpksResponse *supply_opks_internal(Skissm__Account *account, uint32_t opks_num) {
    Skissm__SupplyOpksRequest *request = produce_supply_opks_request(account, opks_num);
    Skissm__SupplyOpksResponse *response = get_skissm_plugin()->proto_handler.supply_opks(account->address, account->auth, request);
    bool succ = consume_supply_opks_response(account, opks_num, response);
    if (!succ) {
        // pack reuest to request_data
        size_t request_data_len = skissm__supply_opks_request__get_packed_size(request);
        uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
        skissm__supply_opks_request__pack(request, request_data);
        
        store_pending_request_internal(account->address, SKISSM__PENDING_REQUEST_TYPE__SUPPLY_OPKS_REQUEST, request_data, request_data_len, NULL, 0);
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
    const uint8_t *plaintext_data, size_t plaintext_data_len
) {
    Skissm__Account *account = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(outbound_session->from, &account);
    if (account == NULL) {
        ssm_notify_log(outbound_session->session_owner, BAD_ACCOUNT, "send_one2one_msg_internal()");
        return NULL;
    }

    Skissm__SendOne2oneMsgRequest *request = produce_send_one2one_msg_request(outbound_session, plaintext_data, plaintext_data_len);
    Skissm__SendOne2oneMsgResponse *response = get_skissm_plugin()->proto_handler.send_one2one_msg(account->address, account->auth, request);
    bool succ = consume_send_one2one_msg_response(outbound_session, response);
    if (!succ) {
        // pack reuest to request_data
        size_t request_data_len = skissm__send_one2one_msg_request__get_packed_size(request);
        uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
        skissm__send_one2one_msg_request__pack(request, request_data);

        store_pending_request_internal(outbound_session->session_owner, SKISSM__PENDING_REQUEST_TYPE__SEND_ONE2ONE_MSG_REQUEST, request_data, request_data_len, NULL, 0);
        //release
        free_mem((void *)&request_data, request_data_len);
    }

    // release
    skissm__account__free_unpacked(account, NULL);
    skissm__send_one2one_msg_request__free_unpacked(request, NULL);

    // done
    return response;
}

void store_pending_request_internal(Skissm__E2eeAddress *user_address, Skissm__PendingRequestType type, uint8_t *request_data, size_t request_data_len, uint8_t *args_data, size_t args_data_len) {
    Skissm__PendingRequest *pending_request = (Skissm__PendingRequest*)malloc(sizeof(Skissm__PendingRequest));
    skissm__pending_request__init(pending_request);
    // pending request type
    pending_request->type = type;
    // request_data
    copy_protobuf_from_array(&(pending_request->request_data), request_data, request_data_len);
    // args
    if (args_data && args_data_len > 0) {
        pending_request->n_request_args = 1;
        pending_request->request_args = (ProtobufCBinaryData *)malloc(sizeof(ProtobufCBinaryData));
        copy_protobuf_from_array(pending_request->request_args, args_data, args_data_len);
    } else {
        pending_request->n_request_args = 0;
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
    bool succ;
    size_t i;
    for (i = 0; i < pending_request_data_num; i++) {
        Skissm__PendingRequest *pending_request = skissm__pending_request__unpack(NULL, request_data_len_list[i], request_data_list[i]);
        switch (request_type_list[i]) {
            case SKISSM__PENDING_REQUEST_TYPE__GET_PRE_KEY_BUNDLE_REQUEST: {
                Skissm__GetPreKeyBundleRequest *get_pre_key_bundle_request = skissm__get_pre_key_bundle_request__unpack(NULL, pending_request->request_data.len, pending_request->request_data.data);
                Skissm__GetPreKeyBundleResponse *get_pre_key_bundle_response = get_skissm_plugin()->proto_handler.get_pre_key_bundle(user_address, auth, get_pre_key_bundle_request);
                bool has_args = pending_request->n_request_args == 1;
                size_t group_pre_key_plaintext_data_len = has_args ? pending_request->request_args[0].len : 0;
                uint8_t *group_pre_key_plaintext_data = has_args ? pending_request->request_args[0].data : NULL;
                Skissm__InviteResponse *invite_response = consume_get_pre_key_bundle_response(user_address, group_pre_key_plaintext_data, group_pre_key_plaintext_data_len, get_pre_key_bundle_response
                );
                succ = (invite_response != NULL && invite_response->code == SKISSM__RESPONSE_CODE__RESPONSE_CODE_OK);
                if (succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(user_address, pending_request_id_list[i]);
                }
                skissm__get_pre_key_bundle_request__free_unpacked(get_pre_key_bundle_request, NULL);
                skissm__get_pre_key_bundle_response__free_unpacked(get_pre_key_bundle_response, NULL);
                skissm__invite_response__free_unpacked(invite_response, NULL);
                break;
            } case SKISSM__PENDING_REQUEST_TYPE__INVITE_REQUEST: {
                Skissm__InviteRequest *invite_request = skissm__invite_request__unpack(NULL, pending_request->request_data.len, pending_request->request_data.data);
                Skissm__InviteResponse *invite_response = get_skissm_plugin()->proto_handler.invite(user_address, auth, invite_request);
                succ = consume_invite_response(invite_response);
                if (succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(user_address, pending_request_id_list[i]);
                }
                skissm__invite_request__free_unpacked(invite_request, NULL);
                skissm__invite_response__free_unpacked(invite_response, NULL);
                break;
            }
            case SKISSM__PENDING_REQUEST_TYPE__ACCEPT_REQUEST: {
                Skissm__AcceptRequest *accept_request = skissm__accept_request__unpack(NULL, pending_request->request_data.len, pending_request->request_data.data);
                Skissm__AcceptResponse *accept_response = get_skissm_plugin()->proto_handler.accept(user_address, auth,  accept_request);
                succ = consume_accept_response(accept_response);
                if (succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(user_address, pending_request_id_list[i]);
                }
                skissm__accept_request__free_unpacked(accept_request, NULL);
                skissm__accept_response__free_unpacked(accept_response, NULL);
                break;
            }
            case SKISSM__PENDING_REQUEST_TYPE__PUBLISH_SPK_REQUEST: {
                Skissm__PublishSpkRequest *publish_spk_request = skissm__publish_spk_request__unpack(NULL, pending_request->request_data.len, pending_request->request_data.data);
                Skissm__PublishSpkResponse *publish_spk_response = get_skissm_plugin()->proto_handler.publish_spk(user_address, auth, publish_spk_request);
                succ = consume_publish_spk_response(account, publish_spk_response);
                if (succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(user_address, pending_request_id_list[i]);
                }
                skissm__publish_spk_request__free_unpacked(publish_spk_request, NULL);
                skissm__publish_spk_response__free_unpacked(publish_spk_response, NULL);
                break;
            }
            case SKISSM__PENDING_REQUEST_TYPE__SUPPLY_OPKS_REQUEST: {
                Skissm__SupplyOpksRequest *supply_opks_request = skissm__supply_opks_request__unpack(NULL, pending_request->request_data.len, pending_request->request_data.data);
                Skissm__SupplyOpksResponse *supply_opks_response = get_skissm_plugin()->proto_handler.supply_opks(user_address, auth,  supply_opks_request);
                succ = consume_supply_opks_response(account, (uint32_t)supply_opks_request->n_one_time_pre_key_public, supply_opks_response);
                if (succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(user_address, pending_request_id_list[i]);
                }
                skissm__supply_opks_request__free_unpacked(supply_opks_request, NULL);
                skissm__supply_opks_response__free_unpacked(supply_opks_response, NULL);
                break;
            }
            case SKISSM__PENDING_REQUEST_TYPE__SEND_ONE2ONE_MSG_REQUEST: {
                Skissm__SendOne2oneMsgRequest *send_one2one_msg_request = skissm__send_one2one_msg_request__unpack(NULL, pending_request->request_data.len, pending_request->request_data.data);
                Skissm__SendOne2oneMsgResponse *send_one2one_msg_response = get_skissm_plugin()->proto_handler.send_one2one_msg(user_address, auth, send_one2one_msg_request);
                Skissm__Session *outbound_session;
                get_skissm_plugin()->db_handler.load_outbound_session(send_one2one_msg_request->msg->from, send_one2one_msg_request->msg->to, &outbound_session);
                succ = consume_send_one2one_msg_response(outbound_session, send_one2one_msg_response);
                if (succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(user_address, pending_request_id_list[i]);
                }
                skissm__send_one2one_msg_request__free_unpacked(send_one2one_msg_request, NULL);
                skissm__send_one2one_msg_response__free_unpacked(send_one2one_msg_response, NULL);
                skissm__session__free_unpacked(outbound_session, NULL);
                break;
            }
            case SKISSM__PENDING_REQUEST_TYPE__CREATE_GROUP_REQUEST: {
                Skissm__CreateGroupRequest *create_group_request = skissm__create_group_request__unpack(NULL, pending_request->request_data.len, pending_request->request_data.data);
                Skissm__CreateGroupResponse *create_group_response = get_skissm_plugin()->proto_handler.create_group(user_address, auth, create_group_request);
                succ = consume_create_group_response(
                    account->e2ee_pack_id,
                    user_address,
                    create_group_request->msg->group_info->group_name,
                    create_group_request->msg->group_info->group_members,
                    create_group_request->msg->group_info->n_group_members,
                    create_group_response
                );
                if (succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(user_address, pending_request_id_list[i]);
                }
                skissm__create_group_request__free_unpacked(create_group_request, NULL);
                skissm__create_group_response__free_unpacked(create_group_response, NULL);
                break;
            }
            case SKISSM__PENDING_REQUEST_TYPE__ADD_GROUP_MEMBERS_REQUEST: {
                Skissm__AddGroupMembersRequest *add_group_members_request = skissm__add_group_members_request__unpack(NULL, pending_request->request_data.len, pending_request->request_data.data);
                Skissm__AddGroupMembersResponse *add_group_members_response = get_skissm_plugin()->proto_handler.add_group_members(user_address, auth, add_group_members_request);
                Skissm__GroupSession *outbound_group_session_1 = NULL;
                get_skissm_plugin()->db_handler.load_group_session_by_address(user_address, user_address, add_group_members_request->msg->group_info->group_address, &outbound_group_session_1);
                succ = consume_add_group_members_response(outbound_group_session_1, add_group_members_response, add_group_members_request->msg->adding_members, add_group_members_request->msg->n_adding_members);
                if (succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(user_address, pending_request_id_list[i]);
                }
                skissm__add_group_members_request__free_unpacked(add_group_members_request, NULL);
                skissm__add_group_members_response__free_unpacked(add_group_members_response, NULL);
                skissm__group_session__free_unpacked(outbound_group_session_1, NULL);
                break;
            }
            case SKISSM__PENDING_REQUEST_TYPE__REMOVE_GROUP_MEMBERS_REQUEST: {
                Skissm__RemoveGroupMembersRequest *remove_group_members_request = skissm__remove_group_members_request__unpack(NULL, pending_request->request_data.len, pending_request->request_data.data);
                Skissm__RemoveGroupMembersResponse *remove_group_members_response = get_skissm_plugin()->proto_handler.remove_group_members(user_address, auth, remove_group_members_request);
                Skissm__GroupSession *outbound_group_session_2 = NULL;
                get_skissm_plugin()->db_handler.load_group_session_by_address(user_address, user_address, remove_group_members_request->msg->group_info->group_address, &outbound_group_session_2);
                succ = consume_remove_group_members_response(outbound_group_session_2, remove_group_members_response, remove_group_members_request->msg->removing_members, remove_group_members_request->msg->n_removing_members);
                if (succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(user_address, pending_request_id_list[i]);
                }
                skissm__remove_group_members_request__free_unpacked(remove_group_members_request, NULL);
                skissm__remove_group_members_response__free_unpacked(remove_group_members_response, NULL);
                skissm__group_session__free_unpacked(outbound_group_session_2, NULL);
                break;
            }
            case SKISSM__PENDING_REQUEST_TYPE__SEND_GROUP_MSG_REQUEST: {
                Skissm__SendGroupMsgRequest *send_group_msg_request = skissm__send_group_msg_request__unpack(NULL, pending_request->request_data.len, pending_request->request_data.data);
                Skissm__SendGroupMsgResponse *send_group_msg_response = get_skissm_plugin()->proto_handler.send_group_msg(user_address, auth, send_group_msg_request);
                Skissm__GroupSession *outbound_group_session_3 = NULL;
                get_skissm_plugin()->db_handler.load_group_session_by_address(user_address, user_address, send_group_msg_request->msg->to, &outbound_group_session_3);
                succ = consume_send_group_msg_response(outbound_group_session_3, send_group_msg_response);
                if (succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(user_address, pending_request_id_list[i]);
                }
                skissm__send_group_msg_request__free_unpacked(send_group_msg_request, NULL);
                skissm__send_group_msg_response__free_unpacked(send_group_msg_response, NULL);
                skissm__group_session__free_unpacked(outbound_group_session_3, NULL);
                break;
            }
            default:
                ssm_notify_log(user_address, DEBUG_LOG, "resend_pending_request() unknown pending request type: %d, %s", request_type_list[i]);
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
