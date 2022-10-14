#include "skissm/e2ee_client_internal.h"

#include <string.h>

#include "skissm/account_manager.h"
#include "skissm/group_session_manager.h"
#include "skissm/mem_util.h"
#include "skissm/session_manager.h"

Skissm__InviteResponse *get_pre_key_bundle_internal(
    Skissm__E2eeAddress *from, const char *to_user_id, const char *to_domain, const char *to_device_id,
    uint8_t *group_pre_key_plaintext_data, size_t group_pre_key_plaintext_data_len
) {
    Skissm__GetPreKeyBundleRequest *request = produce_get_pre_key_bundle_request(to_user_id, to_domain, to_device_id);
    Skissm__GetPreKeyBundleResponse *response = get_skissm_plugin()->proto_handler.get_pre_key_bundle(request);
    Skissm__InviteResponse *invite_response = consume_get_pre_key_bundle_response(
        from, group_pre_key_plaintext_data, group_pre_key_plaintext_data_len, response
    );

    // release
    skissm__get_pre_key_bundle_request__free_unpacked(request, NULL);
    if (response != NULL)
        skissm__get_pre_key_bundle_response__free_unpacked(response, NULL);
    // done
    return invite_response;
}

Skissm__InviteResponse *invite_internal(
    Skissm__Session *outbound_session,
    ProtobufCBinaryData **pre_shared_keys, size_t pre_shared_keys_num
) {
    Skissm__InviteRequest *request = produce_invite_request(outbound_session, pre_shared_keys, pre_shared_keys_num);
    Skissm__InviteResponse *response = get_skissm_plugin()->proto_handler.invite(request);
    bool succ = consume_invite_response(response);
    if (!succ) {
        // pack
        size_t request_data_len = skissm__invite_request__get_packed_size(request);
        uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
        skissm__invite_request__pack(request, request_data);
        // store
        char *pending_request_id = generate_uuid_str();
        get_skissm_plugin()->db_handler.store_pending_request_data(
            outbound_session->from, pending_request_id, INVITE_REQUEST, request_data, request_data_len
        );
        // release
        free(pending_request_id);
    }

    // release
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
    Skissm__AcceptRequest *request = produce_accept_request(e2ee_pack_id, from, to, ciphertext_1);
    Skissm__AcceptResponse *response = get_skissm_plugin()->proto_handler.accept(request);
    bool succ = consume_accept_response(response);
    if (!succ) {
        // pack
        size_t request_data_len = skissm__accept_request__get_packed_size(request);
        uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
        skissm__accept_request__pack(request, request_data);
        // store
        char *pending_request_id = generate_uuid_str();
        get_skissm_plugin()->db_handler.store_pending_request_data(
            from, pending_request_id, ACCEPT_REQUEST, request_data, request_data_len
        );
        // release
        free(pending_request_id);
    }
    // release
    skissm__accept_request__free_unpacked(request, NULL);

    // done
    return response;
}

Skissm__F2fInviteResponse *f2f_invite_internal(
    Skissm__E2eeAddress *from, Skissm__E2eeAddress *to,
    char *e2ee_pack_id,
    uint8_t *secret, size_t secret_len
) {
    Skissm__F2fInviteRequest *request = produce_f2f_invite_request(from, to, e2ee_pack_id, secret, secret_len);
    Skissm__F2fInviteResponse *response = get_skissm_plugin()->proto_handler.f2f_invite(request);
    consume_f2f_invite_response(request, response);

    // release
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
    Skissm__F2fAcceptRequest *request = produce_f2f_accept_request(e2ee_pack_id, from, to, local_account);
    Skissm__F2fAcceptResponse *response = get_skissm_plugin()->proto_handler.f2f_accept(request);
    consume_f2f_accept_response(response);

    // release
    skissm__f2f_accept_request__free_unpacked(request, NULL);

    // done
    return response;
}

Skissm__PublishSpkResponse *publish_spk_internal(Skissm__Account *account) {
    Skissm__PublishSpkRequest *request = produce_publish_spk_request(account);
    Skissm__PublishSpkResponse *response = get_skissm_plugin()->proto_handler.publish_spk(request);
    bool succ = consume_publish_spk_response(account, response);
    if (!succ) {
        // pack
        size_t request_data_len = skissm__publish_spk_request__get_packed_size(request);
        uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
        skissm__publish_spk_request__pack(request, request_data);
        // store
        char *pending_request_id = generate_uuid_str();
        get_skissm_plugin()->db_handler.store_pending_request_data(
            account->address, pending_request_id, PUBLISH_SPK_REQUEST, request_data, request_data_len
        );
        // release
        free(pending_request_id);
    }

    // release
    skissm__publish_spk_request__free_unpacked(request, NULL);

    // done
    return response;
}

Skissm__SupplyOpksResponse *supply_opks_internal(Skissm__Account *account, uint32_t opks_num) {
    Skissm__SupplyOpksRequest *request = produce_supply_opks_request(account, opks_num);
    Skissm__SupplyOpksResponse *response = get_skissm_plugin()->proto_handler.supply_opks(request);
    bool succ = consume_supply_opks_response(account, opks_num, response);
    if (!succ) {
        // pack
        size_t request_data_len = skissm__supply_opks_request__get_packed_size(request);
        uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
        skissm__supply_opks_request__pack(request, request_data);
        // store
        char *pending_request_id = generate_uuid_str();
        get_skissm_plugin()->db_handler.store_pending_request_data(
            account->address, pending_request_id, SUPPLY_OPKS_REQUEST, request_data, request_data_len
        );
        // release
        free(pending_request_id);
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
    Skissm__SendOne2oneMsgRequest *request = produce_send_one2one_msg_request(outbound_session, plaintext_data, plaintext_data_len);
    Skissm__SendOne2oneMsgResponse *response = get_skissm_plugin()->proto_handler.send_one2one_msg(request);
    bool succ = consume_send_one2one_msg_response(outbound_session, response);
    if (!succ) {
        // pack
        size_t request_data_len = skissm__send_one2one_msg_request__get_packed_size(request);
        uint8_t *request_data = (uint8_t *)malloc(sizeof(uint8_t) * request_data_len);
        skissm__send_one2one_msg_request__pack(request, request_data);
        // store
        char *pending_request_id = generate_uuid_str();
        get_skissm_plugin()->db_handler.store_pending_request_data(
            outbound_session->session_owner, pending_request_id, SEND_ONE2ONE_MSG_REQUEST, request_data, request_data_len
        );
        // release
        free(pending_request_id);
    }

    // release
    skissm__send_one2one_msg_request__free_unpacked(request, NULL);

    // done
    return response;
}

void resume_connection_internal(Skissm__Account *account) {
    // check if the account exists
    if (account == NULL) {
        return;
    }

    Skissm__E2eeAddress *address = account->address;
    // load all pending request data
    char **pending_request_id_list;
    uint8_t *request_type_list;
    uint8_t **request_data_list;
    size_t *request_data_len_list;
    size_t pending_request_data_num =
        get_skissm_plugin()->db_handler.load_pending_request_data(
            address, &pending_request_id_list, &request_type_list, &request_data_list, &request_data_len_list
        );
    // send the pending request data
    bool succ;
    size_t i;
    for (i = 0; i < pending_request_data_num; i++) {
        switch (request_type_list[i]) {
            case INVITE_REQUEST: {
                Skissm__InviteRequest *invite_request = skissm__invite_request__unpack(NULL, request_data_len_list[i], request_data_list[i]);
                Skissm__InviteResponse *invite_response = get_skissm_plugin()->proto_handler.invite(invite_request);
                succ = consume_invite_response(invite_response);
                if (succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(address, pending_request_id_list[i]);
                }
                skissm__invite_request__free_unpacked(invite_request, NULL);
                skissm__invite_response__free_unpacked(invite_response, NULL);
                break;
            }
            case ACCEPT_REQUEST: {
                Skissm__AcceptRequest *accept_request = skissm__accept_request__unpack(NULL, request_data_len_list[i], request_data_list[i]);
                Skissm__AcceptResponse *accept_response = get_skissm_plugin()->proto_handler.accept(accept_request);
                succ = consume_accept_response(accept_response);
                if (succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(address, pending_request_id_list[i]);
                }
                skissm__accept_request__free_unpacked(accept_request, NULL);
                skissm__accept_response__free_unpacked(accept_response, NULL);
                break;
            }
            case PUBLISH_SPK_REQUEST: {
                Skissm__PublishSpkRequest *publish_spk_request = skissm__publish_spk_request__unpack(NULL, request_data_len_list[i], request_data_list[i]);
                Skissm__PublishSpkResponse *publish_spk_response = get_skissm_plugin()->proto_handler.publish_spk(publish_spk_request);
                succ = consume_publish_spk_response(account, publish_spk_response);
                if (succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(address, pending_request_id_list[i]);
                }
                skissm__publish_spk_request__free_unpacked(publish_spk_request, NULL);
                skissm__publish_spk_response__free_unpacked(publish_spk_response, NULL);
                break;
            }
            case SUPPLY_OPKS_REQUEST: {
                Skissm__SupplyOpksRequest *supply_opks_request = skissm__supply_opks_request__unpack(NULL, request_data_len_list[i], request_data_list[i]);
                Skissm__SupplyOpksResponse *supply_opks_response = get_skissm_plugin()->proto_handler.supply_opks(supply_opks_request);
                succ = consume_supply_opks_response(account, (uint32_t)supply_opks_request->n_one_time_pre_key_public, supply_opks_response);
                if (succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(address, pending_request_id_list[i]);
                }
                skissm__supply_opks_request__free_unpacked(supply_opks_request, NULL);
                skissm__supply_opks_response__free_unpacked(supply_opks_response, NULL);
                break;
            }
            case SEND_ONE2ONE_MSG_REQUEST: {
                Skissm__SendOne2oneMsgRequest *send_one2one_msg_request = skissm__send_one2one_msg_request__unpack(NULL, request_data_len_list[i], request_data_list[i]);
                Skissm__SendOne2oneMsgResponse *send_one2one_msg_response = get_skissm_plugin()->proto_handler.send_one2one_msg(send_one2one_msg_request);
                Skissm__Session *outbound_session;
                get_skissm_plugin()->db_handler.load_outbound_session(send_one2one_msg_request->msg->from, send_one2one_msg_request->msg->to, &outbound_session);
                succ = consume_send_one2one_msg_response(outbound_session, send_one2one_msg_response);
                if (succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(address, pending_request_id_list[i]);
                }
                skissm__send_one2one_msg_request__free_unpacked(send_one2one_msg_request, NULL);
                skissm__send_one2one_msg_response__free_unpacked(send_one2one_msg_response, NULL);
                skissm__session__free_unpacked(outbound_session, NULL);
                break;
            }
            case CREATE_GROUP_REQUEST: {
                Skissm__CreateGroupRequest *create_group_request = skissm__create_group_request__unpack(NULL, request_data_len_list[i], request_data_list[i]);
                Skissm__CreateGroupResponse *create_group_response = get_skissm_plugin()->proto_handler.create_group(create_group_request);
                succ = consume_create_group_response(
                    account->e2ee_pack_id,
                    address,
                    create_group_request->msg->group_info->group_name,
                    create_group_request->msg->group_info->group_members,
                    create_group_request->msg->group_info->n_group_members,
                    create_group_response
                );
                if (succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(address, pending_request_id_list[i]);
                }
                skissm__create_group_request__free_unpacked(create_group_request, NULL);
                skissm__create_group_response__free_unpacked(create_group_response, NULL);
                break;
            }
            case ADD_GROUP_MEMBERS_REQUEST: {
                Skissm__AddGroupMembersRequest *add_group_members_request = skissm__add_group_members_request__unpack(NULL, request_data_len_list[i], request_data_list[i]);
                Skissm__AddGroupMembersResponse *add_group_members_response = get_skissm_plugin()->proto_handler.add_group_members(add_group_members_request);
                Skissm__GroupSession *outbound_group_session_1 = NULL;
                get_skissm_plugin()->db_handler.load_outbound_group_session(address, add_group_members_request->msg->group_address, &outbound_group_session_1);
                succ = consume_add_group_members_response(outbound_group_session_1, add_group_members_response);
                if (succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(address, pending_request_id_list[i]);
                }
                skissm__add_group_members_request__free_unpacked(add_group_members_request, NULL);
                skissm__add_group_members_response__free_unpacked(add_group_members_response, NULL);
                skissm__group_session__free_unpacked(outbound_group_session_1, NULL);
                break;
            }
            case REMOVE_GROUP_MEMBERS_REQUEST: {
                Skissm__RemoveGroupMembersRequest *remove_group_members_request = skissm__remove_group_members_request__unpack(NULL, request_data_len_list[i], request_data_list[i]);
                Skissm__RemoveGroupMembersResponse *remove_group_members_response = get_skissm_plugin()->proto_handler.remove_group_members(remove_group_members_request);
                Skissm__GroupSession *outbound_group_session_2 = NULL;
                get_skissm_plugin()->db_handler.load_outbound_group_session(address, remove_group_members_request->msg->group_address, &outbound_group_session_2);
                succ = consume_remove_group_members_response(outbound_group_session_2, remove_group_members_response);
                if (succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(address, pending_request_id_list[i]);
                }
                skissm__remove_group_members_request__free_unpacked(remove_group_members_request, NULL);
                skissm__remove_group_members_response__free_unpacked(remove_group_members_response, NULL);
                skissm__group_session__free_unpacked(outbound_group_session_2, NULL);
                break;
            }
            case SEND_GROUP_MSG_REQUEST: {
                Skissm__SendGroupMsgRequest *send_group_msg_request = skissm__send_group_msg_request__unpack(NULL, request_data_len_list[i], request_data_list[i]);
                Skissm__SendGroupMsgResponse *send_group_msg_response = get_skissm_plugin()->proto_handler.send_group_msg(send_group_msg_request);
                Skissm__GroupSession *outbound_group_session_3 = NULL;
                get_skissm_plugin()->db_handler.load_outbound_group_session(address, send_group_msg_request->msg->to, &outbound_group_session_3);
                succ = consume_send_group_msg_response(outbound_group_session_3, send_group_msg_response);
                if (succ) {
                    get_skissm_plugin()->db_handler.unload_pending_request_data(address, pending_request_id_list[i]);
                }
                skissm__send_group_msg_request__free_unpacked(send_group_msg_request, NULL);
                skissm__send_group_msg_response__free_unpacked(send_group_msg_response, NULL);
                skissm__group_session__free_unpacked(outbound_group_session_3, NULL);
                break;
            }
        
            default:
                break;
        };
        // release
        free(pending_request_id_list[i]);
        free_mem((void **)&(request_data_list[i]), request_data_len_list[i]);
    }

    // release
    if (pending_request_data_num > 0) {
        free_mem((void **)&pending_request_id_list, sizeof(char *) * pending_request_data_num);
        free_mem((void **)&request_type_list, sizeof(int) * pending_request_data_num);
        free_mem((void **)&request_data_list, sizeof(uint8_t *) * pending_request_data_num);
        free_mem((void **)&request_data_len_list, sizeof(size_t) * pending_request_data_num);
    }
}
