#include "skissm/e2ee_client_internal.h"

#include <string.h>

#include "skissm/account_manager.h"
#include "skissm/session_manager.h"

size_t get_pre_key_bundle_internal(Skissm__E2eeAddress *from, Skissm__E2eeAddress *to) {
    Skissm__GetPreKeyBundleRequest *request = produce_get_pre_key_bundle_request(to);

    Skissm__GetPreKeyBundleResponse *response = get_skissm_plugin()->proto_handler.get_pre_key_bundle(request);
    size_t result;
    if (response != NULL) {
        consume_get_pre_key_bundle_response(from, to, response);
        // release
        skissm__get_pre_key_bundle_response__free_unpacked(response, NULL);
        result = (size_t)(0);
    } else {
        result = (size_t)(-1);
    }

    // release
    skissm__get_pre_key_bundle_request__free_unpacked(request, NULL);

    // done
    return result;
}

size_t invite_internal(Skissm__Session *outbound_session, ProtobufCBinaryData **pre_shared_keys, size_t pre_shared_keys_len) {
    Skissm__InviteRequest *request = produce_invite_request(
    outbound_session, pre_shared_keys, pre_shared_keys_len);

    Skissm__InviteResponse *response = get_skissm_plugin()->proto_handler.invite(request);
    size_t result;
    if (response != NULL) {
        consume_invite_response(response);
        // release
        skissm__invite_response__free_unpacked(response, NULL);
        result = (size_t)(0);
    } else {
        result = (size_t)(-1);
    }

    // release
    skissm__invite_request__free_unpacked(request, NULL);

    // done
    return result;
}

size_t accept_internal(const char *e2ee_pack_id, Skissm__E2eeAddress *from, Skissm__E2eeAddress *to, ProtobufCBinaryData *ciphertext_1) {
    Skissm__AcceptRequest *request = produce_accept_request(e2ee_pack_id, ciphertext_1);
    Skissm__AcceptResponse *response = get_skissm_plugin()->proto_handler.accept(request);
    size_t result;
    if (response != NULL) {
        consume_accept_response(response);
        // release
        skissm__accept_response__free_unpacked(response, NULL);
        result = (size_t)(0);
    } else {
        result = (size_t)(-1);
    }

    // release
    skissm__accept_request__free_unpacked(request, NULL);

    // done
    return result;
}

size_t publish_spk_internal(Skissm__Account *account) {
    Skissm__PublishSpkRequest *request = produce_publish_spk_request(account);

    Skissm__PublishSpkResponse *response = get_skissm_plugin()->proto_handler.publish_spk(request);
    size_t result;
    if (response != NULL) {
        consume_publish_spk_response(account, response);
        // release
        skissm__publish_spk_response__free_unpacked(response, NULL);
        result = (size_t)(0);
    } else {
        result = (size_t)(-1);
    }

    // release
    skissm__publish_spk_request__free_unpacked(request, NULL);

    // done
    return result;
}

size_t supply_opks_internal(Skissm__Account *account, uint32_t opks_num) {
    Skissm__SupplyOpksRequest *request = produce_supply_opks_request(account, opks_num);

    Skissm__SupplyOpksResponse *response = get_skissm_plugin()->proto_handler.supply_opks(request);
    size_t result;
    if (response != NULL) {
        consume_supply_opks_response(account, response);
        // release
        skissm__supply_opks_response__free_unpacked(response, NULL);
        result = (size_t)(0);
    } else {
        result = (size_t)(-1);
    }

    // release
    skissm__supply_opks_request__free_unpacked(request, NULL);

    // done
    return result;
}

size_t send_one2one_msg_internal(Skissm__Session *outbound_session, const uint8_t *plaintext_data, size_t plaintext_data_len) {
    Skissm__SendOne2oneMsgRequest *request = produce_send_one2one_msg_request(outbound_session, plaintext_data, plaintext_data_len);

    Skissm__SendOne2oneMsgResponse *response = get_skissm_plugin()->proto_handler.send_one2one_msg(request);
    size_t result;
    if (response != NULL) {
        consume_send_one2one_msg_response(outbound_session, response);
        // release
        skissm__send_one2one_msg_response__free_unpacked(response, NULL);
        result = (size_t)(0);
    } else {
        result = (size_t)(-1);
    }

    // release
    skissm__send_one2one_msg_request__free_unpacked(request, NULL);
    skissm__session__free_unpacked(outbound_session, NULL);

    // done
    return result;
}

size_t consume_proto_msg_internal(char *proto_msg_id) {
    Skissm__ConsumeProtoMsgRequest *request = (Skissm__ConsumeProtoMsgRequest*)malloc(sizeof(Skissm__ConsumeProtoMsgRequest));
    skissm__consume_proto_msg_request__init(request);
    request->proto_msg_id = strdup(proto_msg_id);

    Skissm__ConsumeProtoMsgResponse *response = get_skissm_plugin()->proto_handler.consume_proto_msg(request);
    size_t result;
    if (response != NULL) {
        // release
        skissm__consume_proto_msg_response__free_unpacked(response, NULL);
        result = (size_t)(0);
    } else {
        // TODO: what if error happened
        result = (size_t)(-1);
    }

    // release
    skissm__consume_proto_msg_request__free_unpacked(request, NULL);

    // done
    return result;
}
