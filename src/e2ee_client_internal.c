#include "skissm/e2ee_client_internal.h"

#include <string.h>

#include "skissm/account_manager.h"
#include "skissm/session_manager.h"

Skissm__InviteResponse *get_pre_key_bundle_internal(Skissm__E2eeAddress *from, Skissm__E2eeAddress *to) {
    Skissm__GetPreKeyBundleRequest *request = produce_get_pre_key_bundle_request(to);
    Skissm__GetPreKeyBundleResponse *response = get_skissm_plugin()->proto_handler.get_pre_key_bundle(request);
    Skissm__InviteResponse *invite_response = consume_get_pre_key_bundle_response(from, to, response);

    // release
    skissm__get_pre_key_bundle_request__free_unpacked(request, NULL);
    if (response != NULL)
        skissm__get_pre_key_bundle_response__free_unpacked(response, NULL);
    // done
    return invite_response;
}

Skissm__InviteResponse *invite_internal(Skissm__Session *outbound_session, ProtobufCBinaryData **pre_shared_keys, size_t pre_shared_keys_len) {
    Skissm__InviteRequest *request = produce_invite_request(outbound_session, pre_shared_keys, pre_shared_keys_len);
    Skissm__InviteResponse *response = get_skissm_plugin()->proto_handler.invite(request);
    consume_invite_response(response);

    // release
    skissm__invite_request__free_unpacked(request, NULL);

    // done
    return response;
}

Skissm__AcceptResponse *accept_internal(const char *e2ee_pack_id, Skissm__E2eeAddress *from, Skissm__E2eeAddress *to, ProtobufCBinaryData *ciphertext_1) {
    Skissm__AcceptRequest *request = produce_accept_request(e2ee_pack_id, from, to, ciphertext_1);
    Skissm__AcceptResponse *response = get_skissm_plugin()->proto_handler.accept(request);
    consume_accept_response(response);

    // release
    skissm__accept_request__free_unpacked(request, NULL);

    // done
    return response;
}

Skissm__F2fInviteResponse *f2f_invite_internal(
    Skissm__E2eeAddress *from, Skissm__E2eeAddress *to,
    uint8_t *secret, size_t secret_len
) {
    Skissm__F2fInviteRequest *request = produce_f2f_invite_request(from, to, secret, secret_len);
    Skissm__F2fInviteResponse *response = get_skissm_plugin()->proto_handler.f2f_invite(request);
    consume_f2f_invite_response(response);

    // release
    skissm__f2f_invite_request__free_unpacked(request, NULL);

    // done
    return response;
}

Skissm__F2fAcceptResponse *f2f_accept_internal(const char *e2ee_pack_id, Skissm__E2eeAddress *from, Skissm__E2eeAddress *to, Skissm__Account *local_account) {
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
    consume_publish_spk_response(account, response);

    // release
    skissm__publish_spk_request__free_unpacked(request, NULL);

    // done
    return response;
}

Skissm__SupplyOpksResponse *supply_opks_internal(Skissm__Account *account, uint32_t opks_num) {
    Skissm__SupplyOpksRequest *request = produce_supply_opks_request(account, opks_num);
    Skissm__SupplyOpksResponse *response = get_skissm_plugin()->proto_handler.supply_opks(request);
    consume_supply_opks_response(account, opks_num, response);

    // release
    skissm__supply_opks_request__free_unpacked(request, NULL);

    // done
    return response;
}

Skissm__SendOne2oneMsgResponse *send_one2one_msg_internal(Skissm__Session *outbound_session, const uint8_t *plaintext_data, size_t plaintext_data_len) {
    Skissm__SendOne2oneMsgRequest *request = produce_send_one2one_msg_request(outbound_session, plaintext_data, plaintext_data_len);
    Skissm__SendOne2oneMsgResponse *response = get_skissm_plugin()->proto_handler.send_one2one_msg(request);
    consume_send_one2one_msg_response(outbound_session, response);

    // release
    skissm__send_one2one_msg_request__free_unpacked(request, NULL);

    // done
    return response;
}

