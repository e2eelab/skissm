#include <stdio.h>
#include <string.h>

#include "skissm.h"
#include "account.h"
#include "session.h"
#include "ratchet.h"
#include "error.h"
#include "mem_util.h"
#include "e2ee_protocol.h"
#include "group_session.h"

Skissm__GetPreKeyBundleRequestPayload *produce_get_pre_key_bundle_request_payload(Skissm__E2eeAddress *e2ee_address) {
        Skissm__GetPreKeyBundleRequestPayload *get_pre_key_bundle_request_payload =
        (Skissm__GetPreKeyBundleRequestPayload *)malloc(sizeof(Skissm__GetPreKeyBundleRequestPayload));
    skissm__get_pre_key_bundle_request_payload__init(get_pre_key_bundle_request_payload);
    copy_address_from_address(&(get_pre_key_bundle_request_payload->peer_address), e2ee_address);
    return get_pre_key_bundle_request_payload;
}

void consume_get_pre_key_bundle_response_payload(
    Skissm__E2eeAddress *from,
    Skissm__E2eeAddress *to,
    uint8_t *context,
    size_t context_len,
    Skissm__GetPreKeyBundleResponsePayload *get_pre_key_bundle_response_payload) {
    Skissm__E2eePreKeyBundle *their_pre_key_bundle = get_pre_key_bundle_response_payload->pre_key_bundle;

    Skissm__E2eeSession *session = (Skissm__E2eeSession *) malloc(sizeof(Skissm__E2eeSession));
    initialise_session(session, from, to);
    copy_address_from_address(&(session->session_owner), from);
    Skissm__E2eeAccount *local_account = get_local_account(from);
    new_outbound_session(session, local_account, their_pre_key_bundle);
    perform_encrypt_session(session, context, context_len);

    // release
    close_session(session);
}