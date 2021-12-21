/*
 * Copyright © 2020-2021 by Academia Sinica
 *
 * This file is part of SKISSM.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * SKISSM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with SKISSM.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "skissm/account_manager.h"

#include "skissm/account.h"
#include "skissm/e2ee_protocol.h"
#include "skissm/mem_util.h"

/* registration related */
static void handle_register_release(register_user_response_handler *response_handler) {
    // skissm__e2ee_account__free_unpacked(response_handler->account, NULL);
    // response_handler->account = NULL;
}

register_user_response_handler register_user_response_handler_store = {
    NULL,
    handle_register_release
};

/* spk related */
static void handle_publish_spk_release(publish_spk_response_handler *response_handler) { 
    response_handler->account = NULL;
}

publish_spk_response_handler publish_spk_response_handler_store = {NULL, handle_publish_spk_release};

/* opk related */
void supply_opks(struct supply_opks_handler *response_handler) {
    // save to db
    unsigned int i;
    if (response_handler->account->saved == true) {
        for (i = 0; i < response_handler->account->n_one_time_pre_keys; i++) {
            get_ssm_plugin()->add_one_time_pre_key(&(response_handler->account->account_id), response_handler->account->one_time_pre_keys[i]);
        }
    }
}

/* send to the server */
void register_account() {
    Skissm__E2eeAccount *account = create_account();

    // register account to server
    register_user_response_handler_store.account = account;
    send_register_user_request(account, &register_user_response_handler_store);
}

void publish_spk(Skissm__E2eeAccount *account) {
    // publish account spk to server
    publish_spk_response_handler_store.account = account;
    send_publish_spk_request(account, &publish_spk_response_handler_store);
}

Skissm__RegisterUserRequestPayload *produce_register_request_payload(Skissm__E2eeAccount *account) {
    Skissm__RegisterUserRequestPayload *payload = (Skissm__RegisterUserRequestPayload *)malloc(sizeof(Skissm__RegisterUserRequestPayload));
    skissm__register_user_request_payload__init(payload);

    unsigned int i;

    copy_protobuf_from_protobuf(&(payload->identity_key_public), &(account->identity_key_pair->public_key));

    payload->signed_pre_key_public = (Skissm__SignedPreKeyPublic *)malloc(sizeof(Skissm__SignedPreKeyPublic));
    skissm__signed_pre_key_public__init(payload->signed_pre_key_public);
    payload->signed_pre_key_public->spk_id = account->signed_pre_key_pair->spk_id;
    copy_protobuf_from_protobuf(&(payload->signed_pre_key_public->public_key), &(account->signed_pre_key_pair->key_pair->public_key));

    copy_protobuf_from_protobuf(&(payload->signed_pre_key_public->signature), &(account->signed_pre_key_pair->signature));

    payload->n_one_time_pre_keys = account->n_one_time_pre_keys;
    payload->one_time_pre_keys = (Skissm__OneTimePreKeyPublic **)malloc(sizeof(Skissm__OneTimePreKeyPublic *) * payload->n_one_time_pre_keys);
    for (i = 0; i < payload->n_one_time_pre_keys; i++) {
        payload->one_time_pre_keys[i] = (Skissm__OneTimePreKeyPublic *)malloc(sizeof(Skissm__OneTimePreKeyPublic));
        skissm__one_time_pre_key_public__init(payload->one_time_pre_keys[i]);
        payload->one_time_pre_keys[i]->opk_id = account->one_time_pre_keys[i]->opk_id;
        copy_protobuf_from_protobuf(&(payload->one_time_pre_keys[i]->public_key), &(account->one_time_pre_keys[i]->key_pair->public_key));
    }

    return payload;
}

void consume_register_response_payload(Skissm__E2eeAccount *account, Skissm__RegisterUserResponsePayload *payload) {
    copy_address_from_address(&(account->address), payload->address);
    // save to db
    account->saved = true;
    get_ssm_plugin()->store_account(account);
    ssm_notify_user_registered(account);
}

Skissm__PublishSpkRequestPayload *produce_publish_spk_request_payload(Skissm__E2eeAccount *account) {
    generate_signed_pre_key(account);

    Skissm__PublishSpkRequestPayload *publish_spk_message =
        (Skissm__PublishSpkRequestPayload *)malloc(sizeof(Skissm__PublishSpkRequestPayload));
    skissm__publish_spk_request_payload__init(publish_spk_message);

    copy_address_from_address(&(publish_spk_message->user_address), account->address);
    publish_spk_message->signed_pre_key_public = (Skissm__SignedPreKeyPublic *)malloc(sizeof(Skissm__SignedPreKeyPublic));
    skissm__signed_pre_key_public__init(publish_spk_message->signed_pre_key_public);
    publish_spk_message->signed_pre_key_public->spk_id = account->signed_pre_key_pair->spk_id;
    copy_protobuf_from_protobuf(&(publish_spk_message->signed_pre_key_public->public_key), &(account->signed_pre_key_pair->key_pair->public_key));
    copy_protobuf_from_protobuf(&(publish_spk_message->signed_pre_key_public->signature), &(account->signed_pre_key_pair->signature));

    return publish_spk_message;
}

void consume_publish_spk_response_payload(Skissm__E2eeAccount *account) {
    // save to db
    if (account->saved == true) {
        Skissm__SignedPreKeyPair *signed_pre_key_pair = account->signed_pre_key_pair;
        get_ssm_plugin()->update_signed_pre_key(&(account->account_id), signed_pre_key_pair);
    }
}
