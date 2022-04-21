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

#include <string.h>

#include "skissm/account.h"
#include "skissm/e2ee_client.h"
#include "skissm/e2ee_client_internal.h"
#include "skissm/mem_util.h"

Skissm__RegisterUserRequest *produce_register_request(Skissm__Account *account) {
    Skissm__RegisterUserRequest *request = (Skissm__RegisterUserRequest *)malloc(sizeof(Skissm__RegisterUserRequest));
    skissm__register_user_request__init(request);

    unsigned int i;

    request->identity_key_public = (Skissm__IdentityKeyPublic *) malloc(sizeof(Skissm__IdentityKeyPublic));
    skissm__identity_key_public__init(request->identity_key_public);
    copy_protobuf_from_protobuf(&(request->identity_key_public->asym_public_key), &(account->identity_key->asym_key_pair->public_key));
    copy_protobuf_from_protobuf(&(request->identity_key_public->sign_public_key), &(account->identity_key->sign_key_pair->public_key));

    request->signed_pre_key_public = (Skissm__SignedPreKeyPublic *)malloc(sizeof(Skissm__SignedPreKeyPublic));
    skissm__signed_pre_key_public__init(request->signed_pre_key_public);
    request->signed_pre_key_public->spk_id = account->signed_pre_key->spk_id;
    copy_protobuf_from_protobuf(&(request->signed_pre_key_public->public_key), &(account->signed_pre_key->key_pair->public_key));

    copy_protobuf_from_protobuf(&(request->signed_pre_key_public->signature), &(account->signed_pre_key->signature));

    request->n_one_time_pre_keys = account->n_one_time_pre_keys;
    request->one_time_pre_keys = (Skissm__OneTimePreKeyPublic **)malloc(sizeof(Skissm__OneTimePreKeyPublic *) * request->n_one_time_pre_keys);
    for (i = 0; i < request->n_one_time_pre_keys; i++) {
        request->one_time_pre_keys[i] = (Skissm__OneTimePreKeyPublic *)malloc(sizeof(Skissm__OneTimePreKeyPublic));
        skissm__one_time_pre_key_public__init(request->one_time_pre_keys[i]);
        request->one_time_pre_keys[i]->opk_id = account->one_time_pre_keys[i]->opk_id;
        copy_protobuf_from_protobuf(&(request->one_time_pre_keys[i]->public_key), &(account->one_time_pre_keys[i]->key_pair->public_key));
    }

    return request;
}

void consume_register_response(Skissm__Account *account, Skissm__RegisterUserResponse *response) {
    copy_address_from_address(&(account->address), response->address);
    account->saved = true;
    account->password = strdup(response->password);
    // save to db
    get_skissm_plugin()->db_handler.store_account(account);
    ssm_notify_user_registered(account);
}

Skissm__PublishSpkRequest *produce_publish_spk_request(Skissm__Account *account) {
    generate_signed_pre_key(account);

    Skissm__PublishSpkRequest *request =
        (Skissm__PublishSpkRequest *)malloc(sizeof(Skissm__PublishSpkRequest));
    skissm__publish_spk_request__init(request);

    copy_address_from_address(&(request->user_address), account->address);
    request->signed_pre_key_public = (Skissm__SignedPreKeyPublic *)malloc(sizeof(Skissm__SignedPreKeyPublic));
    skissm__signed_pre_key_public__init(request->signed_pre_key_public);
    request->signed_pre_key_public->spk_id = account->signed_pre_key->spk_id;
    copy_protobuf_from_protobuf(&(request->signed_pre_key_public->public_key), &(account->signed_pre_key->key_pair->public_key));
    copy_protobuf_from_protobuf(&(request->signed_pre_key_public->signature), &(account->signed_pre_key->signature));

    return request;
}

void consume_publish_spk_response(Skissm__Account *account, Skissm__PublishSpkResponse *response) {
    if (response->code == OK) {
        // save to db
        if (account->saved == true) {
            Skissm__SignedPreKey *signed_pre_key = account->signed_pre_key;
            get_skissm_plugin()->db_handler.update_signed_pre_key(account->account_id, signed_pre_key);
        }
    }
}

Skissm__SupplyOpksRequest *produce_supply_opks_request(Skissm__Account *account, uint32_t opks_num) {
    Skissm__SupplyOpksRequest *request = (Skissm__SupplyOpksRequest *)malloc(sizeof(Skissm__SupplyOpksRequest));
    skissm__supply_opks_request__init(request);

    Skissm__OneTimePreKey **inserted_one_time_pre_key_pair_list = generate_opks((size_t)opks_num, account);

    request->n_one_time_pre_key_public = (size_t)opks_num;
    request->one_time_pre_key_public = (Skissm__OneTimePreKeyPublic **)malloc(sizeof(Skissm__OneTimePreKeyPublic *) * opks_num);

    copy_address_from_address(&(request->user_address), account->address);

    unsigned int i;
    for (i = 0; i < opks_num; i++) {
        request->one_time_pre_key_public[i] = (Skissm__OneTimePreKeyPublic *)malloc(sizeof(Skissm__OneTimePreKeyPublic));
        skissm__one_time_pre_key_public__init(request->one_time_pre_key_public[i]);
        request->one_time_pre_key_public[i]->opk_id = inserted_one_time_pre_key_pair_list[i]->opk_id;
        copy_protobuf_from_protobuf(&(request->one_time_pre_key_public[i]->public_key), &(inserted_one_time_pre_key_pair_list[i]->key_pair->public_key));
    }

    return request;
}

void consume_supply_opks_response(Skissm__Account *account, Skissm__SupplyOpksResponse *response) {
    if (response->code == OK) {
        // save to db
        unsigned int i;
        for (i = 0; i < account->n_one_time_pre_keys; i++) {
            get_skissm_plugin()->db_handler.add_one_time_pre_key(account->account_id, account->one_time_pre_keys[i]);
        }
    }
}

bool consume_supply_opks_msg(Skissm__E2eeAddress *receiver_address, Skissm__SupplyOpksMsg *msg) {
    uint32_t opks_num = msg->opks_num;
    Skissm__E2eeAddress *user_address = msg->user_address;
    Skissm__Account *account = get_local_account(user_address);

    if (account == NULL || !account->saved) {
        ssm_notify_error(BAD_ONE_TIME_PRE_KEY, "consume_supply_opks_msg()");
        return false;
    }

    supply_opks_internal(account, opks_num);

    return true;
}