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
#include "skissm/group_session.h"
#include "skissm/mem_util.h"
#include "skissm/safe_check.h"

int produce_register_request(Skissm__RegisterUserRequest **request_out, Skissm__Account *account) {
    int ret = 0;

    Skissm__IdentityKey *identity_key = NULL;
    Skissm__KeyPair *identity_key_pair_asym = NULL;
    Skissm__KeyPair *identity_key_pair_sign = NULL;
    Skissm__SignedPreKey *signed_pre_key = NULL;
    Skissm__KeyPair *signed_pre_key_pair = NULL;
    Skissm__OneTimePreKey *one_time_pre_key = NULL;

    if (safe_unregistered_account(account)) {
        identity_key = account->identity_key;
        identity_key_pair_asym = identity_key->asym_key_pair;
        identity_key_pair_sign = identity_key->sign_key_pair;
        signed_pre_key = account->signed_pre_key;
        signed_pre_key_pair = signed_pre_key->key_pair;
    } else {
        ssm_notify_log(NULL, BAD_ACCOUNT, "produce_register_request()");
        ret = -1;
    }

    if (ret == 0) {
        Skissm__RegisterUserRequest *request = (Skissm__RegisterUserRequest *)malloc(sizeof(Skissm__RegisterUserRequest));
        skissm__register_user_request__init(request);

        // copy identity public key
        request->identity_key_public = (Skissm__IdentityKeyPublic *)malloc(sizeof(Skissm__IdentityKeyPublic));
        skissm__identity_key_public__init(request->identity_key_public);
        copy_protobuf_from_protobuf(&(request->identity_key_public->asym_public_key), &(identity_key_pair_asym->public_key));
        copy_protobuf_from_protobuf(&(request->identity_key_public->sign_public_key), &(identity_key_pair_sign->public_key));

        // copy signed pre-key
        request->signed_pre_key_public = (Skissm__SignedPreKeyPublic *)malloc(sizeof(Skissm__SignedPreKeyPublic));
        skissm__signed_pre_key_public__init(request->signed_pre_key_public);
        request->signed_pre_key_public->spk_id = account->signed_pre_key->spk_id;
        copy_protobuf_from_protobuf(&(request->signed_pre_key_public->public_key), &(signed_pre_key_pair->public_key));
        copy_protobuf_from_protobuf(&(request->signed_pre_key_public->signature), &(signed_pre_key->signature));

        // copy one-time pre-key
        request->n_one_time_pre_key_list = account->n_one_time_pre_key_list;
        request->one_time_pre_key_list = (Skissm__OneTimePreKeyPublic **)malloc(sizeof(Skissm__OneTimePreKeyPublic *) * request->n_one_time_pre_key_list);
        size_t i;
        for (i = 0; i < request->n_one_time_pre_key_list; i++) {
            request->one_time_pre_key_list[i] = (Skissm__OneTimePreKeyPublic *)malloc(sizeof(Skissm__OneTimePreKeyPublic));
            skissm__one_time_pre_key_public__init(request->one_time_pre_key_list[i]);

            one_time_pre_key = account->one_time_pre_key_list[i];
            request->one_time_pre_key_list[i]->opk_id = one_time_pre_key->opk_id;
            copy_protobuf_from_protobuf(&(request->one_time_pre_key_list[i]->public_key), &(one_time_pre_key->key_pair->public_key));
        }

        *request_out = request;
    } else {
        *request_out = NULL;
    }

    return ret;
}

bool consume_register_response(Skissm__Account *account, Skissm__RegisterUserResponse *response) {
    int ret = 0;

    Skissm__E2eeAddress *address = NULL;
    char *auth = NULL;
    Skissm__E2eeAddress *other_device_address = NULL;
    Skissm__E2eeAddress *to_address = NULL;
    Skissm__InviteResponse **invite_response_list = NULL;
    size_t invite_response_num;
    size_t i;

    if (!safe_unregistered_account(account)) {
        ssm_notify_log(NULL, BAD_ACCOUNT, "consume_register_response()");
        ret = -1;
    }
    if (!safe_register_user_response(response)) {
        ssm_notify_log(NULL, BAD_RESPONSE, "consume_register_response()");
        ret = -1;
    }

    if (ret == 0) {
        // insert the address the server gave to our account
        copy_address_from_address(&(account->address), response->address);
        if (safe_certificate(response->server_cert)) {
            copy_certificate_from_certificate(&(account->server_cert), response->server_cert);
        }
        account->saved = true;
        account->password = strdup(response->password);
        account->auth = strdup(response->auth);
        account->expires_in = response->expires_in;
        // save to db
        get_skissm_plugin()->db_handler.store_account(account);
        ssm_notify_user_registered(account);

        address = account->address;
        auth = account->auth;

        // create outbound sessions to other devices
        if (response->n_other_device_address_list > 0) {
            for (i = 0; i < response->n_other_device_address_list; i++) {
                other_device_address = (response->other_device_address_list)[i];
                ssm_notify_log(
                    address, DEBUG_LOG, "consume_register_response() other_device_address_list %zu of %zu: address [%s:%s]",
                    i + 1, response->n_other_device_address_list,
                    other_device_address->user->user_id,
                    other_device_address->user->device_id
                );
                ret = get_pre_key_bundle_internal(
                    &invite_response_list,
                    &invite_response_num,
                    address,
                    auth,
                    other_device_address->user->user_id,
                    other_device_address->domain,
                    other_device_address->user->device_id,
                    false,
                    NULL, 0
                );
                if (ret == 0) {
                    free_invite_response_list(&invite_response_list, invite_response_num);
                }
            }
        }

        // send to other friends if necessary
        if (response->n_other_user_address_list > 0) {
            for (i = 0; i < response->n_other_user_address_list; i++) {
                to_address = (response->other_user_address_list)[i];
                ssm_notify_log(
                    address, DEBUG_LOG, "consume_register_response() other_user_address_list %zu of %zu: address [%s:%s]",
                    i + 1, response->n_other_user_address_list,
                    to_address->user->user_id,
                    to_address->user->device_id
                );
                // skip the same user device
                if (safe_strcmp(address->user->device_id, to_address->user->device_id)) {
                    ssm_notify_log(
                        address,
                        DEBUG_LOG,
                        "consume_register_response(): skip invite the same user device: %s",
                        to_address->user->device_id
                    );
                    continue;
                }

                ret = get_pre_key_bundle_internal(
                    &invite_response_list,
                    &invite_response_num,
                    address,
                    auth,
                    to_address->user->user_id,
                    to_address->domain,
                    to_address->user->device_id,
                    false,
                    NULL, 0
                );
                if (ret == 0) {
                    free_invite_response_list(&invite_response_list, invite_response_num);
                }
            }
        }
        return true;
    } else {
        return false;
    }
}

int produce_publish_spk_request(
    Skissm__PublishSpkRequest **request_out,
    Skissm__Account *account
) {
    int ret = 0;

    Skissm__SignedPreKey *signed_pre_key = NULL;
    Skissm__KeyPair *signed_pre_key_pair = NULL;

    if (safe_registered_account(account)) {
        signed_pre_key = account->signed_pre_key;
        signed_pre_key_pair = signed_pre_key->key_pair;
    } else {
        ssm_notify_log(NULL, BAD_ACCOUNT, "produce_publish_spk_request()");
        ret = -1;
    }

    if (ret == 0) {
        Skissm__PublishSpkRequest *request = (Skissm__PublishSpkRequest *)malloc(sizeof(Skissm__PublishSpkRequest));
        skissm__publish_spk_request__init(request);

        // copy the new signed pre-key to the message which will be sent to the server
        copy_address_from_address(&(request->user_address), account->address);
        request->signed_pre_key_public = (Skissm__SignedPreKeyPublic *)malloc(sizeof(Skissm__SignedPreKeyPublic));
        skissm__signed_pre_key_public__init(request->signed_pre_key_public);
        request->signed_pre_key_public->spk_id = signed_pre_key->spk_id;
        copy_protobuf_from_protobuf(&(request->signed_pre_key_public->public_key), &(signed_pre_key_pair->public_key));
        copy_protobuf_from_protobuf(&(request->signed_pre_key_public->signature), &(signed_pre_key->signature));

        *request_out = request;
    } else {
        *request_out = NULL;
    }

    return ret;
}

int consume_publish_spk_response(
    Skissm__Account *account,
    Skissm__PublishSpkResponse *response
) {
    int ret = 0;

    if (!safe_publish_spk_response(response)) {
        ssm_notify_log(NULL, BAD_RESPONSE, "consume_publish_spk_response()");
        ret = -1;
    }
    if (!safe_registered_account(account)) {
        ssm_notify_log(NULL, BAD_ACCOUNT, "consume_publish_spk_response()");
        ret = -1;
    }

    if (ret == 0) {
        // save to db
        if (account->saved == true) {
            Skissm__SignedPreKey *signed_pre_key = account->signed_pre_key;
            get_skissm_plugin()->db_handler.update_signed_pre_key(account->address, signed_pre_key);
        }
    }

    return ret;
}

int produce_supply_opks_request(
    Skissm__SupplyOpksRequest **request_out,
    Skissm__Account *account,
    uint32_t opks_num
) {
    int ret = 0;

    Skissm__SupplyOpksRequest *request = NULL;
    Skissm__OneTimePreKey **one_time_pre_key_list = NULL;
    uint32_t e2ee_pack_id;
    uint32_t cur_opk_id;

    if (safe_registered_account(account)) {
        e2ee_pack_id = account->e2ee_pack_id;
        cur_opk_id = account->next_one_time_pre_key_id;
    } else {
        ssm_notify_log(NULL, BAD_ACCOUNT, "produce_supply_opks_request()");
        ret = -1;
    }

    if (ret == 0) {
        // generate a given number of new one-time pre-keys
        ret = generate_opks(&one_time_pre_key_list, opks_num, e2ee_pack_id, cur_opk_id);
    }

    if (ret == 0) {
        request = (Skissm__SupplyOpksRequest *)malloc(sizeof(Skissm__SupplyOpksRequest));
        skissm__supply_opks_request__init(request);

        request->e2ee_pack_id = account->e2ee_pack_id;
        request->n_one_time_pre_key_public_list = (size_t)opks_num;
        request->one_time_pre_key_public_list = (Skissm__OneTimePreKeyPublic **)malloc(sizeof(Skissm__OneTimePreKeyPublic *) * opks_num);

        copy_address_from_address(&(request->user_address), account->address);

        // copy the new one-time pre-keys to the message which will be sent to the server
        uint32_t i;
        for (i = 0; i < opks_num; i++) {
            request->one_time_pre_key_public_list[i] = (Skissm__OneTimePreKeyPublic *)malloc(sizeof(Skissm__OneTimePreKeyPublic));
            skissm__one_time_pre_key_public__init(request->one_time_pre_key_public_list[i]);
            request->one_time_pre_key_public_list[i]->opk_id = one_time_pre_key_list[i]->opk_id;
            copy_protobuf_from_protobuf(&(request->one_time_pre_key_public_list[i]->public_key), &(one_time_pre_key_list[i]->key_pair->public_key));
        }

        *request_out = request;
    }

    return ret;
}

int consume_supply_opks_response(Skissm__Account *account, uint32_t opks_num, Skissm__SupplyOpksResponse *response) {
    int ret = 0;

    if (!safe_registered_account(account)) {
        ret = -1;
    }
    if (!safe_supply_opks_response(response)) {
        ret = -1;
    }

    if (ret == 0) {
        size_t old_opks_num = account->n_one_time_pre_key_list - opks_num;
        // save to db
        size_t i;
        for (i = 0; i < opks_num; i++) {
            get_skissm_plugin()->db_handler.add_one_time_pre_key(account->address, account->one_time_pre_key_list[old_opks_num + i]);
        }
    }

    return ret;
}

bool consume_supply_opks_msg(Skissm__E2eeAddress *receiver_address, Skissm__SupplyOpksMsg *msg) {
    /** The server notifies us to generate some new one-time pre-keys 
        since our published one-time pre-keys are going to used up. */

    if (!compare_address(receiver_address, msg->user_address)){
        ssm_notify_log(receiver_address, BAD_SERVER_MESSAGE, "consume_supply_opks_msg()");
        return false;
    }

    uint32_t opks_num = msg->opks_num;
    Skissm__E2eeAddress *user_address = msg->user_address;
    Skissm__Account *account = NULL;
    get_skissm_plugin()->db_handler.load_account_by_address(user_address, &account);

    if (account == NULL || !(account->saved)) {
        ssm_notify_log(receiver_address, BAD_ONE_TIME_PRE_KEY, "consume_supply_opks_msg()");
        return false;
    }

    Skissm__SupplyOpksResponse *supply_opks_response = NULL;
    supply_opks_internal(&supply_opks_response, account, opks_num);

    // release
    free_proto(account);
    free_proto(supply_opks_response);

    // done
    return true;
}
