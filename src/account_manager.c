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
#include "account_manager.h"
#include "e2ee_protocol.h"
#include "account.h"
#include "mem_util.h"

/* registration related */
static void handle_register_user_response(
    register_user_response_handler *response_handler,
    Org__E2eelab__Skissm__Proto__E2eeAddress *address
) {
    copy_address_from_address(&(response_handler->account->address), address);
    // save to db
    response_handler->account->saved = true;
    ssm_handler.store_account(response_handler->account);
    ssm_notify_user_registered(response_handler->account);
}

static void handle_register_release(register_user_response_handler *response_handler) {
    org__e2eelab__skissm__proto__e2ee_account__free_unpacked(response_handler->account, NULL);
    response_handler->account = NULL;
}

register_user_response_handler register_user_response_handler_store = {
    NULL,
    handle_register_user_response,
    handle_register_release
};

/* spk related */
static void handle_publish_spk_response(publish_spk_response_handler *response_handler) {
    // save to db
    if (response_handler->account->saved == true) {
        Org__E2eelab__Skissm__Proto__SignedPreKeyPair *signed_pre_key_pair = response_handler->account->signed_pre_key_pair;
        ssm_handler.update_signed_pre_key(response_handler->account, signed_pre_key_pair);
    }
}

static void handle_publish_spk_release(publish_spk_response_handler *response_handler) {
    response_handler->account = NULL;
}

publish_spk_response_handler publish_spk_response_handler_store = {
    NULL,
    handle_publish_spk_response,
    handle_publish_spk_release
};

/* opk related */
void supply_opks(struct supply_opks_handler *response_handler) {
    // save to db
    unsigned int i;
    if (response_handler->account->saved == true){
        for (i = 0; i < response_handler->account->n_one_time_pre_keys; i++){
            ssm_handler.add_one_time_pre_key(response_handler->account, response_handler->account->one_time_pre_keys[i]);
        }
    }
}

/* send to the server */
void register_account(){
    Org__E2eelab__Skissm__Proto__E2eeAccount *account = create_account();

    // register account to server
    register_user_response_handler_store.account = account;
    send_register_user_request(account, &register_user_response_handler_store);
}

void publish_spk(Org__E2eelab__Skissm__Proto__E2eeAccount *account){
    // publish account spk to server
    publish_spk_response_handler_store.account = account;
    send_publish_spk_request(account, &publish_spk_response_handler_store);
}
