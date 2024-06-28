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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "skissm/skissm.h"
#include "skissm/account.h"
#include "skissm/mem_util.h"

#include "mock_db.h"
#include "test_plugin.h"
#include "test_util.h"

static void on_log(Skissm__E2eeAddress *user_address, LogCode log_code, const char *log_msg) {
    print_log((char *)log_msg, log_code);
}

static skissm_event_handler_t test_event_handler = {
    on_log,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

static void free_opks(Skissm__OneTimePreKey ***opks, uint32_t opk_num){
    uint32_t i;
    for (i = 0; i < opk_num; i++){
        skissm__one_time_pre_key__free_unpacked((*opks)[i], NULL);
        (*opks)[i] = NULL;
    }
    free(*opks);
}

void test_update_one_time_pre_key(uint32_t e2ee_pack_id){
    tear_up();
    get_skissm_plugin()->event_handler = test_event_handler;

    Skissm__Account *account = create_account(e2ee_pack_id);
    // generate a random address
    account->address = (Skissm__E2eeAddress *) malloc(sizeof(Skissm__E2eeAddress));
    skissm__e2ee_address__init(account->address);
    account->address->user = (Skissm__PeerUser *) malloc(sizeof(Skissm__PeerUser));
    skissm__peer_user__init(account->address->user);
    account->address->peer_case = SKISSM__E2EE_ADDRESS__PEER_USER;
    account->address->domain = mock_domain_str();
    account->address->user->user_id = generate_uuid_str();
    account->address->user->device_id = generate_uuid_str();

    // save to db
    account->saved = true;
    get_skissm_plugin()->db_handler.store_account(account);

    int used_opk = 10;
    uint32_t opk_id = account->one_time_pre_key_list[used_opk]->opk_id;

    mark_opk_as_used(account, opk_id);
    update_one_time_pre_key(account->address, opk_id);

    sqlite_int64 address_id;
    load_address_id(account->address, &address_id);

    // load the one-time pre-keys
    Skissm__OneTimePreKey **opk_copy = NULL;
    uint32_t opk_num = load_one_time_pre_keys(address_id, &opk_copy);

    // assert the opk is used
    assert(opk_copy[used_opk]->used == true);

    // free
    skissm__account__free_unpacked(account, NULL);
    free_opks(&opk_copy, opk_num);

    tear_down();
}

void test_remove_one_time_pre_key(uint32_t e2ee_pack_id){
    tear_up();
    get_skissm_plugin()->event_handler = test_event_handler;

    Skissm__Account *account = create_account(e2ee_pack_id);
    // generate a random address
    account->address = (Skissm__E2eeAddress *) malloc(sizeof(Skissm__E2eeAddress));
    skissm__e2ee_address__init(account->address);
    account->address->user = (Skissm__PeerUser *) malloc(sizeof(Skissm__PeerUser));
    skissm__peer_user__init(account->address->user);
    account->address->peer_case = SKISSM__E2EE_ADDRESS__PEER_USER;
    account->address->domain = mock_domain_str();
    account->address->user->user_id = generate_uuid_str();
    account->address->user->device_id = generate_uuid_str();

    // save to db
    account->saved = true;
    get_skissm_plugin()->db_handler.store_account(account);

    int origin_opk_num = account->n_one_time_pre_key_list;

    int used_opk_num = 80;
    int i;
    for (i = 0; i < used_opk_num; i++){
        remove_one_time_pre_key(account->address, account->one_time_pre_key_list[i]->opk_id);
    }

    sqlite_int64 address_id;
    load_address_id(account->address, &address_id);

    // load the one-time pre-keys
    Skissm__OneTimePreKey **opk_copy = NULL;
    uint32_t opk_num = load_one_time_pre_keys(address_id, &opk_copy);

    // check if the opks are deleted
    assert(opk_num == origin_opk_num - used_opk_num);

    // free
    skissm__account__free_unpacked(account, NULL);
    free_opks(&opk_copy, opk_num);

    tear_down();
}

int main(){
    uint32_t e2ee_pack_id = gen_e2ee_pack_id_raw(
        0,
        E2EE_PACK_ALG_DIGITAL_SIGNATURE_CURVE25519,
        E2EE_PACK_ALG_KEM_CURVE25519,
        E2EE_PACK_ALG_SYMMETRIC_KEY_AES256GCM,
        E2EE_PACK_ALG_HASH_SHA2_256
    );

    test_update_one_time_pre_key(e2ee_pack_id);
    test_remove_one_time_pre_key(e2ee_pack_id);
    return 0;
}
