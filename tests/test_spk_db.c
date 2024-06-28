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

#include "skissm/account.h"
#include "skissm/mem_util.h"
#include "skissm/skissm.h"

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

void test_load_old_signed_pre_key(uint32_t e2ee_pack_id){
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

    Skissm__SignedPreKey *old_spk = (Skissm__SignedPreKey *) malloc(sizeof(Skissm__SignedPreKey));
    skissm__signed_pre_key__init(old_spk);
    old_spk->spk_id = account->signed_pre_key->spk_id;
    old_spk->key_pair = (Skissm__KeyPair *) malloc(sizeof(Skissm__KeyPair));
    skissm__key_pair__init(old_spk->key_pair);
    copy_protobuf_from_protobuf(&(old_spk->key_pair->private_key), &(account->signed_pre_key->key_pair->private_key));
    copy_protobuf_from_protobuf(&(old_spk->key_pair->public_key), &(account->signed_pre_key->key_pair->public_key));
    copy_protobuf_from_protobuf(&(old_spk->signature), &(account->signed_pre_key->signature));
    old_spk->ttl = account->signed_pre_key->ttl;

    print_result("compare signed_pre_key [1]", is_equal_spk(old_spk, account->signed_pre_key));
    
    // generate a new signed pre-key pair
    generate_signed_pre_key(account);
    get_skissm_plugin()->db_handler.update_signed_pre_key(account->address, account->signed_pre_key);

    // load the updated signed pre-key from db
    Skissm__SignedPreKey *old_spk_copy = NULL;
    load_signed_pre_key(account->address, old_spk->spk_id, &old_spk_copy);

    // assert old_spk equals to old_spk_copy
    assert(is_equal_spk(old_spk, old_spk_copy));
    print_result("compare signed_pre_key [2]", is_equal_spk(old_spk, old_spk_copy));

    // free
    skissm__account__free_unpacked(account, NULL);
    skissm__signed_pre_key__free_unpacked(old_spk, NULL);
    skissm__signed_pre_key__free_unpacked(old_spk_copy, NULL);

    tear_down();
}

void test_remove_expired_signed_pre_key(uint32_t e2ee_pack_id){
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

    uint32_t old_spk_id = account->signed_pre_key->spk_id;

    // generate a new signed pre-key pair
    generate_signed_pre_key(account);
    get_skissm_plugin()->db_handler.update_signed_pre_key(account->address, account->signed_pre_key);
    generate_signed_pre_key(account);
    get_skissm_plugin()->db_handler.update_signed_pre_key(account->address, account->signed_pre_key);

    // remove expired signed pre-keys
    remove_expired_signed_pre_key(account->address);

    // load the old signed pre-key
    Skissm__SignedPreKey *old_spk_copy = NULL;
    load_signed_pre_key(account->address, old_spk_id, &old_spk_copy);

    // assert old_spk_copy is NULL
    assert(old_spk_copy == NULL);

    // free
    skissm__account__free_unpacked(account, NULL);

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

    test_load_old_signed_pre_key(e2ee_pack_id);
    test_remove_expired_signed_pre_key(e2ee_pack_id);
    return 0;
}
