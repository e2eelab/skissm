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

#include "skissm.h"
#include "account.h"
#include "mem_util.h"

// -----------------
#include "test_db.h"
#include "test_env.h"
#include "test_util.h"

static const char DOMAIN[] = "e2eelab.org";

void test_load_old_signed_pre_key(){
    setup();

    Org__E2eelab__Skissm__Proto__E2eeAccount *account = create_account();
    /* Generate a random address */
    account->address = (Org__E2eelab__Skissm__Proto__E2eeAddress *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeAddress));
    org__e2eelab__skissm__proto__e2ee_address__init(account->address);
    account->address->user_id.len = 32;
    account->address->user_id.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    ssm_handler.handle_rg(account->address->user_id.data, 32);
    account->address->domain.len = sizeof(DOMAIN);
    account->address->domain.data = (uint8_t *) malloc(sizeof(uint8_t) * sizeof(DOMAIN));
    memcpy(account->address->domain.data, DOMAIN, sizeof(DOMAIN));
    account->address->device_id.len = 32;
    account->address->device_id.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    ssm_handler.handle_rg(account->address->device_id.data, 32);
    /* Save to db */
    account->saved = true;
    ssm_handler.store_account(account);

    Org__E2eelab__Skissm__Proto__SignedPreKeyPair *old_spk = (Org__E2eelab__Skissm__Proto__SignedPreKeyPair *) malloc(sizeof(Org__E2eelab__Skissm__Proto__SignedPreKeyPair));
    org__e2eelab__skissm__proto__signed_pre_key_pair__init(old_spk);
    old_spk->spk_id = account->signed_pre_key_pair->spk_id;
    old_spk->key_pair = (Org__E2eelab__Skissm__Proto__KeyPair *) malloc(sizeof(Org__E2eelab__Skissm__Proto__KeyPair));
    org__e2eelab__skissm__proto__key_pair__init(old_spk->key_pair);
    copy_protobuf_from_protobuf(&(old_spk->key_pair->private_key), &(account->signed_pre_key_pair->key_pair->private_key));
    copy_protobuf_from_protobuf(&(old_spk->key_pair->public_key), &(account->signed_pre_key_pair->key_pair->public_key));
    copy_protobuf_from_protobuf(&(old_spk->signature), &(account->signed_pre_key_pair->signature));
    old_spk->ttl = account->signed_pre_key_pair->ttl;

    /* Generate a new signed pre-key pair */
    generate_signed_pre_key(account);
    ssm_handler.update_signed_pre_key(account, account->signed_pre_key_pair);

    /* Load the old signed pre-key */
    Org__E2eelab__Skissm__Proto__SignedPreKeyPair *old_spk_copy = NULL;
    load_old_signed_pre_key(&(account->account_id), old_spk->spk_id, &old_spk_copy);

    // assert old_spk equals to old_spk_copy
    print_result("test_load_old_signed_pre_key", is_equal_spk(old_spk, old_spk_copy));

    // free
    org__e2eelab__skissm__proto__e2ee_account__free_unpacked(account, NULL);
    org__e2eelab__skissm__proto__signed_pre_key_pair__free_unpacked(old_spk, NULL);
    org__e2eelab__skissm__proto__signed_pre_key_pair__free_unpacked(old_spk_copy, NULL);

    tear_down();
}

void test_remove_expired_signed_pre_key(){
    setup();

    Org__E2eelab__Skissm__Proto__E2eeAccount *account = create_account();
    /* Generate a random address */
    account->address = (Org__E2eelab__Skissm__Proto__E2eeAddress *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeAddress));
    org__e2eelab__skissm__proto__e2ee_address__init(account->address);
    account->address->user_id.len = 32;
    account->address->user_id.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    ssm_handler.handle_rg(account->address->user_id.data, 32);
    account->address->domain.len = sizeof(DOMAIN);
    account->address->domain.data = (uint8_t *) malloc(sizeof(uint8_t) * sizeof(DOMAIN));
    memcpy(account->address->domain.data, DOMAIN, sizeof(DOMAIN));
    account->address->device_id.len = 32;
    account->address->device_id.data = (uint8_t *) malloc(sizeof(uint8_t) * 32);
    ssm_handler.handle_rg(account->address->device_id.data, 32);
    /* Save to db */
    account->saved = true;
    ssm_handler.store_account(account);

    uint32_t old_spk_id = account->signed_pre_key_pair->spk_id;

    /* Generate a new signed pre-key pair */
    generate_signed_pre_key(account);
    ssm_handler.update_signed_pre_key(account, account->signed_pre_key_pair);
    generate_signed_pre_key(account);
    ssm_handler.update_signed_pre_key(account, account->signed_pre_key_pair);

    /* Remove expired signed pre-keys */
    remove_expired_signed_pre_key(&(account->account_id));

    /* Load the old signed pre-key */
    Org__E2eelab__Skissm__Proto__SignedPreKeyPair *old_spk_copy = NULL;
    load_old_signed_pre_key(&(account->account_id), old_spk_id, &old_spk_copy);

    /* assert old_spk_copy is NULL */
    print_result("test_remove_expired_signed_pre_key", (old_spk_copy == NULL));

    // free
    org__e2eelab__skissm__proto__e2ee_account__free_unpacked(account, NULL);

    tear_down();
}

int main(){
    test_load_old_signed_pre_key();
    //test_remove_expired_signed_pre_key();
    return 0;
}
