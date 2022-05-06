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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "skissm/account.h"
#include "skissm/cipher.h"
#include "skissm/crypto.h"
#include "skissm/mem_util.h"
#include "skissm/skissm.h"

#include "test_plugin.h"
#include "test_util.h"

static void verify_one_time_pre_keys(Skissm__Account *account, unsigned int n_one_time_pre_keys) {
    unsigned int i;

    assert(account->n_one_time_pre_keys == n_one_time_pre_keys);

    for (i = 0; i < account->n_one_time_pre_keys; i++){
        assert(account->one_time_pre_keys[i]->opk_id == (i + 1));
        assert(account->one_time_pre_keys[i]->key_pair->private_key.data != NULL);
        assert(account->one_time_pre_keys[i]->key_pair->private_key.len == CURVE25519_KEY_LENGTH);
        assert(account->one_time_pre_keys[i]->key_pair->public_key.data != NULL);
        assert(account->one_time_pre_keys[i]->key_pair->public_key.len == CURVE25519_KEY_LENGTH);
    }
}

static void register_account_test(uint64_t account_id) {
    // Register test
    Skissm__Account *account = create_account(account_id, TEST_E2EE_PACK_ID);

    assert(account->identity_key->asym_key_pair->private_key.len == CURVE25519_KEY_LENGTH);
    assert(account->identity_key->asym_key_pair->public_key.len == CURVE25519_KEY_LENGTH);
    assert(account->identity_key->sign_key_pair->private_key.len == CURVE25519_KEY_LENGTH);
    assert(account->identity_key->sign_key_pair->public_key.len == CURVE25519_KEY_LENGTH);
    assert(account->signed_pre_key->spk_id == 1);
    assert(account->signed_pre_key->key_pair->private_key.len == CURVE25519_KEY_LENGTH);
    assert(account->signed_pre_key->key_pair->public_key.len == CURVE25519_KEY_LENGTH);
    assert(account->signed_pre_key->signature.len == CURVE_SIGNATURE_LENGTH);
    verify_one_time_pre_keys(account, 100);

    // Generate a new signed pre-key pair and a new signature
    generate_signed_pre_key(account);

    assert(account->signed_pre_key->spk_id == 2);
    assert(account->signed_pre_key->key_pair->private_key.len == CURVE25519_KEY_LENGTH);
    assert(account->signed_pre_key->key_pair->public_key.len == CURVE25519_KEY_LENGTH);
    assert(account->signed_pre_key->signature.len == CURVE_SIGNATURE_LENGTH);

    // Post some new one-time pre-keys test
    // Generate 80 one-time pre-key pairs
    Skissm__OneTimePreKey **output = generate_opks(80, account);

    verify_one_time_pre_keys(account, 180);

    // store account
    mock_random_address(&account->address);
    get_skissm_plugin()->db_handler.store_account(account);
    printf("stored account_id %llu\n", account->account_id);

    // load account
    Skissm__Account *loaded_account = NULL;
    get_skissm_plugin()->db_handler.load_account(account_id, &loaded_account);
    assert(is_equal_account(account, loaded_account));

    // release
    skissm__account__free_unpacked(account, NULL);
    skissm__account__free_unpacked(loaded_account, NULL);
}

static void load_accounts_test(uint64_t num) {
    printf("====== load_accounts_test ======\n");
    unsigned i;
    Skissm__Account **accounts = NULL;
    size_t accounts_num = get_skissm_plugin()->db_handler.load_accounts(&accounts);
    assert(accounts_num == num);
    printf("loaded accounts num: %zu\n", accounts_num);

    // pack/unpack test
    uint8_t **accounts_data;
    size_t *accounts_data_len;
    accounts_data_len = (size_t *)malloc(accounts_num * sizeof(size_t));
    accounts_data = (uint8_t **)malloc(accounts_num * sizeof(uint8_t *));
    memset(accounts_data_len, 0, accounts_num);
    for(i = 0; i<accounts_num; i++) {
        accounts_data_len[i] = skissm__account__get_packed_size(accounts[i]);
        accounts_data[i] = (uint8_t *)malloc(accounts_data_len[i] * sizeof(uint8_t));
        skissm__account__pack(accounts[i], accounts_data[i]);
        assert(accounts_data[i] != NULL);
        assert(accounts_data_len[i] > 0);
    }

    for(i = 0; i<accounts_num; i++) {
        Skissm__Account *unpacked_account  = skissm__account__unpack(NULL, accounts_data_len[i], accounts_data[i]);
        free_mem((void **)(&accounts_data[i]), accounts_data_len[i]);
        assert(unpacked_account->account_id == (i+1));
        assert(is_equal_account(accounts[i], unpacked_account));
        printf("pack/unpack verified: account_id %llu\n", accounts[i]->account_id);
    }
    free_mem((void **)(&accounts_data_len), accounts_num);
    free_mem((void **)(&accounts_data), accounts_num);
}

static void register_accounts_test(uint64_t num) {
    for (uint64_t account_id = 1; account_id<=num; account_id++) {
        register_account_test(account_id);
    }

    load_accounts_test(num);
}

int main(){
    // test start
    tear_up();

    register_accounts_test(8);

    // test stop.
    tear_down();
    return 0;
}
