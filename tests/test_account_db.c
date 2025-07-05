/*
 * Copyright © 2021 Academia Sinica. All Rights Reserved.
 *
 * This file is part of E2EE Security.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * E2EE Security is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with E2EE Security.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "e2ees/account.h"
#include "e2ees/cipher.h"
#include "e2ees/e2ees_client.h"
#include "e2ees/mem_util.h"
#include "e2ees/e2ees.h"

#include "test_plugin.h"
#include "mock_db.h"
#include "test_plugin.h"
#include "test_util.h"

void test_setup() {
    fprintf(stderr, "test_setup\n");
    tear_up();
    tear_down();
}

void test_setup_call_twice() {
    fprintf(stderr, "test_setup_call_twice\n");
    tear_up();;
    tear_down();
    tear_up();;
    tear_down();
}

void test_insert_address() {
    fprintf(stderr, "test_insert_address\n");
    tear_up();

    // create address
    E2ees__E2eeAddress *address = NULL;
    mock_address(&address, "alice", "alice's domain", "alice's device");

    // insert to the db
    sqlite_int64 address_id = insert_address(address);

    // load address
    E2ees__E2eeAddress *address_copy = NULL;
    load_address(address_id, &address_copy);
    assert(compare_address(address, address_copy));

    // release
    if (address_copy != NULL) {
        free_address(address_copy);
    }
    free_address(address);

    tear_down();
}

void test_store_and_load_account() {
    fprintf(stderr, "test_store_and_load_account\n");
    tear_up();

    bool succ = false;
    E2ees__OneTimePreKey *one_time_pre_key = NULL;
    size_t i;

    // mock
    E2ees__Account *account = NULL;
    mock_account(&account);
    E2ees__E2eeAddress *address = account->address;

    // insert to the db
    store_account(account);

    // load address id
    sqlite_int64 address_id;
    succ = load_address_id(address, &address_id);
    assert(succ);

    // load version
    char *version = load_version(address_id);
    assert(strcmp(version, account->version) == 0);

    // load identity key
    E2ees__IdentityKey *identity_key = NULL;
    load_identity_key_pair(address_id, &identity_key);
    assert(is_equal_ik(identity_key, account->identity_key));

    // load signed pre-key
    E2ees__SignedPreKey *signed_pre_key = NULL;
    load_signed_pre_key_pair(address_id, &signed_pre_key);
    assert(is_equal_spk(signed_pre_key, account->signed_pre_key));

    // load number of one-time pre-keys
    int n_one_time_pre_key_list = load_n_one_time_pre_keys(address_id);
    assert(n_one_time_pre_key_list == account->n_one_time_pre_key_list);

    // load one-time pre-keys
    E2ees__OneTimePreKey **one_time_pre_key_list = NULL;
    load_one_time_pre_keys(address_id, &one_time_pre_key_list);
    assert(is_equal_opk_list(one_time_pre_key_list, account->one_time_pre_key_list, n_one_time_pre_key_list));

    // load_account
    E2ees__Account *account_copy = NULL;
    load_account_by_address(address, &account_copy);
    assert(is_equal_account(account, account_copy));

    // release
    free_string(version);
    free_proto(identity_key);
    free_proto(signed_pre_key);
    for (i = 0; i < n_one_time_pre_key_list; i++) {
        one_time_pre_key = one_time_pre_key_list[i];
        free_proto(one_time_pre_key);
    }
    free_mem((void **)&one_time_pre_key_list, sizeof(E2ees__OneTimePreKey *) * n_one_time_pre_key_list);
    free_proto(account);
    free_account(account_copy);

    tear_down();
}

int main() {
    test_setup();
    test_setup_call_twice();
    test_insert_address();
    test_store_and_load_account();
}
