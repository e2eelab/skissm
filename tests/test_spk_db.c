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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "e2ees/account.h"
#include "e2ees/mem_util.h"
#include "e2ees/e2ees.h"

#include "mock_db.h"
#include "test_plugin.h"
#include "test_util.h"

void test_load_old_signed_pre_key() {
    tear_up();

    // mock account
    E2ees__Account *account = NULL;
    mock_account(&account);
    account->saved = true;
    store_account(account);
    E2ees__E2eeAddress *address = account->address;

    E2ees__SignedPreKey *old_spk = NULL;
    copy_spk_from_spk(&old_spk, account->signed_pre_key);
    
    // generate a new signed pre-key pair
    E2ees__SignedPreKey *signed_pre_key = NULL;
    mock_signed_pre_key(&signed_pre_key, 1);

    e2ees__signed_pre_key__free_unpacked(account->signed_pre_key, NULL);
    account->signed_pre_key = signed_pre_key;

    update_signed_pre_key(address, signed_pre_key);

    // load the updated signed pre-key from db
    E2ees__SignedPreKey *old_spk_copy = NULL;
    load_signed_pre_key(address, old_spk->spk_id, &old_spk_copy);
    assert(is_equal_spk(old_spk, old_spk_copy));

    // release
    free_proto(account);
    e2ees__signed_pre_key__free_unpacked(old_spk, NULL);
    e2ees__signed_pre_key__free_unpacked(old_spk_copy, NULL);

    tear_down();
}

void test_remove_expired_signed_pre_key() {
    tear_up();

    E2ees__Account *account = NULL;
    mock_account(&account);
    account->saved = true;
    store_account(account);
    E2ees__E2eeAddress *address = account->address;
    uint32_t old_spk_id = account->signed_pre_key->spk_id;

    // generate a new signed pre-key pair
    E2ees__SignedPreKey *signed_pre_key_1 = NULL;
    mock_signed_pre_key(&signed_pre_key_1, 1);

    e2ees__signed_pre_key__free_unpacked(account->signed_pre_key, NULL);
    account->signed_pre_key = signed_pre_key_1;

    update_signed_pre_key(address, account->signed_pre_key);

    E2ees__SignedPreKey *signed_pre_key_2 = NULL;
    mock_signed_pre_key(&signed_pre_key_2, 2);

    e2ees__signed_pre_key__free_unpacked(account->signed_pre_key, NULL);
    account->signed_pre_key = signed_pre_key_2;

    update_signed_pre_key(address, account->signed_pre_key);

    // remove expired signed pre-keys
    remove_expired_signed_pre_key(address);

    // load the old signed pre-key
    E2ees__SignedPreKey *old_spk_copy = NULL;
    load_signed_pre_key(address, old_spk_id, &old_spk_copy);

    // assert old_spk_copy is NULL
    assert(old_spk_copy == NULL);

    // release
    free_proto(account);

    tear_down();
}

int main() {
    test_load_old_signed_pre_key();
    test_remove_expired_signed_pre_key();
    return 0;
}
