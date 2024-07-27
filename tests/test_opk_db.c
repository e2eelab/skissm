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

static void free_opks(Skissm__OneTimePreKey ***opks, uint32_t opk_num) {
    uint32_t i;
    for (i = 0; i < opk_num; i++){
        skissm__one_time_pre_key__free_unpacked((*opks)[i], NULL);
        (*opks)[i] = NULL;
    }
    free(*opks);
}

void test_update_one_time_pre_key() {
    tear_up();

    Skissm__Account *account = NULL;
    mock_account(&account);
    account->saved = true;
    store_account(account);
    Skissm__E2eeAddress *address = account->address;

    int used_opk = 10;
    uint32_t opk_id = account->one_time_pre_key_list[used_opk]->opk_id;

    mark_opk_as_used(account, opk_id);
    update_one_time_pre_key(address, opk_id);

    sqlite_int64 address_id;
    bool succ = load_address_id(address, &address_id);
    assert(succ);

    // load the one-time pre-keys
    Skissm__OneTimePreKey **opk_copy = NULL;
    uint32_t opk_num = load_one_time_pre_keys(address_id, &opk_copy);

    // assert the opk is used
    assert(opk_copy[used_opk]->used == true);

    // release
    free_proto(account);
    free_opks(&opk_copy, opk_num);

    tear_down();
}

void test_remove_one_time_pre_key() {
    tear_up();

    Skissm__Account *account = NULL;
    mock_account(&account);
    account->saved = true;
    store_account(account);
    Skissm__E2eeAddress *address = account->address;

    int origin_opk_num = account->n_one_time_pre_key_list;

    int used_opk_num = 80;
    int i;
    for (i = 0; i < used_opk_num; i++){
        remove_one_time_pre_key(address, account->one_time_pre_key_list[i]->opk_id);
    }

    sqlite_int64 address_id;
    bool succ = load_address_id(address, &address_id);
    assert(succ);

    // load the one-time pre-keys
    Skissm__OneTimePreKey **opk_copy = NULL;
    uint32_t opk_num = load_one_time_pre_keys(address_id, &opk_copy);

    // check if the opks are deleted
    assert(opk_num == origin_opk_num - used_opk_num);

    // release
    free_proto(account);
    free_opks(&opk_copy, opk_num);

    tear_down();
}

int main() {
    test_update_one_time_pre_key();
    test_remove_one_time_pre_key();
    return 0;
}
