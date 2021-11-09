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

static void free_opks(Org__E2eelab__Skissm__Proto__OneTimePreKeyPair ***opks, uint32_t opk_num){
    uint32_t i;
    for (i = 0; i < opk_num; i++){
        org__e2eelab__skissm__proto__one_time_pre_key_pair__free_unpacked((*opks)[i], NULL);
        (*opks)[i] = NULL;
    }
    free(*opks);
}

void test_update_one_time_pre_key(){
    setup();

    Org__E2eelab__Skissm__Proto__E2eeAccount *account = create_account();
    /* Generate a random address */
    account->address = (Org__E2eelab__Skissm__Proto__E2eeAddress *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeAddress));
    org__e2eelab__skissm__proto__e2ee_address__init(account->address);
    account->address->user_id = (char *) random_chars(32);
    account->address->domain = create_domain_str();
    account->address->device_id = (char *) random_chars(32);

    /* Save to db */
    account->saved = true;
    ssm_plugin.store_account(account);

    int used_opk = 10;
    uint32_t opk_id = account->one_time_pre_keys[used_opk]->opk_id;

    mark_opk_as_used(account, opk_id);
    update_one_time_pre_key(&(account->account_id), opk_id);

    /* load the one-time pre-keys */
    Org__E2eelab__Skissm__Proto__OneTimePreKeyPair **opk_copy = NULL;
    uint32_t opk_num = load_one_time_pre_keys(&(account->account_id), &opk_copy);

    /* assert the opk is used */
    print_result("test_update_one_time_pre_key", (opk_copy[used_opk]->used == true));

    // free
    org__e2eelab__skissm__proto__e2ee_account__free_unpacked(account, NULL);
    free_opks(&opk_copy, opk_num);

    tear_down();
}

void test_remove_one_time_pre_key(){
    setup();

    Org__E2eelab__Skissm__Proto__E2eeAccount *account = create_account();
    /* Generate a random address */
    account->address = (Org__E2eelab__Skissm__Proto__E2eeAddress *) malloc(sizeof(Org__E2eelab__Skissm__Proto__E2eeAddress));
    org__e2eelab__skissm__proto__e2ee_address__init(account->address);
    account->address->user_id = (char *) random_chars(32);
    account->address->domain = create_domain_str();
    account->address->device_id = (char *) random_chars(32);

    /* Save to db */
    account->saved = true;
    ssm_plugin.store_account(account);

    int origin_opk_num = account->n_one_time_pre_keys;

    int used_opk_num = 80;
    int i;
    for (i = 0; i < used_opk_num; i++){
        remove_one_time_pre_key(&(account->account_id), account->one_time_pre_keys[i]->opk_id);
    }

    /* load the one-time pre-keys */
    Org__E2eelab__Skissm__Proto__OneTimePreKeyPair **opk_copy = NULL;
    uint32_t opk_num = load_one_time_pre_keys(&(account->account_id), &opk_copy);

    /* check if the opks are deleted */
    print_result("test_remove_one_time_pre_key", (opk_num == origin_opk_num - used_opk_num));

    // free
    org__e2eelab__skissm__proto__e2ee_account__free_unpacked(account, NULL);
    free_opks(&opk_copy, opk_num);

    tear_down();
}

int main(){
    test_update_one_time_pre_key();
    test_remove_one_time_pre_key();
    return 0;
}
