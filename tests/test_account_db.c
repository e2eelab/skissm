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
#include "skissm/e2ee_client.h"
#include "skissm/mem_util.h"
#include "skissm/skissm.h"

#include "test_plugin.h"
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

// test about account db
void test_setup()
{
    fprintf(stderr, "test_setup\n");
    tear_up();
    tear_down();
}

void test_setup_call_twice()
{
    fprintf(stderr, "test_setup_call_twice\n");
    tear_up();;
    tear_down();
    tear_up();;
    tear_down();
}

void test_insert_address()
{
    fprintf(stderr, "test_insert_address\n");
    tear_up();

    // create address
    Skissm__E2eeAddress *address;
    mock_address(&address, "alice", "alice's domain", "alice's device");

    // insert to the db
    sqlite_int64 address_id = insert_address(address);

    // try to load address
    Skissm__E2eeAddress *address_copy = NULL;
    load_address(address_id, &address_copy);

    if (address_copy != NULL) {
        assert(compare_address(address, address_copy));
        free_address(address_copy);
    }

    // free
    free_address(address);

    tear_down();
}

void test_insert_key_pair()
{
    fprintf(stderr, "test_insert_key_pair\n");
    tear_up();

    // create keypair
    Skissm__KeyPair *keypair;
    mock_keypair(&keypair, "hello public key", "hello private key");

    // insert to the db
    insert_key_pair(keypair);

    // free
    free_keypair(keypair);

    tear_down();
}

void test_insert_signed_pre_key()
{
    fprintf(stderr, "test_insert_signed_pre_key\n");
    tear_up();

    // create spk
    Skissm__SignedPreKey *signed_pre_keypair;
    mock_signed_pre_keypair(&signed_pre_keypair, 0, "hello public key", "hello private key", "hello signature");

    // insert to the db
    insert_signed_pre_key(signed_pre_keypair);

    // free spk
    free_signed_pre_keypair(signed_pre_keypair);

    tear_down();
}

void test_insert_one_time_pre_key()
{
    fprintf(stderr, "test_insert_one_time_pre_key\n");
    tear_up();

    // create opk
    Skissm__OneTimePreKey *one_time_pre_keypair;
    mock_one_time_pre_keypair(&one_time_pre_keypair, 0, 0, "hello public key", "hello private key");

    // insert to the db
    insert_one_time_pre_key(one_time_pre_keypair);

    // free
    free_one_time_pre_key_pair(one_time_pre_keypair);

    tear_down();
}

void test_init_account(uint32_t e2ee_pack_id)
{
    fprintf(stderr, "test_init_account\n");
    tear_up();
    get_skissm_plugin()->event_handler = test_event_handler;

    // create account
    Skissm__Account *account = create_account(e2ee_pack_id);
    mock_address(&(account->address), "alice", "alice's domain", "alice's device");

    // insert to the db
    store_account(account);

    // free
    free_account(account);

    tear_down();
}

void test_update_signed_pre_key(uint32_t e2ee_pack_id)
{
    fprintf(stderr, "test_update_signed_pre_key\n");
    tear_up();
    get_skissm_plugin()->event_handler = test_event_handler;

    // create account
    Skissm__Account *account = create_account(e2ee_pack_id);
    mock_address(&(account->address), "alice", "alice's domain", "alice's device");

    // insert to the db
    store_account(account);

    // create spk
    Skissm__SignedPreKey *signed_pre_key;
    mock_signed_pre_keypair(&signed_pre_key, 1, "hello public key", "hello private key", "hello signature");

    // update_signed_pre_key
    update_signed_pre_key(account->address, signed_pre_key);

    // free
    free_account(account);
    free_signed_pre_keypair(signed_pre_key);

    tear_down();
}

void test_add_one_time_pre_key(uint32_t e2ee_pack_id)
{
    fprintf(stderr, "test_add_one_time_pre_key\n");
    tear_up();
    get_skissm_plugin()->event_handler = test_event_handler;

    // create account
    Skissm__Account *account = create_account(e2ee_pack_id);
    mock_address(&(account->address), "alice", "alice's domain", "alice's device");

    // insert to the db
    store_account(account);

    // create opk
    Skissm__OneTimePreKey *one_time_pre_key;
    mock_one_time_pre_keypair(&one_time_pre_key, 101, 0, "hello public key", "hello private key");

    // add_one_time_pre_key
    add_one_time_pre_key(account->address, one_time_pre_key);

    // free
    free_account(account);
    free_one_time_pre_key_pair(one_time_pre_key);

    tear_down();
}

void test_load_account(uint32_t e2ee_pack_id)
{
    fprintf(stderr, "test_load_account\n");
    tear_up();
    get_skissm_plugin()->event_handler = test_event_handler;

    // create account
    Skissm__Account *account = create_account(e2ee_pack_id);
    mock_address(&(account->address), "alice", "alice's domain", "alice's device");
    account->auth = strdup("auth");

    // insert to the db
    store_account(account);

    // load_account
    Skissm__Account *account_copy;
    load_account_by_address(account->address, &account_copy);

    // assert account equals to account_copy
    assert(is_equal_account(account, account_copy));

    // free
    free_account(account);
    free_account(account_copy);

    tear_down();
}

void test_two_accounts(uint32_t e2ee_pack_id)
{
    fprintf(stderr, "test_two_accounts\n");
    tear_up();
    get_skissm_plugin()->event_handler = test_event_handler;

    // create the first account
    Skissm__Account *account_1 = create_account(e2ee_pack_id);
    mock_address(&(account_1->address), "alice", "alice's domain", "alice's device");

    // insert to the db
    store_account(account_1);

    // create the first account
    Skissm__Account *account_2 = create_account(e2ee_pack_id);
    mock_address(&(account_2->address), "bob", "bob's domain", "bob's device");

    // insert to the db
    store_account(account_2);

    // load the first account
    Skissm__Account *account_copy_1;
    load_account_by_address(account_1->address, &account_copy_1);

    // assert account_1 equals to account_copy_1
    assert(is_equal_account(account_1, account_copy_1));

    // load the second account
    Skissm__Account *account_copy_2;
    load_account_by_address(account_2->address, &account_copy_2);

    // assert account_2 equals to account_copy_2
    assert(is_equal_account(account_2, account_copy_2));

    // free
    free_account(account_1);

    tear_down();
}

int main()
{
    uint32_t e2ee_pack_id = gen_e2ee_pack_id(
        0,
        E2EE_PACK_ID_DIGITAL_SIGNATURE_CURVE25519,
        E2EE_PACK_ID_KEM_CURVE25519,
        E2EE_PACK_ID_SYMMETRIC_ENCRYPTION_AES256_SHA256
    );

    test_setup();
    test_setup_call_twice();
    test_insert_address();
    test_insert_key_pair();
    test_insert_signed_pre_key();
    test_insert_one_time_pre_key();
    test_init_account(e2ee_pack_id);
    test_update_signed_pre_key(e2ee_pack_id);
    test_add_one_time_pre_key(e2ee_pack_id);
    test_load_account(e2ee_pack_id);
    test_two_accounts(e2ee_pack_id);
}
